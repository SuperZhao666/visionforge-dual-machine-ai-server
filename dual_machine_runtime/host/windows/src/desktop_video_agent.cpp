#include "vfdual/desktop_video_agent.hpp"
#include "vfdual/dxgi_frame_semantics.hpp"
#include "vfdual/protocol.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <array>
#include <limits>

namespace vfdual {
namespace {
constexpr std::uint64_t kPeriodicIdrIntervalUs = 1'000'000ULL;

void describe_access_unit(
    std::span<const std::byte> access_unit,
    DesktopVideoStepMetrics& metrics) noexcept {
    if (access_unit.size() >= 4U) {
        metrics.access_unit_prefix_be =
            (std::to_integer<std::uint8_t>(access_unit[0]) << 24U) |
            (std::to_integer<std::uint8_t>(access_unit[1]) << 16U) |
            (std::to_integer<std::uint8_t>(access_unit[2]) << 8U) |
            std::to_integer<std::uint8_t>(access_unit[3]);
    }
    for (std::size_t index = 0; index + 4U < access_unit.size(); ++index) {
        const bool short_start = access_unit[index] == std::byte{0} &&
            access_unit[index + 1U] == std::byte{0} &&
            access_unit[index + 2U] == std::byte{1};
        const bool long_start = index + 5U < access_unit.size() &&
            access_unit[index] == std::byte{0} &&
            access_unit[index + 1U] == std::byte{0} &&
            access_unit[index + 2U] == std::byte{0} &&
            access_unit[index + 3U] == std::byte{1};
        if (!short_start && !long_start) continue;
        const std::uint8_t nal_type =
            std::to_integer<std::uint8_t>(
                access_unit[index + (long_start ? 4U : 3U)]) & 0x1fU;
        if (metrics.first_annex_b_nal_type == 0U) {
            metrics.first_annex_b_nal_type = nal_type;
        }
        metrics.annex_b_nal_type_mask |= 1U << nal_type;
    }
}

std::uint64_t qpc_frequency() noexcept {
    static const std::uint64_t frequency = []() noexcept {
        LARGE_INTEGER value{};
        return QueryPerformanceFrequency(&value)
            ? static_cast<std::uint64_t>(value.QuadPart)
            : 0U;
    }();
    return frequency;
}

std::uint64_t qpc_to_microseconds(std::uint64_t ticks) noexcept {
    const std::uint64_t frequency = qpc_frequency();
    if (frequency == 0U) return 0U;
    return (ticks / frequency) * 1'000'000ULL +
        ((ticks % frequency) * 1'000'000ULL) / frequency;
}

std::uint64_t monotonic_microseconds() noexcept {
    LARGE_INTEGER counter{};
    QueryPerformanceCounter(&counter);
    return qpc_to_microseconds(static_cast<std::uint64_t>(counter.QuadPart));
}

DesktopVideoStepStatus map_capture_status(CaptureStatus status) noexcept {
    switch (status) {
        case CaptureStatus::timeout:
            return DesktopVideoStepStatus::capture_timeout;
        case CaptureStatus::pointer_only_skipped:
            return DesktopVideoStepStatus::capture_pointer_only;
        case CaptureStatus::outside_region_skipped:
            return DesktopVideoStepStatus::capture_outside_region;
        case CaptureStatus::access_lost:
            return DesktopVideoStepStatus::capture_access_lost;
        case CaptureStatus::device_removed:
            return DesktopVideoStepStatus::capture_device_removed;
        case CaptureStatus::frame_ready:
        case CaptureStatus::initialization_failed:
        case CaptureStatus::failed:
            return DesktopVideoStepStatus::capture_failed;
    }
    return DesktopVideoStepStatus::capture_failed;
}

bool initialize_media_foundation_with_timing_fallback(
    MediaFoundationH264Encoder& encoder, ID3D11Device* device,
    const H264EncoderConfig& requested,
    MediaFoundationEncoderMode mode,
    std::uint32_t& effective_timing_fps) noexcept {
    const std::array timings{
        requested.frames_per_second,
        (std::min)(requested.frames_per_second, 120U),
        (std::min)(requested.frames_per_second, 60U),
    };
    std::uint32_t previous{};
    for (const std::uint32_t timing_fps : timings) {
        if (timing_fps == previous) continue;
        previous = timing_fps;
        H264EncoderConfig candidate = requested;
        candidate.frames_per_second = timing_fps;
        if (encoder.initialize(device, candidate, mode)) {
            effective_timing_fps = timing_fps;
            return true;
        }
    }
    return false;
}

constexpr std::uint32_t candidate_mask(HostEncoderCandidate candidate) noexcept {
    return 1U << static_cast<std::uint32_t>(candidate);
}

DesktopVideoInitializationStage candidate_initialization_stage(
    HostEncoderCandidate candidate) noexcept {
    switch (candidate) {
        case HostEncoderCandidate::nvenc_same_adapter_async_shared:
        case HostEncoderCandidate::nvenc_capture_device:
        case HostEncoderCandidate::nvenc_cross_adapter:
            return DesktopVideoInitializationStage::nvenc_initialize;
        case HostEncoderCandidate::windows_hardware_capture_device:
            return DesktopVideoInitializationStage::media_foundation_hardware_initialize;
        case HostEncoderCandidate::software_cpu:
            return DesktopVideoInitializationStage::media_foundation_software_initialize;
    }
    return DesktopVideoInitializationStage::none;
}

DesktopVideoInitializationStage hybrid_initialization_stage(
    HybridGpuFatalStage stage) noexcept {
    switch (stage) {
        case HybridGpuFatalStage::publisher_connect:
        case HybridGpuFatalStage::publish:
            return DesktopVideoInitializationStage::udp_publisher_connect;
        case HybridGpuFatalStage::encoder_initialize:
        case HybridGpuFatalStage::encode:
            return DesktopVideoInitializationStage::nvenc_initialize;
        case HybridGpuFatalStage::none:
        case HybridGpuFatalStage::source_staging_texture:
        case HybridGpuFatalStage::source_copy:
        case HybridGpuFatalStage::readback_map:
        case HybridGpuFatalStage::worker_device:
        case HybridGpuFatalStage::worker_texture:
        case HybridGpuFatalStage::initialization_exception:
        case HybridGpuFatalStage::worker_exception:
            return DesktopVideoInitializationStage::hybrid_pipeline_initialize;
    }
    return DesktopVideoInitializationStage::hybrid_pipeline_initialize;
}

}  // namespace

bool DesktopVideoAgent::initialize(const DesktopVideoAgentConfig& config) noexcept {
    reset();
    if (config.local_host.empty() || config.phone_host.empty() ||
        config.phone_port == 0U || !valid_video_stream_epoch(config.stream_epoch) ||
        config.encoder.width == 0U ||
        config.encoder.height == 0U || !config.data_plane_permit) {
        return fail_initialization(
            DesktopVideoInitializationStage::validate_config, E_INVALIDARG);
    }
    const CaptureStatus capture_status = capture_.initialize(
            config.adapter_index, config.output_index,
            config.capture_region);
    if (capture_status != CaptureStatus::frame_ready) {
        encoder_diagnostics_.capture_hresult = capture_.last_hresult();
        return fail_initialization(
            DesktopVideoInitializationStage::capture_initialize,
            capture_.last_hresult());
    }

    capture_vendor_ = graphics_adapter_vendor(capture_.native_device());
    encoder_diagnostics_.capture_vendor = capture_vendor_;
    const auto candidates = choose_host_encoder_candidates(
        config.encoder_preference, capture_vendor_);
    bool candidate_ready{};
    const auto record_candidate_failure =
        [this](HostEncoderCandidate candidate,
               DesktopVideoInitializationStage stage,
               std::int32_t status) noexcept {
            encoder_diagnostics_.failed_candidate_mask |= candidate_mask(candidate);
            encoder_diagnostics_.last_failed_candidate = candidate;
            encoder_diagnostics_.last_failure_stage = stage;
            encoder_diagnostics_.last_failure_status = status;
            encoder_diagnostics_.has_failed_candidate = true;
        };
    for (std::size_t index = 0; index < candidates.size; ++index) {
        encoder_.reset();
        media_foundation_encoder_.reset();
        frame_bridge_.reset();
        hybrid_pipeline_.reset();
        encoder_backend_ = H264EncoderBackend::none;
        hybrid_pipeline_active_ = false;
        async_shared_same_adapter_ = false;

        const HostEncoderCandidate candidate = candidates.values[index];
        const bool asynchronous_candidate = candidate ==
                HostEncoderCandidate::nvenc_same_adapter_async_shared ||
            candidate == HostEncoderCandidate::nvenc_cross_adapter;
        const bool asynchronous_extent_supported =
            host_async_pipeline_supports_capture_extent(
                config.capture_region.width, config.capture_region.height,
                config.encoder.width, config.encoder.height);
        if (candidate == HostEncoderCandidate::nvenc_same_adapter_async_shared &&
            !asynchronous_extent_supported) {
            // The next capture-device NVENC candidate owns GPU scaling. Do not
            // start an exact-copy pipeline that would reject every source frame.
            continue;
        }
        encoder_diagnostics_.attempted_candidate_mask |= candidate_mask(candidate);
        if (asynchronous_candidate && asynchronous_extent_supported) {
            const bool same_adapter_async = candidate ==
                HostEncoderCandidate::nvenc_same_adapter_async_shared;
            candidate_ready = hybrid_pipeline_.initialize(
                capture_.native_device(), capture_.native_context(),
                HybridGpuVideoPipelineConfig{
                    .stream_epoch = config.stream_epoch,
                    .encoder = config.encoder,
                    .local_host = config.local_host,
                    .local_port = config.local_port,
                    .phone_host = config.phone_host,
                    .phone_port = config.phone_port,
                    .data_plane_permit = config.data_plane_permit,
                    .transfer_mode = same_adapter_async
                        ? HybridGpuTransferMode::same_adapter_shared_texture
                        : HybridGpuTransferMode::cpu_readback,
                });
            if (candidate_ready) {
                hybrid_pipeline_active_ = true;
                async_shared_same_adapter_ = same_adapter_async;
                encoder_backend_ = H264EncoderBackend::nvenc;
                encoder_vendor_ = GraphicsAdapterVendor::nvidia;
                encoder_same_adapter_ = same_adapter_async;
                zero_copy_ = false;
                encoder_timing_fps_ = config.encoder.frames_per_second;
                encoder_diagnostics_.hardware = true;
                encoder_diagnostics_.transform_name = same_adapter_async
                    ? "NVIDIA NVENC D3D11 async direct-shared"
                    : "NVIDIA NVENC D3D11";
                encoder_diagnostics_.adapter_vendor_id = 0x10DEU;
                encoder_diagnostics_.backend = encoder_backend_;
                encoder_diagnostics_.encoder_vendor = encoder_vendor_;
                encoder_diagnostics_.same_adapter = encoder_same_adapter_;
                encoder_diagnostics_.selected_candidate = candidate;
                encoder_diagnostics_.has_selected_candidate = true;
                break;
            }
            const HybridGpuFatalFailure failure = hybrid_pipeline_.fatal_failure();
            record_candidate_failure(
                candidate, hybrid_initialization_stage(failure.stage),
                failure.native_status);
            continue;
        }

        const bool wants_capture_device =
            candidate == HostEncoderCandidate::nvenc_capture_device ||
            candidate == HostEncoderCandidate::windows_hardware_capture_device ||
            candidate == HostEncoderCandidate::software_cpu;
        if (!frame_bridge_.initialize(
                capture_.native_device(), capture_.native_context(),
                config.encoder.width, config.encoder.height,
                config.encoder.frames_per_second,
                wants_capture_device
                    ? FrameEncoderDevicePreference::capture_source
                    : FrameEncoderDevicePreference::nvidia)) {
            record_candidate_failure(
                candidate,
                DesktopVideoInitializationStage::frame_bridge_initialize,
                frame_bridge_.last_hresult());
            continue;
        }

        switch (candidate) {
            case HostEncoderCandidate::nvenc_same_adapter_async_shared:
                break;
            case HostEncoderCandidate::nvenc_capture_device:
            case HostEncoderCandidate::nvenc_cross_adapter:
                candidate_ready = encoder_.initialize(
                    frame_bridge_.encoder_device(), config.encoder);
                if (candidate_ready) {
                    encoder_backend_ = H264EncoderBackend::nvenc;
                    encoder_vendor_ = GraphicsAdapterVendor::nvidia;
                    encoder_same_adapter_ = frame_bridge_.uses_capture_device();
                    encoder_timing_fps_ = config.encoder.frames_per_second;
                    encoder_diagnostics_.hardware = true;
                    encoder_diagnostics_.transform_name = "NVIDIA NVENC D3D11";
                    encoder_diagnostics_.adapter_vendor_id = 0x10DEU;
                }
                break;
            case HostEncoderCandidate::windows_hardware_capture_device:
                // Timing fallback changes only H.264 timestamps. The producer
                // remains present-driven and has no artificial FPS ceiling.
                candidate_ready = initialize_media_foundation_with_timing_fallback(
                    media_foundation_encoder_, frame_bridge_.encoder_device(),
                    config.encoder, MediaFoundationEncoderMode::hardware,
                    encoder_timing_fps_);
                if (candidate_ready) {
                    encoder_backend_ = H264EncoderBackend::windows_hardware;
                    encoder_vendor_ =
                        media_foundation_encoder_.adapter_vendor();
                    encoder_same_adapter_ =
                        frame_bridge_.uses_capture_device();
                    encoder_diagnostics_.hardware = true;
                    encoder_diagnostics_.adapter_vendor_id =
                        media_foundation_encoder_.adapter_vendor_id();
                    encoder_diagnostics_.adapter_luid_low =
                        media_foundation_encoder_.adapter_luid_low();
                    encoder_diagnostics_.adapter_luid_high =
                        media_foundation_encoder_.adapter_luid_high();
                    encoder_diagnostics_.matching_hardware_transforms =
                        media_foundation_encoder_.matching_hardware_transforms();
                    encoder_diagnostics_.transform_name =
                        media_foundation_encoder_.transform_name();
                    encoder_diagnostics_.transform_clsid =
                        media_foundation_encoder_.transform_clsid();
                }
                break;
            case HostEncoderCandidate::software_cpu:
                // Lower values are bitstream timing metadata only. The capture
                // loop stays uncapped and consumes every available desktop frame.
                candidate_ready =
                    initialize_media_foundation_with_timing_fallback(
                        media_foundation_encoder_,
                        frame_bridge_.encoder_device(), config.encoder,
                        MediaFoundationEncoderMode::software,
                        encoder_timing_fps_);
                if (candidate_ready) {
                    encoder_backend_ = H264EncoderBackend::software_cpu;
                    encoder_vendor_ = GraphicsAdapterVendor::microsoft;
                    encoder_same_adapter_ = false;
                    encoder_diagnostics_.hardware = false;
                    encoder_diagnostics_.adapter_vendor_id =
                        media_foundation_encoder_.adapter_vendor_id();
                    encoder_diagnostics_.transform_name =
                        media_foundation_encoder_.transform_name();
                    encoder_diagnostics_.transform_clsid =
                        media_foundation_encoder_.transform_clsid();
                }
                break;
        }
        if (candidate_ready) {
            encoder_diagnostics_.backend = encoder_backend_;
            encoder_diagnostics_.encoder_vendor = encoder_vendor_;
            encoder_diagnostics_.same_adapter = encoder_same_adapter_;
            encoder_diagnostics_.selected_candidate = candidate;
            encoder_diagnostics_.has_selected_candidate = true;
            break;
        }
        const std::int32_t failure_status =
            candidate == HostEncoderCandidate::nvenc_capture_device ||
                candidate == HostEncoderCandidate::nvenc_cross_adapter
            ? encoder_.last_nvenc_status()
            : media_foundation_encoder_.last_hresult();
        record_candidate_failure(
            candidate, candidate_initialization_stage(candidate), failure_status);
    }

    if (!candidate_ready || encoder_backend_ == H264EncoderBackend::none) {
        const DesktopVideoInitializationStage failure_stage =
            encoder_diagnostics_.last_failure_stage ==
                    DesktopVideoInitializationStage::none
                ? DesktopVideoInitializationStage::frame_bridge_initialize
                : encoder_diagnostics_.last_failure_stage;
        return fail_initialization(
            failure_stage, encoder_diagnostics_.last_failure_status);
    }
    if (!hybrid_pipeline_active_ &&
        !publisher_.connect_to(
            config.phone_host, config.phone_port,
            config.local_port, config.local_host,
            config.data_plane_permit)) {
        encoder_diagnostics_.publisher_socket_error =
            publisher_.last_socket_error();
        return fail_initialization(
            DesktopVideoInitializationStage::udp_publisher_connect,
            static_cast<std::int32_t>(
                encoder_diagnostics_.publisher_socket_error));
    }

    config_ = config;
    encoder_diagnostics_.initialization_stage =
        DesktopVideoInitializationStage::complete;
    initialized_ = true;
    return true;
}

DesktopVideoStepMetrics DesktopVideoAgent::publish_next() noexcept {
    DesktopVideoStepMetrics result{};
    if (!initialized_) return result;
    populate_common_metrics(result);
    try {
        if (!config_.data_plane_permit()) {
            result.status = DesktopVideoStepStatus::data_plane_closed;
            return result;
        }
    } catch (...) {
        result.status = DesktopVideoStepStatus::data_plane_closed;
        return result;
    }

    if (hybrid_pipeline_active_) {
        if (const HybridGpuFatalFailure fatal = hybrid_pipeline_.fatal_failure();
            fatal.failed) {
            result.status = desktop_video_status_for_hybrid_failure(fatal.stage);
            result.native_status = fatal.native_status;
            result.source_sequence = fatal.source_sequence;
            populate_common_metrics(result);
            return result;
        }
    }

    CapturedDesktopFrame frame{};
    const bool producer_owns_idle_repeat = capture_stage_owns_idle_repeat(
        hybrid_pipeline_active_, async_shared_same_adapter_);
    const std::uint64_t capture_started = monotonic_microseconds();
    const std::uint32_t capture_timeout_ms = producer_owns_idle_repeat
        ? static_frame_capture_wait_ms(
            capture_started, last_video_submission_us_,
            config_.encoder.frames_per_second, config_.capture_timeout_ms)
        : config_.capture_timeout_ms;
    CaptureStatus capture_status = capture_.acquire_next(
        frame, capture_timeout_ms);
    const std::uint64_t capture_completed = monotonic_microseconds();
    result.capture_us = capture_completed - capture_started;
    const bool repeatable_capture_status =
        capture_status == CaptureStatus::timeout ||
        capture_status == CaptureStatus::pointer_only_skipped ||
        capture_status == CaptureStatus::outside_region_skipped;
    if (producer_owns_idle_repeat && repeatable_capture_status &&
        static_frame_refresh_due(
            capture_completed, last_video_submission_us_,
            config_.encoder.frames_per_second) &&
        capture_.repeat_last(frame)) {
        capture_status = CaptureStatus::frame_ready;
    }
    if (capture_status != CaptureStatus::frame_ready) {
        result.status = map_capture_status(capture_status);
        result.native_status = capture_.last_hresult();
        if (hybrid_pipeline_active_) {
            static_cast<void>(hybrid_pipeline_.pump());
        }
        populate_common_metrics(result);
        return result;
    }

    const bool retained_texture_reused = frame.repeated_content;
    frame.repeated_content = retained_frame_repeats_submitted_content(
        retained_texture_reused, frame.content_sequence,
        last_submitted_content_sequence_);
    result.source_sequence = ++next_source_sequence_;
    result.capture_present_us = qpc_to_microseconds(frame.last_present_qpc);
    result.accumulated_frames = frame.accumulated_frames;
    result.missed_present_frames = frame.missed_present_frames;
    result.repeated_content = frame.repeated_content;

    if (hybrid_pipeline_active_) {
        const HybridGpuSubmitResult submitted = hybrid_pipeline_.submit(
            HybridGpuFrameInput{
                frame.texture,
                result.source_sequence,
                result.capture_present_us,
                result.capture_us,
                frame.accumulated_frames,
                frame.missed_present_frames,
                frame.repeated_content,
            });
        result.bridge_us = submitted.staging_copy_submit_us;
        result.native_status = submitted.hresult;
        switch (submitted.status) {
            case HybridGpuSubmitStatus::accepted:
                result.status = DesktopVideoStepStatus::frame_queued;
                last_video_submission_us_ = monotonic_microseconds();
                last_submitted_content_sequence_ = frame.content_sequence;
                break;
            case HybridGpuSubmitStatus::staging_busy:
                result.status = DesktopVideoStepStatus::staging_busy;
                if (retained_texture_reused) {
                    last_video_submission_us_ = monotonic_microseconds();
                }
                break;
            case HybridGpuSubmitStatus::fatal_failure: {
                const HybridGpuFatalFailure fatal = hybrid_pipeline_.fatal_failure();
                result.status = desktop_video_status_for_hybrid_failure(fatal.stage);
                result.native_status = fatal.native_status;
                break;
            }
            case HybridGpuSubmitStatus::invalid_input:
            case HybridGpuSubmitStatus::not_initialized:
                result.status = DesktopVideoStepStatus::bridge_failed;
                break;
        }
        if (const HybridGpuFatalFailure fatal = hybrid_pipeline_.fatal_failure();
            fatal.failed) {
            result.status = desktop_video_status_for_hybrid_failure(fatal.stage);
            result.native_status = fatal.native_status;
        }
        populate_common_metrics(result);
        return result;
    }

    const std::uint64_t bridge_started = monotonic_microseconds();
    const BridgedFrame bridged_frame = frame_bridge_.bridge(frame.texture);
    result.bridge_us = monotonic_microseconds() - bridge_started;
    result.bridge_mode = bridged_frame.mode;
    zero_copy_ = encoder_backend_ == H264EncoderBackend::nvenc &&
        encoder_same_adapter_ &&
        (bridged_frame.mode == FrameBridgeMode::zero_copy ||
         bridged_frame.mode == FrameBridgeMode::gpu_scale_zero_copy);
    if (bridged_frame.texture == nullptr) {
        result.status = DesktopVideoStepStatus::bridge_failed;
        result.native_status = bridged_frame.hresult;
        populate_common_metrics(result);
        return result;
    }

    if (next_frame_sequence_ == (std::numeric_limits<std::uint32_t>::max)()) {
        // Force the owning runtime to rotate stream_epoch before any terminal
        // sequence is published; sequence reuse inside one epoch is forbidden.
        result.status = DesktopVideoStepStatus::publish_failed;
        result.native_status = E_BOUNDS;
        force_idr_next_ = true;
        populate_common_metrics(result);
        return result;
    }

    const std::uint64_t encode_started = monotonic_microseconds();
    const bool periodic_idr = last_idr_us == 0U ||
        encode_started - last_idr_us >= kPeriodicIdrIntervalUs;
    const bool explicit_recovery_idr = force_idr_next_;
    const bool force_idr = explicit_recovery_idr || periodic_idr;
    force_idr_next_ = false;
    std::span<const std::byte> access_unit;
    std::uint32_t encoded_bytes{};
    bool encoded_keyframe{};
    if (encoder_backend_ == H264EncoderBackend::nvenc) {
        const NvencEncodeResult encoded = encoder_.encode(
            bridged_frame.texture, force_idr);
        result.native_status = encoded.nvenc_status;
        result.nvenc_stage = encoded.stage;
        if (!encoded.success) {
            result.encode_us = monotonic_microseconds() - encode_started;
            result.status = DesktopVideoStepStatus::encode_failed;
            populate_common_metrics(result);
            return result;
        }
        access_unit = encoder_.access_unit();
        encoded_bytes = encoded.bytes;
        encoded_keyframe = encoded.keyframe;
    } else if (encoder_backend_ == H264EncoderBackend::windows_hardware ||
               encoder_backend_ == H264EncoderBackend::software_cpu) {
        const MediaFoundationEncodeResult encoded =
            media_foundation_encoder_.encode(bridged_frame.texture, force_idr);
        result.native_status = encoded.hresult;
        result.media_foundation_stage = encoded.stage;
        if (!encoded.success) {
            result.encode_us = monotonic_microseconds() - encode_started;
            result.status = DesktopVideoStepStatus::encode_failed;
            populate_common_metrics(result);
            return result;
        }
        access_unit = media_foundation_encoder_.access_unit();
        encoded_bytes = encoded.bytes;
        encoded_keyframe = encoded.keyframe;
    } else {
        result.encode_us = monotonic_microseconds() - encode_started;
        result.status = DesktopVideoStepStatus::encode_failed;
        populate_common_metrics(result);
        return result;
    }
    result.encode_us = monotonic_microseconds() - encode_started;

    const bool wire_repeated_content = wire_frame_repeats_content(
        frame.repeated_content,
        explicit_recovery_idr && encoded_keyframe);
    result.repeated_content = wire_repeated_content;
    const std::uint64_t publish_started = monotonic_microseconds();
    const VideoPublishResult published = publisher_.publish(
        {config_.stream_epoch, next_frame_sequence_}, access_unit,
        publish_started, wire_repeated_content);
    const std::uint64_t publish_completed = monotonic_microseconds();
    result.publish_us = publish_completed - publish_started;
    result.frame_id = next_frame_sequence_;
    std::uint32_t following_sequence{};
    const bool sequence_available = advance_video_frame_sequence(
        next_frame_sequence_, following_sequence);
    if (!sequence_available) {
        result.status = DesktopVideoStepStatus::publish_failed;
        result.native_status = E_BOUNDS;
        force_idr_next_ = true;
        populate_common_metrics(result);
        return result;
    }
    next_frame_sequence_ = following_sequence;
    result.access_unit_bytes = encoded_bytes;
    describe_access_unit(access_unit, result);
    result.keyframe = encoded_keyframe;
    if (published.completely_published() && encoded_keyframe) {
        last_idr_us = encode_started;
    } else if (explicit_recovery_idr || encoded_keyframe) {
        // Partial keyframe publication leaves the Android reference chain
        // unusable; request another real IDR on the next encode.
        force_idr_next_ = true;
    }
    result.datagrams_sent = published.fragments_sent;
    result.publish_stage = published.stage;
    if (result.capture_present_us != 0U &&
        publish_completed >= result.capture_present_us) {
        result.capture_to_publish_us =
            publish_completed - result.capture_present_us;
    }
    if (!published.completely_published()) {
        result.status = DesktopVideoStepStatus::publish_failed;
        result.native_status =
            static_cast<std::int32_t>(publisher_.last_socket_error());
        populate_common_metrics(result);
        return result;
    }
    result.status = DesktopVideoStepStatus::frame_published;
    last_video_submission_us_ = publish_completed;
    last_submitted_content_sequence_ = frame.content_sequence;
    populate_common_metrics(result);
    return result;
}

bool DesktopVideoAgent::try_pop_completed(
    DesktopVideoStepMetrics& destination) noexcept {
    if (!initialized_ || !hybrid_pipeline_active_) return false;
    HybridGpuCompletionMetrics completion{};
    if (!hybrid_pipeline_.try_pop_completion(completion)) return false;
    destination = make_hybrid_completion(completion);
    return true;
}

const DesktopVideoEncoderDiagnostics&
DesktopVideoAgent::encoder_diagnostics() const noexcept {
    return encoder_diagnostics_;
}

void DesktopVideoAgent::populate_common_metrics(
    DesktopVideoStepMetrics& destination) const noexcept {
    destination.encoder_backend = encoder_backend_;
    destination.capture_vendor = capture_vendor_;
    destination.encoder_vendor = encoder_vendor_;
    destination.encoder_same_adapter = encoder_same_adapter_;
    destination.zero_copy = zero_copy_;
    destination.asynchronous_pipeline = hybrid_pipeline_active_;
    destination.async_shared_same_adapter = async_shared_same_adapter_;
    destination.encoder_timing_fps = encoder_timing_fps_;
    if (hybrid_pipeline_active_) {
        destination.bridge_mode = async_shared_same_adapter_
            ? FrameBridgeMode::same_adapter_async_shared_texture
            : FrameBridgeMode::hybrid_async_readback_upload;
    }

    const DesktopCaptureStatistics capture_statistics =
        capture_.statistics_snapshot();
    destination.pointer_only_skips = capture_statistics.pointer_only_skips;
    destination.outside_region_skips = capture_statistics.outside_region_skips;
    destination.missed_present_frames_total =
        capture_statistics.missed_present_frames;
    destination.static_content_repeats =
        capture_statistics.static_content_repeats;

    if (!hybrid_pipeline_active_) return;
    const HybridGpuPipelineCounters counters = hybrid_pipeline_.counters();
    destination.hybrid_frames_submitted = counters.frames_submitted;
    destination.hybrid_staging_busy = counters.staging_busy;
    destination.hybrid_was_still_drawing = counters.was_still_drawing;
    destination.hybrid_mailbox_superseded = counters.mailbox_superseded;
    destination.hybrid_mailbox_replaced = counters.mailbox_replaced;
    destination.hybrid_ring_busy = counters.ring_busy;
    destination.hybrid_keyed_timeout = counters.keyed_timeout;
    destination.hybrid_published = counters.published;
    destination.hybrid_completion_metrics_dropped =
        counters.completion_metrics_dropped;
    destination.hybrid_latest_worker_frame_age_us =
        counters.latest_worker_frame_age_us;
    destination.hybrid_maximum_worker_frame_age_us =
        counters.maximum_worker_frame_age_us;
    destination.hybrid_staging_high_watermark =
        counters.staging_high_watermark;
    destination.hybrid_mailbox_high_watermark =
        counters.mailbox_high_watermark;
    destination.hybrid_completion_high_watermark =
        counters.completion_high_watermark;
}

DesktopVideoStepMetrics DesktopVideoAgent::make_hybrid_completion(
    const HybridGpuCompletionMetrics& completion) const noexcept {
    DesktopVideoStepMetrics result{};
    switch (completion.status) {
        case HybridGpuCompletionStatus::frame_published:
            result.status = DesktopVideoStepStatus::frame_published;
            break;
        case HybridGpuCompletionStatus::data_plane_closed:
            result.status = DesktopVideoStepStatus::data_plane_closed;
            break;
        case HybridGpuCompletionStatus::encode_failed:
            result.status = DesktopVideoStepStatus::encode_failed;
            break;
        case HybridGpuCompletionStatus::publish_failed:
            result.status = DesktopVideoStepStatus::publish_failed;
            break;
    }
    result.source_sequence = completion.source_sequence;
    result.frame_id = completion.frame_id;
    result.capture_present_us = completion.capture_present_us;
    result.capture_us = completion.capture_us;
    result.readback_wait_us = completion.readback_wait_us;
    result.readback_copy_us = completion.readback_copy_us;
    result.upload_us = completion.upload_us;
    result.encode_us = completion.encode_us;
    result.publish_us = completion.publish_us;
    result.worker_frame_age_us = completion.worker_frame_age_us;
    result.capture_to_publish_us = completion.capture_to_publish_age_us;
    result.accumulated_frames = completion.accumulated_frames;
    result.missed_present_frames = completion.missed_present_frames;
    result.repeated_content = completion.repeated_content;
    result.access_unit_bytes = completion.access_unit_bytes;
    result.access_unit_prefix_be = completion.access_unit_prefix_be;
    result.first_annex_b_nal_type = completion.first_annex_b_nal_type;
    result.annex_b_nal_type_mask = completion.annex_b_nal_type_mask;
    result.datagrams_sent = completion.datagrams_sent;
    result.keyframe = completion.keyframe;
    result.native_status = completion.native_status;
    result.nvenc_stage = completion.nvenc_stage;
    result.publish_stage = completion.publish_stage;
    populate_common_metrics(result);
    return result;
}

bool DesktopVideoAgent::fail_initialization(
    DesktopVideoInitializationStage stage,
    std::int32_t native_status) noexcept {
    encoder_diagnostics_.initialization_stage = stage;
    encoder_diagnostics_.last_failure_stage = stage;
    encoder_diagnostics_.last_failure_status = native_status;
    release_runtime_resources();
    return false;
}

void DesktopVideoAgent::release_runtime_resources() noexcept {
    initialized_ = false;
    hybrid_pipeline_.reset();
    hybrid_pipeline_active_ = false;
    async_shared_same_adapter_ = false;
    next_frame_sequence_ = 0U;
    next_source_sequence_ = 0U;
    last_video_submission_us_ = 0U;
    last_submitted_content_sequence_ = 0U;
    last_idr_us = 0U;
    force_idr_next_ = false;
    encoder_backend_ = H264EncoderBackend::none;
    capture_vendor_ = GraphicsAdapterVendor::unknown;
    encoder_vendor_ = GraphicsAdapterVendor::unknown;
    encoder_same_adapter_ = false;
    zero_copy_ = false;
    encoder_timing_fps_ = 0U;
    publisher_.reset();
    encoder_.reset();
    frame_bridge_.reset();
    capture_.reset();
    // Media Foundation owns the COM initialization used by an asynchronous
    // hardware MFT. Release the DXGI duplication and bridge COM objects before
    // that encoder balances CoUninitialize on this thread.
    media_foundation_encoder_.reset();
}

void DesktopVideoAgent::reset() noexcept {
    release_runtime_resources();
    encoder_diagnostics_ = {};
}

void DesktopVideoAgent::request_idr() noexcept {
    if (hybrid_pipeline_active_) {
        hybrid_pipeline_.request_idr();
        return;
    }
    force_idr_next_ = true;
}

}  // namespace vfdual
