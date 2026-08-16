#pragma once

#include "vfdual/dxgi_desktop_capture.hpp"
#include "vfdual/d3d11_frame_bridge.hpp"
#include "vfdual/h264_encoder_config.hpp"
#include "vfdual/host_encoder_policy.hpp"
#include "vfdual/hybrid_gpu_video_pipeline.hpp"
#include "vfdual/media_foundation_h264_encoder.hpp"
#include "vfdual/nvenc_h264_encoder.hpp"
#include "vfdual/udp_video_publisher.hpp"
#include "vfdual/wired_link_contract.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace vfdual {

struct DesktopVideoAgentConfig {
    /** Positive 63-bit wire-session identity; rotated on every Host rebuild. */
    std::uint64_t stream_epoch{};
    std::uint32_t adapter_index{};
    std::uint32_t output_index{};
    std::uint32_t capture_timeout_ms{16};
    DesktopCaptureRegion capture_region{};
    H264EncoderConfig encoder{};
    H264EncoderPreference encoder_preference{H264EncoderPreference::automatic};
    std::string local_host{kWiredHostIpv4};
    std::uint16_t local_port{kWiredVideoSourcePort};
    std::string phone_host;
    std::uint16_t phone_port{};
    VideoDataPlanePermitSource data_plane_permit;
};

enum class DesktopVideoStepStatus {
    frame_published,
    data_plane_closed,
    capture_timeout,
    capture_access_lost,
    capture_device_removed,
    capture_failed,
    bridge_failed,
    encode_failed,
    publish_failed,
    frame_queued,
    capture_pointer_only,
    capture_outside_region,
    staging_busy,
};

[[nodiscard]] constexpr DesktopVideoStepStatus desktop_video_status_for_hybrid_failure(
    HybridGpuFatalStage stage) noexcept {
    switch (stage) {
        case HybridGpuFatalStage::publish:
        case HybridGpuFatalStage::publisher_connect:
            return DesktopVideoStepStatus::publish_failed;
        case HybridGpuFatalStage::source_staging_texture:
        case HybridGpuFatalStage::source_copy:
        case HybridGpuFatalStage::readback_map:
        case HybridGpuFatalStage::worker_texture:
            return DesktopVideoStepStatus::bridge_failed;
        case HybridGpuFatalStage::none:
        case HybridGpuFatalStage::worker_device:
        case HybridGpuFatalStage::encoder_initialize:
        case HybridGpuFatalStage::encode:
        case HybridGpuFatalStage::initialization_exception:
        case HybridGpuFatalStage::worker_exception:
            return DesktopVideoStepStatus::encode_failed;
    }
    return DesktopVideoStepStatus::encode_failed;
}

/** Stable startup stages used in release logs and crash-dump triage. */
enum class DesktopVideoInitializationStage : std::uint8_t {
    none,
    validate_config,
    capture_initialize,
    hybrid_pipeline_initialize,
    frame_bridge_initialize,
    nvenc_initialize,
    media_foundation_hardware_initialize,
    media_foundation_software_initialize,
    udp_publisher_connect,
    complete,
};

/** Local-clock timings for one frame. Cross-device timing is intentionally not inferred here. */
struct DesktopVideoStepMetrics {
    DesktopVideoStepStatus status{DesktopVideoStepStatus::capture_failed};
    std::uint64_t source_sequence{};
    std::uint32_t frame_id{};
    std::uint64_t capture_present_us{};
    std::uint64_t capture_us{};
    std::uint64_t readback_wait_us{};
    std::uint64_t readback_copy_us{};
    std::uint64_t bridge_us{};
    std::uint64_t upload_us{};
    std::uint64_t encode_us{};
    std::uint64_t publish_us{};
    std::uint64_t capture_to_publish_us{};
    std::uint32_t accumulated_frames{};
    std::uint32_t missed_present_frames{};
    std::uint64_t pointer_only_skips{};
    std::uint64_t outside_region_skips{};
    std::uint64_t missed_present_frames_total{};
    std::uint64_t static_content_repeats{};
    std::uint64_t hybrid_frames_submitted{};
    std::uint64_t hybrid_staging_busy{};
    std::uint64_t hybrid_was_still_drawing{};
    std::uint64_t hybrid_mailbox_superseded{};
    std::uint64_t hybrid_mailbox_replaced{};
    std::uint64_t hybrid_ring_busy{};
    std::uint64_t hybrid_keyed_timeout{};
    /** Authoritative worker-side UDP publish count for the current stream epoch. */
    std::uint64_t hybrid_published{};
    std::uint64_t hybrid_completion_metrics_dropped{};
    std::uint64_t worker_frame_age_us{};
    std::uint64_t hybrid_latest_worker_frame_age_us{};
    std::uint64_t hybrid_maximum_worker_frame_age_us{};
    std::uint32_t hybrid_staging_high_watermark{};
    std::uint32_t hybrid_mailbox_high_watermark{};
    std::uint32_t hybrid_completion_high_watermark{};
    FrameBridgeMode bridge_mode{FrameBridgeMode::cpu_staging_upload};
    std::uint32_t access_unit_bytes{};
    std::uint32_t access_unit_prefix_be{};
    std::uint8_t first_annex_b_nal_type{};
    std::uint32_t annex_b_nal_type_mask{};
    std::uint16_t datagrams_sent{};
    bool keyframe{};
    bool repeated_content{};
    std::int32_t native_status{};
    H264EncoderBackend encoder_backend{H264EncoderBackend::none};
    GraphicsAdapterVendor capture_vendor{GraphicsAdapterVendor::unknown};
    GraphicsAdapterVendor encoder_vendor{GraphicsAdapterVendor::unknown};
    bool encoder_same_adapter{};
    bool zero_copy{};
    bool asynchronous_pipeline{};
    /** Same physical adapter, separate D3D11 devices, shared keyed textures. */
    bool async_shared_same_adapter{};
    std::uint32_t encoder_timing_fps{};
    NvencEncodeResult::Stage nvenc_stage{NvencEncodeResult::Stage::none};
    MediaFoundationEncodeResult::Stage media_foundation_stage{
        MediaFoundationEncodeResult::Stage::none};
    VideoPublishResult::Stage publish_stage{VideoPublishResult::Stage::none};
};

struct DesktopVideoEncoderDiagnostics {
    DesktopVideoInitializationStage initialization_stage{
        DesktopVideoInitializationStage::none};
    DesktopVideoInitializationStage last_failure_stage{
        DesktopVideoInitializationStage::none};
    H264EncoderBackend backend{H264EncoderBackend::none};
    GraphicsAdapterVendor capture_vendor{GraphicsAdapterVendor::unknown};
    GraphicsAdapterVendor encoder_vendor{GraphicsAdapterVendor::unknown};
    HostEncoderCandidate selected_candidate{HostEncoderCandidate::software_cpu};
    HostEncoderCandidate last_failed_candidate{HostEncoderCandidate::software_cpu};
    std::uint32_t attempted_candidate_mask{};
    std::uint32_t failed_candidate_mask{};
    std::int32_t last_failure_status{};
    std::int32_t capture_hresult{};
    std::uint32_t publisher_socket_error{};
    bool has_selected_candidate{};
    bool has_failed_candidate{};
    bool hardware{};
    bool same_adapter{};
    std::uint32_t adapter_vendor_id{};
    std::uint32_t adapter_luid_low{};
    std::int32_t adapter_luid_high{};
    std::uint32_t matching_hardware_transforms{};
    std::string transform_name;
    std::string transform_clsid;
};

/** Composes the Windows hot path without knowing Android inference or control policy. */
class DesktopVideoAgent final {
public:
    DesktopVideoAgent() noexcept = default;
    DesktopVideoAgent(const DesktopVideoAgent&) = delete;
    DesktopVideoAgent& operator=(const DesktopVideoAgent&) = delete;

    [[nodiscard]] bool initialize(const DesktopVideoAgentConfig& config) noexcept;
    [[nodiscard]] DesktopVideoStepMetrics publish_next() noexcept;
    [[nodiscard]] bool try_pop_completed(DesktopVideoStepMetrics& destination) noexcept;
    [[nodiscard]] const DesktopVideoEncoderDiagnostics& encoder_diagnostics() const noexcept;
    void request_idr() noexcept;
    void reset() noexcept;

private:
    [[nodiscard]] bool fail_initialization(
        DesktopVideoInitializationStage stage, std::int32_t native_status) noexcept;
    void release_runtime_resources() noexcept;
    void populate_common_metrics(DesktopVideoStepMetrics& destination) const noexcept;
    [[nodiscard]] DesktopVideoStepMetrics make_hybrid_completion(
        const HybridGpuCompletionMetrics& completion) const noexcept;

    DxgiDesktopCapture capture_;
    HybridGpuVideoPipeline hybrid_pipeline_;
    D3D11FrameBridge frame_bridge_;
    NvencH264Encoder encoder_;
    MediaFoundationH264Encoder media_foundation_encoder_;
    UdpVideoPublisher publisher_;
    DesktopVideoAgentConfig config_{};
    std::uint32_t next_frame_sequence_{};
    std::uint64_t next_source_sequence_{};
    std::uint64_t last_video_submission_us_{};
    std::uint64_t last_submitted_content_sequence_{};
    std::uint64_t last_idr_us{};
    bool force_idr_next_{};
    H264EncoderBackend encoder_backend_{H264EncoderBackend::none};
    GraphicsAdapterVendor capture_vendor_{GraphicsAdapterVendor::unknown};
    GraphicsAdapterVendor encoder_vendor_{GraphicsAdapterVendor::unknown};
    bool encoder_same_adapter_{};
    bool zero_copy_{};
    bool hybrid_pipeline_active_{};
    bool async_shared_same_adapter_{};
    std::uint32_t encoder_timing_fps_{};
    DesktopVideoEncoderDiagnostics encoder_diagnostics_{};
    bool initialized_{};
};

}  // namespace vfdual
