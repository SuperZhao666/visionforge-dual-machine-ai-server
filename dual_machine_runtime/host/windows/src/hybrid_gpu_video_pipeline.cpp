#include "vfdual/hybrid_gpu_video_pipeline.hpp"

#include "vfdual/dxgi_frame_semantics.hpp"
#include "vfdual/hybrid_gpu_pipeline_policy.hpp"
#include "vfdual/protocol.hpp"
#include "vfdual/udp_video_publisher.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d3d11.h>
#include <d3d11_1.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <new>
#include <mutex>
#include <span>
#include <thread>
#include <utility>
#include <vector>

namespace vfdual {
namespace {

using Microsoft::WRL::ComPtr;
constexpr std::size_t kTransferSlotCount = 3U;
constexpr std::size_t kCompletionCapacity = 64U;
constexpr UINT kNvidiaVendorId = 0x10DEU;
constexpr std::uint64_t kPeriodicIdrIntervalUs = 1'000'000ULL;
constexpr DWORD kProducerKeyedMutexWaitMs = 0U;
constexpr DWORD kWorkerKeyedMutexWaitMs = 2U;
constexpr DWORD kShutdownKeyedMutexWaitMs = 50U;
constexpr UINT64 kProducerTextureKey = 0U;
constexpr UINT64 kWorkerTextureKey = 1U;
constexpr DWORD kHighResolutionWaitableTimerFlag =
    0x00000002U;  // CREATE_WAITABLE_TIMER_HIGH_RESOLUTION

std::uint64_t monotonic_microseconds() noexcept {
    static const std::int64_t frequency = []() noexcept {
        LARGE_INTEGER value{};
        QueryPerformanceFrequency(&value);
        return value.QuadPart;
    }();
    LARGE_INTEGER value{};
    QueryPerformanceCounter(&value);
    if (frequency <= 0 || value.QuadPart <= 0) return 0U;
    return qpc_ticks_to_microseconds(
        static_cast<std::uint64_t>(value.QuadPart),
        static_cast<std::uint64_t>(frequency));
}

HRESULT create_nvidia_device(
    ComPtr<ID3D11Device>& device, ComPtr<ID3D11DeviceContext>& context) noexcept {
    ComPtr<IDXGIFactory1> factory;
    HRESULT result = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(result)) return result;
    for (UINT index = 0; ; ++index) {
        ComPtr<IDXGIAdapter1> adapter;
        result = factory->EnumAdapters1(index, &adapter);
        if (result == DXGI_ERROR_NOT_FOUND || FAILED(result)) return result;
        DXGI_ADAPTER_DESC1 description{};
        result = adapter->GetDesc1(&description);
        if (FAILED(result)) return result;
        if (description.VendorId != kNvidiaVendorId) continue;
        constexpr D3D_FEATURE_LEVEL levels[]{D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
        D3D_FEATURE_LEVEL selected{};
        return D3D11CreateDevice(
            adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT, levels,
            static_cast<UINT>(std::size(levels)), D3D11_SDK_VERSION,
            &device, &selected, &context);
    }
}

[[nodiscard]] bool same_luid(const LUID& left, const LUID& right) noexcept {
    return left.LowPart == right.LowPart && left.HighPart == right.HighPart;
}

HRESULT adapter_luid_for_device(ID3D11Device* device, LUID& destination) noexcept {
    if (device == nullptr) return E_INVALIDARG;
    ComPtr<IDXGIDevice> dxgi_device;
    HRESULT result = device->QueryInterface(IID_PPV_ARGS(&dxgi_device));
    if (FAILED(result)) return result;
    ComPtr<IDXGIAdapter> adapter;
    result = dxgi_device->GetAdapter(&adapter);
    if (FAILED(result)) return result;
    DXGI_ADAPTER_DESC description{};
    result = adapter->GetDesc(&description);
    if (SUCCEEDED(result)) destination = description.AdapterLuid;
    return result;
}

HRESULT create_device_for_adapter_luid(
    const LUID& target_luid, ComPtr<ID3D11Device>& device,
    ComPtr<ID3D11DeviceContext>& context) noexcept {
    ComPtr<IDXGIFactory1> factory;
    HRESULT result = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(result)) return result;
    for (UINT index = 0; ; ++index) {
        ComPtr<IDXGIAdapter1> adapter;
        result = factory->EnumAdapters1(index, &adapter);
        if (result == DXGI_ERROR_NOT_FOUND || FAILED(result)) return result;
        DXGI_ADAPTER_DESC1 description{};
        result = adapter->GetDesc1(&description);
        if (FAILED(result)) return result;
        if (!same_luid(description.AdapterLuid, target_luid)) continue;
        constexpr D3D_FEATURE_LEVEL levels[]{
            D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
        D3D_FEATURE_LEVEL selected{};
        return D3D11CreateDevice(
            adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT, levels,
            static_cast<UINT>(std::size(levels)), D3D11_SDK_VERSION,
            &device, &selected, &context);
    }
}

void describe_access_unit(
    std::span<const std::byte> access_unit,
    HybridGpuCompletionMetrics& metrics) noexcept {
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
            std::to_integer<std::uint8_t>(access_unit[index + (long_start ? 4U : 3U)]) & 0x1fU;
        if (metrics.first_annex_b_nal_type == 0U) {
            metrics.first_annex_b_nal_type = nal_type;
        }
        metrics.annex_b_nal_type_mask |= 1U << nal_type;
    }
}

}  // namespace

struct HybridGpuVideoPipeline::State final {
    struct FrameMetadata {
        std::uint64_t source_sequence{};
        std::uint64_t capture_present_us{};
        std::uint64_t capture_us{};
        std::uint32_t accumulated_frames{1U};
        std::uint32_t missed_present_frames{};
        bool repeated_content{};
        std::uint64_t readback_wait_us{};
        std::uint64_t readback_copy_us{};
    };

    struct StagingSlot {
        ComPtr<ID3D11Texture2D> texture;
        FrameMetadata metadata{};
        std::uint64_t copy_issued_us{};
        std::uint64_t submission_ticket{};
    };

    struct CpuFrameSlot {
        std::vector<std::byte> pixels;
        FrameMetadata metadata{};
    };

    struct SourceSharedSlot {
        ComPtr<ID3D11Texture2D> texture;
        ComPtr<IDXGIKeyedMutex> keyed_mutex;
        HANDLE shared_handle{};
        FrameMetadata metadata{};
    };

    struct WorkerSharedSlot {
        ComPtr<ID3D11Texture2D> texture;
        ComPtr<IDXGIKeyedMutex> keyed_mutex;
    };

    mutable std::mutex api_mutex;
    ComPtr<ID3D11Device> source_device;
    ComPtr<ID3D11DeviceContext> source_context;
    std::array<StagingSlot, kTransferSlotCount> staging_slots;
    PendingSlotPolicy<kTransferSlotCount> staging_policy;
    std::uint64_t next_submission_ticket{};
    std::array<SourceSharedSlot, kTransferSlotCount> source_shared_slots;
    SharedTextureMailboxPolicy<kTransferSlotCount> shared_policy;
    LUID source_adapter_luid{};

    mutable std::mutex worker_mutex;
    std::condition_variable worker_cv;
    std::array<CpuFrameSlot, kTransferSlotCount> cpu_slots;
    LatestOnlySlotPolicy<kTransferSlotCount> cpu_policy;
    FixedLatestRing<HybridGpuCompletionMetrics, kCompletionCapacity> completions;
    std::thread worker;
    HybridGpuVideoPipelineConfig config{};
    bool stop_requested{};
    bool worker_initialization_complete{};
    bool worker_ready{};
    bool worker_keys_returned{true};
    bool initialized{};
    HANDLE worker_wake_event{};
    HANDLE worker_timer{};

    std::atomic<std::uint64_t> idr_request_generation{};
    std::atomic<std::uint64_t> frames_submitted{};
    std::atomic<std::uint64_t> staging_busy{};
    std::atomic<std::uint64_t> was_still_drawing{};
    std::atomic<std::uint64_t> mailbox_superseded{};
    std::atomic<std::uint64_t> published{};
    std::atomic<std::uint64_t> completion_metrics_dropped{};
    std::atomic<std::uint32_t> staging_high_watermark{};
    std::atomic<std::uint32_t> mailbox_high_watermark{};
    std::atomic<std::uint32_t> completion_high_watermark{};
    std::atomic<std::uint64_t> mailbox_replaced{};
    std::atomic<std::uint64_t> ring_busy{};
    std::atomic<std::uint64_t> keyed_timeout{};
    std::atomic<std::uint64_t> latest_worker_frame_age_us{};
    std::atomic<std::uint64_t> maximum_worker_frame_age_us{};
    std::atomic<bool> source_readback_pending{};

    mutable std::mutex fatal_mutex;
    HybridGpuFatalFailure fatal{};
    std::atomic<bool> has_fatal{};

    void update_high_watermark(
        std::atomic<std::uint32_t>& destination, std::uint32_t candidate) noexcept {
        std::uint32_t current = destination.load(std::memory_order_relaxed);
        while (current < candidate &&
               !destination.compare_exchange_weak(
                   current, candidate, std::memory_order_relaxed)) {
        }
    }

    void observe_worker_frame_age(std::uint64_t age_us) noexcept {
        latest_worker_frame_age_us.store(age_us, std::memory_order_relaxed);
        std::uint64_t current =
            maximum_worker_frame_age_us.load(std::memory_order_relaxed);
        while (current < age_us &&
               !maximum_worker_frame_age_us.compare_exchange_weak(
                   current, age_us, std::memory_order_relaxed)) {
        }
    }

    void record_fatal(
        HybridGpuFatalStage stage, std::int32_t native_status,
        std::uint64_t source_sequence) noexcept {
        {
            std::lock_guard lock(fatal_mutex);
            if (has_fatal.load(std::memory_order_relaxed)) return;
            fatal = {true, stage, native_status, source_sequence};
            has_fatal.store(true, std::memory_order_release);
        }
        {
            std::lock_guard lock(worker_mutex);
            stop_requested = true;
        }
        worker_cv.notify_all();
        signal_worker();
    }

    void signal_worker() noexcept {
        if (worker_wake_event != nullptr) {
            static_cast<void>(SetEvent(worker_wake_event));
        }
    }

    [[nodiscard]] HRESULT create_worker_wait_handles() noexcept {
        worker_wake_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (worker_wake_event == nullptr) {
            return HRESULT_FROM_WIN32(GetLastError());
        }
        worker_timer = CreateWaitableTimerExW(
            nullptr, nullptr, kHighResolutionWaitableTimerFlag,
            TIMER_MODIFY_STATE | SYNCHRONIZE);
        if (worker_timer == nullptr) {
            worker_timer = CreateWaitableTimerExW(
                nullptr, nullptr, 0U, TIMER_MODIFY_STATE | SYNCHRONIZE);
        }
        return worker_timer != nullptr
            ? S_OK
            : HRESULT_FROM_WIN32(GetLastError());
    }

    void push_completion(HybridGpuCompletionMetrics metrics) noexcept {
        std::lock_guard lock(worker_mutex);
        if (completions.push(std::move(metrics))) {
            completion_metrics_dropped.fetch_add(1U, std::memory_order_relaxed);
        }
        update_high_watermark(
            completion_high_watermark,
            static_cast<std::uint32_t>(completions.size()));
    }

    void release_worker_slot(std::size_t index) noexcept {
        std::lock_guard lock(worker_mutex);
        cpu_policy.release_worker(index);
    }

    [[nodiscard]] bool initialize_worker_resources(
        ComPtr<ID3D11Device>& encoder_device,
        ComPtr<ID3D11DeviceContext>& encoder_context,
        ComPtr<ID3D11Texture2D>& encoder_texture,
        std::array<WorkerSharedSlot, kTransferSlotCount>& worker_shared_slots,
        NvencH264Encoder& encoder,
        UdpVideoPublisher& publisher) noexcept {
        const bool shared_mode =
            config.transfer_mode ==
            HybridGpuTransferMode::same_adapter_shared_texture;
        HRESULT result = shared_mode
            ? create_device_for_adapter_luid(
                  source_adapter_luid, encoder_device, encoder_context)
            : create_nvidia_device(encoder_device, encoder_context);
        if (FAILED(result)) {
            record_fatal(HybridGpuFatalStage::worker_device, result, 0);
            return false;
        }
        if (!shared_mode) {
            D3D11_TEXTURE2D_DESC description{};
            description.Width = config.encoder.width;
            description.Height = config.encoder.height;
            description.MipLevels = 1U;
            description.ArraySize = 1U;
            description.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
            description.SampleDesc.Count = 1U;
            description.Usage = D3D11_USAGE_DEFAULT;
            description.BindFlags = D3D11_BIND_SHADER_RESOURCE;
            result = encoder_device->CreateTexture2D(
                &description, nullptr, &encoder_texture);
            if (FAILED(result)) {
                record_fatal(HybridGpuFatalStage::worker_texture, result, 0);
                return false;
            }
        }
        if (shared_mode) {
            ComPtr<ID3D11Device1> device1;
            result = encoder_device.As(&device1);
            if (FAILED(result)) {
                record_fatal(HybridGpuFatalStage::worker_device, result, 0);
                return false;
            }
            for (std::size_t index = 0; index < kTransferSlotCount; ++index) {
                const HANDLE handle = source_shared_slots[index].shared_handle;
                if (handle == nullptr) {
                    record_fatal(
                        HybridGpuFatalStage::worker_texture, E_HANDLE, 0);
                    return false;
                }
                result = device1->OpenSharedResource1(
                    handle, IID_PPV_ARGS(&worker_shared_slots[index].texture));
                if (FAILED(result)) {
                    record_fatal(
                        HybridGpuFatalStage::worker_texture, result, 0);
                    return false;
                }
                result = worker_shared_slots[index].texture.As(
                    &worker_shared_slots[index].keyed_mutex);
                if (FAILED(result)) {
                    record_fatal(
                        HybridGpuFatalStage::worker_texture, result, 0);
                    return false;
                }
            }
        }
        if (!encoder.initialize(encoder_device.Get(), config.encoder)) {
            record_fatal(
                HybridGpuFatalStage::encoder_initialize,
                encoder.last_nvenc_status(), 0);
            return false;
        }
        if (!publisher.connect_to(
                config.phone_host, config.phone_port,
                config.local_port, config.local_host,
                config.data_plane_permit)) {
            record_fatal(
                HybridGpuFatalStage::publisher_connect,
                static_cast<std::int32_t>(publisher.last_socket_error()), 0);
            return false;
        }
        return true;
    }

    [[nodiscard]] std::optional<std::size_t> take_latest_cpu_frame() noexcept {
        std::lock_guard lock(worker_mutex);
        return cpu_policy.take_latest();
    }

    bool encode_and_publish(
        const FrameMetadata& frame,
        ID3D11Texture2D* encoder_texture,
        bool cadence_repeat,
        std::uint64_t upload_us,
        NvencH264Encoder& encoder,
        UdpVideoPublisher& publisher,
        std::uint32_t& next_frame_id,
        std::uint64_t& consumed_idr_generation,
        std::uint64_t& last_keyframe_us) noexcept {
        HybridGpuCompletionMetrics metrics{};
        metrics.source_sequence = frame.source_sequence;
        metrics.capture_present_us = frame.capture_present_us;
        metrics.capture_us = frame.capture_us;
        metrics.accumulated_frames = frame.accumulated_frames;
        metrics.missed_present_frames = frame.missed_present_frames;
        metrics.repeated_content = frame.repeated_content || cadence_repeat;
        metrics.readback_wait_us = frame.readback_wait_us;
        metrics.readback_copy_us = frame.readback_copy_us;
        metrics.upload_us = upload_us;

        const std::uint64_t encode_started = monotonic_microseconds();
        if (frame.capture_present_us != 0U &&
            encode_started >= frame.capture_present_us) {
            metrics.worker_frame_age_us =
                encode_started - frame.capture_present_us;
            observe_worker_frame_age(metrics.worker_frame_age_us);
        }
        const std::uint64_t requested_generation =
            idr_request_generation.load(std::memory_order_acquire);
        const bool explicit_idr = requested_generation > consumed_idr_generation;
        const bool periodic_idr = last_keyframe_us == 0U ||
            encode_started - last_keyframe_us >= kPeriodicIdrIntervalUs;
        const NvencEncodeResult encoded = encoder.encode(
            encoder_texture, explicit_idr || periodic_idr);
        metrics.encode_us = monotonic_microseconds() - encode_started;
        metrics.native_status = encoded.nvenc_status;
        metrics.nvenc_stage = encoded.stage;
        metrics.access_unit_bytes = encoded.bytes;
        metrics.keyframe = encoded.keyframe;
        if (!encoded.success) {
            metrics.status = HybridGpuCompletionStatus::encode_failed;
            push_completion(metrics);
            record_fatal(
                HybridGpuFatalStage::encode, encoded.nvenc_status,
                metrics.source_sequence);
            return false;
        }
        if (explicit_idr) consumed_idr_generation = requested_generation;
        if (encoded.keyframe) last_keyframe_us = encode_started;

        metrics.repeated_content = wire_frame_repeats_content(
            metrics.repeated_content,
            explicit_idr && encoded.keyframe);
        const std::span<const std::byte> access_unit = encoder.access_unit();
        describe_access_unit(access_unit, metrics);
        metrics.frame_id = next_frame_id;
        next_frame_id = next_video_logical_frame_sequence(next_frame_id);
        const std::uint64_t publish_started = monotonic_microseconds();
        const VideoPublishResult sent = publisher.publish(
            metrics.frame_id, access_unit, publish_started,
            metrics.repeated_content);
        const std::uint64_t publish_completed = monotonic_microseconds();
        metrics.publish_us = publish_completed - publish_started;
        metrics.datagrams_sent = sent.fragments_sent;
        metrics.publish_stage = sent.stage;
        if (frame.capture_present_us != 0U &&
            publish_completed >= frame.capture_present_us) {
            metrics.capture_to_publish_age_us =
                publish_completed - frame.capture_present_us;
        }
        if (!sent.success) {
            if (sent.stage ==
                VideoPublishResult::Stage::authorization_check) {
                metrics.status =
                    HybridGpuCompletionStatus::data_plane_closed;
                push_completion(metrics);
                return true;
            }
            metrics.status = HybridGpuCompletionStatus::publish_failed;
            metrics.native_status = static_cast<std::int32_t>(publisher.last_socket_error());
            push_completion(metrics);
            record_fatal(
                HybridGpuFatalStage::publish, metrics.native_status,
                metrics.source_sequence);
            return false;
        }
        metrics.status = HybridGpuCompletionStatus::frame_published;
        published.fetch_add(1U, std::memory_order_relaxed);
        push_completion(metrics);
        return true;
    }

    void upload_cpu_frame(
        std::size_t slot_index,
        ID3D11DeviceContext* encoder_context,
        ID3D11Texture2D* encoder_texture,
        FrameMetadata& current_frame,
        std::uint64_t& upload_us) noexcept {
        CpuFrameSlot& frame = cpu_slots[slot_index];
        const std::uint64_t upload_started = monotonic_microseconds();
        encoder_context->UpdateSubresource(
            encoder_texture, 0, nullptr, frame.pixels.data(),
            config.encoder.width * 4U, 0);
        upload_us = monotonic_microseconds() - upload_started;
        current_frame = frame.metadata;
    }

    enum class SharedKeyAcquireStatus { acquired, timeout, failed };

    [[nodiscard]] SharedKeyAcquireStatus acquire_worker_key(
        WorkerSharedSlot& slot, DWORD timeout_ms,
        HRESULT& native_status) noexcept {
        native_status = slot.keyed_mutex->AcquireSync(
            kWorkerTextureKey, timeout_ms);
        if (native_status == S_OK) return SharedKeyAcquireStatus::acquired;
        if (native_status == static_cast<HRESULT>(WAIT_TIMEOUT)) {
            keyed_timeout.fetch_add(1U, std::memory_order_relaxed);
            return SharedKeyAcquireStatus::timeout;
        }
        return SharedKeyAcquireStatus::failed;
    }

    [[nodiscard]] bool release_worker_key(
        std::size_t index, WorkerSharedSlot& slot,
        std::uint64_t source_sequence) noexcept {
        const HRESULT result = slot.keyed_mutex->ReleaseSync(kProducerTextureKey);
        if (FAILED(result)) {
            record_fatal(
                HybridGpuFatalStage::worker_texture, result, source_sequence);
            return false;
        }
        {
            std::lock_guard lock(worker_mutex);
            shared_policy.release_worker(index);
        }
        return true;
    }

    [[nodiscard]] bool reclaim_one_retired_shared_slot(
        std::array<WorkerSharedSlot, kTransferSlotCount>& worker_slots) noexcept {
        std::optional<std::size_t> index;
        {
            std::lock_guard lock(worker_mutex);
            index = shared_policy.take_retired();
        }
        if (!index.has_value()) return false;
        HRESULT status{};
        const SharedKeyAcquireStatus acquired = acquire_worker_key(
            worker_slots[*index], kProducerKeyedMutexWaitMs, status);
        if (acquired == SharedKeyAcquireStatus::timeout) {
            std::lock_guard lock(worker_mutex);
            shared_policy.retire_worker(*index);
            return false;
        }
        if (acquired == SharedKeyAcquireStatus::failed) {
            record_fatal(
                HybridGpuFatalStage::worker_texture, status,
                source_shared_slots[*index].metadata.source_sequence);
            return false;
        }
        return release_worker_key(
            *index, worker_slots[*index],
            source_shared_slots[*index].metadata.source_sequence);
    }

    void reclaim_retired_shared_slots(
        std::array<WorkerSharedSlot, kTransferSlotCount>& worker_slots) noexcept {
        while (!has_fatal.load(std::memory_order_acquire) &&
               reclaim_one_retired_shared_slot(worker_slots)) {
        }
    }

    [[nodiscard]] bool acquire_latest_shared_frame(
        std::array<WorkerSharedSlot, kTransferSlotCount>& worker_slots,
        FrameMetadata& current_frame,
        std::optional<std::size_t>& acquired_index) noexcept {
        acquired_index.reset();
        std::optional<std::size_t> index;
        {
            std::lock_guard lock(worker_mutex);
            index = shared_policy.take_latest();
        }
        if (!index.has_value()) return true;

        HRESULT status{};
        const SharedKeyAcquireStatus acquired = acquire_worker_key(
            worker_slots[*index], kWorkerKeyedMutexWaitMs, status);
        if (acquired == SharedKeyAcquireStatus::timeout) {
            std::lock_guard lock(worker_mutex);
            shared_policy.defer_worker(*index);
            return true;
        }
        if (acquired == SharedKeyAcquireStatus::failed) {
            record_fatal(
                HybridGpuFatalStage::worker_texture, status,
                source_shared_slots[*index].metadata.source_sequence);
            return false;
        }

        current_frame = source_shared_slots[*index].metadata;
        acquired_index = index;
        return true;
    }

    void return_pending_shared_keys(
        std::array<WorkerSharedSlot, kTransferSlotCount>& worker_slots) noexcept {
        while (true) {
            std::optional<std::size_t> index;
            {
                std::lock_guard lock(worker_mutex);
                index = shared_policy.take_latest();
                if (!index.has_value()) index = shared_policy.take_retired();
            }
            if (!index.has_value()) break;
            HRESULT status{};
            const SharedKeyAcquireStatus acquired = acquire_worker_key(
                worker_slots[*index], kShutdownKeyedMutexWaitMs, status);
            if (acquired != SharedKeyAcquireStatus::acquired) {
                record_fatal(
                    HybridGpuFatalStage::worker_texture, status,
                    source_shared_slots[*index].metadata.source_sequence);
                break;
            }
            if (!release_worker_key(
                    *index, worker_slots[*index],
                    source_shared_slots[*index].metadata.source_sequence)) {
                break;
            }
        }
    }

    enum class WorkerWaitStatus { ready, stopped, failed };

    [[nodiscard]] WorkerWaitStatus wait_for_worker_activity(
        std::chrono::steady_clock::time_point idle_repeat_deadline) noexcept {
        {
            std::lock_guard lock(worker_mutex);
            if (stop_requested) return WorkerWaitStatus::stopped;
        }
        const auto before_wait = std::chrono::steady_clock::now();
        if (before_wait >= idle_repeat_deadline) return WorkerWaitStatus::ready;

        const auto remaining = std::chrono::duration_cast<
            std::chrono::nanoseconds>(idle_repeat_deadline - before_wait);
        LARGE_INTEGER due_time{};
        due_time.QuadPart = relative_waitable_timer_due_100ns(
            static_cast<std::uint64_t>(remaining.count()));
        if (!SetWaitableTimerEx(
                worker_timer, &due_time, 0, nullptr,
                nullptr, nullptr, 0U)) {
            record_fatal(
                HybridGpuFatalStage::worker_exception,
                HRESULT_FROM_WIN32(GetLastError()), 0U);
            return WorkerWaitStatus::failed;
        }
        const std::array<HANDLE, 2U> handles{
            worker_wake_event, worker_timer};
        const DWORD result = WaitForMultipleObjects(
            static_cast<DWORD>(handles.size()), handles.data(), FALSE, INFINITE);
        if (result == WAIT_FAILED) {
            record_fatal(
                HybridGpuFatalStage::worker_exception,
                HRESULT_FROM_WIN32(GetLastError()), 0U);
            return WorkerWaitStatus::failed;
        }
        if (result != WAIT_OBJECT_0 && result != WAIT_OBJECT_0 + 1U) {
            record_fatal(HybridGpuFatalStage::worker_exception, E_FAIL, 0U);
            return WorkerWaitStatus::failed;
        }
        std::lock_guard lock(worker_mutex);
        return stop_requested
            ? WorkerWaitStatus::stopped
            : WorkerWaitStatus::ready;
    }

    [[nodiscard]] WorkerWaitStatus wait_for_worker_signal() noexcept {
        {
            std::lock_guard lock(worker_mutex);
            if (stop_requested) return WorkerWaitStatus::stopped;
        }
        const DWORD result = WaitForSingleObject(worker_wake_event, INFINITE);
        if (result == WAIT_FAILED) {
            record_fatal(
                HybridGpuFatalStage::worker_exception,
                HRESULT_FROM_WIN32(GetLastError()), 0U);
            return WorkerWaitStatus::failed;
        }
        if (result != WAIT_OBJECT_0) {
            record_fatal(HybridGpuFatalStage::worker_exception, E_FAIL, 0U);
            return WorkerWaitStatus::failed;
        }
        std::lock_guard lock(worker_mutex);
        return stop_requested
            ? WorkerWaitStatus::stopped
            : WorkerWaitStatus::ready;
    }

    [[nodiscard]] bool run_cpu_worker(
        ID3D11DeviceContext* encoder_context,
        ID3D11Texture2D* encoder_texture,
        NvencH264Encoder& encoder,
        UdpVideoPublisher& publisher) noexcept {
        using Clock = std::chrono::steady_clock;
        const auto period = std::chrono::nanoseconds{
            (std::max)(
                1LL, 1'000'000'000LL /
                    static_cast<std::int64_t>(config.encoder.frames_per_second))};
        auto next_idle_repeat_at = Clock::now() + period;
        std::uint32_t next_frame_id{};
        std::uint64_t consumed_idr_generation{};
        std::uint64_t last_keyframe_us{};
        FrameMetadata current_frame{};
        bool has_current_frame{};
        if (worker_wake_event == nullptr || worker_timer == nullptr) {
            record_fatal(HybridGpuFatalStage::worker_exception, E_HANDLE, 0U);
            return false;
        }

        while (true) {
            const WorkerWaitStatus wait_status =
                wait_for_worker_activity(next_idle_repeat_at);
            if (wait_status == WorkerWaitStatus::stopped) return true;
            if (wait_status == WorkerWaitStatus::failed) return false;
            const auto now = Clock::now();

            std::uint64_t upload_us{};
            bool updated{};
            const std::optional<std::size_t> slot = take_latest_cpu_frame();
            // A fresh mailbox frame bypasses the idle-repeat timer. The timer
            // exists only to refresh truly static content; it is never an FPS
            // gate for new capture frames.
            if (idle_repeat_must_defer_to_source(
                    slot.has_value(), source_readback_pending.load(
                        std::memory_order_acquire))) {
                next_idle_repeat_at = now + period;
                continue;
            }
            if (!slot.has_value() && now < next_idle_repeat_at) continue;
            if (slot.has_value()) {
                upload_cpu_frame(
                    *slot, encoder_context, encoder_texture,
                    current_frame, upload_us);
                release_worker_slot(*slot);
                has_current_frame = true;
                updated = true;
            }
            if (!has_current_frame) {
                next_idle_repeat_at = Clock::now() + period;
                continue;
            }
            if (!encode_and_publish(
                    current_frame, encoder_texture, !updated, upload_us,
                    encoder, publisher, next_frame_id,
                    consumed_idr_generation, last_keyframe_us)) {
                return false;
            }

            const auto completed_at = Clock::now();
            if (updated) {
                next_idle_repeat_at = completed_at + period;
                continue;
            }
            const auto previous_deadline_ns = std::chrono::duration_cast<
                std::chrono::nanoseconds>(
                    next_idle_repeat_at.time_since_epoch()).count();
            const auto completed_at_ns = std::chrono::duration_cast<
                std::chrono::nanoseconds>(
                    completed_at.time_since_epoch()).count();
            const std::uint64_t advanced_deadline_ns =
                advance_absolute_deadline(
                    static_cast<std::uint64_t>(previous_deadline_ns),
                    static_cast<std::uint64_t>(completed_at_ns),
                    static_cast<std::uint64_t>(period.count()));
            next_idle_repeat_at = Clock::time_point{
                std::chrono::nanoseconds{
                    static_cast<std::int64_t>(advanced_deadline_ns)}};
        }
    }

    [[nodiscard]] bool run_shared_worker(
        std::array<WorkerSharedSlot, kTransferSlotCount>& worker_slots,
        NvencH264Encoder& encoder,
        UdpVideoPublisher& publisher) noexcept {
        std::uint32_t next_frame_id{};
        std::uint64_t consumed_idr_generation{};
        std::uint64_t last_keyframe_us{};
        FrameMetadata current_frame{};
        if (worker_wake_event == nullptr) {
            record_fatal(HybridGpuFatalStage::worker_exception, E_HANDLE, 0U);
            return false;
        }

        while (true) {
            const WorkerWaitStatus wait_status = wait_for_worker_signal();
            if (wait_status == WorkerWaitStatus::stopped) return true;
            if (wait_status == WorkerWaitStatus::failed) return false;

            reclaim_retired_shared_slots(worker_slots);
            if (has_fatal.load(std::memory_order_acquire)) return false;

            std::optional<std::size_t> index;
            if (!acquire_latest_shared_frame(
                    worker_slots, current_frame, index)) {
                return false;
            }
            if (!index.has_value()) continue;

            const bool published = encode_and_publish(
                current_frame, worker_slots[*index].texture.Get(), false, 0U,
                encoder, publisher, next_frame_id,
                consumed_idr_generation, last_keyframe_us);
            const bool released = release_worker_key(
                *index, worker_slots[*index], current_frame.source_sequence);
            if (!published || !released) return false;
        }
    }

    void worker_main() noexcept {
        std::array<WorkerSharedSlot, kTransferSlotCount> worker_shared_slots;
        try {
            ComPtr<ID3D11Device> encoder_device;
            ComPtr<ID3D11DeviceContext> encoder_context;
            ComPtr<ID3D11Texture2D> encoder_texture;
            NvencH264Encoder encoder;
            UdpVideoPublisher publisher;
            const bool ready = initialize_worker_resources(
                encoder_device, encoder_context, encoder_texture,
                worker_shared_slots, encoder, publisher);
            {
                std::lock_guard lock(worker_mutex);
                worker_ready = ready;
                worker_initialization_complete = true;
            }
            worker_cv.notify_all();
            if (ready) {
                if (config.transfer_mode ==
                    HybridGpuTransferMode::same_adapter_shared_texture) {
                    static_cast<void>(run_shared_worker(
                        worker_shared_slots, encoder, publisher));
                } else {
                    static_cast<void>(run_cpu_worker(
                        encoder_context.Get(), encoder_texture.Get(),
                        encoder, publisher));
                }
            }
            publisher.reset();
            encoder.reset();
            if (config.transfer_mode ==
                HybridGpuTransferMode::same_adapter_shared_texture) {
                return_pending_shared_keys(worker_shared_slots);
            }
        } catch (...) {
            record_fatal(HybridGpuFatalStage::worker_exception, E_FAIL, 0);
            if (config.transfer_mode ==
                HybridGpuTransferMode::same_adapter_shared_texture) {
                return_pending_shared_keys(worker_shared_slots);
            }
        }
        {
            std::lock_guard lock(worker_mutex);
            worker_ready = false;
            worker_initialization_complete = true;
            worker_keys_returned = true;
        }
        worker_cv.notify_all();
    }

    [[nodiscard]] std::array<std::size_t, kTransferSlotCount>
    oldest_pending_readback_order() const noexcept {
        std::array<std::size_t, kTransferSlotCount> order{};
        for (std::size_t index = 0; index < kTransferSlotCount; ++index) {
            order[index] = index;
        }
        std::sort(order.begin(), order.end(), [this](
            std::size_t left, std::size_t right) noexcept {
            const bool left_pending = staging_policy.is_pending(left);
            const bool right_pending = staging_policy.is_pending(right);
            if (left_pending != right_pending) return left_pending;
            return staging_slots[left].submission_ticket <
                staging_slots[right].submission_ticket;
        });
        return order;
    }

    void copy_readback_to_cpu(
        std::size_t staging_index, const D3D11_MAPPED_SUBRESOURCE& mapped,
        CpuFrameSlot& destination) noexcept {
        const std::uint64_t copy_started = monotonic_microseconds();
        const std::size_t row_bytes =
            static_cast<std::size_t>(config.encoder.width) * 4U;
        for (std::uint32_t row = 0; row < config.encoder.height; ++row) {
            const auto* source_row = static_cast<const std::byte*>(mapped.pData) +
                static_cast<std::size_t>(row) * mapped.RowPitch;
            std::memcpy(
                destination.pixels.data() +
                    static_cast<std::size_t>(row) * row_bytes,
                source_row, row_bytes);
        }
        destination.metadata = staging_slots[staging_index].metadata;
        destination.metadata.readback_wait_us =
            copy_started - staging_slots[staging_index].copy_issued_us;
        destination.metadata.readback_copy_us =
            monotonic_microseconds() - copy_started;
    }

    [[nodiscard]] std::size_t pump_unlocked() noexcept {
        if (!initialized || has_fatal.load(std::memory_order_acquire)) return 0U;
        // Keep the batch slot private until every currently readable staging
        // copy is folded in, so the worker can take only the freshest result.
        std::optional<std::size_t> batch_cpu_index;
        bool has_batch_frame{};
        const auto polling_order = oldest_pending_readback_order();
        for (const std::size_t index : polling_order) {
            if (!staging_policy.is_pending(index)) continue;
            D3D11_MAPPED_SUBRESOURCE mapped{};
            const HRESULT result = source_context->Map(
                staging_slots[index].texture.Get(), 0,
                D3D11_MAP_READ, D3D11_MAP_FLAG_DO_NOT_WAIT, &mapped);
            if (result == DXGI_ERROR_WAS_STILL_DRAWING) {
                was_still_drawing.fetch_add(1U, std::memory_order_relaxed);
                // Copies share one immediate-context command stream. Do not
                // publish a younger slot before the oldest copy is readable.
                break;
            }
            if (FAILED(result)) {
                if (batch_cpu_index.has_value()) {
                    std::lock_guard lock(worker_mutex);
                    cpu_policy.cancel_write(*batch_cpu_index);
                }
                record_fatal(
                    HybridGpuFatalStage::readback_map, result,
                    staging_slots[index].metadata.source_sequence);
                return 0U;
            }

            if (!batch_cpu_index.has_value()) {
                std::lock_guard lock(worker_mutex);
                batch_cpu_index = cpu_policy.acquire_for_write();
            }
            if (!batch_cpu_index.has_value()) {
                source_context->Unmap(staging_slots[index].texture.Get(), 0);
                break;
            }

            CpuFrameSlot& batch = cpu_slots[*batch_cpu_index];
            const bool may_supersede_batch = !has_batch_frame ||
                repeated_frame_can_supersede_mailbox(
                    batch.metadata.repeated_content,
                    staging_slots[index].metadata.repeated_content);
            if (may_supersede_batch) {
                if (has_batch_frame) {
                    mailbox_superseded.fetch_add(1U, std::memory_order_relaxed);
                }
                copy_readback_to_cpu(index, mapped, batch);
                has_batch_frame = true;
            } else {
                mailbox_superseded.fetch_add(1U, std::memory_order_relaxed);
            }
            source_context->Unmap(staging_slots[index].texture.Get(), 0);
            staging_policy.release(index);
        }

        source_readback_pending.store(
            staging_policy.pending_count() != 0U,
            std::memory_order_release);

        if (!batch_cpu_index.has_value() || !has_batch_frame) return 0U;

        bool published_to_mailbox{};
        {
            std::lock_guard lock(worker_mutex);
            const std::optional<std::size_t> pending =
                cpu_policy.mailbox_index();
            const bool may_supersede = !pending.has_value() ||
                repeated_frame_can_supersede_mailbox(
                    cpu_slots[*pending].metadata.repeated_content,
                    cpu_slots[*batch_cpu_index].metadata.repeated_content);
            if (!may_supersede) {
                cpu_policy.cancel_write(*batch_cpu_index);
                mailbox_superseded.fetch_add(1U, std::memory_order_relaxed);
            } else {
                const std::optional<std::size_t> superseded =
                    cpu_policy.publish_latest(*batch_cpu_index);
                if (superseded.has_value()) {
                    mailbox_superseded.fetch_add(1U, std::memory_order_relaxed);
                }
                update_high_watermark(mailbox_high_watermark, 1U);
                published_to_mailbox = true;
            }
        }
        if (!published_to_mailbox) return 0U;
        worker_cv.notify_one();
        signal_worker();
        return 1U;
    }

    [[nodiscard]] HRESULT create_source_shared_resources() noexcept {
        HRESULT result = adapter_luid_for_device(
            source_device.Get(), source_adapter_luid);
        if (FAILED(result)) return result;

        D3D11_TEXTURE2D_DESC description{};
        description.Width = config.encoder.width;
        description.Height = config.encoder.height;
        description.MipLevels = 1U;
        description.ArraySize = 1U;
        description.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        description.SampleDesc.Count = 1U;
        description.Usage = D3D11_USAGE_DEFAULT;
        description.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        description.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE |
            D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;
        for (SourceSharedSlot& slot : source_shared_slots) {
            result = source_device->CreateTexture2D(
                &description, nullptr, &slot.texture);
            if (FAILED(result)) return result;
            result = slot.texture.As(&slot.keyed_mutex);
            if (FAILED(result)) return result;
            ComPtr<IDXGIResource1> resource;
            result = slot.texture.As(&resource);
            if (FAILED(result)) return result;
            result = resource->CreateSharedHandle(
                nullptr,
                DXGI_SHARED_RESOURCE_READ | DXGI_SHARED_RESOURCE_WRITE,
                nullptr, &slot.shared_handle);
            if (FAILED(result)) return result;
        }
        return S_OK;
    }

    [[nodiscard]] HybridGpuSubmitResult submit_shared_unlocked(
        const HybridGpuFrameInput& input) noexcept {
        HybridGpuSubmitResult result{};
        result.source_sequence = input.source_sequence;
        std::optional<std::size_t> index;
        {
            std::lock_guard lock(worker_mutex);
            if (stop_requested) return result;
            index = shared_policy.acquire_for_copy();
        }
        if (!index.has_value()) {
            ring_busy.fetch_add(1U, std::memory_order_relaxed);
            staging_busy.fetch_add(1U, std::memory_order_relaxed);
            result.status = HybridGpuSubmitStatus::staging_busy;
            result.hresult = DXGI_ERROR_WAS_STILL_DRAWING;
            return result;
        }

        SourceSharedSlot& slot = source_shared_slots[*index];
        const HRESULT acquire_status = slot.keyed_mutex->AcquireSync(
            kProducerTextureKey, kProducerKeyedMutexWaitMs);
        if (acquire_status == static_cast<HRESULT>(WAIT_TIMEOUT)) {
            keyed_timeout.fetch_add(1U, std::memory_order_relaxed);
            staging_busy.fetch_add(1U, std::memory_order_relaxed);
            {
                std::lock_guard lock(worker_mutex);
                shared_policy.cancel_copy(*index);
            }
            result.status = HybridGpuSubmitStatus::staging_busy;
            result.hresult = acquire_status;
            return result;
        }
        if (acquire_status != S_OK) {
            {
                std::lock_guard lock(worker_mutex);
                shared_policy.cancel_copy(*index);
            }
            record_fatal(
                HybridGpuFatalStage::source_copy, acquire_status,
                input.source_sequence);
            result.status = HybridGpuSubmitStatus::fatal_failure;
            result.hresult = acquire_status;
            return result;
        }

        const std::uint64_t copy_started = monotonic_microseconds();
        source_context->CopyResource(slot.texture.Get(), input.texture);
        const HRESULT device_status = source_device->GetDeviceRemovedReason();
        if (FAILED(device_status)) {
            record_fatal(
                HybridGpuFatalStage::source_copy, device_status,
                input.source_sequence);
            const HRESULT key_status =
                slot.keyed_mutex->ReleaseSync(kProducerTextureKey);
            if (SUCCEEDED(key_status)) {
                std::lock_guard lock(worker_mutex);
                shared_policy.cancel_copy(*index);
            }
            result.status = HybridGpuSubmitStatus::fatal_failure;
            result.hresult = device_status;
            return result;
        }
        slot.metadata = {
            input.source_sequence,
            input.capture_present_us,
            input.capture_us,
            input.accumulated_frames,
            input.missed_present_frames,
            input.repeated_content,
            0U,
            0U};
        const HRESULT release_status =
            slot.keyed_mutex->ReleaseSync(kWorkerTextureKey);
        if (FAILED(release_status)) {
            record_fatal(
                HybridGpuFatalStage::source_copy, release_status,
                input.source_sequence);
            const HRESULT key_status =
                slot.keyed_mutex->ReleaseSync(kProducerTextureKey);
            if (SUCCEEDED(key_status)) {
                std::lock_guard lock(worker_mutex);
                shared_policy.cancel_copy(*index);
            }
            result.status = HybridGpuSubmitStatus::fatal_failure;
            result.hresult = release_status;
            return result;
        }

        {
            std::lock_guard lock(worker_mutex);
            const std::optional<std::size_t> replaced =
                shared_policy.publish_latest(*index);
            if (replaced.has_value()) {
                mailbox_replaced.fetch_add(1U, std::memory_order_relaxed);
                mailbox_superseded.fetch_add(1U, std::memory_order_relaxed);
            }
            update_high_watermark(mailbox_high_watermark, 1U);
            update_high_watermark(
                staging_high_watermark,
                static_cast<std::uint32_t>(shared_policy.occupied_count()));
        }
        worker_cv.notify_one();
        signal_worker();
        frames_submitted.fetch_add(1U, std::memory_order_relaxed);
        result.staging_copy_submit_us =
            monotonic_microseconds() - copy_started;
        result.status = HybridGpuSubmitStatus::accepted;
        result.hresult = S_OK;
        return result;
    }

    void clear_counters() noexcept {
        frames_submitted.store(0U, std::memory_order_relaxed);
        staging_busy.store(0U, std::memory_order_relaxed);
        was_still_drawing.store(0U, std::memory_order_relaxed);
        mailbox_superseded.store(0U, std::memory_order_relaxed);
        published.store(0U, std::memory_order_relaxed);
        completion_metrics_dropped.store(0U, std::memory_order_relaxed);
        staging_high_watermark.store(0U, std::memory_order_relaxed);
        mailbox_high_watermark.store(0U, std::memory_order_relaxed);
        completion_high_watermark.store(0U, std::memory_order_relaxed);
        mailbox_replaced.store(0U, std::memory_order_relaxed);
        ring_busy.store(0U, std::memory_order_relaxed);
        keyed_timeout.store(0U, std::memory_order_relaxed);
        latest_worker_frame_age_us.store(0U, std::memory_order_relaxed);
        maximum_worker_frame_age_us.store(0U, std::memory_order_relaxed);
        source_readback_pending.store(false, std::memory_order_relaxed);
    }

    void stop_and_release_unlocked() noexcept {
        {
            std::lock_guard api_lock(api_mutex);
            initialized = false;
        }
        {
            std::lock_guard lock(worker_mutex);
            stop_requested = true;
        }
        worker_cv.notify_all();
        signal_worker();
        if (worker.joinable() &&
            config.transfer_mode ==
                HybridGpuTransferMode::same_adapter_shared_texture) {
            std::unique_lock lock(worker_mutex);
            worker_cv.wait(lock, [this]() noexcept {
                return worker_keys_returned;
            });
        }
        try {
            if (worker.joinable()) worker.join();
        } catch (...) {
            record_fatal(HybridGpuFatalStage::worker_exception, E_FAIL, 0);
        }
        {
            std::lock_guard lock(worker_mutex);
            stop_requested = false;
            worker_initialization_complete = false;
            worker_ready = false;
            worker_keys_returned = true;
            cpu_policy.reset();
            shared_policy.reset();
            completions.reset();
        }
        for (auto& slot : cpu_slots) {
            std::vector<std::byte>{}.swap(slot.pixels);
            slot.metadata = {};
        }
        staging_policy.reset();
        for (auto& slot : staging_slots) {
            slot.texture.Reset();
            slot.metadata = {};
            slot.copy_issued_us = 0U;
            slot.submission_ticket = 0U;
        }
        for (auto& slot : source_shared_slots) {
            if (slot.shared_handle != nullptr) {
                CloseHandle(slot.shared_handle);
                slot.shared_handle = nullptr;
            }
            slot.keyed_mutex.Reset();
            slot.texture.Reset();
            slot.metadata = {};
        }
        if (worker_timer != nullptr) {
            CloseHandle(worker_timer);
            worker_timer = nullptr;
        }
        if (worker_wake_event != nullptr) {
            CloseHandle(worker_wake_event);
            worker_wake_event = nullptr;
        }
        source_context.Reset();
        source_device.Reset();
        source_adapter_luid = {};
        config = {};
        next_submission_ticket = 0U;
        idr_request_generation.store(0U, std::memory_order_relaxed);
        clear_counters();
    }

    void reset_unlocked() noexcept {
        stop_and_release_unlocked();
        {
            std::lock_guard lock(fatal_mutex);
            fatal = {};
        }
        has_fatal.store(false, std::memory_order_release);
    }
};

HybridGpuVideoPipeline::HybridGpuVideoPipeline() noexcept {
    try {
        state_ = std::make_unique<State>();
    } catch (const std::bad_alloc&) {
        construction_status_ = E_OUTOFMEMORY;
        state_.reset();
    } catch (...) {
        construction_status_ = E_FAIL;
        state_.reset();
    }
}

HybridGpuVideoPipeline::~HybridGpuVideoPipeline() { reset(); }

bool HybridGpuVideoPipeline::initialize(
    ID3D11Device* source_device, ID3D11DeviceContext* source_context,
    const HybridGpuVideoPipelineConfig& config) noexcept {
    if (!state_) return false;
    state_->reset_unlocked();
    const bool valid_transfer_mode =
        config.transfer_mode == HybridGpuTransferMode::cpu_readback ||
        config.transfer_mode ==
            HybridGpuTransferMode::same_adapter_shared_texture;
    if (source_device == nullptr || source_context == nullptr ||
        config.encoder.width != kHybridGpuFrameWidth ||
        config.encoder.height != kHybridGpuFrameHeight ||
        config.encoder.frames_per_second == 0U ||
        config.local_host.empty() || config.local_port == 0U ||
        config.phone_host.empty() || config.phone_port == 0U ||
        !config.data_plane_permit || !valid_transfer_mode) {
        return false;
    }
    try {
        {
            std::lock_guard api_lock(state_->api_mutex);
            state_->config = config;
            state_->source_device = source_device;
            state_->source_context = source_context;
            HRESULT result = state_->create_worker_wait_handles();
            if (FAILED(result)) {
                state_->record_fatal(
                    HybridGpuFatalStage::initialization_exception,
                    result, 0);
            } else if (config.transfer_mode == HybridGpuTransferMode::cpu_readback) {
                const std::size_t byte_count =
                    static_cast<std::size_t>(config.encoder.width) *
                    config.encoder.height * 4U;
                for (auto& slot : state_->cpu_slots) {
                    slot.pixels.resize(byte_count);
                }

                D3D11_TEXTURE2D_DESC staging{};
                staging.Width = config.encoder.width;
                staging.Height = config.encoder.height;
                staging.MipLevels = 1U;
                staging.ArraySize = 1U;
                staging.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
                staging.SampleDesc.Count = 1U;
                staging.Usage = D3D11_USAGE_STAGING;
                staging.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
                for (auto& slot : state_->staging_slots) {
                    result = source_device->CreateTexture2D(
                        &staging, nullptr, &slot.texture);
                    if (FAILED(result)) {
                        state_->record_fatal(
                            HybridGpuFatalStage::source_staging_texture,
                            result, 0);
                        break;
                    }
                }
            } else {
                result = state_->create_source_shared_resources();
                if (FAILED(result)) {
                    state_->record_fatal(
                        HybridGpuFatalStage::source_staging_texture,
                        result, 0);
                }
            }
        }
        if (state_->has_fatal.load(std::memory_order_acquire)) {
            state_->stop_and_release_unlocked();
            return false;
        }

        {
            std::lock_guard worker_lock(state_->worker_mutex);
            state_->worker_initialization_complete = false;
            state_->worker_ready = false;
            state_->worker_keys_returned = false;
            state_->stop_requested = false;
        }
        state_->worker = std::thread([state = state_.get()]() noexcept {
            state->worker_main();
        });
        std::unique_lock worker_lock(state_->worker_mutex);
        state_->worker_cv.wait(worker_lock, [state = state_.get()]() noexcept {
            return state->worker_initialization_complete;
        });
        const bool ready = state_->worker_ready;
        worker_lock.unlock();
        if (!ready) {
            state_->stop_and_release_unlocked();
            return false;
        }
        {
            std::lock_guard api_lock(state_->api_mutex);
            state_->initialized = true;
        }
        return true;
    } catch (const std::bad_alloc&) {
        state_->record_fatal(
            HybridGpuFatalStage::initialization_exception, E_OUTOFMEMORY, 0);
        state_->stop_and_release_unlocked();
        return false;
    } catch (...) {
        state_->record_fatal(
            HybridGpuFatalStage::initialization_exception, E_FAIL, 0);
        state_->stop_and_release_unlocked();
        return false;
    }
}

HybridGpuSubmitResult HybridGpuVideoPipeline::submit(
    const HybridGpuFrameInput& input) noexcept {
    HybridGpuSubmitResult result{};
    result.source_sequence = input.source_sequence;
    if (!state_) return result;
    std::lock_guard api_lock(state_->api_mutex);
    if (!state_->initialized) return result;
    if (state_->has_fatal.load(std::memory_order_acquire)) {
        result.status = HybridGpuSubmitStatus::fatal_failure;
        return result;
    }
    if (input.texture == nullptr) {
        result.status = HybridGpuSubmitStatus::invalid_input;
        result.hresult = E_INVALIDARG;
        return result;
    }
    D3D11_TEXTURE2D_DESC description{};
    input.texture->GetDesc(&description);
    ComPtr<ID3D11Device> texture_device;
    input.texture->GetDevice(&texture_device);
    if (description.Width != state_->config.encoder.width ||
        description.Height != state_->config.encoder.height ||
        description.Format != DXGI_FORMAT_B8G8R8A8_UNORM ||
        description.SampleDesc.Count != 1U ||
        texture_device.Get() != state_->source_device.Get()) {
        result.status = HybridGpuSubmitStatus::invalid_input;
        result.hresult = E_INVALIDARG;
        return result;
    }

    if (state_->config.transfer_mode ==
        HybridGpuTransferMode::same_adapter_shared_texture) {
        return state_->submit_shared_unlocked(input);
    }
    static_cast<void>(state_->pump_unlocked());
    if (state_->has_fatal.load(std::memory_order_acquire)) {
        result.status = HybridGpuSubmitStatus::fatal_failure;
        std::lock_guard fatal_lock(state_->fatal_mutex);
        result.hresult = state_->fatal.native_status;
        return result;
    }
    const std::optional<std::size_t> slot = state_->staging_policy.acquire();
    if (!slot.has_value()) {
        state_->staging_busy.fetch_add(1U, std::memory_order_relaxed);
        result.status = HybridGpuSubmitStatus::staging_busy;
        result.hresult = DXGI_ERROR_WAS_STILL_DRAWING;
        return result;
    }
    state_->source_readback_pending.store(true, std::memory_order_release);
    const std::uint64_t copy_started = monotonic_microseconds();
    state_->source_context->CopyResource(
        state_->staging_slots[*slot].texture.Get(), input.texture);
    const HRESULT device_status = state_->source_device->GetDeviceRemovedReason();
    if (FAILED(device_status)) {
        state_->staging_policy.release(*slot);
        state_->source_readback_pending.store(
            state_->staging_policy.pending_count() != 0U,
            std::memory_order_release);
        state_->record_fatal(
            HybridGpuFatalStage::source_copy, device_status,
            input.source_sequence);
        result.status = HybridGpuSubmitStatus::fatal_failure;
        result.hresult = device_status;
        return result;
    }
    state_->staging_slots[*slot].copy_issued_us = monotonic_microseconds();
    state_->staging_slots[*slot].submission_ticket =
        state_->next_submission_ticket++;
    state_->staging_slots[*slot].metadata = {
        input.source_sequence,
        input.capture_present_us,
        input.capture_us,
        input.accumulated_frames,
        input.missed_present_frames,
        input.repeated_content,
        0U,
        0U};
    result.staging_copy_submit_us = monotonic_microseconds() - copy_started;
    result.status = HybridGpuSubmitStatus::accepted;
    result.hresult = S_OK;
    state_->frames_submitted.fetch_add(1U, std::memory_order_relaxed);
    state_->update_high_watermark(
        state_->staging_high_watermark,
        static_cast<std::uint32_t>(state_->staging_policy.pending_count()));
    return result;
}

std::size_t HybridGpuVideoPipeline::pump() noexcept {
    if (!state_) return 0U;
    std::lock_guard api_lock(state_->api_mutex);
    if (state_->config.transfer_mode ==
        HybridGpuTransferMode::same_adapter_shared_texture) {
        return 0U;
    }
    return state_->pump_unlocked();
}

bool HybridGpuVideoPipeline::try_pop_completion(
    HybridGpuCompletionMetrics& destination) noexcept {
    if (!state_) return false;
    std::lock_guard lock(state_->worker_mutex);
    return state_->completions.pop(destination);
}

void HybridGpuVideoPipeline::request_idr() noexcept {
    if (!state_) return;
    state_->idr_request_generation.fetch_add(1U, std::memory_order_release);
}

HybridGpuPipelineCounters HybridGpuVideoPipeline::counters() const noexcept {
    if (!state_) return {};
    return {
        state_->frames_submitted.load(std::memory_order_relaxed),
        state_->staging_busy.load(std::memory_order_relaxed),
        state_->was_still_drawing.load(std::memory_order_relaxed),
        state_->mailbox_superseded.load(std::memory_order_relaxed),
        state_->published.load(std::memory_order_relaxed),
        state_->completion_metrics_dropped.load(std::memory_order_relaxed),
        state_->staging_high_watermark.load(std::memory_order_relaxed),
        state_->mailbox_high_watermark.load(std::memory_order_relaxed),
        state_->completion_high_watermark.load(std::memory_order_relaxed),
        state_->mailbox_replaced.load(std::memory_order_relaxed),
        state_->ring_busy.load(std::memory_order_relaxed),
        state_->keyed_timeout.load(std::memory_order_relaxed),
        state_->latest_worker_frame_age_us.load(std::memory_order_relaxed),
        state_->maximum_worker_frame_age_us.load(std::memory_order_relaxed),
    };
}

HybridGpuFatalFailure HybridGpuVideoPipeline::fatal_failure() const noexcept {
    if (!state_) {
        return {
            true, HybridGpuFatalStage::initialization_exception,
            construction_status_ != 0 ? construction_status_ : E_FAIL, 0};
    }
    if (!state_->has_fatal.load(std::memory_order_acquire)) return {};
    std::lock_guard lock(state_->fatal_mutex);
    return state_->fatal;
}

void HybridGpuVideoPipeline::reset() noexcept {
    if (!state_) return;
    state_->reset_unlocked();
}

}  // namespace vfdual
