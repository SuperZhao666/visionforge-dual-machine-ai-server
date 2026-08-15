#pragma once

#include "vfdual/h264_encoder_config.hpp"
#include "vfdual/model_contract.hpp"
#include "vfdual/nvenc_h264_encoder.hpp"
#include "vfdual/udp_video_publisher.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

struct ID3D11Device;
struct ID3D11DeviceContext;
struct ID3D11Texture2D;

namespace vfdual {

inline constexpr std::uint32_t kHybridGpuFrameWidth = kDefaultMobileModel.input.width;
inline constexpr std::uint32_t kHybridGpuFrameHeight = kDefaultMobileModel.input.height;

enum class HybridGpuTransferMode {
    /** Cross-adapter fallback: GPU staging -> CPU mailbox -> worker upload. */
    cpu_readback,
    /** Same-adapter path: NT shared keyed-mutex textures, with no CPU pixels. */
    same_adapter_shared_texture,
};

struct HybridGpuVideoPipelineConfig {
    H264EncoderConfig encoder{};
    std::string local_host;
    std::uint16_t local_port{};
    std::string phone_host;
    std::uint16_t phone_port{};
    VideoDataPlanePermitSource data_plane_permit;
    HybridGpuTransferMode transfer_mode{HybridGpuTransferMode::cpu_readback};
};

/** Metadata accompanying one already-cropped model-sized BGRA capture texture. */
struct HybridGpuFrameInput {
    ID3D11Texture2D* texture{};
    std::uint64_t source_sequence{};
    /** QPC-derived local time at which DXGI reported this desktop present. */
    std::uint64_t capture_present_us{};
    std::uint64_t capture_us{};
    std::uint32_t accumulated_frames{1U};
    std::uint32_t missed_present_frames{};
    bool repeated_content{};
};

enum class HybridGpuSubmitStatus {
    accepted,
    staging_busy,
    invalid_input,
    not_initialized,
    fatal_failure,
};

struct HybridGpuSubmitResult {
    HybridGpuSubmitStatus status{HybridGpuSubmitStatus::not_initialized};
    std::uint64_t source_sequence{};
    std::uint64_t staging_copy_submit_us{};
    std::int32_t hresult{};
};

enum class HybridGpuCompletionStatus {
    frame_published,
    data_plane_closed,
    encode_failed,
    publish_failed,
};

/** One bounded completion record produced by the encode/publish worker. */
struct HybridGpuCompletionMetrics {
    HybridGpuCompletionStatus status{HybridGpuCompletionStatus::encode_failed};
    std::uint64_t source_sequence{};
    std::uint32_t frame_id{};
    std::uint64_t capture_present_us{};
    std::uint64_t capture_us{};
    std::uint32_t accumulated_frames{1U};
    std::uint32_t missed_present_frames{};
    bool repeated_content{};
    std::uint64_t readback_wait_us{};
    std::uint64_t readback_copy_us{};
    std::uint64_t upload_us{};
    std::uint64_t encode_us{};
    std::uint64_t publish_us{};
    /** Age of the retained worker frame when its encode tick starts. */
    std::uint64_t worker_frame_age_us{};
    /** Local end-to-end age from capture_present_us through UDP publish. */
    std::uint64_t capture_to_publish_age_us{};
    std::uint32_t access_unit_bytes{};
    std::uint32_t access_unit_prefix_be{};
    std::uint8_t first_annex_b_nal_type{};
    std::uint32_t annex_b_nal_type_mask{};
    std::uint16_t datagrams_sent{};
    bool keyframe{};
    std::int32_t native_status{};
    NvencEncodeResult::Stage nvenc_stage{NvencEncodeResult::Stage::none};
    VideoPublishResult::Stage publish_stage{VideoPublishResult::Stage::none};
};

struct HybridGpuPipelineCounters {
    std::uint64_t frames_submitted{};
    std::uint64_t staging_busy{};
    std::uint64_t was_still_drawing{};
    std::uint64_t mailbox_superseded{};
    std::uint64_t published{};
    std::uint64_t completion_metrics_dropped{};
    std::uint32_t staging_high_watermark{};
    std::uint32_t mailbox_high_watermark{};
    std::uint32_t completion_high_watermark{};
    /** Shared-texture mailbox replacements; excludes CPU policy rejections. */
    std::uint64_t mailbox_replaced{};
    /** Shared ring had no producer-owned slot available. */
    std::uint64_t ring_busy{};
    /** Producer or worker keyed-mutex acquisition timed out. */
    std::uint64_t keyed_timeout{};
    std::uint64_t latest_worker_frame_age_us{};
    std::uint64_t maximum_worker_frame_age_us{};
};

enum class HybridGpuFatalStage {
    none,
    source_staging_texture,
    source_copy,
    readback_map,
    worker_device,
    worker_texture,
    encoder_initialize,
    publisher_connect,
    encode,
    publish,
    initialization_exception,
    worker_exception,
};

struct HybridGpuFatalFailure {
    bool failed{};
    HybridGpuFatalStage stage{HybridGpuFatalStage::none};
    std::int32_t native_status{};
    std::uint64_t source_sequence{};
};

/**
 * Bounded hybrid-GPU transfer and encode pipeline.
 *
 * submit()/pump() must be serialized on the capture thread. They alone touch
 * the source D3D11 immediate context. In same-adapter mode submit() performs
 * one shared-texture GPU copy; the private worker sends that shared texture
 * directly to NVENC. The worker alone owns its D3D11 device, NVENC session,
 * and UDP publisher.
 */
class HybridGpuVideoPipeline final {
public:
    HybridGpuVideoPipeline() noexcept;
    ~HybridGpuVideoPipeline();
    HybridGpuVideoPipeline(const HybridGpuVideoPipeline&) = delete;
    HybridGpuVideoPipeline& operator=(const HybridGpuVideoPipeline&) = delete;

    [[nodiscard]] bool initialize(
        ID3D11Device* source_device, ID3D11DeviceContext* source_context,
        const HybridGpuVideoPipelineConfig& config) noexcept;
    [[nodiscard]] HybridGpuSubmitResult submit(const HybridGpuFrameInput& input) noexcept;
    /** Polls all pending readbacks without blocking and returns queued-frame count. */
    [[nodiscard]] std::size_t pump() noexcept;
    [[nodiscard]] bool try_pop_completion(HybridGpuCompletionMetrics& destination) noexcept;
    void request_idr() noexcept;
    [[nodiscard]] HybridGpuPipelineCounters counters() const noexcept;
    [[nodiscard]] HybridGpuFatalFailure fatal_failure() const noexcept;
    void reset() noexcept;

private:
    struct State;
    std::unique_ptr<State> state_;
    std::int32_t construction_status_{};
};

}  // namespace vfdual
