#pragma once

#include "vf/host/application/host_streaming_orchestrator.hpp"
#include "vf/host/domain/stream_identity_generator.hpp"
#include "vf/host/interfaces/host_runtime_facade.hpp"

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>

namespace vf::host::interfaces {

enum class HostRuntimeCode {
    FramePublished,
    FramePublishFailed,
    RepeatPublished,
    RepeatPublishFailed,
    WaitingFirstFrame,
    RecreateDuplication,
    RebuildCaptureDevice,
    FailClosed,
    InvalidEncodedFrame,
    EpochRotationRequired,
};

struct HostRuntimeResult {
    HostRuntimeCode code{HostRuntimeCode::FailClosed};
    std::optional<domain::FrameIdentity> identity;
    PublishSummary publish;
    domain::PipelineStatusSnapshot status;
};

/**
 * Windows Host 截图→编码→分片→发送链路的唯一组合根。
 *
 * <p>调用方必须先通过 FileEpochReservationStore 预留 epoch，再构造本对象。所有采集
 * 结果在这里映射为明确动作；首帧前 timeout 不会伪造 REPEAT，任何不完整交付都
 * 保留 IDR 请求并进入可观测失败态。</p>
 */
class HostRuntimeCompositionRoot {
public:
    using TimePoint = std::chrono::steady_clock::time_point;

    HostRuntimeCompositionRoot(
        std::uint64_t reserved_epoch,
        TimePoint now,
        infrastructure::FragmentationConfig fragmentation = {});

    [[nodiscard]] HostRuntimeResult on_capture(
        CaptureStatus capture_status,
        std::span<const std::uint8_t> encoded_access_unit,
        bool is_idr,
        DatagramSink& sink,
        TimePoint now);

    /** sequence 空间耗尽后，调用方持久化预留更高 epoch，再显式旋转。 */
    void rotate_to_reserved_epoch(std::uint64_t reserved_epoch, TimePoint now);
    void request_idr();
    [[nodiscard]] bool mark_app_decoded(domain::FrameIdentity identity) noexcept;

    [[nodiscard]] domain::PipelineStatusSnapshot status(TimePoint now) const noexcept;
    [[nodiscard]] std::optional<domain::FrameIdentity> last_published_frame() const noexcept;
    [[nodiscard]] bool idr_requested() const;

private:
    [[nodiscard]] HostRuntimeResult result(
        HostRuntimeCode code,
        std::optional<domain::FrameIdentity> identity,
        PublishSummary publish,
        TimePoint now) const noexcept;

    // capture_mutex_ 只串行化会产生 frame identity 的采集/旋转事务。外部 sink
    // 调用期间绝不持有 state_mutex_，因此状态读取、IDR 请求和 APP 回调不会被网络阻塞。
    mutable std::mutex capture_mutex_;
    mutable std::mutex state_mutex_;
    domain::VideoPipelineStatus status_;
    application::HostStreamingOrchestrator orchestrator_;
    domain::StreamIdentityGenerator identities_;
    HostRuntimeFacade facade_;
    std::optional<domain::FrameIdentity> last_published_;
};

}  // namespace vf::host::interfaces
