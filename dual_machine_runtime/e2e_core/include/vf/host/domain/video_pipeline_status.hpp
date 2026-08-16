#pragma once

#include "vf/host/domain/frame_identity.hpp"

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string_view>

namespace vf::host::domain {

enum class PipelineBlocker {
    Runnable,
    CaptureWaiting,
    CaptureAccessLost,
    CaptureDeviceRemoved,
    EncoderUnavailable,
    PublishingFrame,
    WaitingCompleteIdrPublish,
    TransportFailure,
    WaitingFreshIdr,
    ReceiverResourceLimit,
    DecoderRestarting,
    PostAckVisibility,
    RecoveryExhausted,
};

struct PipelineStatusSnapshot {
    PipelineBlocker blocker{PipelineBlocker::Runnable};
    std::uint64_t transition_id{};
    std::chrono::milliseconds blocker_age{};
    std::optional<FrameIdentity> last_published_frame;
    std::optional<FrameIdentity> last_decoded_frame;
    std::uint64_t fully_published_idr_count{};
};

/**
 * 低基数、线程安全、单调的流水线状态账本。
 *
 * <p>重复 blocker 不制造伪 transition；迟到的旧帧不会让“最后发布/解码身份”回退；
 * 同一 IDR 的重复回调也不会重复计数。</p>
 */
class VideoPipelineStatus {
public:
    using TimePoint = std::chrono::steady_clock::time_point;

    explicit VideoPipelineStatus(TimePoint now) noexcept : changed_at_(now) {}

    void set_blocker(PipelineBlocker blocker, TimePoint now) noexcept;
    void mark_published(FrameIdentity identity, bool complete_idr) noexcept;
    [[nodiscard]] bool mark_decoded(FrameIdentity identity) noexcept;

    [[nodiscard]] PipelineStatusSnapshot snapshot(TimePoint now) const noexcept;

private:
    mutable std::mutex mutex_;
    PipelineBlocker blocker_{PipelineBlocker::Runnable};
    std::uint64_t transition_id_{};
    TimePoint changed_at_{};
    std::optional<FrameIdentity> last_published_frame_;
    std::optional<FrameIdentity> last_decoded_frame_;
    std::optional<FrameIdentity> last_counted_idr_;
    std::uint64_t fully_published_idr_count_{};
};

[[nodiscard]] std::string_view pipeline_blocker_name(PipelineBlocker blocker) noexcept;

}  // namespace vf::host::domain
