#include "vf/host/domain/video_pipeline_status.hpp"

#include <algorithm>
#include <limits>

namespace vf::host::domain {

void VideoPipelineStatus::set_blocker(PipelineBlocker blocker, TimePoint now) noexcept {
    std::scoped_lock lock(mutex_);
    if (blocker == blocker_) {
        return;
    }
    blocker_ = blocker;
    changed_at_ = std::max(changed_at_, now);
    if (transition_id_ != std::numeric_limits<std::uint64_t>::max()) {
        ++transition_id_;
    }
}

void VideoPipelineStatus::mark_published(FrameIdentity identity, bool complete_idr) noexcept {
    if (!identity.valid()) {
        return;
    }
    std::scoped_lock lock(mutex_);
    if (last_published_frame_ && identity != *last_published_frame_ &&
        !identity.newer_than(*last_published_frame_)) {
        return;
    }
    if (!last_published_frame_ || identity.newer_than(*last_published_frame_)) {
        last_published_frame_ = identity;
    }
    if (complete_idr &&
        (!last_counted_idr_ || identity.newer_than(*last_counted_idr_))) {
        last_counted_idr_ = identity;
        if (fully_published_idr_count_ != std::numeric_limits<std::uint64_t>::max()) {
            ++fully_published_idr_count_;
        }
    }
}

bool VideoPipelineStatus::mark_decoded(FrameIdentity identity) noexcept {
    if (!identity.valid()) {
        return false;
    }
    std::scoped_lock lock(mutex_);
    // APP 只能确认当前发布 epoch 中、且不晚于 Host 已完整发布高水位的帧。
    // 旧 epoch 的迟到 ACK 不能在新会话中重新获得可信身份。
    if (!last_published_frame_ ||
        identity.stream_epoch != last_published_frame_->stream_epoch ||
        identity.newer_than(*last_published_frame_)) {
        return false;
    }
    if (last_decoded_frame_) {
        if (identity == *last_decoded_frame_) {
            return true;  // 幂等重复确认。
        }
        if (!identity.newer_than(*last_decoded_frame_)) {
            return false;
        }
    }
    last_decoded_frame_ = identity;
    return true;
}

PipelineStatusSnapshot VideoPipelineStatus::snapshot(TimePoint now) const noexcept {
    std::scoped_lock lock(mutex_);
    const auto elapsed = now >= changed_at_
        ? std::chrono::duration_cast<std::chrono::milliseconds>(now - changed_at_)
        : std::chrono::milliseconds::zero();
    return {
        .blocker = blocker_,
        .transition_id = transition_id_,
        .blocker_age = elapsed,
        .last_published_frame = last_published_frame_,
        .last_decoded_frame = last_decoded_frame_,
        .fully_published_idr_count = fully_published_idr_count_,
    };
}

std::string_view pipeline_blocker_name(PipelineBlocker blocker) noexcept {
    switch (blocker) {
        case PipelineBlocker::Runnable: return "RUNNABLE";
        case PipelineBlocker::CaptureWaiting: return "CAPTURE_WAITING";
        case PipelineBlocker::CaptureAccessLost: return "CAPTURE_ACCESS_LOST";
        case PipelineBlocker::CaptureDeviceRemoved: return "CAPTURE_DEVICE_REMOVED";
        case PipelineBlocker::EncoderUnavailable: return "ENCODER_UNAVAILABLE";
        case PipelineBlocker::PublishingFrame: return "PUBLISHING_FRAME";
        case PipelineBlocker::WaitingCompleteIdrPublish: return "WAITING_COMPLETE_IDR_PUBLISH";
        case PipelineBlocker::TransportFailure: return "TRANSPORT_FAILURE";
        case PipelineBlocker::WaitingFreshIdr: return "WAITING_FRESH_IDR";
        case PipelineBlocker::ReceiverResourceLimit: return "RECEIVER_RESOURCE_LIMIT";
        case PipelineBlocker::DecoderRestarting: return "DECODER_RESTARTING";
        case PipelineBlocker::PostAckVisibility: return "POST_ACK_VISIBILITY";
        case PipelineBlocker::RecoveryExhausted: return "RECOVERY_EXHAUSTED";
    }
    return "UNKNOWN";
}

}  // namespace vf::host::domain
