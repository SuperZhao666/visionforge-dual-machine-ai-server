#include "vf/host/interfaces/host_runtime_composition_root.hpp"

#include <stdexcept>

namespace vf::host::interfaces {

HostRuntimeCompositionRoot::HostRuntimeCompositionRoot(
    std::uint64_t reserved_epoch,
    TimePoint now,
    infrastructure::FragmentationConfig fragmentation)
    : status_(now),
      orchestrator_(status_),
      identities_(reserved_epoch),
      facade_(fragmentation) {
    status_.set_blocker(domain::PipelineBlocker::WaitingCompleteIdrPublish, now);
}

HostRuntimeResult HostRuntimeCompositionRoot::on_capture(
    CaptureStatus capture_status,
    std::span<const std::uint8_t> encoded_access_unit,
    bool is_idr,
    DatagramSink& sink,
    TimePoint now) {
    // 组合根按采集事件串行化，保证 frame identity 的产生顺序与 socket 发布顺序一致。
    // 这里只持有 capture_mutex_；外部 sink 回调期间不持有状态锁，避免重入死锁。
    std::scoped_lock capture_lock(capture_mutex_);
    std::optional<domain::FrameIdentity> published_before;
    {
        std::scoped_lock state_lock(state_mutex_);
        published_before = last_published_;
    }
    const auto action = orchestrator_.on_capture(
        capture_status, published_before.has_value(), now);

    switch (action) {
        case application::CaptureAction::EncodeAndPublish: {
            if (encoded_access_unit.empty()) {
                facade_.request_idr();
                status_.set_blocker(domain::PipelineBlocker::EncoderUnavailable, now);
                return result(HostRuntimeCode::InvalidEncodedFrame, std::nullopt, {}, now);
            }
            if (identities_.rotation_required()) {
                status_.set_blocker(domain::PipelineBlocker::RecoveryExhausted, now);
                return result(HostRuntimeCode::EpochRotationRequired, std::nullopt, {}, now);
            }
            const auto identity = identities_.next();
            const auto published = facade_.publish_access_unit(
                identity, is_idr, encoded_access_unit, sink);
            if (!published.complete()) {
                facade_.request_idr();
                status_.set_blocker(domain::PipelineBlocker::TransportFailure, now);
                return result(HostRuntimeCode::FramePublishFailed, identity, published, now);
            }
            {
                std::scoped_lock state_lock(state_mutex_);
                last_published_ = identity;
            }
            status_.mark_published(identity, is_idr);
            status_.set_blocker(
                facade_.idr_requested()
                    ? domain::PipelineBlocker::WaitingCompleteIdrPublish
                    : domain::PipelineBlocker::Runnable,
                now);
            return result(HostRuntimeCode::FramePublished, identity, published, now);
        }
        case application::CaptureAction::PublishRepeat: {
            if (!published_before) {
                status_.set_blocker(domain::PipelineBlocker::CaptureWaiting, now);
                return result(HostRuntimeCode::WaitingFirstFrame, std::nullopt, {}, now);
            }
            const bool sent = facade_.publish_repeat(*published_before, sink);
            facade_.request_idr();
            status_.set_blocker(
                sent ? domain::PipelineBlocker::WaitingCompleteIdrPublish
                     : domain::PipelineBlocker::TransportFailure,
                now);
            return result(sent ? HostRuntimeCode::RepeatPublished
                               : HostRuntimeCode::RepeatPublishFailed,
                          published_before,
                          {.fragments_total = 1,
                           .fragments_sent = sent ? 1U : 0U,
                           .socket_error = !sent},
                          now);
        }
        case application::CaptureAction::WaitForFirstFrame:
            return result(HostRuntimeCode::WaitingFirstFrame, std::nullopt, {}, now);
        case application::CaptureAction::RecreateDuplication:
            facade_.request_idr();
            return result(HostRuntimeCode::RecreateDuplication, published_before, {}, now);
        case application::CaptureAction::RebuildCaptureDevice:
            facade_.request_idr();
            return result(HostRuntimeCode::RebuildCaptureDevice, published_before, {}, now);
        case application::CaptureAction::FailClosed:
            facade_.request_idr();
            return result(HostRuntimeCode::FailClosed, published_before, {}, now);
    }
    facade_.request_idr();
    status_.set_blocker(domain::PipelineBlocker::RecoveryExhausted, now);
    return result(HostRuntimeCode::FailClosed, published_before, {}, now);
}

void HostRuntimeCompositionRoot::rotate_to_reserved_epoch(
    std::uint64_t reserved_epoch,
    TimePoint now) {
    std::scoped_lock capture_lock(capture_mutex_);
    identities_.rotate_to(reserved_epoch);
    {
        std::scoped_lock state_lock(state_mutex_);
        last_published_.reset();
    }
    facade_.request_idr();
    status_.set_blocker(domain::PipelineBlocker::WaitingCompleteIdrPublish, now);
}

void HostRuntimeCompositionRoot::request_idr() {
    // HostRuntimeFacade 自身对 IDR 账本加锁；不要与正在发送的慢 socket 串行。
    facade_.request_idr();
}

bool HostRuntimeCompositionRoot::mark_app_decoded(domain::FrameIdentity identity) noexcept {
    return status_.mark_decoded(identity);
}

domain::PipelineStatusSnapshot HostRuntimeCompositionRoot::status(TimePoint now) const noexcept {
    return status_.snapshot(now);
}

std::optional<domain::FrameIdentity>
HostRuntimeCompositionRoot::last_published_frame() const noexcept {
    std::scoped_lock state_lock(state_mutex_);
    return last_published_;
}

bool HostRuntimeCompositionRoot::idr_requested() const {
    return facade_.idr_requested();
}

HostRuntimeResult HostRuntimeCompositionRoot::result(
    HostRuntimeCode code,
    std::optional<domain::FrameIdentity> identity,
    PublishSummary publish,
    TimePoint now) const noexcept {
    return {
        .code = code,
        .identity = identity,
        .publish = publish,
        .status = status_.snapshot(now),
    };
}

}  // namespace vf::host::interfaces
