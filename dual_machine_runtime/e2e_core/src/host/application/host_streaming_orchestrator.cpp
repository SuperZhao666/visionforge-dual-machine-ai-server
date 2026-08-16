#include "vf/host/application/host_streaming_orchestrator.hpp"

namespace vf::host::application {

CaptureAction HostStreamingOrchestrator::on_capture(
    CaptureStatus capture_status,
    bool has_published_frame,
    TimePoint now) noexcept {
    using host::domain::PipelineBlocker;
    switch (capture_status) {
        case CaptureStatus::Frame:
            // 采集成功只表示“有帧可处理”，并不等于编码与全部分片已经交付成功。
            status_.set_blocker(PipelineBlocker::PublishingFrame, now);
            return CaptureAction::EncodeAndPublish;
        case CaptureStatus::WaitTimeout:
            status_.set_blocker(PipelineBlocker::CaptureWaiting, now);
            return has_published_frame ? CaptureAction::PublishRepeat
                                       : CaptureAction::WaitForFirstFrame;
        case CaptureStatus::AccessLost:
            status_.set_blocker(PipelineBlocker::CaptureAccessLost, now);
            return CaptureAction::RecreateDuplication;
        case CaptureStatus::DeviceRemoved:
            status_.set_blocker(PipelineBlocker::CaptureDeviceRemoved, now);
            return CaptureAction::RebuildCaptureDevice;
        case CaptureStatus::Failed:
            status_.set_blocker(PipelineBlocker::TransportFailure, now);
            return CaptureAction::FailClosed;
    }
    status_.set_blocker(PipelineBlocker::TransportFailure, now);
    return CaptureAction::FailClosed;
}

}  // namespace vf::host::application
