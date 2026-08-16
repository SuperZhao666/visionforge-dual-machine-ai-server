#include "test_support.hpp"
#include "vf/host/application/host_streaming_orchestrator.hpp"
#include "vf/host/domain/video_pipeline_status.hpp"

#include <chrono>
#include <exception>
#include <iostream>

namespace {
using namespace std::chrono_literals;
using vf::CaptureStatus;
using vf::host::application::CaptureAction;
using vf::host::application::HostStreamingOrchestrator;
using vf::host::domain::FrameIdentity;
using vf::host::domain::PipelineBlocker;
using vf::host::domain::VideoPipelineStatus;
using vf::test::expect;

void run() {
    const auto t0 = VideoPipelineStatus::TimePoint{};
    VideoPipelineStatus status(t0);
    HostStreamingOrchestrator orchestrator(status);

    expect(orchestrator.on_capture(CaptureStatus::WaitTimeout, false, t0 + 1ms) ==
               CaptureAction::WaitForFirstFrame,
           "timeout before first frame fabricated a repeat action");
    expect(orchestrator.on_capture(CaptureStatus::WaitTimeout, true, t0 + 2ms) ==
               CaptureAction::PublishRepeat,
           "DXGI timeout after publication did not map to repeat");
    expect(status.snapshot(t0 + 3ms).blocker == PipelineBlocker::CaptureWaiting,
           "capture wait blocker missing");

    expect(orchestrator.on_capture(CaptureStatus::AccessLost, t0 + 4ms) ==
               CaptureAction::RecreateDuplication,
           "access-lost was confused with ordinary timeout");
    expect(orchestrator.on_capture(CaptureStatus::DeviceRemoved, t0 + 5ms) ==
               CaptureAction::RebuildCaptureDevice,
           "device removal did not escalate rebuild");
    expect(orchestrator.on_capture(CaptureStatus::Frame, t0 + 6ms) ==
               CaptureAction::EncodeAndPublish,
           "fresh frame did not enter publication");
    expect(status.snapshot(t0 + 6ms).blocker == PipelineBlocker::PublishingFrame,
           "capture success was reported runnable before publication completed");

    status.mark_published(FrameIdentity{2, 10}, true);
    status.mark_published(FrameIdentity{2, 10}, true);
    status.mark_published(FrameIdentity{1, 99}, true);
    expect(status.mark_decoded(FrameIdentity{2, 10}),
           "published frame could not be marked decoded");
    expect(!status.mark_decoded(FrameIdentity{1, 99}),
           "retired epoch decode callback was accepted");
    const auto snapshot = status.snapshot(t0 + 10ms);
    expect(snapshot.blocker == PipelineBlocker::PublishingFrame,
           "pipeline claimed runnable before the composition root completed publication");
    expect(snapshot.fully_published_idr_count == 1,
           "duplicate/stale complete IDR was double-counted");
    expect(snapshot.last_published_frame == FrameIdentity{2, 10} &&
               snapshot.last_decoded_frame == FrameIdentity{2, 10},
           "late frame callback regressed monotonic pipeline identity");
    expect(snapshot.transition_id == 4,
           "status transition count is not low-cardinality and deterministic");
}
}  // namespace

int main() {
    try {
        run();
        std::cout << "VIDEO_PIPELINE_STATUS_TESTS_OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "VIDEO_PIPELINE_STATUS_TESTS_FAILED: " << error.what() << '\n';
        return 1;
    }
}
