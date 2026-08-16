#pragma once

#include "vf/host/domain/video_pipeline_status.hpp"
#include "vf/host_pipeline.hpp"

#include <chrono>

namespace vf::host::application {

enum class CaptureAction {
    EncodeAndPublish,
    PublishRepeat,
    WaitForFirstFrame,
    RecreateDuplication,
    RebuildCaptureDevice,
    FailClosed,
};

/** 将 DXGI 的五种结果显式映射为业务动作，禁止把 timeout 与 access-lost 混为一谈。 */
class HostStreamingOrchestrator {
public:
    using TimePoint = std::chrono::steady_clock::time_point;

    explicit HostStreamingOrchestrator(host::domain::VideoPipelineStatus& status)
        : status_(status) {}

    [[nodiscard]] CaptureAction on_capture(
        CaptureStatus capture_status,
        bool has_published_frame,
        TimePoint now) noexcept;

    /** 兼容旧调用点：旧逻辑只会在已发布过帧后进入采集循环。 */
    [[nodiscard]] CaptureAction on_capture(CaptureStatus capture_status, TimePoint now) noexcept {
        return on_capture(capture_status, true, now);
    }

private:
    host::domain::VideoPipelineStatus& status_;
};

}  // namespace vf::host::application
