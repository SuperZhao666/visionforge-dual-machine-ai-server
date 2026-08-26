#include "vfdual/host_runtime_diagnostics.hpp"

namespace vfdual {

std::string_view encoder_candidate_name(
    HostEncoderCandidate candidate) noexcept {
    switch (candidate) {
        case HostEncoderCandidate::nvenc_same_adapter_async_shared:
            return "nvenc_same_adapter_async_shared";
        case HostEncoderCandidate::nvenc_capture_device:
            return "nvenc_capture_device";
        case HostEncoderCandidate::nvenc_cross_adapter:
            return "nvenc_cross_adapter";
        case HostEncoderCandidate::windows_hardware_capture_device:
            return "windows_hardware_capture_device";
        case HostEncoderCandidate::software_cpu:
            return "software_cpu";
    }
    return "unknown";
}

std::string_view desktop_video_initialization_stage_name(
    DesktopVideoInitializationStage stage) noexcept {
    switch (stage) {
        case DesktopVideoInitializationStage::none:
            return "none";
        case DesktopVideoInitializationStage::validate_config:
            return "validate_config";
        case DesktopVideoInitializationStage::capture_initialize:
            return "capture_initialize";
        case DesktopVideoInitializationStage::hybrid_pipeline_initialize:
            return "hybrid_pipeline_initialize";
        case DesktopVideoInitializationStage::frame_bridge_initialize:
            return "frame_bridge_initialize";
        case DesktopVideoInitializationStage::nvenc_initialize:
            return "nvenc_initialize";
        case DesktopVideoInitializationStage::media_foundation_hardware_initialize:
            return "media_foundation_hardware_initialize";
        case DesktopVideoInitializationStage::media_foundation_software_initialize:
            return "media_foundation_software_initialize";
        case DesktopVideoInitializationStage::udp_publisher_connect:
            return "udp_publisher_connect";
        case DesktopVideoInitializationStage::complete:
            return "complete";
    }
    return "unknown";
}

std::string_view host_application_start_stage_name(
    HostApplicationStartStage stage) noexcept {
    switch (stage) {
        case HostApplicationStartStage::none:
            return "none";
        case HostApplicationStartStage::video_initialize:
            return "video_initialize";
        case HostApplicationStartStage::idr_listener_start:
            return "idr_listener_start";
        case HostApplicationStartStage::mouse_button_publisher_start:
            return "mouse_button_publisher_start";
        case HostApplicationStartStage::authenticated_presence_start:
            return "authenticated_presence_start";
        case HostApplicationStartStage::metrics_csv_open:
            return "metrics_csv_open";
        case HostApplicationStartStage::complete:
            return "complete";
    }
    return "unknown";
}

}  // namespace vfdual
