#pragma once

#include "vfdual/desktop_video_agent.hpp"
#include "vfdual/h264_encoder_config.hpp"
#include "vfdual/host_application.hpp"

#include <string_view>

namespace vfdual {

std::string_view encoder_candidate_name(
    HostEncoderCandidate candidate) noexcept;
std::string_view desktop_video_initialization_stage_name(
    DesktopVideoInitializationStage stage) noexcept;
std::string_view host_application_start_stage_name(
    HostApplicationStartStage stage) noexcept;

}  // namespace vfdual
