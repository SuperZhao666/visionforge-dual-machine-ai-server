#pragma once

#include "vfdual/desktop_video_agent.hpp"

#include <cstdint>
#include <string>

namespace vfdual {

/**
 * Parsed host-side video configuration. This type deliberately contains only
 * capture, encode and transport settings. Android policy and MAKCU control
 * are not represented here.
 */
struct HostRuntimeConfig {
  DesktopVideoAgentConfig video;
  std::string metrics_csv_path;
  std::uint32_t metrics_interval_frames{60};
};

/** Loads the small, explicit key=value host configuration format. */
[[nodiscard]] bool load_host_runtime_config(
    const std::string& file_path, HostRuntimeConfig& destination, std::string& error);

}  // namespace vfdual
