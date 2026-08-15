#pragma once

#include <string_view>

namespace vfdual {

/**
 * Installs a process-wide Windows crash boundary. Fatal reports include a
 * minidump with every thread plus a small text index under
 * %LOCALAPPDATA%\VisionForge\DualMachine\crashes.
 */
void install_host_crash_diagnostics() noexcept;

/** Records a caught top-level C++ failure before the process exits. */
void record_host_cpp_exception(
    std::string_view category, std::string_view detail) noexcept;

}  // namespace vfdual
