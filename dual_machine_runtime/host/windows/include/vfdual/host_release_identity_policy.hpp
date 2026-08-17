#pragma once

#include <string_view>

namespace vfdual {

/**
 * Recognizes only stable VisionForge Host release filenames that the official
 * packaging pipeline has emitted. The path and firewall rule fields are still
 * validated independently; this function only supplies the bounded legacy
 * executable-name migration identity.
 */
[[nodiscard]] bool host_release_executable_name_is_recognized(
    std::wstring_view filename) noexcept;

}  // namespace vfdual
