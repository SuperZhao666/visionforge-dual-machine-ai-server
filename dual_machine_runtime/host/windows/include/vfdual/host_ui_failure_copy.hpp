#pragma once

#include <string>
#include <string_view>

namespace vfdual {

std::wstring widen_ascii(std::string_view value);
bool host_failure_is_authorization_pending(
    std::string_view error) noexcept;
std::wstring friendly_host_failure(std::string_view error);

}  // namespace vfdual
