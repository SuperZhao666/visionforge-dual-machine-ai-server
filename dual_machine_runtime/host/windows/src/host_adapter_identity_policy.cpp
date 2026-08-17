#include "vfdual/host_adapter_identity_policy.hpp"

#include <array>
#include <cwctype>

namespace vfdual {
namespace {

wchar_t fold_ascii_case(wchar_t value) noexcept {
    if (value >= L'A' && value <= L'Z') {
        return static_cast<wchar_t>(value - L'A' + L'a');
    }
    return value;
}

bool contains_insensitive(
    std::wstring_view value,
    std::wstring_view needle) noexcept {
    if (needle.empty() || needle.size() > value.size()) return false;
    for (std::size_t offset = 0U;
         offset + needle.size() <= value.size(); ++offset) {
        bool equal = true;
        for (std::size_t index = 0U; index < needle.size(); ++index) {
            if (fold_ascii_case(value[offset + index]) !=
                fold_ascii_case(needle[index])) {
                equal = false;
                break;
            }
        }
        if (equal) return true;
    }
    return false;
}

bool text_has_virtual_identity(std::wstring_view value) noexcept {
    // These markers are stable Windows/driver identities rather than generic
    // marketing words. A direct-link adapter must be a physical Ethernet jack,
    // so every listed virtual transport is unsuitable even when operational.
    constexpr std::array<std::wstring_view, 13U> kRejectedMarkers{
        L"npcap loopback adapter",
        L"loopback pseudo-interface",
        L"microsoft km-test loopback adapter",
        L"microsoft loopback adapter",
        L"software loopback",
        L"hyper-v virtual ethernet adapter",
        L"virtualbox host-only",
        L"vmware network adapter",
        L"tap-windows adapter",
        L"wireguard tunnel",
        L"wintun",
        L"packet capture",
        L"filter adapter",
    };
    for (const std::wstring_view marker : kRejectedMarkers) {
        if (contains_insensitive(value, marker)) return true;
    }
    return false;
}

}  // namespace

bool host_adapter_has_virtual_or_loopback_identity(
    const HostAdapterIdentityFacts& facts) noexcept {
    return facts.software_loopback_or_tunnel || facts.filter_interface ||
        facts.endpoint_interface ||
        text_has_virtual_identity(facts.connection_name) ||
        text_has_virtual_identity(facts.description);
}

bool host_adapter_has_physical_connector_identity(
    const HostAdapterIdentityFacts& facts) noexcept {
    return facts.hardware_interface && facts.connector_present &&
        !host_adapter_has_virtual_or_loopback_identity(facts);
}

}  // namespace vfdual
