#pragma once

#include <string_view>

namespace vfdual {

/**
 * Platform-neutral identity facts used to keep capture/filter/loopback devices
 * out of the direct-link provisioning path.
 */
struct HostAdapterIdentityFacts {
    bool hardware_interface{};
    bool connector_present{};
    bool filter_interface{};
    bool endpoint_interface{};
    bool software_loopback_or_tunnel{};
    std::wstring_view connection_name;
    std::wstring_view description;
};

/**
 * Returns true for an interface that Windows or its stable device identity
 * identifies as virtual, loopback, tunnel, packet-capture, filter, or endpoint.
 */
[[nodiscard]] bool host_adapter_has_virtual_or_loopback_identity(
    const HostAdapterIdentityFacts& facts) noexcept;

/**
 * Requires a real, user-connectable hardware port. This is intentionally
 * stricter than HardwareInterface alone because Npcap and other filter-backed
 * adapters can report hardware-like flags on some Windows builds.
 */
[[nodiscard]] bool host_adapter_has_physical_connector_identity(
    const HostAdapterIdentityFacts& facts) noexcept;

}  // namespace vfdual
