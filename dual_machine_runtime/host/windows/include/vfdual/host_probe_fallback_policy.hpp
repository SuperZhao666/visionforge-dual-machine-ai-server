#pragma once

#include "vfdual/host_cat6_session.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace vfdual {

/** Exact local route selected by Windows for a discovered mobile peer. */
struct HostProbeRouteIdentity {
    std::uint32_t interface_index{};
    std::uint32_t local_ipv4_host_order{};

    friend bool operator==(
        const HostProbeRouteIdentity&,
        const HostProbeRouteIdentity&) = default;
};

/**
 * Before a peer route is known, returns every bounded RFC1918 directed-
 * broadcast target. Once the route is known, returns only the target on that
 * exact interface/local-address pair so unicast and directed broadcast can be
 * attempted together without leaking probes onto unrelated networks.
 */
[[nodiscard]] std::vector<HostIpv4DirectedBroadcastTarget>
select_wireless_lan_probe_broadcast_targets(
    std::span<const HostIpv4DirectedBroadcastTarget> targets,
    std::optional<HostProbeRouteIdentity> route);

}  // namespace vfdual
