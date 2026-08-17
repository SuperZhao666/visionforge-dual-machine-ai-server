#include "vfdual/host_probe_fallback_policy.hpp"

#include <algorithm>
#include <iterator>

namespace vfdual {

std::vector<HostIpv4DirectedBroadcastTarget>
select_wireless_lan_probe_broadcast_targets(
    std::span<const HostIpv4DirectedBroadcastTarget> targets,
    std::optional<HostProbeRouteIdentity> route) {
    if (!route.has_value()) {
        return {targets.begin(), targets.end()};
    }
    std::vector<HostIpv4DirectedBroadcastTarget> selected;
    std::copy_if(
        targets.begin(), targets.end(), std::back_inserter(selected),
        [&route](const HostIpv4DirectedBroadcastTarget& target) {
            return target.interface_index == route->interface_index &&
                target.local_ipv4_host_order == route->local_ipv4_host_order;
        });
    return selected;
}

}  // namespace vfdual
