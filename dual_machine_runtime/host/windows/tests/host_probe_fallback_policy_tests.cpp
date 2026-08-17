#include "vfdual/host_probe_fallback_policy.hpp"

#include <cstdlib>
#include <iostream>
#include <vector>

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
    std::exit(EXIT_FAILURE);
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

int main() {
    using vfdual::HostIpv4DirectedBroadcastTarget;
    using vfdual::HostProbeRouteIdentity;

    const std::vector<HostIpv4DirectedBroadcastTarget> targets{
        {7U, 0xC0A80164U, 0xC0A801FFU, 24U},
        {11U, 0xC0A80165U, 0xC0A801FFU, 24U},
        {19U, 0x0A000005U, 0x0A0000FFU, 24U},
    };

    const auto before_route =
        vfdual::select_wireless_lan_probe_broadcast_targets(
            targets, std::nullopt);
    CHECK(before_route == targets);

    const auto scoped =
        vfdual::select_wireless_lan_probe_broadcast_targets(
            targets, HostProbeRouteIdentity{11U, 0xC0A80165U});
    CHECK(scoped.size() == 1U);
    CHECK(scoped.front() == targets[1]);

    const auto wrong_local_address =
        vfdual::select_wireless_lan_probe_broadcast_targets(
            targets, HostProbeRouteIdentity{11U, 0xC0A80164U});
    CHECK(wrong_local_address.empty());

    const auto unknown_interface =
        vfdual::select_wireless_lan_probe_broadcast_targets(
            targets, HostProbeRouteIdentity{99U, 0xC0A80165U});
    CHECK(unknown_interface.empty());
    return 0;
}
