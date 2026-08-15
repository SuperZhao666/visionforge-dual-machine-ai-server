#pragma once

#include "vfdual/host_cat6_session.hpp"
#include "vfdual/host_direct_link_provisioner.hpp"
#include "vfdual/host_firewall_provisioner.hpp"
#include "vfdual/isolated_dhcp_server.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>

namespace vfdual {

// Startup must not let an Ethernet adapter that merely retains 10.57.23.1
// consume the Android WLAN discovery window. Peer evidence, not adapter/IP
// state, decides whether CAT6 is selected. Two seconds also covers a CAT6
// ready-agent rebind plus its next 250 ms heartbeat; one second could expire
// just before that heartbeat and force an unnecessary WLAN scan. Slow Android
// DHCP remains covered by the long-running preferred-link probe after WLAN.
inline constexpr auto kHostInitialCat6PeerEvidenceTimeout =
    std::chrono::seconds{2};

// Android's DHCP retry backoff can reach 32 seconds after the physical link
// was already present. Keep each background attempt alive long enough for that
// retry plus address assignment and the first 250 ms ready heartbeat.
inline constexpr auto kHostCat6MobileReadyTimeout = std::chrono::seconds{45};

enum class HostCat6BootstrapFailureStage {
    none,
    direct_link,
    firewall,
    dhcp,
    mobile_ready_timeout,
};

struct HostCat6BootstrapResult {
    std::optional<Cat6SessionSnapshot> mobile;
    HostDirectLinkProvisioningResult direct_link;
    HostFirewallProvisioningResult firewall;
    bool firewall_attempted{};
    bool dhcp_start_attempted{};
    bool dhcp_started{};
    bool dhcp_runtime_failed{};
    std::uint32_t dhcp_native_error{};
    std::string dhcp_detail;
    bool mobile_wait_attempted{};
    /**
     * Chronological "elapsed_ms:old->new" transitions of every live 10.57.x
     * address during the mobile-ready wait. Proves exactly when the isolated
     * address disappears and what appears in its place on hostile machines.
     */
    std::string address_watch;
    std::vector<std::string> diagnostics;
};

[[nodiscard]] inline HostCat6BootstrapFailureStage classify_host_cat6_bootstrap_failure(
    const HostCat6BootstrapResult& result) noexcept {
    if (result.mobile.has_value()) return HostCat6BootstrapFailureStage::none;
    const bool direct_link_ready =
        result.direct_link.status == HostDirectLinkStatus::already_ready ||
        result.direct_link.status == HostDirectLinkStatus::provisioned;
    if (!direct_link_ready) {
        return HostCat6BootstrapFailureStage::direct_link;
    }
    const bool firewall_ready =
        result.firewall.status == HostFirewallStatus::ready ||
        result.firewall.status == HostFirewallStatus::provisioned;
    if (!firewall_ready) {
        return HostCat6BootstrapFailureStage::firewall;
    }
    if (!result.dhcp_started || result.dhcp_runtime_failed) {
        return HostCat6BootstrapFailureStage::dhcp;
    }
    return HostCat6BootstrapFailureStage::mobile_ready_timeout;
}

[[nodiscard]] inline const char* host_cat6_bootstrap_failure_stage_name(
    HostCat6BootstrapFailureStage stage) noexcept {
    switch (stage) {
        case HostCat6BootstrapFailureStage::none: return "none";
        case HostCat6BootstrapFailureStage::direct_link: return "direct_link";
        case HostCat6BootstrapFailureStage::firewall: return "firewall";
        case HostCat6BootstrapFailureStage::dhcp: return "dhcp";
        case HostCat6BootstrapFailureStage::mobile_ready_timeout:
            return "mobile_ready_timeout";
    }
    return "unknown";
}

using HostCat6SessionMeasurer = std::optional<Cat6SessionSnapshot> (*)(
    std::chrono::milliseconds timeout);
using HostCat6WaitMaintenance = std::function<bool()>;

/** Waits in short measurement slices so a desktop stop request is observed promptly. */
[[nodiscard]] std::optional<Cat6SessionSnapshot> wait_for_host_cat6_mobile(
    std::chrono::milliseconds session_timeout,
    std::stop_token stop_token,
    HostCat6SessionMeasurer measure_session,
    HostCat6WaitMaintenance maintenance = {});

/** Configures the isolated subnet, starts its DHCP owner and waits for the CAT6-ready heartbeat. */
[[nodiscard]] HostCat6BootstrapResult bootstrap_host_cat6_link(
    std::chrono::milliseconds session_timeout,
    IsolatedDhcpServer* isolated_dhcp_server,
    std::stop_token stop_token = {});

}  // namespace vfdual
