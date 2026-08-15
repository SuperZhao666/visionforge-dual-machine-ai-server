#pragma once

#include "vfdual/wired_link_contract.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace vfdual {

struct Cat6LinkQuality {
    bool reachable{};
    double packet_loss_ratio{1.0};
    double jitter_ms{250.0};
    double rtt_ms{250.0};
    double throughput_mbps{};
    std::uint32_t probe_samples{};
};

struct Cat6SessionSnapshot {
    std::string host_ipv4;
    std::string mobile_ipv4;
    std::string transport{kCat6TransportName};
    Cat6LinkQuality quality{};
};

struct HostIpv4MulticastCandidate {
    std::uint32_t interface_index{};
    std::uint32_t ipv4_host_order{};
    std::uint8_t prefix_length{};
    bool operational{};
    bool multicast_capable{};
    bool address_preferred{};
};

struct HostIpv4MulticastInterface {
    std::uint32_t interface_index{};
    std::uint32_t ipv4_host_order{};
    std::uint8_t prefix_length{};

    friend bool operator==(
        const HostIpv4MulticastInterface&,
        const HostIpv4MulticastInterface&) = default;
};

/** One directed-broadcast destination pinned to its originating interface. */
struct HostIpv4DirectedBroadcastTarget {
    std::uint32_t interface_index{};
    std::uint32_t local_ipv4_host_order{};
    std::uint32_t broadcast_ipv4_host_order{};
    std::uint8_t prefix_length{};

    friend bool operator==(
        const HostIpv4DirectedBroadcastTarget&,
        const HostIpv4DirectedBroadcastTarget&) = default;
};

/** Selects usable RFC1918/shared-space IPv4 interfaces; metrics must not hide LAN. */
[[nodiscard]] std::vector<HostIpv4MulticastInterface>
select_wireless_lan_multicast_interfaces(
    std::span<const HostIpv4MulticastCandidate> candidates);

/** Derives one bounded directed-broadcast probe destination per selected subnet. */
[[nodiscard]] std::vector<std::uint32_t> wireless_lan_directed_broadcasts(
    std::span<const HostIpv4MulticastInterface> interfaces);

/** Keeps duplicate subnets on different interfaces as distinct probe targets. */
[[nodiscard]] std::vector<HostIpv4DirectedBroadcastTarget>
wireless_lan_directed_broadcast_targets(
    std::span<const HostIpv4MulticastInterface> interfaces);

/** Requires the same bounded ACK evidence on both early and deadline exits. */
[[nodiscard]] bool wireless_lan_discovery_evidence_ready(
    std::uint32_t probe_acknowledgements,
    std::string_view host_ipv4,
    std::string_view mobile_ipv4) noexcept;

struct WirelessLanDiscoveryOutcome {
    std::optional<Cat6SessionSnapshot> session;
    std::string diagnostic;
};

/**
 * Waits for the mobile CAT6-ready heartbeat or an active unicast probe ACK.
 * The fixed CAT6 path binds 10.57.23.1 and only accepts 10.57.23.2.
 */
[[nodiscard]] std::optional<Cat6SessionSnapshot> measure_cat6_mobile_session(
    std::chrono::milliseconds timeout);

/** Discovers and probes a mobile endpoint over the shared wireless LAN. */
[[nodiscard]] std::optional<Cat6SessionSnapshot> measure_wireless_lan_mobile_session(
    std::chrono::milliseconds timeout,
    std::stop_token stop_token = {});

/** Discovers the mobile endpoint and reports the exact multicast memberships used. */
[[nodiscard]] WirelessLanDiscoveryOutcome discover_wireless_lan_mobile_session(
    std::chrono::milliseconds timeout,
    std::stop_token stop_token = {});

/** Revalidates an already selected CAT6 or wireless-LAN endpoint by unicast. */
[[nodiscard]] std::optional<Cat6SessionSnapshot> measure_mobile_session(
    const Cat6SessionSnapshot& endpoint,
    std::chrono::milliseconds timeout);

}  // namespace vfdual
