#include "vfdual/host_cat6_session.hpp"
#include "vfdual/host_cat6_protocol.hpp"
#include "vfdual/host_probe_fallback_policy.hpp"
#include "vfdual/wired_link_contract.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace vfdual {
namespace {

constexpr std::size_t kProbeBytes = 1200U;
constexpr auto kProbeInterval = std::chrono::milliseconds{250};
constexpr std::uint32_t kWirelessDiscoveryProbeAcks = 2U;

class WinsockSession final {
public:
    WinsockSession() noexcept { ready_ = WSAStartup(MAKEWORD(2, 2), &data_) == 0; }
    ~WinsockSession() { if (ready_) WSACleanup(); }
    [[nodiscard]] bool ready() const noexcept { return ready_; }

private:
    WSADATA data_{};
    bool ready_{};
};

class SocketPair final {
public:
    ~SocketPair() {
        if (ready != INVALID_SOCKET) closesocket(ready);
        if (probe != INVALID_SOCKET) closesocket(probe);
    }

    SOCKET probe{INVALID_SOCKET};
    SOCKET ready{INVALID_SOCKET};
};

struct Observation final {
    std::uint32_t ready_messages{};
    std::uint32_t ready_datagrams_received{};
    std::uint32_t invalid_ready_datagrams{};
    std::uint32_t probes_sent{};
    std::uint32_t probe_send_attempts{};
    std::uint32_t probe_send_failures{};
    std::uint32_t probe_interface_selection_failures{};
    std::uint32_t probes_received{};
    std::uint32_t probe_datagrams_received{};
    std::uint32_t rejected_source_datagrams{};
    std::uint32_t select_failures{};
    std::uint32_t ready_receive_failures{};
    std::uint32_t probe_receive_failures{};
    std::uint32_t route_resolution_attempts{};
    std::uint32_t route_resolution_failures{};
    std::uint32_t route_scoped_broadcast_probe_attempts{};
    std::uint32_t response_bytes{};
    int last_probe_send_error{};
    int last_probe_interface_error{};
    int last_receive_error{};
    double total_rtt_ms{};
    double total_jitter_ms{};
    double previous_rtt_ms{};
    bool has_previous_rtt{};
    std::string first_ready_source;
    std::string first_probe_ack_source;
};

struct PendingProbe final {
    std::chrono::steady_clock::time_point sent_at;
    std::uint32_t interface_index{};
    std::uint32_t local_ipv4_host_order{};
};

struct WirelessHostRoute final {
    std::string host_ipv4;
    std::uint32_t interface_index{};
    std::uint32_t local_ipv4_host_order{};
};

struct WirelessMulticastMembership final {
    std::vector<HostIpv4MulticastInterface> candidate_interfaces;
    std::vector<HostIpv4MulticastInterface> joined_interfaces;
    std::vector<HostIpv4DirectedBroadcastTarget> directed_broadcast_targets;
    std::uint32_t membership_failures{};
    std::uint32_t indexed_memberships{};
    std::uint32_t legacy_memberships{};
    std::uint32_t indexed_membership_failures{};
    std::uint32_t legacy_membership_failures{};
    int last_socket_error{};
    int broadcast_probe_socket_error{};
    bool broadcast_probe_enabled{};
    bool fallback_any_attempted{};
    std::string setup_stage{"not_started"};
};

bool parse_address(std::string_view text, in_addr& address) noexcept {
    const std::string value{text};
    return InetPtonA(AF_INET, value.c_str(), &address) == 1;
}

bool bind_socket(SOCKET socket_handle, const in_addr& local, std::uint16_t port) noexcept {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr = local;
    address.sin_port = htons(port);
    return bind(socket_handle, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0;
}

bool set_boolean_socket_option(
    SOCKET socket_handle, int option, BOOL value) noexcept {
    return setsockopt(
        socket_handle, SOL_SOCKET, option,
        reinterpret_cast<const char*>(&value), sizeof(value)) == 0;
}

bool create_unicast_sockets(const in_addr& host, SocketPair& sockets) noexcept {
    sockets.probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockets.ready = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockets.probe == INVALID_SOCKET || sockets.ready == INVALID_SOCKET) return false;
    if (!set_boolean_socket_option(sockets.ready, SO_EXCLUSIVEADDRUSE, TRUE)) return false;
    return bind_socket(sockets.probe, host, 0) &&
           bind_socket(sockets.ready, host, kWiredAnnouncementPort);
}

bool is_source(const sockaddr_in& source, const in_addr& expected) noexcept {
    return source.sin_family == AF_INET && source.sin_addr.s_addr == expected.s_addr;
}

bool is_private_unicast(std::uint32_t value) noexcept {
    const std::uint8_t first = static_cast<std::uint8_t>(value >> 24U);
    const std::uint8_t second = static_cast<std::uint8_t>(value >> 16U);
    return first == 10U ||
        (first == 100U && second >= 64U && second <= 127U) ||
        (first == 172U && second >= 16U && second <= 31U) ||
        (first == 192U && second == 168U);
}

bool is_private_unicast(const in_addr& address) noexcept {
    return is_private_unicast(ntohl(address.s_addr));
}

std::string address_to_string(const in_addr& address) {
    char text[INET_ADDRSTRLEN]{};
    if (InetNtopA(AF_INET, &address, text, sizeof(text)) == nullptr) return {};
    return text;
}

std::string host_order_address_to_string(std::uint32_t address) {
    in_addr network_address{};
    network_address.s_addr = htonl(address);
    return address_to_string(network_address);
}

std::vector<HostIpv4MulticastCandidate> enumerate_multicast_candidates() {
    std::vector<unsigned char> storage(16U * 1024U);
    ULONG size = static_cast<ULONG>(storage.size());
    constexpr ULONG flags =
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER;
    ULONG result = GetAdaptersAddresses(
        AF_INET, flags, nullptr,
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()), &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        storage.resize(size);
        result = GetAdaptersAddresses(
            AF_INET, flags, nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()), &size);
    }
    std::vector<HostIpv4MulticastCandidate> candidates;
    for (auto* adapter = result == NO_ERROR
             ? reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()) : nullptr;
         adapter != nullptr; adapter = adapter->Next) {
        const bool operational = adapter->OperStatus == IfOperStatusUp;
        const bool multicast_capable =
            adapter->IfType != IF_TYPE_SOFTWARE_LOOPBACK &&
            (adapter->Flags & IP_ADAPTER_NO_MULTICAST) == 0U;
        for (auto* unicast = adapter->FirstUnicastAddress;
             unicast != nullptr; unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == nullptr ||
                unicast->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }
            const auto* address = reinterpret_cast<const sockaddr_in*>(
                unicast->Address.lpSockaddr);
            candidates.push_back(HostIpv4MulticastCandidate{
                .interface_index = adapter->IfIndex,
                .ipv4_host_order = ntohl(address->sin_addr.s_addr),
                .prefix_length = static_cast<std::uint8_t>(
                    unicast->OnLinkPrefixLength),
                .operational = operational,
                .multicast_capable = multicast_capable,
                .address_preferred = unicast->DadState == IpDadStatePreferred,
            });
        }
    }
    return candidates;
}

std::string describe_interface_addresses(
    std::span<const HostIpv4MulticastInterface> interfaces) {
    std::ostringstream detail;
    detail << '[';
    for (std::size_t index = 0; index < interfaces.size(); ++index) {
        if (index != 0U) detail << ',';
        const auto& selected = interfaces[index];
        if (selected.interface_index == 0U && selected.ipv4_host_order == 0U) {
            detail << "auto";
        } else {
            detail << host_order_address_to_string(selected.ipv4_host_order)
                   << '/' << static_cast<unsigned>(selected.prefix_length)
                   << "@if" << selected.interface_index;
        }
    }
    detail << ']';
    return detail.str();
}

bool join_multicast_group_by_index(
    SOCKET socket_handle,
    const in_addr& multicast_group,
    std::uint32_t interface_index) noexcept {
    GROUP_REQ membership{};
    membership.gr_interface = interface_index;
    auto* group = reinterpret_cast<sockaddr_in*>(&membership.gr_group);
    group->sin_family = AF_INET;
    group->sin_addr = multicast_group;
    return setsockopt(
        socket_handle, IPPROTO_IP, MCAST_JOIN_GROUP,
        reinterpret_cast<const char*>(&membership), sizeof(membership)) == 0;
}

bool join_multicast_group_by_ipv4(
    SOCKET socket_handle,
    const in_addr& multicast_group,
    std::uint32_t interface_ipv4) noexcept {
    ip_mreq membership{};
    membership.imr_multiaddr = multicast_group;
    membership.imr_interface.s_addr = htonl(interface_ipv4);
    return setsockopt(
        socket_handle, IPPROTO_IP, IP_ADD_MEMBERSHIP,
        reinterpret_cast<const char*>(&membership), sizeof(membership)) == 0;
}

bool create_wireless_discovery_sockets(
    const in_addr& multicast_group,
    SocketPair& sockets,
    WirelessMulticastMembership& multicast) {
    sockets.probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockets.ready = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockets.probe == INVALID_SOCKET || sockets.ready == INVALID_SOCKET) {
        multicast.setup_stage = "socket_create_failed";
        multicast.last_socket_error = WSAGetLastError();
        return false;
    }
    if (!set_boolean_socket_option(sockets.ready, SO_REUSEADDR, TRUE)) {
        multicast.setup_stage = "reuse_address_failed";
        multicast.last_socket_error = WSAGetLastError();
        return false;
    }
    in_addr any{};
    any.s_addr = htonl(INADDR_ANY);
    if (!bind_socket(sockets.probe, any, 0) ||
        !bind_socket(sockets.ready, any, kWiredAnnouncementPort)) {
        multicast.setup_stage = "bind_failed";
        multicast.last_socket_error = WSAGetLastError();
        return false;
    }

    const auto candidates = enumerate_multicast_candidates();
    multicast.candidate_interfaces =
        select_wireless_lan_multicast_interfaces(candidates);
    multicast.directed_broadcast_targets =
        wireless_lan_directed_broadcast_targets(
            multicast.candidate_interfaces);
    multicast.broadcast_probe_enabled = set_boolean_socket_option(
        sockets.probe, SO_BROADCAST, TRUE);
    if (!multicast.broadcast_probe_enabled) {
        multicast.broadcast_probe_socket_error = WSAGetLastError();
    }
    for (const auto& selected : multicast.candidate_interfaces) {
        bool joined = join_multicast_group_by_index(
            sockets.ready, multicast_group, selected.interface_index);
        if (joined) {
            ++multicast.indexed_memberships;
        } else {
            ++multicast.indexed_membership_failures;
            multicast.last_socket_error = WSAGetLastError();
            joined = join_multicast_group_by_ipv4(
                sockets.ready, multicast_group, selected.ipv4_host_order);
            if (joined) {
                ++multicast.legacy_memberships;
            } else {
                ++multicast.legacy_membership_failures;
                ++multicast.membership_failures;
                multicast.last_socket_error = WSAGetLastError();
            }
        }
        if (joined) {
            multicast.joined_interfaces.push_back(selected);
        }
    }
    if (multicast.joined_interfaces.empty()) {
        multicast.fallback_any_attempted = true;
        if (join_multicast_group_by_ipv4(sockets.ready, multicast_group, INADDR_ANY)) {
            ++multicast.legacy_memberships;
            multicast.joined_interfaces.push_back(HostIpv4MulticastInterface{});
        } else {
            ++multicast.legacy_membership_failures;
            ++multicast.membership_failures;
            multicast.last_socket_error = WSAGetLastError();
        }
    }
    // The socket bound to INADDR_ANY also receives limited/direct broadcast.
    // Keep it alive when an AP or Windows network stack rejects multicast.
    multicast.setup_stage = multicast.joined_interfaces.empty()
        ? "broadcast_only" : "ready";
    return true;
}

WirelessHostRoute local_route_for_peer(const in_addr& peer) {
    const SOCKET route_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (route_socket == INVALID_SOCKET) return {};
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr = peer;
    destination.sin_port = htons(kWiredProbePort);
    sockaddr_in local{};
    int local_size = sizeof(local);
    DWORD interface_index{};
    const bool connected = connect(
        route_socket, reinterpret_cast<const sockaddr*>(&destination),
        sizeof(destination)) == 0;
    const bool resolved = connected && getsockname(
        route_socket, reinterpret_cast<sockaddr*>(&local), &local_size) == 0;
    const bool interface_resolved = resolved && GetBestInterfaceEx(
        reinterpret_cast<sockaddr*>(&destination), &interface_index) == NO_ERROR;
    closesocket(route_socket);
    if (!interface_resolved || interface_index == 0U ||
        !is_private_unicast(local.sin_addr)) {
        return {};
    }
    return WirelessHostRoute{
        .host_ipv4 = address_to_string(local.sin_addr),
        .interface_index = interface_index,
        .local_ipv4_host_order = ntohl(local.sin_addr.s_addr),
    };
}

void refresh_wireless_host_route_if_missing(
    const in_addr& peer,
    WirelessHostRoute& route,
    Observation& observation) {
    if (!route.host_ipv4.empty() && route.interface_index != 0U) return;
    ++observation.route_resolution_attempts;
    route = local_route_for_peer(peer);
    if (route.host_ipv4.empty() || route.interface_index == 0U) {
        ++observation.route_resolution_failures;
    }
}

bool select_probe_interface(
    SOCKET socket_handle,
    std::uint32_t interface_index,
    Observation& observation) noexcept {
    if (interface_index == 0U) return true;
    const DWORD network_order_index = htonl(interface_index);
    if (setsockopt(
            socket_handle, IPPROTO_IP, IP_UNICAST_IF,
            reinterpret_cast<const char*>(&network_order_index),
            sizeof(network_order_index)) == 0) {
        return true;
    }
    ++observation.probe_interface_selection_failures;
    observation.last_probe_interface_error = WSAGetLastError();
    return false;
}

bool send_probe(
    SOCKET socket_handle,
    const in_addr& mobile,
    std::uint32_t token,
    Observation& observation,
    std::unordered_map<std::uint32_t, PendingProbe>& pending,
    std::uint32_t interface_index = 0U,
    std::uint32_t local_ipv4_host_order = 0U) {
    ++observation.probe_send_attempts;
    const auto datagram = build_cat6_probe(token, kProbeBytes);
    if (datagram.empty() ||
        !select_probe_interface(socket_handle, interface_index, observation)) {
        ++observation.probe_send_failures;
        return false;
    }
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr = mobile;
    destination.sin_port = htons(kWiredProbePort);
    const int sent = sendto(
        socket_handle, datagram.data(), static_cast<int>(datagram.size()), 0,
        reinterpret_cast<const sockaddr*>(&destination), sizeof(destination));
    if (sent != static_cast<int>(datagram.size())) {
        ++observation.probe_send_failures;
        observation.last_probe_send_error = sent == SOCKET_ERROR
            ? WSAGetLastError() : WSAEMSGSIZE;
        return false;
    }
    ++observation.probes_sent;
    pending[token] = PendingProbe{
        .sent_at = std::chrono::steady_clock::now(),
        .interface_index = interface_index,
        .local_ipv4_host_order = local_ipv4_host_order,
    };
    return true;
}

std::optional<HostProbeRouteIdentity> selected_probe_route(
    const WirelessHostRoute& route) noexcept {
    if (route.host_ipv4.empty() || route.interface_index == 0U ||
        route.local_ipv4_host_order == 0U) {
        return std::nullopt;
    }
    return HostProbeRouteIdentity{
        .interface_index = route.interface_index,
        .local_ipv4_host_order = route.local_ipv4_host_order,
    };
}

void send_directed_broadcast_probes(
    SOCKET socket_handle,
    std::span<const HostIpv4DirectedBroadcastTarget> targets,
    std::optional<HostProbeRouteIdentity> route,
    std::uint32_t& next_token,
    Observation& observation,
    std::unordered_map<std::uint32_t, PendingProbe>& pending) {
    for (const auto& target :
         select_wireless_lan_probe_broadcast_targets(targets, route)) {
        if (route.has_value()) {
            ++observation.route_scoped_broadcast_probe_attempts;
        }
        in_addr destination{};
        destination.s_addr = htonl(target.broadcast_ipv4_host_order);
        send_probe(
            socket_handle, destination, next_token++, observation, pending,
            target.interface_index, target.local_ipv4_host_order);
    }
}

void reset_probe_quality_observation(Observation& observation) noexcept {
    observation.probes_sent = 0U;
    observation.probes_received = 0U;
    observation.response_bytes = 0U;
    observation.total_rtt_ms = 0.0;
    observation.total_jitter_ms = 0.0;
    observation.previous_rtt_ms = 0.0;
    observation.has_previous_rtt = false;
}

bool record_probe_ack(
    std::span<const char> datagram,
    Observation& observation,
    std::unordered_map<std::uint32_t, PendingProbe>& pending) {
    const auto ack_token = parse_cat6_probe_ack(datagram);
    if (!ack_token) return false;
    const auto probe = pending.find(*ack_token);
    if (probe == pending.end()) return false;
    const double rtt_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - probe->second.sent_at).count();
    ++observation.probes_received;
    observation.response_bytes += static_cast<std::uint32_t>(datagram.size());
    observation.total_rtt_ms += rtt_ms;
    if (observation.has_previous_rtt) {
        observation.total_jitter_ms += std::abs(rtt_ms - observation.previous_rtt_ms);
    }
    observation.previous_rtt_ms = rtt_ms;
    observation.has_previous_rtt = true;
    pending.erase(probe);
    return true;
}

Cat6LinkQuality calculate_quality(const Observation& observation) noexcept {
    Cat6LinkQuality quality{};
    quality.reachable = observation.probes_received > 0U;
    quality.probe_samples = observation.probes_received;
    if (observation.probes_sent > 0U) {
        quality.packet_loss_ratio = 1.0 - static_cast<double>(observation.probes_received) /
            static_cast<double>(observation.probes_sent);
    }
    if (observation.probes_received == 0U) return quality;
    quality.rtt_ms = observation.total_rtt_ms / observation.probes_received;
    quality.jitter_ms = observation.probes_received > 1U
        ? observation.total_jitter_ms / (observation.probes_received - 1U) : 0.0;
    quality.throughput_mbps = observation.total_rtt_ms > 0.0
        ? (static_cast<double>(observation.response_bytes) * 8.0) /
            (observation.total_rtt_ms * 1000.0) : 0.0;
    return quality;
}

WirelessLanDiscoveryOutcome make_wireless_discovery_outcome(
    std::optional<Cat6SessionSnapshot> session,
    std::string_view result,
    const WirelessMulticastMembership& multicast,
    const Observation& observation) {
    std::ostringstream diagnostic;
    diagnostic << "result=" << result
               << " setup_stage=" << multicast.setup_stage
               << " candidate_interfaces="
               << describe_interface_addresses(multicast.candidate_interfaces)
               << " joined_interfaces="
               << describe_interface_addresses(multicast.joined_interfaces)
               << " directed_broadcast_targets=[";
    for (std::size_t index = 0;
         index < multicast.directed_broadcast_targets.size(); ++index) {
        if (index != 0U) diagnostic << ',';
        const auto& target = multicast.directed_broadcast_targets[index];
        diagnostic << host_order_address_to_string(
                          target.broadcast_ipv4_host_order)
                   << '@' << host_order_address_to_string(
                          target.local_ipv4_host_order)
                   << "/if" << target.interface_index;
    }
    diagnostic << ']'
               << " broadcast_probe_enabled=" << multicast.broadcast_probe_enabled
               << " broadcast_probe_socket_error="
               << multicast.broadcast_probe_socket_error
               << " membership_failures=" << multicast.membership_failures
               << " indexed_memberships=" << multicast.indexed_memberships
               << " legacy_memberships=" << multicast.legacy_memberships
               << " indexed_membership_failures="
               << multicast.indexed_membership_failures
               << " legacy_membership_failures="
               << multicast.legacy_membership_failures
               << " fallback_any_attempted=" << multicast.fallback_any_attempted
               << " last_socket_error=" << multicast.last_socket_error
               << " ready_messages=" << observation.ready_messages
               << " ready_datagrams_received="
               << observation.ready_datagrams_received
               << " invalid_ready_datagrams="
               << observation.invalid_ready_datagrams
               << " probes_sent=" << observation.probes_sent
               << " probe_send_attempts=" << observation.probe_send_attempts
               << " probe_send_failures=" << observation.probe_send_failures
               << " probe_interface_selection_failures="
               << observation.probe_interface_selection_failures
               << " last_probe_send_error="
               << observation.last_probe_send_error
               << " last_probe_interface_error="
               << observation.last_probe_interface_error
               << " probes_received=" << observation.probes_received
               << " probe_datagrams_received="
               << observation.probe_datagrams_received
               << " rejected_source_datagrams="
               << observation.rejected_source_datagrams
               << " select_failures=" << observation.select_failures
               << " ready_receive_failures="
               << observation.ready_receive_failures
               << " probe_receive_failures="
               << observation.probe_receive_failures
               << " last_receive_error=" << observation.last_receive_error
               << " route_resolution_attempts="
               << observation.route_resolution_attempts
               << " route_resolution_failures="
               << observation.route_resolution_failures
               << " route_scoped_broadcast_probe_attempts="
               << observation.route_scoped_broadcast_probe_attempts
               << " first_ready_source="
               << (observation.first_ready_source.empty()
                       ? "none" : observation.first_ready_source)
               << " first_probe_ack_source="
               << (observation.first_probe_ack_source.empty()
                       ? "none" : observation.first_probe_ack_source);
    return WirelessLanDiscoveryOutcome{
        .session = std::move(session),
        .diagnostic = diagnostic.str(),
    };
}

std::int64_t wait_milliseconds(
    std::chrono::steady_clock::time_point deadline,
    std::chrono::steady_clock::time_point next_probe) noexcept {
    const auto now = std::chrono::steady_clock::now();
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - now);
    const auto until_probe = std::chrono::duration_cast<std::chrono::milliseconds>(
        next_probe - now);
    return (std::max)(
        std::int64_t{1},
        (std::min)(remaining.count(), (std::max)(std::int64_t{1}, until_probe.count())));
}

std::optional<Cat6SessionSnapshot> measure_known_session(
    const Cat6SessionSnapshot& endpoint,
    std::chrono::milliseconds timeout) {
    WinsockSession winsock;
    if (!winsock.ready() || timeout <= std::chrono::milliseconds::zero() ||
        endpoint.host_ipv4.empty() || endpoint.mobile_ipv4.empty()) {
        return std::nullopt;
    }
    in_addr host{};
    in_addr mobile{};
    if (!parse_address(endpoint.host_ipv4, host) ||
        !parse_address(endpoint.mobile_ipv4, mobile)) {
        return std::nullopt;
    }
    SocketPair sockets;
    if (!create_unicast_sockets(host, sockets)) return std::nullopt;

    Observation observation{};
    std::unordered_map<std::uint32_t, PendingProbe> pending;
    std::uint32_t next_token{1U};
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    auto next_probe = std::chrono::steady_clock::now();
    std::array<char, 1500> buffer{};
    while (std::chrono::steady_clock::now() < deadline) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= next_probe) {
            send_probe(sockets.probe, mobile, next_token++, observation, pending);
            next_probe = now + kProbeInterval;
        }
        const std::int64_t wait_ms = wait_milliseconds(deadline, next_probe);
        timeval wait{};
        wait.tv_sec = static_cast<long>(wait_ms / 1000LL);
        wait.tv_usec = static_cast<long>((wait_ms % 1000LL) * 1000LL);
        fd_set readable{};
        FD_SET(sockets.probe, &readable);
        FD_SET(sockets.ready, &readable);
        if (select(0, &readable, nullptr, nullptr, &wait) <= 0) continue;
        for (const SOCKET received_socket : {sockets.ready, sockets.probe}) {
            if (!FD_ISSET(received_socket, &readable)) continue;
            sockaddr_in source{};
            int source_size = sizeof(source);
            const int received = recvfrom(
                received_socket, buffer.data(), static_cast<int>(buffer.size()), 0,
                reinterpret_cast<sockaddr*>(&source), &source_size);
            if (received <= 0 || !is_source(source, mobile)) continue;
            const auto datagram = std::span<const char>(
                buffer.data(), static_cast<std::size_t>(received));
            if (received_socket == sockets.ready) {
                const auto ready = parse_cat6_ready_message(
                    std::string_view(datagram.data(), datagram.size()));
                if (!ready || ready->ipv4 != endpoint.mobile_ipv4) continue;
                ++observation.ready_messages;
                send_probe(sockets.probe, mobile, next_token++, observation, pending);
                continue;
            }
            record_probe_ack(datagram, observation, pending);
        }
    }
    const Cat6LinkQuality quality = calculate_quality(observation);
    if (!quality.reachable) return std::nullopt;
    return Cat6SessionSnapshot{
        endpoint.host_ipv4, endpoint.mobile_ipv4, endpoint.transport, quality};
}

}  // namespace

std::vector<HostIpv4MulticastInterface> select_wireless_lan_multicast_interfaces(
    std::span<const HostIpv4MulticastCandidate> candidates) {
    std::vector<HostIpv4MulticastInterface> selected;
    for (const auto& candidate : candidates) {
        const HostIpv4MulticastInterface interface{
            candidate.interface_index,
            candidate.ipv4_host_order,
            candidate.prefix_length};
        if (!candidate.operational || !candidate.multicast_capable ||
            !candidate.address_preferred ||
            candidate.interface_index == 0U ||
            !is_private_unicast(candidate.ipv4_host_order) ||
            std::ranges::find(selected, interface) != selected.end()) {
            continue;
        }
        selected.push_back(interface);
    }
    return selected;
}

std::vector<std::uint32_t> wireless_lan_directed_broadcasts(
    std::span<const HostIpv4MulticastInterface> interfaces) {
    std::vector<std::uint32_t> broadcasts;
    for (const auto& target :
         wireless_lan_directed_broadcast_targets(interfaces)) {
        if (std::ranges::find(
                broadcasts, target.broadcast_ipv4_host_order) != broadcasts.end()) {
            continue;
        }
        broadcasts.push_back(target.broadcast_ipv4_host_order);
    }
    return broadcasts;
}

std::vector<HostIpv4DirectedBroadcastTarget>
wireless_lan_directed_broadcast_targets(
    std::span<const HostIpv4MulticastInterface> interfaces) {
    std::vector<HostIpv4DirectedBroadcastTarget> targets;
    for (const auto& selected : interfaces) {
        if (selected.prefix_length == 0U || selected.prefix_length > 30U) continue;
        const std::uint32_t host_bits = 32U - selected.prefix_length;
        const std::uint32_t host_mask =
            static_cast<std::uint32_t>((std::uint64_t{1} << host_bits) - 1U);
        const std::uint32_t broadcast = selected.ipv4_host_order | host_mask;
        if (!is_private_unicast(broadcast) ||
            broadcast == selected.ipv4_host_order) {
            continue;
        }
        const HostIpv4DirectedBroadcastTarget target{
            selected.interface_index,
            selected.ipv4_host_order,
            broadcast,
            selected.prefix_length,
        };
        if (std::ranges::find(targets, target) == targets.end()) {
            targets.push_back(target);
        }
    }
    return targets;
}

bool wireless_lan_discovery_evidence_ready(
    std::uint32_t probe_acknowledgements,
    std::string_view host_ipv4,
    std::string_view mobile_ipv4) noexcept {
    return probe_acknowledgements >= kWirelessDiscoveryProbeAcks &&
        !host_ipv4.empty() && !mobile_ipv4.empty();
}

std::optional<Cat6SessionSnapshot> measure_mobile_session(
    const Cat6SessionSnapshot& endpoint,
    std::chrono::milliseconds timeout) {
    return measure_known_session(endpoint, timeout);
}

std::optional<Cat6SessionSnapshot> measure_cat6_mobile_session(
    std::chrono::milliseconds timeout) {
    return measure_known_session(
        Cat6SessionSnapshot{
            kWiredHostIpv4, kWiredMobileIpv4, kCat6TransportName, {}},
        timeout);
}

WirelessLanDiscoveryOutcome discover_wireless_lan_mobile_session(
    std::chrono::milliseconds timeout,
    std::stop_token stop_token) {
    WirelessMulticastMembership multicast;
    Observation observation{};
    WinsockSession winsock;
    if (!winsock.ready() || timeout <= std::chrono::milliseconds::zero()) {
        multicast.setup_stage = winsock.ready() ? "invalid_timeout" : "winsock_failed";
        return make_wireless_discovery_outcome(
            std::nullopt, multicast.setup_stage, multicast, observation);
    }
    in_addr multicast_group{};
    if (!parse_address(kWirelessLanDiscoveryIpv4, multicast_group)) {
        multicast.setup_stage = "invalid_multicast_group";
        return make_wireless_discovery_outcome(
            std::nullopt, multicast.setup_stage, multicast, observation);
    }
    SocketPair sockets;
    if (!create_wireless_discovery_sockets(multicast_group, sockets, multicast)) {
        return make_wireless_discovery_outcome(
            std::nullopt, "socket_setup_failed", multicast, observation);
    }

    std::unordered_map<std::uint32_t, PendingProbe> pending;
    std::optional<in_addr> mobile;
    std::string mobile_ipv4;
    WirelessHostRoute host_route;
    std::uint32_t next_token{1U};
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    auto next_probe = std::chrono::steady_clock::now();
    std::array<char, 1500> buffer{};
    while (!stop_token.stop_requested() &&
           std::chrono::steady_clock::now() < deadline) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= next_probe) {
            const auto route = selected_probe_route(host_route);
            if (mobile.has_value() && route.has_value()) {
                send_probe(
                    sockets.probe, *mobile, next_token++, observation, pending,
                    route->interface_index, route->local_ipv4_host_order);
            }
            if (multicast.broadcast_probe_enabled) {
                // Keep a route-scoped directed-broadcast probe alongside the
                // unicast probe after Ready. Some Android vendor kernels send
                // Ready successfully but do not deliver the first unicast
                // datagrams to a newly network-bound UDP listener.
                send_directed_broadcast_probes(
                    sockets.probe, multicast.directed_broadcast_targets,
                    route, next_token, observation, pending);
            }
            next_probe = now + kProbeInterval;
        }
        const std::int64_t wait_ms = wait_milliseconds(deadline, next_probe);
        timeval wait{};
        wait.tv_sec = static_cast<long>(wait_ms / 1000LL);
        wait.tv_usec = static_cast<long>((wait_ms % 1000LL) * 1000LL);
        fd_set readable{};
        FD_SET(sockets.probe, &readable);
        FD_SET(sockets.ready, &readable);
        const int selected = select(0, &readable, nullptr, nullptr, &wait);
        if (selected == SOCKET_ERROR) {
            ++observation.select_failures;
            observation.last_receive_error = WSAGetLastError();
            continue;
        }
        if (selected == 0) continue;
        for (const SOCKET received_socket : {sockets.ready, sockets.probe}) {
            if (!FD_ISSET(received_socket, &readable)) continue;
            sockaddr_in source{};
            int source_size = sizeof(source);
            const int received = recvfrom(
                received_socket, buffer.data(), static_cast<int>(buffer.size()), 0,
                reinterpret_cast<sockaddr*>(&source), &source_size);
            if (received == SOCKET_ERROR) {
                if (received_socket == sockets.ready) {
                    ++observation.ready_receive_failures;
                } else {
                    ++observation.probe_receive_failures;
                }
                observation.last_receive_error = WSAGetLastError();
                continue;
            }
            if (received <= 0) continue;
            if (!is_private_unicast(source.sin_addr)) {
                ++observation.rejected_source_datagrams;
                continue;
            }
            const auto datagram = std::span<const char>(
                buffer.data(), static_cast<std::size_t>(received));
            const std::string source_ipv4 = address_to_string(source.sin_addr);
            if (received_socket == sockets.ready) {
                ++observation.ready_datagrams_received;
                const auto ready = parse_cat6_ready_message(
                    std::string_view(datagram.data(), datagram.size()));
                if (!ready || source_ipv4.empty() || ready->ipv4 != source_ipv4 ||
                    source_ipv4 == kWiredMobileIpv4) {
                    ++observation.invalid_ready_datagrams;
                    continue;
                }
                if (mobile.has_value() &&
                    mobile->s_addr != source.sin_addr.s_addr) {
                    ++observation.rejected_source_datagrams;
                    continue;
                }
                if (!mobile.has_value()) {
                    mobile = source.sin_addr;
                    mobile_ipv4 = source_ipv4;
                    reset_probe_quality_observation(observation);
                    pending.clear();
                }
                if (observation.first_ready_source.empty()) {
                    observation.first_ready_source = source_ipv4;
                }
                // A Ready heartbeat can arrive before Windows publishes the
                // route for a newly connected WLAN. Retry the route lookup on
                // every heartbeat until it succeeds; retaining the peer with
                // an empty host address for the whole discovery window would
                // otherwise produce a deterministic false timeout.
                refresh_wireless_host_route_if_missing(
                    source.sin_addr, host_route, observation);
                ++observation.ready_messages;
                const auto route = selected_probe_route(host_route);
                if (route.has_value()) {
                    send_probe(
                        sockets.probe, *mobile, next_token++, observation,
                        pending, route->interface_index,
                        route->local_ipv4_host_order);
                    if (multicast.broadcast_probe_enabled) {
                        send_directed_broadcast_probes(
                            sockets.probe,
                            multicast.directed_broadcast_targets, route,
                            next_token, observation, pending);
                    }
                    next_probe = now + kProbeInterval;
                }
                continue;
            }
            ++observation.probe_datagrams_received;
            if (!mobile.has_value()) {
                const auto ack_token = parse_cat6_probe_ack(datagram);
                const auto discovered_probe = ack_token
                    ? pending.find(*ack_token) : pending.end();
                if (!ack_token || discovered_probe == pending.end() ||
                    source_ipv4 == kWiredMobileIpv4) {
                    continue;
                }
                const PendingProbe matched_probe = discovered_probe->second;
                mobile = source.sin_addr;
                mobile_ipv4 = source_ipv4;
                host_route = WirelessHostRoute{
                    .host_ipv4 = host_order_address_to_string(
                        matched_probe.local_ipv4_host_order),
                    .interface_index = matched_probe.interface_index,
                    .local_ipv4_host_order =
                        matched_probe.local_ipv4_host_order,
                };
                reset_probe_quality_observation(observation);
                // Retain the one directed-broadcast transmission that owns
                // this ACK while discarding probes sent on other interfaces.
                // Otherwise the next unicast ACK would make received > sent
                // and produce a negative packet-loss ratio.
                observation.probes_sent = 1U;
                pending.clear();
                pending.emplace(*ack_token, matched_probe);
                next_probe = now;
            } else if (!is_source(source, *mobile)) {
                ++observation.rejected_source_datagrams;
                continue;
            }
            // Directed-broadcast ACK discovery has the same route-publication
            // race as Ready heartbeats. A later ACK must be allowed to repair
            // an initially empty local route identity.
            refresh_wireless_host_route_if_missing(
                source.sin_addr, host_route, observation);
            const bool ack_recorded =
                record_probe_ack(datagram, observation, pending);
            if (ack_recorded && observation.first_probe_ack_source.empty()) {
                observation.first_probe_ack_source = source_ipv4;
            }
            if (wireless_lan_discovery_evidence_ready(
                    observation.probes_received,
                    host_route.host_ipv4, mobile_ipv4)) {
                const Cat6LinkQuality quality = calculate_quality(observation);
                return make_wireless_discovery_outcome(
                    Cat6SessionSnapshot{
                        host_route.host_ipv4, mobile_ipv4,
                        kWirelessLanUdpTransportName, quality},
                    "ready", multicast, observation);
            }
        }
    }
    if (stop_token.stop_requested()) {
        return make_wireless_discovery_outcome(
            std::nullopt, "cancelled", multicast, observation);
    }
    const Cat6LinkQuality quality = calculate_quality(observation);
    if (!wireless_lan_discovery_evidence_ready(
            observation.probes_received,
            host_route.host_ipv4, mobile_ipv4)) {
        return make_wireless_discovery_outcome(
            std::nullopt, "timeout", multicast, observation);
    }
    return make_wireless_discovery_outcome(
        Cat6SessionSnapshot{
            host_route.host_ipv4, mobile_ipv4,
            kWirelessLanUdpTransportName, quality},
        "ready_at_deadline", multicast, observation);
}

std::optional<Cat6SessionSnapshot> measure_wireless_lan_mobile_session(
    std::chrono::milliseconds timeout,
    std::stop_token stop_token) {
    return discover_wireless_lan_mobile_session(timeout, stop_token).session;
}

}  // namespace vfdual
