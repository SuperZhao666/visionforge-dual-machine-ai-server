#include "vfdual/host_cat6_monitor.hpp"
#include "vfdual/host_cat6_session.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifndef VFDUAL_SOURCE_DIR
#error "VFDUAL_SOURCE_DIR must point at the dual_machine_runtime source directory"
#endif

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
    std::exit(EXIT_FAILURE);
}

std::string read_source(const char* relative_path) {
    const std::string path = std::string{VFDUAL_SOURCE_DIR} + "/" + relative_path;
    std::ifstream input{path, std::ios::binary};
    require(input.good(), "input.good()", __FILE__, __LINE__);
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

int main() {
    using namespace std::chrono_literals;
    using vfdual::HostIpv4DirectedBroadcastTarget;
    using vfdual::HostIpv4MulticastCandidate;
    using vfdual::HostIpv4MulticastInterface;
    constexpr std::array multicast_candidates{
        HostIpv4MulticastCandidate{9U, 0x0A391701U, 24U, true, true, true},
        HostIpv4MulticastCandidate{18U, 0xC0A80112U, 24U, true, true, true},
        HostIpv4MulticastCandidate{18U, 0xC0A80112U, 24U, true, true, true},
        HostIpv4MulticastCandidate{19U, 0xC0A80112U, 24U, true, true, true},
        HostIpv4MulticastCandidate{20U, 0xA9FE0102U, 16U, true, true, true},
        HostIpv4MulticastCandidate{21U, 0x7F000001U, 8U, true, true, true},
        HostIpv4MulticastCandidate{22U, 0xC0A8012AU, 24U, false, true, true},
        HostIpv4MulticastCandidate{23U, 0xC0A8012BU, 24U, true, false, true},
        HostIpv4MulticastCandidate{24U, 0xC0A8012CU, 24U, true, true, false},
        HostIpv4MulticastCandidate{0U, 0xC0A8012DU, 24U, true, true, true},
    };
    const auto selected_multicast_interfaces =
        vfdual::select_wireless_lan_multicast_interfaces(multicast_candidates);
    CHECK(selected_multicast_interfaces.size() == 3U);
    CHECK(std::ranges::find(
              selected_multicast_interfaces,
              HostIpv4MulticastInterface{9U, 0x0A391701U, 24U}) !=
          selected_multicast_interfaces.end());
    CHECK(std::ranges::find(
              selected_multicast_interfaces,
              HostIpv4MulticastInterface{18U, 0xC0A80112U, 24U}) !=
          selected_multicast_interfaces.end());
    CHECK(std::ranges::find(
              selected_multicast_interfaces,
              HostIpv4MulticastInterface{19U, 0xC0A80112U, 24U}) !=
           selected_multicast_interfaces.end());
    const auto directed_broadcasts =
        vfdual::wireless_lan_directed_broadcasts(selected_multicast_interfaces);
    CHECK(directed_broadcasts.size() == 2U);
    CHECK(std::ranges::find(directed_broadcasts, 0x0A3917FFU) !=
          directed_broadcasts.end());
    CHECK(std::ranges::find(directed_broadcasts, 0xC0A801FFU) !=
          directed_broadcasts.end());
    const auto directed_broadcast_targets =
        vfdual::wireless_lan_directed_broadcast_targets(
            selected_multicast_interfaces);
    CHECK(directed_broadcast_targets.size() == 3U);
    CHECK(std::ranges::find(
              directed_broadcast_targets,
              HostIpv4DirectedBroadcastTarget{
                  18U, 0xC0A80112U, 0xC0A801FFU, 24U}) !=
          directed_broadcast_targets.end());
    CHECK(std::ranges::find(
              directed_broadcast_targets,
              HostIpv4DirectedBroadcastTarget{
                  19U, 0xC0A80112U, 0xC0A801FFU, 24U}) !=
          directed_broadcast_targets.end());
    constexpr std::array shared_address_candidates{
        HostIpv4MulticastCandidate{
            30U, 0x64401403U, 24U, true, true, true},
    };
    const auto shared_address_interfaces =
        vfdual::select_wireless_lan_multicast_interfaces(
            shared_address_candidates);
    CHECK(shared_address_interfaces.size() == 1U);
    const std::vector expected_shared_address_targets{
        HostIpv4DirectedBroadcastTarget{
            30U, 0x64401403U, 0x644014FFU, 24U},
    };
    CHECK(vfdual::wireless_lan_directed_broadcast_targets(
              shared_address_interfaces) == expected_shared_address_targets);
    constexpr std::array unsafe_broadcast_interfaces{
        HostIpv4MulticastInterface{25U, 0xC0A80101U, 8U},
        HostIpv4MulticastInterface{26U, 0xC0A80101U, 31U},
    };
    CHECK(vfdual::wireless_lan_directed_broadcasts(
              unsafe_broadcast_interfaces).empty());
    CHECK(!vfdual::wireless_lan_discovery_evidence_ready(
        0U, "192.168.1.18", "192.168.1.42"));
    CHECK(!vfdual::wireless_lan_discovery_evidence_ready(
        1U, "192.168.1.18", "192.168.1.42"));
    CHECK(vfdual::wireless_lan_discovery_evidence_ready(
        2U, "192.168.1.18", "192.168.1.42"));
    CHECK(!vfdual::wireless_lan_discovery_evidence_ready(
        2U, "", "192.168.1.42"));
    CHECK(!vfdual::wireless_lan_discovery_evidence_ready(
        2U, "192.168.1.18", ""));

    CHECK(vfdual::host_cat6_monitor_is_reachable(0U, 0ms));
    CHECK(vfdual::host_cat6_monitor_is_reachable(2U, 3999ms));
    CHECK(!vfdual::host_cat6_monitor_is_reachable(3U, 100ms));
    CHECK(!vfdual::host_cat6_monitor_is_reachable(0U, 4001ms));
    CHECK(!vfdual::host_cat6_monitor_requires_recovery(2U, 4001ms));
    CHECK(!vfdual::host_cat6_monitor_requires_recovery(5U, 9999ms));
    CHECK(!vfdual::host_cat6_monitor_requires_recovery(5U, 10000ms));
    CHECK(!vfdual::host_cat6_monitor_requires_recovery(4U, 10001ms));
    CHECK(vfdual::host_cat6_monitor_requires_recovery(5U, 10001ms));

    const std::string header =
        read_source("host/windows/include/vfdual/host_cat6_monitor.hpp");
    const std::string source =
        read_source("host/windows/src/host_cat6_monitor.cpp");
    const std::string runtime_source =
        read_source("host/windows/src/host_runtime_service.cpp");
    const std::string session_header =
        read_source("host/windows/include/vfdual/host_cat6_session.hpp");
    const std::string session_source =
        read_source("host/windows/src/host_cat6_session.cpp");
    CHECK(header.find("[[nodiscard]] bool start(const Cat6SessionSnapshot& initial) noexcept;") !=
          std::string::npos);
    CHECK(header.find("void run() noexcept;") != std::string::npos);
    CHECK(header.find("std::uint64_t monitor_faults{};") != std::string::npos);
    CHECK(source.find("worker_ = std::thread([this]() noexcept { run(); });") !=
          std::string::npos);
    CHECK(source.find("catch (...)") != std::string::npos);
    CHECK(source.find("++monitor_faults_;") != std::string::npos);
    CHECK(source.find("monitor_faults_ = 1U;") != std::string::npos);
    CHECK(source.find("return false;") != std::string::npos);
    CHECK(source.find("if (worker_.joinable()) worker_.join();") !=
          std::string::npos);
    CHECK(runtime_source.find("RuntimeFirewallAuditor firewall_auditor;") !=
          std::string::npos);
    CHECK(runtime_source.find("firewall_auditor.take_result()") !=
          std::string::npos);
    CHECK(runtime_source.find("!firewall_auditor.running()") !=
          std::string::npos);
    CHECK(runtime_source.find(
              "const HostFirewallProvisioningResult firewall_health =\n"
              "                ensure_runtime_firewall();") ==
          std::string::npos);
    CHECK(runtime_source.find("summarize_bootstrap_diagnostics") !=
          std::string::npos);
    CHECK(runtime_source.find("\"count=\" + std::to_string(diagnostics.size())") !=
          std::string::npos);
    CHECK(runtime_source.find("host_cat6_monitor_start_failed") != std::string::npos);
    CHECK(runtime_source.find("cat6_monitor_active = cat6_monitor.start(active_session);") !=
          std::string::npos);
    CHECK(session_header.find("CAT6-ready heartbeat or an active unicast probe ACK") !=
          std::string::npos);
    CHECK(session_header.find("measure_wireless_lan_mobile_session") != std::string::npos);
    CHECK(session_header.find("measure_mobile_session") != std::string::npos);
    CHECK(session_source.find("constexpr auto kProbeInterval") != std::string::npos);
    CHECK(session_source.find("measure_wireless_lan_mobile_session") != std::string::npos);
    CHECK(session_source.find("select_wireless_lan_multicast_interfaces") !=
          std::string::npos);
    CHECK(session_source.find("MCAST_JOIN_GROUP") != std::string::npos);
    CHECK(session_source.find("membership.gr_interface = interface_index") !=
          std::string::npos);
    CHECK(session_source.find("IP_ADD_MEMBERSHIP") != std::string::npos);
    CHECK(session_source.find("membership.imr_interface.s_addr = htonl(interface_ipv4)") !=
          std::string::npos);
    CHECK(session_source.find("SO_BROADCAST") != std::string::npos);
    CHECK(session_source.find("IP_UNICAST_IF") != std::string::npos);
    CHECK(session_source.find("wireless_lan_directed_broadcasts") !=
          std::string::npos);
    CHECK(session_source.find("wireless_lan_directed_broadcast_targets") !=
          std::string::npos);
    CHECK(session_source.find("probe_send_failures=") != std::string::npos);
    CHECK(session_source.find("last_probe_send_error=") != std::string::npos);
    CHECK(session_source.find("ready_receive_failures=") != std::string::npos);
    CHECK(session_source.find("first_ready_source=") != std::string::npos);
    CHECK(session_source.find("observation.probes_sent = 1U;") !=
          std::string::npos);
    const std::string route_refresh =
        "refresh_wireless_host_route_if_missing(";
    const auto route_refresh_definition = session_source.find(route_refresh);
    CHECK(route_refresh_definition != std::string::npos);
    const auto first_route_refresh_call = session_source.find(
        route_refresh, route_refresh_definition + route_refresh.size());
    CHECK(first_route_refresh_call != std::string::npos);
    CHECK(session_source.find(
              route_refresh, first_route_refresh_call + route_refresh.size()) !=
          std::string::npos);
    CHECK(session_source.find("!quality.reachable || host_ipv4.empty()") ==
          std::string::npos);
    CHECK(session_source.find("kWirelessLanUdpTransportName") != std::string::npos);
    CHECK(session_source.find("quality.reachable = observation.probes_received > 0U;") !=
          std::string::npos);
    CHECK(session_source.find("send_probe(sockets.probe, mobile, next_token++, observation, "
                              "pending);") != std::string::npos);
    return 0;
}
