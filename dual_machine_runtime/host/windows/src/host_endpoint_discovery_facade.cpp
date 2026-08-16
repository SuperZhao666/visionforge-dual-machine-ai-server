#include "vfdual/host/application/host_endpoint_discovery_facade.hpp"

#include "vfdual/host_cat6_bootstrap.hpp"
#include "vfdual/host_cat6_session.hpp"
#include "vfdual/host_firewall_provisioner.hpp"
#include "vfdual/isolated_dhcp_server.hpp"

namespace vfdual::host::application {
namespace {

HostMobileEndpointReadModel map_endpoint(const vfdual::Cat6SessionSnapshot& source) {
    return HostMobileEndpointReadModel{
        source.mobile_ipv4,
        source.transport,
        source.quality.reachable,
        source.quality.packet_loss_ratio,
        source.quality.jitter_ms,
        source.quality.rtt_ms,
        source.quality.throughput_mbps};
}

}  // namespace

struct HostEndpointDiscoveryFacade::State final {
    explicit State(vfdual::IsolatedDhcpServer* owner) : direct_link_owner(owner) {}
    vfdual::IsolatedDhcpServer* direct_link_owner{};
};

HostEndpointDiscoveryFacade::HostEndpointDiscoveryFacade(
    vfdual::IsolatedDhcpServer* owner)
    : state_(std::make_unique<State>(owner)) {}
HostEndpointDiscoveryFacade::~HostEndpointDiscoveryFacade() = default;

std::optional<HostMobileEndpointReadModel> HostEndpointDiscoveryFacade::discover(
    std::chrono::milliseconds cat6_timeout,
    std::chrono::milliseconds wireless_timeout,
    std::stop_token stop_token) const {
    const auto bootstrap = vfdual::bootstrap_host_cat6_link(
        cat6_timeout, state_->direct_link_owner, stop_token);
    if (bootstrap.mobile.has_value()) return map_endpoint(*bootstrap.mobile);
    if (stop_token.stop_requested()) return std::nullopt;

    const auto firewall = vfdual::ensure_host_firewall_rules_automatically();
    if (!vfdual::host_firewall_is_ready(firewall.status)) return std::nullopt;
    const auto wireless = vfdual::measure_wireless_lan_mobile_session(
        wireless_timeout, stop_token);
    if (!wireless.has_value()) return std::nullopt;
    return map_endpoint(*wireless);
}

}  // namespace vfdual::host::application
