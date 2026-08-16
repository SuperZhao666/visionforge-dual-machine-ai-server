#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>

namespace vfdual {
class IsolatedDhcpServer;
}

namespace vfdual::host::application {

/** Stable endpoint information consumed by the desktop UI. */
struct HostMobileEndpointReadModel final {
    std::string mobile_ipv4;
    std::string transport;
    bool reachable{};
    double packet_loss_ratio{1.0};
    double jitter_ms{};
    double rtt_ms{};
    double throughput_mbps{};
};

/**
 * Hides CAT6 bootstrap, firewall repair and wireless probe implementations
 * behind one cancellable application operation.
 */
class HostEndpointDiscoveryFacade final {
public:
    explicit HostEndpointDiscoveryFacade(
        vfdual::IsolatedDhcpServer* direct_link_owner = nullptr);
    ~HostEndpointDiscoveryFacade();
    HostEndpointDiscoveryFacade(const HostEndpointDiscoveryFacade&) = delete;
    HostEndpointDiscoveryFacade& operator=(const HostEndpointDiscoveryFacade&) = delete;

    [[nodiscard]] std::optional<HostMobileEndpointReadModel> discover(
        std::chrono::milliseconds cat6_timeout,
        std::chrono::milliseconds wireless_timeout,
        std::stop_token stop_token) const;

private:
    struct State;
    std::unique_ptr<State> state_;
};

}  // namespace vfdual::host::application
