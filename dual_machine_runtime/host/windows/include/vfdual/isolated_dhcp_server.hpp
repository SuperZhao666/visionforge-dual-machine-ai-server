#pragma once

#include "vfdual/isolated_dhcp_protocol.hpp"
#include "vfdual/wired_link_contract.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

namespace vfdual {

enum class IsolatedDhcpStartupStage : std::uint32_t {
    none = 0,
    validate_config = 1,
    winsock = 2,
    parse_config = 3,
    find_interface = 4,
    create_socket = 5,
    exclusive_address = 6,
    interface_filter = 7,
    bind_socket = 8,
    protocol = 9,
    running = 10,
    worker_thread = 11,
};

inline constexpr int kIsolatedDhcpInterfaceProbeAttempts = 30;
inline constexpr auto kIsolatedDhcpInterfaceProbeInterval =
    std::chrono::milliseconds{100};
inline constexpr int kIsolatedDhcpStartupWaitAttempts = 400;
inline constexpr auto kIsolatedDhcpStartupWaitInterval =
    std::chrono::milliseconds{10};

[[nodiscard]] constexpr bool isolated_dhcp_startup_wait_covers_interface_probe()
    noexcept {
    return kIsolatedDhcpStartupWaitInterval *
        kIsolatedDhcpStartupWaitAttempts >=
        kIsolatedDhcpInterfaceProbeInterval *
        kIsolatedDhcpInterfaceProbeAttempts;
}

[[nodiscard]] const char* isolated_dhcp_startup_stage_name(
    IsolatedDhcpStartupStage stage) noexcept;

struct IsolatedDhcpMetrics final {
    std::uint64_t received_packets{};
    std::uint64_t discovers{};
    std::uint64_t requests{};
    std::uint64_t offers{};
    std::uint64_t acknowledgements{};
    std::uint64_t rejected_packets{};
    std::uint64_t malformed_packets{};
    std::uint64_t local_interface_packets{};
    std::uint64_t client_conflict_packets{};
    std::uint64_t request_state_packets{};
    std::uint64_t address_mismatch_packets{};
    std::uint64_t explicit_source_sends{};
    std::uint64_t send_failures{};
    std::uint64_t inbound_interface_drops{};
    std::uint64_t inbound_unverified_drops{};
    std::uint32_t last_send_error{};
    std::uint32_t interface_filter_active{};
    std::uint32_t interface_filter_error{};
    std::uint32_t packet_info_active{};
    std::uint32_t packet_info_error{};
    std::uint32_t interface_index{};
    std::uint32_t startup_stage{};
    std::uint32_t interface_match_count{};
    IsolatedDhcpRejectReason last_reject_reason{IsolatedDhcpRejectReason::none};
};

/**
 * Minimal single-lease DHCP server for the physically isolated CAT6 link.
 *
 * The lease deliberately contains only an IPv4 address and subnet mask. It
 * never emits router (option 3), DNS (option 6), domain, proxy or NTP options,
 * so Android cannot promote this link into an Internet default route.
 */
class IsolatedDhcpServer final {
public:
    IsolatedDhcpServer() = default;
    ~IsolatedDhcpServer();

    IsolatedDhcpServer(const IsolatedDhcpServer&) = delete;
    IsolatedDhcpServer& operator=(const IsolatedDhcpServer&) = delete;

    [[nodiscard]] bool start(
        std::string server_ipv4 = kWiredHostIpv4,
        std::string lease_ipv4 = kWiredMobileIpv4,
        std::string subnet_mask = kWiredSubnetMask,
        std::uint16_t server_port = kWiredDhcpServerPort,
        std::uint16_t client_port = kWiredDhcpClientPort) noexcept;
    void stop() noexcept;

    [[nodiscard]] bool running() const noexcept;
    [[nodiscard]] std::uint32_t last_error() const noexcept;
    [[nodiscard]] IsolatedDhcpStartupStage startup_stage() const noexcept;
    [[nodiscard]] IsolatedDhcpMetrics metrics() const noexcept;

private:
    void run() noexcept;
    void set_startup_stage(IsolatedDhcpStartupStage stage) noexcept;

    std::string server_ipv4_;
    std::string lease_ipv4_;
    std::string subnet_mask_;
    std::uint16_t server_port_{kWiredDhcpServerPort};
    std::uint16_t client_port_{kWiredDhcpClientPort};
    std::thread worker_;
    std::atomic_bool stop_requested_{false};
    std::atomic_bool running_{false};
    std::atomic_uint32_t last_error_{0};
    std::atomic_uint32_t startup_stage_{
        static_cast<std::uint32_t>(IsolatedDhcpStartupStage::none)};
    mutable std::mutex metrics_mutex_;
    IsolatedDhcpMetrics metrics_{};
};

}  // namespace vfdual
