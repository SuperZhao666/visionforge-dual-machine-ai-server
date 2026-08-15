#pragma once

#include "vfdual/udp_socket.hpp"
#include "vfdual/wired_link_contract.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace vfdual {

/** Media-recovery listener bound to the runtime-selected host and mobile endpoints. */
class IdrRequestListener final {
public:
    [[nodiscard]] bool start(
        std::uint16_t port = kWiredIdrPort,
        std::string_view local_ipv4 = kWiredHostIpv4,
        std::string_view expected_source_ipv4 = kWiredMobileIpv4) noexcept;
    void stop() noexcept;
    [[nodiscard]] bool poll_request() noexcept;
    [[nodiscard]] std::uint16_t bound_port() const noexcept { return socket_.local_port(); }
    [[nodiscard]] std::uint64_t accepted_requests() const noexcept { return accepted_requests_; }
    [[nodiscard]] std::uint32_t last_socket_error() const noexcept {
        return socket_.last_error();
    }

private:
    UdpSocket socket_;
    std::string expected_source_ipv4_;
    std::uint64_t accepted_requests_{};
};

}  // namespace vfdual
