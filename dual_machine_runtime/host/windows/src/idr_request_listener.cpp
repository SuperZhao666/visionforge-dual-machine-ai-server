#include "vfdual/idr_request_listener.hpp"

#include <array>
#include <utility>

namespace vfdual {
bool IdrRequestListener::start(
    std::uint16_t port,
    std::string_view local_ipv4,
    std::string_view expected_source_ipv4,
    VideoDataPlanePermitSource permit_source) noexcept {
    stop();
    if (local_ipv4.empty() || expected_source_ipv4.empty() || !permit_source ||
        !socket_.bind_to(local_ipv4, port)) return false;
    try {
        expected_source_ipv4_ = expected_source_ipv4;
        permit_source_ = std::move(permit_source);
    } catch (...) {
        stop();
        return false;
    }
    return true;
}

void IdrRequestListener::stop() noexcept {
    socket_.close();
    expected_source_ipv4_.clear();
    permit_source_ = {};
}

bool IdrRequestListener::poll_request() noexcept {
    std::array<std::byte, 8> packet{};
    std::string source_ipv4;
    const auto received = socket_.receive_from(packet, 0, source_ipv4);
    bool authorized = false;
    try {
        authorized = permit_source_ && permit_source_();
    } catch (...) {
        authorized = false;
    }
    const bool request = authorized &&
        source_ipv4 == expected_source_ipv4_ && received == 4 &&
        packet[0] == std::byte{'I'} && packet[1] == std::byte{'D'} &&
        packet[2] == std::byte{'R'} && packet[3] == std::byte{'1'};
    if (request) ++accepted_requests_;
    return request;
}
}  // namespace vfdual
