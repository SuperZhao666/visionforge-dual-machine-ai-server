#include "vfdual/idr_request_listener.hpp"

#include <algorithm>
#include <array>
#include <span>
#include <utility>

namespace vfdual {
bool IdrRequestListener::start(
    std::uint16_t port,
    std::string_view local_ipv4,
    std::string_view expected_source_ipv4,
    VideoDataPlanePermitSource permit_source,
    std::shared_ptr<HostAuthenticatedDataPlaneSessionV2>
        authenticated_session) noexcept {
    stop();
    if (local_ipv4.empty() || expected_source_ipv4.empty() || !permit_source ||
        !authenticated_session ||
        !socket_.bind_to(local_ipv4, port)) return false;
    try {
        expected_source_ipv4_ = expected_source_ipv4;
        permit_source_ = std::move(permit_source);
        authenticated_session_ = std::move(authenticated_session);
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
    authenticated_session_.reset();
}

bool IdrRequestListener::poll_request() noexcept {
    std::array<std::byte, kMaximumAuthenticatedDatagramBytes> packet{};
    std::string source_ipv4;
    const auto received = socket_.receive_from(packet, 0, source_ipv4);
    bool authorized = false;
    try {
        authorized = permit_source_ && permit_source_();
    } catch (...) {
        authorized = false;
    }
    bool request = false;
    if (authorized && source_ipv4 == expected_source_ipv4_ &&
        authenticated_session_ && received != 0U) {
        PacketOpenResult opened = authenticated_session_->open_idr(
            std::span<const std::byte>{packet.data(), received});
        request = opened.status == PacketOpenStatus::opened &&
            opened.plaintext.size() == 4U &&
            opened.plaintext[0] == std::byte{'I'} &&
            opened.plaintext[1] == std::byte{'D'} &&
            opened.plaintext[2] == std::byte{'R'} &&
            opened.plaintext[3] == std::byte{'1'};
        std::fill(opened.plaintext.begin(), opened.plaintext.end(), std::byte{});
    }
    if (request) ++accepted_requests_;
    return request;
}
}  // namespace vfdual
