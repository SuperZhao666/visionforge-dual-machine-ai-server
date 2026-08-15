#pragma once

#include "vfdual/udp_socket.hpp"

#include <cstdint>
#include <functional>
#include <span>

namespace vfdual {

using VideoDataPlanePermitSource = std::function<bool()>;

struct VideoPublishResult {
    std::uint16_t fragments_sent{};
    std::uint32_t bytes_sent{};
    bool success{};
    enum class Stage : std::uint8_t {
        none,
        validate_input,
        authorization_check,
        encode_datagram,
        socket_send,
        complete,
    } stage{Stage::none};
};

/** Windows transport adapter. It accepts encoded access units only; it never captures or re-encodes frames. */
class UdpVideoPublisher final {
public:
    UdpVideoPublisher() noexcept = default;
    [[nodiscard]] bool connect_to(
        std::string_view host, std::uint16_t port, std::uint16_t local_port = 0,
        std::string_view local_host = {},
        const VideoDataPlanePermitSource& permit_source = {}) noexcept;
    void reset() noexcept;
    [[nodiscard]] VideoPublishResult publish(
        std::uint32_t frame_id, std::span<const std::byte> access_unit,
        std::uint64_t monotonic_us, bool repeated_content = false) noexcept;
    [[nodiscard]] std::uint32_t last_socket_error() const noexcept;
    [[nodiscard]] std::uint16_t local_port() const noexcept;

private:
    [[nodiscard]] bool authorization_permits_send() const noexcept;

    UdpSocket socket_;
    VideoDataPlanePermitSource permit_source_;
};

}  // namespace vfdual
