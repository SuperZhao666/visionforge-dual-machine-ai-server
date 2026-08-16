#pragma once

#include "vfdual/protocol.hpp"
#include "vfdual/udp_socket.hpp"

#include <cstdint>
#include <functional>
#include <span>

namespace vfdual {

using VideoDataPlanePermitSource = std::function<bool()>;

/**
 * Exact outcome of publishing one encoded access unit.
 *
 * `success` is true only when every required UDP fragment has crossed the
 * socket boundary.  Callers must never infer IDR delivery from encoder success
 * or from `fragments_sent > 0`.
 */
struct VideoPublishResult final {
    VideoFrameIdentity identity{};
    std::uint16_t expected_fragments{};
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

    [[nodiscard]] constexpr bool completely_published() const noexcept {
        return success && identity.valid() && expected_fragments != 0U &&
            fragments_sent == expected_fragments && stage == Stage::complete;
    }
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
        VideoFrameIdentity identity, std::span<const std::byte> access_unit,
        std::uint64_t monotonic_us, bool repeated_content = false) noexcept;
    [[nodiscard]] std::uint32_t last_socket_error() const noexcept;
    [[nodiscard]] std::uint16_t local_port() const noexcept;

private:
    [[nodiscard]] bool authorization_permits_send() const noexcept;

    UdpSocket socket_;
    VideoDataPlanePermitSource permit_source_;
};

}  // namespace vfdual
