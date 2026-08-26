#pragma once

#include "vfdual/authenticated_data_plane_v2.hpp"
#include "vfdual/authenticated_peer_handshake_v1.hpp"

#include <cstdint>
#include <memory>
#include <span>

namespace vfdual {

/**
 * Process-lifetime owner of the four VFA2 traffic domains derived by VFB1.
 *
 * The object, rather than an encoder or socket adapter, owns every sender
 * counter and receive replay window.  Host stream recovery may replace those
 * adapters while retaining this object, so it cannot reset an AES-GCM counter
 * under the same traffic key.
 */
class HostAuthenticatedDataPlaneSessionV2 final {
public:
    [[nodiscard]] static std::shared_ptr<HostAuthenticatedDataPlaneSessionV2>
    create(const ConfirmedPeerHandshakeSessionV1& session) noexcept;
#if defined(VFDUAL_HOST_AUTHENTICATED_DATA_PLANE_TESTING)
    [[nodiscard]] static std::shared_ptr<HostAuthenticatedDataPlaneSessionV2>
    create_for_test(
        std::uint64_t connection_id,
        PeerHandshakeDataPlaneKeyView video,
        PeerHandshakeDataPlaneKeyView presence,
        PeerHandshakeDataPlaneKeyView idr,
        PeerHandshakeDataPlaneKeyView mouse_button) noexcept;
#endif

    HostAuthenticatedDataPlaneSessionV2(
        const HostAuthenticatedDataPlaneSessionV2&) = delete;
    HostAuthenticatedDataPlaneSessionV2& operator=(
        const HostAuthenticatedDataPlaneSessionV2&) = delete;

    [[nodiscard]] std::uint64_t connection_id() const noexcept {
        return connection_id_;
    }
    [[nodiscard]] PacketSealResult seal_video(
        std::span<const std::byte> plaintext) noexcept;
    [[nodiscard]] PacketSealResult seal_presence(
        std::span<const std::byte> plaintext) noexcept;
    [[nodiscard]] PacketOpenResult open_idr(
        std::span<const std::byte> datagram) noexcept;
    [[nodiscard]] PacketSealResult seal_mouse_button(
        std::span<const std::byte> plaintext) noexcept;

private:
    HostAuthenticatedDataPlaneSessionV2(
        std::uint64_t connection_id,
        std::unique_ptr<AuthenticatedPacketSealer> video,
        std::unique_ptr<AuthenticatedPacketSealer> presence,
        std::unique_ptr<AuthenticatedPacketOpener> idr,
        std::unique_ptr<AuthenticatedPacketSealer> mouse_button) noexcept;

    std::uint64_t connection_id_{};
    std::unique_ptr<AuthenticatedPacketSealer> video_;
    std::unique_ptr<AuthenticatedPacketSealer> presence_;
    std::unique_ptr<AuthenticatedPacketOpener> idr_;
    std::unique_ptr<AuthenticatedPacketSealer> mouse_button_;
};

}  // namespace vfdual
