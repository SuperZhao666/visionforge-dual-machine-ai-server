#include "vfdual/host_authenticated_data_plane_session_v2.hpp"

#include <algorithm>
#include <utility>

namespace vfdual {
namespace {

[[nodiscard]] AuthenticatedTrafficKey make_key(
    const PeerHandshakeDataPlaneKeyView view,
    const std::uint64_t connection_id,
    const DataPlaneDirection direction,
    const AuthenticatedPacketType packet_type) noexcept {
    AuthenticatedTrafficKey key;
    key.tuple = AuthenticatedPacketTuple{
        .connection_id = connection_id,
        .key_epoch = 1U,
        .direction = direction,
        .packet_type = packet_type,
    };
    std::copy(
        view.aes_256_key.begin(), view.aes_256_key.end(),
        key.aes_256_key.begin());
    std::copy(
        view.nonce_prefix.begin(), view.nonce_prefix.end(),
        key.nonce_prefix.begin());
    return key;
}

}  // namespace

HostAuthenticatedDataPlaneSessionV2::HostAuthenticatedDataPlaneSessionV2(
    const std::uint64_t connection_id,
    std::unique_ptr<AuthenticatedPacketSealer> video,
    std::unique_ptr<AuthenticatedPacketSealer> presence,
    std::unique_ptr<AuthenticatedPacketOpener> idr,
    std::unique_ptr<AuthenticatedPacketSealer> mouse_button) noexcept
    : connection_id_(connection_id),
      video_(std::move(video)),
      presence_(std::move(presence)),
      idr_(std::move(idr)),
      mouse_button_(std::move(mouse_button)) {}

std::shared_ptr<HostAuthenticatedDataPlaneSessionV2>
HostAuthenticatedDataPlaneSessionV2::create(
    const ConfirmedPeerHandshakeSessionV1& session) noexcept {
    try {
        if (session.local_role() != PeerHandshakeRole::host ||
            session.connection_id() == 0U) {
            return {};
        }
        auto provider = make_platform_aes_256_gcm_provider();
        if (!provider) return {};
        const std::uint64_t connection_id = session.connection_id();
        auto video = std::make_unique<AuthenticatedPacketSealer>(
            make_key(
                session.video_host_to_android(), connection_id,
                DataPlaneDirection::host_to_android,
                AuthenticatedPacketType::video),
            *provider);
        auto presence = std::make_unique<AuthenticatedPacketSealer>(
            make_key(
                session.presence_host_to_android(), connection_id,
                DataPlaneDirection::host_to_android,
                AuthenticatedPacketType::presence_probe),
            *provider);
        auto idr = std::make_unique<AuthenticatedPacketOpener>(
            make_key(
                session.idr_android_to_host(), connection_id,
                DataPlaneDirection::android_to_host,
                AuthenticatedPacketType::idr_request),
            *provider);
        auto mouse_button = std::make_unique<AuthenticatedPacketSealer>(
            make_key(
                session.mouse_host_to_android(), connection_id,
                DataPlaneDirection::host_to_android,
                AuthenticatedPacketType::mouse_button),
            *provider);
        return std::shared_ptr<HostAuthenticatedDataPlaneSessionV2>(
            new HostAuthenticatedDataPlaneSessionV2(
                connection_id, std::move(video), std::move(presence),
                std::move(idr), std::move(mouse_button)));
    } catch (...) {
        return {};
    }
}

#if defined(VFDUAL_HOST_AUTHENTICATED_DATA_PLANE_TESTING)
std::shared_ptr<HostAuthenticatedDataPlaneSessionV2>
HostAuthenticatedDataPlaneSessionV2::create_for_test(
    const std::uint64_t connection_id,
    const PeerHandshakeDataPlaneKeyView video_view,
    const PeerHandshakeDataPlaneKeyView presence_view,
    const PeerHandshakeDataPlaneKeyView idr_view,
    const PeerHandshakeDataPlaneKeyView mouse_view) noexcept {
    try {
        if (connection_id == 0U) return {};
        auto provider = make_platform_aes_256_gcm_provider();
        if (!provider) return {};
        auto video = std::make_unique<AuthenticatedPacketSealer>(
            make_key(video_view, connection_id,
                DataPlaneDirection::host_to_android,
                AuthenticatedPacketType::video), *provider);
        auto presence = std::make_unique<AuthenticatedPacketSealer>(
            make_key(presence_view, connection_id,
                DataPlaneDirection::host_to_android,
                AuthenticatedPacketType::presence_probe), *provider);
        auto idr = std::make_unique<AuthenticatedPacketOpener>(
            make_key(idr_view, connection_id,
                DataPlaneDirection::android_to_host,
                AuthenticatedPacketType::idr_request), *provider);
        auto mouse = std::make_unique<AuthenticatedPacketSealer>(
            make_key(mouse_view, connection_id,
                DataPlaneDirection::host_to_android,
                AuthenticatedPacketType::mouse_button), *provider);
        return std::shared_ptr<HostAuthenticatedDataPlaneSessionV2>(
            new HostAuthenticatedDataPlaneSessionV2(
                connection_id, std::move(video), std::move(presence),
                std::move(idr), std::move(mouse)));
    } catch (...) {
        return {};
    }
}
#endif

PacketSealResult HostAuthenticatedDataPlaneSessionV2::seal_video(
    const std::span<const std::byte> plaintext) noexcept {
    return video_ ? video_->seal(plaintext) : PacketSealResult{};
}

PacketSealResult HostAuthenticatedDataPlaneSessionV2::seal_presence(
    const std::span<const std::byte> plaintext) noexcept {
    return presence_ ? presence_->seal(plaintext) : PacketSealResult{};
}

PacketOpenResult HostAuthenticatedDataPlaneSessionV2::open_idr(
    const std::span<const std::byte> datagram) noexcept {
    return idr_ ? idr_->open(datagram) : PacketOpenResult{};
}

PacketSealResult HostAuthenticatedDataPlaneSessionV2::seal_mouse_button(
    const std::span<const std::byte> plaintext) noexcept {
    return mouse_button_ ? mouse_button_->seal(plaintext) : PacketSealResult{};
}

}  // namespace vfdual
