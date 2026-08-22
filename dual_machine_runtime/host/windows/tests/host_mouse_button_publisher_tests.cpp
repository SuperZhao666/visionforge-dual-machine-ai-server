#include "vfdual/authenticated_data_plane_v2.hpp"
#include "vfdual/authenticated_mouse_button_v2.hpp"
#include "vfdual/authenticated_peer_handshake_v1.hpp"
#include "vfdual/host_mouse_button_publisher.hpp"
#include "vfdual/udp_socket.hpp"
#include "vfdual/wired_link_contract.hpp"

#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <span>
#include <thread>
#include <utility>

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: "
              << expression << '\n';
    std::exit(EXIT_FAILURE);
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

int main() {
    constexpr std::uint64_t connection_id = 0x0123'4567'89ab'cdefULL;
    std::array<std::byte, 36U> material{};
    std::array<std::byte, 36U> replacement_material{};
    for (std::size_t index{}; index < material.size(); ++index) {
        material[index] = std::byte{static_cast<std::uint8_t>(0x20U + index)};
        replacement_material[index] =
            std::byte{static_cast<std::uint8_t>(0x60U + index)};
    }
    const vfdual::PeerHandshakeDataPlaneKeyView key_view{
        std::span<const std::byte, 32U>{material.data(), 32U},
        std::span<const std::byte, 4U>{material.data() + 32U, 4U},
    };
    const vfdual::PeerHandshakeDataPlaneKeyView replacement_key_view{
        std::span<const std::byte, 32U>{replacement_material.data(), 32U},
        std::span<const std::byte, 4U>{replacement_material.data() + 32U, 4U},
    };

    vfdual::UdpSocket receiver;
    CHECK(receiver.bind_exclusive_to(
        "127.0.0.2", vfdual::kWiredMouseButtonPort));

    vfdual::HostMouseButtonPublisher publisher;
    CHECK(!publisher.install_confirmed_session(connection_id, key_view));
    CHECK(publisher.start("127.0.0.1", "127.0.0.2", [] { return true; }));

    std::array<std::byte, 64U> datagram{};
    CHECK(receiver.receive(datagram, 120U) == 0U);
    CHECK(!publisher.stats().authenticated_session_ready);
    CHECK(!publisher.install_confirmed_session(0U, key_view));
    CHECK(publisher.install_confirmed_session(connection_id, key_view));
    CHECK(publisher.stats().authenticated_session_ready);

    const std::size_t received = receiver.receive(datagram, 1500U);
    CHECK(received == 49U);
    auto opener_key =
        vfdual::make_authenticated_mouse_button_host_to_android_key(
            connection_id, material);
    auto provider = vfdual::make_platform_aes_256_gcm_provider();
    CHECK(provider != nullptr);
    vfdual::AuthenticatedPacketOpener opener(
        std::move(opener_key), *provider);
    const auto opened = opener.open(
        std::span<const std::byte>{datagram.data(), received});
    CHECK(opened.status == vfdual::PacketOpenStatus::opened);
    std::uint8_t button_mask{0xffU};
    CHECK(vfdual::decode_authenticated_mouse_button_payload(
        opened.plaintext, button_mask));
    CHECK((button_mask & ~vfdual::kAuthenticatedMouseButtonValidMask) == 0U);

    // A lifecycle retry for the same connection must keep the original
    // counter owner. Resetting it would make the opener reject a reused nonce.
    CHECK(publisher.install_confirmed_session(connection_id, key_view));
    const std::size_t duplicate_install_received =
        receiver.receive(datagram, 1500U);
    CHECK(duplicate_install_received == 49U);
    const auto after_duplicate_install = opener.open(
        std::span<const std::byte>{
            datagram.data(), duplicate_install_received});
    CHECK(after_duplicate_install.status == vfdual::PacketOpenStatus::opened);

    // Any invalid replacement fails closed instead of leaving the old key live.
    CHECK(!publisher.install_confirmed_session(0U, key_view));
    CHECK(!publisher.stats().authenticated_session_ready);
    while (receiver.receive(datagram, 10U) != 0U) {
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    CHECK(receiver.receive(datagram, 80U) == 0U);

    constexpr std::uint64_t replacement_connection_id = connection_id + 1U;
    CHECK(publisher.install_confirmed_session(
        replacement_connection_id, replacement_key_view));
    const std::size_t replacement_received = receiver.receive(datagram, 1500U);
    CHECK(replacement_received == 49U);
    auto replacement_opener_key =
        vfdual::make_authenticated_mouse_button_host_to_android_key(
            replacement_connection_id, replacement_material);
    auto replacement_provider = vfdual::make_platform_aes_256_gcm_provider();
    CHECK(replacement_provider != nullptr);
    vfdual::AuthenticatedPacketOpener replacement_opener(
        std::move(replacement_opener_key), *replacement_provider);
    const auto replacement_opened = replacement_opener.open(
        std::span<const std::byte>{datagram.data(), replacement_received});
    CHECK(replacement_opened.status == vfdual::PacketOpenStatus::opened);

    publisher.clear_confirmed_session();
    CHECK(!publisher.stats().authenticated_session_ready);
    while (receiver.receive(datagram, 10U) != 0U) {
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    CHECK(receiver.receive(datagram, 80U) == 0U);

    publisher.stop();
    CHECK(!publisher.stats().running);
    return EXIT_SUCCESS;
}
