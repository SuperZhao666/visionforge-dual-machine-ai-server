#include "vfdual/desktop_video_agent.hpp"
#include "vfdual/protocol.hpp"
#include "vfdual/udp_socket.hpp"
#include "vfdual/udp_video_publisher.hpp"

#include <array>
#include <chrono>
#include <string>
#include <thread>

namespace {

constexpr std::uint64_t kConnectionId = 0x1122'3344'5566'7788ULL;

struct TestKey {
    std::array<std::byte, vfdual::kAes256KeyBytes> key{};
    std::array<std::byte, vfdual::kGcmNoncePrefixBytes> prefix{};

    vfdual::PeerHandshakeDataPlaneKeyView view() const noexcept {
        return {key, prefix};
    }
};

TestKey test_key(const std::uint8_t seed) {
    TestKey result;
    for (std::size_t index = 0; index < result.key.size(); ++index) {
        result.key[index] = std::byte{static_cast<std::uint8_t>(seed + index)};
    }
    for (std::size_t index = 0; index < result.prefix.size(); ++index) {
        result.prefix[index] =
            std::byte{static_cast<std::uint8_t>(seed ^ (0xa0U + index))};
    }
    return result;
}

vfdual::AuthenticatedTrafficKey receiver_key(const TestKey& key) {
    vfdual::AuthenticatedTrafficKey result;
    result.tuple = {
        .connection_id = kConnectionId,
        .key_epoch = 1U,
        .direction = vfdual::DataPlaneDirection::host_to_android,
        .packet_type = vfdual::AuthenticatedPacketType::video,
    };
    result.aes_256_key = key.key;
    result.nonce_prefix = key.prefix;
    return result;
}

}  // namespace

int main() {
    const vfdual::DesktopVideoAgentConfig production_defaults{};
    if (production_defaults.local_host != vfdual::kWiredHostIpv4) return 1;
    if (production_defaults.local_port != vfdual::kWiredVideoSourcePort) return 6;

    vfdual::UdpSocket receiver;
    if (!receiver.bind_to("127.0.0.1", 0) || receiver.local_port() == 0) return 2;

    vfdual::UdpVideoPublisher publisher;
    const TestKey video_key = test_key(0x11U);
    const TestKey presence_key = test_key(0x22U);
    const TestKey idr_key = test_key(0x33U);
    const TestKey mouse_key = test_key(0x44U);
    auto session = vfdual::HostAuthenticatedDataPlaneSessionV2::create_for_test(
        kConnectionId, video_key.view(), presence_key.view(), idr_key.view(),
        mouse_key.view());
    auto provider = vfdual::make_platform_aes_256_gcm_provider();
    if (!session || !provider) return 14;
    vfdual::AuthenticatedPacketOpener opener(
        receiver_key(video_key), *provider);
    bool permit_open = false;
    if (!publisher.connect_to(
            "127.0.0.1", receiver.local_port(), production_defaults.local_port,
            "127.0.0.2", [&permit_open]() noexcept { return permit_open; },
            session)) {
        return 3;
    }
    if (publisher.local_port() != production_defaults.local_port) return 8;
    vfdual::UdpVideoPublisher concurrent_publisher;
    if (concurrent_publisher.connect_to(
            "127.0.0.1", receiver.local_port(), production_defaults.local_port,
            "127.0.0.2", []() noexcept { return true; }, session)) return 7;
    concurrent_publisher.reset();

    constexpr std::array<std::byte, 5> access_unit{
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1},
        std::byte{0x65}};
    constexpr std::uint64_t epoch = 0x1020'3040'5060ULL;
    const auto denied = publisher.publish({epoch, 0U}, access_unit, 0U);
    if (denied.success || denied.fragments_sent != 0U ||
        denied.expected_fragments != 1U ||
        denied.stage != vfdual::VideoPublishResult::Stage::authorization_check) {
        return 13;
    }
    permit_open = true;
    const auto published = publisher.publish({epoch, 1U}, access_unit, 1U);
    if (!published.completely_published() || published.fragments_sent != 1U) return 4;

    std::array<std::byte, vfdual::kMaximumAuthenticatedDatagramBytes> datagram{};
    std::string source_ipv4;
    std::uint16_t source_port{};
    std::size_t received{};
    for (int attempt = 0; attempt < 100; ++attempt) {
        received = receiver.receive_from(datagram, 0, source_ipv4, source_port);
        if (received > 0U) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    auto opened = opener.open(
        std::span<const std::byte>{datagram.data(), received});
    vfdual::VideoFragment decoded;
    if (received == 0U || opened.status != vfdual::PacketOpenStatus::opened ||
        !vfdual::decode_video_packet(
            opened.plaintext, decoded) ||
        decoded.identity != vfdual::VideoFrameIdentity{epoch, 1U} ||
        decoded.repeated_content) {
        return 5;
    }

    publisher.reset();
    if (!publisher.connect_to(
            "127.0.0.1", receiver.local_port(), production_defaults.local_port,
            "127.0.0.2", []() noexcept { return true; }, session)) return 9;
    const auto republished = publisher.publish({epoch, 2U}, access_unit, 2U, true);
    if (!republished.completely_published() ||
        publisher.local_port() != production_defaults.local_port) return 10;
    source_ipv4.clear();
    source_port = 0;
    received = 0U;
    for (int attempt = 0; attempt < 100; ++attempt) {
        received = receiver.receive_from(datagram, 0, source_ipv4, source_port);
        if (received > 0U) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    opened = opener.open(
        std::span<const std::byte>{datagram.data(), received});
    if (received == 0U || opened.status != vfdual::PacketOpenStatus::opened ||
        !vfdual::decode_video_packet(
            opened.plaintext, decoded) ||
        !decoded.repeated_content ||
        decoded.identity != vfdual::VideoFrameIdentity{epoch, 2U}) {
        return 12;
    }
    return source_ipv4 == "127.0.0.2" &&
            source_port == production_defaults.local_port ? 0 : 11;
}
