#include "vfdual/desktop_video_agent.hpp"
#include "vfdual/protocol.hpp"
#include "vfdual/udp_socket.hpp"
#include "vfdual/udp_video_publisher.hpp"

#include <array>
#include <chrono>
#include <string>
#include <thread>

int main() {
    const vfdual::DesktopVideoAgentConfig production_defaults{};
    if (production_defaults.local_host != vfdual::kWiredHostIpv4) return 1;
    if (production_defaults.local_port != vfdual::kWiredVideoSourcePort) return 6;

    vfdual::UdpSocket receiver;
    if (!receiver.bind_to("127.0.0.1", 0) || receiver.local_port() == 0) return 2;

    vfdual::UdpVideoPublisher publisher;
    bool permit_open = false;
    if (!publisher.connect_to(
            "127.0.0.1", receiver.local_port(), production_defaults.local_port,
            "127.0.0.2", [&permit_open]() noexcept { return permit_open; })) {
        return 3;
    }
    if (publisher.local_port() != production_defaults.local_port) return 8;
    vfdual::UdpVideoPublisher concurrent_publisher;
    if (concurrent_publisher.connect_to(
            "127.0.0.1", receiver.local_port(), production_defaults.local_port,
            "127.0.0.2", []() noexcept { return true; })) return 7;
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

    std::array<std::byte, vfdual::kMaxDatagramBytes> datagram{};
    std::string source_ipv4;
    std::uint16_t source_port{};
    std::size_t received{};
    for (int attempt = 0; attempt < 100; ++attempt) {
        received = receiver.receive_from(datagram, 0, source_ipv4, source_port);
        if (received > 0U) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    vfdual::VideoFragment decoded;
    if (received == 0U ||
        !vfdual::decode_video_packet(
            std::span<const std::byte>{datagram.data(), received}, decoded) ||
        decoded.identity != vfdual::VideoFrameIdentity{epoch, 1U} ||
        decoded.repeated_content) {
        return 5;
    }

    publisher.reset();
    if (!publisher.connect_to(
            "127.0.0.1", receiver.local_port(), production_defaults.local_port,
            "127.0.0.2", []() noexcept { return true; })) return 9;
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
    if (received == 0U ||
        !vfdual::decode_video_packet(
            std::span<const std::byte>{datagram.data(), received}, decoded) ||
        !decoded.repeated_content ||
        decoded.identity != vfdual::VideoFrameIdentity{epoch, 2U}) {
        return 12;
    }
    return source_ipv4 == "127.0.0.2" &&
            source_port == production_defaults.local_port ? 0 : 11;
}
