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
            "127.0.0.2", [&permit_open]() noexcept {
                return permit_open;
            })) {
        return 3;
    }
    if (publisher.local_port() != production_defaults.local_port) return 8;
    vfdual::UdpVideoPublisher concurrent_publisher;
    if (concurrent_publisher.connect_to(
            "127.0.0.1", receiver.local_port(), production_defaults.local_port,
            "127.0.0.2", []() noexcept { return true; })) return 7;
    concurrent_publisher.reset();
    constexpr std::array<std::byte, 5> access_unit{
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}, std::byte{0x65}};
    const auto denied = publisher.publish(0, access_unit, 0);
    if (denied.success || denied.fragments_sent != 0U ||
        denied.stage !=
            vfdual::VideoPublishResult::Stage::authorization_check) {
        return 13;
    }
    permit_open = true;
    const auto published = publisher.publish(1, access_unit, 1);
    if (!published.success || published.fragments_sent == 0) return 4;

    std::array<std::byte, 1500> datagram{};
    std::string source_ipv4;
    std::uint16_t source_port{};
    for (int attempt = 0; attempt < 100; ++attempt) {
        if (receiver.receive_from(datagram, 0, source_ipv4, source_port) > 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    if (source_ipv4 != "127.0.0.2" || source_port != production_defaults.local_port) return 5;

    publisher.reset();
    if (!publisher.connect_to(
            "127.0.0.1", receiver.local_port(), production_defaults.local_port,
            "127.0.0.2", []() noexcept { return true; })) return 9;
    const auto republished = publisher.publish(2, access_unit, 2, true);
    if (!republished.success || publisher.local_port() != production_defaults.local_port) return 10;
    source_ipv4.clear();
    source_port = 0;
    std::size_t received{};
    for (int attempt = 0; attempt < 100; ++attempt) {
        received = receiver.receive_from(datagram, 0, source_ipv4, source_port);
        if (received > 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    vfdual::VideoFragment decoded;
    if (received == 0U ||
        !vfdual::decode_video_packet(
            std::span<const std::byte>{
                datagram.data(), static_cast<std::size_t>(received)},
            decoded) ||
        !vfdual::video_repeats_content(decoded.frame_id) ||
        vfdual::video_logical_frame_sequence(decoded.frame_id) != 2U) {
        return 12;
    }
    return source_ipv4 == "127.0.0.2" &&
            source_port == production_defaults.local_port
        ? 0 : 11;
}
