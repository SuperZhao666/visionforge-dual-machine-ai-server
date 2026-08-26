#include "vfdual/idr_request_listener.hpp"

#include "vfdual/udp_socket.hpp"

#include <array>
#include <chrono>
#include <span>
#include <thread>

namespace {

constexpr std::array<std::byte, 4> kIdrRequest{
    std::byte{'I'}, std::byte{'D'}, std::byte{'R'}, std::byte{'1'}};
constexpr std::uint64_t kConnectionId = 0x8877'6655'4433'2211ULL;

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
            std::byte{static_cast<std::uint8_t>(seed ^ (0x90U + index))};
    }
    return result;
}

vfdual::AuthenticatedTrafficKey sender_key(const TestKey& key) {
    vfdual::AuthenticatedTrafficKey result;
    result.tuple = {
        .connection_id = kConnectionId,
        .key_epoch = 1U,
        .direction = vfdual::DataPlaneDirection::android_to_host,
        .packet_type = vfdual::AuthenticatedPacketType::idr_request,
    };
    result.aes_256_key = key.key;
    result.nonce_prefix = key.prefix;
    return result;
}

bool poll_until_request(vfdual::IdrRequestListener& listener) {
    for (int attempt = 0; attempt < 100; ++attempt) {
        if (listener.poll_request()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return false;
}

bool send_from(
    std::string_view source_ipv4, std::uint16_t destination_port,
    std::span<const std::byte> packet) {
    vfdual::UdpSocket sender;
    return sender.bind_to(source_ipv4, 0) &&
        sender.connect_to("127.0.0.1", destination_port) && sender.send(packet);
}

}  // namespace

int main() {
    const TestKey video_key = test_key(0x10U);
    const TestKey presence_key = test_key(0x20U);
    const TestKey idr_key = test_key(0x30U);
    const TestKey mouse_key = test_key(0x40U);
    auto session = vfdual::HostAuthenticatedDataPlaneSessionV2::create_for_test(
        kConnectionId, video_key.view(), presence_key.view(), idr_key.view(),
        mouse_key.view());
    auto provider = vfdual::make_platform_aes_256_gcm_provider();
    if (!session || !provider) return 15;
    vfdual::AuthenticatedPacketSealer sender(sender_key(idr_key), *provider);
    vfdual::IdrRequestListener listener;
    if (listener.start(0, "127.0.0.1", "127.0.0.2")) return 1;

    bool permitted = true;
    if (!listener.start(
            0,
            "127.0.0.1",
            "127.0.0.2",
            [&permitted] { return permitted; }, session)) {
        return 2;
    }
    if (listener.bound_port() == 0) return 3;
    auto sealed = sender.seal(kIdrRequest);
    if (sealed.status != vfdual::PacketSealStatus::sealed) return 16;
    if (!send_from("127.0.0.1", listener.bound_port(), sealed.datagram)) return 4;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (listener.poll_request() || listener.accepted_requests() != 0) return 5;
    sealed = sender.seal(kIdrRequest);
    if (sealed.status != vfdual::PacketSealStatus::sealed ||
        !send_from("127.0.0.2", listener.bound_port(), sealed.datagram)) return 6;
    if (!poll_until_request(listener) || listener.accepted_requests() != 1) return 7;

    permitted = false;
    sealed = sender.seal(kIdrRequest);
    if (sealed.status != vfdual::PacketSealStatus::sealed ||
        !send_from("127.0.0.2", listener.bound_port(), sealed.datagram)) return 8;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (listener.poll_request() || listener.accepted_requests() != 1) return 9;

    if (!listener.start(
            0, "127.0.0.1", "127.0.0.2",
            []() -> bool { throw 1; }, session)) {
        return 10;
    }
    sealed = sender.seal(kIdrRequest);
    if (sealed.status != vfdual::PacketSealStatus::sealed ||
        !send_from("127.0.0.2", listener.bound_port(), sealed.datagram)) return 11;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (listener.poll_request() || listener.accepted_requests() != 1) return 12;

    if (!listener.start(
            0, "127.0.0.1", "127.0.0.2", [] { return true; }, session)) {
        return 13;
    }
    listener.stop();
    if (!listener.start(
            0, "127.0.0.1", "127.0.0.2", [] { return true; }, session)) {
        return 14;
    }
    listener.stop();
    return 0;
}
