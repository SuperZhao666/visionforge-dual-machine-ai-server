#include "vfdual/udp_socket.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>

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
    vfdual::UdpSocket exclusive_receiver;
    CHECK(exclusive_receiver.bind_exclusive_to("127.0.0.1", 0U));
    const std::uint16_t port = exclusive_receiver.local_port();
    CHECK(port != 0U);

    vfdual::UdpSocket competing_receiver;
    CHECK(!competing_receiver.bind_to("127.0.0.1", port));

    vfdual::UdpSocket sender;
    CHECK(sender.connect_to("127.0.0.1", port));
    const std::array payload{
        std::byte{0x56}, std::byte{0x46}, std::byte{0x43}, std::byte{0x32}};
    CHECK(sender.send(payload));
    std::array<std::byte, 32U> received{};
    std::string source_host;
    std::uint16_t source_port{};
    const std::size_t received_bytes = exclusive_receiver.receive_from(
        received, 1000U, source_host, source_port);
    CHECK(received_bytes == payload.size());
    CHECK(source_host == "127.0.0.1");
    CHECK(source_port != 0U);
    CHECK(std::equal(
        payload.begin(), payload.end(), received.begin()));

    vfdual::UdpSocket invalid;
    CHECK(!invalid.bind_exclusive_to("not-an-ip", 0U));
    return EXIT_SUCCESS;
}
