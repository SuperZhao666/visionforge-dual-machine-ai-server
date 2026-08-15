#include "vfdual/idr_request_listener.hpp"

// Development-only regression for the legacy plaintext IDR listener. Formal
// builds are blocked while this ABI remains reachable.
#include "vfdual/udp_socket.hpp"

#include <array>
#include <chrono>
#include <thread>

namespace {

constexpr std::array<std::byte, 4> kIdrRequest{
    std::byte{'I'}, std::byte{'D'}, std::byte{'R'}, std::byte{'1'}};

bool poll_until_request(vfdual::IdrRequestListener& listener) {
    for (int attempt = 0; attempt < 100; ++attempt) {
        if (listener.poll_request()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return false;
}

bool send_from(std::string_view source_ipv4, std::uint16_t destination_port) {
    vfdual::UdpSocket sender;
    return sender.bind_to(source_ipv4, 0) &&
        sender.connect_to("127.0.0.1", destination_port) && sender.send(kIdrRequest);
}

}  // namespace

int main() {
    vfdual::IdrRequestListener listener;
    if (!listener.start(0, "127.0.0.1", "127.0.0.2")) return 1;
    if (listener.bound_port() == 0) return 2;
    if (!send_from("127.0.0.1", listener.bound_port())) return 3;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (listener.poll_request() || listener.accepted_requests() != 0) return 4;
    if (!send_from("127.0.0.2", listener.bound_port())) return 5;
    if (!poll_until_request(listener) || listener.accepted_requests() != 1) return 6;

    if (!listener.start(0, "127.0.0.1", "127.0.0.2")) return 7;
    listener.stop();
    if (!listener.start(0, "127.0.0.1", "127.0.0.2")) return 8;
    listener.stop();
    return 0;
}
