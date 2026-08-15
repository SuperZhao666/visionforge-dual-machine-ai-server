#include "vfdual/udp_socket.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>

#include <array>
#include <cstring>
#include <string>

namespace vfdual {
UdpSocket::UdpSocket() noexcept = default;
UdpSocket::~UdpSocket() { close(); }

void UdpSocket::close() noexcept {
    if (handle_ != 0) closesocket(static_cast<SOCKET>(handle_));
    if (winsock_started_) WSACleanup();
    handle_ = 0;
    winsock_started_ = false;
}

bool UdpSocket::open() noexcept {
    close();
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) { last_error_ = WSAGetLastError(); return false; }
    winsock_started_ = true;
    const SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket == INVALID_SOCKET) { last_error_ = WSAGetLastError(); close(); return false; }
    handle_ = static_cast<std::uintptr_t>(socket); return true;
}

bool UdpSocket::bind_to(std::uint16_t port) noexcept {
    return bind_to({}, port);
}

bool UdpSocket::bind_to(std::string_view local_host, std::uint16_t port) noexcept {
    if (handle_ == 0 && !open()) return false;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (local_host.empty()) {
        address.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        std::array<char, INET_ADDRSTRLEN> host_text{};
        if (local_host.size() >= host_text.size()) {
            last_error_ = WSAEINVAL;
            return false;
        }
        std::memcpy(host_text.data(), local_host.data(), local_host.size());
        if (InetPtonA(AF_INET, host_text.data(), &address.sin_addr) != 1) {
            last_error_ = WSAEINVAL;
            return false;
        }
    }
    if (::bind(static_cast<SOCKET>(handle_), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) { last_error_ = WSAGetLastError(); return false; }
    return true;
}

bool UdpSocket::bind_exclusive_to(
    std::string_view local_host, std::uint16_t port) noexcept {
    if (handle_ == 0 && !open()) return false;
    const BOOL exclusive = TRUE;
    if (setsockopt(
            static_cast<SOCKET>(handle_),
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            reinterpret_cast<const char*>(&exclusive),
            sizeof(exclusive)) == SOCKET_ERROR) {
        last_error_ = WSAGetLastError();
        return false;
    }
    return bind_to(local_host, port);
}

bool UdpSocket::connect_to(std::string_view host, std::uint16_t port) noexcept {
    if (handle_ == 0 && !open()) return false;
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(port);
    std::array<char, INET_ADDRSTRLEN> host_text{};
    if (host.empty() || host.size() >= host_text.size()) {
        last_error_ = WSAEINVAL;
        return false;
    }
    std::memcpy(host_text.data(), host.data(), host.size());
    if (InetPtonA(AF_INET, host_text.data(), &address.sin_addr) != 1) { last_error_ = WSAEINVAL; return false; }
    if (::connect(static_cast<SOCKET>(handle_), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) { last_error_ = WSAGetLastError(); return false; }
    return true;
}

bool UdpSocket::send(std::span<const std::byte> bytes) noexcept {
    if (handle_ == 0 || bytes.empty() || bytes.size() > INT_MAX) { last_error_ = WSAEINVAL; return false; }
    const int sent = ::send(static_cast<SOCKET>(handle_), reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
    if (sent != static_cast<int>(bytes.size())) { last_error_ = WSAGetLastError(); return false; }
    return true;
}

std::size_t UdpSocket::receive(std::span<std::byte> destination, std::uint32_t timeout_ms) noexcept {
    std::string ignored_source;
    return receive_from(destination, timeout_ms, ignored_source);
}

std::size_t UdpSocket::receive_from(
    std::span<std::byte> destination, std::uint32_t timeout_ms,
    std::string& source_host) noexcept {
    std::uint16_t ignored_source_port{};
    return receive_from(destination, timeout_ms, source_host, ignored_source_port);
}

std::size_t UdpSocket::receive_from(
    std::span<std::byte> destination, std::uint32_t timeout_ms,
    std::string& source_host, std::uint16_t& source_port) noexcept {
    source_host.clear();
    source_port = 0;
    if (handle_ == 0 || destination.empty()) { last_error_ = WSAEINVAL; return 0; }
    fd_set readable; FD_ZERO(&readable); FD_SET(static_cast<SOCKET>(handle_), &readable);
    timeval timeout{static_cast<long>(timeout_ms / 1000), static_cast<long>((timeout_ms % 1000) * 1000)};
    const int ready = ::select(0, &readable, nullptr, nullptr, &timeout);
    if (ready <= 0) { if (ready < 0) last_error_ = WSAGetLastError(); return 0; }
    sockaddr_in source{};
    int source_size = sizeof(source);
    const int received = ::recvfrom(
        static_cast<SOCKET>(handle_), reinterpret_cast<char*>(destination.data()),
        static_cast<int>(destination.size()), 0,
        reinterpret_cast<sockaddr*>(&source), &source_size);
    if (received < 0) { last_error_ = WSAGetLastError(); return 0; }
    char source_text[INET_ADDRSTRLEN]{};
    if (InetNtopA(AF_INET, &source.sin_addr, source_text, sizeof(source_text)) == nullptr) {
        last_error_ = WSAGetLastError();
        return 0;
    }
    try {
        source_host.assign(source_text);
    } catch (...) {
        last_error_ = WSAENOBUFS;
        return 0;
    }
    source_port = ntohs(source.sin_port);
    return static_cast<std::size_t>(received);
}

std::uint16_t UdpSocket::local_port() const noexcept {
    if (handle_ == 0) return 0;
    sockaddr_in address{};
    int address_size = sizeof(address);
    if (getsockname(static_cast<SOCKET>(handle_), reinterpret_cast<sockaddr*>(&address),
                    &address_size) != 0) return 0;
    return ntohs(address.sin_port);
}

std::uint32_t UdpSocket::last_error() const noexcept { return last_error_; }
}  // namespace vfdual
