#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace vfdual {

class UdpSocket final {
public:
    UdpSocket() noexcept;
    ~UdpSocket();
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    [[nodiscard]] bool open() noexcept;
    void close() noexcept;
    [[nodiscard]] bool bind_to(std::uint16_t port) noexcept;
    [[nodiscard]] bool bind_to(std::string_view local_host, std::uint16_t port) noexcept;
    /**
     * Enables Windows SO_EXCLUSIVEADDRUSE before binding. Secure v2 control
     * uses this so exactly one process owns its fixed CAT6 control endpoint.
     */
    [[nodiscard]] bool bind_exclusive_to(
        std::string_view local_host, std::uint16_t port) noexcept;
    [[nodiscard]] bool connect_to(std::string_view host, std::uint16_t port) noexcept;
    [[nodiscard]] bool send(std::span<const std::byte> bytes) noexcept;
    [[nodiscard]] std::size_t receive(std::span<std::byte> destination, std::uint32_t timeout_ms) noexcept;
    [[nodiscard]] std::size_t receive_from(
        std::span<std::byte> destination, std::uint32_t timeout_ms,
        std::string& source_host) noexcept;
    [[nodiscard]] std::size_t receive_from(
        std::span<std::byte> destination, std::uint32_t timeout_ms,
        std::string& source_host, std::uint16_t& source_port) noexcept;
    [[nodiscard]] std::uint16_t local_port() const noexcept;
    [[nodiscard]] std::uint32_t last_error() const noexcept;

private:
    std::uintptr_t handle_{};
    std::uint32_t last_error_{};
    bool winsock_started_{};
};

}  // namespace vfdual
