#include "vfdual/authenticated_control_tcp_transport_v1.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <limits>
#include <new>
#include <utility>

namespace vfdual {
namespace {

using SteadyClock = std::chrono::steady_clock;

[[nodiscard]] AuthenticatedControlTcpErrorV1 success() noexcept {
    return {AuthenticatedControlTcpStatusV1::succeeded, 0U,
            ControlBootstrapParseStatusV1::parsed};
}

[[nodiscard]] AuthenticatedControlTcpErrorV1 failure(
    const AuthenticatedControlTcpStatusV1 status,
    const std::uint32_t native_error = 0U,
    const ControlBootstrapParseStatusV1 record_rejection =
        ControlBootstrapParseStatusV1::record_too_short) noexcept {
    return {status, native_error, record_rejection};
}

inline constexpr std::array<std::byte, 4U> kAuthenticatedControlMagic{
    std::byte{'V'}, std::byte{'F'}, std::byte{'C'}, std::byte{'1'}};
inline constexpr std::size_t kAuthenticatedControlPayloadLengthOffset = 36U;

[[nodiscard]] std::uint32_t load_u32_be(
    const std::span<const std::byte> bytes,
    const std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(bytes[offset])) << 24U) |
        (static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(bytes[offset + 1U])) << 16U) |
        (static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(bytes[offset + 2U])) << 8U) |
        static_cast<std::uint32_t>(
            std::to_integer<std::uint8_t>(bytes[offset + 3U]));
}

[[nodiscard]] bool authenticated_control_record_size(
    const std::span<const std::byte> header,
    const ControlRecordDirectionV1 expected_direction,
    std::size_t& total_size) noexcept {
    total_size = 0U;
    if (header.size() < kAuthenticatedControlHeaderBytes ||
        expected_direction == ControlRecordDirectionV1::invalid ||
        !std::equal(
            kAuthenticatedControlMagic.begin(),
            kAuthenticatedControlMagic.end(),
            header.begin()) ||
        std::to_integer<std::uint8_t>(header[4U]) !=
            kAuthenticatedControlRecordVersion ||
        std::to_integer<std::uint8_t>(header[5U]) !=
            kAuthenticatedControlHeaderBytes ||
        std::to_integer<std::uint8_t>(header[6U]) !=
            static_cast<std::uint8_t>(expected_direction)) {
        return false;
    }
    const auto message_type = static_cast<ControlMessageTypeV1>(
        std::to_integer<std::uint8_t>(header[7U]));
    if (message_type == ControlMessageTypeV1::invalid ||
        static_cast<std::uint8_t>(message_type) >
            static_cast<std::uint8_t>(
                ControlMessageTypeV1::host_start_intent_claim_response)) {
        return false;
    }
    const std::uint32_t payload_size = load_u32_be(
        header, kAuthenticatedControlPayloadLengthOffset);
    if (payload_size > kMaximumAuthenticatedControlPayloadBytes) return false;
    total_size = kAuthenticatedControlHeaderBytes +
        static_cast<std::size_t>(payload_size) + kGcmTagBytes;
    return true;
}

[[nodiscard]] bool copy_ipv4(
    const std::string_view source,
    std::array<char, INET_ADDRSTRLEN>& destination) noexcept {
    if (source.empty() || source.size() >= destination.size()) return false;
    std::memcpy(destination.data(), source.data(), source.size());
    destination[source.size()] = '\0';
    return true;
}

[[nodiscard]] bool make_ipv4_address(
    const std::string_view ipv4,
    const std::uint16_t port,
    sockaddr_in& destination) noexcept {
    destination = {};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(port);
    std::array<char, INET_ADDRSTRLEN> text{};
    return copy_ipv4(ipv4, text) &&
        InetPtonA(AF_INET, text.data(), &destination.sin_addr) == 1;
}

[[nodiscard]] bool set_nonblocking(const SOCKET socket) noexcept {
    u_long enabled = 1U;
    return ioctlsocket(socket, FIONBIO, &enabled) != SOCKET_ERROR;
}

[[nodiscard]] bool configure_connected_socket(const SOCKET socket) noexcept {
    const BOOL no_delay = TRUE;
    return set_nonblocking(socket) &&
        setsockopt(
            socket, IPPROTO_TCP, TCP_NODELAY,
            reinterpret_cast<const char*>(&no_delay),
            sizeof(no_delay)) != SOCKET_ERROR;
}

enum class WaitKind : std::uint8_t { readable, writable };

[[nodiscard]] AuthenticatedControlTcpErrorV1 wait_until(
    const SOCKET socket,
    const WaitKind kind,
    const SteadyClock::time_point deadline) noexcept {
    for (;;) {
        const auto now = SteadyClock::now();
        if (now >= deadline) {
            return failure(AuthenticatedControlTcpStatusV1::timed_out);
        }
        const auto remaining = std::chrono::duration_cast<
            std::chrono::microseconds>(deadline - now);
        const auto bounded = (std::min)(
            remaining,
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::seconds{60}));
        timeval timeout{
            static_cast<long>(bounded.count() / 1'000'000),
            static_cast<long>(bounded.count() % 1'000'000)};
        fd_set readable;
        fd_set writable;
        fd_set exceptional;
        FD_ZERO(&readable);
        FD_ZERO(&writable);
        FD_ZERO(&exceptional);
        FD_SET(socket, &exceptional);
        if (kind == WaitKind::readable) {
            FD_SET(socket, &readable);
        } else {
            FD_SET(socket, &writable);
        }
        const int ready = select(
            0,
            kind == WaitKind::readable ? &readable : nullptr,
            kind == WaitKind::writable ? &writable : nullptr,
            &exceptional,
            &timeout);
        if (ready > 0) {
            if (FD_ISSET(socket, &exceptional)) {
                int socket_error{};
                int size = sizeof(socket_error);
                if (getsockopt(
                        socket, SOL_SOCKET, SO_ERROR,
                        reinterpret_cast<char*>(&socket_error),
                        &size) == SOCKET_ERROR) {
                    socket_error = WSAGetLastError();
                }
                return failure(
                    AuthenticatedControlTcpStatusV1::socket_error,
                    static_cast<std::uint32_t>(socket_error));
            }
            return success();
        }
        if (ready == 0) continue;
        const int error = WSAGetLastError();
        if (error == WSAEINTR) continue;
        return failure(
            AuthenticatedControlTcpStatusV1::socket_error,
            static_cast<std::uint32_t>(error));
    }
}

[[nodiscard]] std::string socket_ipv4(
    const SOCKET socket,
    const bool peer) {
    sockaddr_in address{};
    int size = sizeof(address);
    const int result = peer
        ? getpeername(
            socket, reinterpret_cast<sockaddr*>(&address), &size)
        : getsockname(
            socket, reinterpret_cast<sockaddr*>(&address), &size);
    if (result != 0 || address.sin_family != AF_INET) return {};
    std::array<char, INET_ADDRSTRLEN> text{};
    if (InetNtopA(
            AF_INET, &address.sin_addr, text.data(),
            static_cast<DWORD>(text.size())) == nullptr) {
        return {};
    }
    try {
        return std::string{text.data()};
    } catch (...) {
        return {};
    }
}

[[nodiscard]] std::uint16_t socket_port(
    const SOCKET socket,
    const bool peer) noexcept {
    sockaddr_in address{};
    int size = sizeof(address);
    const int result = peer
        ? getpeername(
            socket, reinterpret_cast<sockaddr*>(&address), &size)
        : getsockname(
            socket, reinterpret_cast<sockaddr*>(&address), &size);
    return result == 0 && address.sin_family == AF_INET
        ? ntohs(address.sin_port)
        : 0U;
}

[[nodiscard]] bool same_ipv4(
    const std::string_view expected,
    const std::string& actual) noexcept {
    return !expected.empty() && expected == actual;
}

}  // namespace

AuthenticatedControlTcpConnectionV1::AuthenticatedControlTcpConnectionV1(
    const std::uintptr_t handle,
    const bool winsock_started) noexcept
    : handle_(handle), winsock_started_(winsock_started) {}

AuthenticatedControlTcpConnectionV1::~AuthenticatedControlTcpConnectionV1() {
    close();
}

AuthenticatedControlTcpConnectionResultV1
AuthenticatedControlTcpConnectionV1::connect(
    const std::string_view local_ipv4,
    const std::string_view expected_peer_ipv4,
    const std::uint16_t peer_port,
    const std::uint32_t timeout_milliseconds) noexcept {
    AuthenticatedControlTcpConnectionResultV1 result{};
    if (expected_peer_ipv4.empty() || peer_port == 0U ||
        timeout_milliseconds == 0U) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::invalid_configuration);
        return result;
    }
    WSADATA data{};
    const int startup = WSAStartup(MAKEWORD(2, 2), &data);
    if (startup != 0) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::socket_error,
            static_cast<std::uint32_t>(startup));
        return result;
    }
    SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == INVALID_SOCKET) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::socket_error,
            static_cast<std::uint32_t>(WSAGetLastError()));
        WSACleanup();
        return result;
    }
    if (!configure_connected_socket(socket)) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::socket_error,
            static_cast<std::uint32_t>(WSAGetLastError()));
        closesocket(socket);
        WSACleanup();
        return result;
    }
    if (!local_ipv4.empty()) {
        sockaddr_in local{};
        if (!make_ipv4_address(local_ipv4, 0U, local) ||
            ::bind(
                socket, reinterpret_cast<const sockaddr*>(&local),
                sizeof(local)) == SOCKET_ERROR) {
            result.error = failure(
                AuthenticatedControlTcpStatusV1::socket_error,
                static_cast<std::uint32_t>(WSAGetLastError()));
            closesocket(socket);
            WSACleanup();
            return result;
        }
    }
    sockaddr_in peer{};
    if (!make_ipv4_address(expected_peer_ipv4, peer_port, peer)) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::invalid_configuration);
        closesocket(socket);
        WSACleanup();
        return result;
    }
    const int connected = ::connect(
        socket, reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    if (connected == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS &&
            error != WSAEINVAL) {
            result.error = failure(
                AuthenticatedControlTcpStatusV1::socket_error,
                static_cast<std::uint32_t>(error));
            closesocket(socket);
            WSACleanup();
            return result;
        }
        const auto deadline = SteadyClock::now() +
            std::chrono::milliseconds{timeout_milliseconds};
        const auto waited = wait_until(socket, WaitKind::writable, deadline);
        if (!waited.succeeded()) {
            result.error = waited;
            closesocket(socket);
            WSACleanup();
            return result;
        }
        int socket_error{};
        int size = sizeof(socket_error);
        if (getsockopt(
                socket, SOL_SOCKET, SO_ERROR,
                reinterpret_cast<char*>(&socket_error), &size) ==
                SOCKET_ERROR ||
            socket_error != 0) {
            if (socket_error == 0) socket_error = WSAGetLastError();
            result.error = failure(
                AuthenticatedControlTcpStatusV1::socket_error,
                static_cast<std::uint32_t>(socket_error));
            closesocket(socket);
            WSACleanup();
            return result;
        }
    }
    auto connection = std::unique_ptr<AuthenticatedControlTcpConnectionV1>(
        new (std::nothrow) AuthenticatedControlTcpConnectionV1(
            static_cast<std::uintptr_t>(socket), true));
    if (connection == nullptr) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::allocation_failed);
        closesocket(socket);
        WSACleanup();
        return result;
    }
    if (!same_ipv4(expected_peer_ipv4, connection->peer_ipv4())) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::peer_mismatch);
        connection->close();
        return result;
    }
    result.connection = std::move(connection);
    result.error = success();
    return result;
}

AuthenticatedControlTcpReadResultV1
AuthenticatedControlTcpConnectionV1::read_bootstrap_record(
    const ControlBootstrapDirectionV1 expected_direction,
    const std::uint32_t timeout_milliseconds) noexcept {
    AuthenticatedControlTcpReadResultV1 result{};
    if (!is_open() || timeout_milliseconds == 0U) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::invalid_configuration);
        return result;
    }
    ControlBootstrapStreamDecoderV1 decoder(expected_direction);
    if (decoder.failed()) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::invalid_configuration);
        close();
        return result;
    }
    const auto deadline = SteadyClock::now() +
        std::chrono::milliseconds{timeout_milliseconds};
    std::array<std::byte, 4'096U> buffer{};
    for (;;) {
        if (pending_offset_ < pending_input_.size()) {
            const auto source = std::span<const std::byte>{pending_input_}
                .subspan(pending_offset_);
            const auto fed = decoder.feed(source);
            pending_offset_ += fed.consumed;
            if (pending_offset_ == pending_input_.size()) {
                std::fill(
                    pending_input_.begin(), pending_input_.end(),
                    std::byte{0U});
                pending_input_.clear();
                pending_offset_ = 0U;
            }
            if (fed.status ==
                ControlBootstrapStreamStatusV1::record_ready) {
                auto record = decoder.take_record();
                if (!record.has_value()) {
                    result.error = failure(
                        AuthenticatedControlTcpStatusV1::allocation_failed);
                    close();
                    return result;
                }
                result.encoded_record = std::move(*record);
                result.error = success();
                return result;
            }
            if (fed.status == ControlBootstrapStreamStatusV1::rejected ||
                fed.status ==
                    ControlBootstrapStreamStatusV1::allocation_failed) {
                result.error = failure(
                    fed.status ==
                            ControlBootstrapStreamStatusV1::allocation_failed
                        ? AuthenticatedControlTcpStatusV1::allocation_failed
                        : AuthenticatedControlTcpStatusV1::invalid_record,
                    0U,
                    fed.rejection);
                close();
                return result;
            }
        }

        const auto waited = wait_until(
            static_cast<SOCKET>(handle_), WaitKind::readable, deadline);
        if (!waited.succeeded()) {
            result.error = waited;
            close();
            return result;
        }
        const int received = recv(
            static_cast<SOCKET>(handle_),
            reinterpret_cast<char*>(buffer.data()),
            static_cast<int>(buffer.size()),
            0);
        if (received == 0) {
            result.error = failure(
                AuthenticatedControlTcpStatusV1::peer_closed);
            close();
            return result;
        }
        if (received == SOCKET_ERROR) {
            const int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK || error == WSAEINTR) continue;
            result.error = failure(
                AuthenticatedControlTcpStatusV1::socket_error,
                static_cast<std::uint32_t>(error));
            close();
            return result;
        }
        try {
            pending_input_.assign(
                buffer.begin(), buffer.begin() + received);
            pending_offset_ = 0U;
        } catch (...) {
            result.error = failure(
                AuthenticatedControlTcpStatusV1::allocation_failed);
            close();
            return result;
        }
        std::fill(buffer.begin(), buffer.end(), std::byte{0U});
    }
}

AuthenticatedControlTcpErrorV1
AuthenticatedControlTcpConnectionV1::write_bootstrap_record(
    const std::span<const std::byte> encoded_record,
    const ControlBootstrapDirectionV1 expected_direction,
    const std::uint32_t timeout_milliseconds) noexcept {
    if (!is_open() || timeout_milliseconds == 0U) {
        return failure(
            AuthenticatedControlTcpStatusV1::invalid_configuration);
    }
    const auto parsed = parse_authenticated_control_bootstrap_record_v1(
        encoded_record, expected_direction);
    if (parsed.status != ControlBootstrapParseStatusV1::parsed) {
        const auto error = failure(
            AuthenticatedControlTcpStatusV1::invalid_record,
            0U,
            parsed.status);
        close();
        return error;
    }
    const auto deadline = SteadyClock::now() +
        std::chrono::milliseconds{timeout_milliseconds};
    std::size_t sent_bytes{};
    while (sent_bytes < encoded_record.size()) {
        const auto waited = wait_until(
            static_cast<SOCKET>(handle_), WaitKind::writable, deadline);
        if (!waited.succeeded()) {
            close();
            return waited;
        }
        const std::size_t remaining = encoded_record.size() - sent_bytes;
        const int chunk = static_cast<int>((std::min)(
            remaining,
            static_cast<std::size_t>((std::numeric_limits<int>::max)())));
        const int sent = send(
            static_cast<SOCKET>(handle_),
            reinterpret_cast<const char*>(encoded_record.data() + sent_bytes),
            chunk,
            0);
        if (sent > 0) {
            sent_bytes += static_cast<std::size_t>(sent);
            continue;
        }
        if (sent == 0) {
            const auto error = failure(
                AuthenticatedControlTcpStatusV1::peer_closed);
            close();
            return error;
        }
        const int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK || error == WSAEINTR) continue;
        const auto result = failure(
            AuthenticatedControlTcpStatusV1::socket_error,
            static_cast<std::uint32_t>(error));
        close();
        return result;
    }
    return success();
}

AuthenticatedControlTcpReadResultV1
AuthenticatedControlTcpConnectionV1::read_authenticated_record(
    const ControlRecordDirectionV1 expected_direction,
    const std::uint32_t timeout_milliseconds) noexcept {
    AuthenticatedControlTcpReadResultV1 result{};
    if (!is_open() || timeout_milliseconds == 0U ||
        expected_direction == ControlRecordDirectionV1::invalid) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::invalid_configuration);
        return result;
    }
    const auto deadline = SteadyClock::now() +
        std::chrono::milliseconds{timeout_milliseconds};
    std::array<std::byte, 4'096U> buffer{};
    std::size_t total_size{};
    try {
        result.encoded_record.reserve(kAuthenticatedControlHeaderBytes);
        for (;;) {
            if (pending_offset_ < pending_input_.size()) {
                const std::size_t target = total_size == 0U
                    ? kAuthenticatedControlHeaderBytes : total_size;
                const std::size_t needed =
                    target - result.encoded_record.size();
                const std::size_t available =
                    pending_input_.size() - pending_offset_;
                const std::size_t copied = (std::min)(needed, available);
                result.encoded_record.insert(
                    result.encoded_record.end(),
                    pending_input_.begin() +
                        static_cast<std::ptrdiff_t>(pending_offset_),
                    pending_input_.begin() +
                        static_cast<std::ptrdiff_t>(pending_offset_ + copied));
                pending_offset_ += copied;
                if (pending_offset_ == pending_input_.size()) {
                    std::fill(
                        pending_input_.begin(), pending_input_.end(),
                        std::byte{0U});
                    pending_input_.clear();
                    pending_offset_ = 0U;
                }
                if (total_size == 0U &&
                    result.encoded_record.size() ==
                        kAuthenticatedControlHeaderBytes) {
                    if (!authenticated_control_record_size(
                            result.encoded_record,
                            expected_direction,
                            total_size)) {
                        result.error = failure(
                            AuthenticatedControlTcpStatusV1::invalid_record);
                        close();
                        return result;
                    }
                    result.encoded_record.reserve(total_size);
                }
                if (total_size != 0U &&
                    result.encoded_record.size() == total_size) {
                    result.error = success();
                    return result;
                }
                // recv() may coalesce the fixed header and encrypted body.
                // Consume every byte already retained in pending_input_
                // before waiting for another socket-read notification;
                // otherwise a complete single-packet VFC1 record stalls until
                // the operation deadline even though its body is in memory.
                if (pending_offset_ < pending_input_.size()) continue;
            }

            const auto waited = wait_until(
                static_cast<SOCKET>(handle_), WaitKind::readable, deadline);
            if (!waited.succeeded()) {
                result.error = waited;
                close();
                return result;
            }
            const int received = recv(
                static_cast<SOCKET>(handle_),
                reinterpret_cast<char*>(buffer.data()),
                static_cast<int>(buffer.size()), 0);
            if (received == 0) {
                result.error = failure(
                    AuthenticatedControlTcpStatusV1::peer_closed);
                close();
                return result;
            }
            if (received == SOCKET_ERROR) {
                const int error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK || error == WSAEINTR) continue;
                result.error = failure(
                    AuthenticatedControlTcpStatusV1::socket_error,
                    static_cast<std::uint32_t>(error));
                close();
                return result;
            }
            pending_input_.assign(
                buffer.begin(), buffer.begin() + received);
            pending_offset_ = 0U;
            std::fill(buffer.begin(), buffer.end(), std::byte{0U});
        }
    } catch (...) {
        result.encoded_record.clear();
        result.error = failure(
            AuthenticatedControlTcpStatusV1::allocation_failed);
        close();
        return result;
    }
}

AuthenticatedControlTcpErrorV1
AuthenticatedControlTcpConnectionV1::write_authenticated_record(
    const std::span<const std::byte> encoded_record,
    const ControlRecordDirectionV1 expected_direction,
    const std::uint32_t timeout_milliseconds) noexcept {
    std::size_t expected_size{};
    if (!is_open() || timeout_milliseconds == 0U ||
        !authenticated_control_record_size(
            encoded_record, expected_direction, expected_size) ||
        expected_size != encoded_record.size()) {
        const auto error = failure(
            AuthenticatedControlTcpStatusV1::invalid_record);
        close();
        return error;
    }
    const auto deadline = SteadyClock::now() +
        std::chrono::milliseconds{timeout_milliseconds};
    std::size_t sent_bytes{};
    while (sent_bytes < encoded_record.size()) {
        const auto waited = wait_until(
            static_cast<SOCKET>(handle_), WaitKind::writable, deadline);
        if (!waited.succeeded()) {
            close();
            return waited;
        }
        const std::size_t remaining = encoded_record.size() - sent_bytes;
        const int chunk = static_cast<int>((std::min)(
            remaining,
            static_cast<std::size_t>((std::numeric_limits<int>::max)())));
        const int sent = send(
            static_cast<SOCKET>(handle_),
            reinterpret_cast<const char*>(encoded_record.data() + sent_bytes),
            chunk, 0);
        if (sent > 0) {
            sent_bytes += static_cast<std::size_t>(sent);
            continue;
        }
        if (sent == 0) {
            const auto error = failure(
                AuthenticatedControlTcpStatusV1::peer_closed);
            close();
            return error;
        }
        const int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK || error == WSAEINTR) continue;
        const auto result = failure(
            AuthenticatedControlTcpStatusV1::socket_error,
            static_cast<std::uint32_t>(error));
        close();
        return result;
    }
    return success();
}

void AuthenticatedControlTcpConnectionV1::close() noexcept {
    if (handle_ != 0U) {
        shutdown(static_cast<SOCKET>(handle_), SD_BOTH);
        closesocket(static_cast<SOCKET>(handle_));
    }
    handle_ = 0U;
    std::fill(
        pending_input_.begin(), pending_input_.end(), std::byte{0U});
    pending_input_.clear();
    pending_offset_ = 0U;
    if (winsock_started_) WSACleanup();
    winsock_started_ = false;
}

bool AuthenticatedControlTcpConnectionV1::is_open() const noexcept {
    return handle_ != 0U;
}

std::string AuthenticatedControlTcpConnectionV1::local_ipv4() const {
    return is_open()
        ? socket_ipv4(static_cast<SOCKET>(handle_), false)
        : std::string{};
}

std::string AuthenticatedControlTcpConnectionV1::peer_ipv4() const {
    return is_open()
        ? socket_ipv4(static_cast<SOCKET>(handle_), true)
        : std::string{};
}

std::uint16_t AuthenticatedControlTcpConnectionV1::local_port() const noexcept {
    return is_open()
        ? socket_port(static_cast<SOCKET>(handle_), false)
        : 0U;
}

std::uint16_t AuthenticatedControlTcpConnectionV1::peer_port() const noexcept {
    return is_open()
        ? socket_port(static_cast<SOCKET>(handle_), true)
        : 0U;
}

AuthenticatedControlTcpListenerV1::~AuthenticatedControlTcpListenerV1() {
    close();
}

AuthenticatedControlTcpErrorV1 AuthenticatedControlTcpListenerV1::start(
    const std::string_view local_ipv4,
    const std::uint16_t port) noexcept {
    close();
    if (local_ipv4.empty()) {
        return failure(
            AuthenticatedControlTcpStatusV1::invalid_configuration);
    }
    WSADATA data{};
    const int startup = WSAStartup(MAKEWORD(2, 2), &data);
    if (startup != 0) {
        return failure(
            AuthenticatedControlTcpStatusV1::socket_error,
            static_cast<std::uint32_t>(startup));
    }
    winsock_started_ = true;
    const SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == INVALID_SOCKET) {
        const auto error = failure(
            AuthenticatedControlTcpStatusV1::socket_error,
            static_cast<std::uint32_t>(WSAGetLastError()));
        close();
        return error;
    }
    handle_ = static_cast<std::uintptr_t>(socket);
    const BOOL exclusive = TRUE;
    if (setsockopt(
            socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
            reinterpret_cast<const char*>(&exclusive),
            sizeof(exclusive)) == SOCKET_ERROR ||
        !set_nonblocking(socket)) {
        const auto error = failure(
            AuthenticatedControlTcpStatusV1::socket_error,
            static_cast<std::uint32_t>(WSAGetLastError()));
        close();
        return error;
    }
    sockaddr_in local{};
    if (!make_ipv4_address(local_ipv4, port, local)) {
        close();
        return failure(
            AuthenticatedControlTcpStatusV1::invalid_configuration);
    }
    if (::bind(
            socket, reinterpret_cast<const sockaddr*>(&local),
            sizeof(local)) == SOCKET_ERROR ||
        listen(socket, 1) == SOCKET_ERROR) {
        const auto error = failure(
            AuthenticatedControlTcpStatusV1::socket_error,
            static_cast<std::uint32_t>(WSAGetLastError()));
        close();
        return error;
    }
    return success();
}

AuthenticatedControlTcpConnectionResultV1
AuthenticatedControlTcpListenerV1::accept(
    const std::string_view expected_peer_ipv4,
    const std::uint32_t timeout_milliseconds) noexcept {
    return accept_candidate(
        expected_peer_ipv4, true, timeout_milliseconds);
}

AuthenticatedControlTcpConnectionResultV1
AuthenticatedControlTcpListenerV1::accept_untrusted_first_pair(
    const std::uint32_t timeout_milliseconds) noexcept {
    return accept_candidate({}, false, timeout_milliseconds);
}

AuthenticatedControlTcpConnectionResultV1
AuthenticatedControlTcpListenerV1::accept_bound_pair_candidate(
    const std::uint32_t timeout_milliseconds) noexcept {
    return accept_candidate({}, false, timeout_milliseconds);
}

AuthenticatedControlTcpConnectionResultV1
AuthenticatedControlTcpListenerV1::accept_candidate(
    const std::string_view expected_peer_ipv4,
    const bool enforce_expected_peer,
    const std::uint32_t timeout_milliseconds) noexcept {
    AuthenticatedControlTcpConnectionResultV1 result{};
    if (!is_open() || (enforce_expected_peer && expected_peer_ipv4.empty()) ||
        timeout_milliseconds == 0U) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::invalid_configuration);
        return result;
    }
    const auto deadline = SteadyClock::now() +
        std::chrono::milliseconds{timeout_milliseconds};
    const auto waited = wait_until(
        static_cast<SOCKET>(handle_), WaitKind::readable, deadline);
    if (!waited.succeeded()) {
        result.error = waited;
        return result;
    }
    sockaddr_in peer{};
    int peer_size = sizeof(peer);
    const SOCKET accepted = ::accept(
        static_cast<SOCKET>(handle_),
        reinterpret_cast<sockaddr*>(&peer),
        &peer_size);
    if (accepted == INVALID_SOCKET) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::socket_error,
            static_cast<std::uint32_t>(WSAGetLastError()));
        return result;
    }
    WSADATA data{};
    const int startup = WSAStartup(MAKEWORD(2, 2), &data);
    if (startup != 0 || !configure_connected_socket(accepted)) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::socket_error,
            startup != 0
                ? static_cast<std::uint32_t>(startup)
                : static_cast<std::uint32_t>(WSAGetLastError()));
        closesocket(accepted);
        if (startup == 0) WSACleanup();
        return result;
    }
    auto connection = std::unique_ptr<AuthenticatedControlTcpConnectionV1>(
        new (std::nothrow) AuthenticatedControlTcpConnectionV1(
            static_cast<std::uintptr_t>(accepted), true));
    if (connection == nullptr) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::allocation_failed);
        closesocket(accepted);
        WSACleanup();
        return result;
    }
    if (enforce_expected_peer &&
        !same_ipv4(expected_peer_ipv4, connection->peer_ipv4())) {
        result.error = failure(
            AuthenticatedControlTcpStatusV1::peer_mismatch);
        connection->close();
        return result;
    }
    result.connection = std::move(connection);
    result.error = success();
    return result;
}

void AuthenticatedControlTcpListenerV1::close() noexcept {
    if (handle_ != 0U) {
        closesocket(static_cast<SOCKET>(handle_));
    }
    handle_ = 0U;
    if (winsock_started_) WSACleanup();
    winsock_started_ = false;
}

bool AuthenticatedControlTcpListenerV1::is_open() const noexcept {
    return handle_ != 0U;
}

std::uint16_t AuthenticatedControlTcpListenerV1::local_port() const noexcept {
    return is_open()
        ? socket_port(static_cast<SOCKET>(handle_), false)
        : 0U;
}

}  // namespace vfdual
