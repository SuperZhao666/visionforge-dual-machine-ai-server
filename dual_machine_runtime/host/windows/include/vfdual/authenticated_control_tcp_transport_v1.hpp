#pragma once

#include "vfdual/authenticated_control_bootstrap_record_v1.hpp"
#include "vfdual/authenticated_control_record_v1.hpp"
#include "vfdual/wired_link_contract.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vfdual {

enum class AuthenticatedControlTcpStatusV1 : std::uint8_t {
    succeeded = 1U,
    invalid_configuration = 2U,
    timed_out = 3U,
    peer_closed = 4U,
    peer_mismatch = 5U,
    invalid_record = 6U,
    socket_error = 7U,
    allocation_failed = 8U,
};

/** Sanitized transport result; it never retains a record or remote payload. */
struct AuthenticatedControlTcpErrorV1 final {
    AuthenticatedControlTcpStatusV1 status{
        AuthenticatedControlTcpStatusV1::invalid_configuration};
    std::uint32_t native_error{};
    ControlBootstrapParseStatusV1 record_rejection{
        ControlBootstrapParseStatusV1::record_too_short};

    [[nodiscard]] bool succeeded() const noexcept {
        return status == AuthenticatedControlTcpStatusV1::succeeded;
    }
};

struct AuthenticatedControlTcpReadResultV1 final {
    std::vector<std::byte> encoded_record;
    AuthenticatedControlTcpErrorV1 error;

    [[nodiscard]] bool succeeded() const noexcept {
        return !encoded_record.empty() && error.succeeded();
    }
};

class AuthenticatedControlTcpConnectionV1;

struct AuthenticatedControlTcpConnectionResultV1 final {
    std::unique_ptr<AuthenticatedControlTcpConnectionV1> connection;
    AuthenticatedControlTcpErrorV1 error;

    [[nodiscard]] bool succeeded() const noexcept {
        return connection != nullptr && error.succeeded();
    }
};

/**
 * One non-blocking TCP connection for the bounded VFB1/VFC1 control attempt.
 *
 * The VFB1 methods preserve coalesced remainder bytes, complete short writes,
 * apply one total deadline per operation, and close the connection on timeout,
 * half-close, malformed framing or socket failure. They do not authenticate a
 * peer: only the higher-level identity signatures and Finished proofs can do
 * that.
 */
class AuthenticatedControlTcpConnectionV1 final {
public:
    ~AuthenticatedControlTcpConnectionV1();
    AuthenticatedControlTcpConnectionV1(
        const AuthenticatedControlTcpConnectionV1&) = delete;
    AuthenticatedControlTcpConnectionV1& operator=(
        const AuthenticatedControlTcpConnectionV1&) = delete;

    [[nodiscard]] static AuthenticatedControlTcpConnectionResultV1 connect(
        std::string_view local_ipv4,
        std::string_view expected_peer_ipv4,
        std::uint16_t peer_port = kWiredAuthenticatedControlPort,
        std::uint32_t timeout_milliseconds = 5'000U) noexcept;

    [[nodiscard]] AuthenticatedControlTcpReadResultV1 read_bootstrap_record(
        ControlBootstrapDirectionV1 expected_direction,
        std::uint32_t timeout_milliseconds) noexcept;
    [[nodiscard]] AuthenticatedControlTcpErrorV1 write_bootstrap_record(
        std::span<const std::byte> encoded_record,
        ControlBootstrapDirectionV1 expected_direction,
        std::uint32_t timeout_milliseconds) noexcept;
    [[nodiscard]] AuthenticatedControlTcpReadResultV1
    read_authenticated_record(
        ControlRecordDirectionV1 expected_direction,
        std::uint32_t timeout_milliseconds) noexcept;
    [[nodiscard]] AuthenticatedControlTcpErrorV1
    write_authenticated_record(
        std::span<const std::byte> encoded_record,
        ControlRecordDirectionV1 expected_direction,
        std::uint32_t timeout_milliseconds) noexcept;

    void close() noexcept;
    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] std::string local_ipv4() const;
    [[nodiscard]] std::string peer_ipv4() const;
    [[nodiscard]] std::uint16_t local_port() const noexcept;
    [[nodiscard]] std::uint16_t peer_port() const noexcept;

private:
    friend class AuthenticatedControlTcpListenerV1;
    explicit AuthenticatedControlTcpConnectionV1(
        std::uintptr_t handle,
        bool winsock_started) noexcept;

    std::uintptr_t handle_{};
    bool winsock_started_{};
    std::vector<std::byte> pending_input_;
    std::size_t pending_offset_{};
};

/** Exclusive single-process Host listener for the VFB1 control endpoint. */
class AuthenticatedControlTcpListenerV1 final {
public:
    AuthenticatedControlTcpListenerV1() noexcept = default;
    ~AuthenticatedControlTcpListenerV1();
    AuthenticatedControlTcpListenerV1(
        const AuthenticatedControlTcpListenerV1&) = delete;
    AuthenticatedControlTcpListenerV1& operator=(
        const AuthenticatedControlTcpListenerV1&) = delete;

    [[nodiscard]] AuthenticatedControlTcpErrorV1 start(
        std::string_view local_ipv4,
        std::uint16_t port = kWiredAuthenticatedControlPort) noexcept;
    [[nodiscard]] AuthenticatedControlTcpConnectionResultV1 accept(
        std::string_view expected_peer_ipv4,
        std::uint32_t timeout_milliseconds) noexcept;
    /**
     * Accepts one unauthenticated candidate only for the fresh-pair flow.
     * The returned socket route is committed into VFP1 and both users must
     * confirm the resulting SAS before either identity may sign activation.
     * Bound-session callers must continue to use accept(expected_peer_ipv4).
     */
    [[nodiscard]] AuthenticatedControlTcpConnectionResultV1
    accept_untrusted_first_pair(
        std::uint32_t timeout_milliseconds) noexcept;
    /**
     * Accepts one bounded candidate for an already persisted pair when no IP
     * address is trusted or persisted. The caller must bind the actual socket
     * route into the signed transcript and verify the stored peer SPKI plus a
     * fresh server generation credential before retaining the connection.
     */
    [[nodiscard]] AuthenticatedControlTcpConnectionResultV1
    accept_bound_pair_candidate(
        std::uint32_t timeout_milliseconds) noexcept;
    void close() noexcept;
    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] std::uint16_t local_port() const noexcept;

private:
    [[nodiscard]] AuthenticatedControlTcpConnectionResultV1 accept_candidate(
        std::string_view expected_peer_ipv4,
        bool enforce_expected_peer,
        std::uint32_t timeout_milliseconds) noexcept;

    std::uintptr_t handle_{};
    bool winsock_started_{};
};

}  // namespace vfdual
