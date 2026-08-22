#pragma once

#include "vfdual/authenticated_data_plane_v2.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <vector>

namespace vfdual {

inline constexpr std::uint8_t kAuthenticatedControlRecordVersion = 1U;
inline constexpr std::size_t kAuthenticatedControlHeaderBytes = 40U;
inline constexpr std::size_t kMaximumAuthenticatedControlPayloadBytes =
    65'536U;
inline constexpr std::uint64_t kMaximumAuthenticatedControlRecordsPerKey =
    1ULL << 23U;
inline constexpr std::uint64_t kMaximumAuthenticatedControlCounter =
    kMaximumAuthenticatedControlRecordsPerKey - 1U;

enum class ControlRecordDirectionV1 : std::uint8_t {
    invalid = 0U,
    host_to_android = 1U,
    android_to_host = 2U,
};

enum class ControlMessageTypeV1 : std::uint8_t {
    invalid = 0U,
    lease_offer = 1U,
    lease_accept = 2U,
    lease_commit = 3U,
    session_close = 4U,
    session_close_ack = 5U,
};

/**
 * Identity of one directional control-key domain.
 *
 * Message type is intentionally absent: every control type in one direction
 * shares this tuple, one key/prefix, one send counter, and one replay window.
 */
struct AuthenticatedControlTupleV1 final {
    std::uint64_t connection_id{};
    std::uint64_t session_generation{};
    std::uint32_t key_epoch{};
    ControlRecordDirectionV1 direction{ControlRecordDirectionV1::invalid};

    bool operator==(const AuthenticatedControlTupleV1&) const = default;
};

struct AuthenticatedControlTrafficKeyV1 final {
    AuthenticatedControlTupleV1 tuple;
    std::array<std::byte, kAes256KeyBytes> aes_256_key{};
    std::array<std::byte, kGcmNoncePrefixBytes> nonce_prefix{};

    AuthenticatedControlTrafficKeyV1() = default;
    ~AuthenticatedControlTrafficKeyV1();

    AuthenticatedControlTrafficKeyV1(
        const AuthenticatedControlTrafficKeyV1&) = delete;
    AuthenticatedControlTrafficKeyV1& operator=(
        const AuthenticatedControlTrafficKeyV1&) = delete;
    AuthenticatedControlTrafficKeyV1(
        AuthenticatedControlTrafficKeyV1&& other) noexcept;
    AuthenticatedControlTrafficKeyV1& operator=(
        AuthenticatedControlTrafficKeyV1&& other) noexcept;
};

enum class ControlRecordParseStatusV1 {
    parsed,
    record_too_short,
    invalid_magic,
    unsupported_version,
    invalid_header_size,
    invalid_direction,
    invalid_message_type,
    invalid_tuple,
    counter_exceeds_key_lifetime,
    payload_too_large,
    length_mismatch,
};

struct ParsedAuthenticatedControlRecordV1 final {
    AuthenticatedControlTupleV1 tuple;
    ControlMessageTypeV1 message_type{ControlMessageTypeV1::invalid};
    std::uint64_t counter{};
    std::span<const std::byte> authenticated_header;
    std::span<const std::byte> ciphertext;
    std::span<const std::byte> tag;
};

struct ControlRecordParseResultV1 final {
    ControlRecordParseStatusV1 status{
        ControlRecordParseStatusV1::record_too_short};
    ParsedAuthenticatedControlRecordV1 record;
};

/** Pure framing parse. It does not authenticate or mutate replay state. */
[[nodiscard]] ControlRecordParseResultV1
parse_authenticated_control_record_v1(
    std::span<const std::byte> envelope) noexcept;

[[nodiscard]] std::array<std::byte, kGcmNonceBytes>
compose_authenticated_control_nonce_v1(
    std::span<const std::byte, kGcmNoncePrefixBytes> prefix,
    std::uint64_t counter) noexcept;

enum class ControlRecordSealStatusV1 {
    sealed,
    invalid_configuration,
    invalid_message_type,
    plaintext_too_large,
    counter_exhausted,
    allocation_failed,
    encryption_failed,
};

struct ControlRecordSealResultV1 final {
    ControlRecordSealStatusV1 status{
        ControlRecordSealStatusV1::invalid_configuration};
    std::uint64_t counter{};
    std::vector<std::byte> envelope;
};

class AuthenticatedControlRecordSealerV1 final {
public:
    AuthenticatedControlRecordSealerV1(
        AuthenticatedControlTrafficKeyV1 traffic_key,
        Aes256GcmProvider& provider) noexcept;
    ~AuthenticatedControlRecordSealerV1();

    AuthenticatedControlRecordSealerV1(
        const AuthenticatedControlRecordSealerV1&) = delete;
    AuthenticatedControlRecordSealerV1& operator=(
        const AuthenticatedControlRecordSealerV1&) = delete;

    [[nodiscard]] ControlRecordSealResultV1 seal(
        ControlMessageTypeV1 message_type,
        std::span<const std::byte> plaintext) noexcept;

private:
    friend struct AuthenticatedControlRecordV1TestAccess;

    AuthenticatedControlRecordSealerV1(
        AuthenticatedControlTrafficKeyV1 traffic_key,
        Aes256GcmProvider& provider,
        std::uint64_t initial_counter) noexcept;

    AuthenticatedControlTupleV1 tuple_;
    std::array<std::byte, kGcmNoncePrefixBytes> nonce_prefix_{};
    std::unique_ptr<Aes256GcmCipher> cipher_;
    std::uint64_t next_counter_{};
    bool counter_available_{true};
    std::mutex mutex_;
};

enum class ControlRecordOpenStatusV1 {
    opened,
    unauthenticated_record,
    invalid_configuration,
    allocation_failed,
};

struct ControlRecordOpenResultV1 final {
    ControlRecordOpenStatusV1 status{
        ControlRecordOpenStatusV1::invalid_configuration};
    ControlMessageTypeV1 message_type{ControlMessageTypeV1::invalid};
    std::uint64_t authenticated_counter{};
    std::vector<std::byte> plaintext;
};

/**
 * Opens VFC1 records and exposes one generic result for every packet-controlled
 * parse, tuple, replay, or tag failure. Replay state advances only after tag
 * verification succeeds.
 */
class AuthenticatedControlRecordOpenerV1 final {
public:
    AuthenticatedControlRecordOpenerV1(
        AuthenticatedControlTrafficKeyV1 traffic_key,
        Aes256GcmProvider& provider) noexcept;
    ~AuthenticatedControlRecordOpenerV1();

    AuthenticatedControlRecordOpenerV1(
        const AuthenticatedControlRecordOpenerV1&) = delete;
    AuthenticatedControlRecordOpenerV1& operator=(
        const AuthenticatedControlRecordOpenerV1&) = delete;

    [[nodiscard]] ControlRecordOpenResultV1 open(
        std::span<const std::byte> envelope) noexcept;
    [[nodiscard]] ReplayWindowSnapshot replay_snapshot() const noexcept;

private:
    AuthenticatedControlTupleV1 tuple_;
    std::array<std::byte, kGcmNoncePrefixBytes> nonce_prefix_{};
    std::unique_ptr<Aes256GcmCipher> cipher_;
    SlidingReplayWindow1024 replay_window_;
    mutable std::mutex mutex_;
};

}  // namespace vfdual
