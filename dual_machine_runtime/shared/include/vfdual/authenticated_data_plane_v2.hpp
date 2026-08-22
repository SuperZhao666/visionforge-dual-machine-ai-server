#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <vector>

namespace vfdual {

inline constexpr std::uint8_t kAuthenticatedDataPlaneVersion = 2U;
inline constexpr std::size_t kAuthenticatedPacketHeaderBytes = 32U;
inline constexpr std::size_t kAes256KeyBytes = 32U;
inline constexpr std::size_t kGcmNoncePrefixBytes = 4U;
inline constexpr std::size_t kGcmCounterBytes = 8U;
inline constexpr std::size_t kGcmNonceBytes =
    kGcmNoncePrefixBytes + kGcmCounterBytes;
inline constexpr std::size_t kGcmTagBytes = 16U;
inline constexpr std::size_t kReplayWindowBits = 1024U;
inline constexpr std::size_t kMaximumAuthenticatedDatagramBytes = 1412U;
inline constexpr std::size_t kMaximumAuthenticatedPayloadBytes =
    kMaximumAuthenticatedDatagramBytes -
    kAuthenticatedPacketHeaderBytes -
    kGcmTagBytes;
// Conservative per-traffic-key ceiling modelled after modern AEAD transport
// key-update limits. The 64-bit wire counter remains available for protocol
// evolution, but a v2 sender must rekey long before integer exhaustion.
inline constexpr std::uint64_t kMaximumPacketsPerTrafficKey = 1ULL << 23U;
inline constexpr std::uint64_t kMaximumAuthenticatedPacketCounter =
    kMaximumPacketsPerTrafficKey - 1U;

enum class AuthenticatedPacketType : std::uint8_t {
    invalid = 0U,
    video = 1U,
    presence_probe = 2U,
    idr_request = 3U,
    mouse_button = 4U,
};

enum class DataPlaneDirection : std::uint8_t {
    invalid = 0U,
    host_to_android = 1U,
    android_to_host = 2U,
};

/**
 * Identity of one traffic-key domain.
 *
 * A data-plane key, nonce prefix, send counter and receive replay window are
 * bound to exactly one tuple. Callers must install a freshly derived traffic
 * key for every distinct tuple and every key epoch.
 */
struct AuthenticatedPacketTuple final {
    std::uint64_t connection_id{};
    std::uint32_t key_epoch{};
    DataPlaneDirection direction{DataPlaneDirection::invalid};
    AuthenticatedPacketType packet_type{AuthenticatedPacketType::invalid};

    bool operator==(const AuthenticatedPacketTuple&) const = default;
};

struct AuthenticatedTrafficKey final {
    AuthenticatedPacketTuple tuple;
    std::array<std::byte, kAes256KeyBytes> aes_256_key{};
    std::array<std::byte, kGcmNoncePrefixBytes> nonce_prefix{};

    AuthenticatedTrafficKey() = default;
    ~AuthenticatedTrafficKey();

    AuthenticatedTrafficKey(const AuthenticatedTrafficKey&) = delete;
    AuthenticatedTrafficKey& operator=(const AuthenticatedTrafficKey&) = delete;
    AuthenticatedTrafficKey(AuthenticatedTrafficKey&& other) noexcept;
    AuthenticatedTrafficKey& operator=(AuthenticatedTrafficKey&& other) noexcept;
};

/**
 * One imported AES-256-GCM key. Production Windows implementations are backed
 * by BCrypt. Other platforms can inject their native, audited AEAD provider.
 */
class Aes256GcmCipher {
public:
    virtual ~Aes256GcmCipher() = default;

    /** Output buffers contain usable data only when the method returns true. */
    [[nodiscard]] virtual bool encrypt(
        std::span<const std::byte, kGcmNonceBytes> nonce,
        std::span<const std::byte> authenticated_data,
        std::span<const std::byte> plaintext,
        std::span<std::byte> ciphertext,
        std::span<std::byte, kGcmTagBytes> tag) noexcept = 0;

    [[nodiscard]] virtual bool decrypt(
        std::span<const std::byte, kGcmNonceBytes> nonce,
        std::span<const std::byte> authenticated_data,
        std::span<const std::byte> ciphertext,
        std::span<const std::byte, kGcmTagBytes> tag,
        std::span<std::byte> plaintext) noexcept = 0;
};

class Aes256GcmProvider {
public:
    virtual ~Aes256GcmProvider() = default;

    [[nodiscard]] virtual std::unique_ptr<Aes256GcmCipher> import_key(
        std::span<const std::byte, kAes256KeyBytes> key) noexcept = 0;
};

/** Returns a BCrypt provider on Windows and nullptr on unsupported platforms. */
[[nodiscard]] std::unique_ptr<Aes256GcmProvider>
make_platform_aes_256_gcm_provider() noexcept;

enum class PacketParseStatus {
    parsed,
    packet_too_short,
    invalid_magic,
    unsupported_version,
    invalid_header_size,
    invalid_packet_type,
    invalid_direction,
    counter_exceeds_key_lifetime,
    payload_too_large,
    length_mismatch,
};

struct ParsedAuthenticatedPacket final {
    AuthenticatedPacketTuple tuple;
    std::uint64_t counter{};
    std::span<const std::byte> authenticated_header;
    std::span<const std::byte> ciphertext;
    std::span<const std::byte> tag;
};

struct PacketParseResult final {
    PacketParseStatus status{PacketParseStatus::packet_too_short};
    ParsedAuthenticatedPacket packet;
};

/** Pure framing parse. It never authenticates data or mutates replay state. */
[[nodiscard]] PacketParseResult parse_authenticated_packet_v2(
    std::span<const std::byte> datagram) noexcept;

enum class PacketValidationStatus {
    valid,
    invalid_expected_tuple,
    wrong_connection_id,
    wrong_key_epoch,
    wrong_direction,
    wrong_packet_type,
};

/** Pure expected-tuple validation. It never mutates replay state. */
[[nodiscard]] PacketValidationStatus validate_authenticated_packet_v2(
    const ParsedAuthenticatedPacket& packet,
    const AuthenticatedPacketTuple& expected) noexcept;

enum class ReplayDisposition {
    fresh,
    duplicate,
    too_old,
};

struct ReplayWindowSnapshot final {
    bool initialized{};
    std::uint64_t highest_authenticated_counter{};
};

/**
 * A fixed 1024-bit sliding replay window.
 *
 * classify() is read-only. Only AuthenticatedPacketOpener can commit a
 * counter, and it does so after a successful GCM authentication.
 */
class SlidingReplayWindow1024 final {
public:
    [[nodiscard]] ReplayDisposition classify(
        std::uint64_t counter) const noexcept;
    [[nodiscard]] ReplayWindowSnapshot snapshot() const noexcept;

private:
    friend class AuthenticatedPacketOpener;
    friend class AuthenticatedControlRecordOpenerV1;

    [[nodiscard]] bool commit_authenticated(std::uint64_t counter) noexcept;

    std::array<std::uint64_t, kReplayWindowBits / 64U> seen_{};
    std::uint64_t highest_counter_{};
    bool initialized_{};
};

[[nodiscard]] std::array<std::byte, kGcmNonceBytes>
compose_authenticated_packet_nonce(
    std::span<const std::byte, kGcmNoncePrefixBytes> prefix,
    std::uint64_t counter) noexcept;

enum class PacketSealStatus {
    sealed,
    invalid_configuration,
    plaintext_too_large,
    counter_exhausted,
    allocation_failed,
    encryption_failed,
};

struct PacketSealResult final {
    PacketSealStatus status{PacketSealStatus::invalid_configuration};
    std::uint64_t counter{};
    std::vector<std::byte> datagram;
};

class AuthenticatedPacketSealer final {
public:
    AuthenticatedPacketSealer(
        AuthenticatedTrafficKey traffic_key,
        Aes256GcmProvider& provider) noexcept;
    ~AuthenticatedPacketSealer();

    AuthenticatedPacketSealer(const AuthenticatedPacketSealer&) = delete;
    AuthenticatedPacketSealer& operator=(
        const AuthenticatedPacketSealer&) = delete;

    [[nodiscard]] PacketSealResult seal(
        std::span<const std::byte> plaintext) noexcept;

private:
    friend struct AuthenticatedDataPlaneV2TestAccess;

    AuthenticatedPacketSealer(
        AuthenticatedTrafficKey traffic_key,
        Aes256GcmProvider& provider,
        std::uint64_t initial_counter) noexcept;

    AuthenticatedPacketTuple tuple_;
    std::array<std::byte, kGcmNoncePrefixBytes> nonce_prefix_{};
    std::unique_ptr<Aes256GcmCipher> cipher_;
    std::uint64_t next_counter_{};
    bool counter_available_{true};
    std::mutex mutex_;
};

enum class PacketOpenStatus {
    opened,
    malformed_packet,
    invalid_configuration,
    wrong_connection_id,
    wrong_key_epoch,
    wrong_direction,
    wrong_packet_type,
    duplicate,
    too_old,
    authentication_failed,
    allocation_failed,
};

struct PacketOpenResult final {
    PacketOpenStatus status{PacketOpenStatus::invalid_configuration};
    PacketParseStatus parse_status{PacketParseStatus::packet_too_short};
    PacketValidationStatus validation_status{
        PacketValidationStatus::invalid_expected_tuple};
    std::uint64_t authenticated_counter{};
    std::vector<std::byte> plaintext;
};

class AuthenticatedPacketOpener final {
public:
    AuthenticatedPacketOpener(
        AuthenticatedTrafficKey traffic_key,
        Aes256GcmProvider& provider) noexcept;
    ~AuthenticatedPacketOpener();

    AuthenticatedPacketOpener(const AuthenticatedPacketOpener&) = delete;
    AuthenticatedPacketOpener& operator=(
        const AuthenticatedPacketOpener&) = delete;

    [[nodiscard]] PacketOpenResult open(
        std::span<const std::byte> datagram) noexcept;
    [[nodiscard]] ReplayWindowSnapshot replay_snapshot() const noexcept;

private:
    AuthenticatedPacketTuple tuple_;
    std::array<std::byte, kGcmNoncePrefixBytes> nonce_prefix_{};
    std::unique_ptr<Aes256GcmCipher> cipher_;
    SlidingReplayWindow1024 replay_window_;
    mutable std::mutex mutex_;
};

}  // namespace vfdual
