#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vfdual {

inline constexpr std::uint32_t kAuthenticatedPeerHandshakeVersion = 1U;
inline constexpr std::size_t kPeerHandshakeSha256Bytes = 32U;
inline constexpr std::size_t kPeerHandshakeP256PublicKeyBytes = 65U;
inline constexpr std::size_t kPeerHandshakeNonceBytes = 32U;
inline constexpr std::size_t kPeerHandshakeAes256KeyBytes = 32U;
inline constexpr std::size_t kPeerHandshakeNoncePrefixBytes = 4U;
inline constexpr std::size_t kPeerHandshakeDataPlaneMaterialBytes =
    kPeerHandshakeAes256KeyBytes + kPeerHandshakeNoncePrefixBytes;
inline constexpr std::size_t kPeerHandshakeMaximumPairIdBytes = 64U;
inline constexpr std::size_t kPeerHandshakeMaximumRuntimeVersionBytes = 32U;
inline constexpr std::size_t kPeerHandshakeFieldCount = 18U;
// Exact maximum with all 18 TLV headers, a 64-byte pair id, and two 32-byte
// stable SemVer values. Keeping this bound exact rejects trailing extensions
// before any peer-controlled allocation while accepting every contracted value.
inline constexpr std::size_t kPeerHandshakeMaximumCanonicalBytes = 538U;
inline constexpr std::size_t kHkdfSha256MaximumOutputBytes = 255U * 32U;
inline constexpr std::string_view kAuthenticatedPeerHandshakeDomain{
    "visionforge-peer-handshake-v1"};

using PeerHandshakeSha256 =
    std::array<std::byte, kPeerHandshakeSha256Bytes>;
using PeerHandshakeP256PublicKey =
    std::array<std::byte, kPeerHandshakeP256PublicKeyBytes>;
using PeerHandshakeNonce =
    std::array<std::byte, kPeerHandshakeNonceBytes>;

enum class PeerHandshakeRole : std::uint8_t {
    host = 1U,
    android = 2U,
};

enum class PeerHandshakeTransportKind : std::uint8_t {
    cat6 = 1U,
    wlan = 2U,
};

/** Controls the only intentionally optional transcript field. */
enum class PeerHandshakePairIdRequirement : std::uint8_t {
    allow_empty_before_activation = 1U,
    require_bound_pair = 2U,
};

enum class PeerHandshakeNativeStatusDomain : std::uint8_t {
    none = 0U,
    bcrypt_ntstatus = 1U,
};

enum class PeerHandshakeErrorCode : std::uint8_t {
    none = 0U,
    allocation_failed,
    transcript_too_large,
    truncated_tlv,
    unknown_tag,
    duplicate_tag,
    out_of_order_tag,
    missing_field,
    invalid_field_length,
    invalid_domain,
    unsupported_protocol_version,
    invalid_identity_binding,
    invalid_ephemeral_public_key,
    invalid_nonce,
    invalid_connection_id,
    invalid_session_generation,
    invalid_transport_kind,
    invalid_endpoint,
    invalid_pair_id,
    invalid_runtime_version,
    invalid_pair_id_requirement,
    invalid_role,
    pair_binding_required_for_key_derivation,
    ephemeral_private_key_already_consumed,
    local_ephemeral_key_mismatch,
    pending_confirmation_closed,
    local_finished_not_generated,
    peer_finished_authentication_failed,
    platform_crypto_unavailable,
    crypto_provider_failed,
    crypto_operation_failed,
    hkdf_output_too_large,
};

/**
 * Sanitized failure metadata. It intentionally contains no transcript,
 * private-key, shared-secret, derived-key, Finished, or peer-controlled text.
 */
struct PeerHandshakeError final {
    PeerHandshakeErrorCode code{PeerHandshakeErrorCode::none};
    PeerHandshakeNativeStatusDomain native_domain{
        PeerHandshakeNativeStatusDomain::none};
    std::uint32_t native_status{};
    std::uint8_t field_tag{0xffU};
    std::string_view operation;

    [[nodiscard]] bool has_error() const noexcept {
        return code != PeerHandshakeErrorCode::none;
    }
};

[[nodiscard]] const char* peer_handshake_error_code_name(
    PeerHandshakeErrorCode code) noexcept;

/** The exact 18 values covered by both long-term identity signatures. */
struct PeerHandshakeTranscriptFields final {
    std::string domain{std::string(kAuthenticatedPeerHandshakeDomain)};
    std::uint32_t protocol_version{kAuthenticatedPeerHandshakeVersion};
    PeerHandshakeSha256 host_identity_spki_sha256{};
    PeerHandshakeSha256 android_identity_spki_sha256{};
    PeerHandshakeP256PublicKey host_ephemeral_public_key{};
    PeerHandshakeP256PublicKey android_ephemeral_public_key{};
    PeerHandshakeNonce host_nonce{};
    PeerHandshakeNonce android_nonce{};
    std::uint64_t connection_id{};
    std::uint64_t session_generation{};
    PeerHandshakeTransportKind transport_kind{
        PeerHandshakeTransportKind::cat6};
    std::array<std::byte, 4U> host_ipv4{};
    std::array<std::byte, 4U> android_ipv4{};
    std::uint16_t video_port{};
    std::uint16_t control_port{};
    std::string pair_id;
    std::string host_runtime_version;
    std::string android_runtime_version;
};

struct PeerHandshakeTranscriptResult;

/**
 * Validated canonical transcript. Construction is restricted to the strict
 * encoder/parser so downstream signing and ECDH code cannot accept an
 * unvalidated field bag or caller-supplied transcript hash.
 */
class CanonicalPeerHandshakeTranscriptV1 final {
public:
    CanonicalPeerHandshakeTranscriptV1(
        const CanonicalPeerHandshakeTranscriptV1&) = default;
    CanonicalPeerHandshakeTranscriptV1& operator=(
        const CanonicalPeerHandshakeTranscriptV1&) = default;
    CanonicalPeerHandshakeTranscriptV1(
        CanonicalPeerHandshakeTranscriptV1&&) noexcept = default;
    CanonicalPeerHandshakeTranscriptV1& operator=(
        CanonicalPeerHandshakeTranscriptV1&&) noexcept = default;

    [[nodiscard]] const PeerHandshakeTranscriptFields& fields() const noexcept;
    [[nodiscard]] std::span<const std::byte> canonical_bytes() const noexcept;
    [[nodiscard]] const PeerHandshakeSha256& transcript_sha256() const noexcept;

private:
    CanonicalPeerHandshakeTranscriptV1(
        PeerHandshakeTranscriptFields fields,
        std::vector<std::byte> canonical_bytes,
        PeerHandshakeSha256 transcript_sha256);

    friend struct PeerHandshakeTranscriptResult;
    friend PeerHandshakeTranscriptResult
    build_canonical_peer_handshake_transcript_v1(
        const PeerHandshakeTranscriptFields&,
        PeerHandshakePairIdRequirement) noexcept;
    friend PeerHandshakeTranscriptResult
    parse_canonical_peer_handshake_transcript_v1(
        std::span<const std::byte>,
        PeerHandshakePairIdRequirement) noexcept;

    PeerHandshakeTranscriptFields fields_;
    std::vector<std::byte> canonical_bytes_;
    PeerHandshakeSha256 transcript_sha256_{};
};

struct PeerHandshakeTranscriptResult final {
    std::optional<CanonicalPeerHandshakeTranscriptV1> transcript;
    PeerHandshakeError error;

    [[nodiscard]] bool succeeded() const noexcept {
        return transcript.has_value() && !error.has_error();
    }
};

[[nodiscard]] PeerHandshakeTranscriptResult
build_canonical_peer_handshake_transcript_v1(
    const PeerHandshakeTranscriptFields& fields,
    PeerHandshakePairIdRequirement pair_id_requirement) noexcept;

[[nodiscard]] PeerHandshakeTranscriptResult
parse_canonical_peer_handshake_transcript_v1(
    std::span<const std::byte> canonical_bytes,
    PeerHandshakePairIdRequirement pair_id_requirement) noexcept;

struct PeerHandshakeDataPlaneKeyView final {
    std::span<const std::byte, kPeerHandshakeAes256KeyBytes> aes_256_key;
    std::span<const std::byte, kPeerHandshakeNoncePrefixBytes> nonce_prefix;
};

/**
 * Non-secret binding metadata released with a confirmed peer session.
 *
 * This is a value snapshot, not a view into the transcript or session
 * storage.  The fields are populated only from the validated canonical
 * transcript and its channel-binding exporter during key derivation.
 */
struct ConfirmedPeerHandshakeBindingV1 final {
    std::string pair_id;
    PeerHandshakeSha256 host_identity_spki_sha256{};
    PeerHandshakeSha256 android_identity_spki_sha256{};
    std::uint64_t connection_id{};
    std::uint64_t session_generation{};
    PeerHandshakeSha256 transcript_sha256{};
    PeerHandshakeSha256 channel_binding_sha256{};
};

struct PeerHandshakeDigestResult final {
    std::optional<PeerHandshakeSha256> digest;
    PeerHandshakeError error;

    [[nodiscard]] bool succeeded() const noexcept {
        return digest.has_value() && !error.has_error();
    }
};

class PlatformP256EphemeralKeyAgreementV1;
class PendingPeerHandshakeConfirmationV1;
class HostPeerHandshakeTranscriptSignerV1;

/**
 * Non-copyable session material released only after peer Finished acceptance.
 * Ownership is transferred only through std::unique_ptr; the secret owner
 * itself is deliberately non-movable so a moved-from object cannot expose
 * zeroed key material through an otherwise valid getter.
 * Every traffic domain is independently HKDF-expanded with its frozen label;
 * Finished keys and the exporter are not exposed as raw public API bytes.
 */
class ConfirmedPeerHandshakeSessionV1 final {
public:
    ~ConfirmedPeerHandshakeSessionV1();
    ConfirmedPeerHandshakeSessionV1(
        const ConfirmedPeerHandshakeSessionV1&) =
        delete;
    ConfirmedPeerHandshakeSessionV1& operator=(
        const ConfirmedPeerHandshakeSessionV1&) = delete;
    ConfirmedPeerHandshakeSessionV1(
        ConfirmedPeerHandshakeSessionV1&&) = delete;
    ConfirmedPeerHandshakeSessionV1& operator=(
        ConfirmedPeerHandshakeSessionV1&&) = delete;

    [[nodiscard]] PeerHandshakeRole local_role() const noexcept;
    [[nodiscard]] std::uint64_t connection_id() const noexcept;
    /** Returns an owned snapshot; no session-backed view can dangle. */
    [[nodiscard]] ConfirmedPeerHandshakeBindingV1 binding() const;
    [[nodiscard]] PeerHandshakeDataPlaneKeyView
    control_host_to_android() const noexcept;
    [[nodiscard]] PeerHandshakeDataPlaneKeyView
    control_android_to_host() const noexcept;
    [[nodiscard]] PeerHandshakeDataPlaneKeyView
    presence_host_to_android() const noexcept;
    [[nodiscard]] PeerHandshakeDataPlaneKeyView
    video_host_to_android() const noexcept;
    [[nodiscard]] PeerHandshakeDataPlaneKeyView
    idr_android_to_host() const noexcept;
    [[nodiscard]] PeerHandshakeDataPlaneKeyView
    mouse_host_to_android() const noexcept;
    [[nodiscard]] const PeerHandshakeSha256& transcript_sha256() const noexcept;
    [[nodiscard]] const PeerHandshakeSha256&
    channel_binding_sha256() const noexcept;

private:
    ConfirmedPeerHandshakeSessionV1() = default;
    void erase() noexcept;
    [[nodiscard]] PeerHandshakeDigestResult create_finished_mac_for_role(
        PeerHandshakeRole role) const noexcept;
    [[nodiscard]] bool verify_finished_mac_for_role(
        PeerHandshakeRole role,
        std::span<const std::byte> candidate_mac,
        PeerHandshakeError& error) const noexcept;

    friend class PlatformP256EphemeralKeyAgreementV1;
    friend class PendingPeerHandshakeConfirmationV1;
#if defined(VFDUAL_ENABLE_AUTHENTICATED_PEER_HANDSHAKE_TEST_ACCESS)
    friend struct AuthenticatedPeerHandshakeV1TestAccess;
#endif

    PeerHandshakeRole local_role_{PeerHandshakeRole::host};
    ConfirmedPeerHandshakeBindingV1 binding_{};
    std::array<std::byte, 36U> control_host_to_android_{};
    std::array<std::byte, 36U> control_android_to_host_{};
    std::array<std::byte, 36U> presence_host_to_android_{};
    std::array<std::byte, 36U> video_host_to_android_{};
    std::array<std::byte, 36U> idr_android_to_host_{};
    std::array<std::byte, 36U> mouse_host_to_android_{};
    std::array<std::byte, 32U> finished_host_{};
    std::array<std::byte, 32U> finished_android_{};
    std::array<std::byte, 32U> channel_binding_exporter_{};
};

struct PeerHandshakeConfirmationResult final {
    std::unique_ptr<ConfirmedPeerHandshakeSessionV1> confirmed_session;
    PeerHandshakeError error;

    /** True only when the peer Finished was verified and keys were released. */
    [[nodiscard]] bool peer_finished_accepted() const noexcept {
        return confirmed_session != nullptr && !error.has_error();
    }
};

/**
 * Key-confirmation gate. This move-only type exposes no traffic material or
 * channel binding. It can emit only this endpoint's Finished and can release
 * a ConfirmedPeerHandshakeSessionV1 only after accepting the peer's Finished.
 * Any failed verification irreversibly closes and zeroizes the pending state.
 */
class PendingPeerHandshakeConfirmationV1 final {
public:
    ~PendingPeerHandshakeConfirmationV1();
    PendingPeerHandshakeConfirmationV1(
        const PendingPeerHandshakeConfirmationV1&) = delete;
    PendingPeerHandshakeConfirmationV1& operator=(
        const PendingPeerHandshakeConfirmationV1&) = delete;
    PendingPeerHandshakeConfirmationV1(
        PendingPeerHandshakeConfirmationV1&& other) noexcept;
    PendingPeerHandshakeConfirmationV1& operator=(
        PendingPeerHandshakeConfirmationV1&& other) noexcept;

    [[nodiscard]] PeerHandshakeRole local_role() const noexcept;
    [[nodiscard]] PeerHandshakeDigestResult
    create_local_finished_mac() noexcept;
    [[nodiscard]] PeerHandshakeConfirmationResult
    confirm_peer_finished_and_consume(
        std::span<const std::byte> peer_finished_mac) && noexcept;

private:
    PendingPeerHandshakeConfirmationV1(
        PeerHandshakeRole local_role,
        std::unique_ptr<ConfirmedPeerHandshakeSessionV1>
            unconfirmed_session) noexcept;
    void close() noexcept;

    friend class PlatformP256EphemeralKeyAgreementV1;
#if defined(VFDUAL_ENABLE_AUTHENTICATED_PEER_HANDSHAKE_TEST_ACCESS)
    friend struct AuthenticatedPeerHandshakeV1TestAccess;
#endif

    PeerHandshakeRole local_role_{PeerHandshakeRole::host};
    std::unique_ptr<ConfirmedPeerHandshakeSessionV1> unconfirmed_session_;
    bool closed_{true};
    bool local_finished_generated_{};
};

/**
 * Platform P-256 ECDH key. The production factory always generates a fresh
 * private key inside BCrypt. There is no public provider-injection or raw
 * private-key import entry point.
 */
class PlatformP256EphemeralKeyAgreementV1 final {
public:
    ~PlatformP256EphemeralKeyAgreementV1();
    PlatformP256EphemeralKeyAgreementV1(
        const PlatformP256EphemeralKeyAgreementV1&) = delete;
    PlatformP256EphemeralKeyAgreementV1& operator=(
        const PlatformP256EphemeralKeyAgreementV1&) = delete;
    PlatformP256EphemeralKeyAgreementV1(
        PlatformP256EphemeralKeyAgreementV1&&) noexcept;
    PlatformP256EphemeralKeyAgreementV1& operator=(
        PlatformP256EphemeralKeyAgreementV1&&) noexcept;

    /** BCrypt on Windows; unsupported platforms fail closed. */
    [[nodiscard]] static std::unique_ptr<
        PlatformP256EphemeralKeyAgreementV1>
    generate_platform(PeerHandshakeError& error) noexcept;

    [[nodiscard]] std::span<
        const std::byte, kPeerHandshakeP256PublicKeyBytes>
    public_key_sec1() const noexcept;

    /**
     * One-shot transition after the caller has verified the peer's long-term
     * identity signature against its independently trusted/bound SPKI. This
     * method does not perform that identity verification itself. On the first
     * call it irreversibly consumes the ephemeral private key before any
     * transcript/peer/provider validation; success and every failure leave the
     * key unusable. A non-empty pair binding is mandatory.
     */
    [[nodiscard]] std::unique_ptr<PendingPeerHandshakeConfirmationV1>
    derive_pending_after_peer_identity_verified(
        PeerHandshakeRole local_role,
        const CanonicalPeerHandshakeTranscriptV1& transcript,
        PeerHandshakeError& error) noexcept;

private:
    struct Impl;

    PlatformP256EphemeralKeyAgreementV1(
        std::unique_ptr<Impl> impl,
        PeerHandshakeP256PublicKey public_key) noexcept;

    /** Only the typed Host transcript signer may perform this freshness gate. */
    [[nodiscard]] bool is_fresh_for_host_transcript_signing(
        PeerHandshakeError& error) const noexcept;

    friend class HostPeerHandshakeTranscriptSignerV1;

#if defined(VFDUAL_ENABLE_AUTHENTICATED_PEER_HANDSHAKE_TEST_ACCESS)
    [[nodiscard]] static std::unique_ptr<
        PlatformP256EphemeralKeyAgreementV1>
    import_test_private_key(
        std::span<const std::byte, 32U> private_scalar_be,
        std::span<const std::byte, kPeerHandshakeP256PublicKeyBytes>
            expected_public_key_sec1,
        PeerHandshakeError& error) noexcept;
    [[nodiscard]] static PeerHandshakeDigestResult derive_test_prk(
        std::span<const std::byte, 32U> shared_secret_be,
        std::span<const std::byte, 32U> transcript_sha256) noexcept;
    [[nodiscard]] PeerHandshakeDigestResult derive_test_shared_secret(
        std::span<const std::byte, kPeerHandshakeP256PublicKeyBytes>
            peer_public_key_sec1) const noexcept;
    [[nodiscard]] static PeerHandshakeError exercise_test_hkdf_expand(
        std::size_t output_bytes) noexcept;
    void invalidate_platform_provider_for_test() noexcept;

    friend struct AuthenticatedPeerHandshakeV1TestAccess;
#endif

    std::unique_ptr<Impl> impl_;
    PeerHandshakeP256PublicKey public_key_{};
    mutable std::mutex mutex_;
};

}  // namespace vfdual
