#pragma once

#include "vfdual/authenticated_control_bootstrap_payload_v1.hpp"
#include "vfdual/authenticated_peer_handshake_v1.hpp"
#include "vfdual/host_device_identity_runtime.hpp"
#include "vfdual/host_pair_generation_credential_verifier_v1.hpp"
#include "vfdual/host_pair_generation_pop_signer_v1.hpp"
#include "vfdual/host_peer_handshake_transcript_signer_v1.hpp"
#include "vfdual/pair_generation_proposal_v1.hpp"

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

inline constexpr std::uint64_t
    kHostAuthenticatedControlHandshakeTimeoutMillisecondsV1 = 60'000U;
inline constexpr std::int64_t
    kHostAuthenticatedControlServerChallengeMaximumTtlSecondsV1 = 30;

/** Wall time is used only for server expiry; monotonic time owns the timeout. */
struct HostAuthenticatedControlTimeV1 final {
    std::int64_t epoch_seconds{};
    std::uint64_t monotonic_milliseconds{};
};

/** Server-authenticated durable pair state supplied by the composition root. */
struct HostAuthenticatedControlPairBindingV1 final {
    std::string entitlement_id;
    std::string pair_id;
    std::string binding_id;
    std::uint64_t binding_revision{};
    std::uint64_t revocation_version{};
    /** Durable local/server high-water mark; zero is valid only before first use. */
    std::uint64_t generation_high_watermark{};
    std::string host_identity_spki_sha256;
    std::string android_identity_spki_sha256;
    std::vector<std::uint8_t> android_subject_public_key_info_der;
};

/** Live socket/direct-link facts; none may be learned from the remote record. */
struct HostAuthenticatedControlRouteV1 final {
    PeerHandshakeTransportKind transport_kind{
        PeerHandshakeTransportKind::cat6};
    std::array<std::byte, 4U> host_ipv4{};
    std::array<std::byte, 4U> android_ipv4{};
    std::uint16_t video_port{};
    std::uint16_t control_port{};
    std::string host_runtime_version;
};

enum class HostAuthenticatedControlErrorCodeV1 : std::uint8_t {
    none = 0U,
    invalid_configuration,
    timed_out,
    unexpected_record,
    peer_aborted,
    pair_binding_mismatch,
    server_authorization_rejected,
    cryptographic_verification_failed,
    allocation_failed,
    closed,
};

/** Sanitized result metadata; never contains record, token, key, or signature. */
struct HostAuthenticatedControlErrorV1 final {
    HostAuthenticatedControlErrorCodeV1 code{
        HostAuthenticatedControlErrorCodeV1::none};

    [[nodiscard]] bool has_error() const noexcept {
        return code != HostAuthenticatedControlErrorCodeV1::none;
    }
};

struct HostAuthenticatedControlRecordResultV1 final {
    std::vector<std::byte> outbound_record;
    HostAuthenticatedControlErrorV1 error;

    [[nodiscard]] bool succeeded() const noexcept {
        return !outbound_record.empty() && !error.has_error();
    }
};

struct HostAuthenticatedControlCompletionResultV1 final {
    std::vector<std::byte> host_finished_record;
    std::unique_ptr<ConfirmedPeerHandshakeSessionV1> confirmed_session;
    std::uint64_t session_generation{};
    HostAuthenticatedControlErrorV1 error;

    [[nodiscard]] bool succeeded() const noexcept {
        return !host_finished_record.empty() && confirmed_session != nullptr &&
            session_generation != 0U && !error.has_error();
    }
};

class HostAuthenticatedControlCoordinatorV1;

struct HostAuthenticatedControlConstructionResultV1 final {
    std::unique_ptr<HostAuthenticatedControlCoordinatorV1> coordinator;
    HostAuthenticatedControlErrorV1 error;

    [[nodiscard]] bool succeeded() const noexcept {
        return coordinator != nullptr && !error.has_error();
    }
};

/** Test-only boundary signature; production construction cannot inject it. */
using HostPairCredentialVerificationTestCallbackV1 = bool (*)(
    void* context,
    std::string_view compact_token_ascii,
    const HostPairGenerationCredentialExpectedV1& expected,
    std::int64_t now_epoch) noexcept;

/**
 * Host owner for the exact nine-record authenticated control bootstrap.
 *
 * The caller must keep HostDeviceIdentityRuntime alive for this owner's whole
 * lifetime. A malformed, repeated, out-of-order, expired, unverifiable, or
 * aborted record permanently burns this instance and its fresh ECDH key.
 * Traffic material is returned only together with the encoded Host Finished
 * after Android identity and Android Finished both verify.
 */
class HostAuthenticatedControlCoordinatorV1 final {
public:
    ~HostAuthenticatedControlCoordinatorV1();
    HostAuthenticatedControlCoordinatorV1(
        const HostAuthenticatedControlCoordinatorV1&) = delete;
    HostAuthenticatedControlCoordinatorV1& operator=(
        const HostAuthenticatedControlCoordinatorV1&) = delete;
    HostAuthenticatedControlCoordinatorV1(
        HostAuthenticatedControlCoordinatorV1&&) = delete;
    HostAuthenticatedControlCoordinatorV1& operator=(
        HostAuthenticatedControlCoordinatorV1&&) = delete;

    /** Production path: build-pinned credential keyring and platform ECDH/RNG. */
    [[nodiscard]] static HostAuthenticatedControlConstructionResultV1 create(
        HostDeviceIdentityRuntime& identity_runtime,
        HostAuthenticatedControlPairBindingV1 expected_pair,
        HostAuthenticatedControlRouteV1 route,
        HostAuthenticatedControlTimeV1 now) noexcept;

#if defined(VFDUAL_ENABLE_HOST_AUTHENTICATED_CONTROL_TEST_ACCESS)
    /** Isolated deterministic seam; absent from every production object. */
    [[nodiscard]] static HostAuthenticatedControlConstructionResultV1
    create_for_test(
        const HostPublicIdentity& host_public_identity,
        HostPairGenerationPopSignerV1& pair_pop_signer,
        HostPeerHandshakeTranscriptSignerV1& transcript_signer,
        HostAuthenticatedControlPairBindingV1 expected_pair,
        HostAuthenticatedControlRouteV1 route,
        HostAuthenticatedControlTimeV1 now,
        std::unique_ptr<PlatformP256EphemeralKeyAgreementV1> host_ephemeral,
        PeerHandshakeNonce host_nonce,
        HostPairCredentialVerificationTestCallbackV1 credential_callback,
        void* credential_callback_context) noexcept;
#endif

    [[nodiscard]] HostAuthenticatedControlRecordResultV1 start(
        HostAuthenticatedControlTimeV1 now) noexcept;
    [[nodiscard]] HostAuthenticatedControlRecordResultV1
    accept_android_challenge_request(
        std::span<const std::byte> encoded_record,
        HostAuthenticatedControlTimeV1 now) noexcept;
    [[nodiscard]] HostAuthenticatedControlRecordResultV1
    accept_server_challenge(
        std::span<const std::byte> encoded_record,
        HostAuthenticatedControlTimeV1 now) noexcept;
    [[nodiscard]] HostAuthenticatedControlRecordResultV1
    accept_pair_generation_credential(
        std::span<const std::byte> encoded_record,
        HostAuthenticatedControlTimeV1 now) noexcept;
    [[nodiscard]] HostAuthenticatedControlCompletionResultV1
    accept_android_handshake_confirmation(
        std::span<const std::byte> encoded_record,
        HostAuthenticatedControlTimeV1 now) noexcept;

    void close() noexcept;
    [[nodiscard]] bool is_closed() const noexcept;
    [[nodiscard]] bool is_completed() const noexcept;
    [[nodiscard]] std::size_t accepted_event_count() const noexcept;

private:
    HostAuthenticatedControlCoordinatorV1(
        const HostPublicIdentity& host_public_identity,
        HostPairGenerationPopSignerV1& pair_pop_signer,
        HostPeerHandshakeTranscriptSignerV1& transcript_signer,
        HostAuthenticatedControlPairBindingV1 expected_pair,
        HostAuthenticatedControlRouteV1 route,
        HostAuthenticatedControlTimeV1 created_at,
        std::unique_ptr<PlatformP256EphemeralKeyAgreementV1> host_ephemeral,
        PeerHandshakeNonce host_nonce,
        std::unique_ptr<HostPairGenerationCredentialV1Verifier>
            credential_verifier,
        HostPairCredentialVerificationTestCallbackV1 credential_callback,
        void* credential_callback_context) noexcept;

    [[nodiscard]] static HostAuthenticatedControlConstructionResultV1
    create_internal(
        const HostPublicIdentity& host_public_identity,
        HostPairGenerationPopSignerV1& pair_pop_signer,
        HostPeerHandshakeTranscriptSignerV1& transcript_signer,
        HostAuthenticatedControlPairBindingV1 expected_pair,
        HostAuthenticatedControlRouteV1 route,
        HostAuthenticatedControlTimeV1 now,
        std::unique_ptr<PlatformP256EphemeralKeyAgreementV1> host_ephemeral,
        PeerHandshakeNonce host_nonce,
        std::unique_ptr<HostPairGenerationCredentialV1Verifier>
            credential_verifier,
        HostPairCredentialVerificationTestCallbackV1 credential_callback,
        void* credential_callback_context) noexcept;

    [[nodiscard]] bool time_is_valid_locked(
        HostAuthenticatedControlTimeV1 now) noexcept;
    [[nodiscard]] bool verify_pair_credential_locked(
        std::string_view compact_token_ascii,
        const HostPairGenerationCredentialExpectedV1& expected,
        std::int64_t now_epoch) noexcept;
    void burn_locked(HostAuthenticatedControlErrorCodeV1 code) noexcept;
    void erase_state_locked() noexcept;

    const HostPublicIdentity* host_public_identity_{};
    HostPairGenerationPopSignerV1* pair_pop_signer_{};
    HostPeerHandshakeTranscriptSignerV1* transcript_signer_{};
    HostAuthenticatedControlPairBindingV1 expected_pair_;
    HostAuthenticatedControlRouteV1 route_;
    HostAuthenticatedControlTimeV1 created_at_{};
    ControlBootstrapSequenceV1 sequence_{ControlBootstrapRoleV1::host};
    std::unique_ptr<PlatformP256EphemeralKeyAgreementV1> host_ephemeral_;
    PeerHandshakeNonce host_nonce_{};
    PeerHandshakeSha256 android_identity_spki_sha256_{};
    std::unique_ptr<HostPairGenerationCredentialV1Verifier>
        credential_verifier_;
    HostPairCredentialVerificationTestCallbackV1 credential_callback_{};
    void* credential_callback_context_{};

    PeerHandshakeP256PublicKey android_ephemeral_public_key_{};
    PeerHandshakeNonce android_nonce_{};
    std::string android_runtime_version_;
    std::unique_ptr<HostSignedPairGenerationChallengeV1> signed_challenge_;
    std::optional<VerifiedPairGenerationProposalV1> proposal_;
    std::unique_ptr<HostSignedPeerHandshakeContextV1> signed_context_;
    bool started_{};
    bool closed_{};
    bool completed_{};
    mutable std::mutex mutex_;
};

[[nodiscard]] const char* host_authenticated_control_error_code_name_v1(
    HostAuthenticatedControlErrorCodeV1 code) noexcept;

}  // namespace vfdual
