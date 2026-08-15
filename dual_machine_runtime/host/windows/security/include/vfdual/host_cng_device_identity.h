#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vfdual {

class HostPeerHandshakeTranscriptSignerV1;

/**
 * Host device identity protocol boundary.
 *
 * This module proves possession of a local P-256 key.  It deliberately does
 * not claim TPM attestation, measured boot, server registration, or Android
 * channel wiring.  Formal mode accepts only a non-exportable signing key from
 * the Microsoft Platform Crypto Provider whose CNG implementation reports
 * hardware backing.  Development software keys are a separate, explicitly
 * named policy and every public/signature result labels them non-formal.
 */
inline constexpr std::uint32_t kHostIdentityChallengeProtocolVersion = 1U;
inline constexpr std::string_view kHostIdentityChallengeDomain{
    "visionforge-dual-machine-host-device-challenge-v1"};
inline constexpr std::wstring_view kMicrosoftPlatformCryptoProvider{
    L"Microsoft Platform Crypto Provider"};
inline constexpr std::wstring_view kMicrosoftSoftwareKeyStorageProvider{
    L"Microsoft Software Key Storage Provider"};
inline constexpr std::wstring_view kFormalHostIdentityKeyName{
    L"VisionForge.HostIdentity.P256.Formal.v1"};
inline constexpr std::wstring_view kDevelopmentHostIdentityKeyName{
    L"VisionForge.HostIdentity.P256.Development.v1"};

// Values are the public NCrypt contract flags, repeated here so the policy and
// test adapter do not need to expose Windows headers in this narrow interface.
inline constexpr std::uint32_t kCngAllowSigningFlag = 0x00000002U;
inline constexpr std::uint32_t kCngPrivateExportPolicyMask = 0x0000000fU;
inline constexpr std::uint32_t kCngImplementationHardwareFlag = 0x00000001U;
inline constexpr std::uint32_t kCngImplementationSoftwareFlag = 0x00000002U;
inline constexpr std::uint32_t kCngMachineKeyFlag = 0x00000020U;

enum class HostIdentityPolicyKind : std::uint8_t {
    formal_platform_tpm = 1U,
    development_named_software_provider = 2U,
};

enum class HostIdentityAssurance : std::uint8_t {
    formal_platform_tpm = 1U,
    non_formal_development_software = 2U,
};

enum class HostIdentityChallengeType : std::uint8_t {
    pairing = 1U,
    session_binding = 2U,
    session_rekey = 3U,
};

enum class HostIdentitySignatureEncoding : std::uint8_t {
    ecdsa_p256_sha256_der_low_s = 1U,
};

enum class HostIdentityNativeStatusDomain : std::uint8_t {
    none = 0U,
    ncrypt_security_status = 1U,
    bcrypt_ntstatus = 2U,
};

enum class HostIdentityErrorCode : std::uint8_t {
    none = 0U,
    invalid_policy,
    invalid_challenge,
    provider_open_failed,
    key_open_or_create_failed,
    key_property_write_failed,
    key_finalize_failed,
    key_cleanup_failed,
    key_property_read_failed,
    key_contract_rejected,
    public_key_export_failed,
    public_key_format_rejected,
    signature_format_rejected,
    sha256_failed,
    signature_failed,
    verification_failed,
};

/** Sanitized secondary failure retained when failure cleanup also fails. */
struct HostIdentityCleanupFailure final {
    HostIdentityErrorCode code{HostIdentityErrorCode::none};
    HostIdentityNativeStatusDomain native_domain{
        HostIdentityNativeStatusDomain::none};
    std::uint32_t native_status{};
    std::string operation;

    [[nodiscard]] bool has_error() const noexcept {
        return code != HostIdentityErrorCode::none;
    }
};

/** Sanitized diagnostic. It contains no key bytes or challenge contents. */
struct HostIdentityError final {
    HostIdentityErrorCode code{HostIdentityErrorCode::none};
    HostIdentityNativeStatusDomain native_domain{
        HostIdentityNativeStatusDomain::none};
    std::uint32_t native_status{};
    std::string operation;
    std::optional<HostIdentityCleanupFailure> cleanup_failure;

    [[nodiscard]] bool has_error() const noexcept {
        return code != HostIdentityErrorCode::none;
    }
};

[[nodiscard]] const char* host_identity_error_code_name(
    HostIdentityErrorCode code) noexcept;
[[nodiscard]] const char* host_identity_assurance_name(
    HostIdentityAssurance assurance) noexcept;
[[nodiscard]] std::string format_host_identity_error(
    const HostIdentityError& error);
/** Keep the causal failure primary while attaching a cleanup failure. */
[[nodiscard]] HostIdentityError preserve_host_identity_cleanup_failure(
    HostIdentityError primary,
    const HostIdentityError& cleanup_failure);

/**
 * Policy factories keep formal and development provider selection separate.
 * Formal policy never probes or falls back to a software provider.
 */
class HostIdentityPolicy final {
public:
    [[nodiscard]] static HostIdentityPolicy formal_platform_tpm();
    [[nodiscard]] static HostIdentityPolicy development_named_software_provider(
        std::wstring provider_name);

    [[nodiscard]] HostIdentityPolicyKind kind() const noexcept;
    [[nodiscard]] std::wstring_view provider_name() const noexcept;

private:
    HostIdentityPolicy(
        HostIdentityPolicyKind kind, std::wstring provider_name);

    HostIdentityPolicyKind kind_;
    std::wstring provider_name_;
};

/** Exact inputs covered by the detached host signature. */
struct HostIdentityChallenge final {
    std::uint32_t protocol_version{kHostIdentityChallengeProtocolVersion};
    HostIdentityChallengeType challenge_type{
        HostIdentityChallengeType::pairing};
    std::string host_id;
    std::array<std::uint8_t, 32U> server_nonce{};
    std::array<std::uint8_t, 32U>
        android_peer_ephemeral_public_key_sha256{};
    std::array<std::uint8_t, 32U>
        android_peer_identity_public_key_sha256{};
    std::array<std::uint8_t, 16U> session_id{};
    std::uint64_t epoch{};
};

struct HostIdentityBytesResult final {
    std::vector<std::uint8_t> bytes;
    HostIdentityError error;

    [[nodiscard]] bool succeeded() const noexcept {
        return !error.has_error();
    }
};

/**
 * Canonical format: domain and fields are encoded as ascending tagged TLVs.
 * Each TLV is tag:u8, length:u32-big-endian, value. Integer values are also
 * big-endian. Public-key fingerprint and assurance are signed fields; this
 * prevents label substitution but does not constitute remote attestation.
 */
[[nodiscard]] HostIdentityBytesResult build_host_identity_challenge(
    const HostIdentityChallenge& challenge,
    const std::array<std::uint8_t, 32U>& host_public_key_sha256,
    HostIdentityAssurance untrusted_local_assurance_claim);

struct CngKeyOpenRequest final {
    std::wstring provider_name;
    std::wstring persistent_key_name;
    bool machine_scope{};
};

/** Raw CNG properties used by the policy boundary for fail-closed auditing. */
struct CngKeyMetadata final {
    std::wstring provider_name;
    std::wstring persistent_key_name;
    std::wstring algorithm_name;
    std::wstring algorithm_group_name;
    std::uint32_t key_length_bits{};
    std::uint32_t key_usage{};
    std::uint32_t export_policy{};
    std::uint32_t implementation_type{};
    std::uint32_t key_type{};
};

/**
 * Narrow key interface. It intentionally has no private-key export method.
 * export_public_ecc_blob() returns only BCRYPT_ECCPUBLIC_BLOB.
 */
class CngSigningKey {
public:
    virtual ~CngSigningKey() = default;
    [[nodiscard]] virtual const CngKeyMetadata& metadata() const noexcept = 0;
    [[nodiscard]] virtual HostIdentityBytesResult
    export_public_ecc_blob() = 0;
    /** Returns CNG's fixed-width IEEE P1363 r||s representation. */
    [[nodiscard]] virtual HostIdentityBytesResult sign_sha256_digest(
        std::span<const std::uint8_t> sha256_digest) = 0;
    /**
     * Delete a key created by the current open operation when identity
     * initialization fails before the public identity is published.
     * Existing persisted keys are never passed to this method.
     */
    [[nodiscard]] virtual HostIdentityError
    discard_new_persisted_key_after_failed_initialization() = 0;
};

struct CngKeyOpenResult final {
    std::unique_ptr<CngSigningKey> key;
    HostIdentityError error;
    bool created{};

    [[nodiscard]] bool succeeded() const noexcept {
        return key != nullptr && !error.has_error();
    }
};

class CngKeyStoreAdapter {
public:
    virtual ~CngKeyStoreAdapter() = default;
    [[nodiscard]] virtual CngKeyOpenResult open_or_create_p256_signing_key(
        const CngKeyOpenRequest& request) = 0;
};

/** Pure policy audit; it validates metadata but never mints an identity. */
[[nodiscard]] bool validate_cng_key_metadata_for_policy(
    const HostIdentityPolicy& policy,
    const CngKeyMetadata& metadata,
    HostIdentityError& error);

struct HostPublicIdentity final {
    // This client-originated label is signed to prevent in-transit relabeling,
    // but remains an untrusted claim. Formal authorization must come from a
    // server-owned registration/attestation record for this exact SPKI.
    HostIdentityAssurance untrusted_local_assurance_claim{
        HostIdentityAssurance::non_formal_development_software};
    std::wstring provider_name;
    std::vector<std::uint8_t> subject_public_key_info_der;
    std::array<std::uint8_t, 32U> public_key_sha256{};
    std::string public_key_sha256_hex;

};

struct HostIdentitySignature final {
    HostIdentityAssurance untrusted_local_assurance_claim{
        HostIdentityAssurance::non_formal_development_software};
    HostIdentitySignatureEncoding encoding{
        HostIdentitySignatureEncoding::ecdsa_p256_sha256_der_low_s};
    std::array<std::uint8_t, 32U> public_key_sha256{};
    std::array<std::uint8_t, 32U> challenge_sha256{};
    std::vector<std::uint8_t> canonical_challenge;
    std::vector<std::uint8_t> signature_der;
};

struct HostIdentitySignatureResult final {
    std::optional<HostIdentitySignature> signature;
    HostIdentityError error;

    [[nodiscard]] bool succeeded() const noexcept {
        return signature.has_value() && !error.has_error();
    }
};

struct HostIdentityVerificationResult final {
    // True means only that the supplied SPKI possessed the signing key for the
    // supplied challenge. It never establishes TPM or formal assurance.
    bool proof_of_possession_valid{};
    HostIdentityError error;

    [[nodiscard]] bool completed() const noexcept {
        return !error.has_error();
    }
};

class HostCngDeviceIdentity final {
public:
    ~HostCngDeviceIdentity();
    HostCngDeviceIdentity(HostCngDeviceIdentity&&) noexcept;
    HostCngDeviceIdentity& operator=(HostCngDeviceIdentity&&) noexcept;
    HostCngDeviceIdentity(const HostCngDeviceIdentity&) = delete;
    HostCngDeviceIdentity& operator=(const HostCngDeviceIdentity&) = delete;

    /** Production path using NCrypt/BCrypt. */
    [[nodiscard]] static std::unique_ptr<HostCngDeviceIdentity> open_windows(
        const HostIdentityPolicy& policy, HostIdentityError& error);

    /**
     * Dependency-injected development path. It rejects formal policy before
     * invoking the adapter, so a mock cannot mint formal assurance.
     */
    [[nodiscard]] static std::unique_ptr<HostCngDeviceIdentity>
    open_development_with_adapter(
        const HostIdentityPolicy& policy,
        CngKeyStoreAdapter& adapter,
        HostIdentityError& error);

    [[nodiscard]] const HostPublicIdentity& public_identity() const noexcept;
    [[nodiscard]] HostIdentitySignatureResult sign_challenge(
        const HostIdentityChallenge& challenge);

private:
    HostCngDeviceIdentity(
        std::unique_ptr<CngSigningKey> key,
        HostPublicIdentity public_identity);
    [[nodiscard]] static std::unique_ptr<HostCngDeviceIdentity>
    open_with_trusted_adapter(
        const HostIdentityPolicy& policy,
        CngKeyStoreAdapter& adapter,
        HostIdentityError& error);

    /**
     * Dedicated protocol bridge for the typed peer-handshake signer.  This is
     * intentionally private: callers cannot ask the device identity to sign
     * arbitrary bytes, hashes, or caller-built canonical transcripts.
     */
    [[nodiscard]] HostIdentityBytesResult
    create_peer_handshake_transcript_signature(
        const std::array<std::uint8_t, 32U>& transcript_sha256);

    friend class HostPeerHandshakeTranscriptSignerV1;

    std::unique_ptr<CngSigningKey> key_;
    HostPublicIdentity public_identity_;
};

/**
 * Public-key-only proof-of-possession verifier.
 *
 * The public identity and its assurance label are attacker-supplied at a wire
 * boundary. A server must additionally match the SPKI/fingerprint against its
 * own trusted registration and server-owned assurance/attestation state.
 */
[[nodiscard]] HostIdentityVerificationResult
verify_host_identity_proof_of_possession(
    const HostPublicIdentity& public_identity,
    const HostIdentityChallenge& challenge,
    const HostIdentitySignature& signature);

}  // namespace vfdual
