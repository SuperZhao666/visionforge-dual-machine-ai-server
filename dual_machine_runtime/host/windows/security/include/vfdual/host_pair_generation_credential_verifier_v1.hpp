#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace vfdual {

inline constexpr std::string_view kPairGenerationCredentialTypeV1{
    "vf-dual-machine-pair-generation-credential-v1"};
inline constexpr std::string_view kPairGenerationCredentialIssuerV1{
    "visionforge-dual-machine-service"};
inline constexpr std::string_view kPairGenerationCredentialAudienceV1{
    "visionforge-dual-machine-peer-handshake-v1"};
inline constexpr std::size_t kPairGenerationCredentialMaximumTokenBytesV1 =
    8192U;
inline constexpr std::int64_t kPairGenerationCredentialMaximumTtlSecondsV1 =
    30;
inline constexpr std::int64_t
    kPairGenerationCredentialMaximumFutureSecondsV1 = 2;

enum class HostPairGenerationCredentialErrorCodeV1 : std::uint8_t {
    none = 0U,
    key_invalid,
    source_invalid,
    token_invalid,
    crypto_unavailable,
    allocation_failed,
    operation_failed,
};

/** Sanitized failure metadata. It never retains token, key, claim, or path. */
struct HostPairGenerationCredentialErrorV1 final {
    HostPairGenerationCredentialErrorCodeV1 code{
        HostPairGenerationCredentialErrorCodeV1::none};

    [[nodiscard]] bool has_error() const noexcept {
        return code != HostPairGenerationCredentialErrorCodeV1::none;
    }
};

[[nodiscard]] const char* host_pair_generation_credential_error_code_name_v1(
    HostPairGenerationCredentialErrorCodeV1 code) noexcept;

/**
 * Authoritative allocation context expected by one operation-boundary check.
 *
 * The verifier validates and defensively copies every value. The caller must
 * source this context from already-authenticated, durable pair state; token
 * claims are never allowed to become their own authority.
 */
struct HostPairGenerationCredentialExpectedV1 final {
    std::string allocation_request_id;
    std::string pair_id;
    std::string entitlement_id;
    std::string binding_id;
    std::int64_t binding_revision{};
    std::int64_t revocation_version{};
    std::int64_t generation{};
    std::int64_t connection_id{};
    std::string host_identity_spki_sha256;
    std::string android_identity_spki_sha256;
    std::string transcript_proposal_sha256;
};

/** Immutable typed result created only after strict envelope verification. */
class VerifiedHostPairGenerationCredentialV1 final {
public:
    VerifiedHostPairGenerationCredentialV1(
        const VerifiedHostPairGenerationCredentialV1&) noexcept = default;
    VerifiedHostPairGenerationCredentialV1& operator=(
        const VerifiedHostPairGenerationCredentialV1&) noexcept = default;
    VerifiedHostPairGenerationCredentialV1(
        VerifiedHostPairGenerationCredentialV1&& other) noexcept
        : claims_(other.claims_) {}
    VerifiedHostPairGenerationCredentialV1& operator=(
        VerifiedHostPairGenerationCredentialV1&& other) noexcept {
        claims_ = other.claims_;
        return *this;
    }
    ~VerifiedHostPairGenerationCredentialV1() = default;

    [[nodiscard]] const std::string& key_id() const noexcept;
    [[nodiscard]] const std::string& allocation_request_id() const noexcept;
    [[nodiscard]] const std::string& pair_id() const noexcept;
    [[nodiscard]] const std::string& entitlement_id() const noexcept;
    [[nodiscard]] const std::string& binding_id() const noexcept;
    [[nodiscard]] std::int64_t binding_revision() const noexcept;
    [[nodiscard]] std::int64_t revocation_version() const noexcept;
    [[nodiscard]] std::int64_t generation() const noexcept;
    [[nodiscard]] std::int64_t connection_id() const noexcept;
    [[nodiscard]] const std::string& host_identity_spki_sha256()
        const noexcept;
    [[nodiscard]] const std::string& android_identity_spki_sha256()
        const noexcept;
    [[nodiscard]] const std::string& transcript_proposal_sha256()
        const noexcept;
    [[nodiscard]] const std::string& credential_nonce() const noexcept;
    [[nodiscard]] std::int64_t issued_at_epoch() const noexcept;
    [[nodiscard]] std::int64_t not_before_epoch() const noexcept;
    [[nodiscard]] std::int64_t expires_at_epoch() const noexcept;
    [[nodiscard]] const std::array<std::uint8_t, 32U>& token_sha256()
        const noexcept;

private:
    struct Claims;

    explicit VerifiedHostPairGenerationCredentialV1(
        std::shared_ptr<const Claims> claims) noexcept;

    friend class HostPairGenerationCredentialV1Verifier;

    std::shared_ptr<const Claims> claims_;
};

struct HostPairGenerationCredentialVerificationResultV1 final {
    std::optional<VerifiedHostPairGenerationCredentialV1> credential;
    HostPairGenerationCredentialErrorV1 error;

    [[nodiscard]] bool succeeded() const noexcept {
        return credential.has_value() && !error.has_error();
    }
};

class HostPairGenerationCredentialV1Verifier;

struct HostPairGenerationCredentialV1VerifierConstructionResult final {
    std::unique_ptr<HostPairGenerationCredentialV1Verifier> verifier;
    HostPairGenerationCredentialErrorV1 error;

    [[nodiscard]] bool succeeded() const noexcept {
        return verifier != nullptr && !error.has_error();
    }
};

#if defined(VFDUAL_ENABLE_HOST_PAIR_CREDENTIAL_TEST_ACCESS)
/** Runtime-generated public material exposed only to the isolated test build. */
struct HostPairGenerationCredentialTestPublicKeyV1 final {
    std::span<const std::uint8_t> canonical_spki_der;
};
#endif

/**
 * Strict Windows RS256 verifier for a bounded, build-pinned rotation ring.
 *
 * The production factory deliberately accepts no key bytes, path, registry
 * name, network response, environment variable, or generic configuration.
 * Formal release composition must compile the approved public ring into this
 * target. Until that composition exists the factory fails closed. Tests use a
 * separately compiled, macro-gated fixture factory and never link its object
 * code into VisionForgeHost.
 */
class HostPairGenerationCredentialV1Verifier final {
public:
    ~HostPairGenerationCredentialV1Verifier();
    HostPairGenerationCredentialV1Verifier(
        const HostPairGenerationCredentialV1Verifier&) = delete;
    HostPairGenerationCredentialV1Verifier& operator=(
        const HostPairGenerationCredentialV1Verifier&) = delete;
    HostPairGenerationCredentialV1Verifier(
        HostPairGenerationCredentialV1Verifier&&) = delete;
    HostPairGenerationCredentialV1Verifier& operator=(
        HostPairGenerationCredentialV1Verifier&&) = delete;

    [[nodiscard]] static
    HostPairGenerationCredentialV1VerifierConstructionResult
    create_from_build_pinned_keyring() noexcept;

#if defined(VFDUAL_ENABLE_HOST_PAIR_CREDENTIAL_TEST_ACCESS)
    [[nodiscard]] static
    HostPairGenerationCredentialV1VerifierConstructionResult
    create_for_test_fixture_keyring(
        std::span<const HostPairGenerationCredentialTestPublicKeyV1>
            pair_credential_keys,
        std::span<const HostPairGenerationCredentialTestPublicKeyV1>
            other_purpose_keys) noexcept;
#endif

    [[nodiscard]] HostPairGenerationCredentialVerificationResultV1 verify(
        std::string_view compact_token_ascii,
        const HostPairGenerationCredentialExpectedV1& expected,
        std::int64_t now_epoch) const noexcept;

private:
    struct Implementation;

    [[nodiscard]] static
    HostPairGenerationCredentialV1VerifierConstructionResult
    create_from_canonical_spki_der_for_internal_use(
        std::span<const std::span<const std::uint8_t>>
            pair_credential_keys,
        std::span<const std::span<const std::uint8_t>>
            other_purpose_keys) noexcept;

    explicit HostPairGenerationCredentialV1Verifier(
        std::unique_ptr<Implementation> implementation) noexcept;

    std::unique_ptr<Implementation> implementation_;
};

}  // namespace vfdual
