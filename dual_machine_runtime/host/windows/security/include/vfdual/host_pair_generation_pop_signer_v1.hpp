#pragma once

#include "vfdual/host_cng_device_identity.h"
#include "vfdual/pair_generation_pop_v1.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace vfdual {

/**
 * Server-authoritative fields covered by both peers before a generation
 * proposal exists.  The Host identity hash is deliberately absent and is
 * always read from the current non-exportable HostCngDeviceIdentity.
 */
struct HostPairGenerationChallengeSigningInputV1 final {
    std::string request_id;
    std::string allocation_request_id;
    std::string entitlement_id;
    std::string pair_id;
    std::string binding_id;
    std::uint64_t binding_revision{};
    std::uint64_t revocation_version{};
    PeerHandshakeSha256 android_identity_spki_sha256{};
};

class HostSignedPairGenerationChallengeV1 final {
public:
    HostSignedPairGenerationChallengeV1(
        const HostSignedPairGenerationChallengeV1&) = delete;
    HostSignedPairGenerationChallengeV1& operator=(
        const HostSignedPairGenerationChallengeV1&) = delete;
    HostSignedPairGenerationChallengeV1(
        HostSignedPairGenerationChallengeV1&&) = delete;
    HostSignedPairGenerationChallengeV1& operator=(
        HostSignedPairGenerationChallengeV1&&) = delete;

    [[nodiscard]] const CanonicalPairGenerationChallengeRequestV1&
    request() const noexcept;
    [[nodiscard]] std::span<const std::uint8_t>
    signature_der_low_s() const noexcept;

private:
    HostSignedPairGenerationChallengeV1(
        CanonicalPairGenerationChallengeRequestV1 request,
        std::vector<std::uint8_t> signature_der_low_s) noexcept;

    friend class HostPairGenerationPopSignerV1;

    CanonicalPairGenerationChallengeRequestV1 request_;
    std::vector<std::uint8_t> signature_der_low_s_;
};

struct HostPairGenerationChallengeSigningResultV1 final {
    std::unique_ptr<HostSignedPairGenerationChallengeV1> signed_challenge;
    PairGenerationPopError protocol_error;
    HostIdentityError identity_error;

    [[nodiscard]] bool succeeded() const noexcept {
        return signed_challenge != nullptr && !protocol_error.has_error() &&
            !identity_error.has_error();
    }
};

class HostSignedPairGenerationFinalProofV1 final {
public:
    HostSignedPairGenerationFinalProofV1(
        const HostSignedPairGenerationFinalProofV1&) = delete;
    HostSignedPairGenerationFinalProofV1& operator=(
        const HostSignedPairGenerationFinalProofV1&) = delete;
    HostSignedPairGenerationFinalProofV1(
        HostSignedPairGenerationFinalProofV1&&) = delete;
    HostSignedPairGenerationFinalProofV1& operator=(
        HostSignedPairGenerationFinalProofV1&&) = delete;

    [[nodiscard]] const CanonicalPairGenerationFinalCredentialProofV1&
    proof() const noexcept;
    [[nodiscard]] std::span<const std::uint8_t>
    signature_der_low_s() const noexcept;

private:
    HostSignedPairGenerationFinalProofV1(
        CanonicalPairGenerationFinalCredentialProofV1 proof,
        std::vector<std::uint8_t> signature_der_low_s) noexcept;

    friend class HostPairGenerationPopSignerV1;

    CanonicalPairGenerationFinalCredentialProofV1 proof_;
    std::vector<std::uint8_t> signature_der_low_s_;
};

struct HostPairGenerationFinalSigningResultV1 final {
    std::unique_ptr<HostSignedPairGenerationFinalProofV1> signed_proof;
    PairGenerationPopError protocol_error;
    HostIdentityError identity_error;

    [[nodiscard]] bool succeeded() const noexcept {
        return signed_proof != nullptr && !protocol_error.has_error() &&
            !identity_error.has_error();
    }
};

/**
 * Restricted Host PoP capability.  It exposes no raw-byte or raw-digest
 * signing API.  Both operations rebuild the exact cross-language canonical
 * payload internally, and final proof signing can only continue from a
 * challenge object created by this type.
 */
class HostPairGenerationPopSignerV1 final {
public:
    explicit HostPairGenerationPopSignerV1(
        HostCngDeviceIdentity& identity) noexcept;

    [[nodiscard]] HostPairGenerationChallengeSigningResultV1
    build_and_sign_challenge(
        HostPairGenerationChallengeSigningInputV1 input) noexcept;

    [[nodiscard]] HostPairGenerationFinalSigningResultV1
    build_and_sign_final_credential_proof(
        const HostSignedPairGenerationChallengeV1& signed_challenge,
        std::string challenge_id,
        std::uint64_t challenge_expires_at_epoch,
        std::span<const std::byte, 32U> server_nonce,
        const VerifiedPairGenerationProposalV1& proposal) noexcept;

private:
    HostCngDeviceIdentity& identity_;
};

}  // namespace vfdual
