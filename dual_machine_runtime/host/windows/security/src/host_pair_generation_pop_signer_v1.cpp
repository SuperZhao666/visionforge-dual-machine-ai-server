#include "vfdual/host_pair_generation_pop_signer_v1.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <new>
#include <utility>

namespace vfdual {
namespace {

[[nodiscard]] PeerHandshakeSha256 identity_hash_as_bytes(
    const std::array<std::uint8_t, 32U>& identity_hash) noexcept {
    PeerHandshakeSha256 result{};
    std::transform(
        identity_hash.begin(),
        identity_hash.end(),
        result.begin(),
        [](const std::uint8_t value) { return std::byte{value}; });
    return result;
}

[[nodiscard]] std::array<std::uint8_t, 32U> digest_as_uint8(
    const PeerHandshakeSha256& digest) noexcept {
    std::array<std::uint8_t, 32U> result{};
    std::transform(
        digest.begin(), digest.end(), result.begin(), [](const std::byte value) {
            return std::to_integer<std::uint8_t>(value);
        });
    return result;
}

[[nodiscard]] PairGenerationPopError allocation_error() noexcept {
    return {.code = PairGenerationPopErrorCode::allocation_failed};
}

[[nodiscard]] PairGenerationPopError operation_error() noexcept {
    return {.code = PairGenerationPopErrorCode::request_invalid};
}

}  // namespace

HostSignedPairGenerationChallengeV1::
HostSignedPairGenerationChallengeV1(
    CanonicalPairGenerationChallengeRequestV1 request,
    std::vector<std::uint8_t> signature_der_low_s) noexcept
    : request_(std::move(request)),
      signature_der_low_s_(std::move(signature_der_low_s)) {}

const CanonicalPairGenerationChallengeRequestV1&
HostSignedPairGenerationChallengeV1::request() const noexcept {
    return request_;
}

std::span<const std::uint8_t>
HostSignedPairGenerationChallengeV1::signature_der_low_s() const noexcept {
    return signature_der_low_s_;
}

HostSignedPairGenerationFinalProofV1::
HostSignedPairGenerationFinalProofV1(
    CanonicalPairGenerationFinalCredentialProofV1 proof,
    std::vector<std::uint8_t> signature_der_low_s) noexcept
    : proof_(std::move(proof)),
      signature_der_low_s_(std::move(signature_der_low_s)) {}

const CanonicalPairGenerationFinalCredentialProofV1&
HostSignedPairGenerationFinalProofV1::proof() const noexcept {
    return proof_;
}

std::span<const std::uint8_t>
HostSignedPairGenerationFinalProofV1::signature_der_low_s() const noexcept {
    return signature_der_low_s_;
}

HostPairGenerationPopSignerV1::HostPairGenerationPopSignerV1(
    HostCngDeviceIdentity& identity) noexcept
    : identity_(identity) {}

HostPairGenerationChallengeSigningResultV1
HostPairGenerationPopSignerV1::build_and_sign_challenge(
    HostPairGenerationChallengeSigningInputV1 input) noexcept {
    try {
        PairGenerationChallengeFieldsV1 fields{
            .request_id = std::move(input.request_id),
            .allocation_request_id =
                std::move(input.allocation_request_id),
            .entitlement_id = std::move(input.entitlement_id),
            .pair_id = std::move(input.pair_id),
            .binding_id = std::move(input.binding_id),
            .binding_revision = input.binding_revision,
            .revocation_version = input.revocation_version,
            .host_identity_spki_sha256 = identity_hash_as_bytes(
                identity_.public_identity().public_key_sha256),
            .android_identity_spki_sha256 =
                input.android_identity_spki_sha256,
        };
        PairGenerationChallengeResultV1 built =
            build_pair_generation_challenge_request_v1(fields);
        if (!built.succeeded()) {
            return {nullptr, built.error, {}};
        }
        const auto digest = digest_as_uint8(
            built.request->payload_sha256());
        HostIdentityBytesResult signature =
            identity_.create_pair_generation_pop_signature(digest);
        if (!signature.succeeded()) {
            return {nullptr, {}, std::move(signature.error)};
        }
        auto signed_challenge =
            std::unique_ptr<HostSignedPairGenerationChallengeV1>(
                new HostSignedPairGenerationChallengeV1(
                    std::move(*built.request),
                    std::move(signature.bytes)));
        return {std::move(signed_challenge), {}, {}};
    } catch (const std::bad_alloc&) {
        return {nullptr, allocation_error(), {}};
    } catch (...) {
        return {nullptr, operation_error(), {}};
    }
}

HostPairGenerationFinalSigningResultV1
HostPairGenerationPopSignerV1::build_and_sign_final_credential_proof(
    const HostSignedPairGenerationChallengeV1& signed_challenge,
    std::string challenge_id,
    const std::uint64_t challenge_expires_at_epoch,
    const std::span<const std::byte, 32U> server_nonce,
    const VerifiedPairGenerationProposalV1& proposal) noexcept {
    try {
        PairGenerationFinalProofResultV1 built =
            build_pair_generation_final_credential_proof_v1(
                signed_challenge.request(),
                challenge_id,
                challenge_expires_at_epoch,
                server_nonce,
                proposal);
        if (!built.succeeded()) {
            return {nullptr, built.error, {}};
        }
        const auto digest = digest_as_uint8(
            built.proof->payload_sha256());
        HostIdentityBytesResult signature =
            identity_.create_pair_generation_pop_signature(digest);
        if (!signature.succeeded()) {
            return {nullptr, {}, std::move(signature.error)};
        }
        auto signed_proof =
            std::unique_ptr<HostSignedPairGenerationFinalProofV1>(
                new HostSignedPairGenerationFinalProofV1(
                    std::move(*built.proof),
                    std::move(signature.bytes)));
        return {std::move(signed_proof), {}, {}};
    } catch (const std::bad_alloc&) {
        return {nullptr, allocation_error(), {}};
    } catch (...) {
        return {nullptr, operation_error(), {}};
    }
}

}  // namespace vfdual
