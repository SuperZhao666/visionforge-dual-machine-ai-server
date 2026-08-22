#pragma once

#include "vfdual/pair_generation_proposal_v1.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vfdual {

inline constexpr std::uint32_t kPairGenerationPopProtocolVersion = 2U;
inline constexpr std::uint32_t kPairGenerationPopProposalVersion = 1U;
inline constexpr std::uint64_t kPairGenerationPopSigned64Maximum =
    0x7fff'ffff'ffff'ffffULL;
inline constexpr std::string_view kPairGenerationChallengeRequestDomain{
    "visionforge-pair-generation-challenge-request-v1"};
inline constexpr std::string_view kPairGenerationFinalCredentialProofDomain{
    "visionforge-pair-generation-final-credential-proof-v1"};
inline constexpr std::string_view kPairGenerationConnectionIdDomain{
    "visionforge-pair-generation-connection-id-derivation-v1"};

enum class PairGenerationPopErrorCode : std::uint8_t {
    none = 0U,
    allocation_failed,
    request_invalid,
    identifier_invalid,
    identity_hash_invalid,
    identity_roles_invalid,
    signed64_invalid,
    nonce_invalid,
    nonce_roles_invalid,
    proposal_invalid,
    proposal_binding_invalid,
    request_integrity_invalid,
    connection_id_zero,
    connection_id_mismatch,
    crypto_unavailable,
    crypto_operation_failed,
};

struct PairGenerationPopError final {
    PairGenerationPopErrorCode code{PairGenerationPopErrorCode::none};

    [[nodiscard]] bool has_error() const noexcept {
        return code != PairGenerationPopErrorCode::none;
    }
};

[[nodiscard]] const char* pair_generation_pop_error_code_name(
    PairGenerationPopErrorCode code) noexcept;

struct PairGenerationChallengeFieldsV1 final {
    std::string request_id;
    std::string allocation_request_id;
    std::string entitlement_id;
    std::string pair_id;
    std::string binding_id;
    std::uint64_t binding_revision{};
    std::uint64_t revocation_version{};
    PeerHandshakeSha256 host_identity_spki_sha256{};
    PeerHandshakeSha256 android_identity_spki_sha256{};
};

struct PairGenerationChallengeResultV1;

class CanonicalPairGenerationChallengeRequestV1 final {
public:
    CanonicalPairGenerationChallengeRequestV1(
        const CanonicalPairGenerationChallengeRequestV1&) = default;
    CanonicalPairGenerationChallengeRequestV1& operator=(
        const CanonicalPairGenerationChallengeRequestV1&) = default;
    CanonicalPairGenerationChallengeRequestV1(
        CanonicalPairGenerationChallengeRequestV1&&) noexcept = default;
    CanonicalPairGenerationChallengeRequestV1& operator=(
        CanonicalPairGenerationChallengeRequestV1&&) noexcept = default;

    [[nodiscard]] const PairGenerationChallengeFieldsV1& fields() const noexcept;
    [[nodiscard]] std::span<const std::byte> canonical_bytes() const noexcept;
    [[nodiscard]] const PeerHandshakeSha256& payload_sha256() const noexcept;

private:
    CanonicalPairGenerationChallengeRequestV1(
        PairGenerationChallengeFieldsV1 fields,
        std::vector<std::byte> canonical_bytes,
        PeerHandshakeSha256 payload_sha256);

    friend struct PairGenerationChallengeResultV1;
    friend PairGenerationChallengeResultV1
    build_pair_generation_challenge_request_v1(
        const PairGenerationChallengeFieldsV1&) noexcept;

    PairGenerationChallengeFieldsV1 fields_;
    std::vector<std::byte> canonical_bytes_;
    PeerHandshakeSha256 payload_sha256_{};
};

struct PairGenerationChallengeResultV1 final {
    std::optional<CanonicalPairGenerationChallengeRequestV1> request;
    PairGenerationPopError error;

    [[nodiscard]] bool succeeded() const noexcept {
        return request.has_value() && !error.has_error();
    }
};

[[nodiscard]] PairGenerationChallengeResultV1
build_pair_generation_challenge_request_v1(
    const PairGenerationChallengeFieldsV1& fields) noexcept;

struct PairGenerationConnectionIdResultV1 final {
    std::uint64_t connection_id{};
    PairGenerationPopError error;

    [[nodiscard]] bool succeeded() const noexcept {
        return connection_id != 0U && !error.has_error();
    }
};

[[nodiscard]] PairGenerationConnectionIdResultV1
derive_pair_generation_connection_id_v1(
    std::span<const std::byte, 32U> server_nonce,
    std::string_view challenge_id,
    std::span<const std::byte, 32U> host_nonce,
    std::span<const std::byte, 32U> android_nonce,
    std::string_view pair_id,
    const PeerHandshakeSha256& host_identity_spki_sha256,
    const PeerHandshakeSha256& android_identity_spki_sha256) noexcept;

struct PairGenerationFinalProofResultV1;

class CanonicalPairGenerationFinalCredentialProofV1 final {
public:
    CanonicalPairGenerationFinalCredentialProofV1(
        const CanonicalPairGenerationFinalCredentialProofV1&) = default;
    CanonicalPairGenerationFinalCredentialProofV1& operator=(
        const CanonicalPairGenerationFinalCredentialProofV1&) = default;
    CanonicalPairGenerationFinalCredentialProofV1(
        CanonicalPairGenerationFinalCredentialProofV1&&) noexcept = default;
    CanonicalPairGenerationFinalCredentialProofV1& operator=(
        CanonicalPairGenerationFinalCredentialProofV1&&) noexcept = default;

    [[nodiscard]] const CanonicalPairGenerationChallengeRequestV1&
    challenge_request() const noexcept;
    [[nodiscard]] std::string_view challenge_id() const noexcept;
    [[nodiscard]] std::uint64_t challenge_expires_at_epoch() const noexcept;
    [[nodiscard]] std::uint64_t connection_id() const noexcept;
    [[nodiscard]] const PeerHandshakeSha256&
    transcript_proposal_sha256() const noexcept;
    [[nodiscard]] std::span<const std::byte> canonical_bytes() const noexcept;
    [[nodiscard]] const PeerHandshakeSha256& payload_sha256() const noexcept;

private:
    CanonicalPairGenerationFinalCredentialProofV1(
        CanonicalPairGenerationChallengeRequestV1 challenge_request,
        std::string challenge_id,
        std::uint64_t challenge_expires_at_epoch,
        std::uint64_t connection_id,
        PeerHandshakeSha256 transcript_proposal_sha256,
        std::vector<std::byte> canonical_bytes,
        PeerHandshakeSha256 payload_sha256);

    friend struct PairGenerationFinalProofResultV1;
    friend PairGenerationFinalProofResultV1
    build_pair_generation_final_credential_proof_v1(
        const CanonicalPairGenerationChallengeRequestV1&,
        std::string_view,
        std::uint64_t,
        std::span<const std::byte, 32U>,
        const VerifiedPairGenerationProposalV1&) noexcept;

    CanonicalPairGenerationChallengeRequestV1 challenge_request_;
    std::string challenge_id_;
    std::uint64_t challenge_expires_at_epoch_{};
    std::uint64_t connection_id_{};
    PeerHandshakeSha256 transcript_proposal_sha256_{};
    std::vector<std::byte> canonical_bytes_;
    PeerHandshakeSha256 payload_sha256_{};
};

struct PairGenerationFinalProofResultV1 final {
    std::optional<CanonicalPairGenerationFinalCredentialProofV1> proof;
    PairGenerationPopError error;

    [[nodiscard]] bool succeeded() const noexcept {
        return proof.has_value() && !error.has_error();
    }
};

[[nodiscard]] PairGenerationFinalProofResultV1
build_pair_generation_final_credential_proof_v1(
    const CanonicalPairGenerationChallengeRequestV1& challenge_request,
    std::string_view challenge_id,
    std::uint64_t challenge_expires_at_epoch,
    std::span<const std::byte, 32U> server_nonce,
    const VerifiedPairGenerationProposalV1& proposal) noexcept;

}  // namespace vfdual
