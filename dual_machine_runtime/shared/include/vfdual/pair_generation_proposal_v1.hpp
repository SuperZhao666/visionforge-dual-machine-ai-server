#pragma once

#include "vfdual/authenticated_peer_handshake_v1.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vfdual {

inline constexpr std::uint32_t kPairGenerationProposalVersion = 1U;
inline constexpr std::size_t kPairGenerationProposalFieldCount = 17U;
inline constexpr std::size_t kPairGenerationProposalPairIdBytes = 32U;
inline constexpr std::size_t kPairGenerationProposalMaximumCanonicalBytes =
    503U;
inline constexpr std::uint64_t kPairGenerationProposalSigned64Maximum =
    0x7fff'ffff'ffff'ffffULL;
inline constexpr std::string_view kPairGenerationProposalDomain{
    "visionforge-peer-generation-proposal-v1"};

enum class PairGenerationProposalErrorCode : std::uint8_t {
    none = 0U,
    allocation_failed,
    proposal_too_large,
    truncated_tlv,
    unknown_tag,
    duplicate_tag,
    out_of_order_tag,
    missing_field,
    trailing_data,
    noncanonical_encoding,
    invalid_field_length,
    invalid_domain,
    unsupported_version,
    invalid_identity_binding,
    invalid_ephemeral_public_key,
    invalid_nonce,
    invalid_connection_id,
    invalid_transport_kind,
    invalid_endpoint,
    invalid_pair_id,
    invalid_runtime_version,
    invalid_generation,
    crypto_unavailable,
    operation_failed,
};

/** Sanitized failure metadata containing no raw proposal or provider cause. */
struct PairGenerationProposalError final {
    PairGenerationProposalErrorCode code{
        PairGenerationProposalErrorCode::none};
    std::uint8_t field_tag{0xffU};

    [[nodiscard]] bool has_error() const noexcept {
        return code != PairGenerationProposalErrorCode::none;
    }
};

[[nodiscard]] const char* pair_generation_proposal_error_code_name(
    PairGenerationProposalErrorCode code) noexcept;

/**
 * Caller-owned values; the verified owner always takes defensive copies.
 * Production coordination must source connection_id from a non-zero 63-bit
 * CSPRNG or both fresh nonces plus a server challenge, endpoints from the live
 * socket/direct-link context, and pair_id from the active server binding. This
 * foundation validates representations but does not prove those authorities.
 */
struct PairGenerationProposalFields final {
    PeerHandshakeSha256 host_identity_spki_sha256{};
    PeerHandshakeSha256 android_identity_spki_sha256{};
    PeerHandshakeP256PublicKey host_ephemeral_public_key{};
    PeerHandshakeP256PublicKey android_ephemeral_public_key{};
    PeerHandshakeNonce host_nonce{};
    PeerHandshakeNonce android_nonce{};
    std::uint64_t connection_id{};
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

struct PairGenerationProposalResult;

/** Strictly validated immutable owner for the canonical 17-field proposal. */
class VerifiedPairGenerationProposalV1 final {
public:
    VerifiedPairGenerationProposalV1(
        const VerifiedPairGenerationProposalV1&) = default;
    VerifiedPairGenerationProposalV1& operator=(
        const VerifiedPairGenerationProposalV1&) = default;
    VerifiedPairGenerationProposalV1(
        VerifiedPairGenerationProposalV1&&) noexcept = default;
    VerifiedPairGenerationProposalV1& operator=(
        VerifiedPairGenerationProposalV1&&) noexcept = default;

    [[nodiscard]] const PairGenerationProposalFields& fields() const noexcept;
    [[nodiscard]] std::span<const std::byte> canonical_bytes() const noexcept;
    [[nodiscard]] const PeerHandshakeSha256& proposal_sha256() const noexcept;

private:
    VerifiedPairGenerationProposalV1(
        PairGenerationProposalFields fields,
        std::vector<std::byte> canonical_bytes,
        PeerHandshakeSha256 proposal_sha256);

    friend struct PairGenerationProposalResult;
    friend PairGenerationProposalResult build_pair_generation_proposal_v1(
        const PairGenerationProposalFields&) noexcept;
    friend PairGenerationProposalResult parse_pair_generation_proposal_v1(
        std::span<const std::byte>) noexcept;

    PairGenerationProposalFields fields_;
    std::vector<std::byte> canonical_bytes_;
    PeerHandshakeSha256 proposal_sha256_{};
};

struct PairGenerationProposalResult final {
    std::optional<VerifiedPairGenerationProposalV1> proposal;
    PairGenerationProposalError error;

    [[nodiscard]] bool succeeded() const noexcept {
        return proposal.has_value() && !error.has_error();
    }
};

[[nodiscard]] PairGenerationProposalResult build_pair_generation_proposal_v1(
    const PairGenerationProposalFields& fields) noexcept;

[[nodiscard]] PairGenerationProposalResult parse_pair_generation_proposal_v1(
    std::span<const std::byte> canonical_bytes) noexcept;

/**
 * Inserts only the server-authoritative positive signed-64 generation into the
 * existing final 18-field transcript. Every other field is copied from the
 * verified proposal and revalidated by the existing handshake builder.
 */
[[nodiscard]] PeerHandshakeTranscriptResult
build_final_peer_handshake_transcript_from_proposal_v1(
    const VerifiedPairGenerationProposalV1& proposal,
    std::int64_t generation) noexcept;

}  // namespace vfdual
