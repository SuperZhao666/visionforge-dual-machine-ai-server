#include "vfdual/pair_generation_pop_v1.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#endif

namespace vfdual {
namespace {

constexpr std::size_t kIdentifierCharacters = 32U;
constexpr std::size_t kSha256Bytes = 32U;

[[nodiscard]] PairGenerationPopError pop_error(
    const PairGenerationPopErrorCode code) noexcept {
    return {.code = code};
}

[[nodiscard]] bool contains_nonzero(
    const std::span<const std::byte> value) noexcept {
    return std::any_of(value.begin(), value.end(), [](const std::byte byte) {
        return byte != std::byte{0U};
    });
}

[[nodiscard]] bool lower_hex_identifier_valid(
    const std::string_view value) noexcept {
    return value.size() == kIdentifierCharacters &&
        std::any_of(value.begin(), value.end(), [](const char value) {
            return value != '0';
        }) &&
        std::all_of(value.begin(), value.end(), [](const char value) {
            return (value >= '0' && value <= '9') ||
                (value >= 'a' && value <= 'f');
        });
}

[[nodiscard]] bool positive_signed64(const std::uint64_t value) noexcept {
    return value != 0U && value <= kPairGenerationPopSigned64Maximum;
}

[[nodiscard]] PairGenerationPopError validate_identity_hashes(
    const PeerHandshakeSha256& host_identity,
    const PeerHandshakeSha256& android_identity) noexcept {
    if (!contains_nonzero(host_identity) ||
        !contains_nonzero(android_identity)) {
        return pop_error(PairGenerationPopErrorCode::identity_hash_invalid);
    }
    if (host_identity == android_identity) {
        return pop_error(PairGenerationPopErrorCode::identity_roles_invalid);
    }
    return {};
}

[[nodiscard]] PairGenerationPopError validate_challenge_fields(
    const PairGenerationChallengeFieldsV1& fields) noexcept {
    if (!lower_hex_identifier_valid(fields.request_id) ||
        !lower_hex_identifier_valid(fields.allocation_request_id) ||
        !lower_hex_identifier_valid(fields.entitlement_id) ||
        !lower_hex_identifier_valid(fields.pair_id) ||
        !lower_hex_identifier_valid(fields.binding_id)) {
        return pop_error(PairGenerationPopErrorCode::identifier_invalid);
    }
    if (!positive_signed64(fields.binding_revision) ||
        !positive_signed64(fields.revocation_version)) {
        return pop_error(PairGenerationPopErrorCode::signed64_invalid);
    }
    return validate_identity_hashes(
        fields.host_identity_spki_sha256,
        fields.android_identity_spki_sha256);
}

[[nodiscard]] char nibble_hex(const std::uint8_t value) noexcept {
    return value < 10U
        ? static_cast<char>('0' + value)
        : static_cast<char>('a' + (value - 10U));
}

[[nodiscard]] std::string lower_hex(
    const std::span<const std::byte> value) {
    std::string encoded(value.size() * 2U, '0');
    for (std::size_t index{}; index < value.size(); ++index) {
        const auto byte = std::to_integer<std::uint8_t>(value[index]);
        encoded[index * 2U] = nibble_hex(byte >> 4U);
        encoded[(index * 2U) + 1U] = nibble_hex(byte & 0x0fU);
    }
    return encoded;
}

[[nodiscard]] std::vector<std::byte> ascii_bytes(
    const std::string_view value) {
    std::vector<std::byte> encoded(value.size());
    std::transform(
        value.begin(), value.end(), encoded.begin(), [](const char value) {
            return std::byte{static_cast<std::uint8_t>(value)};
        });
    return encoded;
}

#if defined(_WIN32)
[[nodiscard]] bool bcrypt_succeeded(const NTSTATUS status) noexcept {
    return status >= 0;
}

class UniqueAlgorithm final {
public:
    UniqueAlgorithm() = default;
    ~UniqueAlgorithm() {
        if (handle != nullptr) BCryptCloseAlgorithmProvider(handle, 0U);
    }
    UniqueAlgorithm(const UniqueAlgorithm&) = delete;
    UniqueAlgorithm& operator=(const UniqueAlgorithm&) = delete;

    BCRYPT_ALG_HANDLE handle{};
};

class UniqueHash final {
public:
    UniqueHash() = default;
    ~UniqueHash() {
        if (handle != nullptr) BCryptDestroyHash(handle);
    }
    UniqueHash(const UniqueHash&) = delete;
    UniqueHash& operator=(const UniqueHash&) = delete;

    BCRYPT_HASH_HANDLE handle{};
};

[[nodiscard]] PairGenerationPopError bcrypt_sha256(
    const std::span<const std::byte> key,
    const std::span<const std::byte> input,
    PeerHandshakeSha256& output,
    const bool hmac) noexcept {
    if (key.size() > std::numeric_limits<ULONG>::max() ||
        input.size() > std::numeric_limits<ULONG>::max()) {
        return pop_error(PairGenerationPopErrorCode::crypto_operation_failed);
    }
    try {
        UniqueAlgorithm algorithm;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &algorithm.handle,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            hmac ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0U);
        if (!bcrypt_succeeded(status)) {
            return pop_error(PairGenerationPopErrorCode::crypto_unavailable);
        }

        ULONG object_bytes{};
        ULONG copied{};
        status = BCryptGetProperty(
            algorithm.handle,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_bytes),
            sizeof(object_bytes),
            &copied,
            0U);
        if (!bcrypt_succeeded(status) || copied != sizeof(object_bytes) ||
            object_bytes == 0U) {
            return pop_error(
                PairGenerationPopErrorCode::crypto_operation_failed);
        }

        std::vector<UCHAR> object(object_bytes);
        UniqueHash hash;
        PUCHAR key_data = key.empty()
            ? nullptr
            : reinterpret_cast<PUCHAR>(
                const_cast<std::byte*>(key.data()));
        status = BCryptCreateHash(
            algorithm.handle,
            &hash.handle,
            object.data(),
            object_bytes,
            key_data,
            static_cast<ULONG>(key.size()),
            0U);
        if (!bcrypt_succeeded(status)) {
            return pop_error(
                PairGenerationPopErrorCode::crypto_operation_failed);
        }
        if (!input.empty()) {
            status = BCryptHashData(
                hash.handle,
                reinterpret_cast<PUCHAR>(
                    const_cast<std::byte*>(input.data())),
                static_cast<ULONG>(input.size()),
                0U);
            if (!bcrypt_succeeded(status)) {
                return pop_error(
                    PairGenerationPopErrorCode::crypto_operation_failed);
            }
        }
        status = BCryptFinishHash(
            hash.handle,
            reinterpret_cast<PUCHAR>(output.data()),
            static_cast<ULONG>(output.size()),
            0U);
        if (!bcrypt_succeeded(status)) {
            output.fill(std::byte{0U});
            return pop_error(
                PairGenerationPopErrorCode::crypto_operation_failed);
        }
        return {};
    } catch (const std::bad_alloc&) {
        output.fill(std::byte{0U});
        return pop_error(PairGenerationPopErrorCode::allocation_failed);
    } catch (...) {
        output.fill(std::byte{0U});
        return pop_error(PairGenerationPopErrorCode::crypto_operation_failed);
    }
}
#endif

[[nodiscard]] PairGenerationPopError sha256_bytes(
    const std::span<const std::byte> input,
    PeerHandshakeSha256& output) noexcept {
#if defined(_WIN32)
    const PairGenerationPopError error =
        bcrypt_sha256({}, input, output, false);
    if (!error.has_error() && !contains_nonzero(output)) {
        output.fill(std::byte{0U});
        return pop_error(PairGenerationPopErrorCode::crypto_operation_failed);
    }
    return error;
#else
    static_cast<void>(input);
    output.fill(std::byte{0U});
    return pop_error(PairGenerationPopErrorCode::crypto_unavailable);
#endif
}

[[nodiscard]] PairGenerationPopError hmac_sha256_bytes(
    const std::span<const std::byte> key,
    const std::span<const std::byte> input,
    PeerHandshakeSha256& output) noexcept {
#if defined(_WIN32)
    return bcrypt_sha256(key, input, output, true);
#else
    static_cast<void>(key);
    static_cast<void>(input);
    output.fill(std::byte{0U});
    return pop_error(PairGenerationPopErrorCode::crypto_unavailable);
#endif
}

[[nodiscard]] std::string encode_challenge_request(
    const PairGenerationChallengeFieldsV1& fields) {
    std::string output;
    output.reserve(640U);
    output += "{\"allocation_request_id\":\"";
    output += fields.allocation_request_id;
    output += "\",\"android_identity_spki_sha256\":\"";
    output += lower_hex(fields.android_identity_spki_sha256);
    output += "\",\"binding_id\":\"";
    output += fields.binding_id;
    output += "\",\"binding_revision\":";
    output += std::to_string(fields.binding_revision);
    output += ",\"domain\":\"";
    output += kPairGenerationChallengeRequestDomain;
    output += "\",\"entitlement_id\":\"";
    output += fields.entitlement_id;
    output += "\",\"host_identity_spki_sha256\":\"";
    output += lower_hex(fields.host_identity_spki_sha256);
    output += "\",\"pair_id\":\"";
    output += fields.pair_id;
    output += "\",\"protocol_version\":";
    output += std::to_string(kPairGenerationPopProtocolVersion);
    output += ",\"request_id\":\"";
    output += fields.request_id;
    output += "\",\"revocation_version\":";
    output += std::to_string(fields.revocation_version);
    output += '}';
    return output;
}

[[nodiscard]] std::string encode_connection_seed(
    const std::string_view challenge_id,
    const std::span<const std::byte, 32U> host_nonce,
    const std::span<const std::byte, 32U> android_nonce,
    const std::string_view pair_id,
    const PeerHandshakeSha256& host_identity,
    const PeerHandshakeSha256& android_identity) {
    std::string output;
    output.reserve(640U);
    output += "{\"android_identity_spki_sha256\":\"";
    output += lower_hex(android_identity);
    output += "\",\"android_nonce\":\"";
    output += lower_hex(android_nonce);
    output += "\",\"challenge_id\":\"";
    output += challenge_id;
    output += "\",\"domain\":\"";
    output += kPairGenerationConnectionIdDomain;
    output += "\",\"host_identity_spki_sha256\":\"";
    output += lower_hex(host_identity);
    output += "\",\"host_nonce\":\"";
    output += lower_hex(host_nonce);
    output += "\",\"pair_id\":\"";
    output += pair_id;
    output += "\",\"proposal_version\":";
    output += std::to_string(kPairGenerationPopProposalVersion);
    output += ",\"protocol_version\":";
    output += std::to_string(kPairGenerationPopProtocolVersion);
    output += '}';
    return output;
}

[[nodiscard]] std::string encode_final_proof(
    const CanonicalPairGenerationChallengeRequestV1& request,
    const std::string_view challenge_id,
    const std::uint64_t challenge_expires_at_epoch,
    const std::uint64_t connection_id,
    const PeerHandshakeSha256& server_nonce_sha256,
    const PeerHandshakeSha256& proposal_sha256) {
    const PairGenerationChallengeFieldsV1& fields = request.fields();
    std::string output;
    output.reserve(1100U);
    output += "{\"allocation_request_id\":\"";
    output += fields.allocation_request_id;
    output += "\",\"android_identity_spki_sha256\":\"";
    output += lower_hex(fields.android_identity_spki_sha256);
    output += "\",\"binding_id\":\"";
    output += fields.binding_id;
    output += "\",\"binding_revision\":";
    output += std::to_string(fields.binding_revision);
    output += ",\"challenge_expires_at_epoch\":";
    output += std::to_string(challenge_expires_at_epoch);
    output += ",\"challenge_id\":\"";
    output += challenge_id;
    output += "\",\"challenge_request_id\":\"";
    output += fields.request_id;
    output += "\",\"challenge_request_payload_sha256\":\"";
    output += lower_hex(request.payload_sha256());
    output += "\",\"connection_id\":";
    output += std::to_string(connection_id);
    output += ",\"domain\":\"";
    output += kPairGenerationFinalCredentialProofDomain;
    output += "\",\"entitlement_id\":\"";
    output += fields.entitlement_id;
    output += "\",\"host_identity_spki_sha256\":\"";
    output += lower_hex(fields.host_identity_spki_sha256);
    output += "\",\"pair_id\":\"";
    output += fields.pair_id;
    output += "\",\"proposal_version\":";
    output += std::to_string(kPairGenerationPopProposalVersion);
    output += ",\"protocol_version\":";
    output += std::to_string(kPairGenerationPopProtocolVersion);
    output += ",\"revocation_version\":";
    output += std::to_string(fields.revocation_version);
    output += ",\"server_nonce_sha256\":\"";
    output += lower_hex(server_nonce_sha256);
    output += "\",\"transcript_proposal_sha256\":\"";
    output += lower_hex(proposal_sha256);
    output += "\"}";
    return output;
}

}  // namespace

const char* pair_generation_pop_error_code_name(
    const PairGenerationPopErrorCode code) noexcept {
    switch (code) {
        case PairGenerationPopErrorCode::none: return "none";
        case PairGenerationPopErrorCode::allocation_failed: return "allocation_failed";
        case PairGenerationPopErrorCode::request_invalid: return "request_invalid";
        case PairGenerationPopErrorCode::identifier_invalid: return "identifier_invalid";
        case PairGenerationPopErrorCode::identity_hash_invalid: return "identity_hash_invalid";
        case PairGenerationPopErrorCode::identity_roles_invalid: return "identity_roles_invalid";
        case PairGenerationPopErrorCode::signed64_invalid: return "signed64_invalid";
        case PairGenerationPopErrorCode::nonce_invalid: return "nonce_invalid";
        case PairGenerationPopErrorCode::nonce_roles_invalid: return "nonce_roles_invalid";
        case PairGenerationPopErrorCode::proposal_invalid: return "proposal_invalid";
        case PairGenerationPopErrorCode::proposal_binding_invalid: return "proposal_binding_invalid";
        case PairGenerationPopErrorCode::request_integrity_invalid: return "request_integrity_invalid";
        case PairGenerationPopErrorCode::connection_id_zero: return "connection_id_zero";
        case PairGenerationPopErrorCode::connection_id_mismatch: return "connection_id_mismatch";
        case PairGenerationPopErrorCode::crypto_unavailable: return "crypto_unavailable";
        case PairGenerationPopErrorCode::crypto_operation_failed: return "crypto_operation_failed";
    }
    return "unknown";
}

CanonicalPairGenerationChallengeRequestV1::
CanonicalPairGenerationChallengeRequestV1(
    PairGenerationChallengeFieldsV1 fields,
    std::vector<std::byte> canonical_bytes,
    const PeerHandshakeSha256 payload_sha256)
    : fields_(std::move(fields)),
      canonical_bytes_(std::move(canonical_bytes)),
      payload_sha256_(payload_sha256) {}

const PairGenerationChallengeFieldsV1&
CanonicalPairGenerationChallengeRequestV1::fields() const noexcept {
    return fields_;
}

std::span<const std::byte>
CanonicalPairGenerationChallengeRequestV1::canonical_bytes() const noexcept {
    return canonical_bytes_;
}

const PeerHandshakeSha256&
CanonicalPairGenerationChallengeRequestV1::payload_sha256() const noexcept {
    return payload_sha256_;
}

PairGenerationChallengeResultV1 build_pair_generation_challenge_request_v1(
    const PairGenerationChallengeFieldsV1& fields) noexcept {
    try {
        const PairGenerationPopError validation =
            validate_challenge_fields(fields);
        if (validation.has_error()) return {std::nullopt, validation};
        std::vector<std::byte> canonical =
            ascii_bytes(encode_challenge_request(fields));
        PeerHandshakeSha256 digest{};
        const PairGenerationPopError hash_error =
            sha256_bytes(canonical, digest);
        if (hash_error.has_error()) return {std::nullopt, hash_error};
        return {
            CanonicalPairGenerationChallengeRequestV1{
                fields, std::move(canonical), digest},
            {},
        };
    } catch (const std::bad_alloc&) {
        return {std::nullopt,
            pop_error(PairGenerationPopErrorCode::allocation_failed)};
    } catch (...) {
        return {std::nullopt,
            pop_error(PairGenerationPopErrorCode::request_invalid)};
    }
}

PairGenerationConnectionIdResultV1 derive_pair_generation_connection_id_v1(
    const std::span<const std::byte, 32U> server_nonce,
    const std::string_view challenge_id,
    const std::span<const std::byte, 32U> host_nonce,
    const std::span<const std::byte, 32U> android_nonce,
    const std::string_view pair_id,
    const PeerHandshakeSha256& host_identity_spki_sha256,
    const PeerHandshakeSha256& android_identity_spki_sha256) noexcept {
    if (!contains_nonzero(server_nonce) || !contains_nonzero(host_nonce) ||
        !contains_nonzero(android_nonce)) {
        return {0U, pop_error(PairGenerationPopErrorCode::nonce_invalid)};
    }
    if (std::equal(
            host_nonce.begin(), host_nonce.end(), android_nonce.begin())) {
        return {0U,
            pop_error(PairGenerationPopErrorCode::nonce_roles_invalid)};
    }
    if (!lower_hex_identifier_valid(challenge_id) ||
        !lower_hex_identifier_valid(pair_id)) {
        return {0U,
            pop_error(PairGenerationPopErrorCode::identifier_invalid)};
    }
    const PairGenerationPopError identity_error = validate_identity_hashes(
        host_identity_spki_sha256, android_identity_spki_sha256);
    if (identity_error.has_error()) return {0U, identity_error};
    try {
        const std::vector<std::byte> seed = ascii_bytes(
            encode_connection_seed(
                challenge_id,
                host_nonce,
                android_nonce,
                pair_id,
                host_identity_spki_sha256,
                android_identity_spki_sha256));
        PeerHandshakeSha256 digest{};
        const PairGenerationPopError hmac_error = hmac_sha256_bytes(
            server_nonce, seed, digest);
        if (hmac_error.has_error()) return {0U, hmac_error};
        std::uint64_t connection_id{};
        for (std::size_t index{}; index < sizeof(connection_id); ++index) {
            connection_id = (connection_id << 8U) |
                std::to_integer<std::uint8_t>(digest[index]);
        }
        connection_id &= kPairGenerationPopSigned64Maximum;
        digest.fill(std::byte{0U});
        if (connection_id == 0U) {
            return {0U,
                pop_error(PairGenerationPopErrorCode::connection_id_zero)};
        }
        return {connection_id, {}};
    } catch (const std::bad_alloc&) {
        return {0U,
            pop_error(PairGenerationPopErrorCode::allocation_failed)};
    } catch (...) {
        return {0U,
            pop_error(PairGenerationPopErrorCode::crypto_operation_failed)};
    }
}

CanonicalPairGenerationFinalCredentialProofV1::
CanonicalPairGenerationFinalCredentialProofV1(
    CanonicalPairGenerationChallengeRequestV1 challenge_request,
    std::string challenge_id,
    const std::uint64_t challenge_expires_at_epoch,
    const std::uint64_t connection_id,
    const PeerHandshakeSha256 transcript_proposal_sha256,
    std::vector<std::byte> canonical_bytes,
    const PeerHandshakeSha256 payload_sha256)
    : challenge_request_(std::move(challenge_request)),
      challenge_id_(std::move(challenge_id)),
      challenge_expires_at_epoch_(challenge_expires_at_epoch),
      connection_id_(connection_id),
      transcript_proposal_sha256_(transcript_proposal_sha256),
      canonical_bytes_(std::move(canonical_bytes)),
      payload_sha256_(payload_sha256) {}

const CanonicalPairGenerationChallengeRequestV1&
CanonicalPairGenerationFinalCredentialProofV1::challenge_request()
    const noexcept {
    return challenge_request_;
}

std::string_view
CanonicalPairGenerationFinalCredentialProofV1::challenge_id() const noexcept {
    return challenge_id_;
}

std::uint64_t
CanonicalPairGenerationFinalCredentialProofV1::challenge_expires_at_epoch()
    const noexcept {
    return challenge_expires_at_epoch_;
}

std::uint64_t
CanonicalPairGenerationFinalCredentialProofV1::connection_id() const noexcept {
    return connection_id_;
}

const PeerHandshakeSha256&
CanonicalPairGenerationFinalCredentialProofV1::
transcript_proposal_sha256() const noexcept {
    return transcript_proposal_sha256_;
}

std::span<const std::byte>
CanonicalPairGenerationFinalCredentialProofV1::canonical_bytes()
    const noexcept {
    return canonical_bytes_;
}

const PeerHandshakeSha256&
CanonicalPairGenerationFinalCredentialProofV1::payload_sha256()
    const noexcept {
    return payload_sha256_;
}

PairGenerationFinalProofResultV1
build_pair_generation_final_credential_proof_v1(
    const CanonicalPairGenerationChallengeRequestV1& challenge_request,
    const std::string_view challenge_id,
    const std::uint64_t challenge_expires_at_epoch,
    const std::span<const std::byte, 32U> server_nonce,
    const VerifiedPairGenerationProposalV1& proposal) noexcept {
    if (!lower_hex_identifier_valid(challenge_id)) {
        return {std::nullopt,
            pop_error(PairGenerationPopErrorCode::identifier_invalid)};
    }
    if (!positive_signed64(challenge_expires_at_epoch)) {
        return {std::nullopt,
            pop_error(PairGenerationPopErrorCode::signed64_invalid)};
    }
    if (!contains_nonzero(server_nonce)) {
        return {std::nullopt,
            pop_error(PairGenerationPopErrorCode::nonce_invalid)};
    }
    try {
        PairGenerationChallengeResultV1 rebuilt_result =
            build_pair_generation_challenge_request_v1(
                challenge_request.fields());
        if (!rebuilt_result.succeeded()) {
            return {std::nullopt, rebuilt_result.error};
        }
        if (!std::equal(
                challenge_request.canonical_bytes().begin(),
                challenge_request.canonical_bytes().end(),
                rebuilt_result.request->canonical_bytes().begin(),
                rebuilt_result.request->canonical_bytes().end()) ||
            challenge_request.payload_sha256() !=
                rebuilt_result.request->payload_sha256()) {
            return {std::nullopt,
                pop_error(
                    PairGenerationPopErrorCode::request_integrity_invalid)};
        }

        PairGenerationProposalResult reparsed =
            parse_pair_generation_proposal_v1(proposal.canonical_bytes());
        if (!reparsed.succeeded() ||
            reparsed.proposal->proposal_sha256() !=
                proposal.proposal_sha256()) {
            return {std::nullopt,
                pop_error(PairGenerationPopErrorCode::proposal_invalid)};
        }
        const PairGenerationChallengeFieldsV1& request_fields =
            rebuilt_result.request->fields();
        const PairGenerationProposalFields& proposal_fields =
            reparsed.proposal->fields();
        if (proposal_fields.pair_id != request_fields.pair_id ||
            proposal_fields.host_identity_spki_sha256 !=
                request_fields.host_identity_spki_sha256 ||
            proposal_fields.android_identity_spki_sha256 !=
                request_fields.android_identity_spki_sha256) {
            return {std::nullopt,
                pop_error(
                    PairGenerationPopErrorCode::proposal_binding_invalid)};
        }

        const PairGenerationConnectionIdResultV1 connection =
            derive_pair_generation_connection_id_v1(
                server_nonce,
                challenge_id,
                proposal_fields.host_nonce,
                proposal_fields.android_nonce,
                request_fields.pair_id,
                request_fields.host_identity_spki_sha256,
                request_fields.android_identity_spki_sha256);
        if (!connection.succeeded()) return {std::nullopt, connection.error};
        if (proposal_fields.connection_id != connection.connection_id) {
            return {std::nullopt,
                pop_error(
                    PairGenerationPopErrorCode::connection_id_mismatch)};
        }

        PeerHandshakeSha256 server_nonce_sha256{};
        const PairGenerationPopError server_nonce_hash_error =
            sha256_bytes(server_nonce, server_nonce_sha256);
        if (server_nonce_hash_error.has_error()) {
            return {std::nullopt, server_nonce_hash_error};
        }
        const PeerHandshakeSha256 proposal_sha256 =
            reparsed.proposal->proposal_sha256();
        std::vector<std::byte> canonical = ascii_bytes(encode_final_proof(
            *rebuilt_result.request,
            challenge_id,
            challenge_expires_at_epoch,
            connection.connection_id,
            server_nonce_sha256,
            proposal_sha256));
        server_nonce_sha256.fill(std::byte{0U});
        PeerHandshakeSha256 digest{};
        const PairGenerationPopError digest_error =
            sha256_bytes(canonical, digest);
        if (digest_error.has_error()) return {std::nullopt, digest_error};
        return {
            CanonicalPairGenerationFinalCredentialProofV1{
                std::move(*rebuilt_result.request),
                std::string(challenge_id),
                challenge_expires_at_epoch,
                connection.connection_id,
                proposal_sha256,
                std::move(canonical),
                digest},
            {},
        };
    } catch (const std::bad_alloc&) {
        return {std::nullopt,
            pop_error(PairGenerationPopErrorCode::allocation_failed)};
    } catch (...) {
        return {std::nullopt,
            pop_error(PairGenerationPopErrorCode::request_invalid)};
    }
}

}  // namespace vfdual
