#include "vfdual/pair_generation_pop_v1.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

void require(const bool condition, const std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

[[nodiscard]] std::uint8_t hex_nibble(const char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(10 + value - 'a');
    }
    throw std::runtime_error("invalid test hex");
}

template <std::size_t Size>
[[nodiscard]] std::array<std::byte, Size> decode_hex(
    const std::string_view value) {
    require(value.size() == Size * 2U, "test hex length mismatch");
    std::array<std::byte, Size> decoded{};
    for (std::size_t index{}; index < Size; ++index) {
        decoded[index] = std::byte{static_cast<std::uint8_t>(
            (hex_nibble(value[index * 2U]) << 4U) |
            hex_nibble(value[(index * 2U) + 1U]))};
    }
    return decoded;
}

[[nodiscard]] std::string repeated_hex(
    const std::uint8_t value, const std::size_t count) {
    constexpr std::string_view alphabet{"0123456789abcdef"};
    std::string encoded;
    encoded.reserve(count * 2U);
    for (std::size_t index{}; index < count; ++index) {
        encoded.push_back(alphabet[value >> 4U]);
        encoded.push_back(alphabet[value & 0x0fU]);
    }
    return encoded;
}

[[nodiscard]] std::string lower_hex(
    const std::span<const std::byte> value) {
    constexpr std::string_view alphabet{"0123456789abcdef"};
    std::string encoded;
    encoded.reserve(value.size() * 2U);
    for (const std::byte current : value) {
        const auto byte = std::to_integer<std::uint8_t>(current);
        encoded.push_back(alphabet[byte >> 4U]);
        encoded.push_back(alphabet[byte & 0x0fU]);
    }
    return encoded;
}

[[nodiscard]] vfdual::PairGenerationChallengeFieldsV1 vector_fields() {
    vfdual::PairGenerationChallengeFieldsV1 fields;
    fields.request_id = repeated_hex(0x01U, 16U);
    fields.allocation_request_id = repeated_hex(0x02U, 16U);
    fields.entitlement_id = repeated_hex(0x03U, 16U);
    fields.pair_id = repeated_hex(0x04U, 16U);
    fields.binding_id = repeated_hex(0x05U, 16U);
    fields.binding_revision = 0x0102'0304'0506'0708ULL;
    fields.revocation_version = 9U;
    fields.host_identity_spki_sha256.fill(std::byte{0x10U});
    fields.android_identity_spki_sha256.fill(std::byte{0x20U});
    return fields;
}

[[nodiscard]] vfdual::PeerHandshakeNonce host_nonce() {
    vfdual::PeerHandshakeNonce nonce{};
    for (std::size_t index{}; index < nonce.size(); ++index) {
        nonce[index] = std::byte{static_cast<std::uint8_t>(0x40U + index)};
    }
    return nonce;
}

[[nodiscard]] vfdual::PeerHandshakeNonce android_nonce() {
    vfdual::PeerHandshakeNonce nonce{};
    for (std::size_t index{}; index < nonce.size(); ++index) {
        nonce[index] = std::byte{static_cast<std::uint8_t>(0x60U + index)};
    }
    return nonce;
}

[[nodiscard]] vfdual::PairGenerationProposalFields vector_proposal_fields(
    const std::uint64_t connection_id) {
    constexpr std::string_view host_public_hex{
        "046b17d1f2e12c4247f8bce6e563a440"
        "f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e"
        "162bce33576b315ececbb6406837bf51f5"};
    constexpr std::string_view android_public_hex{
        "047cf27b188d034f7e8a52380304b51a"
        "c3c08969e277f21b35a60b48fc47669978"
        "07775510db8ed040293d9ac69f7430d"
        "bba7dade63ce982299e04b79d227873d1"};
    vfdual::PairGenerationProposalFields fields;
    fields.host_identity_spki_sha256.fill(std::byte{0x10U});
    fields.android_identity_spki_sha256.fill(std::byte{0x20U});
    fields.host_ephemeral_public_key =
        decode_hex<vfdual::PeerHandshakeP256PublicKey{}.size()>(
            host_public_hex);
    fields.android_ephemeral_public_key =
        decode_hex<vfdual::PeerHandshakeP256PublicKey{}.size()>(
            android_public_hex);
    fields.host_nonce = host_nonce();
    fields.android_nonce = android_nonce();
    fields.connection_id = connection_id;
    fields.transport_kind = vfdual::PeerHandshakeTransportKind::cat6;
    fields.host_ipv4 = {
        std::byte{0xc0U}, std::byte{0xa8U},
        std::byte{0x37U}, std::byte{0x01U}};
    fields.android_ipv4 = {
        std::byte{0xc0U}, std::byte{0xa8U},
        std::byte{0x37U}, std::byte{0x02U}};
    fields.video_port = 45678U;
    fields.control_port = 45679U;
    fields.pair_id = repeated_hex(0x04U, 16U);
    fields.host_runtime_version = "17.8.47";
    fields.android_runtime_version = "17.8.47";
    return fields;
}

void frozen_cross_language_vectors_match() {
    constexpr std::uint64_t expected_connection_id =
        63'191'577'505'803'677ULL;
    constexpr std::string_view expected_request_hash{
        "f5fe7552fdd4009c4fcf6bb795cc8fe49c8ced14f90e82fdef384029f171acea"};
    constexpr std::string_view expected_proposal_hash{
        "f347088b897243eb8a2f1a69fb1e031cacd7f35cd2163efa9741dcf2964caf3f"};
    constexpr std::string_view expected_final_hash{
        "2fe727665a08adf4893b869a8d5c9842064b53f8952a32693ca37fd2a83a72e1"};
    constexpr std::string_view server_nonce_hex{
        "dc66120c8c1a81e879aac654e34421b55111d30c5e6836df235f18e90c0b0e69"};

    const vfdual::PairGenerationChallengeResultV1 request =
        vfdual::build_pair_generation_challenge_request_v1(vector_fields());
    require(request.succeeded(), "challenge request build failed");
    require(
        request.request->canonical_bytes().size() == 587U,
        "challenge request canonical length drifted");
    require(
        lower_hex(request.request->payload_sha256()) == expected_request_hash,
        "challenge request hash drifted");

    const auto server_nonce = decode_hex<32U>(server_nonce_hex);
    const vfdual::PairGenerationConnectionIdResultV1 connection =
        vfdual::derive_pair_generation_connection_id_v1(
            server_nonce,
            repeated_hex(0x06U, 16U),
            host_nonce(),
            android_nonce(),
            request.request->fields().pair_id,
            request.request->fields().host_identity_spki_sha256,
            request.request->fields().android_identity_spki_sha256);
    require(connection.succeeded(), "connection ID derivation failed");
    require(
        connection.connection_id == expected_connection_id,
        "connection ID vector drifted");

    const vfdual::PairGenerationProposalResult proposal =
        vfdual::build_pair_generation_proposal_v1(
            vector_proposal_fields(connection.connection_id));
    require(proposal.succeeded(), "proposal build failed");
    require(
        lower_hex(proposal.proposal->proposal_sha256()) ==
            expected_proposal_hash,
        "proposal hash drifted");

    const vfdual::PairGenerationFinalProofResultV1 final_proof =
        vfdual::build_pair_generation_final_credential_proof_v1(
            *request.request,
            repeated_hex(0x06U, 16U),
            0x1234'5678ULL,
            server_nonce,
            *proposal.proposal);
    require(final_proof.succeeded(), "final proof build failed");
    require(
        final_proof.proof->canonical_bytes().size() == 1033U,
        "final proof canonical length drifted");
    require(
        final_proof.proof->connection_id() == expected_connection_id,
        "final proof connection ID drifted");
    require(
        final_proof.proof->transcript_proposal_sha256() ==
            proposal.proposal->proposal_sha256(),
        "final proof proposal hash binding drifted");
    require(
        lower_hex(final_proof.proof->payload_sha256()) == expected_final_hash,
        "final proof hash drifted");
}

void invalid_authority_and_role_inputs_fail_closed() {
    vfdual::PairGenerationChallengeFieldsV1 invalid = vector_fields();
    invalid.request_id.assign(32U, '0');
    vfdual::PairGenerationChallengeResultV1 request =
        vfdual::build_pair_generation_challenge_request_v1(invalid);
    require(
        request.error.code ==
            vfdual::PairGenerationPopErrorCode::identifier_invalid,
        "zero request ID was accepted");

    invalid = vector_fields();
    invalid.android_identity_spki_sha256 =
        invalid.host_identity_spki_sha256;
    request = vfdual::build_pair_generation_challenge_request_v1(invalid);
    require(
        request.error.code ==
            vfdual::PairGenerationPopErrorCode::identity_roles_invalid,
        "same-role identity hashes were accepted");

    const auto nonce = decode_hex<32U>(
        "dc66120c8c1a81e879aac654e34421b55111d30c5e6836df235f18e90c0b0e69");
    const vfdual::PairGenerationChallengeFieldsV1 valid = vector_fields();
    const vfdual::PairGenerationConnectionIdResultV1 connection =
        vfdual::derive_pair_generation_connection_id_v1(
            nonce,
            repeated_hex(0x06U, 16U),
            host_nonce(),
            host_nonce(),
            valid.pair_id,
            valid.host_identity_spki_sha256,
            valid.android_identity_spki_sha256);
    require(
        connection.error.code ==
            vfdual::PairGenerationPopErrorCode::nonce_roles_invalid,
        "same-role nonces were accepted");
}

void final_proof_rejects_caller_selected_connection_id() {
    constexpr std::uint64_t expected_connection_id =
        63'191'577'505'803'677ULL;
    const vfdual::PairGenerationChallengeResultV1 request =
        vfdual::build_pair_generation_challenge_request_v1(vector_fields());
    require(request.succeeded(), "challenge request setup failed");
    const vfdual::PairGenerationProposalResult proposal =
        vfdual::build_pair_generation_proposal_v1(
            vector_proposal_fields(expected_connection_id + 1U));
    require(proposal.succeeded(), "mismatched proposal setup failed");
    const auto nonce = decode_hex<32U>(
        "dc66120c8c1a81e879aac654e34421b55111d30c5e6836df235f18e90c0b0e69");
    const vfdual::PairGenerationFinalProofResultV1 final_proof =
        vfdual::build_pair_generation_final_credential_proof_v1(
            *request.request,
            repeated_hex(0x06U, 16U),
            0x1234'5678ULL,
            nonce,
            *proposal.proposal);
    require(
        final_proof.error.code ==
            vfdual::PairGenerationPopErrorCode::connection_id_mismatch,
        "caller-selected connection ID was accepted");
}

}  // namespace

int main() {
    try {
        frozen_cross_language_vectors_match();
        invalid_authority_and_role_inputs_fail_closed();
        final_proof_rejects_caller_selected_connection_id();
        std::cout << "PAIR_GENERATION_POP_V1_OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "PAIR_GENERATION_POP_V1_FAILED: "
                  << error.what() << '\n';
        return 1;
    }
}
