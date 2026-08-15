#include "vfdual/pair_generation_proposal_v1.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if !defined(VFDUAL_SOURCE_DIR)
#error "VFDUAL_SOURCE_DIR is required for proposal noexcept source contracts"
#endif

namespace {

[[noreturn]] void fail(
    const char* expression, const char* file, const int line) {
    std::cerr << file << ':' << line << ": CHECK failed: "
              << expression << '\n';
    std::exit(1);
}

#define CHECK(expression) \
    ((expression) ? static_cast<void>(0) : fail(#expression, __FILE__, __LINE__))

constexpr std::string_view kHostPublicHex{
    "046b17d1f2e12c4247f8bce6e563a440"
    "f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e"
    "162bce33576b315ececbb6406837bf51f5"};
constexpr std::string_view kAndroidPublicHex{
    "047cf27b188d034f7e8a52380304b51a"
    "c3c08969e277f21b35a60b48fc47669978"
    "07775510db8ed040293d9ac69f7430d"
    "bba7dade63ce982299e04b79d227873d1"};
constexpr std::string_view kProposalCanonicalHex{
    "0000000027766973696f6e666f7267652d706565722d67656e65726174696f6e2d"
    "70726f706f73616c2d763101000000040000000102000000200001020304050607"
    "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f030000002020212223"
    "2425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0400000041"
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f505"
    "00000041047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc"
    "4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227"
    "873d10600000020404142434445464748494a4b4c4d4e4f50515253545556575859"
    "5a5b5c5d5e5f0700000020606162636465666768696a6b6c6d6e6f707172737475"
    "767778797a7b7c7d7e7f080000000810203040506070800900000001010a000000"
    "04c0a837010b00000004c0a837020c00000002b26e0d00000002b26f0e00000020"
    "30313233343536373839616263646566303132333435363738396162636465660f00"
    "00000731372e382e3437100000000731372e382e3437"};
constexpr std::string_view kProposalSha256Hex{
    "89669a6d4e73b4ae9e9e44e042c75426a520f611009077d5caa5a8fafad9732d"};
constexpr std::string_view kFinalTranscriptSha256Hex{
    "ea8f01700d0921665958fcb8dc0f9abf657499cc7423ff37dd6efbd233025098"};
constexpr std::int64_t kVectorGeneration = 0x0102'0304'0506'0708LL;

[[nodiscard]] std::uint8_t nibble(const char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(10 + value - 'a');
    }
    fail("valid lowercase hex", __FILE__, __LINE__);
}

[[nodiscard]] std::vector<std::byte> bytes_from_hex(
    const std::string_view value) {
    CHECK(value.size() % 2U == 0U);
    std::vector<std::byte> output(value.size() / 2U);
    for (std::size_t index{}; index < output.size(); ++index) {
        output[index] = std::byte{static_cast<std::uint8_t>(
            (nibble(value[index * 2U]) << 4U) |
            nibble(value[index * 2U + 1U]))};
    }
    return output;
}

template <std::size_t Size>
[[nodiscard]] std::array<std::byte, Size> array_from_hex(
    const std::string_view value) {
    const std::vector<std::byte> parsed = bytes_from_hex(value);
    CHECK(parsed.size() == Size);
    std::array<std::byte, Size> output{};
    std::copy(parsed.begin(), parsed.end(), output.begin());
    return output;
}

template <typename Left, typename Right>
[[nodiscard]] bool bytes_equal(const Left& left, const Right& right) {
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin(), right.end());
}

[[nodiscard]] bool contains_nonzero(
    const std::span<const std::byte> value) {
    return std::any_of(value.begin(), value.end(), [](const std::byte byte) {
        return byte != std::byte{0U};
    });
}

[[nodiscard]] vfdual::PairGenerationProposalFields vector_fields() {
    vfdual::PairGenerationProposalFields fields;
    for (std::size_t index{}; index < 32U; ++index) {
        fields.host_identity_spki_sha256[index] =
            std::byte{static_cast<std::uint8_t>(index)};
        fields.android_identity_spki_sha256[index] =
            std::byte{static_cast<std::uint8_t>(0x20U + index)};
        fields.host_nonce[index] =
            std::byte{static_cast<std::uint8_t>(0x40U + index)};
        fields.android_nonce[index] =
            std::byte{static_cast<std::uint8_t>(0x60U + index)};
    }
    fields.host_ephemeral_public_key =
        array_from_hex<vfdual::kPeerHandshakeP256PublicKeyBytes>(
            kHostPublicHex);
    fields.android_ephemeral_public_key =
        array_from_hex<vfdual::kPeerHandshakeP256PublicKeyBytes>(
            kAndroidPublicHex);
    fields.connection_id = 0x1020'3040'5060'7080ULL;
    fields.transport_kind = vfdual::PeerHandshakeTransportKind::cat6;
    fields.host_ipv4 = {
        std::byte{0xc0U}, std::byte{0xa8U},
        std::byte{0x37U}, std::byte{0x01U}};
    fields.android_ipv4 = {
        std::byte{0xc0U}, std::byte{0xa8U},
        std::byte{0x37U}, std::byte{0x02U}};
    fields.video_port = 45678U;
    fields.control_port = 45679U;
    fields.pair_id = "0123456789abcdef0123456789abcdef";
    fields.host_runtime_version = "17.8.47";
    fields.android_runtime_version = "17.8.47";
    return fields;
}

struct TlvRange final {
    std::size_t tag_offset{};
    std::size_t value_offset{};
    std::size_t value_bytes{};
    std::size_t total_bytes{};
};

[[nodiscard]] std::uint32_t load_u32_be(
    const std::span<const std::byte> value) {
    CHECK(value.size() == 4U);
    std::uint32_t result{};
    for (const std::byte byte : value) {
        result = (result << 8U) | std::to_integer<std::uint8_t>(byte);
    }
    return result;
}

[[nodiscard]] std::vector<TlvRange> tlv_ranges(
    const std::span<const std::byte> canonical) {
    std::vector<TlvRange> result;
    std::size_t offset{};
    while (offset < canonical.size()) {
        CHECK(canonical.size() - offset >= 5U);
        const std::uint32_t length =
            load_u32_be(canonical.subspan(offset + 1U, 4U));
        CHECK(canonical.size() - offset >= 5U + length);
        result.push_back({offset, offset + 5U, length, 5U + length});
        offset += 5U + length;
    }
    return result;
}

void expect_parse_error(
    const std::vector<std::byte>& value,
    const vfdual::PairGenerationProposalErrorCode expected) {
    const auto result = vfdual::parse_pair_generation_proposal_v1(value);
    CHECK(!result.succeeded());
    CHECK(result.error.code == expected);
}

void expect_build_error(
    const vfdual::PairGenerationProposalFields& fields,
    const vfdual::PairGenerationProposalErrorCode expected) {
    const auto result = vfdual::build_pair_generation_proposal_v1(fields);
    CHECK(!result.succeeded());
    CHECK(result.error.code == expected);
}

void verify_frozen_vector_and_restricted_final_mapping() {
    vfdual::PairGenerationProposalFields fields = vector_fields();
    const auto result = vfdual::build_pair_generation_proposal_v1(fields);
    CHECK(result.succeeded());
    const std::vector<std::byte> expected =
        bytes_from_hex(kProposalCanonicalHex);
    CHECK(result.proposal->canonical_bytes().size() == 453U);
    CHECK(bytes_equal(result.proposal->canonical_bytes(), expected));
    CHECK(bytes_equal(
        result.proposal->proposal_sha256(),
        array_from_hex<32U>(kProposalSha256Hex)));

    const auto parsed = vfdual::parse_pair_generation_proposal_v1(expected);
    CHECK(parsed.succeeded());
    CHECK(bytes_equal(
        parsed.proposal->canonical_bytes(),
        result.proposal->canonical_bytes()));
    CHECK(parsed.proposal->fields().pair_id == fields.pair_id);

    const auto final_result =
        vfdual::build_final_peer_handshake_transcript_from_proposal_v1(
            *result.proposal, kVectorGeneration);
    CHECK(final_result.succeeded());
    CHECK(final_result.transcript->canonical_bytes().size() == 456U);
    CHECK(bytes_equal(
        final_result.transcript->transcript_sha256(),
        array_from_hex<32U>(kFinalTranscriptSha256Hex)));
    const auto& final_fields = final_result.transcript->fields();
    const auto& proposal_fields = result.proposal->fields();
    CHECK(final_fields.host_identity_spki_sha256 ==
        proposal_fields.host_identity_spki_sha256);
    CHECK(final_fields.android_identity_spki_sha256 ==
        proposal_fields.android_identity_spki_sha256);
    CHECK(final_fields.host_ephemeral_public_key ==
        proposal_fields.host_ephemeral_public_key);
    CHECK(final_fields.android_ephemeral_public_key ==
        proposal_fields.android_ephemeral_public_key);
    CHECK(final_fields.host_nonce == proposal_fields.host_nonce);
    CHECK(final_fields.android_nonce == proposal_fields.android_nonce);
    CHECK(final_fields.connection_id == proposal_fields.connection_id);
    CHECK(final_fields.session_generation ==
        static_cast<std::uint64_t>(kVectorGeneration));
    CHECK(final_fields.transport_kind == proposal_fields.transport_kind);
    CHECK(final_fields.host_ipv4 == proposal_fields.host_ipv4);
    CHECK(final_fields.android_ipv4 == proposal_fields.android_ipv4);
    CHECK(final_fields.video_port == proposal_fields.video_port);
    CHECK(final_fields.control_port == proposal_fields.control_port);
    CHECK(final_fields.pair_id == proposal_fields.pair_id);
    CHECK(final_fields.host_runtime_version ==
        proposal_fields.host_runtime_version);
    CHECK(final_fields.android_runtime_version ==
        proposal_fields.android_runtime_version);

    fields.pair_id.assign(32U, 'f');
    fields.host_nonce.fill(std::byte{0U});
    CHECK(result.proposal->fields().pair_id ==
        "0123456789abcdef0123456789abcdef");
    CHECK(contains_nonzero(result.proposal->fields().host_nonce));
}

void verify_strict_parser() {
    const auto built =
        vfdual::build_pair_generation_proposal_v1(vector_fields());
    CHECK(built.succeeded());
    const std::vector<std::byte> canonical(
        built.proposal->canonical_bytes().begin(),
        built.proposal->canonical_bytes().end());
    const std::vector<TlvRange> ranges = tlv_ranges(canonical);
    CHECK(ranges.size() == vfdual::kPairGenerationProposalFieldCount);

    std::vector<std::byte> duplicate = canonical;
    duplicate[ranges[1].tag_offset] = std::byte{0U};
    expect_parse_error(
        duplicate,
        vfdual::PairGenerationProposalErrorCode::duplicate_tag);

    std::vector<std::byte> out_of_order = canonical;
    out_of_order[ranges[1].tag_offset] = std::byte{2U};
    expect_parse_error(
        out_of_order,
        vfdual::PairGenerationProposalErrorCode::out_of_order_tag);

    std::vector<std::byte> unknown = canonical;
    unknown[ranges.back().tag_offset] = std::byte{17U};
    expect_parse_error(
        unknown,
        vfdual::PairGenerationProposalErrorCode::unknown_tag);

    std::vector<std::byte> missing = canonical;
    missing.erase(
        missing.begin() + static_cast<std::ptrdiff_t>(ranges[7].tag_offset),
        missing.begin() + static_cast<std::ptrdiff_t>(
            ranges[7].tag_offset + ranges[7].total_bytes));
    expect_parse_error(
        missing,
        vfdual::PairGenerationProposalErrorCode::out_of_order_tag);

    std::vector<std::byte> trailing = canonical;
    trailing.push_back(std::byte{0U});
    expect_parse_error(
        trailing,
        vfdual::PairGenerationProposalErrorCode::trailing_data);

    std::vector<std::byte> truncated(
        canonical.begin(), canonical.begin() + 4);
    expect_parse_error(
        truncated,
        vfdual::PairGenerationProposalErrorCode::truncated_tlv);

    std::vector<std::byte> invalid_length = canonical;
    std::fill_n(
        invalid_length.begin() +
            static_cast<std::ptrdiff_t>(ranges[2].tag_offset + 1U),
        4U,
        std::byte{0xffU});
    expect_parse_error(
        invalid_length,
        vfdual::PairGenerationProposalErrorCode::invalid_field_length);

    std::vector<std::byte> invalid_domain = canonical;
    invalid_domain[ranges[0].value_offset + ranges[0].value_bytes - 1U] =
        std::byte{'2'};
    expect_parse_error(
        invalid_domain,
        vfdual::PairGenerationProposalErrorCode::invalid_domain);

    std::vector<std::byte> unsupported_version = canonical;
    unsupported_version[ranges[1].value_offset + 3U] = std::byte{2U};
    expect_parse_error(
        unsupported_version,
        vfdual::PairGenerationProposalErrorCode::unsupported_version);

    expect_parse_error(
        {}, vfdual::PairGenerationProposalErrorCode::missing_field);
    expect_parse_error(
        std::vector<std::byte>(
            vfdual::kPairGenerationProposalMaximumCanonicalBytes + 1U),
        vfdual::PairGenerationProposalErrorCode::proposal_too_large);
}

void verify_builder_boundaries() {
    auto fields = vector_fields();
    fields.host_identity_spki_sha256.fill(std::byte{0U});
    expect_build_error(
        fields,
        vfdual::PairGenerationProposalErrorCode::invalid_identity_binding);
    fields = vector_fields();
    fields.android_identity_spki_sha256 =
        fields.host_identity_spki_sha256;
    expect_build_error(
        fields,
        vfdual::PairGenerationProposalErrorCode::invalid_identity_binding);
    fields = vector_fields();
    fields.host_ephemeral_public_key.fill(std::byte{0U});
    fields.host_ephemeral_public_key[0] = std::byte{0x04U};
    expect_build_error(
        fields,
        vfdual::PairGenerationProposalErrorCode::invalid_ephemeral_public_key);
    fields = vector_fields();
    fields.android_ephemeral_public_key = fields.host_ephemeral_public_key;
    expect_build_error(
        fields,
        vfdual::PairGenerationProposalErrorCode::invalid_ephemeral_public_key);
    fields = vector_fields();
    fields.host_nonce.fill(std::byte{0U});
    expect_build_error(
        fields, vfdual::PairGenerationProposalErrorCode::invalid_nonce);
    fields = vector_fields();
    fields.android_nonce = fields.host_nonce;
    expect_build_error(
        fields, vfdual::PairGenerationProposalErrorCode::invalid_nonce);
    fields = vector_fields();
    fields.connection_id = 0U;
    expect_build_error(
        fields,
        vfdual::PairGenerationProposalErrorCode::invalid_connection_id);
    fields = vector_fields();
    fields.connection_id =
        vfdual::kPairGenerationProposalSigned64Maximum + 1U;
    expect_build_error(
        fields,
        vfdual::PairGenerationProposalErrorCode::invalid_connection_id);
    fields = vector_fields();
    fields.transport_kind =
        static_cast<vfdual::PeerHandshakeTransportKind>(3U);
    expect_build_error(
        fields,
        vfdual::PairGenerationProposalErrorCode::invalid_transport_kind);
    fields = vector_fields();
    fields.video_port = 0U;
    expect_build_error(
        fields, vfdual::PairGenerationProposalErrorCode::invalid_endpoint);
    fields = vector_fields();
    fields.control_port = fields.video_port;
    expect_build_error(
        fields, vfdual::PairGenerationProposalErrorCode::invalid_endpoint);
    fields = vector_fields();
    fields.pair_id.assign(32U, 'A');
    expect_build_error(
        fields, vfdual::PairGenerationProposalErrorCode::invalid_pair_id);
    fields = vector_fields();
    fields.host_runtime_version = "01.2.3";
    expect_build_error(
        fields,
        vfdual::PairGenerationProposalErrorCode::invalid_runtime_version);
    fields = vector_fields();
    fields.android_runtime_version = "1.2.3+dev";
    expect_build_error(
        fields,
        vfdual::PairGenerationProposalErrorCode::invalid_runtime_version);
}

void verify_generation_boundary_and_sanitized_errors() {
    const auto proposal =
        vfdual::build_pair_generation_proposal_v1(vector_fields());
    CHECK(proposal.succeeded());
    for (const std::int64_t generation : {0LL, -1LL}) {
        const auto final_result =
            vfdual::build_final_peer_handshake_transcript_from_proposal_v1(
                *proposal.proposal, generation);
        CHECK(!final_result.succeeded());
        CHECK(final_result.error.code ==
            vfdual::PeerHandshakeErrorCode::invalid_session_generation);
        CHECK(final_result.error.native_domain ==
            vfdual::PeerHandshakeNativeStatusDomain::none);
        CHECK(final_result.error.native_status == 0U);
    }
    const auto maximum =
        vfdual::build_final_peer_handshake_transcript_from_proposal_v1(
            *proposal.proposal, std::numeric_limits<std::int64_t>::max());
    CHECK(maximum.succeeded());

    const auto invalid = vector_fields();
    auto reflected = invalid;
    reflected.android_nonce = reflected.host_nonce;
    const auto error = vfdual::build_pair_generation_proposal_v1(reflected);
    CHECK(!error.succeeded());
    CHECK(std::string_view(vfdual::pair_generation_proposal_error_code_name(
        error.error.code)) == "invalid_nonce");
    CHECK(sizeof(error.error) == 2U);
}

[[nodiscard]] std::string read_source_file(const std::string& relative_path) {
    const std::string path =
        std::string(VFDUAL_SOURCE_DIR) + "/" + relative_path;
    std::ifstream input(path, std::ios::binary);
    CHECK(input.good());
    return {
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()};
}

void verify_noexcept_allocation_boundaries_source_contract() {
    static_assert(noexcept(vfdual::build_pair_generation_proposal_v1(
        std::declval<const vfdual::PairGenerationProposalFields&>())));
    static_assert(noexcept(vfdual::parse_pair_generation_proposal_v1(
        std::declval<std::span<const std::byte>>())));
    static_assert(noexcept(
        vfdual::build_final_peer_handshake_transcript_from_proposal_v1(
            std::declval<
                const vfdual::VerifiedPairGenerationProposalV1&>(),
            std::declval<std::int64_t>())));

    const std::string source = read_source_file(
        "shared/src/pair_generation_proposal_v1.cpp");
    const std::size_t validation_declaration = source.find(
        "PairGenerationProposalError validate_fields(");
    const std::size_t validation_body =
        source.find('{', validation_declaration);
    const std::size_t validation_noexcept =
        source.find("noexcept", validation_declaration);
    CHECK(validation_declaration != std::string::npos);
    CHECK(validation_body != std::string::npos);
    CHECK(validation_noexcept == std::string::npos ||
        validation_noexcept > validation_body);

    const std::size_t builder = source.find(
        "PairGenerationProposalResult build_pair_generation_proposal_v1(");
    const std::size_t builder_try = source.find("try {", builder);
    const std::size_t builder_validation =
        source.find("validate_fields(fields)", builder);
    CHECK(builder != std::string::npos);
    CHECK(builder_try != std::string::npos);
    CHECK(builder_validation != std::string::npos);
    CHECK(builder_try < builder_validation);

    const std::size_t final_helper = source.find(
        "build_final_peer_handshake_transcript_from_proposal_v1(");
    const std::size_t final_try = source.find("try {", final_helper);
    const std::size_t final_copy =
        source.find("final_fields_from_proposal(", final_helper);
    const std::size_t final_bad_alloc =
        source.find("catch (const std::bad_alloc&)", final_helper);
    const std::size_t final_allocation_error = source.find(
        "PeerHandshakeErrorCode::allocation_failed",
        final_bad_alloc);
    CHECK(final_helper != std::string::npos);
    CHECK(final_try != std::string::npos);
    CHECK(final_copy != std::string::npos);
    CHECK(final_bad_alloc != std::string::npos);
    CHECK(final_allocation_error != std::string::npos);
    CHECK(final_try < final_copy);
    CHECK(final_copy < final_bad_alloc);
    CHECK(final_bad_alloc < final_allocation_error);
}

}  // namespace

int main() {
    verify_frozen_vector_and_restricted_final_mapping();
    verify_strict_parser();
    verify_builder_boundaries();
    verify_generation_boundary_and_sanitized_errors();
    verify_noexcept_allocation_boundaries_source_contract();
    std::cout << "pair_generation_proposal_v1_tests: PASS\n";
    return 0;
}
