#if !defined(VFDUAL_ENABLE_AUTHENTICATED_PEER_HANDSHAKE_TEST_ACCESS)
#error "authenticated peer handshake tests require the isolated test-access seam"
#endif

#include "vfdual/authenticated_peer_handshake_v1.hpp"

#include <algorithm>
#include <array>
#include <barrier>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace vfdual {

struct AuthenticatedPeerHandshakeV1TestAccess final {
    [[nodiscard]] static std::unique_ptr<
        PlatformP256EphemeralKeyAgreementV1>
    import_private_key(
        const std::span<const std::byte, 32U> private_scalar_be,
        const std::span<
            const std::byte, kPeerHandshakeP256PublicKeyBytes> public_key,
        PeerHandshakeError& error) {
        return PlatformP256EphemeralKeyAgreementV1::import_test_private_key(
            private_scalar_be, public_key, error);
    }

    [[nodiscard]] static PeerHandshakeDigestResult derive_prk(
        const std::span<const std::byte, 32U> shared_secret_be,
        const std::span<const std::byte, 32U> transcript_sha256) {
        return PlatformP256EphemeralKeyAgreementV1::derive_test_prk(
            shared_secret_be, transcript_sha256);
    }

    [[nodiscard]] static PeerHandshakeDigestResult derive_shared_secret(
        const PlatformP256EphemeralKeyAgreementV1& local_key,
        const std::span<
            const std::byte, kPeerHandshakeP256PublicKeyBytes> peer_public_key) {
        return local_key.derive_test_shared_secret(peer_public_key);
    }

    [[nodiscard]] static PeerHandshakeError exercise_hkdf_expand(
        const std::size_t output_bytes) {
        return PlatformP256EphemeralKeyAgreementV1::
            exercise_test_hkdf_expand(output_bytes);
    }

    static void invalidate_platform_provider(
        PlatformP256EphemeralKeyAgreementV1& key_agreement) {
        key_agreement.invalidate_platform_provider_for_test();
    }

    [[nodiscard]] static std::span<const std::byte, 32U> finished_host_key(
        const ConfirmedPeerHandshakeSessionV1& secrets) {
        return secrets.finished_host_;
    }

    [[nodiscard]] static std::span<const std::byte, 32U>
    finished_android_key(const ConfirmedPeerHandshakeSessionV1& secrets) {
        return secrets.finished_android_;
    }

    [[nodiscard]] static std::span<const std::byte, 32U> exporter(
        const ConfirmedPeerHandshakeSessionV1& secrets) {
        return secrets.channel_binding_exporter_;
    }

    [[nodiscard]] static bool all_secret_storage_zero(
        const ConfirmedPeerHandshakeSessionV1& secrets) {
        const auto all_zero = [](const auto& bytes) {
            return std::all_of(
                bytes.begin(), bytes.end(), [](const std::byte value) {
                    return value == std::byte{0U};
                });
        };
        return all_zero(secrets.control_host_to_android_) &&
            all_zero(secrets.control_android_to_host_) &&
            all_zero(secrets.presence_host_to_android_) &&
            all_zero(secrets.video_host_to_android_) &&
            all_zero(secrets.idr_android_to_host_) &&
            all_zero(secrets.mouse_host_to_android_) &&
            all_zero(secrets.finished_host_) &&
            all_zero(secrets.finished_android_) &&
            all_zero(secrets.channel_binding_exporter_) &&
            all_zero(secrets.transcript_sha256_) &&
            all_zero(secrets.channel_binding_sha256_);
    }

    [[nodiscard]] static bool handshake_only_secrets_zero(
        const ConfirmedPeerHandshakeSessionV1& secrets) {
        const auto all_zero = [](const auto& bytes) {
            return std::all_of(
                bytes.begin(), bytes.end(), [](const std::byte value) {
                    return value == std::byte{0U};
                });
        };
        return all_zero(secrets.finished_host_) &&
            all_zero(secrets.finished_android_) &&
            all_zero(secrets.channel_binding_exporter_);
    }

    [[nodiscard]] static const ConfirmedPeerHandshakeSessionV1&
    unconfirmed_schedule(const PendingPeerHandshakeConfirmationV1& pending) {
        return *pending.unconfirmed_session_;
    }

    [[nodiscard]] static bool pending_is_closed_and_cleared(
        const PendingPeerHandshakeConfirmationV1& pending) {
        return pending.closed_ && pending.unconfirmed_session_ == nullptr &&
            !pending.local_finished_generated_;
    }
};

}  // namespace vfdual

namespace {

static_assert(!std::is_copy_constructible_v<
    vfdual::PlatformP256EphemeralKeyAgreementV1>);
static_assert(!std::is_copy_assignable_v<
    vfdual::PlatformP256EphemeralKeyAgreementV1>);
static_assert(std::is_move_constructible_v<
    vfdual::PlatformP256EphemeralKeyAgreementV1>);
static_assert(!std::is_default_constructible_v<
    vfdual::PlatformP256EphemeralKeyAgreementV1>);
static_assert(!std::is_copy_constructible_v<
    vfdual::ConfirmedPeerHandshakeSessionV1>);
static_assert(!std::is_copy_assignable_v<
    vfdual::ConfirmedPeerHandshakeSessionV1>);
static_assert(!std::is_move_constructible_v<
    vfdual::ConfirmedPeerHandshakeSessionV1>);
static_assert(!std::is_move_assignable_v<
    vfdual::ConfirmedPeerHandshakeSessionV1>);
static_assert(!std::is_default_constructible_v<
    vfdual::ConfirmedPeerHandshakeSessionV1>);
static_assert(!std::is_copy_constructible_v<
    vfdual::PendingPeerHandshakeConfirmationV1>);
static_assert(std::is_move_constructible_v<
    vfdual::PendingPeerHandshakeConfirmationV1>);

template <typename Type>
concept ExposesVideoTrafficMaterial = requires(const Type& value) {
    value.video_host_to_android();
};

template <typename Type>
concept ExposesChannelBinding = requires(const Type& value) {
    value.channel_binding_sha256();
};

static_assert(!ExposesVideoTrafficMaterial<
    vfdual::PendingPeerHandshakeConfirmationV1>);
static_assert(!ExposesChannelBinding<
    vfdual::PendingPeerHandshakeConfirmationV1>);
static_assert(ExposesVideoTrafficMaterial<
    vfdual::ConfirmedPeerHandshakeSessionV1>);
static_assert(ExposesChannelBinding<
    vfdual::ConfirmedPeerHandshakeSessionV1>);

void require(
    const bool condition,
    const char* expression,
    const char* file,
    const int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
    std::exit(EXIT_FAILURE);
}

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

[[nodiscard]] std::uint8_t hex_nibble(const char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(value - 'a' + 10);
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<std::uint8_t>(value - 'A' + 10);
    }
    CHECK(false);
    return 0U;
}

[[nodiscard]] std::vector<std::byte> bytes_from_hex(
    const std::string_view value) {
    CHECK(value.size() % 2U == 0U);
    std::vector<std::byte> result(value.size() / 2U);
    for (std::size_t index{}; index < result.size(); ++index) {
        result[index] = std::byte{static_cast<std::uint8_t>(
            (hex_nibble(value[index * 2U]) << 4U) |
            hex_nibble(value[index * 2U + 1U]))};
    }
    return result;
}

template <std::size_t Size>
[[nodiscard]] std::array<std::byte, Size> array_from_hex(
    const std::string_view value) {
    const auto decoded = bytes_from_hex(value);
    CHECK(decoded.size() == Size);
    std::array<std::byte, Size> result{};
    std::copy(decoded.begin(), decoded.end(), result.begin());
    return result;
}

[[nodiscard, maybe_unused]] std::vector<std::byte> concatenate(
    const vfdual::PeerHandshakeDataPlaneKeyView material) {
    std::vector<std::byte> result;
    result.reserve(
        material.aes_256_key.size() + material.nonce_prefix.size());
    result.insert(
        result.end(), material.aes_256_key.begin(), material.aes_256_key.end());
    result.insert(
        result.end(), material.nonce_prefix.begin(), material.nonce_prefix.end());
    return result;
}

template <typename Left, typename Right>
[[nodiscard]] bool bytes_equal(const Left& left, const Right& right) {
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin(), right.end());
}

[[nodiscard]] vfdual::PeerHandshakeP256PublicKey scalar_one_public_key() {
    return array_from_hex<vfdual::kPeerHandshakeP256PublicKeyBytes>(
        "046b17d1f2e12c4247f8bce6e563a440"
        "f277037d812deb33a0f4a13945d898c2"
        "964fe342e2fe1a7f9b8ee7eb4a7c0f9e"
        "162bce33576b315ececbb6406837bf51f5");
}

[[nodiscard]] vfdual::PeerHandshakeP256PublicKey scalar_two_public_key() {
    return array_from_hex<vfdual::kPeerHandshakeP256PublicKeyBytes>(
        "047cf27b188d034f7e8a52380304b51a"
        "c3c08969e277f21b35a60b48fc476699"
        "7807775510db8ed040293d9ac69f7430d"
        "bba7dade63ce982299e04b79d227873d1");
}

[[nodiscard]] vfdual::PeerHandshakeP256PublicKey scalar_379_public_key() {
    return array_from_hex<vfdual::kPeerHandshakeP256PublicKeyBytes>(
        "04005543894af3d00ed7d740abdbd75c"
        "96b06877b787db5f70eea78b90a8d7c0"
        "0abb4c85a3d8ea29efaafa24406912dd8"
        "4d5b14dc32bf656ef6c6bd58a5d943f92");
}

[[nodiscard, maybe_unused]] vfdual::PeerHandshakeP256PublicKey scalar_three_public_key() {
    return array_from_hex<vfdual::kPeerHandshakeP256PublicKeyBytes>(
        "045ecbe4d1a6330a44c8f7ef951d4bf1"
        "65e6c6b721efada985fb41661bc6e7fd6"
        "c8734640c4998ff7e374b06ce1a64a2e"
        "cd82ab036384fb83d9a79b127a27d5032");
}

[[nodiscard, maybe_unused]] std::array<std::byte, 32U> scalar(
    const std::uint16_t value) {
    std::array<std::byte, 32U> result{};
    result[30] = std::byte{static_cast<std::uint8_t>(value >> 8U)};
    result[31] = std::byte{static_cast<std::uint8_t>(value)};
    return result;
}

[[nodiscard]] vfdual::PeerHandshakeTranscriptFields vector_fields() {
    vfdual::PeerHandshakeTranscriptFields fields;
    for (std::size_t index{};
         index < fields.host_identity_spki_sha256.size();
         ++index) {
        fields.host_identity_spki_sha256[index] =
            std::byte{static_cast<std::uint8_t>(index)};
        fields.android_identity_spki_sha256[index] =
            std::byte{static_cast<std::uint8_t>(0x20U + index)};
        fields.host_nonce[index] =
            std::byte{static_cast<std::uint8_t>(0x40U + index)};
        fields.android_nonce[index] =
            std::byte{static_cast<std::uint8_t>(0x60U + index)};
    }
    fields.host_ephemeral_public_key = scalar_one_public_key();
    fields.android_ephemeral_public_key = scalar_two_public_key();
    fields.connection_id = 0x1020'3040'5060'7080ULL;
    fields.session_generation = 0x0102'0304'0506'0708ULL;
    fields.transport_kind = vfdual::PeerHandshakeTransportKind::cat6;
    fields.host_ipv4 = {
        std::byte{0xc0U}, std::byte{0xa8U},
        std::byte{0x37U}, std::byte{0x01U}};
    fields.android_ipv4 = {
        std::byte{0xc0U}, std::byte{0xa8U},
        std::byte{0x37U}, std::byte{0x02U}};
    fields.video_port = 45678U;
    fields.control_port = 45679U;
    fields.pair_id = "PAIR-2026_08.04";
    fields.host_runtime_version = "17.8.47";
    fields.android_runtime_version = "17.8.47";
    return fields;
}

[[nodiscard]] vfdual::PeerHandshakeTranscriptResult build_vector_transcript() {
    return vfdual::build_canonical_peer_handshake_transcript_v1(
        vector_fields(),
        vfdual::PeerHandshakePairIdRequirement::require_bound_pair);
}

void expect_build_error(
    const vfdual::PeerHandshakeTranscriptFields& fields,
    const vfdual::PeerHandshakeErrorCode expected,
    const vfdual::PeerHandshakePairIdRequirement requirement =
        vfdual::PeerHandshakePairIdRequirement::require_bound_pair) {
    const auto result = vfdual::build_canonical_peer_handshake_transcript_v1(
        fields, requirement);
    CHECK(!result.succeeded());
    CHECK(result.error.code == expected);
    CHECK(result.error.operation.find("PAIR-2026") == std::string_view::npos);
    CHECK(result.error.operation.find("17.8.47") == std::string_view::npos);
}

[[nodiscard]] std::uint32_t load_u32_be(
    const std::span<const std::byte> bytes) {
    CHECK(bytes.size() == 4U);
    std::uint32_t value{};
    for (const auto byte : bytes) {
        value = (value << 8U) | std::to_integer<std::uint8_t>(byte);
    }
    return value;
}

struct TlvRange final {
    std::size_t offset{};
    std::size_t bytes{};
};

[[nodiscard]] std::array<TlvRange, vfdual::kPeerHandshakeFieldCount>
tlv_ranges(const std::span<const std::byte> canonical) {
    std::array<TlvRange, vfdual::kPeerHandshakeFieldCount> result{};
    std::size_t offset{};
    while (offset < canonical.size()) {
        CHECK(canonical.size() - offset >= 5U);
        const std::uint8_t tag =
            std::to_integer<std::uint8_t>(canonical[offset]);
        CHECK(tag < result.size());
        const std::uint32_t length =
            load_u32_be(canonical.subspan(offset + 1U, 4U));
        CHECK(canonical.size() - offset >= 5U + length);
        result[tag] = {offset, 5U + length};
        offset += 5U + length;
    }
    return result;
}

[[nodiscard]] std::vector<std::byte> without_tlv(
    const std::span<const std::byte> canonical,
    const std::uint8_t tag) {
    const auto ranges = tlv_ranges(canonical);
    std::vector<std::byte> result(canonical.begin(), canonical.end());
    result.erase(
        result.begin() + static_cast<std::ptrdiff_t>(ranges[tag].offset),
        result.begin() + static_cast<std::ptrdiff_t>(
            ranges[tag].offset + ranges[tag].bytes));
    return result;
}

[[nodiscard]] std::vector<std::byte> with_swapped_tlvs(
    const std::span<const std::byte> canonical,
    const std::uint8_t first_tag,
    const std::uint8_t second_tag) {
    CHECK(first_tag + 1U == second_tag);
    const auto ranges = tlv_ranges(canonical);
    std::vector<std::byte> result;
    result.reserve(canonical.size());
    result.insert(
        result.end(),
        canonical.begin(),
        canonical.begin() + static_cast<std::ptrdiff_t>(ranges[first_tag].offset));
    result.insert(
        result.end(),
        canonical.begin() + static_cast<std::ptrdiff_t>(ranges[second_tag].offset),
        canonical.begin() + static_cast<std::ptrdiff_t>(
            ranges[second_tag].offset + ranges[second_tag].bytes));
    result.insert(
        result.end(),
        canonical.begin() + static_cast<std::ptrdiff_t>(ranges[first_tag].offset),
        canonical.begin() + static_cast<std::ptrdiff_t>(
            ranges[first_tag].offset + ranges[first_tag].bytes));
    result.insert(
        result.end(),
        canonical.begin() + static_cast<std::ptrdiff_t>(
            ranges[second_tag].offset + ranges[second_tag].bytes),
        canonical.end());
    return result;
}

[[maybe_unused]] void verify_frozen_transcript_vector() {
    const auto built = build_vector_transcript();
    CHECK(built.succeeded());
    CHECK(built.transcript->canonical_bytes().size() == 439U);
    const auto expected = bytes_from_hex(
        "000000001d766973696f6e666f7267652d706565722d68616e647368616b652d7631"
        "010000000400000001"
        "0200000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "0300000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "0400000041046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        "0500000041047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
        "0600000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        "0700000020606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        "08000000081020304050607080"
        "09000000080102030405060708"
        "0a0000000101"
        "0b00000004c0a83701"
        "0c00000004c0a83702"
        "0d00000002b26e"
        "0e00000002b26f"
        "0f0000000f504149522d323032365f30382e3034"
        "100000000731372e382e3437"
        "110000000731372e382e3437");
    CHECK(bytes_equal(built.transcript->canonical_bytes(), expected));
    CHECK(bytes_equal(
        built.transcript->transcript_sha256(),
        bytes_from_hex(
            "e90e31ad0d9399f36274e42248064fa3"
            "ef9f3f0d73e9e73f0ea0ce8aabd24117")));

    const auto parsed = vfdual::parse_canonical_peer_handshake_transcript_v1(
        expected,
        vfdual::PeerHandshakePairIdRequirement::require_bound_pair);
    CHECK(parsed.succeeded());
    CHECK(bytes_equal(
        parsed.transcript->canonical_bytes(),
        built.transcript->canonical_bytes()));
    CHECK(parsed.transcript->fields().connection_id ==
        0x1020'3040'5060'7080ULL);
    CHECK(parsed.transcript->fields().session_generation ==
        0x0102'0304'0506'0708ULL);
    CHECK(parsed.transcript->fields().video_port == 45678U);
    CHECK(parsed.transcript->fields().control_port == 45679U);
}

[[maybe_unused]] void verify_strict_tlv_rejections() {
    const auto built = build_vector_transcript();
    CHECK(built.succeeded());
    const auto canonical = built.transcript->canonical_bytes();
    const auto requirement =
        vfdual::PeerHandshakePairIdRequirement::require_bound_pair;

    auto missing = without_tlv(canonical, 2U);
    auto result = vfdual::parse_canonical_peer_handshake_transcript_v1(
        missing, requirement);
    CHECK(result.error.code == vfdual::PeerHandshakeErrorCode::missing_field);
    CHECK(result.error.field_tag == 2U);

    auto reordered = with_swapped_tlvs(canonical, 2U, 3U);
    result = vfdual::parse_canonical_peer_handshake_transcript_v1(
        reordered, requirement);
    CHECK(result.error.code ==
        vfdual::PeerHandshakeErrorCode::out_of_order_tag);

    const auto ranges = tlv_ranges(canonical);
    std::vector<std::byte> duplicate(canonical.begin(), canonical.end());
    duplicate.insert(
        duplicate.end(),
        canonical.begin() + static_cast<std::ptrdiff_t>(ranges[17].offset),
        canonical.end());
    result = vfdual::parse_canonical_peer_handshake_transcript_v1(
        duplicate, requirement);
    CHECK(result.error.code == vfdual::PeerHandshakeErrorCode::duplicate_tag);

    std::vector<std::byte> unknown(canonical.begin(), canonical.end());
    unknown.insert(
        unknown.end(),
        {std::byte{18U}, std::byte{0U}, std::byte{0U},
         std::byte{0U}, std::byte{0U}});
    result = vfdual::parse_canonical_peer_handshake_transcript_v1(
        unknown, requirement);
    CHECK(result.error.code == vfdual::PeerHandshakeErrorCode::unknown_tag);

    std::vector<std::byte> truncated(canonical.begin(), canonical.end() - 1);
    result = vfdual::parse_canonical_peer_handshake_transcript_v1(
        truncated, requirement);
    CHECK(result.error.code == vfdual::PeerHandshakeErrorCode::truncated_tlv);

    std::vector<std::byte> u32_max_length(canonical.begin(), canonical.end());
    const std::size_t length_offset = ranges[1].offset + 1U;
    std::fill_n(
        u32_max_length.begin() + static_cast<std::ptrdiff_t>(length_offset),
        4U,
        std::byte{0xffU});
    result = vfdual::parse_canonical_peer_handshake_transcript_v1(
        u32_max_length, requirement);
    CHECK(result.error.code == vfdual::PeerHandshakeErrorCode::truncated_tlv);

    std::vector<std::byte> too_large(
        vfdual::kPeerHandshakeMaximumCanonicalBytes + 1U, std::byte{0U});
    result = vfdual::parse_canonical_peer_handshake_transcript_v1(
        too_large, requirement);
    CHECK(result.error.code ==
        vfdual::PeerHandshakeErrorCode::transcript_too_large);

    std::vector<std::byte> invalid_domain(canonical.begin(), canonical.end());
    invalid_domain[ranges[0].offset + 5U] ^= std::byte{1U};
    result = vfdual::parse_canonical_peer_handshake_transcript_v1(
        invalid_domain, requirement);
    CHECK(result.error.code == vfdual::PeerHandshakeErrorCode::invalid_domain);

    std::vector<std::byte> unsupported_u32(canonical.begin(), canonical.end());
    std::fill_n(
        unsupported_u32.begin() + static_cast<std::ptrdiff_t>(
            ranges[1].offset + 5U),
        4U,
        std::byte{0xffU});
    result = vfdual::parse_canonical_peer_handshake_transcript_v1(
        unsupported_u32, requirement);
    CHECK(result.error.code ==
        vfdual::PeerHandshakeErrorCode::unsupported_protocol_version);

    std::vector<std::byte> compressed(canonical.begin(), canonical.end());
    const std::size_t ephemeral_offset = ranges[4].offset;
    compressed[ephemeral_offset + 4U] = std::byte{33U};
    compressed[ephemeral_offset + 5U] = std::byte{0x02U};
    compressed.erase(
        compressed.begin() + static_cast<std::ptrdiff_t>(
            ephemeral_offset + 5U + 33U),
        compressed.begin() + static_cast<std::ptrdiff_t>(
            ephemeral_offset + ranges[4].bytes));
    result = vfdual::parse_canonical_peer_handshake_transcript_v1(
        compressed, requirement);
    CHECK(result.error.code ==
        vfdual::PeerHandshakeErrorCode::invalid_field_length);

    std::vector<std::byte> infinity(canonical.begin(), canonical.end());
    infinity[ephemeral_offset + 4U] = std::byte{1U};
    infinity[ephemeral_offset + 5U] = std::byte{0x00U};
    infinity.erase(
        infinity.begin() + static_cast<std::ptrdiff_t>(
            ephemeral_offset + 6U),
        infinity.begin() + static_cast<std::ptrdiff_t>(
            ephemeral_offset + ranges[4].bytes));
    result = vfdual::parse_canonical_peer_handshake_transcript_v1(
        infinity, requirement);
    CHECK(result.error.code ==
        vfdual::PeerHandshakeErrorCode::invalid_field_length);
}

[[maybe_unused]] void verify_field_validation_boundaries() {
    auto fields = vector_fields();
    fields.host_identity_spki_sha256.fill(std::byte{0U});
    expect_build_error(
        fields, vfdual::PeerHandshakeErrorCode::invalid_identity_binding);
    fields = vector_fields();
    fields.android_identity_spki_sha256.fill(std::byte{0U});
    expect_build_error(
        fields, vfdual::PeerHandshakeErrorCode::invalid_identity_binding);
    fields = vector_fields();
    fields.host_identity_spki_sha256 = fields.android_identity_spki_sha256;
    expect_build_error(
        fields, vfdual::PeerHandshakeErrorCode::invalid_identity_binding);

    fields = vector_fields();
    fields.host_ephemeral_public_key[0] = std::byte{0x02U};
    expect_build_error(
        fields,
        vfdual::PeerHandshakeErrorCode::invalid_ephemeral_public_key);
    fields = vector_fields();
    fields.host_ephemeral_public_key[0] = std::byte{0x06U};
    expect_build_error(
        fields,
        vfdual::PeerHandshakeErrorCode::invalid_ephemeral_public_key);
    fields = vector_fields();
    fields.host_ephemeral_public_key[0] = std::byte{0x00U};
    expect_build_error(
        fields,
        vfdual::PeerHandshakeErrorCode::invalid_ephemeral_public_key);
    fields = vector_fields();
    std::fill(
        fields.host_ephemeral_public_key.begin() + 1,
        fields.host_ephemeral_public_key.end(),
        std::byte{0U});
    expect_build_error(
        fields,
        vfdual::PeerHandshakeErrorCode::invalid_ephemeral_public_key);
    const auto p256_prime = array_from_hex<32U>(
        "ffffffff000000010000000000000000"
        "00000000ffffffffffffffffffffffff");
    fields = vector_fields();
    std::copy(
        p256_prime.begin(),
        p256_prime.end(),
        fields.host_ephemeral_public_key.begin() + 1);
    expect_build_error(
        fields,
        vfdual::PeerHandshakeErrorCode::invalid_ephemeral_public_key);
    fields = vector_fields();
    std::copy(
        p256_prime.begin(),
        p256_prime.end(),
        fields.host_ephemeral_public_key.begin() + 33);
    expect_build_error(
        fields,
        vfdual::PeerHandshakeErrorCode::invalid_ephemeral_public_key);
    fields = vector_fields();
    fields.host_ephemeral_public_key.back() ^= std::byte{1U};
    expect_build_error(
        fields,
        vfdual::PeerHandshakeErrorCode::invalid_ephemeral_public_key);
    fields = vector_fields();
    fields.host_ephemeral_public_key = fields.android_ephemeral_public_key;
    expect_build_error(
        fields,
        vfdual::PeerHandshakeErrorCode::invalid_ephemeral_public_key);

    fields = vector_fields();
    fields.host_nonce.fill(std::byte{0U});
    expect_build_error(fields, vfdual::PeerHandshakeErrorCode::invalid_nonce);
    fields = vector_fields();
    fields.host_nonce = fields.android_nonce;
    expect_build_error(fields, vfdual::PeerHandshakeErrorCode::invalid_nonce);
    fields = vector_fields();
    fields.host_nonce.fill(std::byte{0U});
    fields.host_nonce.back() = std::byte{1U};
    CHECK(vfdual::build_canonical_peer_handshake_transcript_v1(
        fields,
        vfdual::PeerHandshakePairIdRequirement::require_bound_pair).succeeded());

    fields = vector_fields();
    fields.connection_id = 0U;
    expect_build_error(
        fields, vfdual::PeerHandshakeErrorCode::invalid_connection_id);
    fields = vector_fields();
    fields.session_generation = 0U;
    expect_build_error(
        fields, vfdual::PeerHandshakeErrorCode::invalid_session_generation);
    fields = vector_fields();
    fields.connection_id = std::numeric_limits<std::uint64_t>::max();
    fields.session_generation = std::numeric_limits<std::uint64_t>::max();
    CHECK(vfdual::build_canonical_peer_handshake_transcript_v1(
        fields,
        vfdual::PeerHandshakePairIdRequirement::require_bound_pair).succeeded());

    fields = vector_fields();
    fields.transport_kind =
        static_cast<vfdual::PeerHandshakeTransportKind>(0U);
    expect_build_error(
        fields, vfdual::PeerHandshakeErrorCode::invalid_transport_kind);
    fields = vector_fields();
    fields.video_port = 0U;
    expect_build_error(fields, vfdual::PeerHandshakeErrorCode::invalid_endpoint);
    fields = vector_fields();
    fields.control_port = fields.video_port;
    expect_build_error(fields, vfdual::PeerHandshakeErrorCode::invalid_endpoint);

    fields = vector_fields();
    fields.pair_id.clear();
    CHECK(vfdual::build_canonical_peer_handshake_transcript_v1(
        fields,
        vfdual::PeerHandshakePairIdRequirement::allow_empty_before_activation)
        .succeeded());
    expect_build_error(
        fields,
        vfdual::PeerHandshakeErrorCode::invalid_pair_id,
        vfdual::PeerHandshakePairIdRequirement::require_bound_pair);
    fields = vector_fields();
    fields.pair_id.assign(vfdual::kPeerHandshakeMaximumPairIdBytes, 'A');
    fields.host_runtime_version = "1234567890.1234567890.1234567890";
    fields.android_runtime_version = "1234567890.1234567890.1234567890";
    const auto all_maximum_fields =
        vfdual::build_canonical_peer_handshake_transcript_v1(
            fields,
            vfdual::PeerHandshakePairIdRequirement::require_bound_pair);
    CHECK(all_maximum_fields.succeeded());
    CHECK(all_maximum_fields.transcript->canonical_bytes().size() ==
        vfdual::kPeerHandshakeMaximumCanonicalBytes);
    CHECK(vfdual::build_canonical_peer_handshake_transcript_v1(
        fields,
        vfdual::PeerHandshakePairIdRequirement::require_bound_pair).succeeded());
    fields.pair_id.push_back('A');
    expect_build_error(fields, vfdual::PeerHandshakeErrorCode::invalid_pair_id);
    fields = vector_fields();
    fields.pair_id = "PAIR/INVALID";
    expect_build_error(fields, vfdual::PeerHandshakeErrorCode::invalid_pair_id);
    fields = vector_fields();
    fields.pair_id = std::string("PAIR\0ID", 7U);
    expect_build_error(fields, vfdual::PeerHandshakeErrorCode::invalid_pair_id);

    constexpr std::array<std::string_view, 13U> invalid_versions{
        "", "1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.03",
        "v1.2.3", "1.2.3-alpha", "1.2.3+build", " 1.2.3",
        "1.2.3 ", "1.2.x"};
    for (const auto invalid : invalid_versions) {
        fields = vector_fields();
        fields.host_runtime_version = invalid;
        expect_build_error(
            fields,
            vfdual::PeerHandshakeErrorCode::invalid_runtime_version);
    }
    fields = vector_fields();
    fields.host_runtime_version = "1234567890.1234567890.1234567890";
    fields.android_runtime_version = "0.0.0";
    CHECK(fields.host_runtime_version.size() ==
        vfdual::kPeerHandshakeMaximumRuntimeVersionBytes);
    CHECK(vfdual::build_canonical_peer_handshake_transcript_v1(
        fields,
        vfdual::PeerHandshakePairIdRequirement::require_bound_pair).succeeded());

    fields = vector_fields();
    fields.domain = "visionforge-peer-handshake-v2";
    expect_build_error(fields, vfdual::PeerHandshakeErrorCode::invalid_domain);
    fields = vector_fields();
    fields.protocol_version = std::numeric_limits<std::uint32_t>::max();
    expect_build_error(
        fields,
        vfdual::PeerHandshakeErrorCode::unsupported_protocol_version);
    fields = vector_fields();
    expect_build_error(
        fields,
        vfdual::PeerHandshakeErrorCode::invalid_pair_id_requirement,
        static_cast<vfdual::PeerHandshakePairIdRequirement>(0U));
}

[[maybe_unused]] void verify_every_accepted_field_mutation_changes_transcript_hash() {
    const auto baseline = build_vector_transcript();
    CHECK(baseline.succeeded());
    std::vector<vfdual::PeerHandshakeTranscriptFields> mutations;
    auto fields = vector_fields();
    fields.host_identity_spki_sha256[0] ^= std::byte{1U};
    mutations.push_back(fields);
    fields = vector_fields();
    fields.android_identity_spki_sha256[0] ^= std::byte{1U};
    mutations.push_back(fields);
    fields = vector_fields();
    fields.host_ephemeral_public_key = scalar_379_public_key();
    mutations.push_back(fields);
    fields = vector_fields();
    fields.android_ephemeral_public_key = scalar_379_public_key();
    mutations.push_back(fields);
    fields = vector_fields();
    fields.host_nonce[0] ^= std::byte{1U};
    mutations.push_back(fields);
    fields = vector_fields();
    fields.android_nonce[0] ^= std::byte{1U};
    mutations.push_back(fields);
    fields = vector_fields();
    ++fields.connection_id;
    mutations.push_back(fields);
    fields = vector_fields();
    ++fields.session_generation;
    mutations.push_back(fields);
    fields = vector_fields();
    fields.transport_kind = vfdual::PeerHandshakeTransportKind::wlan;
    mutations.push_back(fields);
    fields = vector_fields();
    fields.host_ipv4.back() ^= std::byte{1U};
    mutations.push_back(fields);
    fields = vector_fields();
    fields.android_ipv4.back() ^= std::byte{1U};
    mutations.push_back(fields);
    fields = vector_fields();
    --fields.video_port;
    mutations.push_back(fields);
    fields = vector_fields();
    ++fields.control_port;
    mutations.push_back(fields);
    fields = vector_fields();
    fields.pair_id += "-NEXT";
    mutations.push_back(fields);
    fields = vector_fields();
    fields.host_runtime_version = "17.8.48";
    mutations.push_back(fields);
    fields = vector_fields();
    fields.android_runtime_version = "17.8.48";
    mutations.push_back(fields);

    for (const auto& mutation : mutations) {
        const auto changed =
            vfdual::build_canonical_peer_handshake_transcript_v1(
                mutation,
                vfdual::PeerHandshakePairIdRequirement::require_bound_pair);
        CHECK(changed.succeeded());
        CHECK(changed.transcript->transcript_sha256() !=
            baseline.transcript->transcript_sha256());
    }
}

#if defined(_WIN32)

struct VectorKeyPair final {
    std::unique_ptr<vfdual::PlatformP256EphemeralKeyAgreementV1> host;
    std::unique_ptr<vfdual::PlatformP256EphemeralKeyAgreementV1> android;
};

[[nodiscard]] VectorKeyPair import_vector_keys() {
    vfdual::PeerHandshakeError error;
    auto host = vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        import_private_key(scalar(1U), scalar_one_public_key(), error);
    CHECK(host != nullptr);
    CHECK(!error.has_error());
    auto android = vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        import_private_key(scalar(2U), scalar_two_public_key(), error);
    CHECK(android != nullptr);
    CHECK(!error.has_error());
    return {std::move(host), std::move(android)};
}

struct PendingPair final {
    std::unique_ptr<vfdual::PendingPeerHandshakeConfirmationV1> host;
    std::unique_ptr<vfdual::PendingPeerHandshakeConfirmationV1> android;
    vfdual::PeerHandshakeSha256 host_finished{};
    vfdual::PeerHandshakeSha256 android_finished{};
};

[[nodiscard]] PendingPair derive_pending_pair(
    VectorKeyPair& keys,
    const vfdual::CanonicalPeerHandshakeTranscriptV1& transcript) {
    vfdual::PeerHandshakeError error;
    auto host = keys.host->derive_pending_after_peer_identity_verified(
        vfdual::PeerHandshakeRole::host, transcript, error);
    CHECK(host != nullptr);
    CHECK(!error.has_error());
    auto android = keys.android->derive_pending_after_peer_identity_verified(
        vfdual::PeerHandshakeRole::android, transcript, error);
    CHECK(android != nullptr);
    CHECK(!error.has_error());
    CHECK(host->local_role() == vfdual::PeerHandshakeRole::host);
    CHECK(android->local_role() == vfdual::PeerHandshakeRole::android);
    const auto host_finished = host->create_local_finished_mac();
    const auto android_finished = android->create_local_finished_mac();
    CHECK(host_finished.succeeded());
    CHECK(android_finished.succeeded());
    return {
        std::move(host),
        std::move(android),
        *host_finished.digest,
        *android_finished.digest,
    };
}

struct ConfirmedPair final {
    std::unique_ptr<vfdual::ConfirmedPeerHandshakeSessionV1> host;
    std::unique_ptr<vfdual::ConfirmedPeerHandshakeSessionV1> android;
};

[[nodiscard]] ConfirmedPair confirm_pending_pair(PendingPair pending) {
    auto host_result = std::move(*pending.host)
        .confirm_peer_finished_and_consume(pending.android_finished);
    CHECK(host_result.peer_finished_accepted());
    CHECK(!host_result.error.has_error());
    auto android_result = std::move(*pending.android)
        .confirm_peer_finished_and_consume(pending.host_finished);
    CHECK(android_result.peer_finished_accepted());
    CHECK(!android_result.error.has_error());
    CHECK(host_result.confirmed_session->local_role() ==
        vfdual::PeerHandshakeRole::host);
    CHECK(android_result.confirmed_session->local_role() ==
        vfdual::PeerHandshakeRole::android);
    return {
        std::move(host_result.confirmed_session),
        std::move(android_result.confirmed_session),
    };
}

void check_vector_confirmed_material(
    const vfdual::ConfirmedPeerHandshakeSessionV1& secrets) {
    CHECK(bytes_equal(
        concatenate(secrets.control_host_to_android()),
        bytes_from_hex(
            "0f4714afae44c3000fe5fcdca61f2a42"
            "094e5d7b75ae35e7b0b8ddefd5e7a2ffcd8ec73d")));
    CHECK(bytes_equal(
        concatenate(secrets.control_android_to_host()),
        bytes_from_hex(
            "7e5d8ae1483a45162434aa0b7d125e71"
            "e5785c1a961b4796e5495d1329ee23d277bb26ac")));
    CHECK(bytes_equal(
        concatenate(secrets.presence_host_to_android()),
        bytes_from_hex(
            "172a609bf56696232b79bed3a13373ce"
            "79a7aa33a24878c427923a421b5425ec69865a7e")));
    CHECK(bytes_equal(
        concatenate(secrets.video_host_to_android()),
        bytes_from_hex(
            "5abce1e7877c4894688bf65e5ad0df08"
            "b6a1ab597155df19ae049222de2fe2a8a9a2618c")));
    CHECK(bytes_equal(
        concatenate(secrets.idr_android_to_host()),
        bytes_from_hex(
            "857be929d83a3e3fd56f8c21dec1db5b"
            "07e9d46b1550376b36042f4622519dee0b9cb385")));
    CHECK(bytes_equal(
        concatenate(secrets.mouse_host_to_android()),
        bytes_from_hex(
            "521dd222ba6d023752df2704eefb5d82"
            "b4218705922f70d81238d68c984cb6ec17b59d00")));
    CHECK(bytes_equal(
        secrets.channel_binding_sha256(),
        bytes_from_hex(
            "5238342449e1585fe95db78cf437a47d"
            "386d0e2cf895a751053afa0cc431a98b")));
}

void check_vector_unconfirmed_handshake_secrets(
    const vfdual::ConfirmedPeerHandshakeSessionV1& secrets) {
    CHECK(bytes_equal(
        vfdual::AuthenticatedPeerHandshakeV1TestAccess::finished_host_key(
            secrets),
        bytes_from_hex(
            "51391a6d16c2a0d15e2a6d0d41647091"
            "627d9d1035f6df979c18131ad552dddb")));
    CHECK(bytes_equal(
        vfdual::AuthenticatedPeerHandshakeV1TestAccess::finished_android_key(
            secrets),
        bytes_from_hex(
            "943c2f631e1f2e862d059ba0b19e2283"
            "14a149ab6076ea36aac179afe5ce6eaa")));
    CHECK(bytes_equal(
        vfdual::AuthenticatedPeerHandshakeV1TestAccess::exporter(secrets),
        bytes_from_hex(
            "226bd61eff3f8a9c097beefca9bcd9c4"
            "3c4b28019f16c8e99c03f70d0a0e33d2")));
}

void verify_ecdh_hkdf_finished_and_channel_binding_vector() {
    const auto transcript = build_vector_transcript();
    CHECK(transcript.succeeded());
    auto raw_vector_keys = import_vector_keys();

    const auto expected_shared = array_from_hex<32U>(
        "7cf27b188d034f7e8a52380304b51ac3"
        "c08969e277f21b35a60b48fc47669978");
    const auto host_shared =
        vfdual::AuthenticatedPeerHandshakeV1TestAccess::derive_shared_secret(
            *raw_vector_keys.host,
            raw_vector_keys.android->public_key_sec1());
    const auto android_shared =
        vfdual::AuthenticatedPeerHandshakeV1TestAccess::derive_shared_secret(
            *raw_vector_keys.android,
            raw_vector_keys.host->public_key_sec1());
    CHECK(host_shared.succeeded());
    CHECK(android_shared.succeeded());
    CHECK(*host_shared.digest == expected_shared);
    CHECK(*android_shared.digest == expected_shared);

    const auto prk =
        vfdual::AuthenticatedPeerHandshakeV1TestAccess::derive_prk(
            expected_shared, transcript.transcript->transcript_sha256());
    CHECK(prk.succeeded());
    CHECK(bytes_equal(
        *prk.digest,
        bytes_from_hex(
            "aa864bd95772a3a4a544ccd5fa23b588"
            "1dab0462e1439d23d04b5a19dac4e7e0")));

    auto handshake_keys = import_vector_keys();
    auto pending = derive_pending_pair(
        handshake_keys, *transcript.transcript);
    const auto& host_unconfirmed =
        vfdual::AuthenticatedPeerHandshakeV1TestAccess::
            unconfirmed_schedule(*pending.host);
    const auto& android_unconfirmed =
        vfdual::AuthenticatedPeerHandshakeV1TestAccess::
            unconfirmed_schedule(*pending.android);
    check_vector_confirmed_material(host_unconfirmed);
    check_vector_unconfirmed_handshake_secrets(host_unconfirmed);
    check_vector_confirmed_material(android_unconfirmed);
    check_vector_unconfirmed_handshake_secrets(android_unconfirmed);
    CHECK(bytes_equal(
        pending.host_finished,
        bytes_from_hex(
            "c55b5a1bb27b4d841cd71e246c57dd16"
            "6c90fbd10703be001e1ae8367e360f2e")));
    CHECK(bytes_equal(
        pending.android_finished,
        bytes_from_hex(
            "4eaa3269be3d699c74458b4ecf2336ac"
            "67b6275f504f03d24a5180c31622ded6")));

    auto confirmed = confirm_pending_pair(std::move(pending));
    check_vector_confirmed_material(*confirmed.host);
    check_vector_confirmed_material(*confirmed.android);
    CHECK(vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        handshake_only_secrets_zero(*confirmed.host));
    CHECK(vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        handshake_only_secrets_zero(*confirmed.android));
    CHECK(bytes_equal(
        concatenate(confirmed.host->control_host_to_android()),
        concatenate(confirmed.android->control_host_to_android())));

}

void verify_pending_finished_gate_is_typed_and_fail_closed() {
    const auto transcript = build_vector_transcript();
    CHECK(transcript.succeeded());
    vfdual::PeerHandshakeError error;

    auto before_local_keys = import_vector_keys();
    auto before_local = before_local_keys.host->
        derive_pending_after_peer_identity_verified(
            vfdual::PeerHandshakeRole::host,
            *transcript.transcript,
            error);
    CHECK(before_local != nullptr);
    const vfdual::PeerHandshakeSha256 arbitrary_mac{};
    auto before_local_result = std::move(*before_local)
        .confirm_peer_finished_and_consume(arbitrary_mac);
    CHECK(!before_local_result.peer_finished_accepted());
    CHECK(before_local_result.error.code ==
        vfdual::PeerHandshakeErrorCode::local_finished_not_generated);
    CHECK(vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        pending_is_closed_and_cleared(*before_local));

    auto wrong_keys = import_vector_keys();
    auto wrong_pending = derive_pending_pair(
        wrong_keys, *transcript.transcript);
    auto wrong_peer_finished = wrong_pending.android_finished;
    wrong_peer_finished[0] ^= std::byte{1U};
    auto wrong_result = std::move(*wrong_pending.host)
        .confirm_peer_finished_and_consume(wrong_peer_finished);
    CHECK(!wrong_result.peer_finished_accepted());
    CHECK(wrong_result.confirmed_session == nullptr);
    CHECK(wrong_result.error.code ==
        vfdual::PeerHandshakeErrorCode::peer_finished_authentication_failed);
    CHECK(vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        pending_is_closed_and_cleared(*wrong_pending.host));
    CHECK(wrong_pending.host->create_local_finished_mac().error.code ==
        vfdual::PeerHandshakeErrorCode::pending_confirmation_closed);
    auto closed_retry = std::move(*wrong_pending.host)
        .confirm_peer_finished_and_consume(wrong_pending.android_finished);
    CHECK(!closed_retry.peer_finished_accepted());
    CHECK(closed_retry.error.code ==
        vfdual::PeerHandshakeErrorCode::pending_confirmation_closed);

    auto short_keys = import_vector_keys();
    auto short_pending = derive_pending_pair(
        short_keys, *transcript.transcript);
    auto short_result = std::move(*short_pending.host)
        .confirm_peer_finished_and_consume(
            std::span<const std::byte>{short_pending.android_finished}
                .first(31U));
    CHECK(!short_result.peer_finished_accepted());
    CHECK(short_result.error.code ==
        vfdual::PeerHandshakeErrorCode::peer_finished_authentication_failed);
    CHECK(vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        pending_is_closed_and_cleared(*short_pending.host));
}

void verify_pairing_only_transcript_cannot_release_key_material() {
    auto fields = vector_fields();
    fields.pair_id.clear();
    const auto pairing_only =
        vfdual::build_canonical_peer_handshake_transcript_v1(
            fields,
            vfdual::PeerHandshakePairIdRequirement::
                allow_empty_before_activation);
    CHECK(pairing_only.succeeded());
    vfdual::PeerHandshakeError error;
    auto host = vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        import_private_key(scalar(1U), scalar_one_public_key(), error);
    CHECK(host != nullptr);
    CHECK(host->derive_pending_after_peer_identity_verified(
        vfdual::PeerHandshakeRole::host,
        *pairing_only.transcript,
        error) == nullptr);
    CHECK(error.code ==
        vfdual::PeerHandshakeErrorCode::
            pair_binding_required_for_key_derivation);
    const auto bound = build_vector_transcript();
    CHECK(bound.succeeded());
    CHECK(host->derive_pending_after_peer_identity_verified(
        vfdual::PeerHandshakeRole::host,
        *bound.transcript,
        error) == nullptr);
    CHECK(error.code ==
        vfdual::PeerHandshakeErrorCode::ephemeral_private_key_already_consumed);
}

void verify_ephemeral_private_key_is_one_shot_on_all_attempts() {
    const auto transcript = build_vector_transcript();
    CHECK(transcript.succeeded());
    vfdual::PeerHandshakeError error;
    auto host = vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        import_private_key(scalar(1U), scalar_one_public_key(), error);
    CHECK(host != nullptr);
    auto pending = host->derive_pending_after_peer_identity_verified(
        vfdual::PeerHandshakeRole::host,
        *transcript.transcript,
        error);
    CHECK(pending != nullptr);
    CHECK(host->derive_pending_after_peer_identity_verified(
        vfdual::PeerHandshakeRole::host,
        *transcript.transcript,
        error) == nullptr);
    CHECK(error.code ==
        vfdual::PeerHandshakeErrorCode::ephemeral_private_key_already_consumed);

    auto provider_failure_key =
        vfdual::AuthenticatedPeerHandshakeV1TestAccess::import_private_key(
            scalar(1U), scalar_one_public_key(), error);
    CHECK(provider_failure_key != nullptr);
    vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        invalidate_platform_provider(*provider_failure_key);
    CHECK(provider_failure_key->derive_pending_after_peer_identity_verified(
        vfdual::PeerHandshakeRole::host,
        *transcript.transcript,
        error) == nullptr);
    CHECK(error.code ==
        vfdual::PeerHandshakeErrorCode::crypto_operation_failed);
    CHECK(provider_failure_key->derive_pending_after_peer_identity_verified(
        vfdual::PeerHandshakeRole::host,
        *transcript.transcript,
        error) == nullptr);
    CHECK(error.code ==
        vfdual::PeerHandshakeErrorCode::ephemeral_private_key_already_consumed);

    auto concurrent_key =
        vfdual::AuthenticatedPeerHandshakeV1TestAccess::import_private_key(
            scalar(1U), scalar_one_public_key(), error);
    CHECK(concurrent_key != nullptr);
    std::array<std::unique_ptr<
        vfdual::PendingPeerHandshakeConfirmationV1>, 2U> concurrent_results;
    std::array<vfdual::PeerHandshakeError, 2U> concurrent_errors;
    std::barrier start_line(3);
    const auto race_attempt = [&](const std::size_t index) {
        start_line.arrive_and_wait();
        concurrent_results[index] = concurrent_key->
            derive_pending_after_peer_identity_verified(
                vfdual::PeerHandshakeRole::host,
                *transcript.transcript,
                concurrent_errors[index]);
    };
    std::thread first_attempt(race_attempt, 0U);
    std::thread second_attempt(race_attempt, 1U);
    start_line.arrive_and_wait();
    first_attempt.join();
    second_attempt.join();
    const std::size_t success_count =
        static_cast<std::size_t>(concurrent_results[0] != nullptr) +
        static_cast<std::size_t>(concurrent_results[1] != nullptr);
    CHECK(success_count == 1U);
    const std::size_t rejected_index = concurrent_results[0] == nullptr
        ? 0U : 1U;
    CHECK(concurrent_errors[rejected_index].code ==
        vfdual::PeerHandshakeErrorCode::ephemeral_private_key_already_consumed);
}

void verify_leading_zero_ecdh_secret_is_preserved_as_be32() {
    vfdual::PeerHandshakeError error;
    auto raw_host = vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        import_private_key(scalar(1U), scalar_one_public_key(), error);
    CHECK(raw_host != nullptr);
    auto raw_android = vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        import_private_key(scalar(379U), scalar_379_public_key(), error);
    CHECK(raw_android != nullptr);
    const auto expected = array_from_hex<32U>(
        "005543894af3d00ed7d740abdbd75c96"
        "b06877b787db5f70eea78b90a8d7c00a");
    const auto host_shared =
        vfdual::AuthenticatedPeerHandshakeV1TestAccess::derive_shared_secret(
            *raw_host, raw_android->public_key_sec1());
    const auto android_shared =
        vfdual::AuthenticatedPeerHandshakeV1TestAccess::derive_shared_secret(
            *raw_android, raw_host->public_key_sec1());
    CHECK(host_shared.succeeded());
    CHECK(android_shared.succeeded());
    CHECK(*host_shared.digest == expected);
    CHECK(*android_shared.digest == expected);
    CHECK(host_shared.digest->front() == std::byte{0U});

    auto fields = vector_fields();
    fields.android_ephemeral_public_key = scalar_379_public_key();
    const auto transcript =
        vfdual::build_canonical_peer_handshake_transcript_v1(
            fields,
            vfdual::PeerHandshakePairIdRequirement::require_bound_pair);
    CHECK(transcript.succeeded());
    auto host = vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        import_private_key(scalar(1U), scalar_one_public_key(), error);
    auto android = vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        import_private_key(scalar(379U), scalar_379_public_key(), error);
    CHECK(host != nullptr);
    CHECK(android != nullptr);
    VectorKeyPair handshake_keys{std::move(host), std::move(android)};
    auto confirmed = confirm_pending_pair(derive_pending_pair(
        handshake_keys, *transcript.transcript));
    CHECK(bytes_equal(
        concatenate(confirmed.host->control_host_to_android()),
        concatenate(confirmed.android->control_host_to_android())));
}

void verify_cross_session_and_role_binding() {
    const auto first = build_vector_transcript();
    CHECK(first.succeeded());
    auto second_fields = vector_fields();
    second_fields.host_ephemeral_public_key = scalar_379_public_key();
    second_fields.android_ephemeral_public_key = scalar_three_public_key();
    ++second_fields.connection_id;
    ++second_fields.session_generation;
    second_fields.host_nonce[0] ^= std::byte{0x80U};
    second_fields.android_nonce[0] ^= std::byte{0x80U};
    const auto second = vfdual::build_canonical_peer_handshake_transcript_v1(
        second_fields,
        vfdual::PeerHandshakePairIdRequirement::require_bound_pair);
    CHECK(second.succeeded());
    vfdual::PeerHandshakeError error;

    auto first_keys = import_vector_keys();
    auto first_pending = derive_pending_pair(first_keys, *first.transcript);
    const auto first_host_finished = first_pending.host_finished;
    auto first_confirmed = confirm_pending_pair(std::move(first_pending));

    auto make_second_keys = [&error]() {
        auto host = vfdual::AuthenticatedPeerHandshakeV1TestAccess::
            import_private_key(
                scalar(379U), scalar_379_public_key(), error);
        CHECK(host != nullptr);
        auto android = vfdual::AuthenticatedPeerHandshakeV1TestAccess::
            import_private_key(
                scalar(3U), scalar_three_public_key(), error);
        CHECK(android != nullptr);
        return VectorKeyPair{std::move(host), std::move(android)};
    };
    auto mismatch_second_keys = make_second_keys();
    auto mismatch_pending = derive_pending_pair(
        mismatch_second_keys, *second.transcript);
    auto rejected = std::move(*mismatch_pending.android)
        .confirm_peer_finished_and_consume(first_host_finished);
    CHECK(!rejected.peer_finished_accepted());
    CHECK(rejected.error.code ==
        vfdual::PeerHandshakeErrorCode::peer_finished_authentication_failed);
    CHECK(vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        pending_is_closed_and_cleared(*mismatch_pending.android));

    auto second_keys = make_second_keys();
    auto second_confirmed = confirm_pending_pair(derive_pending_pair(
        second_keys, *second.transcript));
    CHECK(first_confirmed.host->channel_binding_sha256() !=
        second_confirmed.host->channel_binding_sha256());
    CHECK(!bytes_equal(
        concatenate(first_confirmed.host->video_host_to_android()),
        concatenate(second_confirmed.host->video_host_to_android())));

    auto mismatch_fields = vector_fields();
    mismatch_fields.host_ephemeral_public_key = scalar_379_public_key();
    const auto mismatch = vfdual::build_canonical_peer_handshake_transcript_v1(
        mismatch_fields,
        vfdual::PeerHandshakePairIdRequirement::require_bound_pair);
    CHECK(mismatch.succeeded());
    auto mismatch_key = vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        import_private_key(scalar(1U), scalar_one_public_key(), error);
    CHECK(mismatch_key != nullptr);
    CHECK(mismatch_key->derive_pending_after_peer_identity_verified(
        vfdual::PeerHandshakeRole::host,
        *mismatch.transcript,
        error) == nullptr);
    CHECK(error.code ==
        vfdual::PeerHandshakeErrorCode::local_ephemeral_key_mismatch);
    CHECK(mismatch_key->derive_pending_after_peer_identity_verified(
        vfdual::PeerHandshakeRole::host,
        *first.transcript,
        error) == nullptr);
    CHECK(error.code ==
        vfdual::PeerHandshakeErrorCode::ephemeral_private_key_already_consumed);

    auto invalid_role_key = vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        import_private_key(scalar(1U), scalar_one_public_key(), error);
    CHECK(invalid_role_key != nullptr);
    CHECK(invalid_role_key->derive_pending_after_peer_identity_verified(
        static_cast<vfdual::PeerHandshakeRole>(0U),
        *first.transcript,
        error) == nullptr);
    CHECK(error.code == vfdual::PeerHandshakeErrorCode::invalid_role);
    CHECK(invalid_role_key->derive_pending_after_peer_identity_verified(
        vfdual::PeerHandshakeRole::host,
        *first.transcript,
        error) == nullptr);
    CHECK(error.code ==
        vfdual::PeerHandshakeErrorCode::ephemeral_private_key_already_consumed);
}

void verify_hkdf_limit_and_independent_domains() {
    CHECK(!vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        exercise_hkdf_expand(vfdual::kHkdfSha256MaximumOutputBytes)
        .has_error());
    CHECK(vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        exercise_hkdf_expand(vfdual::kHkdfSha256MaximumOutputBytes + 1U)
        .code == vfdual::PeerHandshakeErrorCode::hkdf_output_too_large);
    CHECK(vfdual::AuthenticatedPeerHandshakeV1TestAccess::
        exercise_hkdf_expand(std::numeric_limits<std::size_t>::max())
        .code == vfdual::PeerHandshakeErrorCode::hkdf_output_too_large);

    const auto transcript = build_vector_transcript();
    auto keys = import_vector_keys();
    auto confirmed = confirm_pending_pair(derive_pending_pair(
        keys, *transcript.transcript));
    const auto& secrets = *confirmed.host;
    const std::array<std::vector<std::byte>, 6U> traffic_domains{
        concatenate(secrets.control_host_to_android()),
        concatenate(secrets.control_android_to_host()),
        concatenate(secrets.presence_host_to_android()),
        concatenate(secrets.video_host_to_android()),
        concatenate(secrets.idr_android_to_host()),
        concatenate(secrets.mouse_host_to_android()),
    };
    for (std::size_t left{}; left < traffic_domains.size(); ++left) {
        for (std::size_t right = left + 1U;
             right < traffic_domains.size();
             ++right) {
            CHECK(traffic_domains[left] != traffic_domains[right]);
        }
    }
}

void verify_fresh_platform_factory_has_no_static_key_reuse() {
    vfdual::PeerHandshakeError error;
    auto host = vfdual::PlatformP256EphemeralKeyAgreementV1::generate_platform(
        error);
    CHECK(host != nullptr);
    CHECK(!error.has_error());
    auto android =
        vfdual::PlatformP256EphemeralKeyAgreementV1::generate_platform(error);
    CHECK(android != nullptr);
    CHECK(!error.has_error());
    CHECK(!bytes_equal(host->public_key_sec1(), android->public_key_sec1()));

    auto fields = vector_fields();
    std::copy(
        host->public_key_sec1().begin(),
        host->public_key_sec1().end(),
        fields.host_ephemeral_public_key.begin());
    std::copy(
        android->public_key_sec1().begin(),
        android->public_key_sec1().end(),
        fields.android_ephemeral_public_key.begin());
    const auto transcript =
        vfdual::build_canonical_peer_handshake_transcript_v1(
            fields,
            vfdual::PeerHandshakePairIdRequirement::require_bound_pair);
    CHECK(transcript.succeeded());
    VectorKeyPair generated_keys{std::move(host), std::move(android)};
    auto confirmed = confirm_pending_pair(derive_pending_pair(
        generated_keys, *transcript.transcript));
    CHECK(bytes_equal(
        concatenate(confirmed.host->video_host_to_android()),
        concatenate(confirmed.android->video_host_to_android())));
}

#else

void verify_unsupported_platform_fails_closed() {
    vfdual::PeerHandshakeError error;
    CHECK(vfdual::PlatformP256EphemeralKeyAgreementV1::generate_platform(
        error) == nullptr);
    CHECK(error.code ==
        vfdual::PeerHandshakeErrorCode::platform_crypto_unavailable);
    const auto transcript = build_vector_transcript();
    CHECK(!transcript.succeeded());
    CHECK(transcript.error.code ==
        vfdual::PeerHandshakeErrorCode::platform_crypto_unavailable);
}

#endif

}  // namespace

int main() {
#if defined(_WIN32)
    verify_frozen_transcript_vector();
    verify_strict_tlv_rejections();
    verify_field_validation_boundaries();
    verify_every_accepted_field_mutation_changes_transcript_hash();
    verify_ecdh_hkdf_finished_and_channel_binding_vector();
    verify_pending_finished_gate_is_typed_and_fail_closed();
    verify_pairing_only_transcript_cannot_release_key_material();
    verify_ephemeral_private_key_is_one_shot_on_all_attempts();
    verify_leading_zero_ecdh_secret_is_preserved_as_be32();
    verify_cross_session_and_role_binding();
    verify_hkdf_limit_and_independent_domains();
    verify_fresh_platform_factory_has_no_static_key_reuse();
#else
    verify_unsupported_platform_fails_closed();
#endif
    std::cout << "authenticated peer handshake v1 tests passed\n";
    return EXIT_SUCCESS;
}
