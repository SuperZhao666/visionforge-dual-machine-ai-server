#include "vfdual/authenticated_data_plane_v2.hpp"
#include "vfdual/authenticated_mouse_button_v2.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace vfdual {

struct AuthenticatedDataPlaneV2TestAccess final {
    [[nodiscard]] static std::unique_ptr<AuthenticatedPacketSealer> make_sealer(
        AuthenticatedTrafficKey traffic_key,
        Aes256GcmProvider& provider,
        const std::uint64_t initial_counter) {
        return std::unique_ptr<AuthenticatedPacketSealer>(
            new AuthenticatedPacketSealer(
                std::move(traffic_key), provider, initial_counter));
    }
};

}  // namespace vfdual

namespace {

static_assert(!std::is_copy_constructible_v<vfdual::AuthenticatedTrafficKey>);
static_assert(!std::is_copy_assignable_v<vfdual::AuthenticatedTrafficKey>);
static_assert(std::is_move_constructible_v<vfdual::AuthenticatedTrafficKey>);

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

constexpr std::size_t kCounterOffset = 20U;
constexpr std::size_t kPayloadLengthOffset = 28U;

[[nodiscard]] vfdual::AuthenticatedPacketTuple make_tuple() {
    return vfdual::AuthenticatedPacketTuple{
        .connection_id = 0x1020'3040'5060'7080ULL,
        .key_epoch = 9U,
        .direction = vfdual::DataPlaneDirection::host_to_android,
        .packet_type = vfdual::AuthenticatedPacketType::video,
    };
}

[[nodiscard]] vfdual::AuthenticatedTrafficKey make_traffic_key(
    const vfdual::AuthenticatedPacketTuple tuple,
    const std::uint8_t key_seed = 0x21U,
    const std::uint8_t prefix_seed = 0xa0U) {
    vfdual::AuthenticatedTrafficKey key;
    key.tuple = tuple;
    for (std::size_t index{}; index < key.aes_256_key.size(); ++index) {
        key.aes_256_key[index] =
            std::byte{static_cast<std::uint8_t>(key_seed + index)};
    }
    for (std::size_t index{}; index < key.nonce_prefix.size(); ++index) {
        key.nonce_prefix[index] =
            std::byte{static_cast<std::uint8_t>(prefix_seed + index)};
    }
    return key;
}

[[nodiscard]] vfdual::AuthenticatedTrafficKey make_interop_traffic_key() {
    auto key = make_traffic_key(make_tuple(), 0U, 0U);
    key.nonce_prefix = {
        std::byte{0xa1U},
        std::byte{0xb2U},
        std::byte{0xc3U},
        std::byte{0xd4U},
    };
    return key;
}

[[nodiscard]] std::vector<std::byte> bytes(
    const std::string_view value) {
    std::vector<std::byte> result;
    result.reserve(value.size());
    for (const char character : value) {
        result.push_back(
            std::byte{static_cast<unsigned char>(character)});
    }
    return result;
}

[[nodiscard]] std::uint8_t hex_nibble(const char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(value - 'a' + 10);
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

#if !defined(_WIN32)

// Test-only authenticator used to exercise state-machine behavior when the
// BCrypt production provider is unavailable. It is never exposed by shared/.
class TestOnlyCipher final : public vfdual::Aes256GcmCipher {
public:
    explicit TestOnlyCipher(
        const std::span<const std::byte, vfdual::kAes256KeyBytes> key) {
        std::copy(key.begin(), key.end(), key_.begin());
    }

    [[nodiscard]] bool encrypt(
        const std::span<const std::byte, vfdual::kGcmNonceBytes> nonce,
        const std::span<const std::byte> authenticated_data,
        const std::span<const std::byte> plaintext,
        const std::span<std::byte> ciphertext,
        const std::span<std::byte, vfdual::kGcmTagBytes> tag)
        noexcept override {
        if (plaintext.size() != ciphertext.size()) return false;
        for (std::size_t index{}; index < plaintext.size(); ++index) {
            ciphertext[index] = plaintext[index] ^ key_[index % key_.size()];
        }
        const auto expected = calculate_tag(nonce, authenticated_data, ciphertext);
        std::copy(expected.begin(), expected.end(), tag.begin());
        return true;
    }

    [[nodiscard]] bool decrypt(
        const std::span<const std::byte, vfdual::kGcmNonceBytes> nonce,
        const std::span<const std::byte> authenticated_data,
        const std::span<const std::byte> ciphertext,
        const std::span<const std::byte, vfdual::kGcmTagBytes> tag,
        const std::span<std::byte> plaintext) noexcept override {
        if (ciphertext.size() != plaintext.size()) return false;
        const auto expected = calculate_tag(nonce, authenticated_data, ciphertext);
        std::uint8_t difference{};
        for (std::size_t index{}; index < tag.size(); ++index) {
            difference |= std::to_integer<std::uint8_t>(tag[index] ^ expected[index]);
        }
        if (difference != 0U) return false;
        for (std::size_t index{}; index < ciphertext.size(); ++index) {
            plaintext[index] = ciphertext[index] ^ key_[index % key_.size()];
        }
        return true;
    }

private:
    [[nodiscard]] std::array<std::byte, vfdual::kGcmTagBytes> calculate_tag(
        const std::span<const std::byte> nonce,
        const std::span<const std::byte> authenticated_data,
        const std::span<const std::byte> ciphertext) const noexcept {
        std::array<std::byte, vfdual::kGcmTagBytes> tag{};
        std::size_t position{};
        auto mix = [&](const std::span<const std::byte> input) {
            for (const std::byte value : input) {
                const auto mixed = static_cast<std::uint8_t>(
                    std::to_integer<std::uint8_t>(tag[position]) ^
                    std::to_integer<std::uint8_t>(value) ^
                    std::to_integer<std::uint8_t>(
                        key_[position % key_.size()]));
                tag[position] = std::byte{mixed};
                position = (position + 1U) % tag.size();
            }
        };
        mix(nonce);
        mix(authenticated_data);
        mix(ciphertext);
        return tag;
    }

    std::array<std::byte, vfdual::kAes256KeyBytes> key_{};
};

class TestOnlyProvider final : public vfdual::Aes256GcmProvider {
public:
    [[nodiscard]] std::unique_ptr<vfdual::Aes256GcmCipher> import_key(
        const std::span<const std::byte, vfdual::kAes256KeyBytes> key)
        noexcept override {
        try {
            return std::make_unique<TestOnlyCipher>(key);
        } catch (...) {
            return {};
        }
    }
};

#endif

[[nodiscard]] std::unique_ptr<vfdual::Aes256GcmProvider>
make_test_provider() {
#if defined(_WIN32)
    auto provider = vfdual::make_platform_aes_256_gcm_provider();
    CHECK(provider != nullptr);
    return provider;
#else
    return std::make_unique<TestOnlyProvider>();
#endif
}

struct FailFirstEncryptionState final {
    bool should_fail{true};
    std::vector<std::array<std::byte, vfdual::kGcmNonceBytes>> nonces;
};

class FailFirstEncryptionCipher final : public vfdual::Aes256GcmCipher {
public:
    FailFirstEncryptionCipher(
        std::unique_ptr<vfdual::Aes256GcmCipher> inner,
        FailFirstEncryptionState& state)
        : inner_(std::move(inner)), state_(state) {}

    [[nodiscard]] bool encrypt(
        const std::span<const std::byte, vfdual::kGcmNonceBytes> nonce,
        const std::span<const std::byte> authenticated_data,
        const std::span<const std::byte> plaintext,
        const std::span<std::byte> ciphertext,
        const std::span<std::byte, vfdual::kGcmTagBytes> tag)
        noexcept override {
        std::array<std::byte, vfdual::kGcmNonceBytes> nonce_copy{};
        std::copy(nonce.begin(), nonce.end(), nonce_copy.begin());
        try {
            state_.nonces.push_back(nonce_copy);
        } catch (...) {
            return false;
        }
        if (state_.should_fail) {
            state_.should_fail = false;
            std::fill(ciphertext.begin(), ciphertext.end(), std::byte{0x5aU});
            std::fill(tag.begin(), tag.end(), std::byte{0xa5U});
            return false;
        }
        return inner_->encrypt(
            nonce, authenticated_data, plaintext, ciphertext, tag);
    }

    [[nodiscard]] bool decrypt(
        const std::span<const std::byte, vfdual::kGcmNonceBytes> nonce,
        const std::span<const std::byte> authenticated_data,
        const std::span<const std::byte> ciphertext,
        const std::span<const std::byte, vfdual::kGcmTagBytes> tag,
        const std::span<std::byte> plaintext) noexcept override {
        return inner_->decrypt(
            nonce, authenticated_data, ciphertext, tag, plaintext);
    }

private:
    std::unique_ptr<vfdual::Aes256GcmCipher> inner_;
    FailFirstEncryptionState& state_;
};

class FailFirstEncryptionProvider final : public vfdual::Aes256GcmProvider {
public:
    FailFirstEncryptionProvider(
        std::unique_ptr<vfdual::Aes256GcmProvider> inner,
        FailFirstEncryptionState& state)
        : inner_(std::move(inner)), state_(state) {}

    [[nodiscard]] std::unique_ptr<vfdual::Aes256GcmCipher> import_key(
        const std::span<const std::byte, vfdual::kAes256KeyBytes> key)
        noexcept override {
        auto inner_cipher = inner_->import_key(key);
        if (inner_cipher == nullptr) return {};
        try {
            return std::make_unique<FailFirstEncryptionCipher>(
                std::move(inner_cipher), state_);
        } catch (...) {
            return {};
        }
    }

private:
    std::unique_ptr<vfdual::Aes256GcmProvider> inner_;
    FailFirstEncryptionState& state_;
};

[[nodiscard]] vfdual::PacketSealResult seal_at(
    const vfdual::AuthenticatedPacketTuple tuple,
    const std::uint64_t counter,
    const std::span<const std::byte> plaintext,
    const std::uint8_t key_seed = 0x21U,
    const std::uint8_t prefix_seed = 0xa0U) {
    auto provider = make_test_provider();
    auto sealer = vfdual::AuthenticatedDataPlaneV2TestAccess::make_sealer(
        make_traffic_key(tuple, key_seed, prefix_seed), *provider, counter);
    return sealer->seal(plaintext);
}

void verify_nonce_layout_and_round_trip() {
    const std::array<std::byte, vfdual::kGcmNoncePrefixBytes> prefix{
        std::byte{0xa1U}, std::byte{0xb2U},
        std::byte{0xc3U}, std::byte{0xd4U}};
    const auto nonce = vfdual::compose_authenticated_packet_nonce(
        prefix, 0x0102'0304'0506'0708ULL);
    const std::array<std::byte, vfdual::kGcmNonceBytes> expected_nonce{
        std::byte{0xa1U}, std::byte{0xb2U}, std::byte{0xc3U},
        std::byte{0xd4U}, std::byte{0x01U}, std::byte{0x02U},
        std::byte{0x03U}, std::byte{0x04U}, std::byte{0x05U},
        std::byte{0x06U}, std::byte{0x07U}, std::byte{0x08U}};
    CHECK(nonce == expected_nonce);

    const auto tuple = make_tuple();
    const auto plaintext = bytes("authenticated-video-fragment");
    auto provider = make_test_provider();
    auto sealer = vfdual::AuthenticatedDataPlaneV2TestAccess::make_sealer(
        make_traffic_key(tuple), *provider, 7U);
    const auto sealed = sealer->seal(plaintext);
    CHECK(sealed.status == vfdual::PacketSealStatus::sealed);
    CHECK(sealed.counter == 7U);

    const auto parsed =
        vfdual::parse_authenticated_packet_v2(sealed.datagram);
    CHECK(parsed.status == vfdual::PacketParseStatus::parsed);
    CHECK(parsed.packet.tuple == tuple);
    CHECK(parsed.packet.counter == 7U);
    CHECK(parsed.packet.authenticated_header.size() ==
        vfdual::kAuthenticatedPacketHeaderBytes);
    CHECK(parsed.packet.ciphertext.size() == plaintext.size());
    CHECK(parsed.packet.tag.size() == vfdual::kGcmTagBytes);
    CHECK(vfdual::validate_authenticated_packet_v2(parsed.packet, tuple) ==
        vfdual::PacketValidationStatus::valid);

    vfdual::AuthenticatedPacketOpener opener(
        make_traffic_key(tuple), *provider);
    const auto opened = opener.open(sealed.datagram);
    CHECK(opened.status == vfdual::PacketOpenStatus::opened);
    CHECK(opened.authenticated_counter == 7U);
    CHECK(opened.plaintext == plaintext);
    const auto snapshot = opener.replay_snapshot();
    CHECK(snapshot.initialized);
    CHECK(snapshot.highest_authenticated_counter == 7U);

    auto empty_provider = make_test_provider();
    auto empty_sealer = vfdual::AuthenticatedDataPlaneV2TestAccess::make_sealer(
        make_traffic_key(tuple), *empty_provider, 8U);
    vfdual::AuthenticatedPacketOpener empty_opener(
        make_traffic_key(tuple), *empty_provider);
    const auto empty_packet = empty_sealer->seal({});
    CHECK(empty_packet.status == vfdual::PacketSealStatus::sealed);
    const auto empty_opened = empty_opener.open(empty_packet.datagram);
    CHECK(empty_opened.status == vfdual::PacketOpenStatus::opened);
    CHECK(empty_opened.plaintext.empty());
}

void verify_java_cpp_interop_vector() {
    constexpr std::uint64_t counter = 0x0012'3456ULL;
    const auto expected_nonce = bytes_from_hex(
        "a1b2c3d40000000000123456");
    const auto actual_nonce = vfdual::compose_authenticated_packet_nonce(
        make_interop_traffic_key().nonce_prefix, counter);
    CHECK(std::equal(
        actual_nonce.begin(), actual_nonce.end(), expected_nonce.begin()));

    const auto expected_wire = bytes_from_hex(
        "564641320220010110203040506070800000000900000000001234560000000a"
        "9f6f11ab7a5393b4deda150df8b50ba9769f359e4cb09f4eddaf");
    const auto parsed = vfdual::parse_authenticated_packet_v2(expected_wire);
    CHECK(parsed.status == vfdual::PacketParseStatus::parsed);
    CHECK(parsed.packet.tuple == make_tuple());
    CHECK(parsed.packet.counter == counter);
#if defined(_WIN32)
    auto provider = make_test_provider();
    auto sealer = vfdual::AuthenticatedDataPlaneV2TestAccess::make_sealer(
        make_interop_traffic_key(), *provider, counter);
    const auto sealed = sealer->seal(bytes("interop-v2"));
    CHECK(sealed.status == vfdual::PacketSealStatus::sealed);
    CHECK(sealed.datagram == expected_wire);

    vfdual::AuthenticatedPacketOpener opener(
        make_interop_traffic_key(), *provider);
    const auto opened = opener.open(expected_wire);
    CHECK(opened.status == vfdual::PacketOpenStatus::opened);
    CHECK(opened.authenticated_counter == counter);
    CHECK(opened.plaintext == bytes("interop-v2"));
#endif
}

void verify_authenticated_mouse_button_v2_foundation() {
    constexpr std::uint64_t connection_id = 0x1020'3040'5060'7080ULL;
    constexpr std::uint64_t counter = 0x0012'3456ULL;
    constexpr std::uint8_t button_mask = 0x13U;
    std::array<std::byte, vfdual::kAuthenticatedMouseButtonTrafficMaterialBytes>
        traffic_material{};
    for (std::size_t index{}; index < vfdual::kAes256KeyBytes; ++index) {
        traffic_material[index] = std::byte{static_cast<std::uint8_t>(index)};
    }
    traffic_material[vfdual::kAes256KeyBytes] = std::byte{0xa1U};
    traffic_material[vfdual::kAes256KeyBytes + 1U] = std::byte{0xb2U};
    traffic_material[vfdual::kAes256KeyBytes + 2U] = std::byte{0xc3U};
    traffic_material[vfdual::kAes256KeyBytes + 3U] = std::byte{0xd4U};

    const auto tuple =
        vfdual::make_authenticated_mouse_button_host_to_android_tuple(
            connection_id);
    CHECK(tuple.connection_id == connection_id);
    CHECK(tuple.key_epoch == vfdual::kAuthenticatedMouseButtonKeyEpochV1);
    CHECK(tuple.direction == vfdual::DataPlaneDirection::host_to_android);
    CHECK(tuple.packet_type == vfdual::AuthenticatedPacketType::mouse_button);

    auto key = vfdual::make_authenticated_mouse_button_host_to_android_key(
        connection_id, traffic_material);
    CHECK(key.tuple == tuple);
    CHECK(std::equal(
        key.aes_256_key.begin(),
        key.aes_256_key.end(),
        traffic_material.begin()));
    CHECK(std::equal(
        key.nonce_prefix.begin(),
        key.nonce_prefix.end(),
        traffic_material.begin() +
            static_cast<std::ptrdiff_t>(vfdual::kAes256KeyBytes)));

    std::array<std::byte, vfdual::kAuthenticatedMouseButtonPayloadBytes>
        payload{};
    CHECK(vfdual::encode_authenticated_mouse_button_payload(
        button_mask, payload));
    CHECK(payload[0] == std::byte{button_mask});
    std::uint8_t decoded_mask{};
    CHECK(vfdual::decode_authenticated_mouse_button_payload(
        payload, decoded_mask));
    CHECK(decoded_mask == button_mask);
    CHECK(!vfdual::encode_authenticated_mouse_button_payload(0x20U, payload));
    CHECK(payload[0] == std::byte{0U});
    CHECK(!vfdual::decode_authenticated_mouse_button_payload({}, decoded_mask));
    CHECK(decoded_mask == 0U);
    const std::array malformed_payload{std::byte{0x20U}};
    CHECK(!vfdual::decode_authenticated_mouse_button_payload(
        malformed_payload, decoded_mask));
    CHECK(decoded_mask == 0U);

    const auto expected_wire = bytes_from_hex(
        "5646413202200401102030405060708000000001000000000012345600000001"
        "e538c212489c5714a9ab8b22096d01bc92");
    const auto parsed = vfdual::parse_authenticated_packet_v2(expected_wire);
    CHECK(parsed.status == vfdual::PacketParseStatus::parsed);
    CHECK(parsed.packet.tuple == tuple);
    CHECK(parsed.packet.counter == counter);
    CHECK(parsed.packet.ciphertext.size() ==
        vfdual::kAuthenticatedMouseButtonPayloadBytes);

#if defined(_WIN32)
    auto provider = make_test_provider();
    auto sealer = vfdual::AuthenticatedDataPlaneV2TestAccess::make_sealer(
        std::move(key), *provider, counter);
    const auto sealed = sealer->seal(std::array{std::byte{button_mask}});
    CHECK(sealed.status == vfdual::PacketSealStatus::sealed);
    CHECK(sealed.datagram == expected_wire);

    vfdual::AuthenticatedPacketOpener opener(
        vfdual::make_authenticated_mouse_button_host_to_android_key(
            connection_id, traffic_material),
        *provider);
    const auto opened = opener.open(expected_wire);
    CHECK(opened.status == vfdual::PacketOpenStatus::opened);
    CHECK(opened.authenticated_counter == counter);
    CHECK(vfdual::decode_authenticated_mouse_button_payload(
        opened.plaintext, decoded_mask));
    CHECK(decoded_mask == button_mask);
    CHECK(opener.open(expected_wire).status ==
        vfdual::PacketOpenStatus::duplicate);
#endif
}

template <typename Mutator>
void verify_authentication_failure_does_not_advance(Mutator mutate) {
    const auto tuple = make_tuple();
    const auto plaintext = bytes("mutation-target");
    auto forged = seal_at(tuple, 5'000U, plaintext);
    CHECK(forged.status == vfdual::PacketSealStatus::sealed);
    mutate(forged.datagram);

    auto provider = make_test_provider();
    vfdual::AuthenticatedPacketOpener opener(
        make_traffic_key(tuple), *provider);
    const auto rejected = opener.open(forged.datagram);
    CHECK(rejected.status == vfdual::PacketOpenStatus::authentication_failed);
    CHECK(rejected.plaintext.empty());
    CHECK(!opener.replay_snapshot().initialized);

    const auto legitimate = seal_at(tuple, 0U, plaintext);
    CHECK(legitimate.status == vfdual::PacketSealStatus::sealed);
    const auto accepted = opener.open(legitimate.datagram);
    CHECK(accepted.status == vfdual::PacketOpenStatus::opened);
    CHECK(accepted.authenticated_counter == 0U);
}

void verify_tag_aad_and_ciphertext_fail_closed() {
    verify_authentication_failure_does_not_advance(
        [](std::vector<std::byte>& datagram) {
            datagram.back() ^= std::byte{0x80U};
        });
    verify_authentication_failure_does_not_advance(
        [](std::vector<std::byte>& datagram) {
            datagram[vfdual::kAuthenticatedPacketHeaderBytes] ^=
                std::byte{0x40U};
        });
    verify_authentication_failure_does_not_advance(
        [](std::vector<std::byte>& datagram) {
            // The counter is AAD. Changing it must fail GCM and must not move
            // the replay window to the attacker-selected high counter.
            datagram[kCounterOffset + 7U] ^= std::byte{0x01U};
        });
}

void verify_encryption_failure_burns_nonce_counter() {
    const auto tuple = make_tuple();
    FailFirstEncryptionState state;
    FailFirstEncryptionProvider provider(make_test_provider(), state);
    auto sealer = vfdual::AuthenticatedDataPlaneV2TestAccess::make_sealer(
        make_traffic_key(tuple), provider, 5U);

    const auto failed = sealer->seal(bytes("provider-fails-after-touching-output"));
    CHECK(failed.status == vfdual::PacketSealStatus::encryption_failed);
    CHECK(failed.counter == 5U);
    CHECK(failed.datagram.empty());

    const auto recovered = sealer->seal(bytes("next-nonce-only"));
    CHECK(recovered.status == vfdual::PacketSealStatus::sealed);
    CHECK(recovered.counter == 6U);
    CHECK(state.nonces.size() == 2U);
    CHECK(state.nonces[0] != state.nonces[1]);
    CHECK(state.nonces[0] == vfdual::compose_authenticated_packet_nonce(
        make_traffic_key(tuple).nonce_prefix, 5U));
    CHECK(state.nonces[1] == vfdual::compose_authenticated_packet_nonce(
        make_traffic_key(tuple).nonce_prefix, 6U));

    FailFirstEncryptionState last_state;
    FailFirstEncryptionProvider last_provider(
        make_test_provider(), last_state);
    auto last_sealer = vfdual::AuthenticatedDataPlaneV2TestAccess::make_sealer(
        make_traffic_key(tuple),
        last_provider,
        vfdual::kMaximumAuthenticatedPacketCounter);
    const auto last_failed = last_sealer->seal(bytes("burn-last-nonce"));
    CHECK(last_failed.status == vfdual::PacketSealStatus::encryption_failed);
    CHECK(last_failed.counter == vfdual::kMaximumAuthenticatedPacketCounter);
    CHECK(last_sealer->seal(bytes("must-rekey")).status ==
        vfdual::PacketSealStatus::counter_exhausted);
}

void verify_malformed_lengths_fail_closed() {
    const auto tuple = make_tuple();
    const auto plaintext = bytes("length-contract");
    const auto sealed = seal_at(tuple, 0U, plaintext);
    CHECK(sealed.status == vfdual::PacketSealStatus::sealed);
    auto provider = make_test_provider();
    vfdual::AuthenticatedPacketOpener opener(
        make_traffic_key(tuple), *provider);

    auto truncated = sealed.datagram;
    truncated.pop_back();
    CHECK(vfdual::parse_authenticated_packet_v2(truncated).status ==
        vfdual::PacketParseStatus::length_mismatch);
    CHECK(opener.open(truncated).status ==
        vfdual::PacketOpenStatus::malformed_packet);

    auto extended = sealed.datagram;
    extended.push_back(std::byte{0U});
    CHECK(vfdual::parse_authenticated_packet_v2(extended).status ==
        vfdual::PacketParseStatus::length_mismatch);
    CHECK(opener.open(extended).status ==
        vfdual::PacketOpenStatus::malformed_packet);

    auto oversized_claim = sealed.datagram;
    const std::uint32_t oversized = static_cast<std::uint32_t>(
        vfdual::kMaximumAuthenticatedPayloadBytes + 1U);
    oversized_claim[kPayloadLengthOffset] =
        std::byte{static_cast<std::uint8_t>(oversized >> 24U)};
    oversized_claim[kPayloadLengthOffset + 1U] =
        std::byte{static_cast<std::uint8_t>(oversized >> 16U)};
    oversized_claim[kPayloadLengthOffset + 2U] =
        std::byte{static_cast<std::uint8_t>(oversized >> 8U)};
    oversized_claim[kPayloadLengthOffset + 3U] =
        std::byte{static_cast<std::uint8_t>(oversized)};
    CHECK(vfdual::parse_authenticated_packet_v2(oversized_claim).status ==
        vfdual::PacketParseStatus::payload_too_large);
    CHECK(opener.open(oversized_claim).status ==
        vfdual::PacketOpenStatus::malformed_packet);
    CHECK(!opener.replay_snapshot().initialized);

    auto maximum_payload = std::vector<std::byte>(
        vfdual::kMaximumAuthenticatedPayloadBytes, std::byte{0x5aU});
    const auto maximum_packet = seal_at(tuple, 1U, maximum_payload);
    CHECK(maximum_packet.status == vfdual::PacketSealStatus::sealed);
    CHECK(maximum_packet.datagram.size() ==
        vfdual::kMaximumAuthenticatedDatagramBytes);
    CHECK(vfdual::parse_authenticated_packet_v2(maximum_packet.datagram).status ==
        vfdual::PacketParseStatus::parsed);

    maximum_payload.push_back(std::byte{0U});
    CHECK(seal_at(tuple, 2U, maximum_payload).status ==
        vfdual::PacketSealStatus::plaintext_too_large);

    auto maximum_u32_claim = sealed.datagram;
    std::fill_n(
        maximum_u32_claim.begin() +
            static_cast<std::ptrdiff_t>(kPayloadLengthOffset),
        4U,
        std::byte{0xffU});
    CHECK(vfdual::parse_authenticated_packet_v2(maximum_u32_claim).status ==
        vfdual::PacketParseStatus::payload_too_large);

    CHECK(opener.open(sealed.datagram).status ==
        vfdual::PacketOpenStatus::opened);
}

void verify_structural_header_rejections() {
    const auto sealed = seal_at(make_tuple(), 0U, bytes("header"));
    CHECK(sealed.status == vfdual::PacketSealStatus::sealed);

    auto mutated = sealed.datagram;
    mutated[0] ^= std::byte{1U};
    CHECK(vfdual::parse_authenticated_packet_v2(mutated).status ==
        vfdual::PacketParseStatus::invalid_magic);
    mutated = sealed.datagram;
    mutated[4] = std::byte{1U};
    CHECK(vfdual::parse_authenticated_packet_v2(mutated).status ==
        vfdual::PacketParseStatus::unsupported_version);
    mutated = sealed.datagram;
    mutated[5] = std::byte{31U};
    CHECK(vfdual::parse_authenticated_packet_v2(mutated).status ==
        vfdual::PacketParseStatus::invalid_header_size);
    mutated = sealed.datagram;
    mutated[6] = std::byte{0U};
    CHECK(vfdual::parse_authenticated_packet_v2(mutated).status ==
        vfdual::PacketParseStatus::invalid_packet_type);
    mutated = sealed.datagram;
    mutated[7] = std::byte{0U};
    CHECK(vfdual::parse_authenticated_packet_v2(mutated).status ==
        vfdual::PacketParseStatus::invalid_direction);
    mutated = sealed.datagram;
    std::uint64_t outside_key_lifetime = vfdual::kMaximumPacketsPerTrafficKey;
    for (std::size_t index{}; index < sizeof(outside_key_lifetime); ++index) {
        mutated[kCounterOffset + sizeof(outside_key_lifetime) - 1U - index] =
            std::byte{static_cast<std::uint8_t>(outside_key_lifetime)};
        outside_key_lifetime >>= 8U;
    }
    CHECK(vfdual::parse_authenticated_packet_v2(mutated).status ==
        vfdual::PacketParseStatus::counter_exceeds_key_lifetime);
}

void verify_wrong_tuple_fields_are_rejected_without_side_effects() {
    const auto tuple = make_tuple();
    const auto sealed = seal_at(tuple, 0U, bytes("bound-to-one-tuple"));
    CHECK(sealed.status == vfdual::PacketSealStatus::sealed);

    auto expect = [&](vfdual::AuthenticatedPacketTuple wrong_tuple,
                      const vfdual::PacketOpenStatus expected_status) {
        auto provider = make_test_provider();
        vfdual::AuthenticatedPacketOpener opener(
            make_traffic_key(wrong_tuple), *provider);
        const auto opened = opener.open(sealed.datagram);
        CHECK(opened.status == expected_status);
        CHECK(opened.plaintext.empty());
        CHECK(!opener.replay_snapshot().initialized);
    };

    auto wrong = tuple;
    ++wrong.connection_id;
    expect(wrong, vfdual::PacketOpenStatus::wrong_connection_id);
    wrong = tuple;
    ++wrong.key_epoch;
    expect(wrong, vfdual::PacketOpenStatus::wrong_key_epoch);
    wrong = tuple;
    wrong.direction = vfdual::DataPlaneDirection::android_to_host;
    expect(wrong, vfdual::PacketOpenStatus::wrong_direction);
    wrong = tuple;
    wrong.packet_type = vfdual::AuthenticatedPacketType::presence_probe;
    expect(wrong, vfdual::PacketOpenStatus::wrong_packet_type);

    auto invalid = tuple;
    invalid.connection_id = 0U;
    auto provider = make_test_provider();
    vfdual::AuthenticatedPacketSealer invalid_sealer(
        make_traffic_key(invalid), *provider);
    CHECK(invalid_sealer.seal(bytes("x")).status ==
        vfdual::PacketSealStatus::invalid_configuration);
    vfdual::AuthenticatedPacketOpener invalid_opener(
        make_traffic_key(invalid), *provider);
    CHECK(invalid_opener.open(sealed.datagram).status ==
        vfdual::PacketOpenStatus::invalid_configuration);
}

void verify_duplicate_and_full_replay_window() {
    const auto tuple = make_tuple();
    const auto payload = bytes("replay-window");
    const auto packet_0 = seal_at(tuple, 0U, payload);
    const auto packet_1 = seal_at(tuple, 1U, payload);
    const auto packet_63 = seal_at(tuple, 63U, payload);
    const auto packet_64 = seal_at(tuple, 64U, payload);
    const auto packet_65 = seal_at(tuple, 65U, payload);
    const auto packet_1023 = seal_at(tuple, 1'023U, payload);
    const auto packet_1024 = seal_at(tuple, 1'024U, payload);
    CHECK(packet_0.status == vfdual::PacketSealStatus::sealed);
    CHECK(packet_1.status == vfdual::PacketSealStatus::sealed);
    CHECK(packet_63.status == vfdual::PacketSealStatus::sealed);
    CHECK(packet_64.status == vfdual::PacketSealStatus::sealed);
    CHECK(packet_65.status == vfdual::PacketSealStatus::sealed);
    CHECK(packet_1023.status == vfdual::PacketSealStatus::sealed);
    CHECK(packet_1024.status == vfdual::PacketSealStatus::sealed);

    auto provider = make_test_provider();
    vfdual::AuthenticatedPacketOpener opener(
        make_traffic_key(tuple), *provider);
    CHECK(opener.open(packet_0.datagram).status ==
        vfdual::PacketOpenStatus::opened);
    CHECK(opener.open(packet_0.datagram).status ==
        vfdual::PacketOpenStatus::duplicate);
    CHECK(opener.open(packet_63.datagram).status ==
        vfdual::PacketOpenStatus::opened);
    CHECK(opener.open(packet_0.datagram).status ==
        vfdual::PacketOpenStatus::duplicate);
    CHECK(opener.open(packet_64.datagram).status ==
        vfdual::PacketOpenStatus::opened);
    CHECK(opener.open(packet_0.datagram).status ==
        vfdual::PacketOpenStatus::duplicate);
    CHECK(opener.open(packet_65.datagram).status ==
        vfdual::PacketOpenStatus::opened);
    CHECK(opener.open(packet_0.datagram).status ==
        vfdual::PacketOpenStatus::duplicate);
    CHECK(opener.open(packet_1023.datagram).status ==
        vfdual::PacketOpenStatus::opened);
    CHECK(opener.open(packet_0.datagram).status ==
        vfdual::PacketOpenStatus::duplicate);
    CHECK(opener.open(packet_1024.datagram).status ==
        vfdual::PacketOpenStatus::opened);

    // Distance 1023 is inside the window; distance 1024 is too old.
    CHECK(opener.open(packet_1.datagram).status ==
        vfdual::PacketOpenStatus::opened);
    CHECK(opener.open(packet_1.datagram).status ==
        vfdual::PacketOpenStatus::duplicate);
    CHECK(opener.open(packet_0.datagram).status ==
        vfdual::PacketOpenStatus::too_old);
    const auto snapshot = opener.replay_snapshot();
    CHECK(snapshot.initialized);
    CHECK(snapshot.highest_authenticated_counter == 1'024U);
}

void verify_exact_replay_window_shift_boundaries() {
    const auto tuple = make_tuple();
    const auto payload = bytes("exact-window-shift");
    for (const std::uint64_t advance : {63U, 64U, 1'023U, 1'024U}) {
        const auto first = seal_at(tuple, 0U, payload);
        const auto advanced = seal_at(tuple, advance, payload);
        CHECK(first.status == vfdual::PacketSealStatus::sealed);
        CHECK(advanced.status == vfdual::PacketSealStatus::sealed);
        auto provider = make_test_provider();
        vfdual::AuthenticatedPacketOpener opener(
            make_traffic_key(tuple), *provider);
        CHECK(opener.open(first.datagram).status ==
            vfdual::PacketOpenStatus::opened);
        CHECK(opener.open(advanced.datagram).status ==
            vfdual::PacketOpenStatus::opened);
        const auto first_again = opener.open(first.datagram).status;
        CHECK(first_again == (advance < vfdual::kReplayWindowBits
            ? vfdual::PacketOpenStatus::duplicate
            : vfdual::PacketOpenStatus::too_old));

        if (advance == vfdual::kReplayWindowBits) {
            const auto inside_edge = seal_at(tuple, 1U, payload);
            CHECK(opener.open(inside_edge.datagram).status ==
                vfdual::PacketOpenStatus::opened);
        }
    }
}

void verify_key_lifetime_requires_rekey_before_counter_wrap() {
    const auto tuple = make_tuple();
    auto provider = make_test_provider();
    auto sealer = vfdual::AuthenticatedDataPlaneV2TestAccess::make_sealer(
        make_traffic_key(tuple),
        *provider,
        vfdual::kMaximumAuthenticatedPacketCounter);
    const auto last = sealer->seal(bytes("last-counter-before-rekey"));
    CHECK(last.status == vfdual::PacketSealStatus::sealed);
    CHECK(last.counter == vfdual::kMaximumAuthenticatedPacketCounter);
    const auto parsed = vfdual::parse_authenticated_packet_v2(last.datagram);
    CHECK(parsed.status == vfdual::PacketParseStatus::parsed);
    CHECK(parsed.packet.counter == vfdual::kMaximumAuthenticatedPacketCounter);

    const auto exhausted = sealer->seal(bytes("must-rekey"));
    CHECK(exhausted.status == vfdual::PacketSealStatus::counter_exhausted);
    CHECK(exhausted.datagram.empty());

    auto invalid = vfdual::AuthenticatedDataPlaneV2TestAccess::make_sealer(
        make_traffic_key(tuple),
        *provider,
        vfdual::kMaximumPacketsPerTrafficKey);
    CHECK(invalid->seal(bytes("outside-key-lifetime")).status ==
        vfdual::PacketSealStatus::counter_exhausted);
}

void verify_tuple_domains_have_independent_keys_and_counters() {
    const auto video_tuple = make_tuple();
    auto control_tuple = video_tuple;
    control_tuple.direction = vfdual::DataPlaneDirection::android_to_host;
    control_tuple.packet_type = vfdual::AuthenticatedPacketType::idr_request;

    auto provider = make_test_provider();
    vfdual::AuthenticatedPacketSealer video_sealer(
        make_traffic_key(video_tuple, 0x11U, 0x31U), *provider);
    vfdual::AuthenticatedPacketSealer control_sealer(
        make_traffic_key(control_tuple, 0x51U, 0x71U), *provider);
    const auto video_packet = video_sealer.seal(bytes("video"));
    const auto control_packet = control_sealer.seal(bytes("idr"));
    CHECK(video_packet.status == vfdual::PacketSealStatus::sealed);
    CHECK(control_packet.status == vfdual::PacketSealStatus::sealed);
    CHECK(video_packet.counter == 0U);
    CHECK(control_packet.counter == 0U);

    vfdual::AuthenticatedPacketOpener video_opener(
        make_traffic_key(video_tuple, 0x11U, 0x31U), *provider);
    vfdual::AuthenticatedPacketOpener control_opener(
        make_traffic_key(control_tuple, 0x51U, 0x71U), *provider);
    CHECK(video_opener.open(video_packet.datagram).status ==
        vfdual::PacketOpenStatus::opened);
    CHECK(control_opener.open(control_packet.datagram).status ==
        vfdual::PacketOpenStatus::opened);
    CHECK(video_opener.open(control_packet.datagram).status ==
        vfdual::PacketOpenStatus::wrong_direction);

    // A correct tuple with a different per-tuple key cannot authenticate.
    vfdual::AuthenticatedPacketOpener wrong_key_opener(
        make_traffic_key(video_tuple, 0x52U, 0x31U), *provider);
    CHECK(wrong_key_opener.open(video_packet.datagram).status ==
        vfdual::PacketOpenStatus::authentication_failed);
    CHECK(!wrong_key_opener.replay_snapshot().initialized);
}

#if defined(_WIN32)
void verify_windows_provider_matches_aes_256_gcm_vector() {
    auto provider = vfdual::make_platform_aes_256_gcm_provider();
    CHECK(provider != nullptr);
    const std::array<std::byte, vfdual::kAes256KeyBytes> zero_key{};
    auto cipher = provider->import_key(zero_key);
    CHECK(cipher != nullptr);
    const std::array<std::byte, vfdual::kGcmNonceBytes> zero_nonce{};
    std::array<std::byte, vfdual::kGcmTagBytes> tag{};
    std::array<std::byte, 0U> empty{};
    CHECK(cipher->encrypt(zero_nonce, {}, empty, empty, tag));
    const std::array<std::byte, vfdual::kGcmTagBytes> expected_tag{
        std::byte{0x53U}, std::byte{0x0fU}, std::byte{0x8aU},
        std::byte{0xfbU}, std::byte{0xc7U}, std::byte{0x45U},
        std::byte{0x36U}, std::byte{0xb9U}, std::byte{0xa9U},
        std::byte{0x63U}, std::byte{0xb4U}, std::byte{0xf1U},
        std::byte{0xc4U}, std::byte{0xcbU}, std::byte{0x73U},
        std::byte{0x8bU}};
    CHECK(tag == expected_tag);
    CHECK(cipher->decrypt(zero_nonce, {}, empty, tag, empty));
}
#endif

}  // namespace

int main() {
    verify_nonce_layout_and_round_trip();
    verify_java_cpp_interop_vector();
    verify_authenticated_mouse_button_v2_foundation();
    verify_tag_aad_and_ciphertext_fail_closed();
    verify_encryption_failure_burns_nonce_counter();
    verify_malformed_lengths_fail_closed();
    verify_structural_header_rejections();
    verify_wrong_tuple_fields_are_rejected_without_side_effects();
    verify_duplicate_and_full_replay_window();
    verify_exact_replay_window_shift_boundaries();
    verify_key_lifetime_requires_rekey_before_counter_wrap();
    verify_tuple_domains_have_independent_keys_and_counters();
#if defined(_WIN32)
    verify_windows_provider_matches_aes_256_gcm_vector();
#endif
    std::cout << "authenticated data plane v2 tests passed\n";
    return EXIT_SUCCESS;
}
