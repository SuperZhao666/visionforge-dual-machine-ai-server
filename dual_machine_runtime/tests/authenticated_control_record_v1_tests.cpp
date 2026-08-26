#include "vfdual/authenticated_control_record_v1.hpp"

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

struct AuthenticatedControlRecordV1TestAccess final {
    [[nodiscard]] static std::unique_ptr<AuthenticatedControlRecordSealerV1>
    make_sealer(
        AuthenticatedControlTrafficKeyV1 traffic_key,
        Aes256GcmProvider& provider,
        const std::uint64_t initial_counter) {
        return std::unique_ptr<AuthenticatedControlRecordSealerV1>(
            new AuthenticatedControlRecordSealerV1(
                std::move(traffic_key), provider, initial_counter));
    }
};

}  // namespace vfdual

namespace {

static_assert(
    !std::is_copy_constructible_v<vfdual::AuthenticatedControlTrafficKeyV1>);
static_assert(
    std::is_move_constructible_v<vfdual::AuthenticatedControlTrafficKeyV1>);

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

constexpr std::size_t kDirectionOffset = 6U;
constexpr std::size_t kMessageTypeOffset = 7U;
constexpr std::size_t kConnectionIdOffset = 8U;
constexpr std::size_t kCounterOffset = 28U;

[[nodiscard]] vfdual::AuthenticatedControlTupleV1 make_tuple() {
    return vfdual::AuthenticatedControlTupleV1{
        .connection_id = 0x0102'0304'0506'0708ULL,
        .session_generation = 0x1112'1314'1516'1718ULL,
        .key_epoch = 1U,
        .direction = vfdual::ControlRecordDirectionV1::host_to_android,
    };
}

[[nodiscard]] vfdual::AuthenticatedControlTrafficKeyV1 make_key(
    const vfdual::AuthenticatedControlTupleV1 tuple = make_tuple()) {
    vfdual::AuthenticatedControlTrafficKeyV1 key;
    key.tuple = tuple;
    for (std::size_t index{}; index < key.aes_256_key.size(); ++index) {
        key.aes_256_key[index] =
            std::byte{static_cast<std::uint8_t>(index)};
    }
    key.nonce_prefix = {
        std::byte{0xa0U},
        std::byte{0xa1U},
        std::byte{0xa2U},
        std::byte{0xa3U},
    };
    return key;
}

[[nodiscard]] std::vector<std::byte> bytes(const std::string_view value) {
    std::vector<std::byte> result;
    result.reserve(value.size());
    for (const char character : value) {
        result.push_back(std::byte{static_cast<unsigned char>(character)});
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
            difference |= std::to_integer<std::uint8_t>(
                tag[index] ^ expected[index]);
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
                tag[position] ^= value ^ key_[position % key_.size()];
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

struct FailFirstState final {
    bool should_fail{true};
};

class FailFirstCipher final : public vfdual::Aes256GcmCipher {
public:
    FailFirstCipher(
        const std::span<const std::byte, vfdual::kAes256KeyBytes> key,
        FailFirstState& state)
        : inner_(key), state_(state) {}

    [[nodiscard]] bool encrypt(
        const std::span<const std::byte, vfdual::kGcmNonceBytes> nonce,
        const std::span<const std::byte> authenticated_data,
        const std::span<const std::byte> plaintext,
        const std::span<std::byte> ciphertext,
        const std::span<std::byte, vfdual::kGcmTagBytes> tag)
        noexcept override {
        if (state_.should_fail) {
            state_.should_fail = false;
            std::fill(ciphertext.begin(), ciphertext.end(), std::byte{0x5aU});
            std::fill(tag.begin(), tag.end(), std::byte{0xa5U});
            return false;
        }
        return inner_.encrypt(
            nonce, authenticated_data, plaintext, ciphertext, tag);
    }

    [[nodiscard]] bool decrypt(
        const std::span<const std::byte, vfdual::kGcmNonceBytes> nonce,
        const std::span<const std::byte> authenticated_data,
        const std::span<const std::byte> ciphertext,
        const std::span<const std::byte, vfdual::kGcmTagBytes> tag,
        const std::span<std::byte> plaintext) noexcept override {
        return inner_.decrypt(
            nonce, authenticated_data, ciphertext, tag, plaintext);
    }

private:
    TestOnlyCipher inner_;
    FailFirstState& state_;
};

class FailFirstProvider final : public vfdual::Aes256GcmProvider {
public:
    explicit FailFirstProvider(FailFirstState& state) : state_(state) {}

    [[nodiscard]] std::unique_ptr<vfdual::Aes256GcmCipher> import_key(
        const std::span<const std::byte, vfdual::kAes256KeyBytes> key)
        noexcept override {
        try {
            return std::make_unique<FailFirstCipher>(key, state_);
        } catch (...) {
            return {};
        }
    }

private:
    FailFirstState& state_;
};

void verifies_shared_counter_and_round_trip() {
    TestOnlyProvider provider;
    vfdual::AuthenticatedControlRecordSealerV1 sealer(make_key(), provider);
    vfdual::AuthenticatedControlRecordOpenerV1 opener(make_key(), provider);

    const auto offer_plaintext = bytes("lease-token-v1");
    const auto accept_plaintext = bytes("accept-v1");
    const auto offer = sealer.seal(
        vfdual::ControlMessageTypeV1::lease_offer, offer_plaintext);
    const auto accept = sealer.seal(
        vfdual::ControlMessageTypeV1::lease_accept, accept_plaintext);
    CHECK(offer.status == vfdual::ControlRecordSealStatusV1::sealed);
    CHECK(accept.status == vfdual::ControlRecordSealStatusV1::sealed);
    CHECK(offer.counter == 0U);
    CHECK(accept.counter == 1U);

    const auto parsed_offer =
        vfdual::parse_authenticated_control_record_v1(offer.envelope);
    const auto parsed_accept =
        vfdual::parse_authenticated_control_record_v1(accept.envelope);
    CHECK(parsed_offer.status == vfdual::ControlRecordParseStatusV1::parsed);
    CHECK(parsed_offer.record.message_type ==
        vfdual::ControlMessageTypeV1::lease_offer);
    CHECK(parsed_accept.record.message_type ==
        vfdual::ControlMessageTypeV1::lease_accept);
    CHECK(parsed_accept.record.counter == 1U);

    const auto opened_offer = opener.open(offer.envelope);
    CHECK(opened_offer.status == vfdual::ControlRecordOpenStatusV1::opened);
    CHECK(opened_offer.message_type ==
        vfdual::ControlMessageTypeV1::lease_offer);
    CHECK(opened_offer.plaintext == offer_plaintext);
    const auto duplicate = opener.open(offer.envelope);
    CHECK(duplicate.status ==
        vfdual::ControlRecordOpenStatusV1::unauthenticated_record);
    CHECK(duplicate.plaintext.empty());
    const auto opened_accept = opener.open(accept.envelope);
    CHECK(opened_accept.status == vfdual::ControlRecordOpenStatusV1::opened);
    CHECK(opened_accept.plaintext == accept_plaintext);
}

void verifies_start_intent_claim_types_share_counter_and_round_trip() {
    TestOnlyProvider provider;
    vfdual::AuthenticatedControlRecordSealerV1 sealer(make_key(), provider);
    vfdual::AuthenticatedControlRecordOpenerV1 opener(make_key(), provider);

    const std::vector<std::byte> request_plaintext(
        16U, std::byte{0x11U});
    const std::vector<std::byte> response_plaintext(
        32U, std::byte{0x22U});
    const auto request = sealer.seal(
        vfdual::ControlMessageTypeV1::host_start_intent_claim_request,
        request_plaintext);
    const auto response = sealer.seal(
        vfdual::ControlMessageTypeV1::host_start_intent_claim_response,
        response_plaintext);

    CHECK(request.status == vfdual::ControlRecordSealStatusV1::sealed);
    CHECK(response.status == vfdual::ControlRecordSealStatusV1::sealed);
    CHECK(request.counter == 0U);
    CHECK(response.counter == 1U);

    const auto opened_request = opener.open(request.envelope);
    CHECK(opened_request.status ==
        vfdual::ControlRecordOpenStatusV1::opened);
    CHECK(opened_request.message_type ==
        vfdual::ControlMessageTypeV1::host_start_intent_claim_request);
    CHECK(opened_request.plaintext == request_plaintext);

    const auto opened_response = opener.open(response.envelope);
    CHECK(opened_response.status ==
        vfdual::ControlRecordOpenStatusV1::opened);
    CHECK(opened_response.message_type ==
        vfdual::ControlMessageTypeV1::host_start_intent_claim_response);
    CHECK(opened_response.plaintext == response_plaintext);
}

void verifies_mutations_do_not_commit_replay_state() {
    TestOnlyProvider provider;
    vfdual::AuthenticatedControlRecordSealerV1 sealer(make_key(), provider);
    vfdual::AuthenticatedControlRecordOpenerV1 opener(make_key(), provider);

    const auto first = sealer.seal(
        vfdual::ControlMessageTypeV1::lease_offer, bytes("first"));
    auto bad_tag = first.envelope;
    bad_tag.back() ^= std::byte{0x01U};
    CHECK(opener.open(bad_tag).status ==
        vfdual::ControlRecordOpenStatusV1::unauthenticated_record);
    CHECK(!opener.replay_snapshot().initialized);
    CHECK(opener.open(first.envelope).status ==
        vfdual::ControlRecordOpenStatusV1::opened);

    const auto second = sealer.seal(
        vfdual::ControlMessageTypeV1::lease_commit, bytes("second"));
    auto wrong_type = second.envelope;
    wrong_type[kMessageTypeOffset] = std::byte{
        static_cast<std::uint8_t>(
            vfdual::ControlMessageTypeV1::session_close)};
    CHECK(opener.open(wrong_type).status ==
        vfdual::ControlRecordOpenStatusV1::unauthenticated_record);
    auto wrong_direction = second.envelope;
    wrong_direction[kDirectionOffset] = std::byte{
        static_cast<std::uint8_t>(
            vfdual::ControlRecordDirectionV1::android_to_host)};
    CHECK(opener.open(wrong_direction).status ==
        vfdual::ControlRecordOpenStatusV1::unauthenticated_record);
    auto wrong_connection = second.envelope;
    wrong_connection[kConnectionIdOffset] ^= std::byte{0x40U};
    CHECK(opener.open(wrong_connection).status ==
        vfdual::ControlRecordOpenStatusV1::unauthenticated_record);
    CHECK(opener.open(second.envelope).status ==
        vfdual::ControlRecordOpenStatusV1::opened);
}

void verifies_strict_parser() {
    TestOnlyProvider provider;
    vfdual::AuthenticatedControlRecordSealerV1 sealer(make_key(), provider);
    const auto sealed = sealer.seal(
        vfdual::ControlMessageTypeV1::session_close, bytes("close"));
    CHECK(sealed.status == vfdual::ControlRecordSealStatusV1::sealed);

    auto truncated = sealed.envelope;
    truncated.pop_back();
    CHECK(vfdual::parse_authenticated_control_record_v1(truncated).status ==
        vfdual::ControlRecordParseStatusV1::length_mismatch);
    auto trailing = sealed.envelope;
    trailing.push_back(std::byte{0U});
    CHECK(vfdual::parse_authenticated_control_record_v1(trailing).status ==
        vfdual::ControlRecordParseStatusV1::length_mismatch);
    auto invalid_type = sealed.envelope;
    invalid_type[kMessageTypeOffset] = std::byte{0xffU};
    CHECK(vfdual::parse_authenticated_control_record_v1(invalid_type).status ==
        vfdual::ControlRecordParseStatusV1::invalid_message_type);
    auto above_limit = sealed.envelope;
    const auto disallowed = vfdual::kMaximumAuthenticatedControlRecordsPerKey;
    for (std::size_t index{}; index < sizeof(disallowed); ++index) {
        const int shift = 56 - static_cast<int>(index * 8U);
        above_limit[kCounterOffset + index] = std::byte{
            static_cast<std::uint8_t>(disallowed >> shift)};
    }
    CHECK(vfdual::parse_authenticated_control_record_v1(above_limit).status ==
        vfdual::ControlRecordParseStatusV1::counter_exceeds_key_lifetime);
}

void verifies_provider_failure_burns_counter_and_limit() {
    FailFirstState state;
    FailFirstProvider failing_provider(state);
    auto sealer = vfdual::AuthenticatedControlRecordV1TestAccess::make_sealer(
        make_key(), failing_provider, 5U);
    const auto failed = sealer->seal(
        vfdual::ControlMessageTypeV1::lease_offer, bytes("failure"));
    CHECK(failed.status ==
        vfdual::ControlRecordSealStatusV1::encryption_failed);
    CHECK(failed.counter == 5U);
    CHECK(failed.envelope.empty());
    const auto after_failure = sealer->seal(
        vfdual::ControlMessageTypeV1::lease_offer, bytes("retry"));
    CHECK(after_failure.status ==
        vfdual::ControlRecordSealStatusV1::sealed);
    CHECK(after_failure.counter == 6U);

    TestOnlyProvider provider;
    auto final_sealer =
        vfdual::AuthenticatedControlRecordV1TestAccess::make_sealer(
            make_key(), provider,
            vfdual::kMaximumAuthenticatedControlCounter);
    const auto final = final_sealer->seal(
        vfdual::ControlMessageTypeV1::session_close, bytes("last"));
    CHECK(final.status == vfdual::ControlRecordSealStatusV1::sealed);
    CHECK(final.counter == vfdual::kMaximumAuthenticatedControlCounter);
    CHECK(final_sealer->seal(
        vfdual::ControlMessageTypeV1::session_close, bytes("too-late")).status ==
        vfdual::ControlRecordSealStatusV1::counter_exhausted);
}

void verifies_invalid_inputs_fail_closed() {
    TestOnlyProvider provider;
    vfdual::AuthenticatedControlRecordSealerV1 sealer(make_key(), provider);
    CHECK(sealer.seal(
        vfdual::ControlMessageTypeV1::invalid, bytes("x")).status ==
        vfdual::ControlRecordSealStatusV1::invalid_message_type);
    std::vector<std::byte> oversized(
        vfdual::kMaximumAuthenticatedControlPayloadBytes + 1U);
    CHECK(sealer.seal(
        vfdual::ControlMessageTypeV1::lease_offer, oversized).status ==
        vfdual::ControlRecordSealStatusV1::plaintext_too_large);

    auto invalid_tuple = make_tuple();
    invalid_tuple.session_generation = 0U;
    vfdual::AuthenticatedControlRecordOpenerV1 invalid_opener(
        make_key(invalid_tuple), provider);
    CHECK(invalid_opener.open({}).status ==
        vfdual::ControlRecordOpenStatusV1::invalid_configuration);
}

void verifies_platform_aes_gcm_vector() {
    auto provider = vfdual::make_platform_aes_256_gcm_provider();
#if defined(_WIN32)
    CHECK(provider != nullptr);
    vfdual::AuthenticatedControlRecordSealerV1 sealer(
        make_key(), *provider);
    const auto sealed = sealer.seal(
        vfdual::ControlMessageTypeV1::lease_offer, bytes("lease-token-v1"));
    CHECK(sealed.status == vfdual::ControlRecordSealStatusV1::sealed);
    const auto expected = bytes_from_hex(
        "56464331012801010102030405060708"
        "11121314151617180000000100000000000000000000000e"
        "70dc3d454649c1d3d25ed51e27eb"
        "90c38f65b29d2116262be102a306a49e");
    CHECK(sealed.envelope == expected);
#else
    CHECK(provider == nullptr);
#endif
}

}  // namespace

int main() {
    verifies_shared_counter_and_round_trip();
    verifies_start_intent_claim_types_share_counter_and_round_trip();
    verifies_mutations_do_not_commit_replay_state();
    verifies_strict_parser();
    verifies_provider_failure_burns_counter_and_limit();
    verifies_invalid_inputs_fail_closed();
    verifies_platform_aes_gcm_vector();
    std::cout << "authenticated_control_record_v1_tests: PASS\n";
    return EXIT_SUCCESS;
}
