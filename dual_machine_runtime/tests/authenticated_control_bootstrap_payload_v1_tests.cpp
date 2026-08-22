#include "vfdual/authenticated_control_bootstrap_payload_v1.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {

void require(
    const bool condition,
    const char* expression,
    const char* file,
    const int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: "
              << expression << '\n';
    std::exit(EXIT_FAILURE);
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

namespace {

using Message = vfdual::ControlBootstrapMessageTypeV1;
using Status = vfdual::ControlBootstrapPayloadStatusV1;

[[nodiscard]] std::vector<std::byte> ascii(const std::string_view value) {
    std::vector<std::byte> result(value.size());
    std::transform(value.begin(), value.end(), result.begin(), [](const char value) {
        return std::byte{static_cast<std::uint8_t>(value)};
    });
    return result;
}

[[nodiscard]] std::vector<std::byte> filled(
    const std::size_t size,
    const std::uint8_t value) {
    return std::vector<std::byte>(size, std::byte{value});
}

[[nodiscard]] std::vector<std::byte> u16(const std::uint16_t value) {
    return {
        std::byte{static_cast<std::uint8_t>(value >> 8U)},
        std::byte{static_cast<std::uint8_t>(value)},
    };
}

[[nodiscard]] std::vector<std::byte> u64(const std::uint64_t value) {
    std::vector<std::byte> result(8U);
    for (std::size_t index{}; index < result.size(); ++index) {
        result[index] = std::byte{static_cast<std::uint8_t>(
            value >> ((result.size() - index - 1U) * 8U))};
    }
    return result;
}

[[nodiscard]] std::vector<std::byte> canonical_spki(
    const std::uint8_t coordinate) {
    auto result = std::vector<std::byte>{
        std::byte{0x30U}, std::byte{0x59U}, std::byte{0x30U}, std::byte{0x13U},
        std::byte{0x06U}, std::byte{0x07U}, std::byte{0x2aU}, std::byte{0x86U},
        std::byte{0x48U}, std::byte{0xceU}, std::byte{0x3dU}, std::byte{0x02U},
        std::byte{0x01U}, std::byte{0x06U}, std::byte{0x08U}, std::byte{0x2aU},
        std::byte{0x86U}, std::byte{0x48U}, std::byte{0xceU}, std::byte{0x3dU},
        std::byte{0x03U}, std::byte{0x01U}, std::byte{0x07U}, std::byte{0x03U},
        std::byte{0x42U}, std::byte{0x00U}, std::byte{0x04U},
    };
    result.resize(91U, std::byte{coordinate});
    return result;
}

[[nodiscard]] std::vector<std::byte> sec1(const std::uint8_t coordinate) {
    auto result = filled(65U, coordinate);
    result.front() = std::byte{0x04U};
    return result;
}

[[nodiscard]] std::vector<std::byte> signature() {
    return {
        std::byte{0x30U}, std::byte{0x06U},
        std::byte{0x02U}, std::byte{0x01U}, std::byte{0x01U},
        std::byte{0x02U}, std::byte{0x01U}, std::byte{0x01U},
    };
}

[[nodiscard]] std::vector<std::vector<std::byte>> valid_values(
    const Message message) {
    switch (message) {
        case Message::host_hello:
            return {
                canonical_spki(0x11U), sec1(0x22U), filled(32U, 0x33U),
                {std::byte{1U}},
                {std::byte{10U}, std::byte{57U}, std::byte{23U}, std::byte{1U}},
                {std::byte{10U}, std::byte{57U}, std::byte{23U}, std::byte{2U}},
                u16(5000U), u16(5006U), ascii("1.2.3")};
        case Message::android_challenge_request:
            return {
                ascii("11111111111111111111111111111111"),
                ascii("22222222222222222222222222222222"),
                ascii("33333333333333333333333333333333"),
                ascii("44444444444444444444444444444444"),
                ascii("55555555555555555555555555555555"),
                u64(7U), u64(9U), canonical_spki(0x44U), sec1(0x55U),
                filled(32U, 0x66U), ascii("2.3.4"), signature()};
        case Message::host_challenge_proof:
        case Message::host_final_proof:
        case Message::host_handshake_signature:
            return {signature()};
        case Message::server_challenge:
            return {
                ascii("11111111111111111111111111111111"),
                u64(1'756'000'000U), filled(32U, 0xa5U)};
        case Message::pair_generation_credential:
            return {ascii("eyJhbGciOiJSUzI1NiJ9.e30.c2ln")};
        case Message::android_handshake_confirmation:
            return {signature(), filled(32U, 0x77U)};
        case Message::host_finished:
            return {filled(32U, 0x88U)};
        case Message::abort:
            return {u16(1U)};
        case Message::invalid:
            return {};
    }
    return {};
}

[[nodiscard]] std::vector<vfdual::ControlBootstrapPayloadFieldV1> views(
    const std::vector<std::vector<std::byte>>& values) {
    std::vector<vfdual::ControlBootstrapPayloadFieldV1> result;
    result.reserve(values.size());
    for (std::size_t index{}; index < values.size(); ++index) {
        result.push_back({
            static_cast<std::uint8_t>(index),
            std::span<const std::byte>{values[index]}});
    }
    return result;
}

[[nodiscard]] std::vector<std::byte> hex(const std::string_view encoded) {
    CHECK(encoded.size() % 2U == 0U);
    auto nibble = [](const char value) -> std::uint8_t {
        if (value >= '0' && value <= '9') {
            return static_cast<std::uint8_t>(value - '0');
        }
        if (value >= 'a' && value <= 'f') {
            return static_cast<std::uint8_t>(value - 'a' + 10);
        }
        CHECK(false);
        return 0U;
    };
    std::vector<std::byte> result(encoded.size() / 2U);
    for (std::size_t index{}; index < result.size(); ++index) {
        result[index] = std::byte{static_cast<std::uint8_t>(
            (nibble(encoded[index * 2U]) << 4U) |
            nibble(encoded[index * 2U + 1U]))};
    }
    return result;
}

void test_every_message_round_trips_with_exact_schema() {
    constexpr std::array messages{
        Message::host_hello,
        Message::android_challenge_request,
        Message::host_challenge_proof,
        Message::server_challenge,
        Message::host_final_proof,
        Message::pair_generation_credential,
        Message::host_handshake_signature,
        Message::android_handshake_confirmation,
        Message::host_finished,
        Message::abort,
    };
    for (const Message message : messages) {
        const auto values = valid_values(message);
        const auto field_views = views(values);
        const auto encoded = vfdual::encode_control_bootstrap_payload_v1(
            message, field_views);
        CHECK(encoded.status == Status::encoded);
        const auto parsed = vfdual::parse_control_bootstrap_payload_v1(
            message, encoded.payload);
        CHECK(parsed.status == Status::parsed);
        CHECK(parsed.payload.message_type == message);
        CHECK(parsed.payload.field_count == values.size());
        for (std::size_t index{}; index < values.size(); ++index) {
            CHECK(std::equal(
                parsed.payload.field(static_cast<std::uint8_t>(index)).begin(),
                parsed.payload.field(static_cast<std::uint8_t>(index)).end(),
                values[index].begin(), values[index].end()));
        }
        CHECK(parsed.payload.field(0xffU).empty());
    }
}

void test_server_challenge_fixed_cross_language_vector() {
    const auto values = valid_values(Message::server_challenge);
    const auto encoded = vfdual::encode_control_bootstrap_payload_v1(
        Message::server_challenge, views(values));
    CHECK(encoded.status == Status::encoded);
    CHECK(encoded.payload == hex(
        "0000000020"
        "3131313131313131313131313131313131313131313131313131313131313131"
        "01000000080000000068aa6f00"
        "0200000020"
        "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"
        "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"));
}

void test_parser_rejects_tag_length_value_and_trailing_confusion() {
    const auto values = valid_values(Message::server_challenge);
    const auto encoded = vfdual::encode_control_bootstrap_payload_v1(
        Message::server_challenge, views(values));
    CHECK(encoded.status == Status::encoded);
    auto mutation = encoded.payload;
    mutation[0U] = std::byte{1U};
    auto parsed = vfdual::parse_control_bootstrap_payload_v1(
        Message::server_challenge, mutation);
    CHECK(parsed.status == Status::unexpected_field_tag);
    CHECK(parsed.field_tag == 1U);
    mutation = encoded.payload;
    mutation[4U] = std::byte{31U};
    CHECK(vfdual::parse_control_bootstrap_payload_v1(
        Message::server_challenge, mutation).status ==
        Status::invalid_field_length);
    mutation = encoded.payload;
    mutation[5U] = std::byte{'g'};
    CHECK(vfdual::parse_control_bootstrap_payload_v1(
        Message::server_challenge, mutation).status ==
        Status::invalid_field_value);
    mutation = encoded.payload;
    mutation.pop_back();
    CHECK(vfdual::parse_control_bootstrap_payload_v1(
        Message::server_challenge, mutation).status ==
        Status::truncated_tlv);
    mutation = encoded.payload;
    mutation.push_back(std::byte{0U});
    CHECK(vfdual::parse_control_bootstrap_payload_v1(
        Message::server_challenge, mutation).status ==
        Status::trailing_data);
    CHECK(vfdual::parse_control_bootstrap_payload_v1(
        Message::invalid, encoded.payload).status ==
        Status::invalid_message_type);
    CHECK(vfdual::parse_control_bootstrap_payload_v1(
        Message::server_challenge, {}).status == Status::payload_empty);
}

void test_encoder_rejects_noncanonical_and_cross_field_values() {
    auto hello_values = valid_values(Message::host_hello);
    hello_values[7U] = hello_values[6U];
    CHECK(vfdual::encode_control_bootstrap_payload_v1(
        Message::host_hello, views(hello_values)).status ==
        Status::invalid_field_value);
    hello_values = valid_values(Message::host_hello);
    hello_values[8U] = ascii("01.2.3");
    CHECK(vfdual::encode_control_bootstrap_payload_v1(
        Message::host_hello, views(hello_values)).status ==
        Status::invalid_field_value);
    auto signature_values = valid_values(Message::host_final_proof);
    signature_values[0U][1U] = std::byte{0x05U};
    CHECK(vfdual::encode_control_bootstrap_payload_v1(
        Message::host_final_proof, views(signature_values)).status ==
        Status::invalid_field_value);
    auto android_values = valid_values(Message::android_challenge_request);
    android_values[0U][0U] = std::byte{'A'};
    CHECK(vfdual::encode_control_bootstrap_payload_v1(
        Message::android_challenge_request, views(android_values)).status ==
        Status::invalid_field_value);
    auto wrong_count = valid_values(Message::server_challenge);
    wrong_count.pop_back();
    CHECK(vfdual::encode_control_bootstrap_payload_v1(
        Message::server_challenge, views(wrong_count)).status ==
        Status::invalid_field_count);
    const auto wrong_tag_values = valid_values(Message::server_challenge);
    auto wrong_tags = views(wrong_tag_values);
    wrong_tags[1U].tag = 2U;
    CHECK(vfdual::encode_control_bootstrap_payload_v1(
        Message::server_challenge, wrong_tags).status ==
        Status::unexpected_field_tag);
}

void test_credential_bound_is_exact_and_jwt_shaped() {
    std::string maximum("a.");
    maximum.append(
        vfdual::kControlBootstrapPayloadMaximumCredentialBytesV1 - 4U,
        'b');
    maximum.append(".c");
    auto values = std::vector<std::vector<std::byte>>{ascii(maximum)};
    const auto encoded = vfdual::encode_control_bootstrap_payload_v1(
        Message::pair_generation_credential, views(values));
    CHECK(encoded.status == Status::encoded);
    CHECK(vfdual::parse_control_bootstrap_payload_v1(
        Message::pair_generation_credential, encoded.payload).status ==
        Status::parsed);
    maximum.insert(maximum.begin(), 'a');
    values = {ascii(maximum)};
    CHECK(vfdual::encode_control_bootstrap_payload_v1(
        Message::pair_generation_credential, views(values)).status ==
        Status::invalid_field_length);
    values = {ascii("header.payload.")};
    CHECK(vfdual::encode_control_bootstrap_payload_v1(
        Message::pair_generation_credential, views(values)).status ==
        Status::invalid_field_value);
}

}  // namespace

int main() {
    test_every_message_round_trips_with_exact_schema();
    test_server_challenge_fixed_cross_language_vector();
    test_parser_rejects_tag_length_value_and_trailing_confusion();
    test_encoder_rejects_noncanonical_and_cross_field_values();
    test_credential_bound_is_exact_and_jwt_shaped();
    std::cout << "authenticated control bootstrap payload v1 tests passed\n";
    return EXIT_SUCCESS;
}
