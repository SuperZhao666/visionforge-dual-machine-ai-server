#include "vfdual/authenticated_control_bootstrap_record_v1.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <iterator>
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

[[nodiscard]] std::vector<std::byte> ascii(
    const std::string_view value) {
    std::vector<std::byte> result;
    result.reserve(value.size());
    std::transform(
        value.begin(), value.end(), std::back_inserter(result),
        [](const char character) {
            return std::byte{static_cast<std::uint8_t>(character)};
        });
    return result;
}

[[nodiscard]] std::vector<std::byte> hex(
    const std::string_view encoded) {
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
    for (std::size_t index = 0U; index < result.size(); ++index) {
        result[index] = std::byte{static_cast<std::uint8_t>(
            (nibble(encoded[index * 2U]) << 4U) |
            nibble(encoded[index * 2U + 1U]))};
    }
    return result;
}

void test_fixed_cross_language_vector() {
    const auto payload = ascii("host-hello");
    const auto encoded =
        vfdual::encode_authenticated_control_bootstrap_record_v1(
            vfdual::ControlBootstrapDirectionV1::host_to_android,
            vfdual::ControlBootstrapMessageTypeV1::host_hello,
            payload);
    CHECK(encoded.status ==
        vfdual::ControlBootstrapEncodeStatusV1::encoded);
    CHECK(encoded.record == hex(
        "56464231010c01010000000a686f73742d68656c6c6f"));
    const auto parsed =
        vfdual::parse_authenticated_control_bootstrap_record_v1(
            encoded.record,
            vfdual::ControlBootstrapDirectionV1::host_to_android);
    CHECK(parsed.status ==
        vfdual::ControlBootstrapParseStatusV1::parsed);
    CHECK(parsed.record.direction ==
        vfdual::ControlBootstrapDirectionV1::host_to_android);
    CHECK(parsed.record.message_type ==
        vfdual::ControlBootstrapMessageTypeV1::host_hello);
    CHECK(std::equal(
        parsed.record.payload.begin(), parsed.record.payload.end(),
        payload.begin(), payload.end()));
}

void test_direction_contract_covers_every_message() {
    using D = vfdual::ControlBootstrapDirectionV1;
    using M = vfdual::ControlBootstrapMessageTypeV1;
    constexpr std::array host_types{
        M::host_hello,
        M::host_challenge_proof,
        M::host_final_proof,
        M::host_handshake_signature,
        M::host_finished,
    };
    constexpr std::array android_types{
        M::android_challenge_request,
        M::server_challenge,
        M::pair_generation_credential,
        M::android_handshake_confirmation,
    };
    for (const auto type : host_types) {
        CHECK(vfdual::control_bootstrap_message_allowed_v1(
            D::host_to_android, type));
        CHECK(!vfdual::control_bootstrap_message_allowed_v1(
            D::android_to_host, type));
    }
    for (const auto type : android_types) {
        CHECK(vfdual::control_bootstrap_message_allowed_v1(
            D::android_to_host, type));
        CHECK(!vfdual::control_bootstrap_message_allowed_v1(
            D::host_to_android, type));
    }
    CHECK(vfdual::control_bootstrap_message_allowed_v1(
        D::host_to_android, M::abort));
    CHECK(vfdual::control_bootstrap_message_allowed_v1(
        D::android_to_host, M::abort));
    CHECK(!vfdual::control_bootstrap_message_allowed_v1(
        D::invalid, M::abort));
    CHECK(!vfdual::control_bootstrap_message_allowed_v1(
        D::host_to_android, M::invalid));
}

void test_invalid_encode_inputs_fail_before_allocation() {
    using D = vfdual::ControlBootstrapDirectionV1;
    using M = vfdual::ControlBootstrapMessageTypeV1;
    const std::array one{std::byte{1U}};
    CHECK(vfdual::encode_authenticated_control_bootstrap_record_v1(
        D::invalid, M::host_hello, one).status ==
        vfdual::ControlBootstrapEncodeStatusV1::invalid_direction);
    CHECK(vfdual::encode_authenticated_control_bootstrap_record_v1(
        D::host_to_android, M::invalid, one).status ==
        vfdual::ControlBootstrapEncodeStatusV1::invalid_message_type);
    CHECK(vfdual::encode_authenticated_control_bootstrap_record_v1(
        D::android_to_host, M::host_hello, one).status ==
        vfdual::ControlBootstrapEncodeStatusV1::direction_mismatch);
    CHECK(vfdual::encode_authenticated_control_bootstrap_record_v1(
        D::host_to_android, M::host_hello, {}).status ==
        vfdual::ControlBootstrapEncodeStatusV1::payload_empty);
    const std::vector<std::byte> oversized(
        vfdual::kMaximumAuthenticatedControlBootstrapPayloadBytes + 1U);
    CHECK(vfdual::encode_authenticated_control_bootstrap_record_v1(
        D::host_to_android, M::host_hello, oversized).status ==
        vfdual::ControlBootstrapEncodeStatusV1::payload_too_large);
}

void test_parser_rejects_mutation_reflection_and_length_confusion() {
    using D = vfdual::ControlBootstrapDirectionV1;
    using M = vfdual::ControlBootstrapMessageTypeV1;
    const auto payload = ascii("challenge");
    const auto encoded =
        vfdual::encode_authenticated_control_bootstrap_record_v1(
            D::android_to_host, M::server_challenge, payload);
    CHECK(encoded.status ==
        vfdual::ControlBootstrapEncodeStatusV1::encoded);
    auto mutation = encoded.record;
    mutation[0U] ^= std::byte{1U};
    CHECK(vfdual::parse_authenticated_control_bootstrap_record_v1(
        mutation, D::android_to_host).status ==
        vfdual::ControlBootstrapParseStatusV1::invalid_magic);
    mutation = encoded.record;
    mutation[4U] = std::byte{2U};
    CHECK(vfdual::parse_authenticated_control_bootstrap_record_v1(
        mutation, D::android_to_host).status ==
        vfdual::ControlBootstrapParseStatusV1::unsupported_version);
    mutation = encoded.record;
    mutation[5U] = std::byte{13U};
    CHECK(vfdual::parse_authenticated_control_bootstrap_record_v1(
        mutation, D::android_to_host).status ==
        vfdual::ControlBootstrapParseStatusV1::invalid_header_size);
    mutation = encoded.record;
    mutation[6U] = std::byte{0U};
    CHECK(vfdual::parse_authenticated_control_bootstrap_record_v1(
        mutation, D::android_to_host).status ==
        vfdual::ControlBootstrapParseStatusV1::invalid_direction);
    CHECK(vfdual::parse_authenticated_control_bootstrap_record_v1(
        encoded.record, D::host_to_android).status ==
        vfdual::ControlBootstrapParseStatusV1::unexpected_direction);
    mutation = encoded.record;
    mutation[7U] = std::byte{0xffU};
    CHECK(vfdual::parse_authenticated_control_bootstrap_record_v1(
        mutation, D::android_to_host).status ==
        vfdual::ControlBootstrapParseStatusV1::invalid_message_type);
    mutation = encoded.record;
    mutation[7U] = std::byte{1U};
    CHECK(vfdual::parse_authenticated_control_bootstrap_record_v1(
        mutation, D::android_to_host).status ==
        vfdual::ControlBootstrapParseStatusV1::direction_mismatch);
    mutation = encoded.record;
    mutation[11U] = std::byte{0U};
    CHECK(vfdual::parse_authenticated_control_bootstrap_record_v1(
        mutation, D::android_to_host).status ==
        vfdual::ControlBootstrapParseStatusV1::payload_empty);
    mutation = encoded.record;
    mutation[8U] = std::byte{0U};
    mutation[9U] = std::byte{1U};
    mutation[10U] = std::byte{0U};
    mutation[11U] = std::byte{1U};
    CHECK(vfdual::parse_authenticated_control_bootstrap_record_v1(
        mutation, D::android_to_host).status ==
        vfdual::ControlBootstrapParseStatusV1::payload_too_large);
    mutation = encoded.record;
    mutation.pop_back();
    CHECK(vfdual::parse_authenticated_control_bootstrap_record_v1(
        mutation, D::android_to_host).status ==
        vfdual::ControlBootstrapParseStatusV1::length_mismatch);
    mutation = encoded.record;
    mutation.push_back(std::byte{0U});
    CHECK(vfdual::parse_authenticated_control_bootstrap_record_v1(
        mutation, D::android_to_host).status ==
        vfdual::ControlBootstrapParseStatusV1::length_mismatch);
}

void test_maximum_payload_is_exact() {
    const std::vector<std::byte> maximum(
        vfdual::kMaximumAuthenticatedControlBootstrapPayloadBytes,
        std::byte{0xa5U});
    const auto encoded =
        vfdual::encode_authenticated_control_bootstrap_record_v1(
            vfdual::ControlBootstrapDirectionV1::android_to_host,
            vfdual::ControlBootstrapMessageTypeV1::
                pair_generation_credential,
            maximum);
    CHECK(encoded.status ==
        vfdual::ControlBootstrapEncodeStatusV1::encoded);
    const auto parsed =
        vfdual::parse_authenticated_control_bootstrap_record_v1(
            encoded.record,
            vfdual::ControlBootstrapDirectionV1::android_to_host);
    CHECK(parsed.status ==
        vfdual::ControlBootstrapParseStatusV1::parsed);
    CHECK(parsed.record.payload.size() == maximum.size());
}

void test_host_and_android_complete_the_same_exact_sequence() {
    using A = vfdual::ControlBootstrapAdvanceStatusV1;
    using F = vfdual::ControlBootstrapFlowV1;
    using M = vfdual::ControlBootstrapMessageTypeV1;
    using P = vfdual::ControlBootstrapSequencePhaseV1;
    using R = vfdual::ControlBootstrapRoleV1;
    constexpr std::array sequence{
        M::host_hello,
        M::android_challenge_request,
        M::host_challenge_proof,
        M::server_challenge,
        M::host_final_proof,
        M::pair_generation_credential,
        M::host_handshake_signature,
        M::android_handshake_confirmation,
        M::host_finished,
    };
    vfdual::ControlBootstrapSequenceV1 host(R::host);
    vfdual::ControlBootstrapSequenceV1 android(R::android);
    for (std::size_t index = 0U; index < sequence.size(); ++index) {
        const bool host_sends = index % 2U == 0U;
        const auto host_expected = host.expected_next();
        const auto android_expected = android.expected_next();
        CHECK(host_expected.present);
        CHECK(android_expected.present);
        CHECK(host_expected.message_type == sequence[index]);
        CHECK(android_expected.message_type == sequence[index]);
        CHECK(host_expected.flow ==
            (host_sends ? F::outbound : F::inbound));
        CHECK(android_expected.flow ==
            (host_sends ? F::inbound : F::outbound));
        const A expected_status = index + 1U == sequence.size()
            ? A::completed
            : A::advanced;
        CHECK((host_sends
            ? host.advance_outbound(sequence[index])
            : host.advance_inbound(sequence[index])) == expected_status);
        CHECK((host_sends
            ? android.advance_inbound(sequence[index])
            : android.advance_outbound(sequence[index])) == expected_status);
        CHECK(host.accepted_event_count() == index + 1U);
        CHECK(android.accepted_event_count() == index + 1U);
    }
    CHECK(host.phase() == P::completed);
    CHECK(android.phase() == P::completed);
    CHECK(!host.expected_next().present);
    CHECK(host.advance_outbound(M::abort) == A::already_terminal);
    CHECK(android.advance_inbound(M::host_finished) == A::already_terminal);
}

void test_sequence_failures_and_abort_are_terminal() {
    using A = vfdual::ControlBootstrapAdvanceStatusV1;
    using M = vfdual::ControlBootstrapMessageTypeV1;
    using P = vfdual::ControlBootstrapSequencePhaseV1;
    using R = vfdual::ControlBootstrapRoleV1;

    vfdual::ControlBootstrapSequenceV1 wrong_flow(R::host);
    CHECK(wrong_flow.advance_inbound(M::host_hello) == A::wrong_flow);
    CHECK(wrong_flow.phase() == P::failed);
    CHECK(wrong_flow.accepted_event_count() == 0U);
    CHECK(wrong_flow.advance_outbound(M::host_hello) == A::already_terminal);

    vfdual::ControlBootstrapSequenceV1 skipped(R::host);
    CHECK(skipped.advance_outbound(M::host_final_proof) ==
        A::unexpected_message);
    CHECK(skipped.phase() == P::failed);

    vfdual::ControlBootstrapSequenceV1 repeated(R::host);
    CHECK(repeated.advance_outbound(M::host_hello) == A::advanced);
    CHECK(repeated.advance_outbound(M::host_hello) == A::wrong_flow);
    CHECK(repeated.phase() == P::failed);

    vfdual::ControlBootstrapSequenceV1 local_abort(R::host);
    CHECK(local_abort.advance_outbound(M::abort) == A::aborted);
    CHECK(local_abort.phase() == P::aborted);
    CHECK(local_abort.advance_inbound(M::abort) == A::already_terminal);

    vfdual::ControlBootstrapSequenceV1 peer_abort(R::android);
    CHECK(peer_abort.advance_inbound(M::abort) == A::aborted);
    CHECK(peer_abort.phase() == P::aborted);

    vfdual::ControlBootstrapSequenceV1 invalid(R::invalid);
    CHECK(invalid.phase() == P::failed);
    CHECK(invalid.advance_outbound(M::abort) == A::already_terminal);
}

}  // namespace

int main() {
    test_fixed_cross_language_vector();
    test_direction_contract_covers_every_message();
    test_invalid_encode_inputs_fail_before_allocation();
    test_parser_rejects_mutation_reflection_and_length_confusion();
    test_maximum_payload_is_exact();
    test_host_and_android_complete_the_same_exact_sequence();
    test_sequence_failures_and_abort_are_terminal();
    std::cout << "authenticated control bootstrap record v1 tests passed\n";
    return EXIT_SUCCESS;
}
