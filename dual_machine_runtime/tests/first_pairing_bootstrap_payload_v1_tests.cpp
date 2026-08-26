#include "vfdual/first_pairing_bootstrap_payload_v1.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

#define CHECK(condition)                                                      \
    do {                                                                      \
        if (!(condition)) {                                                   \
            std::cerr << "CHECK failed at line " << __LINE__ << ": "       \
                      << #condition << '\n';                                  \
            return EXIT_FAILURE;                                              \
        }                                                                     \
    } while (false)

template <std::size_t Size>
std::array<std::byte, Size> filled(const std::uint8_t value) {
    std::array<std::byte, Size> result{};
    result.fill(std::byte{value});
    return result;
}

std::vector<std::uint8_t> shaped_spki() {
    const std::array<std::uint8_t, 27U> prefix{
        0x30U, 0x59U, 0x30U, 0x13U, 0x06U, 0x07U, 0x2aU, 0x86U,
        0x48U, 0xceU, 0x3dU, 0x02U, 0x01U, 0x06U, 0x08U, 0x2aU,
        0x86U, 0x48U, 0xceU, 0x3dU, 0x03U, 0x01U, 0x07U, 0x03U,
        0x42U, 0x00U, 0x04U};
    std::vector<std::uint8_t> result(prefix.begin(), prefix.end());
    for (std::uint8_t value = 1U; value <= 64U; ++value) {
        result.push_back(value);
    }
    return result;
}

std::vector<std::uint8_t> shaped_signature() {
    return {0x30U, 0x06U, 0x02U, 0x01U, 0x01U,
            0x02U, 0x01U, 0x01U};
}

}  // namespace

int main() {
    using namespace vfdual;
    using Type = ControlBootstrapMessageTypeV1;
    using Direction = ControlBootstrapDirectionV1;

    FirstPairingOfferPayloadV1 offer;
    offer.attempt_id = filled<16U>(0x11U);
    offer.identity_subject_public_key_info_der = shaped_spki();
    offer.ephemeral_public_key = filled<65U>(0x22U);
    offer.ephemeral_public_key[0U] = std::byte{0x04U};
    offer.nonce = filled<32U>(0x33U);
    offer.runtime_version_sha256 = filled<32U>(0x44U);
    offer.expires_at_epoch = 1'800'000'000ULL;

    const auto encoded_offer = encode_first_pairing_offer_payload_v1(
        Type::host_first_pair_offer, offer);
    CHECK(encoded_offer.has_value());
    CHECK(encoded_offer->size() == 256U);
    const auto parsed_offer = parse_first_pairing_offer_payload_v1(
        Type::host_first_pair_offer, *encoded_offer);
    CHECK(parsed_offer.has_value());
    CHECK(parsed_offer->attempt_id == offer.attempt_id);
    CHECK(parsed_offer->identity_subject_public_key_info_der ==
        offer.identity_subject_public_key_info_der);
    CHECK(parsed_offer->ephemeral_public_key == offer.ephemeral_public_key);
    CHECK(parsed_offer->nonce == offer.nonce);
    CHECK(parsed_offer->runtime_version_sha256 ==
        offer.runtime_version_sha256);
    CHECK(parsed_offer->expires_at_epoch == offer.expires_at_epoch);
    auto bad_offer = *encoded_offer;
    bad_offer[5U] = std::byte{0U};
    CHECK(!parse_first_pairing_offer_payload_v1(
        Type::host_first_pair_offer, bad_offer).has_value());

    FirstPairingConfirmationPayloadV1 confirmation;
    confirmation.fields.role = FirstPairingConfirmationRoleV1::android;
    confirmation.fields.method =
        FirstPairingConfirmationMethodV1::decimal_sas;
    confirmation.fields.attempt_id = offer.attempt_id;
    confirmation.fields.commitment_sha256 = filled<32U>(0x55U);
    confirmation.fields.expires_at_epoch = offer.expires_at_epoch;
    confirmation.signature_der_low_s = shaped_signature();
    const auto encoded_confirmation =
        encode_first_pairing_confirmation_payload_v1(
            Type::android_first_pair_confirmation, confirmation);
    CHECK(encoded_confirmation.has_value());
    const auto parsed_confirmation =
        parse_first_pairing_confirmation_payload_v1(
            Type::android_first_pair_confirmation, *encoded_confirmation);
    CHECK(parsed_confirmation.has_value());
    CHECK(parsed_confirmation->fields.commitment_sha256 ==
        confirmation.fields.commitment_sha256);
    CHECK(parsed_confirmation->signature_der_low_s ==
        confirmation.signature_der_low_s);
    CHECK(!encode_first_pairing_confirmation_payload_v1(
        Type::host_first_pair_confirmation, confirmation).has_value());

    const ActivationConfirmationProof proof{
        .activation_mode = "activate",
        .android_client_version = "1.0.0",
        .android_device_code = "ANDROID-ABC",
        .android_device_profile_sha256 = std::string(64U, '4'),
        .android_key_sha256 = std::string(64U, '5'),
        .challenge_id = std::string(32U, '1'),
        .challenge_token_sha256 = std::string(64U, '6'),
        .host_client_version = "17.8.81",
        .host_device_code = "HOST-XYZ",
        .host_key_sha256 = std::string(64U, '7'),
        .pair_id = std::string(32U, '2'),
        .protocol_version = 2U,
        .request_id = std::string(32U, '3'),
        .target_entitlement_id = "",
    };
    const auto encoded_proof =
        encode_first_pairing_activation_proof_request_v1(proof);
    CHECK(encoded_proof.has_value());
    const auto parsed_proof =
        parse_first_pairing_activation_proof_request_v1(*encoded_proof);
    CHECK(parsed_proof.has_value());
    CHECK(build_activation_confirmation_payload(*parsed_proof) ==
        build_activation_confirmation_payload(proof));
    auto bad_proof = *encoded_proof;
    bad_proof.back() = std::byte{1U};
    CHECK(!parse_first_pairing_activation_proof_request_v1(
        bad_proof).has_value());

    FirstPairingActivationSignaturePayloadV1 activation_signature{
        .canonical_payload_sha256 = filled<32U>(0x66U),
        .signature_der_low_s = shaped_signature(),
    };
    const auto encoded_signature =
        encode_first_pairing_activation_signature_payload_v1(
            activation_signature);
    CHECK(encoded_signature.has_value());
    const auto parsed_signature =
        parse_first_pairing_activation_signature_payload_v1(
            *encoded_signature);
    CHECK(parsed_signature.has_value());
    CHECK(parsed_signature->canonical_payload_sha256 ==
        activation_signature.canonical_payload_sha256);

    const FirstPairingActivationResultPayloadV1 activation_result{
        .entitlement_id = std::string(32U, '1'),
        .pair_id = std::string(32U, '2'),
        .binding_id = std::string(32U, '3'),
        .binding_revision = 4U,
        .revocation_version = 5U,
    };
    const auto encoded_result =
        encode_first_pairing_activation_result_payload_v1(activation_result);
    CHECK(encoded_result.has_value());
    const auto parsed_result =
        parse_first_pairing_activation_result_payload_v1(*encoded_result);
    CHECK(parsed_result.has_value());
    CHECK(parsed_result->pair_id == activation_result.pair_id);
    CHECK(parsed_result->binding_revision == 4U);

    const auto complete = encode_first_pairing_complete_payload_v1(
        confirmation.fields.commitment_sha256);
    CHECK(complete.has_value());
    CHECK(parse_first_pairing_complete_payload_v1(*complete) ==
        confirmation.fields.commitment_sha256);

    const std::array host_types{
        Type::host_first_pair_offer,
        Type::host_first_pair_confirmation,
        Type::host_activation_signature,
        Type::first_pair_complete};
    const std::array android_types{
        Type::android_first_pair_offer,
        Type::android_first_pair_confirmation,
        Type::activation_proof_request,
        Type::activation_result};
    const std::array<std::byte, 1U> body{std::byte{1U}};
    for (const Type type : host_types) {
        CHECK(encode_authenticated_control_bootstrap_record_v1(
            Direction::host_to_android, type, body).status ==
            ControlBootstrapEncodeStatusV1::encoded);
        CHECK(encode_authenticated_control_bootstrap_record_v1(
            Direction::android_to_host, type, body).status ==
            ControlBootstrapEncodeStatusV1::direction_mismatch);
    }
    for (const Type type : android_types) {
        CHECK(encode_authenticated_control_bootstrap_record_v1(
            Direction::android_to_host, type, body).status ==
            ControlBootstrapEncodeStatusV1::encoded);
        CHECK(encode_authenticated_control_bootstrap_record_v1(
            Direction::host_to_android, type, body).status ==
            ControlBootstrapEncodeStatusV1::direction_mismatch);
    }

    std::cout << "first pairing bootstrap payload v1 tests passed\n";
    return EXIT_SUCCESS;
}
