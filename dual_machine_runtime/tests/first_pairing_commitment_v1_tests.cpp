#include "vfdual/first_pairing_commitment_v1.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

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

template <std::size_t Size>
void fill(std::array<std::byte, Size>& value, const std::uint8_t byte) {
    value.fill(std::byte{byte});
}

[[nodiscard]] vfdual::FirstPairingCommitmentFieldsV1 fields() {
    vfdual::FirstPairingCommitmentFieldsV1 value{};
    for (std::size_t index = 0U; index < value.attempt_id.size(); ++index) {
        value.attempt_id[index] = std::byte{
            static_cast<std::uint8_t>(index + 1U)};
    }
    fill(value.host_identity_spki_sha256, 0x11U);
    fill(value.android_identity_spki_sha256, 0x22U);
    fill(value.host_ephemeral_public_key, 0x33U);
    fill(value.android_ephemeral_public_key, 0x44U);
    value.host_ephemeral_public_key[0U] = std::byte{0x04U};
    value.android_ephemeral_public_key[0U] = std::byte{0x04U};
    fill(value.host_nonce, 0x55U);
    fill(value.android_nonce, 0x66U);
    value.host_ipv4 = {
        std::byte{192U}, std::byte{168U},
        std::byte{1U}, std::byte{22U}};
    value.android_ipv4 = {
        std::byte{192U}, std::byte{168U},
        std::byte{1U}, std::byte{42U}};
    value.video_port = 5005U;
    value.control_port = 5006U;
    fill(value.host_runtime_version_sha256, 0x77U);
    fill(value.android_runtime_version_sha256, 0x88U);
    value.expires_at_epoch = 2'000'000'000U;
    return value;
}

void fixed_cross_language_vector() {
    const auto result = vfdual::build_first_pairing_commitment_v1(fields());
    CHECK(result.succeeded());
    CHECK(result.canonical_encoding.size() == 368U);
    CHECK(result.canonical_encoding[0U] == std::byte{0x56U});
    CHECK(result.canonical_encoding[367U] == std::byte{0x00U});
    constexpr char digits[] = "0123456789abcdef";
    std::string commitment;
    commitment.reserve(result.commitment_sha256.size() * 2U);
    for (const auto byte : result.commitment_sha256) {
        const auto value = std::to_integer<std::uint8_t>(byte);
        commitment.push_back(digits[value >> 4U]);
        commitment.push_back(digits[value & 0x0fU]);
    }
    CHECK(commitment ==
        "33f3dca1e5830d6588a192e46cb3490a"
        "498988bef840cd63284dd98f5b5fa741");
    CHECK(result.sas() == "102685");
}

void invalid_fields_fail_closed() {
    auto candidate = fields();
    candidate.host_identity_spki_sha256 =
        candidate.android_identity_spki_sha256;
    CHECK(!vfdual::build_first_pairing_commitment_v1(candidate).succeeded());

    candidate = fields();
    candidate.host_ephemeral_public_key[0U] = std::byte{0x02U};
    CHECK(!vfdual::build_first_pairing_commitment_v1(candidate).succeeded());

    candidate = fields();
    candidate.control_port = candidate.video_port;
    CHECK(!vfdual::build_first_pairing_commitment_v1(candidate).succeeded());

    candidate = fields();
    candidate.required_capabilities = 0U;
    CHECK(!vfdual::build_first_pairing_commitment_v1(candidate).succeeded());
}

void fixed_user_confirmation_vector() {
    vfdual::FirstPairingUserConfirmationFieldsV1 input{};
    for (std::size_t index = 0U; index < input.attempt_id.size(); ++index) {
        input.attempt_id[index] = std::byte{
            static_cast<std::uint8_t>(index + 1U)};
    }
    input.commitment_sha256.fill(std::byte{0xaaU});
    input.expires_at_epoch = 2'000'000'000U;
    const auto result =
        vfdual::build_first_pairing_user_confirmation_v1(input);
    CHECK(result.succeeded());
    CHECK(result.canonical_encoding[0U] == std::byte{0x56U});
    CHECK(result.canonical_encoding[4U] == std::byte{0x01U});
    constexpr char digits[] = "0123456789abcdef";
    std::string digest;
    digest.reserve(result.payload_sha256.size() * 2U);
    for (const auto byte : result.payload_sha256) {
        const auto value = std::to_integer<std::uint8_t>(byte);
        digest.push_back(digits[value >> 4U]);
        digest.push_back(digits[value & 0x0fU]);
    }
    CHECK(digest ==
        "e54fa513da2102870b3e7f6439d5cbf7"
        "2c6568f69c0d42de0e8fe3d0e6290308");

    auto invalid = input;
    invalid.expires_at_epoch = 0U;
    CHECK(!vfdual::build_first_pairing_user_confirmation_v1(
        invalid).succeeded());
    invalid = input;
    invalid.method = static_cast<
        vfdual::FirstPairingConfirmationMethodV1>(0U);
    CHECK(!vfdual::build_first_pairing_user_confirmation_v1(
        invalid).succeeded());
}

}  // namespace

int main() {
    fixed_cross_language_vector();
    invalid_fields_fail_closed();
    fixed_user_confirmation_vector();
    std::cout << "first pairing commitment v1 tests passed\n";
    return EXIT_SUCCESS;
}
