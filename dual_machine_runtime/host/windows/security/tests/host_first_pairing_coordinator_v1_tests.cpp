#include "vfdual/host_first_pairing_coordinator_v1.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
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

constexpr std::array<std::uint8_t, 32U> kP256HalfOrder{
    0x7fU, 0xffU, 0xffU, 0xffU, 0x80U, 0x00U, 0x00U, 0x00U,
    0x7fU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
    0xdeU, 0x73U, 0x7dU, 0x56U, 0xd3U, 0x8bU, 0xcfU, 0x42U,
    0x79U, 0xdcU, 0xe5U, 0x61U, 0x7eU, 0x31U, 0x92U, 0xa8U};
constexpr std::array<std::uint8_t, 32U> kP256Order{
    0xffU, 0xffU, 0xffU, 0xffU, 0x00U, 0x00U, 0x00U, 0x00U,
    0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
    0xbcU, 0xe6U, 0xfaU, 0xadU, 0xa7U, 0x17U, 0x9eU, 0x84U,
    0xf3U, 0xb9U, 0xcaU, 0xc2U, 0xfcU, 0x63U, 0x25U, 0x51U};

[[nodiscard]] vfdual::HostIdentityError test_error(
    const vfdual::HostIdentityErrorCode code,
    const std::string_view operation) {
    return {.code = code, .operation = std::string(operation)};
}

class EphemeralBcryptSigningKey final : public vfdual::CngSigningKey {
public:
    ~EphemeralBcryptSigningKey() override {
        if (key_ != nullptr) static_cast<void>(BCryptDestroyKey(key_));
        if (algorithm_ != nullptr) {
            static_cast<void>(BCryptCloseAlgorithmProvider(algorithm_, 0U));
        }
    }

    [[nodiscard]] static std::unique_ptr<EphemeralBcryptSigningKey> create(
        vfdual::HostIdentityError& error) {
        auto result = std::unique_ptr<EphemeralBcryptSigningKey>(
            new EphemeralBcryptSigningKey());
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &result->algorithm_, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            error = test_error(
                vfdual::HostIdentityErrorCode::key_open_or_create_failed,
                "test_open_android_ecdsa_provider");
            return nullptr;
        }
        status = BCryptGenerateKeyPair(
            result->algorithm_, &result->key_, 256U, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            error = test_error(
                vfdual::HostIdentityErrorCode::key_open_or_create_failed,
                "test_generate_android_ecdsa_key");
            return nullptr;
        }
        status = BCryptFinalizeKeyPair(result->key_, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            error = test_error(
                vfdual::HostIdentityErrorCode::key_finalize_failed,
                "test_finalize_android_ecdsa_key");
            return nullptr;
        }
        error = {};
        return result;
    }

    [[nodiscard]] const vfdual::CngKeyMetadata& metadata()
        const noexcept override {
        return metadata_;
    }

    [[nodiscard]] vfdual::HostIdentityBytesResult
    export_public_ecc_blob() override {
        ULONG required{};
        NTSTATUS status = BCryptExportKey(
            key_, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0U, &required, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, test_error(
                vfdual::HostIdentityErrorCode::public_key_export_failed,
                "test_query_android_public_blob")};
        }
        std::vector<std::uint8_t> output(required);
        ULONG written{};
        status = BCryptExportKey(
            key_, nullptr, BCRYPT_ECCPUBLIC_BLOB,
            output.data(), static_cast<ULONG>(output.size()),
            &written, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, test_error(
                vfdual::HostIdentityErrorCode::public_key_export_failed,
                "test_export_android_public_blob")};
        }
        output.resize(written);
        return {std::move(output), {}};
    }

    [[nodiscard]] vfdual::HostIdentityBytesResult sign_sha256_digest(
        const std::span<const std::uint8_t> digest) override {
        if (digest.size() != 32U) {
            return {{}, test_error(
                vfdual::HostIdentityErrorCode::signature_failed,
                "test_reject_android_digest_size")};
        }
        ULONG required{};
        NTSTATUS status = BCryptSignHash(
            key_, nullptr, const_cast<PUCHAR>(digest.data()),
            static_cast<ULONG>(digest.size()), nullptr, 0U, &required, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, test_error(
                vfdual::HostIdentityErrorCode::signature_failed,
                "test_query_android_signature")};
        }
        std::vector<std::uint8_t> output(required);
        ULONG written{};
        status = BCryptSignHash(
            key_, nullptr, const_cast<PUCHAR>(digest.data()),
            static_cast<ULONG>(digest.size()), output.data(),
            static_cast<ULONG>(output.size()), &written, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, test_error(
                vfdual::HostIdentityErrorCode::signature_failed,
                "test_create_android_signature")};
        }
        output.resize(written);
        return {std::move(output), {}};
    }

    [[nodiscard]] vfdual::HostIdentityError
    discard_new_persisted_key_after_failed_initialization() override {
        return {};
    }

private:
    EphemeralBcryptSigningKey()
        : metadata_{
            .provider_name = std::wstring(
                vfdual::kMicrosoftSoftwareKeyStorageProvider),
            .persistent_key_name = std::wstring(
                vfdual::kDevelopmentHostIdentityKeyName),
            .algorithm_name = L"ECDSA_P256",
            .algorithm_group_name = L"ECDSA",
            .key_length_bits = 256U,
            .key_usage = vfdual::kCngAllowSigningFlag,
            .export_policy = 0U,
            .implementation_type = vfdual::kCngImplementationSoftwareFlag,
            .key_type = 0U,
        } {}

    vfdual::CngKeyMetadata metadata_;
    BCRYPT_ALG_HANDLE algorithm_{};
    BCRYPT_KEY_HANDLE key_{};
};

class FakeKeyStore final : public vfdual::CngKeyStoreAdapter {
public:
    [[nodiscard]] vfdual::CngKeyOpenResult
    open_or_create_p256_signing_key(
        const vfdual::CngKeyOpenRequest&) override {
        vfdual::HostIdentityError error;
        auto key = EphemeralBcryptSigningKey::create(error);
        if (key == nullptr) return {nullptr, std::move(error)};
        key_ = key.get();
        return {std::move(key), {}};
    }

    EphemeralBcryptSigningKey* key_{};
};

[[nodiscard]] std::unique_ptr<vfdual::HostCngDeviceIdentity>
open_android_identity(FakeKeyStore& store) {
    vfdual::HostIdentityError error;
    auto identity = vfdual::HostCngDeviceIdentity::open_development_with_adapter(
        vfdual::HostIdentityPolicy::development_named_software_provider(
            std::wstring(vfdual::kMicrosoftSoftwareKeyStorageProvider)),
        store, error);
    CHECK(identity != nullptr);
    CHECK(!error.has_error());
    CHECK(store.key_ != nullptr);
    return identity;
}

[[nodiscard]] std::array<std::uint8_t, 32U> subtract_scalar(
    const std::array<std::uint8_t, 32U>& minuend,
    const std::array<std::uint8_t, 32U>& subtrahend) {
    std::array<std::uint8_t, 32U> result{};
    unsigned borrow{};
    for (std::size_t offset{}; offset < result.size(); ++offset) {
        const std::size_t index = result.size() - 1U - offset;
        const unsigned left = minuend[index];
        const unsigned right =
            static_cast<unsigned>(subtrahend[index]) + borrow;
        if (left >= right) {
            result[index] = static_cast<std::uint8_t>(left - right);
            borrow = 0U;
        } else {
            result[index] = static_cast<std::uint8_t>(
                0x100U + left - right);
            borrow = 1U;
        }
    }
    CHECK(borrow == 0U);
    return result;
}

void append_der_integer(
    std::vector<std::uint8_t>& output,
    const std::array<std::uint8_t, 32U>& scalar) {
    const auto first_nonzero = std::find_if(
        scalar.begin(), scalar.end(),
        [](const std::uint8_t value) { return value != 0U; });
    CHECK(first_nonzero != scalar.end());
    const bool prefix = (*first_nonzero & 0x80U) != 0U;
    output.push_back(0x02U);
    output.push_back(static_cast<std::uint8_t>(
        scalar.end() - first_nonzero + (prefix ? 1U : 0U)));
    if (prefix) output.push_back(0x00U);
    output.insert(output.end(), first_nonzero, scalar.end());
}

[[nodiscard]] std::vector<std::uint8_t> canonical_der(
    const std::span<const std::uint8_t> p1363) {
    CHECK(p1363.size() == 64U);
    std::array<std::uint8_t, 32U> r{};
    std::array<std::uint8_t, 32U> s{};
    std::copy_n(p1363.begin(), r.size(), r.begin());
    std::copy_n(p1363.begin() + 32U, s.size(), s.begin());
    if (std::lexicographical_compare(
            kP256HalfOrder.begin(), kP256HalfOrder.end(),
            s.begin(), s.end())) {
        s = subtract_scalar(kP256Order, s);
    }
    std::vector<std::uint8_t> body;
    append_der_integer(body, r);
    append_der_integer(body, s);
    std::vector<std::uint8_t> der{
        0x30U, static_cast<std::uint8_t>(body.size())};
    der.insert(der.end(), body.begin(), body.end());
    return der;
}

[[nodiscard]] std::vector<std::uint8_t> sign_confirmation(
    EphemeralBcryptSigningKey& key,
    const vfdual::FirstPairingUserConfirmationFieldsV1& fields) {
    const auto built = vfdual::build_first_pairing_user_confirmation_v1(fields);
    CHECK(built.succeeded());
    std::array<std::uint8_t, 32U> digest{};
    std::transform(
        built.payload_sha256.begin(), built.payload_sha256.end(),
        digest.begin(), [](const std::byte value) {
            return std::to_integer<std::uint8_t>(value);
        });
    auto raw = key.sign_sha256_digest(digest);
    CHECK(raw.succeeded());
    return canonical_der(raw.bytes);
}

[[nodiscard]] std::vector<std::byte> android_record(
    const vfdual::ControlBootstrapMessageTypeV1 type,
    const std::span<const std::byte> payload) {
    auto encoded = vfdual::encode_authenticated_control_bootstrap_record_v1(
        vfdual::ControlBootstrapDirectionV1::android_to_host, type, payload);
    CHECK(encoded.status == vfdual::ControlBootstrapEncodeStatusV1::encoded);
    return std::move(encoded.record);
}

[[nodiscard]] std::span<const std::byte> host_payload(
    const std::span<const std::byte> record,
    const vfdual::ControlBootstrapMessageTypeV1 expected) {
    const auto parsed = vfdual::parse_authenticated_control_bootstrap_record_v1(
        record, vfdual::ControlBootstrapDirectionV1::host_to_android);
    CHECK(parsed.status == vfdual::ControlBootstrapParseStatusV1::parsed);
    CHECK(parsed.record.message_type == expected);
    return parsed.record.payload;
}

[[nodiscard]] std::string device_code(
    const std::string_view prefix,
    const std::string_view fingerprint) {
    std::string result{prefix};
    for (std::size_t index{}; index < 32U; ++index) {
        const char value = fingerprint[index];
        result.push_back(value >= 'a' && value <= 'f'
            ? static_cast<char>(value - 'a' + 'A') : value);
    }
    return result;
}

struct PairingFixture final {
    vfdual::HostAuthenticatedControlTimeV1 now{
        .epoch_seconds = 1'787'470'000,
        .monotonic_milliseconds = 10'000U,
    };
    vfdual::HostFirstPairingRouteV1 route{
        .host_ipv4 = {
            std::byte{192U}, std::byte{168U}, std::byte{1U}, std::byte{22U}},
        .android_ipv4 = {
            std::byte{192U}, std::byte{168U}, std::byte{1U}, std::byte{42U}},
        .video_port = 5005U,
        .control_port = 5006U,
    };
    std::unique_ptr<vfdual::HostDeviceIdentityRuntime> host_runtime;
    FakeKeyStore android_store;
    std::unique_ptr<vfdual::HostCngDeviceIdentity> android_identity;
    std::unique_ptr<vfdual::PlatformP256EphemeralKeyAgreementV1>
        android_ephemeral;

    PairingFixture() {
        vfdual::HostIdentityError host_error;
        host_runtime = vfdual::HostDeviceIdentityRuntime::
            open_for_current_build(host_error);
        CHECK(host_runtime != nullptr);
        CHECK(!host_error.has_error());
        android_identity = open_android_identity(android_store);
        vfdual::PeerHandshakeError ephemeral_error;
        android_ephemeral = vfdual::PlatformP256EphemeralKeyAgreementV1::
            generate_platform(ephemeral_error);
        CHECK(android_ephemeral != nullptr);
        CHECK(!ephemeral_error.has_error());
    }

    [[nodiscard]] vfdual::FirstPairingOfferPayloadV1 android_offer_for(
        const vfdual::FirstPairingOfferPayloadV1& host_offer) const {
        vfdual::FirstPairingOfferPayloadV1 offer;
        offer.required_capabilities = host_offer.required_capabilities;
        offer.confirmation_method = host_offer.confirmation_method;
        offer.attempt_id = host_offer.attempt_id;
        offer.identity_subject_public_key_info_der =
            android_identity->public_identity().subject_public_key_info_der;
        std::copy(
            android_ephemeral->public_key_sec1().begin(),
            android_ephemeral->public_key_sec1().end(),
            offer.ephemeral_public_key.begin());
        offer.nonce.fill(std::byte{0xa5U});
        if (offer.nonce == host_offer.nonce) {
            offer.nonce.front() ^= std::byte{0x01U};
        }
        offer.runtime_version_sha256.fill(std::byte{0x7bU});
        offer.expires_at_epoch = host_offer.expires_at_epoch;
        return offer;
    }
};

void test_success_is_provisional_and_bound_to_both_confirmations() {
    PairingFixture fixture;
    auto created = vfdual::HostFirstPairingCoordinatorV1::create(
        *fixture.host_runtime, fixture.route, "1.0.8", "1.0.0",
        vfdual::FirstPairingConfirmationMethodV1::decimal_sas, fixture.now);
    CHECK(created.succeeded());
    const auto host_offer = vfdual::parse_first_pairing_offer_payload_v1(
        vfdual::ControlBootstrapMessageTypeV1::host_first_pair_offer,
        host_payload(created.host_offer_record,
            vfdual::ControlBootstrapMessageTypeV1::host_first_pair_offer));
    CHECK(host_offer.has_value());

    const auto android_offer = fixture.android_offer_for(*host_offer);
    const auto android_offer_payload =
        vfdual::encode_first_pairing_offer_payload_v1(
            vfdual::ControlBootstrapMessageTypeV1::android_first_pair_offer,
            android_offer);
    CHECK(android_offer_payload.has_value());
    const auto accepted = created.coordinator->accept_android_offer(
        android_record(
            vfdual::ControlBootstrapMessageTypeV1::android_first_pair_offer,
            *android_offer_payload),
        fixture.now);
    CHECK(accepted.succeeded());
    CHECK(accepted.decimal_sas.size() == 6U);

    const auto host_confirmation =
        created.coordinator->confirm_local_user(fixture.now);
    CHECK(host_confirmation.succeeded());
    const auto parsed_host_confirmation =
        vfdual::parse_first_pairing_confirmation_payload_v1(
            vfdual::ControlBootstrapMessageTypeV1::
                host_first_pair_confirmation,
            host_payload(host_confirmation.outbound_record,
                vfdual::ControlBootstrapMessageTypeV1::
                    host_first_pair_confirmation));
    CHECK(parsed_host_confirmation.has_value());
    CHECK(parsed_host_confirmation->fields.commitment_sha256 ==
        accepted.commitment_sha256);

    vfdual::FirstPairingConfirmationPayloadV1 android_confirmation;
    android_confirmation.fields = {
        .role = vfdual::FirstPairingConfirmationRoleV1::android,
        .method = android_offer.confirmation_method,
        .attempt_id = android_offer.attempt_id,
        .commitment_sha256 = accepted.commitment_sha256,
        .expires_at_epoch = android_offer.expires_at_epoch,
    };
    android_confirmation.signature_der_low_s = sign_confirmation(
        *fixture.android_store.key_, android_confirmation.fields);
    const auto android_confirmation_payload =
        vfdual::encode_first_pairing_confirmation_payload_v1(
            vfdual::ControlBootstrapMessageTypeV1::
                android_first_pair_confirmation,
            android_confirmation);
    CHECK(android_confirmation_payload.has_value());
    const auto confirmation_error =
        created.coordinator->accept_android_user_confirmation(
            android_record(
                vfdual::ControlBootstrapMessageTypeV1::
                    android_first_pair_confirmation,
                *android_confirmation_payload),
            fixture.now);
    CHECK(!confirmation_error.has_error());

    const auto& host_public = fixture.host_runtime->public_identity();
    const auto& android_public = fixture.android_identity->public_identity();
    const std::string pair_id(32U, '2');
    const vfdual::ActivationConfirmationProof proof{
        .activation_mode = "activate",
        .android_client_version = "1.0.0",
        .android_device_code = device_code(
            "ANDROID-", android_public.public_key_sha256_hex),
        .android_device_profile_sha256 = std::string(64U, '4'),
        .android_key_sha256 = android_public.public_key_sha256_hex,
        .challenge_id = std::string(32U, '1'),
        .challenge_token_sha256 = std::string(64U, '6'),
        .host_client_version = "1.0.0",
        .host_device_code = device_code(
            "HOST-", host_public.public_key_sha256_hex),
        .host_key_sha256 = host_public.public_key_sha256_hex,
        .pair_id = pair_id,
        .protocol_version = vfdual::kUsageAuthorizationProtocolVersion,
        .request_id = std::string(32U, '3'),
        .target_entitlement_id = "",
    };
    const auto proof_payload =
        vfdual::encode_first_pairing_activation_proof_request_v1(proof);
    CHECK(proof_payload.has_value());
    const auto host_signature =
        created.coordinator->accept_activation_proof_request(
            android_record(
                vfdual::ControlBootstrapMessageTypeV1::
                    activation_proof_request,
                *proof_payload),
            fixture.now);
    CHECK(host_signature.succeeded());
    const auto signature =
        vfdual::parse_first_pairing_activation_signature_payload_v1(
            host_payload(host_signature.outbound_record,
                vfdual::ControlBootstrapMessageTypeV1::
                    host_activation_signature));
    CHECK(signature.has_value());

    const vfdual::FirstPairingActivationResultPayloadV1 activation{
        .entitlement_id = std::string(32U, 'a'),
        .pair_id = pair_id,
        .binding_id = std::string(32U, 'b'),
        .binding_revision = 7U,
        .revocation_version = 3U,
    };
    const auto activation_payload =
        vfdual::encode_first_pairing_activation_result_payload_v1(activation);
    CHECK(activation_payload.has_value());
    const auto completed = created.coordinator->accept_activation_result(
        android_record(
            vfdual::ControlBootstrapMessageTypeV1::activation_result,
            *activation_payload),
        fixture.now);
    CHECK(completed.succeeded());
    CHECK(completed.provisional_pair_binding.entitlement_id ==
        activation.entitlement_id);
    CHECK(completed.provisional_pair_binding.generation_high_watermark == 0U);
    CHECK(completed.provisional_pair_binding.android_identity_spki_sha256 ==
        android_public.public_key_sha256_hex);
    const auto complete_commitment =
        vfdual::parse_first_pairing_complete_payload_v1(
            host_payload(completed.complete_record,
                vfdual::ControlBootstrapMessageTypeV1::first_pair_complete));
    CHECK(complete_commitment.has_value());
    CHECK(*complete_commitment == accepted.commitment_sha256);
}

void test_wrong_android_key_burns_attempt() {
    PairingFixture fixture;
    auto created = vfdual::HostFirstPairingCoordinatorV1::create(
        *fixture.host_runtime, fixture.route, "1.0.8", "1.0.0",
        vfdual::FirstPairingConfirmationMethodV1::decimal_sas, fixture.now);
    CHECK(created.succeeded());
    const auto host_offer = vfdual::parse_first_pairing_offer_payload_v1(
        vfdual::ControlBootstrapMessageTypeV1::host_first_pair_offer,
        host_payload(created.host_offer_record,
            vfdual::ControlBootstrapMessageTypeV1::host_first_pair_offer));
    CHECK(host_offer.has_value());
    const auto offer = fixture.android_offer_for(*host_offer);
    const auto offer_payload = vfdual::encode_first_pairing_offer_payload_v1(
        vfdual::ControlBootstrapMessageTypeV1::android_first_pair_offer, offer);
    CHECK(offer_payload.has_value());
    const auto accepted = created.coordinator->accept_android_offer(
        android_record(
            vfdual::ControlBootstrapMessageTypeV1::android_first_pair_offer,
            *offer_payload), fixture.now);
    CHECK(accepted.succeeded());

    FakeKeyStore wrong_store;
    auto wrong_identity = open_android_identity(wrong_store);
    CHECK(wrong_identity != nullptr);
    vfdual::FirstPairingConfirmationPayloadV1 confirmation;
    confirmation.fields = {
        .role = vfdual::FirstPairingConfirmationRoleV1::android,
        .method = offer.confirmation_method,
        .attempt_id = offer.attempt_id,
        .commitment_sha256 = accepted.commitment_sha256,
        .expires_at_epoch = offer.expires_at_epoch,
    };
    confirmation.signature_der_low_s = sign_confirmation(
        *wrong_store.key_, confirmation.fields);
    const auto payload = vfdual::encode_first_pairing_confirmation_payload_v1(
        vfdual::ControlBootstrapMessageTypeV1::android_first_pair_confirmation,
        confirmation);
    CHECK(payload.has_value());
    const auto rejected =
        created.coordinator->accept_android_user_confirmation(
            android_record(
                vfdual::ControlBootstrapMessageTypeV1::
                    android_first_pair_confirmation,
                *payload), fixture.now);
    CHECK(rejected.code == vfdual::HostFirstPairingErrorCodeV1::
        cryptographic_verification_failed);
    CHECK(created.coordinator->is_closed());
}

void test_monotonic_timeout_burns_attempt() {
    PairingFixture fixture;
    auto created = vfdual::HostFirstPairingCoordinatorV1::create(
        *fixture.host_runtime, fixture.route, "1.0.8", "1.0.0",
        vfdual::FirstPairingConfirmationMethodV1::decimal_sas, fixture.now);
    CHECK(created.succeeded());
    auto late = fixture.now;
    late.monotonic_milliseconds +=
        vfdual::kHostFirstPairingMaximumLifetimeMillisecondsV1 + 1U;
    const auto rejected = created.coordinator->accept_android_offer(
        std::vector<std::byte>{std::byte{0U}}, late);
    CHECK(rejected.error.code ==
        vfdual::HostFirstPairingErrorCodeV1::timed_out);
    CHECK(created.coordinator->is_closed());
}

}  // namespace

int main() {
    test_success_is_provisional_and_bound_to_both_confirmations();
    test_wrong_android_key_burns_attempt();
    test_monotonic_timeout_burns_attempt();
    std::cout << "host first pairing coordinator v1 tests passed\n";
    return EXIT_SUCCESS;
}
