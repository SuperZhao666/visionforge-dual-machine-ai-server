#include "vfdual/host_first_pairing_coordinator_v1.hpp"

#include "vfdual/host_activation_confirmation_signer_v1.hpp"
#include "vfdual/host_first_pairing_user_confirmation_signer_v1.hpp"

#ifndef _WIN32
#error "host_first_pairing_coordinator_v1 is Windows-only"
#endif

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
#include <cctype>
#include <limits>
#include <new>
#include <span>
#include <string_view>
#include <utility>

namespace vfdual {
namespace {

[[nodiscard]] HostFirstPairingErrorV1 error(
    const HostFirstPairingErrorCodeV1 code) noexcept {
    return {code};
}

template <std::size_t Size>
[[nodiscard]] bool nonzero(const std::array<std::byte, Size>& value) noexcept {
    return std::any_of(value.begin(), value.end(), [](const std::byte item) {
        return item != std::byte{0U};
    });
}

[[nodiscard]] bool valid_version(const std::string_view value) noexcept {
    if (value.empty() || value.size() > 80U) return false;
    return std::all_of(value.begin(), value.end(), [](const char item) {
        return (item >= '0' && item <= '9') || item == '.' || item == '-' ||
            item == '+' || item == '_' || (item >= 'A' && item <= 'Z') ||
            (item >= 'a' && item <= 'z');
    });
}

[[nodiscard]] std::optional<PeerHandshakeSha256> sha256(
    const std::span<const std::uint8_t> input) noexcept {
    if (input.empty() || input.size() > (std::numeric_limits<ULONG>::max)()) {
        return std::nullopt;
    }
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    const auto close = [&]() noexcept {
        if (hash != nullptr) static_cast<void>(BCryptDestroyHash(hash));
        if (algorithm != nullptr) {
            static_cast<void>(BCryptCloseAlgorithmProvider(algorithm, 0U));
        }
    };
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U);
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptCreateHash(
            algorithm, &hash, nullptr, 0U, nullptr, 0U, 0U);
    }
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptHashData(
            hash, const_cast<PUCHAR>(input.data()),
            static_cast<ULONG>(input.size()), 0U);
    }
    PeerHandshakeSha256 result{};
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptFinishHash(
            hash, reinterpret_cast<PUCHAR>(result.data()),
            static_cast<ULONG>(result.size()), 0U);
    }
    close();
    if (!BCRYPT_SUCCESS(status)) return std::nullopt;
    return result;
}

[[nodiscard]] bool random_bytes(const std::span<std::byte> output) noexcept {
    return !output.empty() &&
        output.size() <= (std::numeric_limits<ULONG>::max)() &&
        BCRYPT_SUCCESS(BCryptGenRandom(
            nullptr,
            reinterpret_cast<PUCHAR>(output.data()),
            static_cast<ULONG>(output.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

[[nodiscard]] std::string lower_hex(
    const PeerHandshakeSha256& value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.resize(value.size() * 2U);
    for (std::size_t index{}; index < value.size(); ++index) {
        const auto item = std::to_integer<std::uint8_t>(value[index]);
        result[index * 2U] = digits[item >> 4U];
        result[index * 2U + 1U] = digits[item & 0x0fU];
    }
    return result;
}

[[nodiscard]] std::string device_code(
    const std::string_view prefix,
    const std::string_view fingerprint) {
    std::string result{prefix};
    result.reserve(prefix.size() + 32U);
    for (std::size_t index{}; index < 32U; ++index) {
        result.push_back(static_cast<char>(std::toupper(
            static_cast<unsigned char>(fingerprint[index]))));
    }
    return result;
}

[[nodiscard]] std::array<std::uint8_t, 32U> as_uint8(
    const PeerHandshakeSha256& value) noexcept {
    std::array<std::uint8_t, 32U> result{};
    std::transform(value.begin(), value.end(), result.begin(),
        [](const std::byte item) {
            return std::to_integer<std::uint8_t>(item);
        });
    return result;
}

[[nodiscard]] PeerHandshakeSha256 as_bytes(
    const std::array<std::uint8_t, 32U>& value) noexcept {
    PeerHandshakeSha256 result{};
    std::transform(value.begin(), value.end(), result.begin(),
        [](const std::uint8_t item) { return std::byte{item}; });
    return result;
}

[[nodiscard]] std::optional<std::vector<std::byte>> frame(
    const ControlBootstrapMessageTypeV1 type,
    const std::span<const std::byte> payload) noexcept {
    auto encoded = encode_authenticated_control_bootstrap_record_v1(
        ControlBootstrapDirectionV1::host_to_android, type, payload);
    if (encoded.status != ControlBootstrapEncodeStatusV1::encoded) {
        return std::nullopt;
    }
    return std::move(encoded.record);
}

[[nodiscard]] std::optional<std::span<const std::byte>> inbound_payload(
    const std::span<const std::byte> encoded,
    const ControlBootstrapMessageTypeV1 expected) noexcept {
    const auto parsed = parse_authenticated_control_bootstrap_record_v1(
        encoded, ControlBootstrapDirectionV1::android_to_host);
    if (parsed.status != ControlBootstrapParseStatusV1::parsed ||
        parsed.record.message_type != expected) return std::nullopt;
    return parsed.record.payload;
}

[[nodiscard]] bool valid_route(const HostFirstPairingRouteV1& route) noexcept {
    return nonzero(route.host_ipv4) && nonzero(route.android_ipv4) &&
        route.host_ipv4 != route.android_ipv4 && route.video_port != 0U &&
        route.control_port != 0U && route.video_port != route.control_port;
}

}  // namespace

HostFirstPairingCoordinatorV1::HostFirstPairingCoordinatorV1(
    HostDeviceIdentityRuntime& identity_runtime,
    HostFirstPairingRouteV1 route,
    std::string host_runtime_version,
    std::string host_client_version,
    FirstPairingOfferPayloadV1 host_offer,
    std::unique_ptr<PlatformP256EphemeralKeyAgreementV1> host_ephemeral,
    const std::uint64_t started_monotonic_milliseconds) noexcept
    : identity_runtime_(identity_runtime),
      route_(route),
      host_runtime_version_(std::move(host_runtime_version)),
      host_client_version_(std::move(host_client_version)),
      host_offer_(std::move(host_offer)),
      host_ephemeral_(std::move(host_ephemeral)),
      started_monotonic_milliseconds_(started_monotonic_milliseconds) {
    expected_host_device_code_ = device_code(
        "HOST-", identity_runtime_.public_identity().public_key_sha256_hex);
}

HostFirstPairingCoordinatorV1::~HostFirstPairingCoordinatorV1() { close(); }

HostFirstPairingConstructionResultV1
HostFirstPairingCoordinatorV1::create(
    HostDeviceIdentityRuntime& identity_runtime,
    const HostFirstPairingRouteV1& route,
    std::string host_runtime_version,
    std::string host_client_version,
    const FirstPairingConfirmationMethodV1 confirmation_method,
    const HostAuthenticatedControlTimeV1& now) noexcept {
    HostFirstPairingConstructionResultV1 result{};
    try {
        if (!valid_route(route) || !valid_version(host_runtime_version) ||
            !valid_version(host_client_version) || now.epoch_seconds <= 0 ||
            now.monotonic_milliseconds == 0U ||
            (confirmation_method !=
                    FirstPairingConfirmationMethodV1::decimal_sas &&
             confirmation_method != FirstPairingConfirmationMethodV1::qr)) {
            result.error = error(
                HostFirstPairingErrorCodeV1::invalid_configuration);
            return result;
        }
        PeerHandshakeError ephemeral_error;
        auto ephemeral = PlatformP256EphemeralKeyAgreementV1::
            generate_platform(ephemeral_error);
        if (ephemeral == nullptr || ephemeral_error.has_error()) {
            result.error = error(
                HostFirstPairingErrorCodeV1::
                    cryptographic_verification_failed);
            return result;
        }
        FirstPairingOfferPayloadV1 offer;
        offer.confirmation_method = confirmation_method;
        if (!random_bytes(offer.attempt_id) || !random_bytes(offer.nonce)) {
            result.error = error(
                HostFirstPairingErrorCodeV1::
                    cryptographic_verification_failed);
            return result;
        }
        offer.identity_subject_public_key_info_der =
            identity_runtime.public_identity().subject_public_key_info_der;
        std::copy(
            ephemeral->public_key_sec1().begin(),
            ephemeral->public_key_sec1().end(),
            offer.ephemeral_public_key.begin());
        const auto runtime_hash = sha256(std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t*>(host_runtime_version.data()),
            host_runtime_version.size()});
        if (!runtime_hash.has_value() ||
            static_cast<std::uint64_t>(now.epoch_seconds) >
                (std::numeric_limits<std::uint64_t>::max)() -
                    kHostFirstPairingMaximumLifetimeSecondsV1) {
            result.error = error(
                HostFirstPairingErrorCodeV1::
                    cryptographic_verification_failed);
            return result;
        }
        offer.runtime_version_sha256 = *runtime_hash;
        offer.expires_at_epoch = static_cast<std::uint64_t>(now.epoch_seconds) +
            kHostFirstPairingMaximumLifetimeSecondsV1;
        const auto payload = encode_first_pairing_offer_payload_v1(
            ControlBootstrapMessageTypeV1::host_first_pair_offer, offer);
        if (!payload.has_value()) {
            result.error = error(
                HostFirstPairingErrorCodeV1::invalid_configuration);
            return result;
        }
        const auto record = frame(
            ControlBootstrapMessageTypeV1::host_first_pair_offer, *payload);
        if (!record.has_value()) {
            result.error = error(
                HostFirstPairingErrorCodeV1::invalid_configuration);
            return result;
        }
        result.coordinator = std::unique_ptr<HostFirstPairingCoordinatorV1>(
            new HostFirstPairingCoordinatorV1(
                identity_runtime, route, std::move(host_runtime_version),
                std::move(host_client_version), std::move(offer),
                std::move(ephemeral), now.monotonic_milliseconds));
        result.host_offer_record = *record;
        return result;
    } catch (...) {
        result.error = error(HostFirstPairingErrorCodeV1::invalid_configuration);
        return result;
    }
}

HostFirstPairingOfferAcceptedResultV1
HostFirstPairingCoordinatorV1::accept_android_offer(
    const std::span<const std::byte> encoded_record,
    const HostAuthenticatedControlTimeV1& now) noexcept {
    HostFirstPairingOfferAcceptedResultV1 result{};
    if (closed_) {
        result.error = terminal_error_.has_error() ? terminal_error_ :
            error(HostFirstPairingErrorCodeV1::closed);
        return result;
    }
    if (offer_accepted_ || !time_valid(now)) {
        burn(offer_accepted_ ? HostFirstPairingErrorCodeV1::unexpected_record :
            HostFirstPairingErrorCodeV1::timed_out);
        result.error = terminal_error_;
        return result;
    }
    try {
        const auto payload = inbound_payload(
            encoded_record,
            ControlBootstrapMessageTypeV1::android_first_pair_offer);
        if (!payload.has_value()) {
            burn(HostFirstPairingErrorCodeV1::unexpected_record);
            result.error = terminal_error_;
            return result;
        }
        const auto offer = parse_first_pairing_offer_payload_v1(
            ControlBootstrapMessageTypeV1::android_first_pair_offer, *payload);
        if (!offer.has_value() ||
            offer->attempt_id != host_offer_.attempt_id ||
            offer->required_capabilities != host_offer_.required_capabilities ||
            offer->confirmation_method != host_offer_.confirmation_method ||
            offer->expires_at_epoch != host_offer_.expires_at_epoch ||
            offer->identity_subject_public_key_info_der ==
                host_offer_.identity_subject_public_key_info_der ||
            offer->ephemeral_public_key == host_offer_.ephemeral_public_key ||
            offer->nonce == host_offer_.nonce) {
            burn(HostFirstPairingErrorCodeV1::identity_binding_mismatch);
            result.error = terminal_error_;
            return result;
        }
        const auto android_hash = sha256(
            offer->identity_subject_public_key_info_der);
        if (!android_hash.has_value()) {
            burn(HostFirstPairingErrorCodeV1::
                cryptographic_verification_failed);
            result.error = terminal_error_;
            return result;
        }
        FirstPairingCommitmentFieldsV1 fields;
        fields.transport_kind = FirstPairingTransportKindV1::ethernet;
        fields.required_capabilities = host_offer_.required_capabilities;
        fields.attempt_id = host_offer_.attempt_id;
        fields.host_identity_spki_sha256 = as_bytes(
            identity_runtime_.public_identity().public_key_sha256);
        fields.android_identity_spki_sha256 = *android_hash;
        fields.host_ephemeral_public_key = host_offer_.ephemeral_public_key;
        fields.android_ephemeral_public_key = offer->ephemeral_public_key;
        fields.host_nonce = host_offer_.nonce;
        fields.android_nonce = offer->nonce;
        fields.host_ipv4 = route_.host_ipv4;
        fields.android_ipv4 = route_.android_ipv4;
        fields.video_port = route_.video_port;
        fields.control_port = route_.control_port;
        fields.host_runtime_version_sha256 =
            host_offer_.runtime_version_sha256;
        fields.android_runtime_version_sha256 =
            offer->runtime_version_sha256;
        fields.expires_at_epoch = host_offer_.expires_at_epoch;
        commitment_ = build_first_pairing_commitment_v1(fields);
        if (!commitment_.succeeded()) {
            burn(HostFirstPairingErrorCodeV1::
                cryptographic_verification_failed);
            result.error = terminal_error_;
            return result;
        }
        android_offer_ = *offer;
        android_identity_spki_der_ =
            offer->identity_subject_public_key_info_der;
        android_identity_sha256_ = *android_hash;
        android_identity_sha256_hex_ = lower_hex(*android_hash);
        expected_android_device_code_ = device_code(
            "ANDROID-", android_identity_sha256_hex_);
        offer_accepted_ = true;
        result.decimal_sas = commitment_.sas();
        result.commitment_sha256 = commitment_.commitment_sha256;
        return result;
    } catch (...) {
        burn(HostFirstPairingErrorCodeV1::
            cryptographic_verification_failed);
        result.error = terminal_error_;
        return result;
    }
}

HostFirstPairingRecordResultV1
HostFirstPairingCoordinatorV1::confirm_local_user(
    const HostAuthenticatedControlTimeV1& now) noexcept {
    HostFirstPairingRecordResultV1 result{};
    if (closed_) {
        result.error = terminal_error_.has_error() ? terminal_error_ :
            error(HostFirstPairingErrorCodeV1::closed);
        return result;
    }
    const bool within_time = time_valid(now);
    if (!offer_accepted_ || local_confirmed_ || !within_time) {
        burn(!within_time ? HostFirstPairingErrorCodeV1::timed_out :
            HostFirstPairingErrorCodeV1::unexpected_record);
        result.error = terminal_error_;
        return result;
    }
    FirstPairingUserConfirmationFieldsV1 fields;
    fields.role = FirstPairingConfirmationRoleV1::host;
    fields.method = host_offer_.confirmation_method;
    fields.attempt_id = host_offer_.attempt_id;
    fields.commitment_sha256 = commitment_.commitment_sha256;
    fields.expires_at_epoch = host_offer_.expires_at_epoch;
    auto signed_confirmation = identity_runtime_
        .first_pairing_user_confirmation_signer()
        .build_and_sign_after_local_user_confirmation(fields);
    if (!signed_confirmation.succeeded()) {
        burn(HostFirstPairingErrorCodeV1::
            cryptographic_verification_failed);
        result.error = terminal_error_;
        return result;
    }
    const FirstPairingConfirmationPayloadV1 confirmation{
        .fields = fields,
        .signature_der_low_s =
            std::move(signed_confirmation.signature_der_low_s),
    };
    const auto payload = encode_first_pairing_confirmation_payload_v1(
        ControlBootstrapMessageTypeV1::host_first_pair_confirmation,
        confirmation);
    const auto record = payload.has_value() ? frame(
        ControlBootstrapMessageTypeV1::host_first_pair_confirmation,
        *payload) : std::nullopt;
    if (!record.has_value()) {
        burn(HostFirstPairingErrorCodeV1::
            cryptographic_verification_failed);
        result.error = terminal_error_;
        return result;
    }
    local_confirmation_record_ = *record;
    local_confirmed_ = true;
    result.outbound_record = local_confirmation_record_;
    return result;
}

HostFirstPairingErrorV1
HostFirstPairingCoordinatorV1::accept_android_user_confirmation(
    const std::span<const std::byte> encoded_record,
    const HostAuthenticatedControlTimeV1& now) noexcept {
    if (closed_) return terminal_error_.has_error() ? terminal_error_ :
        error(HostFirstPairingErrorCodeV1::closed);
    const bool within_time = time_valid(now);
    if (!offer_accepted_ || android_confirmed_ || !within_time) {
        burn(!within_time ? HostFirstPairingErrorCodeV1::timed_out :
            HostFirstPairingErrorCodeV1::unexpected_record);
        return terminal_error_;
    }
    const auto payload = inbound_payload(
        encoded_record,
        ControlBootstrapMessageTypeV1::android_first_pair_confirmation);
    const auto confirmation = payload.has_value()
        ? parse_first_pairing_confirmation_payload_v1(
            ControlBootstrapMessageTypeV1::android_first_pair_confirmation,
            *payload) : std::nullopt;
    if (!confirmation.has_value() ||
        confirmation->fields.method != host_offer_.confirmation_method ||
        confirmation->fields.attempt_id != host_offer_.attempt_id ||
        confirmation->fields.commitment_sha256 !=
            commitment_.commitment_sha256 ||
        confirmation->fields.expires_at_epoch !=
            host_offer_.expires_at_epoch) {
        burn(HostFirstPairingErrorCodeV1::identity_binding_mismatch);
        return terminal_error_;
    }
    const auto verified = verify_android_first_pairing_user_confirmation_v1(
        android_identity_spki_der_, as_uint8(android_identity_sha256_),
        confirmation->fields,
        confirmation->signature_der_low_s);
    if (!verified.completed() || !verified.proof_of_possession_valid) {
        burn(HostFirstPairingErrorCodeV1::
            cryptographic_verification_failed);
        return terminal_error_;
    }
    android_confirmed_ = true;
    return {};
}

HostFirstPairingRecordResultV1
HostFirstPairingCoordinatorV1::accept_activation_proof_request(
    const std::span<const std::byte> encoded_record,
    const HostAuthenticatedControlTimeV1& now) noexcept {
    HostFirstPairingRecordResultV1 result{};
    if (closed_) {
        result.error = terminal_error_.has_error() ? terminal_error_ :
            error(HostFirstPairingErrorCodeV1::closed);
        return result;
    }
    const bool within_time = time_valid(now);
    if (!local_confirmed_ || !android_confirmed_ || activation_signed_ ||
        !within_time) {
        burn(!within_time ? HostFirstPairingErrorCodeV1::timed_out :
            HostFirstPairingErrorCodeV1::unexpected_record);
        result.error = terminal_error_;
        return result;
    }
    const auto payload = inbound_payload(
        encoded_record,
        ControlBootstrapMessageTypeV1::activation_proof_request);
    const auto proof = payload.has_value()
        ? parse_first_pairing_activation_proof_request_v1(*payload)
        : std::nullopt;
    if (!proof.has_value() ||
        proof->host_key_sha256 !=
            identity_runtime_.public_identity().public_key_sha256_hex ||
        proof->android_key_sha256 != android_identity_sha256_hex_ ||
        proof->host_device_code != expected_host_device_code_ ||
        proof->android_device_code != expected_android_device_code_ ||
        proof->host_client_version != host_client_version_) {
        burn(HostFirstPairingErrorCodeV1::activation_proof_rejected);
        result.error = terminal_error_;
        return result;
    }
    auto signed_proof = identity_runtime_.activation_confirmation_signer()
        .build_and_sign_activation_confirmation(*proof);
    if (!signed_proof.succeeded()) {
        burn(HostFirstPairingErrorCodeV1::activation_proof_rejected);
        result.error = terminal_error_;
        return result;
    }
    FirstPairingActivationSignaturePayloadV1 signature;
    signature.canonical_payload_sha256 = as_bytes(
        signed_proof.canonical_payload_sha256);
    signature.signature_der_low_s =
        std::move(signed_proof.signature_der_low_s);
    const auto signature_payload =
        encode_first_pairing_activation_signature_payload_v1(signature);
    const auto record = signature_payload.has_value() ? frame(
        ControlBootstrapMessageTypeV1::host_activation_signature,
        *signature_payload) : std::nullopt;
    if (!record.has_value()) {
        burn(HostFirstPairingErrorCodeV1::
            cryptographic_verification_failed);
        result.error = terminal_error_;
        return result;
    }
    activation_pair_id_ = proof->pair_id;
    activation_signed_ = true;
    result.outbound_record = *record;
    return result;
}

HostFirstPairingCompletionResultV1
HostFirstPairingCoordinatorV1::accept_activation_result(
    const std::span<const std::byte> encoded_record,
    const HostAuthenticatedControlTimeV1& now) noexcept {
    HostFirstPairingCompletionResultV1 result{};
    if (closed_) {
        result.error = terminal_error_.has_error() ? terminal_error_ :
            error(HostFirstPairingErrorCodeV1::closed);
        return result;
    }
    const bool within_time = time_valid(now);
    if (!activation_signed_ || completed_ || !within_time) {
        burn(!within_time ? HostFirstPairingErrorCodeV1::timed_out :
            HostFirstPairingErrorCodeV1::unexpected_record);
        result.error = terminal_error_;
        return result;
    }
    const auto payload = inbound_payload(
        encoded_record, ControlBootstrapMessageTypeV1::activation_result);
    const auto activation = payload.has_value()
        ? parse_first_pairing_activation_result_payload_v1(*payload)
        : std::nullopt;
    if (!activation.has_value() || activation->pair_id != activation_pair_id_) {
        burn(HostFirstPairingErrorCodeV1::identity_binding_mismatch);
        result.error = terminal_error_;
        return result;
    }
    const auto complete_payload = encode_first_pairing_complete_payload_v1(
        commitment_.commitment_sha256);
    const auto complete = complete_payload.has_value() ? frame(
        ControlBootstrapMessageTypeV1::first_pair_complete,
        *complete_payload) : std::nullopt;
    if (!complete.has_value()) {
        burn(HostFirstPairingErrorCodeV1::
            cryptographic_verification_failed);
        result.error = terminal_error_;
        return result;
    }
    result.provisional_pair_binding = {
        .entitlement_id = activation->entitlement_id,
        .pair_id = activation->pair_id,
        .binding_id = activation->binding_id,
        .binding_revision = activation->binding_revision,
        .revocation_version = activation->revocation_version,
        .generation_high_watermark = 0U,
        .host_identity_spki_sha256 =
            identity_runtime_.public_identity().public_key_sha256_hex,
        .android_identity_spki_sha256 = android_identity_sha256_hex_,
        .android_subject_public_key_info_der = android_identity_spki_der_,
    };
    result.complete_record = *complete;
    completed_ = true;
    return result;
}

bool HostFirstPairingCoordinatorV1::time_valid(
    const HostAuthenticatedControlTimeV1& now) const noexcept {
    if (now.epoch_seconds <= 0 || now.monotonic_milliseconds == 0U ||
        static_cast<std::uint64_t>(now.epoch_seconds) >
            host_offer_.expires_at_epoch ||
        now.monotonic_milliseconds < started_monotonic_milliseconds_) {
        return false;
    }
    return now.monotonic_milliseconds - started_monotonic_milliseconds_ <=
        kHostFirstPairingMaximumLifetimeMillisecondsV1;
}

void HostFirstPairingCoordinatorV1::burn(
    const HostFirstPairingErrorCodeV1 code) noexcept {
    if (!terminal_error_.has_error()) terminal_error_ = error(code);
    close();
}

void HostFirstPairingCoordinatorV1::close() noexcept {
    if (closed_) return;
    closed_ = true;
    host_ephemeral_.reset();
    std::fill(local_confirmation_record_.begin(),
        local_confirmation_record_.end(), std::byte{0U});
    local_confirmation_record_.clear();
}

bool HostFirstPairingCoordinatorV1::is_closed() const noexcept {
    return closed_;
}

}  // namespace vfdual
