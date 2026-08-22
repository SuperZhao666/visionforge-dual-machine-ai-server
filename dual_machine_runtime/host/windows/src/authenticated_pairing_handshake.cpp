#include "vfdual/host_authenticated_control_coordinator_v1.hpp"

#include "vfdual/authenticated_control_bootstrap_record_v1.hpp"
#include "vfdual/host_cng_device_identity.h"
#include "vfdual/pair_generation_pop_v1.hpp"

#ifndef _WIN32
#error "Host authenticated control coordination is Windows-only"
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
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace vfdual {
namespace {

inline constexpr std::uint64_t kSigned64Maximum =
    0x7fff'ffff'ffff'ffffULL;

[[nodiscard]] HostAuthenticatedControlErrorV1 control_error(
    const HostAuthenticatedControlErrorCodeV1 code) noexcept {
    return {.code = code};
}

[[nodiscard]] HostAuthenticatedControlRecordResultV1 record_failure(
    const HostAuthenticatedControlErrorCodeV1 code) noexcept {
    return {{}, control_error(code)};
}

[[nodiscard]] HostAuthenticatedControlCompletionResultV1 completion_failure(
    const HostAuthenticatedControlErrorCodeV1 code) noexcept {
    return {{}, nullptr, 0U, control_error(code)};
}

[[nodiscard]] HostAuthenticatedControlConstructionResultV1
construction_failure(
    const HostAuthenticatedControlErrorCodeV1 code) noexcept {
    return {nullptr, control_error(code)};
}

template <typename T, std::size_t Size>
void secure_zero(std::array<T, Size>& value) noexcept {
    SecureZeroMemory(value.data(), sizeof(T) * value.size());
}

template <typename T>
void secure_zero(std::vector<T>& value) noexcept {
    if (!value.empty()) {
        SecureZeroMemory(value.data(), sizeof(T) * value.size());
    }
    value.clear();
}

void secure_zero(std::string& value) noexcept {
    if (!value.empty()) SecureZeroMemory(value.data(), value.size());
    value.clear();
}

[[nodiscard]] bool contains_nonzero(
    const std::span<const std::byte> value) noexcept {
    return std::any_of(value.begin(), value.end(), [](const std::byte current) {
        return current != std::byte{0U};
    });
}

[[nodiscard]] bool lower_hex(
    const std::string_view value,
    const std::size_t exact_size) noexcept {
    return value.size() == exact_size &&
        std::all_of(value.begin(), value.end(), [](const char current) {
            return (current >= '0' && current <= '9') ||
                (current >= 'a' && current <= 'f');
        });
}

[[nodiscard]] std::uint8_t hex_nibble(const char value) noexcept {
    return value >= '0' && value <= '9'
        ? static_cast<std::uint8_t>(value - '0')
        : static_cast<std::uint8_t>(value - 'a' + 10);
}

[[nodiscard]] bool decode_sha256_hex(
    const std::string_view encoded,
    PeerHandshakeSha256& output) noexcept {
    if (!lower_hex(encoded, output.size() * 2U)) return false;
    for (std::size_t index{}; index < output.size(); ++index) {
        output[index] = std::byte{static_cast<std::uint8_t>(
            (hex_nibble(encoded[index * 2U]) << 4U) |
            hex_nibble(encoded[index * 2U + 1U]))};
    }
    return contains_nonzero(output);
}

[[nodiscard]] std::string lower_hex_sha256(
    const PeerHandshakeSha256& digest) {
    constexpr std::string_view digits{"0123456789abcdef"};
    std::string encoded(digest.size() * 2U, '0');
    for (std::size_t index{}; index < digest.size(); ++index) {
        const auto value = std::to_integer<std::uint8_t>(digest[index]);
        encoded[index * 2U] = digits[value >> 4U];
        encoded[index * 2U + 1U] = digits[value & 0x0fU];
    }
    return encoded;
}

[[nodiscard]] bool stable_semver(const std::string_view value) noexcept {
    if (value.empty() || value.size() >
            kPeerHandshakeMaximumRuntimeVersionBytes) {
        return false;
    }
    std::size_t components{};
    std::size_t component_start{};
    for (std::size_t index{}; index <= value.size(); ++index) {
        if (index != value.size() && value[index] != '.') {
            if (value[index] < '0' || value[index] > '9') return false;
            continue;
        }
        const std::size_t component_size = index - component_start;
        if (component_size == 0U ||
            (component_size > 1U && value[component_start] == '0')) {
            return false;
        }
        ++components;
        component_start = index + 1U;
    }
    return components == 3U;
}

[[nodiscard]] std::span<const std::byte> bytes_of(
    const std::span<const std::uint8_t> value) noexcept {
    return std::as_bytes(value);
}

[[nodiscard]] std::span<const std::uint8_t> unsigned_bytes_of(
    const std::span<const std::byte> value) noexcept {
    return {
        reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}

[[nodiscard]] std::span<const std::byte> bytes_of(
    const std::string_view value) noexcept {
    return std::as_bytes(std::span<const char>{value.data(), value.size()});
}

[[nodiscard]] std::array<std::byte, 2U> u16_be(
    const std::uint16_t value) noexcept {
    return {
        std::byte{static_cast<std::uint8_t>(value >> 8U)},
        std::byte{static_cast<std::uint8_t>(value)},
    };
}

[[nodiscard]] std::string ascii_string(
    const std::span<const std::byte> value) {
    return {
        reinterpret_cast<const char*>(value.data()), value.size()};
}

template <std::size_t Size>
[[nodiscard]] std::array<std::byte, Size> copy_bytes(
    const std::span<const std::byte> value) noexcept {
    std::array<std::byte, Size> result{};
    if (value.size() == Size) std::copy(value.begin(), value.end(), result.begin());
    return result;
}

class SensitiveAscii final {
public:
    explicit SensitiveAscii(const std::span<const std::byte> value)
        : value_(ascii_string(value)) {}
    ~SensitiveAscii() { secure_zero(value_); }
    SensitiveAscii(const SensitiveAscii&) = delete;
    SensitiveAscii& operator=(const SensitiveAscii&) = delete;

    [[nodiscard]] std::string_view value() const noexcept { return value_; }

private:
    std::string value_;
};

struct InboundPayloadResult final {
    std::optional<ParsedControlBootstrapPayloadV1> payload;
    HostAuthenticatedControlErrorCodeV1 error{
        HostAuthenticatedControlErrorCodeV1::none};

    [[nodiscard]] bool succeeded() const noexcept {
        return payload.has_value() &&
            error == HostAuthenticatedControlErrorCodeV1::none;
    }
};

[[nodiscard]] InboundPayloadResult accept_inbound_payload(
    ControlBootstrapSequenceV1& sequence,
    const std::span<const std::byte> encoded_record,
    const ControlBootstrapMessageTypeV1 expected_type) noexcept {
    const auto framed = parse_authenticated_control_bootstrap_record_v1(
        encoded_record, ControlBootstrapDirectionV1::android_to_host);
    if (framed.status != ControlBootstrapParseStatusV1::parsed) {
        return {std::nullopt,
            HostAuthenticatedControlErrorCodeV1::unexpected_record};
    }
    const auto actual_type = framed.record.message_type;
    if (actual_type == ControlBootstrapMessageTypeV1::abort) {
        static_cast<void>(sequence.advance_inbound(actual_type));
        return {std::nullopt,
            HostAuthenticatedControlErrorCodeV1::peer_aborted};
    }
    if (actual_type != expected_type) {
        static_cast<void>(sequence.advance_inbound(actual_type));
        return {std::nullopt,
            HostAuthenticatedControlErrorCodeV1::unexpected_record};
    }
    if (sequence.advance_inbound(actual_type) !=
            ControlBootstrapAdvanceStatusV1::advanced) {
        return {std::nullopt,
            HostAuthenticatedControlErrorCodeV1::unexpected_record};
    }
    const auto parsed = parse_control_bootstrap_payload_v1(
        actual_type, framed.record.payload);
    if (parsed.status != ControlBootstrapPayloadStatusV1::parsed) {
        return {std::nullopt,
            HostAuthenticatedControlErrorCodeV1::unexpected_record};
    }
    return {parsed.payload, HostAuthenticatedControlErrorCodeV1::none};
}

[[nodiscard]] HostAuthenticatedControlRecordResultV1 encode_outbound(
    ControlBootstrapSequenceV1& sequence,
    const ControlBootstrapMessageTypeV1 message_type,
    const std::span<const ControlBootstrapPayloadFieldV1> fields) noexcept {
    auto payload = encode_control_bootstrap_payload_v1(message_type, fields);
    if (payload.status != ControlBootstrapPayloadStatusV1::encoded) {
        return record_failure(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
    }
    auto record = encode_authenticated_control_bootstrap_record_v1(
        ControlBootstrapDirectionV1::host_to_android,
        message_type,
        payload.payload);
    secure_zero(payload.payload);
    if (record.status != ControlBootstrapEncodeStatusV1::encoded) {
        secure_zero(record.record);
        return record_failure(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
    }
    const auto advanced = sequence.advance_outbound(message_type);
    const bool final_message =
        message_type == ControlBootstrapMessageTypeV1::host_finished;
    if ((!final_message && advanced != ControlBootstrapAdvanceStatusV1::advanced) ||
        (final_message && advanced != ControlBootstrapAdvanceStatusV1::completed)) {
        secure_zero(record.record);
        return record_failure(
            HostAuthenticatedControlErrorCodeV1::unexpected_record);
    }
    return {std::move(record.record), {}};
}

[[nodiscard]] PeerHandshakeSha256 host_identity_hash(
    const HostPublicIdentity& identity) noexcept {
    PeerHandshakeSha256 result{};
    std::transform(
        identity.public_key_sha256.begin(),
        identity.public_key_sha256.end(),
        result.begin(),
        [](const std::uint8_t value) { return std::byte{value}; });
    return result;
}

[[nodiscard]] bool configuration_valid(
    const HostPublicIdentity& host_public_identity,
    const HostAuthenticatedControlPairBindingV1& expected_pair,
    const HostAuthenticatedControlRouteV1& route,
    const HostAuthenticatedControlTimeV1 now,
    const PlatformP256EphemeralKeyAgreementV1* host_ephemeral,
    const PeerHandshakeNonce& host_nonce,
    const HostPairGenerationCredentialV1Verifier* credential_verifier,
    const HostPairCredentialVerificationTestCallbackV1 credential_callback,
    PeerHandshakeSha256& android_identity_hash) noexcept {
    if (now.epoch_seconds <= 0 ||
        now.monotonic_milliseconds >
            std::numeric_limits<std::uint64_t>::max() -
                kHostAuthenticatedControlHandshakeTimeoutMillisecondsV1 ||
        host_ephemeral == nullptr ||
        !contains_nonzero(host_nonce) ||
        (credential_verifier == nullptr && credential_callback == nullptr) ||
        host_public_identity.subject_public_key_info_der.empty() ||
        host_public_identity.public_key_sha256_hex !=
            expected_pair.host_identity_spki_sha256 ||
        !lower_hex(expected_pair.entitlement_id, 32U) ||
        !lower_hex(expected_pair.pair_id, 32U) ||
        !lower_hex(expected_pair.binding_id, 32U) ||
        expected_pair.binding_revision == 0U ||
        expected_pair.binding_revision > kSigned64Maximum ||
        expected_pair.revocation_version == 0U ||
        expected_pair.revocation_version > kSigned64Maximum ||
        expected_pair.generation_high_watermark > kSigned64Maximum ||
        !lower_hex(expected_pair.host_identity_spki_sha256, 64U) ||
        !decode_sha256_hex(
            expected_pair.android_identity_spki_sha256,
            android_identity_hash) ||
        expected_pair.host_identity_spki_sha256 ==
            expected_pair.android_identity_spki_sha256 ||
        expected_pair.android_subject_public_key_info_der.size() != 91U ||
        route.video_port == 0U || route.control_port == 0U ||
        route.video_port == route.control_port ||
        !stable_semver(route.host_runtime_version)) {
        return false;
    }
    switch (route.transport_kind) {
        case PeerHandshakeTransportKind::cat6:
        case PeerHandshakeTransportKind::wlan:
            return true;
    }
    return false;
}

}  // namespace

HostAuthenticatedControlCoordinatorV1::HostAuthenticatedControlCoordinatorV1(
    const HostPublicIdentity& host_public_identity,
    HostPairGenerationPopSignerV1& pair_pop_signer,
    HostPeerHandshakeTranscriptSignerV1& transcript_signer,
    HostAuthenticatedControlPairBindingV1 expected_pair,
    HostAuthenticatedControlRouteV1 route,
    const HostAuthenticatedControlTimeV1 created_at,
    std::unique_ptr<PlatformP256EphemeralKeyAgreementV1> host_ephemeral,
    const PeerHandshakeNonce host_nonce,
    std::unique_ptr<HostPairGenerationCredentialV1Verifier>
        credential_verifier,
    const HostPairCredentialVerificationTestCallbackV1 credential_callback,
    void* const credential_callback_context) noexcept
    : host_public_identity_(&host_public_identity),
      pair_pop_signer_(&pair_pop_signer),
      transcript_signer_(&transcript_signer),
      expected_pair_(std::move(expected_pair)),
      route_(std::move(route)),
      created_at_(created_at),
      host_ephemeral_(std::move(host_ephemeral)),
      host_nonce_(host_nonce),
      credential_verifier_(std::move(credential_verifier)),
      credential_callback_(credential_callback),
      credential_callback_context_(credential_callback_context) {}

HostAuthenticatedControlCoordinatorV1::~HostAuthenticatedControlCoordinatorV1() {
    close();
}

HostAuthenticatedControlConstructionResultV1
HostAuthenticatedControlCoordinatorV1::create(
    HostDeviceIdentityRuntime& identity_runtime,
    HostAuthenticatedControlPairBindingV1 expected_pair,
    HostAuthenticatedControlRouteV1 route,
    const HostAuthenticatedControlTimeV1 now) noexcept {
    auto verifier = HostPairGenerationCredentialV1Verifier::
        create_from_build_pinned_keyring();
    if (!verifier.succeeded()) {
        return construction_failure(
            HostAuthenticatedControlErrorCodeV1::invalid_configuration);
    }
    PeerHandshakeError ephemeral_error;
    auto ephemeral = PlatformP256EphemeralKeyAgreementV1::generate_platform(
        ephemeral_error);
    if (ephemeral == nullptr || ephemeral_error.has_error()) {
        return construction_failure(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
    }
    PeerHandshakeNonce nonce{};
    const NTSTATUS random_status = BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(nonce.data()),
        static_cast<ULONG>(nonce.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(random_status) || !contains_nonzero(nonce)) {
        secure_zero(nonce);
        return construction_failure(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
    }
    return create_internal(
        identity_runtime.public_identity(),
        identity_runtime.pair_generation_pop_signer(),
        identity_runtime.peer_handshake_signer(),
        std::move(expected_pair),
        std::move(route),
        now,
        std::move(ephemeral),
        nonce,
        std::move(verifier.verifier),
        nullptr,
        nullptr);
}

#if defined(VFDUAL_ENABLE_HOST_AUTHENTICATED_CONTROL_TEST_ACCESS)
HostAuthenticatedControlConstructionResultV1
HostAuthenticatedControlCoordinatorV1::create_for_test(
    const HostPublicIdentity& host_public_identity,
    HostPairGenerationPopSignerV1& pair_pop_signer,
    HostPeerHandshakeTranscriptSignerV1& transcript_signer,
    HostAuthenticatedControlPairBindingV1 expected_pair,
    HostAuthenticatedControlRouteV1 route,
    const HostAuthenticatedControlTimeV1 now,
    std::unique_ptr<PlatformP256EphemeralKeyAgreementV1> host_ephemeral,
    const PeerHandshakeNonce host_nonce,
    const HostPairCredentialVerificationTestCallbackV1 credential_callback,
    void* const credential_callback_context) noexcept {
    return create_internal(
        host_public_identity,
        pair_pop_signer,
        transcript_signer,
        std::move(expected_pair),
        std::move(route),
        now,
        std::move(host_ephemeral),
        host_nonce,
        nullptr,
        credential_callback,
        credential_callback_context);
}
#endif

HostAuthenticatedControlConstructionResultV1
HostAuthenticatedControlCoordinatorV1::create_internal(
    const HostPublicIdentity& host_public_identity,
    HostPairGenerationPopSignerV1& pair_pop_signer,
    HostPeerHandshakeTranscriptSignerV1& transcript_signer,
    HostAuthenticatedControlPairBindingV1 expected_pair,
    HostAuthenticatedControlRouteV1 route,
    const HostAuthenticatedControlTimeV1 now,
    std::unique_ptr<PlatformP256EphemeralKeyAgreementV1> host_ephemeral,
    const PeerHandshakeNonce host_nonce,
    std::unique_ptr<HostPairGenerationCredentialV1Verifier>
        credential_verifier,
    const HostPairCredentialVerificationTestCallbackV1 credential_callback,
    void* const credential_callback_context) noexcept {
    try {
        PeerHandshakeSha256 android_identity_hash{};
        if (!configuration_valid(
                host_public_identity,
                expected_pair,
                route,
                now,
                host_ephemeral.get(),
                host_nonce,
                credential_verifier.get(),
                credential_callback,
                android_identity_hash)) {
            secure_zero(android_identity_hash);
            return construction_failure(
                HostAuthenticatedControlErrorCodeV1::invalid_configuration);
        }
        auto coordinator =
            std::unique_ptr<HostAuthenticatedControlCoordinatorV1>(
                new HostAuthenticatedControlCoordinatorV1(
                    host_public_identity,
                    pair_pop_signer,
                    transcript_signer,
                    std::move(expected_pair),
                    std::move(route),
                    now,
                    std::move(host_ephemeral),
                    host_nonce,
                    std::move(credential_verifier),
                    credential_callback,
                    credential_callback_context));
        coordinator->android_identity_spki_sha256_ = android_identity_hash;
        secure_zero(android_identity_hash);
        return {std::move(coordinator), {}};
    } catch (const std::bad_alloc&) {
        return construction_failure(
            HostAuthenticatedControlErrorCodeV1::allocation_failed);
    } catch (...) {
        return construction_failure(
            HostAuthenticatedControlErrorCodeV1::invalid_configuration);
    }
}

HostAuthenticatedControlRecordResultV1
HostAuthenticatedControlCoordinatorV1::start(
    const HostAuthenticatedControlTimeV1 now) noexcept {
    std::lock_guard lock(mutex_);
    if (closed_) return record_failure(
        HostAuthenticatedControlErrorCodeV1::closed);
    if (started_) {
        burn_locked(HostAuthenticatedControlErrorCodeV1::unexpected_record);
        return record_failure(
            HostAuthenticatedControlErrorCodeV1::unexpected_record);
    }
    if (!time_is_valid_locked(now)) {
        burn_locked(HostAuthenticatedControlErrorCodeV1::timed_out);
        return record_failure(HostAuthenticatedControlErrorCodeV1::timed_out);
    }
    try {
        const auto transport = std::array{
            std::byte{static_cast<std::uint8_t>(route_.transport_kind)}};
        const auto video_port = u16_be(route_.video_port);
        const auto control_port = u16_be(route_.control_port);
        const auto& public_identity = *host_public_identity_;
        const auto fields = std::array<ControlBootstrapPayloadFieldV1, 9U>{
            ControlBootstrapPayloadFieldV1{0U, bytes_of(
                std::span<const std::uint8_t>{
                    public_identity.subject_public_key_info_der})},
            ControlBootstrapPayloadFieldV1{1U,
                host_ephemeral_->public_key_sec1()},
            ControlBootstrapPayloadFieldV1{2U, host_nonce_},
            ControlBootstrapPayloadFieldV1{3U, transport},
            ControlBootstrapPayloadFieldV1{4U, route_.host_ipv4},
            ControlBootstrapPayloadFieldV1{5U, route_.android_ipv4},
            ControlBootstrapPayloadFieldV1{6U, video_port},
            ControlBootstrapPayloadFieldV1{7U, control_port},
            ControlBootstrapPayloadFieldV1{8U,
                bytes_of(route_.host_runtime_version)},
        };
        auto result = encode_outbound(
            sequence_, ControlBootstrapMessageTypeV1::host_hello, fields);
        if (!result.succeeded()) {
            burn_locked(result.error.code);
            return result;
        }
        started_ = true;
        return result;
    } catch (const std::bad_alloc&) {
        burn_locked(HostAuthenticatedControlErrorCodeV1::allocation_failed);
        return record_failure(
            HostAuthenticatedControlErrorCodeV1::allocation_failed);
    } catch (...) {
        burn_locked(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
        return record_failure(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
    }
}

HostAuthenticatedControlRecordResultV1
HostAuthenticatedControlCoordinatorV1::accept_android_challenge_request(
    const std::span<const std::byte> encoded_record,
    const HostAuthenticatedControlTimeV1 now) noexcept {
    std::lock_guard lock(mutex_);
    if (closed_) return record_failure(
        HostAuthenticatedControlErrorCodeV1::closed);
    if (!started_) {
        burn_locked(HostAuthenticatedControlErrorCodeV1::unexpected_record);
        return record_failure(
            HostAuthenticatedControlErrorCodeV1::unexpected_record);
    }
    if (!time_is_valid_locked(now)) {
        burn_locked(HostAuthenticatedControlErrorCodeV1::timed_out);
        return record_failure(HostAuthenticatedControlErrorCodeV1::timed_out);
    }
    try {
        auto inbound = accept_inbound_payload(
            sequence_, encoded_record,
            ControlBootstrapMessageTypeV1::android_challenge_request);
        if (!inbound.succeeded()) {
            burn_locked(inbound.error);
            return record_failure(inbound.error);
        }
        const auto& payload = *inbound.payload;
        const std::string request_id = ascii_string(payload.field(0U));
        const std::string allocation_request_id =
            ascii_string(payload.field(1U));
        const std::string entitlement_id = ascii_string(payload.field(2U));
        const std::string pair_id = ascii_string(payload.field(3U));
        const std::string binding_id = ascii_string(payload.field(4U));
        const std::uint64_t binding_revision =
            read_control_bootstrap_u64_be_v1(payload.field(5U));
        const std::uint64_t revocation_version =
            read_control_bootstrap_u64_be_v1(payload.field(6U));
        const auto android_spki_bytes = unsigned_bytes_of(payload.field(7U));
        const auto android_ephemeral =
            copy_bytes<kPeerHandshakeP256PublicKeyBytes>(payload.field(8U));
        const auto android_nonce =
            copy_bytes<kPeerHandshakeNonceBytes>(payload.field(9U));
        const std::string android_runtime_version =
            ascii_string(payload.field(10U));
        const auto android_signature = unsigned_bytes_of(payload.field(11U));

        if (entitlement_id != expected_pair_.entitlement_id ||
            pair_id != expected_pair_.pair_id ||
            binding_id != expected_pair_.binding_id ||
            binding_revision != expected_pair_.binding_revision ||
            revocation_version != expected_pair_.revocation_version ||
            !std::equal(
                android_spki_bytes.begin(), android_spki_bytes.end(),
                expected_pair_.android_subject_public_key_info_der.begin(),
                expected_pair_.android_subject_public_key_info_der.end()) ||
            !stable_semver(android_runtime_version)) {
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::pair_binding_mismatch);
            return record_failure(
                HostAuthenticatedControlErrorCodeV1::pair_binding_mismatch);
        }

        PairGenerationChallengeFieldsV1 challenge_fields{
            .request_id = request_id,
            .allocation_request_id = allocation_request_id,
            .entitlement_id = entitlement_id,
            .pair_id = pair_id,
            .binding_id = binding_id,
            .binding_revision = binding_revision,
            .revocation_version = revocation_version,
            .host_identity_spki_sha256 =
                host_identity_hash(*host_public_identity_),
            .android_identity_spki_sha256 =
                android_identity_spki_sha256_,
        };
        auto typed_request =
            build_pair_generation_challenge_request_v1(challenge_fields);
        if (!typed_request.succeeded()) {
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::pair_binding_mismatch);
            return record_failure(
                HostAuthenticatedControlErrorCodeV1::pair_binding_mismatch);
        }
        const auto android_verified =
            verify_android_pair_generation_challenge_identity_signature_v1(
                android_spki_bytes,
                *typed_request.request,
                android_signature);
        if (!android_verified.completed() ||
            !android_verified.proof_of_possession_valid) {
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
            return record_failure(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
        }

        HostPairGenerationChallengeSigningInputV1 signing_input{
            .request_id = request_id,
            .allocation_request_id = allocation_request_id,
            .entitlement_id = entitlement_id,
            .pair_id = pair_id,
            .binding_id = binding_id,
            .binding_revision = binding_revision,
            .revocation_version = revocation_version,
            .android_identity_spki_sha256 =
                android_identity_spki_sha256_,
        };
        auto signed_request = pair_pop_signer_->build_and_sign_challenge(
            std::move(signing_input));
        if (!signed_request.succeeded() ||
            signed_request.signed_challenge->request().payload_sha256() !=
                typed_request.request->payload_sha256()) {
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
            return record_failure(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
        }

        const auto signature_bytes = bytes_of(
            signed_request.signed_challenge->signature_der_low_s());
        const auto fields = std::array<ControlBootstrapPayloadFieldV1, 1U>{
            ControlBootstrapPayloadFieldV1{0U, signature_bytes},
        };
        android_ephemeral_public_key_ = android_ephemeral;
        android_nonce_ = android_nonce;
        android_runtime_version_ = android_runtime_version;
        signed_challenge_ = std::move(signed_request.signed_challenge);
        auto result = encode_outbound(
            sequence_,
            ControlBootstrapMessageTypeV1::host_challenge_proof,
            fields);
        if (!result.succeeded()) burn_locked(result.error.code);
        return result;
    } catch (const std::bad_alloc&) {
        burn_locked(HostAuthenticatedControlErrorCodeV1::allocation_failed);
        return record_failure(
            HostAuthenticatedControlErrorCodeV1::allocation_failed);
    } catch (...) {
        burn_locked(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
        return record_failure(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
    }
}

HostAuthenticatedControlRecordResultV1
HostAuthenticatedControlCoordinatorV1::accept_server_challenge(
    const std::span<const std::byte> encoded_record,
    const HostAuthenticatedControlTimeV1 now) noexcept {
    std::lock_guard lock(mutex_);
    if (closed_) return record_failure(
        HostAuthenticatedControlErrorCodeV1::closed);
    if (!time_is_valid_locked(now)) {
        burn_locked(HostAuthenticatedControlErrorCodeV1::timed_out);
        return record_failure(HostAuthenticatedControlErrorCodeV1::timed_out);
    }
    try {
        auto inbound = accept_inbound_payload(
            sequence_, encoded_record,
            ControlBootstrapMessageTypeV1::server_challenge);
        if (!inbound.succeeded() || signed_challenge_ == nullptr) {
            const auto code = inbound.error ==
                    HostAuthenticatedControlErrorCodeV1::none
                ? HostAuthenticatedControlErrorCodeV1::unexpected_record
                : inbound.error;
            burn_locked(code);
            return record_failure(code);
        }
        const auto& payload = *inbound.payload;
        const std::string challenge_id = ascii_string(payload.field(0U));
        const std::uint64_t expires_at =
            read_control_bootstrap_u64_be_v1(payload.field(1U));
        auto server_nonce =
            copy_bytes<kPeerHandshakeNonceBytes>(payload.field(2U));
        if (expires_at <= static_cast<std::uint64_t>(now.epoch_seconds) ||
            now.epoch_seconds >
                std::numeric_limits<std::int64_t>::max() -
                    kHostAuthenticatedControlServerChallengeMaximumTtlSecondsV1 ||
            expires_at > static_cast<std::uint64_t>(
                now.epoch_seconds +
                kHostAuthenticatedControlServerChallengeMaximumTtlSecondsV1)) {
            secure_zero(server_nonce);
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    server_authorization_rejected);
            return record_failure(
                HostAuthenticatedControlErrorCodeV1::
                    server_authorization_rejected);
        }

        const auto connection = derive_pair_generation_connection_id_v1(
            server_nonce,
            challenge_id,
            host_nonce_,
            android_nonce_,
            expected_pair_.pair_id,
            host_identity_hash(*host_public_identity_),
            android_identity_spki_sha256_);
        if (!connection.succeeded()) {
            secure_zero(server_nonce);
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
            return record_failure(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
        }

        PairGenerationProposalFields proposal_fields{
            .host_identity_spki_sha256 =
                host_identity_hash(*host_public_identity_),
            .android_identity_spki_sha256 =
                android_identity_spki_sha256_,
            .host_ephemeral_public_key = copy_bytes<
                kPeerHandshakeP256PublicKeyBytes>(
                    host_ephemeral_->public_key_sec1()),
            .android_ephemeral_public_key =
                android_ephemeral_public_key_,
            .host_nonce = host_nonce_,
            .android_nonce = android_nonce_,
            .connection_id = connection.connection_id,
            .transport_kind = route_.transport_kind,
            .host_ipv4 = route_.host_ipv4,
            .android_ipv4 = route_.android_ipv4,
            .video_port = route_.video_port,
            .control_port = route_.control_port,
            .pair_id = expected_pair_.pair_id,
            .host_runtime_version = route_.host_runtime_version,
            .android_runtime_version = android_runtime_version_,
        };
        auto built_proposal = build_pair_generation_proposal_v1(
            proposal_fields);
        if (!built_proposal.succeeded()) {
            secure_zero(server_nonce);
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
            return record_failure(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
        }
        auto signed_final =
            pair_pop_signer_->build_and_sign_final_credential_proof(
                *signed_challenge_,
                challenge_id,
                expires_at,
                server_nonce,
                *built_proposal.proposal);
        secure_zero(server_nonce);
        if (!signed_final.succeeded()) {
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
            return record_failure(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
        }
        const auto signature_bytes = bytes_of(
            signed_final.signed_proof->signature_der_low_s());
        const auto fields = std::array<ControlBootstrapPayloadFieldV1, 1U>{
            ControlBootstrapPayloadFieldV1{0U, signature_bytes},
        };
        proposal_ = std::move(*built_proposal.proposal);
        auto result = encode_outbound(
            sequence_,
            ControlBootstrapMessageTypeV1::host_final_proof,
            fields);
        if (!result.succeeded()) burn_locked(result.error.code);
        return result;
    } catch (const std::bad_alloc&) {
        burn_locked(HostAuthenticatedControlErrorCodeV1::allocation_failed);
        return record_failure(
            HostAuthenticatedControlErrorCodeV1::allocation_failed);
    } catch (...) {
        burn_locked(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
        return record_failure(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
    }
}

HostAuthenticatedControlRecordResultV1
HostAuthenticatedControlCoordinatorV1::accept_pair_generation_credential(
    const std::span<const std::byte> encoded_record,
    const HostAuthenticatedControlTimeV1 now) noexcept {
    std::lock_guard lock(mutex_);
    if (closed_) return record_failure(
        HostAuthenticatedControlErrorCodeV1::closed);
    if (!time_is_valid_locked(now)) {
        burn_locked(HostAuthenticatedControlErrorCodeV1::timed_out);
        return record_failure(HostAuthenticatedControlErrorCodeV1::timed_out);
    }
    try {
        auto inbound = accept_inbound_payload(
            sequence_, encoded_record,
            ControlBootstrapMessageTypeV1::pair_generation_credential);
        if (!inbound.succeeded() || proposal_ == std::nullopt ||
            signed_challenge_ == nullptr || host_ephemeral_ == nullptr) {
            const auto code = inbound.error ==
                    HostAuthenticatedControlErrorCodeV1::none
                ? HostAuthenticatedControlErrorCodeV1::unexpected_record
                : inbound.error;
            burn_locked(code);
            return record_failure(code);
        }
        const auto& payload = *inbound.payload;
        const std::uint64_t generation =
            read_control_bootstrap_u64_be_v1(payload.field(0U));
        const std::uint64_t candidate_connection_id =
            read_control_bootstrap_u64_be_v1(payload.field(1U));
        const auto candidate_proposal_hash =
            copy_bytes<kPeerHandshakeSha256Bytes>(payload.field(2U));
        SensitiveAscii compact_credential(payload.field(3U));
        const auto& proposal = *proposal_;
        if (generation == 0U || generation > kSigned64Maximum ||
            generation <= expected_pair_.generation_high_watermark ||
            candidate_connection_id != proposal.fields().connection_id ||
            candidate_proposal_hash != proposal.proposal_sha256()) {
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    server_authorization_rejected);
            return record_failure(
                HostAuthenticatedControlErrorCodeV1::
                    server_authorization_rejected);
        }

        const auto& challenge_fields =
            signed_challenge_->request().fields();
        HostPairGenerationCredentialExpectedV1 expected{
            .allocation_request_id = challenge_fields.allocation_request_id,
            .pair_id = expected_pair_.pair_id,
            .entitlement_id = expected_pair_.entitlement_id,
            .binding_id = expected_pair_.binding_id,
            .binding_revision = static_cast<std::int64_t>(
                expected_pair_.binding_revision),
            .revocation_version = static_cast<std::int64_t>(
                expected_pair_.revocation_version),
            .generation = static_cast<std::int64_t>(generation),
            .connection_id = static_cast<std::int64_t>(
                candidate_connection_id),
            .host_identity_spki_sha256 =
                expected_pair_.host_identity_spki_sha256,
            .android_identity_spki_sha256 =
                expected_pair_.android_identity_spki_sha256,
            .transcript_proposal_sha256 =
                lower_hex_sha256(candidate_proposal_hash),
        };
        if (!verify_pair_credential_locked(
                compact_credential.value(), expected, now.epoch_seconds)) {
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    server_authorization_rejected);
            return record_failure(
                HostAuthenticatedControlErrorCodeV1::
                    server_authorization_rejected);
        }

        auto expected_transcript =
            build_final_peer_handshake_transcript_from_proposal_v1(
                proposal, static_cast<std::int64_t>(generation));
        if (!expected_transcript.succeeded()) {
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
            return record_failure(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
        }

        HostPeerHandshakeSigningInputV1 signing_input{
            .host_ephemeral = std::move(host_ephemeral_),
            .android_identity_spki_sha256 =
                proposal.fields().android_identity_spki_sha256,
            .android_ephemeral_public_key =
                proposal.fields().android_ephemeral_public_key,
            .host_nonce = proposal.fields().host_nonce,
            .android_nonce = proposal.fields().android_nonce,
            .connection_id = proposal.fields().connection_id,
            .session_generation = generation,
            .transport_kind = proposal.fields().transport_kind,
            .host_ipv4 = proposal.fields().host_ipv4,
            .android_ipv4 = proposal.fields().android_ipv4,
            .video_port = proposal.fields().video_port,
            .control_port = proposal.fields().control_port,
            .pair_id = proposal.fields().pair_id,
            .host_runtime_version = proposal.fields().host_runtime_version,
            .android_runtime_version = proposal.fields().android_runtime_version,
        };
        auto signed_context = transcript_signer_->build_and_sign_bound_transcript(
            std::move(signing_input));
        if (!signed_context.succeeded() ||
            signed_context.context->transcript().transcript_sha256() !=
                expected_transcript.transcript->transcript_sha256() ||
            !std::equal(
                signed_context.context->transcript().canonical_bytes().begin(),
                signed_context.context->transcript().canonical_bytes().end(),
                expected_transcript.transcript->canonical_bytes().begin(),
                expected_transcript.transcript->canonical_bytes().end())) {
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
            return record_failure(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
        }

        const auto signature_bytes = bytes_of(
            signed_context.context->signature_der_low_s());
        const auto fields = std::array<ControlBootstrapPayloadFieldV1, 1U>{
            ControlBootstrapPayloadFieldV1{0U, signature_bytes},
        };
        signed_context_ = std::move(signed_context.context);
        signed_challenge_.reset();
        proposal_.reset();
        credential_verifier_.reset();
        credential_callback_ = nullptr;
        credential_callback_context_ = nullptr;
        auto result = encode_outbound(
            sequence_,
            ControlBootstrapMessageTypeV1::host_handshake_signature,
            fields);
        if (!result.succeeded()) burn_locked(result.error.code);
        return result;
    } catch (const std::bad_alloc&) {
        burn_locked(HostAuthenticatedControlErrorCodeV1::allocation_failed);
        return record_failure(
            HostAuthenticatedControlErrorCodeV1::allocation_failed);
    } catch (...) {
        burn_locked(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
        return record_failure(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
    }
}

HostAuthenticatedControlCompletionResultV1
HostAuthenticatedControlCoordinatorV1::
accept_android_handshake_confirmation(
    const std::span<const std::byte> encoded_record,
    const HostAuthenticatedControlTimeV1 now) noexcept {
    std::lock_guard lock(mutex_);
    if (closed_) return completion_failure(
        HostAuthenticatedControlErrorCodeV1::closed);
    if (!time_is_valid_locked(now)) {
        burn_locked(HostAuthenticatedControlErrorCodeV1::timed_out);
        return completion_failure(
            HostAuthenticatedControlErrorCodeV1::timed_out);
    }
    try {
        auto inbound = accept_inbound_payload(
            sequence_, encoded_record,
            ControlBootstrapMessageTypeV1::android_handshake_confirmation);
        if (!inbound.succeeded() || signed_context_ == nullptr) {
            const auto code = inbound.error ==
                    HostAuthenticatedControlErrorCodeV1::none
                ? HostAuthenticatedControlErrorCodeV1::unexpected_record
                : inbound.error;
            burn_locked(code);
            return completion_failure(code);
        }
        const auto& payload = *inbound.payload;
        const auto android_signature = unsigned_bytes_of(payload.field(0U));
        const auto android_finished = payload.field(1U);
        const auto identity_verified =
            verify_android_peer_handshake_identity_signature_v1(
                expected_pair_.android_subject_public_key_info_der,
                signed_context_->transcript(),
                android_signature);
        if (!identity_verified.completed() ||
            !identity_verified.proof_of_possession_valid) {
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
            return completion_failure(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
        }

        PeerHandshakeError pending_error;
        auto pending = signed_context_->
            derive_pending_after_peer_identity_verified_for_bound_transcript(
                pending_error);
        if (pending == nullptr || pending_error.has_error()) {
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
            return completion_failure(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
        }
        auto host_finished = pending->create_local_finished_mac();
        if (!host_finished.succeeded()) {
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
            return completion_failure(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
        }
        auto confirmed = std::move(*pending).confirm_peer_finished_and_consume(
            android_finished);
        if (!confirmed.peer_finished_accepted() ||
            confirmed.confirmed_session->local_role() !=
                PeerHandshakeRole::host ||
            confirmed.confirmed_session->connection_id() !=
                signed_context_->transcript().fields().connection_id ||
            confirmed.confirmed_session->transcript_sha256() !=
                signed_context_->transcript().transcript_sha256()) {
            burn_locked(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
            return completion_failure(
                HostAuthenticatedControlErrorCodeV1::
                    cryptographic_verification_failed);
        }

        const auto fields = std::array<ControlBootstrapPayloadFieldV1, 1U>{
            ControlBootstrapPayloadFieldV1{0U, *host_finished.digest},
        };
        auto encoded = encode_outbound(
            sequence_, ControlBootstrapMessageTypeV1::host_finished, fields);
        if (!encoded.succeeded()) {
            burn_locked(encoded.error.code);
            return completion_failure(encoded.error.code);
        }

        // Confirmed material is still not an active capability. The caller's
        // production composition root must atomically install this session at
        // key_epoch=1 together with the raw usage lease before enabling I/O.
        completed_ = true;
        closed_ = true;
        const std::uint64_t session_generation =
            signed_context_->transcript().fields().session_generation;
        auto session = std::move(confirmed.confirmed_session);
        erase_state_locked();
        return {
            std::move(encoded.outbound_record),
            std::move(session),
            session_generation,
            {}};
    } catch (const std::bad_alloc&) {
        burn_locked(HostAuthenticatedControlErrorCodeV1::allocation_failed);
        return completion_failure(
            HostAuthenticatedControlErrorCodeV1::allocation_failed);
    } catch (...) {
        burn_locked(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
        return completion_failure(
            HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
    }
}

bool HostAuthenticatedControlCoordinatorV1::time_is_valid_locked(
    const HostAuthenticatedControlTimeV1 now) noexcept {
    return now.epoch_seconds > 0 &&
        now.epoch_seconds >= created_at_.epoch_seconds &&
        now.monotonic_milliseconds >= created_at_.monotonic_milliseconds &&
        now.monotonic_milliseconds - created_at_.monotonic_milliseconds <=
            kHostAuthenticatedControlHandshakeTimeoutMillisecondsV1;
}

bool HostAuthenticatedControlCoordinatorV1::verify_pair_credential_locked(
    const std::string_view compact_token_ascii,
    const HostPairGenerationCredentialExpectedV1& expected,
    const std::int64_t now_epoch) noexcept {
    if (credential_verifier_ != nullptr) {
        return credential_verifier_->verify(
            compact_token_ascii, expected, now_epoch).succeeded();
    }
    return credential_callback_ != nullptr && credential_callback_(
        credential_callback_context_,
        compact_token_ascii,
        expected,
        now_epoch);
}

void HostAuthenticatedControlCoordinatorV1::burn_locked(
    const HostAuthenticatedControlErrorCodeV1) noexcept {
    closed_ = true;
    completed_ = false;
    erase_state_locked();
}

void HostAuthenticatedControlCoordinatorV1::erase_state_locked() noexcept {
    host_ephemeral_.reset();
    signed_challenge_.reset();
    proposal_.reset();
    signed_context_.reset();
    credential_verifier_.reset();
    credential_callback_ = nullptr;
    credential_callback_context_ = nullptr;
    host_public_identity_ = nullptr;
    pair_pop_signer_ = nullptr;
    transcript_signer_ = nullptr;
    secure_zero(host_nonce_);
    secure_zero(android_identity_spki_sha256_);
    secure_zero(android_ephemeral_public_key_);
    secure_zero(android_nonce_);
    secure_zero(android_runtime_version_);
    secure_zero(expected_pair_.android_subject_public_key_info_der);
    secure_zero(expected_pair_.host_identity_spki_sha256);
    secure_zero(expected_pair_.android_identity_spki_sha256);
    expected_pair_.entitlement_id.clear();
    expected_pair_.pair_id.clear();
    expected_pair_.binding_id.clear();
    expected_pair_.binding_revision = 0U;
    expected_pair_.revocation_version = 0U;
    expected_pair_.generation_high_watermark = 0U;
    secure_zero(route_.host_runtime_version);
}

void HostAuthenticatedControlCoordinatorV1::close() noexcept {
    std::lock_guard lock(mutex_);
    if (closed_ && host_public_identity_ == nullptr) return;
    closed_ = true;
    if (!completed_) completed_ = false;
    erase_state_locked();
}

bool HostAuthenticatedControlCoordinatorV1::is_closed() const noexcept {
    std::lock_guard lock(mutex_);
    return closed_;
}

bool HostAuthenticatedControlCoordinatorV1::is_completed() const noexcept {
    std::lock_guard lock(mutex_);
    return completed_;
}

std::size_t HostAuthenticatedControlCoordinatorV1::accepted_event_count()
    const noexcept {
    std::lock_guard lock(mutex_);
    return sequence_.accepted_event_count();
}

const char* host_authenticated_control_error_code_name_v1(
    const HostAuthenticatedControlErrorCodeV1 code) noexcept {
    switch (code) {
        case HostAuthenticatedControlErrorCodeV1::none: return "none";
        case HostAuthenticatedControlErrorCodeV1::invalid_configuration:
            return "invalid_configuration";
        case HostAuthenticatedControlErrorCodeV1::timed_out: return "timed_out";
        case HostAuthenticatedControlErrorCodeV1::unexpected_record:
            return "unexpected_record";
        case HostAuthenticatedControlErrorCodeV1::peer_aborted:
            return "peer_aborted";
        case HostAuthenticatedControlErrorCodeV1::pair_binding_mismatch:
            return "pair_binding_mismatch";
        case HostAuthenticatedControlErrorCodeV1::server_authorization_rejected:
            return "server_authorization_rejected";
        case HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed:
            return "cryptographic_verification_failed";
        case HostAuthenticatedControlErrorCodeV1::allocation_failed:
            return "allocation_failed";
        case HostAuthenticatedControlErrorCodeV1::closed: return "closed";
    }
    return "unknown";
}

}  // namespace vfdual
