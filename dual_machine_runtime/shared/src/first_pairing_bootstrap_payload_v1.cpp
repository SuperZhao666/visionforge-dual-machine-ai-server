#include "vfdual/first_pairing_bootstrap_payload_v1.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <string_view>
#include <utility>

namespace vfdual {
namespace {

constexpr std::uint8_t kVersion = 1U;
constexpr std::size_t kOfferBytes = 256U;
constexpr std::size_t kMaximumActivationProofWireBytes = 2'048U;
constexpr std::array<std::byte, 4U> kHostOfferMagic{
    std::byte{'V'}, std::byte{'F'}, std::byte{'H'}, std::byte{'O'}};
constexpr std::array<std::byte, 4U> kAndroidOfferMagic{
    std::byte{'V'}, std::byte{'F'}, std::byte{'A'}, std::byte{'O'}};
constexpr std::array<std::byte, 4U> kConfirmationMagic{
    std::byte{'V'}, std::byte{'F'}, std::byte{'C'}, std::byte{'F'}};
constexpr std::array<std::byte, 4U> kActivationRequestMagic{
    std::byte{'V'}, std::byte{'F'}, std::byte{'A'}, std::byte{'R'}};
constexpr std::array<std::byte, 4U> kActivationSignatureMagic{
    std::byte{'V'}, std::byte{'F'}, std::byte{'A'}, std::byte{'S'}};
constexpr std::array<std::byte, 4U> kActivationResultMagic{
    std::byte{'V'}, std::byte{'F'}, std::byte{'R'}, std::byte{'S'}};
constexpr std::array<std::byte, 4U> kCompleteMagic{
    std::byte{'V'}, std::byte{'F'}, std::byte{'P'}, std::byte{'C'}};
constexpr std::array<std::byte, 27U> kP256SpkiPrefix{
    std::byte{0x30U}, std::byte{0x59U}, std::byte{0x30U}, std::byte{0x13U},
    std::byte{0x06U}, std::byte{0x07U}, std::byte{0x2aU}, std::byte{0x86U},
    std::byte{0x48U}, std::byte{0xceU}, std::byte{0x3dU}, std::byte{0x02U},
    std::byte{0x01U}, std::byte{0x06U}, std::byte{0x08U}, std::byte{0x2aU},
    std::byte{0x86U}, std::byte{0x48U}, std::byte{0xceU}, std::byte{0x3dU},
    std::byte{0x03U}, std::byte{0x01U}, std::byte{0x07U}, std::byte{0x03U},
    std::byte{0x42U}, std::byte{0x00U}, std::byte{0x04U}};

template <typename T>
[[nodiscard]] bool nonzero(const T& value) noexcept {
    return std::any_of(value.begin(), value.end(), [](const auto item) {
        return item != decltype(item){};
    });
}

[[nodiscard]] bool valid_spki(
    const std::span<const std::uint8_t> value) noexcept {
    if (value.size() != 91U) return false;
    return std::equal(
        kP256SpkiPrefix.begin(), kP256SpkiPrefix.end(), value.begin(),
        [](const std::byte left, const std::uint8_t right) {
            return std::to_integer<std::uint8_t>(left) == right;
        }) && std::any_of(value.begin() + 27, value.end(),
            [](const std::uint8_t item) { return item != 0U; });
}

[[nodiscard]] bool valid_signature(
    const std::span<const std::uint8_t> value) noexcept {
    return value.size() >= 8U && value.size() <= 72U &&
        value.front() == 0x30U && value[1U] == value.size() - 2U;
}

[[nodiscard]] bool valid_offer_type(
    const ControlBootstrapMessageTypeV1 type) noexcept {
    return type == ControlBootstrapMessageTypeV1::host_first_pair_offer ||
        type == ControlBootstrapMessageTypeV1::android_first_pair_offer;
}

[[nodiscard]] bool valid_confirmation_type(
    const ControlBootstrapMessageTypeV1 type) noexcept {
    return type ==
            ControlBootstrapMessageTypeV1::host_first_pair_confirmation ||
        type ==
            ControlBootstrapMessageTypeV1::android_first_pair_confirmation;
}

[[nodiscard]] FirstPairingConfirmationRoleV1 role_for_type(
    const ControlBootstrapMessageTypeV1 type) noexcept {
    if (type ==
        ControlBootstrapMessageTypeV1::host_first_pair_confirmation) {
        return FirstPairingConfirmationRoleV1::host;
    }
    if (type ==
        ControlBootstrapMessageTypeV1::android_first_pair_confirmation) {
        return FirstPairingConfirmationRoleV1::android;
    }
    return static_cast<FirstPairingConfirmationRoleV1>(0U);
}

class Writer final {
public:
    explicit Writer(const std::size_t reserve) { bytes_.reserve(reserve); }

    template <std::size_t Size>
    void append(const std::array<std::byte, Size>& value) {
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }
    void append(const std::span<const std::uint8_t> value) {
        for (const std::uint8_t item : value) bytes_.push_back(std::byte{item});
    }
    void u8(const std::uint8_t value) { bytes_.push_back(std::byte{value}); }
    void u16(const std::uint16_t value) {
        u8(static_cast<std::uint8_t>(value >> 8U));
        u8(static_cast<std::uint8_t>(value));
    }
    void u32(const std::uint32_t value) {
        u8(static_cast<std::uint8_t>(value >> 24U));
        u8(static_cast<std::uint8_t>(value >> 16U));
        u8(static_cast<std::uint8_t>(value >> 8U));
        u8(static_cast<std::uint8_t>(value));
    }
    void u64(const std::uint64_t value) {
        for (std::size_t index{}; index < 8U; ++index) {
            u8(static_cast<std::uint8_t>(value >> ((7U - index) * 8U)));
        }
    }
    void string(const std::string_view value) {
        u16(static_cast<std::uint16_t>(value.size()));
        for (const char item : value) {
            u8(static_cast<std::uint8_t>(item));
        }
    }
    [[nodiscard]] std::vector<std::byte> take() { return std::move(bytes_); }

private:
    std::vector<std::byte> bytes_;
};

class Reader final {
public:
    explicit Reader(const std::span<const std::byte> bytes) : bytes_(bytes) {}

    template <std::size_t Size>
    [[nodiscard]] bool exact(std::array<std::byte, Size>& output) {
        const auto value = take(Size);
        if (!value.has_value()) return false;
        std::copy(value->begin(), value->end(), output.begin());
        return true;
    }
    [[nodiscard]] bool exact_uint8(std::vector<std::uint8_t>& output,
                                   const std::size_t size) {
        const auto value = take(size);
        if (!value.has_value()) return false;
        output.resize(size);
        std::transform(value->begin(), value->end(), output.begin(),
            [](const std::byte item) {
                return std::to_integer<std::uint8_t>(item);
            });
        return true;
    }
    [[nodiscard]] std::optional<std::uint8_t> u8() {
        const auto value = take(1U);
        if (!value.has_value()) return std::nullopt;
        return std::to_integer<std::uint8_t>(value->front());
    }
    [[nodiscard]] std::optional<std::uint16_t> u16() {
        const auto value = take(2U);
        if (!value.has_value()) return std::nullopt;
        return static_cast<std::uint16_t>(
            (std::to_integer<std::uint8_t>((*value)[0U]) << 8U) |
            std::to_integer<std::uint8_t>((*value)[1U]));
    }
    [[nodiscard]] std::optional<std::uint32_t> u32() {
        const auto value = take(4U);
        if (!value.has_value()) return std::nullopt;
        std::uint32_t result{};
        for (const std::byte item : *value) {
            result = (result << 8U) | std::to_integer<std::uint8_t>(item);
        }
        return result;
    }
    [[nodiscard]] std::optional<std::uint64_t> u64() {
        const auto value = take(8U);
        if (!value.has_value()) return std::nullopt;
        std::uint64_t result{};
        for (const std::byte item : *value) {
            result = (result << 8U) | std::to_integer<std::uint8_t>(item);
        }
        return result;
    }
    [[nodiscard]] std::optional<std::string> string(
        const std::size_t maximum, const bool allow_empty = false) {
        const auto length = u16();
        if (!length.has_value() || *length > maximum ||
            (!allow_empty && *length == 0U)) {
            return std::nullopt;
        }
        const auto value = take(*length);
        if (!value.has_value()) return std::nullopt;
        std::string output;
        output.reserve(value->size());
        for (const std::byte item : *value) {
            const auto character = std::to_integer<std::uint8_t>(item);
            if (character < 0x20U || character > 0x7eU) return std::nullopt;
            output.push_back(static_cast<char>(character));
        }
        return output;
    }
    [[nodiscard]] bool magic(const std::array<std::byte, 4U>& expected) {
        std::array<std::byte, 4U> actual{};
        return exact(actual) && actual == expected;
    }
    [[nodiscard]] bool header(const std::array<std::byte, 4U>& expected) {
        if (!magic_at_start(expected)) return false;
        const auto version = [this]() -> std::optional<std::uint8_t> {
            return u8();
        }();
        const auto r1 = u8();
        const auto r2 = u8();
        const auto r3 = u8();
        return version == kVersion && r1 == 0U && r2 == 0U && r3 == 0U;
    }
    [[nodiscard]] bool finished() const noexcept {
        return offset_ == bytes_.size();
    }

private:
    [[nodiscard]] bool magic_at_start(
        const std::array<std::byte, 4U>& expected) {
        if (offset_ != 0U || bytes_.size() < 4U) return false;
        std::array<std::byte, 4U> actual{};
        if (!exact(actual)) return false;
        return actual == expected;
    }
    [[nodiscard]] std::optional<std::span<const std::byte>> take(
        const std::size_t size) {
        if (size > bytes_.size() - offset_) return std::nullopt;
        const auto value = bytes_.subspan(offset_, size);
        offset_ += size;
        return value;
    }

    std::span<const std::byte> bytes_;
    std::size_t offset_{};
};

void write_header(Writer& writer, const std::array<std::byte, 4U>& magic) {
    writer.append(magic);
    writer.u8(kVersion);
    writer.u8(0U);
    writer.u8(0U);
    writer.u8(0U);
}

[[nodiscard]] bool lower_hex_32(const std::string_view value) noexcept {
    bool nonzero_seen{};
    if (value.size() != 32U) return false;
    for (const char item : value) {
        if (!((item >= '0' && item <= '9') ||
              (item >= 'a' && item <= 'f'))) return false;
        nonzero_seen = nonzero_seen || item != '0';
    }
    return nonzero_seen;
}

[[nodiscard]] bool valid_offer(
    const FirstPairingOfferPayloadV1& payload) noexcept {
    const bool method = payload.confirmation_method ==
            FirstPairingConfirmationMethodV1::decimal_sas ||
        payload.confirmation_method == FirstPairingConfirmationMethodV1::qr;
    return payload.required_capabilities ==
            kFirstPairingCapabilityTwoSidedUserConfirmationV1 && method &&
        nonzero(payload.attempt_id) &&
        valid_spki(payload.identity_subject_public_key_info_der) &&
        payload.ephemeral_public_key[0U] == std::byte{0x04U} &&
        nonzero(payload.ephemeral_public_key) && nonzero(payload.nonce) &&
        nonzero(payload.runtime_version_sha256) &&
        payload.expires_at_epoch != 0U;
}

}  // namespace

std::optional<std::vector<std::byte>> encode_first_pairing_offer_payload_v1(
    const ControlBootstrapMessageTypeV1 message_type,
    const FirstPairingOfferPayloadV1& payload) noexcept {
    if (!valid_offer_type(message_type) || !valid_offer(payload)) {
        return std::nullopt;
    }
    try {
        Writer writer{kOfferBytes};
        writer.append(message_type ==
                ControlBootstrapMessageTypeV1::host_first_pair_offer
            ? kHostOfferMagic : kAndroidOfferMagic);
        writer.u8(kVersion);
        writer.u8(static_cast<std::uint8_t>(payload.confirmation_method));
        writer.u16(0U);
        writer.u32(payload.required_capabilities);
        writer.append(payload.attempt_id);
        writer.append(payload.identity_subject_public_key_info_der);
        writer.append(payload.ephemeral_public_key);
        writer.append(payload.nonce);
        writer.append(payload.runtime_version_sha256);
        writer.u64(payload.expires_at_epoch);
        auto result = writer.take();
        if (result.size() != kOfferBytes) return std::nullopt;
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<FirstPairingOfferPayloadV1>
parse_first_pairing_offer_payload_v1(
    const ControlBootstrapMessageTypeV1 message_type,
    const std::span<const std::byte> encoded) noexcept {
    if (!valid_offer_type(message_type) || encoded.size() != kOfferBytes) {
        return std::nullopt;
    }
    try {
        Reader reader{encoded};
        const auto& magic = message_type ==
                ControlBootstrapMessageTypeV1::host_first_pair_offer
            ? kHostOfferMagic : kAndroidOfferMagic;
        if (!reader.magic(magic)) return std::nullopt;
        const auto version = reader.u8();
        const auto method = reader.u8();
        const auto reserved = reader.u16();
        const auto capabilities = reader.u32();
        FirstPairingOfferPayloadV1 result;
        if (version != kVersion || !method.has_value() || reserved != 0U ||
            !capabilities.has_value() || !reader.exact(result.attempt_id) ||
            !reader.exact_uint8(
                result.identity_subject_public_key_info_der, 91U) ||
            !reader.exact(result.ephemeral_public_key) ||
            !reader.exact(result.nonce) ||
            !reader.exact(result.runtime_version_sha256)) {
            return std::nullopt;
        }
        const auto expiry = reader.u64();
        if (!expiry.has_value() || !reader.finished()) return std::nullopt;
        result.required_capabilities = *capabilities;
        result.confirmation_method =
            static_cast<FirstPairingConfirmationMethodV1>(*method);
        result.expires_at_epoch = *expiry;
        if (!valid_offer(result)) return std::nullopt;
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::vector<std::byte>>
encode_first_pairing_confirmation_payload_v1(
    const ControlBootstrapMessageTypeV1 message_type,
    const FirstPairingConfirmationPayloadV1& payload) noexcept {
    if (!valid_confirmation_type(message_type) ||
        payload.fields.role != role_for_type(message_type) ||
        !build_first_pairing_user_confirmation_v1(payload.fields).succeeded() ||
        !valid_signature(payload.signature_der_low_s)) {
        return std::nullopt;
    }
    try {
        Writer writer{66U + payload.signature_der_low_s.size()};
        writer.append(kConfirmationMagic);
        writer.u8(kVersion);
        writer.u8(static_cast<std::uint8_t>(payload.fields.role));
        writer.u8(static_cast<std::uint8_t>(payload.fields.method));
        writer.u8(0U);
        writer.append(payload.fields.attempt_id);
        writer.append(payload.fields.commitment_sha256);
        writer.u64(payload.fields.expires_at_epoch);
        writer.u16(static_cast<std::uint16_t>(
            payload.signature_der_low_s.size()));
        writer.append(payload.signature_der_low_s);
        return writer.take();
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<FirstPairingConfirmationPayloadV1>
parse_first_pairing_confirmation_payload_v1(
    const ControlBootstrapMessageTypeV1 message_type,
    const std::span<const std::byte> encoded) noexcept {
    if (!valid_confirmation_type(message_type) || encoded.size() < 74U ||
        encoded.size() > 138U) return std::nullopt;
    try {
        Reader reader{encoded};
        if (!reader.magic(kConfirmationMagic)) return std::nullopt;
        const auto version = reader.u8();
        const auto role = reader.u8();
        const auto method = reader.u8();
        const auto reserved = reader.u8();
        FirstPairingConfirmationPayloadV1 result;
        if (version != kVersion || !role.has_value() || !method.has_value() ||
            reserved != 0U || !reader.exact(result.fields.attempt_id) ||
            !reader.exact(result.fields.commitment_sha256)) {
            return std::nullopt;
        }
        const auto expiry = reader.u64();
        const auto signature_size = reader.u16();
        if (!expiry.has_value() || !signature_size.has_value() ||
            !reader.exact_uint8(result.signature_der_low_s, *signature_size) ||
            !reader.finished()) return std::nullopt;
        result.fields.role =
            static_cast<FirstPairingConfirmationRoleV1>(*role);
        result.fields.method =
            static_cast<FirstPairingConfirmationMethodV1>(*method);
        result.fields.expires_at_epoch = *expiry;
        if (result.fields.role != role_for_type(message_type) ||
            !build_first_pairing_user_confirmation_v1(result.fields).succeeded() ||
            !valid_signature(result.signature_der_low_s)) {
            return std::nullopt;
        }
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::vector<std::byte>>
encode_first_pairing_activation_proof_request_v1(
    const ActivationConfirmationProof& proof) noexcept {
    if (!build_activation_confirmation_payload(proof).has_value()) {
        return std::nullopt;
    }
    try {
        Writer writer{kMaximumActivationProofWireBytes};
        write_header(writer, kActivationRequestMagic);
        writer.string(proof.activation_mode);
        writer.string(proof.android_client_version);
        writer.string(proof.android_device_code);
        writer.string(proof.android_device_profile_sha256);
        writer.string(proof.android_key_sha256);
        writer.string(proof.challenge_id);
        writer.string(proof.challenge_token_sha256);
        writer.string(proof.host_client_version);
        writer.string(proof.host_device_code);
        writer.string(proof.host_key_sha256);
        writer.string(proof.pair_id);
        writer.u32(proof.protocol_version);
        writer.string(proof.request_id);
        writer.string(proof.target_entitlement_id);
        auto result = writer.take();
        if (result.size() > kMaximumActivationProofWireBytes) {
            return std::nullopt;
        }
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<ActivationConfirmationProof>
parse_first_pairing_activation_proof_request_v1(
    const std::span<const std::byte> encoded) noexcept {
    if (encoded.size() < 8U ||
        encoded.size() > kMaximumActivationProofWireBytes) {
        return std::nullopt;
    }
    try {
        Reader reader{encoded};
        if (!reader.header(kActivationRequestMagic)) return std::nullopt;
        ActivationConfirmationProof proof;
        auto activation_mode = reader.string(16U);
        auto android_client_version = reader.string(80U);
        auto android_device_code = reader.string(128U);
        auto android_profile = reader.string(64U);
        auto android_key = reader.string(64U);
        auto challenge_id = reader.string(32U);
        auto challenge_token_hash = reader.string(64U);
        auto host_client_version = reader.string(80U);
        auto host_device_code = reader.string(128U);
        auto host_key = reader.string(64U);
        auto pair_id = reader.string(32U);
        auto protocol_version = reader.u32();
        auto request_id = reader.string(32U);
        auto target = reader.string(32U, true);
        if (!activation_mode || !android_client_version ||
            !android_device_code || !android_profile || !android_key ||
            !challenge_id || !challenge_token_hash || !host_client_version ||
            !host_device_code || !host_key || !pair_id || !protocol_version ||
            !request_id || !target || !reader.finished()) {
            return std::nullopt;
        }
        proof.activation_mode = std::move(*activation_mode);
        proof.android_client_version = std::move(*android_client_version);
        proof.android_device_code = std::move(*android_device_code);
        proof.android_device_profile_sha256 = std::move(*android_profile);
        proof.android_key_sha256 = std::move(*android_key);
        proof.challenge_id = std::move(*challenge_id);
        proof.challenge_token_sha256 = std::move(*challenge_token_hash);
        proof.host_client_version = std::move(*host_client_version);
        proof.host_device_code = std::move(*host_device_code);
        proof.host_key_sha256 = std::move(*host_key);
        proof.pair_id = std::move(*pair_id);
        proof.protocol_version = *protocol_version;
        proof.request_id = std::move(*request_id);
        proof.target_entitlement_id = std::move(*target);
        if (!build_activation_confirmation_payload(proof).has_value()) {
            return std::nullopt;
        }
        return proof;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::vector<std::byte>>
encode_first_pairing_activation_signature_payload_v1(
    const FirstPairingActivationSignaturePayloadV1& payload) noexcept {
    if (!nonzero(payload.canonical_payload_sha256) ||
        !valid_signature(payload.signature_der_low_s)) return std::nullopt;
    try {
        Writer writer{42U + payload.signature_der_low_s.size()};
        write_header(writer, kActivationSignatureMagic);
        writer.append(payload.canonical_payload_sha256);
        writer.u16(static_cast<std::uint16_t>(
            payload.signature_der_low_s.size()));
        writer.append(payload.signature_der_low_s);
        return writer.take();
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<FirstPairingActivationSignaturePayloadV1>
parse_first_pairing_activation_signature_payload_v1(
    const std::span<const std::byte> encoded) noexcept {
    if (encoded.size() < 50U || encoded.size() > 114U) return std::nullopt;
    try {
        Reader reader{encoded};
        FirstPairingActivationSignaturePayloadV1 result;
        if (!reader.header(kActivationSignatureMagic) ||
            !reader.exact(result.canonical_payload_sha256)) {
            return std::nullopt;
        }
        const auto size = reader.u16();
        if (!size || !reader.exact_uint8(result.signature_der_low_s, *size) ||
            !reader.finished() ||
            !nonzero(result.canonical_payload_sha256) ||
            !valid_signature(result.signature_der_low_s)) {
            return std::nullopt;
        }
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::vector<std::byte>>
encode_first_pairing_activation_result_payload_v1(
    const FirstPairingActivationResultPayloadV1& payload) noexcept {
    if (!lower_hex_32(payload.entitlement_id) ||
        !lower_hex_32(payload.pair_id) || !lower_hex_32(payload.binding_id) ||
        payload.binding_revision == 0U) return std::nullopt;
    try {
        Writer writer{120U};
        write_header(writer, kActivationResultMagic);
        writer.append(std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t*>(payload.entitlement_id.data()),
            payload.entitlement_id.size()});
        writer.append(std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t*>(payload.pair_id.data()),
            payload.pair_id.size()});
        writer.append(std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t*>(payload.binding_id.data()),
            payload.binding_id.size()});
        writer.u64(payload.binding_revision);
        writer.u64(payload.revocation_version);
        auto result = writer.take();
        if (result.size() != 120U) return std::nullopt;
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<FirstPairingActivationResultPayloadV1>
parse_first_pairing_activation_result_payload_v1(
    const std::span<const std::byte> encoded) noexcept {
    if (encoded.size() != 120U) return std::nullopt;
    try {
        Reader reader{encoded};
        if (!reader.header(kActivationResultMagic)) return std::nullopt;
        const auto read_hex = [&reader]() -> std::optional<std::string> {
            std::vector<std::uint8_t> raw;
            if (!reader.exact_uint8(raw, 32U)) return std::nullopt;
            return std::string(raw.begin(), raw.end());
        };
        FirstPairingActivationResultPayloadV1 result;
        auto entitlement = read_hex();
        auto pair = read_hex();
        auto binding = read_hex();
        auto revision = reader.u64();
        auto revocation = reader.u64();
        if (!entitlement || !pair || !binding || !revision || !revocation ||
            !reader.finished()) return std::nullopt;
        result.entitlement_id = std::move(*entitlement);
        result.pair_id = std::move(*pair);
        result.binding_id = std::move(*binding);
        result.binding_revision = *revision;
        result.revocation_version = *revocation;
        if (!lower_hex_32(result.entitlement_id) ||
            !lower_hex_32(result.pair_id) ||
            !lower_hex_32(result.binding_id) ||
            result.binding_revision == 0U) return std::nullopt;
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::vector<std::byte>>
encode_first_pairing_complete_payload_v1(
    const PeerHandshakeSha256& commitment_sha256) noexcept {
    if (!nonzero(commitment_sha256)) return std::nullopt;
    try {
        Writer writer{40U};
        write_header(writer, kCompleteMagic);
        writer.append(commitment_sha256);
        return writer.take();
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<PeerHandshakeSha256> parse_first_pairing_complete_payload_v1(
    const std::span<const std::byte> encoded) noexcept {
    if (encoded.size() != 40U) return std::nullopt;
    Reader reader{encoded};
    PeerHandshakeSha256 result{};
    if (!reader.header(kCompleteMagic) || !reader.exact(result) ||
        !reader.finished() || !nonzero(result)) return std::nullopt;
    return result;
}

}  // namespace vfdual
