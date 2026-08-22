#include "vfdual/authenticated_control_bootstrap_payload_v1.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <new>

namespace vfdual {
namespace {

enum class FieldSemantic : std::uint8_t {
    opaque,
    lower_hex_identifier,
    positive_u64,
    canonical_p256_spki,
    sec1_p256_public_key,
    nonzero_bytes,
    transport_kind,
    nonzero_port,
    stable_semver,
    ecdsa_der,
    compact_jwt,
    positive_u16,
};

struct FieldRule final {
    std::size_t minimum;
    std::size_t maximum;
    FieldSemantic semantic;
};

struct MessageSchema final {
    const FieldRule* rules{};
    std::size_t field_count{};
};

constexpr FieldRule exact(
    const std::size_t bytes,
    const FieldSemantic semantic = FieldSemantic::opaque) noexcept {
    return {bytes, bytes, semantic};
}

constexpr FieldRule bounded(
    const std::size_t minimum,
    const std::size_t maximum,
    const FieldSemantic semantic = FieldSemantic::opaque) noexcept {
    return {minimum, maximum, semantic};
}

constexpr std::array kHostHelloRules{
    exact(91U, FieldSemantic::canonical_p256_spki),
    exact(65U, FieldSemantic::sec1_p256_public_key),
    exact(32U, FieldSemantic::nonzero_bytes),
    exact(1U, FieldSemantic::transport_kind),
    exact(4U),
    exact(4U),
    exact(2U, FieldSemantic::nonzero_port),
    exact(2U, FieldSemantic::nonzero_port),
    bounded(1U, 32U, FieldSemantic::stable_semver),
};

constexpr std::array kAndroidChallengeRequestRules{
    exact(32U, FieldSemantic::lower_hex_identifier),
    exact(32U, FieldSemantic::lower_hex_identifier),
    exact(32U, FieldSemantic::lower_hex_identifier),
    exact(32U, FieldSemantic::lower_hex_identifier),
    exact(32U, FieldSemantic::lower_hex_identifier),
    exact(8U, FieldSemantic::positive_u64),
    exact(8U, FieldSemantic::positive_u64),
    exact(91U, FieldSemantic::canonical_p256_spki),
    exact(65U, FieldSemantic::sec1_p256_public_key),
    exact(32U, FieldSemantic::nonzero_bytes),
    bounded(1U, 32U, FieldSemantic::stable_semver),
    bounded(8U, 72U, FieldSemantic::ecdsa_der),
};

constexpr std::array kSignatureRules{
    bounded(8U, 72U, FieldSemantic::ecdsa_der),
};

constexpr std::array kServerChallengeRules{
    exact(32U, FieldSemantic::lower_hex_identifier),
    exact(8U, FieldSemantic::positive_u64),
    exact(32U, FieldSemantic::nonzero_bytes),
};

constexpr std::array kCredentialRules{
    bounded(
        1U,
        kControlBootstrapPayloadMaximumCredentialBytesV1,
        FieldSemantic::compact_jwt),
};

constexpr std::array kAndroidHandshakeConfirmationRules{
    bounded(8U, 72U, FieldSemantic::ecdsa_der),
    exact(32U, FieldSemantic::nonzero_bytes),
};

constexpr std::array kHostFinishedRules{
    exact(32U, FieldSemantic::nonzero_bytes),
};

constexpr std::array kAbortRules{
    exact(2U, FieldSemantic::positive_u16),
};

constexpr std::array<std::byte, 27U> kP256SpkiPrefix{
    std::byte{0x30U}, std::byte{0x59U}, std::byte{0x30U}, std::byte{0x13U},
    std::byte{0x06U}, std::byte{0x07U}, std::byte{0x2aU}, std::byte{0x86U},
    std::byte{0x48U}, std::byte{0xceU}, std::byte{0x3dU}, std::byte{0x02U},
    std::byte{0x01U}, std::byte{0x06U}, std::byte{0x08U}, std::byte{0x2aU},
    std::byte{0x86U}, std::byte{0x48U}, std::byte{0xceU}, std::byte{0x3dU},
    std::byte{0x03U}, std::byte{0x01U}, std::byte{0x07U}, std::byte{0x03U},
    std::byte{0x42U}, std::byte{0x00U}, std::byte{0x04U},
};

[[nodiscard]] MessageSchema schema_for(
    const ControlBootstrapMessageTypeV1 message_type) noexcept {
    switch (message_type) {
        case ControlBootstrapMessageTypeV1::host_hello:
            return {kHostHelloRules.data(), kHostHelloRules.size()};
        case ControlBootstrapMessageTypeV1::android_challenge_request:
            return {
                kAndroidChallengeRequestRules.data(),
                kAndroidChallengeRequestRules.size()};
        case ControlBootstrapMessageTypeV1::host_challenge_proof:
        case ControlBootstrapMessageTypeV1::host_final_proof:
        case ControlBootstrapMessageTypeV1::host_handshake_signature:
            return {kSignatureRules.data(), kSignatureRules.size()};
        case ControlBootstrapMessageTypeV1::server_challenge:
            return {
                kServerChallengeRules.data(),
                kServerChallengeRules.size()};
        case ControlBootstrapMessageTypeV1::pair_generation_credential:
            return {kCredentialRules.data(), kCredentialRules.size()};
        case ControlBootstrapMessageTypeV1::android_handshake_confirmation:
            return {
                kAndroidHandshakeConfirmationRules.data(),
                kAndroidHandshakeConfirmationRules.size()};
        case ControlBootstrapMessageTypeV1::host_finished:
            return {kHostFinishedRules.data(), kHostFinishedRules.size()};
        case ControlBootstrapMessageTypeV1::abort:
            return {kAbortRules.data(), kAbortRules.size()};
        case ControlBootstrapMessageTypeV1::invalid:
            break;
    }
    return {};
}

[[nodiscard]] bool contains_nonzero(
    const std::span<const std::byte> value) noexcept {
    return std::any_of(value.begin(), value.end(), [](const std::byte current) {
        return current != std::byte{0U};
    });
}

[[nodiscard]] bool lower_hex_identifier_valid(
    const std::span<const std::byte> value) noexcept {
    return value.size() == 32U && contains_nonzero(value) &&
        std::all_of(value.begin(), value.end(), [](const std::byte current) {
            const auto character = std::to_integer<std::uint8_t>(current);
            return (character >= static_cast<std::uint8_t>('0') &&
                    character <= static_cast<std::uint8_t>('9')) ||
                (character >= static_cast<std::uint8_t>('a') &&
                 character <= static_cast<std::uint8_t>('f'));
        });
}

[[nodiscard]] bool stable_semver_valid(
    const std::span<const std::byte> value) noexcept {
    if (value.empty() || value.size() > 32U) return false;
    std::size_t component_start{};
    std::size_t components{};
    for (std::size_t index{}; index <= value.size(); ++index) {
        if (index != value.size() && value[index] != std::byte{'.'}) {
            const auto character = std::to_integer<std::uint8_t>(value[index]);
            if (character < static_cast<std::uint8_t>('0') ||
                character > static_cast<std::uint8_t>('9')) {
                return false;
            }
            continue;
        }
        const std::size_t component_size = index - component_start;
        if (component_size == 0U ||
            (component_size > 1U &&
             value[component_start] == std::byte{'0'})) {
            return false;
        }
        ++components;
        component_start = index + 1U;
    }
    return components == 3U;
}

[[nodiscard]] bool canonical_der_integer_valid(
    const std::span<const std::byte> value) noexcept {
    if (value.empty() || value.size() > 33U) return false;
    const auto first = std::to_integer<std::uint8_t>(value.front());
    if ((first & 0x80U) != 0U) return false;
    if (value.size() > 1U && first == 0U &&
        (std::to_integer<std::uint8_t>(value[1U]) & 0x80U) == 0U) {
        return false;
    }
    return contains_nonzero(value);
}

[[nodiscard]] bool canonical_ecdsa_der_valid(
    const std::span<const std::byte> value) noexcept {
    if (value.size() < 8U || value.size() > 72U ||
        value[0U] != std::byte{0x30U} ||
        std::to_integer<std::uint8_t>(value[1U]) != value.size() - 2U) {
        return false;
    }
    std::size_t offset = 2U;
    if (value[offset++] != std::byte{0x02U}) return false;
    const std::size_t r_size =
        std::to_integer<std::uint8_t>(value[offset++]);
    if (r_size == 0U || offset + r_size + 2U > value.size()) return false;
    if (!canonical_der_integer_valid(value.subspan(offset, r_size))) {
        return false;
    }
    offset += r_size;
    if (value[offset++] != std::byte{0x02U}) return false;
    const std::size_t s_size =
        std::to_integer<std::uint8_t>(value[offset++]);
    if (s_size == 0U || offset + s_size != value.size()) return false;
    return canonical_der_integer_valid(value.subspan(offset, s_size));
}

[[nodiscard]] bool compact_jwt_valid(
    const std::span<const std::byte> value) noexcept {
    if (value.empty() ||
        value.size() > kControlBootstrapPayloadMaximumCredentialBytesV1) {
        return false;
    }
    std::size_t dots{};
    std::size_t segment_size{};
    for (const std::byte current : value) {
        const auto character = std::to_integer<std::uint8_t>(current);
        if (character == static_cast<std::uint8_t>('.')) {
            if (segment_size == 0U || dots == 2U) return false;
            ++dots;
            segment_size = 0U;
            continue;
        }
        const bool base64url =
            (character >= static_cast<std::uint8_t>('A') &&
             character <= static_cast<std::uint8_t>('Z')) ||
            (character >= static_cast<std::uint8_t>('a') &&
             character <= static_cast<std::uint8_t>('z')) ||
            (character >= static_cast<std::uint8_t>('0') &&
             character <= static_cast<std::uint8_t>('9')) ||
            character == static_cast<std::uint8_t>('-') ||
            character == static_cast<std::uint8_t>('_');
        if (!base64url) return false;
        ++segment_size;
    }
    return dots == 2U && segment_size != 0U;
}

[[nodiscard]] bool field_value_valid(
    const FieldRule& rule,
    const std::span<const std::byte> value) noexcept {
    if (value.size() < rule.minimum || value.size() > rule.maximum) {
        return false;
    }
    switch (rule.semantic) {
        case FieldSemantic::opaque:
            return true;
        case FieldSemantic::lower_hex_identifier:
            return lower_hex_identifier_valid(value);
        case FieldSemantic::positive_u64:
            return read_control_bootstrap_u64_be_v1(value) != 0U &&
                (std::to_integer<std::uint8_t>(value.front()) & 0x80U) == 0U;
        case FieldSemantic::canonical_p256_spki:
            return value.size() == 91U &&
                std::equal(
                    kP256SpkiPrefix.begin(),
                    kP256SpkiPrefix.end(),
                    value.begin()) &&
                contains_nonzero(value.subspan(kP256SpkiPrefix.size()));
        case FieldSemantic::sec1_p256_public_key:
            return value.size() == 65U && value.front() == std::byte{0x04U} &&
                contains_nonzero(value.subspan(1U));
        case FieldSemantic::nonzero_bytes:
            return contains_nonzero(value);
        case FieldSemantic::transport_kind:
            return value.size() == 1U &&
                (value.front() == std::byte{1U} ||
                 value.front() == std::byte{2U});
        case FieldSemantic::nonzero_port:
            return read_control_bootstrap_u16_be_v1(value) != 0U;
        case FieldSemantic::stable_semver:
            return stable_semver_valid(value);
        case FieldSemantic::ecdsa_der:
            return canonical_ecdsa_der_valid(value);
        case FieldSemantic::compact_jwt:
            return compact_jwt_valid(value);
        case FieldSemantic::positive_u16:
            return read_control_bootstrap_u16_be_v1(value) != 0U;
    }
    return false;
}

[[nodiscard]] bool cross_field_values_valid(
    const ControlBootstrapMessageTypeV1 message_type,
    const std::span<const ControlBootstrapPayloadFieldV1> fields) noexcept {
    if (message_type != ControlBootstrapMessageTypeV1::host_hello) return true;
    return read_control_bootstrap_u16_be_v1(fields[6U].value) !=
        read_control_bootstrap_u16_be_v1(fields[7U].value);
}

void append_u32_be(
    std::vector<std::byte>& output,
    const std::uint32_t value) {
    output.push_back(std::byte{static_cast<std::uint8_t>(value >> 24U)});
    output.push_back(std::byte{static_cast<std::uint8_t>(value >> 16U)});
    output.push_back(std::byte{static_cast<std::uint8_t>(value >> 8U)});
    output.push_back(std::byte{static_cast<std::uint8_t>(value)});
}

[[nodiscard]] std::uint32_t read_u32_be(
    const std::span<const std::byte, 4U> value) noexcept {
    return (static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(value[0U])) << 24U) |
        (static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(value[1U])) << 16U) |
        (static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(value[2U])) << 8U) |
        static_cast<std::uint32_t>(
            std::to_integer<std::uint8_t>(value[3U]));
}

[[nodiscard]] ControlBootstrapPayloadEncodeResultV1 encode_failure(
    const ControlBootstrapPayloadStatusV1 status,
    const std::uint8_t field_tag = 0xffU) noexcept {
    ControlBootstrapPayloadEncodeResultV1 result{};
    result.status = status;
    result.field_tag = field_tag;
    return result;
}

[[nodiscard]] ControlBootstrapPayloadParseResultV1 parse_failure(
    const ControlBootstrapPayloadStatusV1 status,
    const std::uint8_t field_tag = 0xffU) noexcept {
    ControlBootstrapPayloadParseResultV1 result{};
    result.status = status;
    result.field_tag = field_tag;
    return result;
}

}  // namespace

ControlBootstrapPayloadEncodeResultV1 encode_control_bootstrap_payload_v1(
    const ControlBootstrapMessageTypeV1 message_type,
    const std::span<const ControlBootstrapPayloadFieldV1> fields) noexcept {
    const MessageSchema schema = schema_for(message_type);
    if (schema.rules == nullptr) {
        return encode_failure(
            ControlBootstrapPayloadStatusV1::invalid_message_type);
    }
    if (fields.size() != schema.field_count) {
        return encode_failure(
            ControlBootstrapPayloadStatusV1::invalid_field_count);
    }
    std::size_t encoded_size{};
    for (std::size_t index{}; index < fields.size(); ++index) {
        const auto expected_tag = static_cast<std::uint8_t>(index);
        if (fields[index].tag != expected_tag) {
            return encode_failure(
                ControlBootstrapPayloadStatusV1::unexpected_field_tag,
                fields[index].tag);
        }
        const FieldRule& rule = schema.rules[index];
        if (fields[index].value.size() < rule.minimum ||
            fields[index].value.size() > rule.maximum) {
            return encode_failure(
                ControlBootstrapPayloadStatusV1::invalid_field_length,
                expected_tag);
        }
        if (!field_value_valid(rule, fields[index].value)) {
            return encode_failure(
                ControlBootstrapPayloadStatusV1::invalid_field_value,
                expected_tag);
        }
        const std::size_t field_bytes =
            kControlBootstrapPayloadTlvHeaderBytesV1 +
            fields[index].value.size();
        if (encoded_size >
            kMaximumAuthenticatedControlBootstrapPayloadBytes - field_bytes) {
            return encode_failure(
                ControlBootstrapPayloadStatusV1::payload_too_large);
        }
        encoded_size += field_bytes;
    }
    if (!cross_field_values_valid(message_type, fields)) {
        return encode_failure(
            ControlBootstrapPayloadStatusV1::invalid_field_value,
            7U);
    }
    try {
        std::vector<std::byte> encoded;
        encoded.reserve(encoded_size);
        for (const auto& field : fields) {
            encoded.push_back(std::byte{field.tag});
            append_u32_be(
                encoded,
                static_cast<std::uint32_t>(field.value.size()));
            encoded.insert(
                encoded.end(), field.value.begin(), field.value.end());
        }
        ControlBootstrapPayloadEncodeResultV1 result{};
        result.status = ControlBootstrapPayloadStatusV1::encoded;
        result.payload = std::move(encoded);
        return result;
    } catch (const std::bad_alloc&) {
        return encode_failure(
            ControlBootstrapPayloadStatusV1::allocation_failed);
    } catch (...) {
        return encode_failure(
            ControlBootstrapPayloadStatusV1::allocation_failed);
    }
}

std::span<const std::byte> ParsedControlBootstrapPayloadV1::field(
    const std::uint8_t tag) const noexcept {
    if (tag >= field_count) return {};
    return fields[tag];
}

ControlBootstrapPayloadParseResultV1 parse_control_bootstrap_payload_v1(
    const ControlBootstrapMessageTypeV1 message_type,
    const std::span<const std::byte> encoded) noexcept {
    const MessageSchema schema = schema_for(message_type);
    if (schema.rules == nullptr) {
        return parse_failure(
            ControlBootstrapPayloadStatusV1::invalid_message_type);
    }
    if (encoded.empty()) {
        return parse_failure(ControlBootstrapPayloadStatusV1::payload_empty);
    }
    if (encoded.size() > kMaximumAuthenticatedControlBootstrapPayloadBytes) {
        return parse_failure(
            ControlBootstrapPayloadStatusV1::payload_too_large);
    }
    ParsedControlBootstrapPayloadV1 parsed{};
    parsed.message_type = message_type;
    parsed.field_count = schema.field_count;
    std::array<ControlBootstrapPayloadFieldV1,
        kControlBootstrapPayloadMaximumFieldsV1> validation_fields{};
    std::size_t offset{};
    for (std::size_t index{}; index < schema.field_count; ++index) {
        const auto expected_tag = static_cast<std::uint8_t>(index);
        if (encoded.size() - offset <
            kControlBootstrapPayloadTlvHeaderBytesV1) {
            return parse_failure(
                ControlBootstrapPayloadStatusV1::truncated_tlv,
                expected_tag);
        }
        const auto actual_tag =
            std::to_integer<std::uint8_t>(encoded[offset]);
        if (actual_tag != expected_tag) {
            return parse_failure(
                ControlBootstrapPayloadStatusV1::unexpected_field_tag,
                actual_tag);
        }
        const auto length_bytes =
            encoded.subspan(offset + 1U, 4U);
        const std::size_t field_size = read_u32_be(
            std::span<const std::byte, 4U>{
                length_bytes.data(), length_bytes.size()});
        const FieldRule& rule = schema.rules[index];
        if (field_size < rule.minimum || field_size > rule.maximum) {
            return parse_failure(
                ControlBootstrapPayloadStatusV1::invalid_field_length,
                expected_tag);
        }
        offset += kControlBootstrapPayloadTlvHeaderBytesV1;
        if (field_size > encoded.size() - offset) {
            return parse_failure(
                ControlBootstrapPayloadStatusV1::truncated_tlv,
                expected_tag);
        }
        const auto value = encoded.subspan(offset, field_size);
        if (!field_value_valid(rule, value)) {
            return parse_failure(
                ControlBootstrapPayloadStatusV1::invalid_field_value,
                expected_tag);
        }
        parsed.fields[index] = value;
        validation_fields[index] = {expected_tag, value};
        offset += field_size;
    }
    if (offset != encoded.size()) {
        return parse_failure(ControlBootstrapPayloadStatusV1::trailing_data);
    }
    if (!cross_field_values_valid(
            message_type,
            std::span<const ControlBootstrapPayloadFieldV1>{
                validation_fields.data(), schema.field_count})) {
        return parse_failure(
            ControlBootstrapPayloadStatusV1::invalid_field_value,
            7U);
    }
    ControlBootstrapPayloadParseResultV1 result{};
    result.status = ControlBootstrapPayloadStatusV1::parsed;
    result.payload = parsed;
    return result;
}

std::uint16_t read_control_bootstrap_u16_be_v1(
    const std::span<const std::byte> value) noexcept {
    if (value.size() != 2U) return 0U;
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(
             std::to_integer<std::uint8_t>(value[0U])) << 8U) |
        static_cast<std::uint16_t>(
            std::to_integer<std::uint8_t>(value[1U])));
}

std::uint64_t read_control_bootstrap_u64_be_v1(
    const std::span<const std::byte> value) noexcept {
    if (value.size() != 8U) return 0U;
    std::uint64_t result{};
    for (const std::byte current : value) {
        result = (result << 8U) |
            std::to_integer<std::uint8_t>(current);
    }
    return result;
}

}  // namespace vfdual
