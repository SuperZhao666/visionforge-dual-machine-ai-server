#include "vfdual/usage_authorization_contract.hpp"

#include <array>
#include <charconv>
#include <limits>
#include <string>

namespace vfdual {
namespace {

constexpr std::size_t kHex128Characters = 32U;
constexpr std::size_t kSha256Characters = 64U;
constexpr std::size_t kMaximumDeviceCodeCharacters = 128U;
constexpr std::size_t kMaximumClientVersionCharacters = 80U;
constexpr std::string_view kInitialActivationMode{"activate"};
constexpr std::string_view kReactivationMode{"reactivate"};
constexpr std::string_view kDeviceBindingActivationMode{"bind_device"};

[[nodiscard]] bool is_nonzero_lower_hex(
    const std::string_view value, const std::size_t expected) noexcept {
    if (value.size() != expected) return false;
    bool nonzero = false;
    for (const char character : value) {
        if (!((character >= '0' && character <= '9') ||
                (character >= 'a' && character <= 'f'))) {
            return false;
        }
        nonzero = nonzero || character != '0';
    }
    return nonzero;
}

[[nodiscard]] bool is_activation_target_valid(
    const std::string_view activation_mode,
    const std::string_view target_entitlement_id) noexcept {
    if (activation_mode == kInitialActivationMode) {
        return target_entitlement_id.empty();
    }
    return (activation_mode == kReactivationMode ||
               activation_mode == kDeviceBindingActivationMode) &&
        is_nonzero_lower_hex(target_entitlement_id, kHex128Characters);
}

[[nodiscard]] bool is_device_code(const std::string_view value) noexcept {
    if (value.empty() || value.size() > kMaximumDeviceCodeCharacters) {
        return false;
    }
    for (const char character : value) {
        if (!((character >= 'A' && character <= 'Z') ||
                (character >= '0' && character <= '9') ||
                character == '.' || character == '_' || character == ':' ||
                character == '-')) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool is_client_version(const std::string_view value) noexcept {
    if (value.empty() || value.size() > kMaximumClientVersionCharacters) {
        return false;
    }
    bool digit_seen = false;
    for (const char character : value) {
        if (character >= '0' && character <= '9') {
            digit_seen = true;
            continue;
        }
        if (character != '.' && character != '-' && character != '+' &&
            character != '_' && !(character >= 'A' && character <= 'Z') &&
            !(character >= 'a' && character <= 'z')) {
            return false;
        }
    }
    return digit_seen;
}

[[nodiscard]] bool common_usage_fields_valid(
    const std::string_view entitlement_id,
    const std::string_view pair_id,
    const std::uint32_t protocol_version,
    const std::uint64_t revocation_version) noexcept {
    return is_nonzero_lower_hex(entitlement_id, kHex128Characters) &&
        is_nonzero_lower_hex(pair_id, kHex128Characters) &&
        protocol_version == kUsageAuthorizationProtocolVersion &&
        revocation_version > 0U;
}

[[nodiscard]] std::string quoted(const std::string_view value) {
    std::string result;
    result.reserve(value.size() + 2U);
    result.push_back('"');
    for (const unsigned char character : value) {
        switch (character) {
            case '"':
                result += "\\\"";
                break;
            case '\\':
                result += "\\\\";
                break;
            case '\b':
                result += "\\b";
                break;
            case '\f':
                result += "\\f";
                break;
            case '\n':
                result += "\\n";
                break;
            case '\r':
                result += "\\r";
                break;
            case '\t':
                result += "\\t";
                break;
            default:
                if (character < 0x20U) {
                    constexpr std::array<char, 16> kHex{
                        '0', '1', '2', '3', '4', '5', '6', '7',
                        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
                    result += "\\u00";
                    result.push_back(kHex[(character >> 4U) & 0x0fU]);
                    result.push_back(kHex[character & 0x0fU]);
                } else {
                    result.push_back(static_cast<char>(character));
                }
                break;
        }
    }
    result.push_back('"');
    return result;
}

void append_string_field(
    std::string& destination,
    const std::string_view key,
    const std::string_view value,
    const bool first = false) {
    if (!first) destination.push_back(',');
    destination += quoted(key);
    destination.push_back(':');
    destination += quoted(value);
}

void append_unsigned_field(
    std::string& destination,
    const std::string_view key,
    const std::uint64_t value,
    const bool first = false) {
    if (!first) destination.push_back(',');
    destination += quoted(key);
    destination.push_back(':');
    std::array<char, std::numeric_limits<std::uint64_t>::digits10 + 2U> text{};
    const auto encoded =
        std::to_chars(text.data(), text.data() + text.size(), value);
    destination.append(text.data(), encoded.ptr);
}

void append_boolean_field(
    std::string& destination,
    const std::string_view key,
    const bool value,
    const bool first = false) {
    if (!first) destination.push_back(',');
    destination += quoted(key);
    destination.push_back(':');
    destination += value ? "true" : "false";
}

}  // namespace

std::optional<std::string> build_activation_confirmation_payload(
    const ActivationConfirmationProof& proof) {
    if (!is_activation_target_valid(
            proof.activation_mode, proof.target_entitlement_id) ||
        !is_client_version(proof.android_client_version) ||
        !is_device_code(proof.android_device_code) ||
        !is_nonzero_lower_hex(
            proof.android_device_profile_sha256, kSha256Characters) ||
        !is_nonzero_lower_hex(
            proof.android_key_sha256, kSha256Characters) ||
        !is_nonzero_lower_hex(proof.challenge_id, kHex128Characters) ||
        !is_nonzero_lower_hex(
            proof.challenge_token_sha256, kSha256Characters) ||
        !is_client_version(proof.host_client_version) ||
        !is_device_code(proof.host_device_code) ||
        !is_nonzero_lower_hex(proof.host_key_sha256, kSha256Characters) ||
        !is_nonzero_lower_hex(proof.pair_id, kHex128Characters) ||
        proof.protocol_version != kUsageAuthorizationProtocolVersion ||
        !is_nonzero_lower_hex(proof.request_id, kHex128Characters)) {
        return std::nullopt;
    }
    std::string payload{"{"};
    append_string_field(
        payload, "activation_mode", proof.activation_mode, true);
    append_string_field(
        payload, "android_client_version", proof.android_client_version);
    append_string_field(
        payload, "android_device_code", proof.android_device_code);
    append_string_field(
        payload, "android_device_profile_sha256",
        proof.android_device_profile_sha256);
    append_string_field(
        payload, "android_key_sha256", proof.android_key_sha256);
    append_string_field(payload, "challenge_id", proof.challenge_id);
    append_string_field(
        payload, "challenge_token_sha256", proof.challenge_token_sha256);
    append_string_field(payload, "domain", kActivationConfirmDomain);
    append_string_field(
        payload, "host_client_version", proof.host_client_version);
    append_string_field(payload, "host_device_code", proof.host_device_code);
    append_string_field(payload, "host_key_sha256", proof.host_key_sha256);
    append_string_field(payload, "pair_id", proof.pair_id);
    append_unsigned_field(
        payload, "protocol_version", proof.protocol_version);
    append_string_field(payload, "request_id", proof.request_id);
    append_string_field(
        payload, "target_entitlement_id", proof.target_entitlement_id);
    payload.push_back('}');
    return payload;
}

std::optional<std::string> build_usage_start_challenge_payload(
    const UsageStartChallengeProof& proof) {
    if (!common_usage_fields_valid(
            proof.entitlement_id, proof.pair_id, proof.protocol_version,
            proof.revocation_version) ||
        !is_nonzero_lower_hex(
            proof.channel_binding_sha256, kSha256Characters) ||
        !is_nonzero_lower_hex(proof.request_id, kHex128Characters) ||
        !is_nonzero_lower_hex(proof.request_nonce, kHex128Characters)) {
        return std::nullopt;
    }
    std::string payload{"{"};
    append_string_field(
        payload, "channel_binding_sha256",
        proof.channel_binding_sha256, true);
    append_string_field(payload, "domain", kUsageStartChallengeDomain);
    append_string_field(payload, "entitlement_id", proof.entitlement_id);
    append_string_field(payload, "pair_id", proof.pair_id);
    append_unsigned_field(
        payload, "protocol_version", proof.protocol_version);
    append_string_field(payload, "request_id", proof.request_id);
    append_string_field(payload, "request_nonce", proof.request_nonce);
    append_unsigned_field(
        payload, "revocation_version", proof.revocation_version);
    payload.push_back('}');
    return payload;
}

std::optional<std::string> build_usage_start_payload(
    const UsageStartProof& proof) {
    if (!common_usage_fields_valid(
        proof.entitlement_id, proof.pair_id, proof.protocol_version,
            proof.revocation_version) ||
        !proof.android_runtime_ready || !proof.host_runtime_ready ||
        !is_nonzero_lower_hex(
            proof.channel_binding_sha256, kSha256Characters) ||
        !is_nonzero_lower_hex(proof.request_id, kHex128Characters) ||
        !is_nonzero_lower_hex(proof.request_nonce, kHex128Characters) ||
        !is_nonzero_lower_hex(
            proof.start_challenge_id, kHex128Characters) ||
        !is_nonzero_lower_hex(
            proof.start_challenge_token_sha256, kSha256Characters)) {
        return std::nullopt;
    }
    std::string payload{"{"};
    append_unsigned_field(
        payload, "android_frames_total", proof.android_frames_total, true);
    append_boolean_field(
        payload, "android_runtime_ready", proof.android_runtime_ready);
    append_string_field(
        payload, "channel_binding_sha256", proof.channel_binding_sha256);
    append_string_field(payload, "domain", kUsageStartDomain);
    append_string_field(payload, "entitlement_id", proof.entitlement_id);
    append_unsigned_field(
        payload, "host_frames_total", proof.host_frames_total);
    append_boolean_field(
        payload, "host_runtime_ready", proof.host_runtime_ready);
    append_string_field(payload, "pair_id", proof.pair_id);
    append_unsigned_field(
        payload, "protocol_version", proof.protocol_version);
    append_string_field(payload, "request_id", proof.request_id);
    append_string_field(payload, "request_nonce", proof.request_nonce);
    append_unsigned_field(
        payload, "revocation_version", proof.revocation_version);
    append_string_field(
        payload, "start_challenge_id", proof.start_challenge_id);
    append_string_field(
        payload, "start_challenge_token_sha256",
        proof.start_challenge_token_sha256);
    payload.push_back('}');
    return payload;
}

std::optional<std::string> build_usage_heartbeat_payload(
    const UsageHeartbeatProof& proof) {
    if (!common_usage_fields_valid(
            proof.entitlement_id, proof.pair_id, proof.protocol_version,
            proof.revocation_version) ||
        proof.sequence == 0U ||
        !is_nonzero_lower_hex(
            proof.channel_binding_sha256, kSha256Characters) ||
        !is_nonzero_lower_hex(
            proof.previous_lease_sha256, kSha256Characters) ||
        !is_nonzero_lower_hex(proof.request_id, kHex128Characters) ||
        !is_nonzero_lower_hex(proof.request_nonce, kHex128Characters) ||
        !is_nonzero_lower_hex(proof.session_id, kHex128Characters)) {
        return std::nullopt;
    }
    std::string payload{"{"};
    append_unsigned_field(
        payload, "android_frames_total", proof.android_frames_total, true);
    append_string_field(
        payload, "channel_binding_sha256", proof.channel_binding_sha256);
    append_string_field(payload, "domain", kUsageHeartbeatDomain);
    append_string_field(payload, "entitlement_id", proof.entitlement_id);
    append_unsigned_field(
        payload, "host_frames_total", proof.host_frames_total);
    append_string_field(payload, "pair_id", proof.pair_id);
    append_string_field(
        payload, "previous_lease_sha256", proof.previous_lease_sha256);
    append_unsigned_field(
        payload, "protocol_version", proof.protocol_version);
    append_string_field(payload, "request_id", proof.request_id);
    append_string_field(payload, "request_nonce", proof.request_nonce);
    append_unsigned_field(
        payload, "revocation_version", proof.revocation_version);
    append_unsigned_field(payload, "sequence", proof.sequence);
    append_string_field(payload, "session_id", proof.session_id);
    payload.push_back('}');
    return payload;
}

std::optional<std::string> build_usage_stop_payload(
    const UsageStopProof& proof) {
    if (!common_usage_fields_valid(
            proof.entitlement_id, proof.pair_id, proof.protocol_version,
            proof.revocation_version) ||
        !is_nonzero_lower_hex(
            proof.channel_binding_sha256, kSha256Characters) ||
        !is_nonzero_lower_hex(
            proof.previous_lease_sha256, kSha256Characters) ||
        !is_nonzero_lower_hex(proof.request_id, kHex128Characters) ||
        !is_nonzero_lower_hex(proof.request_nonce, kHex128Characters) ||
        !is_nonzero_lower_hex(proof.session_id, kHex128Characters)) {
        return std::nullopt;
    }
    std::string payload{"{"};
    append_string_field(
        payload, "channel_binding_sha256",
        proof.channel_binding_sha256, true);
    append_string_field(payload, "domain", kUsageStopDomain);
    append_string_field(payload, "entitlement_id", proof.entitlement_id);
    append_string_field(payload, "pair_id", proof.pair_id);
    append_string_field(
        payload, "previous_lease_sha256", proof.previous_lease_sha256);
    append_unsigned_field(
        payload, "protocol_version", proof.protocol_version);
    append_string_field(payload, "request_id", proof.request_id);
    append_string_field(payload, "request_nonce", proof.request_nonce);
    append_unsigned_field(
        payload, "revocation_version", proof.revocation_version);
    append_string_field(payload, "session_id", proof.session_id);
    payload.push_back('}');
    return payload;
}

std::optional<std::string> build_entitlement_status_payload(
    const EntitlementStatusProof& proof) {
    if (!common_usage_fields_valid(
            proof.entitlement_id, proof.pair_id, proof.protocol_version,
            proof.revocation_version) ||
        !is_nonzero_lower_hex(proof.request_nonce, kHex128Characters)) {
        return std::nullopt;
    }
    std::string payload{"{"};
    append_string_field(payload, "domain", kEntitlementStatusDomain, true);
    append_string_field(payload, "entitlement_id", proof.entitlement_id);
    append_string_field(payload, "pair_id", proof.pair_id);
    append_unsigned_field(
        payload, "protocol_version", proof.protocol_version);
    append_string_field(payload, "request_nonce", proof.request_nonce);
    append_unsigned_field(
        payload, "revocation_version", proof.revocation_version);
    payload.push_back('}');
    return payload;
}

}  // namespace vfdual
