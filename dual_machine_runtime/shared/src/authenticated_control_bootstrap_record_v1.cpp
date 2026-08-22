#include "vfdual/authenticated_control_bootstrap_record_v1.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace vfdual {
namespace {

constexpr std::array<std::byte, 4U> kMagic{
    std::byte{0x56U}, std::byte{0x46U},
    std::byte{0x42U}, std::byte{0x31U}};
constexpr std::size_t kVersionOffset = 4U;
constexpr std::size_t kHeaderSizeOffset = 5U;
constexpr std::size_t kDirectionOffset = 6U;
constexpr std::size_t kMessageTypeOffset = 7U;
constexpr std::size_t kPayloadLengthOffset = 8U;

[[nodiscard]] bool valid_direction(
    const ControlBootstrapDirectionV1 direction) noexcept {
    return direction == ControlBootstrapDirectionV1::host_to_android ||
        direction == ControlBootstrapDirectionV1::android_to_host;
}

[[nodiscard]] bool valid_message_type(
    const ControlBootstrapMessageTypeV1 message_type) noexcept {
    const auto encoded = static_cast<std::uint8_t>(message_type);
    return encoded >=
            static_cast<std::uint8_t>(
                ControlBootstrapMessageTypeV1::host_hello) &&
        encoded <=
            static_cast<std::uint8_t>(
                ControlBootstrapMessageTypeV1::abort);
}

void write_u32_be(
    const std::span<std::byte, 4U> output,
    const std::uint32_t value) noexcept {
    output[0U] = std::byte{static_cast<std::uint8_t>(value >> 24U)};
    output[1U] = std::byte{static_cast<std::uint8_t>(value >> 16U)};
    output[2U] = std::byte{static_cast<std::uint8_t>(value >> 8U)};
    output[3U] = std::byte{static_cast<std::uint8_t>(value)};
}

[[nodiscard]] std::uint32_t read_u32_be(
    const std::span<const std::byte, 4U> input) noexcept {
    return (static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(input[0U])) << 24U) |
        (static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(input[1U])) << 16U) |
        (static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(input[2U])) << 8U) |
        static_cast<std::uint32_t>(
            std::to_integer<std::uint8_t>(input[3U]));
}

}  // namespace

bool control_bootstrap_message_allowed_v1(
    const ControlBootstrapDirectionV1 direction,
    const ControlBootstrapMessageTypeV1 message_type) noexcept {
    if (!valid_direction(direction) || !valid_message_type(message_type)) {
        return false;
    }
    if (message_type == ControlBootstrapMessageTypeV1::abort) return true;
    switch (direction) {
        case ControlBootstrapDirectionV1::host_to_android:
            return message_type ==
                    ControlBootstrapMessageTypeV1::host_hello ||
                message_type ==
                    ControlBootstrapMessageTypeV1::host_challenge_proof ||
                message_type ==
                    ControlBootstrapMessageTypeV1::host_final_proof ||
                message_type ==
                    ControlBootstrapMessageTypeV1::host_handshake_signature ||
                message_type ==
                    ControlBootstrapMessageTypeV1::host_finished;
        case ControlBootstrapDirectionV1::android_to_host:
            return message_type ==
                    ControlBootstrapMessageTypeV1::
                        android_challenge_request ||
                message_type ==
                    ControlBootstrapMessageTypeV1::server_challenge ||
                message_type ==
                    ControlBootstrapMessageTypeV1::
                        pair_generation_credential ||
                message_type ==
                    ControlBootstrapMessageTypeV1::
                        android_handshake_confirmation;
        case ControlBootstrapDirectionV1::invalid:
            return false;
    }
    return false;
}

ControlBootstrapEncodeResultV1
encode_authenticated_control_bootstrap_record_v1(
    const ControlBootstrapDirectionV1 direction,
    const ControlBootstrapMessageTypeV1 message_type,
    const std::span<const std::byte> payload) noexcept {
    ControlBootstrapEncodeResultV1 result{};
    if (!valid_direction(direction)) return result;
    if (!valid_message_type(message_type)) {
        result.status =
            ControlBootstrapEncodeStatusV1::invalid_message_type;
        return result;
    }
    if (!control_bootstrap_message_allowed_v1(direction, message_type)) {
        result.status = ControlBootstrapEncodeStatusV1::direction_mismatch;
        return result;
    }
    if (payload.empty()) {
        result.status = ControlBootstrapEncodeStatusV1::payload_empty;
        return result;
    }
    if (payload.size() >
            kMaximumAuthenticatedControlBootstrapPayloadBytes ||
        payload.size() > std::numeric_limits<std::uint32_t>::max()) {
        result.status = ControlBootstrapEncodeStatusV1::payload_too_large;
        return result;
    }
    try {
        result.record.resize(
            kAuthenticatedControlBootstrapHeaderBytes + payload.size());
    } catch (...) {
        result.status = ControlBootstrapEncodeStatusV1::allocation_failed;
        return result;
    }
    std::copy(kMagic.begin(), kMagic.end(), result.record.begin());
    result.record[kVersionOffset] =
        std::byte{kAuthenticatedControlBootstrapVersion};
    result.record[kHeaderSizeOffset] = std::byte{
        static_cast<std::uint8_t>(
            kAuthenticatedControlBootstrapHeaderBytes)};
    result.record[kDirectionOffset] =
        std::byte{static_cast<std::uint8_t>(direction)};
    result.record[kMessageTypeOffset] =
        std::byte{static_cast<std::uint8_t>(message_type)};
    write_u32_be(
        std::span<std::byte, 4U>{
            result.record.data() + kPayloadLengthOffset, 4U},
        static_cast<std::uint32_t>(payload.size()));
    std::copy(
        payload.begin(), payload.end(),
        result.record.begin() + static_cast<std::ptrdiff_t>(
            kAuthenticatedControlBootstrapHeaderBytes));
    result.status = ControlBootstrapEncodeStatusV1::encoded;
    return result;
}

ControlBootstrapParseResultV1
parse_authenticated_control_bootstrap_record_v1(
    const std::span<const std::byte> encoded,
    const ControlBootstrapDirectionV1 expected_direction) noexcept {
    ControlBootstrapParseResultV1 result{};
    if (encoded.size() < kAuthenticatedControlBootstrapHeaderBytes) {
        return result;
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), encoded.begin())) {
        result.status = ControlBootstrapParseStatusV1::invalid_magic;
        return result;
    }
    if (std::to_integer<std::uint8_t>(encoded[kVersionOffset]) !=
            kAuthenticatedControlBootstrapVersion) {
        result.status = ControlBootstrapParseStatusV1::unsupported_version;
        return result;
    }
    if (std::to_integer<std::uint8_t>(encoded[kHeaderSizeOffset]) !=
            kAuthenticatedControlBootstrapHeaderBytes) {
        result.status = ControlBootstrapParseStatusV1::invalid_header_size;
        return result;
    }
    const auto direction = static_cast<ControlBootstrapDirectionV1>(
        std::to_integer<std::uint8_t>(encoded[kDirectionOffset]));
    if (!valid_direction(direction)) {
        result.status = ControlBootstrapParseStatusV1::invalid_direction;
        return result;
    }
    if (!valid_direction(expected_direction) ||
        direction != expected_direction) {
        result.status = ControlBootstrapParseStatusV1::unexpected_direction;
        return result;
    }
    const auto message_type = static_cast<ControlBootstrapMessageTypeV1>(
        std::to_integer<std::uint8_t>(encoded[kMessageTypeOffset]));
    if (!valid_message_type(message_type)) {
        result.status = ControlBootstrapParseStatusV1::invalid_message_type;
        return result;
    }
    if (!control_bootstrap_message_allowed_v1(direction, message_type)) {
        result.status = ControlBootstrapParseStatusV1::direction_mismatch;
        return result;
    }
    const std::uint32_t payload_size = read_u32_be(
        std::span<const std::byte, 4U>{
            encoded.data() + kPayloadLengthOffset, 4U});
    if (payload_size == 0U) {
        result.status = ControlBootstrapParseStatusV1::payload_empty;
        return result;
    }
    if (payload_size >
            kMaximumAuthenticatedControlBootstrapPayloadBytes) {
        result.status = ControlBootstrapParseStatusV1::payload_too_large;
        return result;
    }
    if (encoded.size() !=
            kAuthenticatedControlBootstrapHeaderBytes + payload_size) {
        result.status = ControlBootstrapParseStatusV1::length_mismatch;
        return result;
    }
    result.status = ControlBootstrapParseStatusV1::parsed;
    result.record = ParsedControlBootstrapRecordV1{
        .direction = direction,
        .message_type = message_type,
        .payload = encoded.subspan(
            kAuthenticatedControlBootstrapHeaderBytes, payload_size),
    };
    return result;
}

}  // namespace vfdual
