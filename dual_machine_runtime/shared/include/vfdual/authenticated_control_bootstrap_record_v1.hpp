#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace vfdual {

inline constexpr std::uint8_t kAuthenticatedControlBootstrapVersion = 1U;
inline constexpr std::size_t kAuthenticatedControlBootstrapHeaderBytes = 12U;
inline constexpr std::size_t kMaximumAuthenticatedControlBootstrapPayloadBytes =
    65'536U;

enum class ControlBootstrapDirectionV1 : std::uint8_t {
    invalid = 0U,
    host_to_android = 1U,
    android_to_host = 2U,
};

/** Ordered messages used before VFC1 traffic keys become available. */
enum class ControlBootstrapMessageTypeV1 : std::uint8_t {
    invalid = 0U,
    host_hello = 1U,
    android_challenge_request = 2U,
    host_challenge_proof = 3U,
    server_challenge = 4U,
    host_final_proof = 5U,
    pair_generation_credential = 6U,
    host_handshake_signature = 7U,
    android_handshake_confirmation = 8U,
    host_finished = 9U,
    abort = 10U,
};

/**
 * This framing is deliberately unauthenticated. It provides only strict TCP
 * record boundaries, direction separation and bounded allocation before both
 * identity signatures and Finished proofs establish VFC1 keys. Payload codecs
 * must rebuild and validate their own typed cryptographic objects; callers must
 * never treat a successfully parsed bootstrap record as peer authentication.
 */
[[nodiscard]] bool control_bootstrap_message_allowed_v1(
    ControlBootstrapDirectionV1 direction,
    ControlBootstrapMessageTypeV1 message_type) noexcept;

enum class ControlBootstrapEncodeStatusV1 : std::uint8_t {
    encoded,
    invalid_direction,
    invalid_message_type,
    direction_mismatch,
    payload_empty,
    payload_too_large,
    allocation_failed,
};

struct ControlBootstrapEncodeResultV1 final {
    ControlBootstrapEncodeStatusV1 status{
        ControlBootstrapEncodeStatusV1::invalid_direction};
    std::vector<std::byte> record;
};

[[nodiscard]] ControlBootstrapEncodeResultV1
encode_authenticated_control_bootstrap_record_v1(
    ControlBootstrapDirectionV1 direction,
    ControlBootstrapMessageTypeV1 message_type,
    std::span<const std::byte> payload) noexcept;

enum class ControlBootstrapParseStatusV1 : std::uint8_t {
    parsed,
    record_too_short,
    invalid_magic,
    unsupported_version,
    invalid_header_size,
    invalid_direction,
    unexpected_direction,
    invalid_message_type,
    direction_mismatch,
    payload_empty,
    payload_too_large,
    length_mismatch,
};

struct ParsedControlBootstrapRecordV1 final {
    ControlBootstrapDirectionV1 direction{
        ControlBootstrapDirectionV1::invalid};
    ControlBootstrapMessageTypeV1 message_type{
        ControlBootstrapMessageTypeV1::invalid};
    std::span<const std::byte> payload;
};

struct ControlBootstrapParseResultV1 final {
    ControlBootstrapParseStatusV1 status{
        ControlBootstrapParseStatusV1::record_too_short};
    ParsedControlBootstrapRecordV1 record;
};

[[nodiscard]] ControlBootstrapParseResultV1
parse_authenticated_control_bootstrap_record_v1(
    std::span<const std::byte> encoded,
    ControlBootstrapDirectionV1 expected_direction) noexcept;

}  // namespace vfdual
