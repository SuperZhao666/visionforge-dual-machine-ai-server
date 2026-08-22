#pragma once

#include "vfdual/authenticated_control_bootstrap_record_v1.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace vfdual {

inline constexpr std::size_t kControlBootstrapPayloadTlvHeaderBytesV1 = 5U;
inline constexpr std::size_t kControlBootstrapPayloadMaximumFieldsV1 = 12U;
inline constexpr std::size_t
    kControlBootstrapPayloadMaximumCredentialBytesV1 = 8'192U;

enum class HostHelloFieldTagV1 : std::uint8_t {
    host_identity_spki_der = 0U,
    host_ephemeral_public_key = 1U,
    host_nonce = 2U,
    transport_kind = 3U,
    host_ipv4 = 4U,
    android_ipv4 = 5U,
    video_port = 6U,
    control_port = 7U,
    host_runtime_version = 8U,
};

enum class AndroidChallengeRequestFieldTagV1 : std::uint8_t {
    request_id = 0U,
    allocation_request_id = 1U,
    entitlement_id = 2U,
    pair_id = 3U,
    binding_id = 4U,
    binding_revision = 5U,
    revocation_version = 6U,
    android_identity_spki_der = 7U,
    android_ephemeral_public_key = 8U,
    android_nonce = 9U,
    android_runtime_version = 10U,
    android_challenge_signature_der = 11U,
};

enum class ServerChallengeFieldTagV1 : std::uint8_t {
    challenge_id = 0U,
    expires_at_epoch = 1U,
    server_nonce = 2U,
};

enum class AndroidHandshakeConfirmationFieldTagV1 : std::uint8_t {
    transcript_signature_der = 0U,
    android_finished = 1U,
};

/** Caller-owned field bytes. Tags must be exactly 0..N-1 in canonical order. */
struct ControlBootstrapPayloadFieldV1 final {
    std::uint8_t tag{};
    std::span<const std::byte> value;
};

enum class ControlBootstrapPayloadStatusV1 : std::uint8_t {
    encoded = 1U,
    parsed = 2U,
    invalid_message_type,
    invalid_field_count,
    payload_empty,
    payload_too_large,
    truncated_tlv,
    unexpected_field_tag,
    invalid_field_length,
    invalid_field_value,
    trailing_data,
    allocation_failed,
};

struct ControlBootstrapPayloadEncodeResultV1 final {
    ControlBootstrapPayloadStatusV1 status{
        ControlBootstrapPayloadStatusV1::invalid_message_type};
    std::uint8_t field_tag{0xffU};
    std::vector<std::byte> payload;
};

/**
 * Schema-aware canonical payload encoder for all ten VFB1 message types.
 *
 * This validates only the wire representation. The coordinator must still
 * rebuild the existing pair-generation/transcript objects and perform every
 * identity signature, server credential and Finished verification.
 */
[[nodiscard]] ControlBootstrapPayloadEncodeResultV1
encode_control_bootstrap_payload_v1(
    ControlBootstrapMessageTypeV1 message_type,
    std::span<const ControlBootstrapPayloadFieldV1> fields) noexcept;

/** Non-owning parsed view; every field span aliases the supplied payload. */
struct ParsedControlBootstrapPayloadV1 final {
    ControlBootstrapMessageTypeV1 message_type{
        ControlBootstrapMessageTypeV1::invalid};
    std::array<std::span<const std::byte>,
        kControlBootstrapPayloadMaximumFieldsV1> fields{};
    std::size_t field_count{};

    [[nodiscard]] std::span<const std::byte> field(
        std::uint8_t tag) const noexcept;
};

struct ControlBootstrapPayloadParseResultV1 final {
    ControlBootstrapPayloadStatusV1 status{
        ControlBootstrapPayloadStatusV1::invalid_message_type};
    std::uint8_t field_tag{0xffU};
    ParsedControlBootstrapPayloadV1 payload;
};

[[nodiscard]] ControlBootstrapPayloadParseResultV1
parse_control_bootstrap_payload_v1(
    ControlBootstrapMessageTypeV1 message_type,
    std::span<const std::byte> encoded) noexcept;

[[nodiscard]] std::uint16_t read_control_bootstrap_u16_be_v1(
    std::span<const std::byte> value) noexcept;

[[nodiscard]] std::uint64_t read_control_bootstrap_u64_be_v1(
    std::span<const std::byte> value) noexcept;

}  // namespace vfdual
