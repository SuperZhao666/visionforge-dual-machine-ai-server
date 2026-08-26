#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
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
    host_first_pair_offer = 11U,
    android_first_pair_offer = 12U,
    android_first_pair_confirmation = 13U,
    host_first_pair_confirmation = 14U,
    activation_proof_request = 15U,
    host_activation_signature = 16U,
    activation_result = 17U,
    first_pair_complete = 18U,
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

/**
 * Incremental bounded decoder for the unauthenticated VFB1 TCP envelope.
 *
 * TCP does not preserve application write boundaries. A caller may therefore
 * feed one byte, an arbitrary fragment, or several coalesced records. This
 * owner consumes at most one complete record at a time and reports the exact
 * number of source bytes consumed, so the caller can retain and feed any
 * remainder after taking the ready record. Header rejection is terminal for
 * the current TCP connection; malformed input can never trigger an allocation
 * larger than the frozen VFB1 maximum.
 */
enum class ControlBootstrapStreamStatusV1 : std::uint8_t {
    need_more = 1U,
    record_ready = 2U,
    output_pending = 3U,
    rejected = 4U,
    allocation_failed = 5U,
};

struct ControlBootstrapStreamFeedResultV1 final {
    ControlBootstrapStreamStatusV1 status{
        ControlBootstrapStreamStatusV1::rejected};
    std::size_t consumed{};
    ControlBootstrapParseStatusV1 rejection{
        ControlBootstrapParseStatusV1::record_too_short};
};

class ControlBootstrapStreamDecoderV1 final {
public:
    explicit ControlBootstrapStreamDecoderV1(
        ControlBootstrapDirectionV1 expected_direction) noexcept;
    ~ControlBootstrapStreamDecoderV1();

    ControlBootstrapStreamDecoderV1(
        const ControlBootstrapStreamDecoderV1&) = delete;
    ControlBootstrapStreamDecoderV1& operator=(
        const ControlBootstrapStreamDecoderV1&) = delete;

    [[nodiscard]] ControlBootstrapStreamFeedResultV1 feed(
        std::span<const std::byte> source) noexcept;
    /** Returns one complete encoded record and resets for the next record. */
    [[nodiscard]] std::optional<std::vector<std::byte>> take_record() noexcept;
    [[nodiscard]] bool failed() const noexcept;
    [[nodiscard]] bool record_ready() const noexcept;

private:
    void reject(ControlBootstrapParseStatusV1 status) noexcept;
    void reset_for_next_record() noexcept;

    ControlBootstrapDirectionV1 expected_direction_{
        ControlBootstrapDirectionV1::invalid};
    std::vector<std::byte> encoded_;
    std::size_t expected_record_bytes_{};
    bool failed_{};
    bool ready_{};
    ControlBootstrapParseStatusV1 rejection_{
        ControlBootstrapParseStatusV1::record_too_short};
};

enum class ControlBootstrapRoleV1 : std::uint8_t {
    invalid = 0U,
    host = 1U,
    android = 2U,
};

enum class ControlBootstrapFlowV1 : std::uint8_t {
    invalid = 0U,
    outbound = 1U,
    inbound = 2U,
};

enum class ControlBootstrapSequencePhaseV1 : std::uint8_t {
    in_progress = 1U,
    completed = 2U,
    aborted = 3U,
    failed = 4U,
};

enum class ControlBootstrapAdvanceStatusV1 : std::uint8_t {
    advanced = 1U,
    completed = 2U,
    aborted = 3U,
    unexpected_message = 4U,
    wrong_flow = 5U,
    already_terminal = 6U,
};

struct ControlBootstrapExpectedEventV1 final {
    bool present{};
    ControlBootstrapFlowV1 flow{ControlBootstrapFlowV1::invalid};
    ControlBootstrapMessageTypeV1 message_type{
        ControlBootstrapMessageTypeV1::invalid};
};

/**
 * Fail-closed owner for the exact nine-record pre-VFC1 exchange.
 *
 * Any skipped, repeated or wrong-flow non-abort record permanently fails this
 * instance. Abort is accepted in either direction before completion and also
 * becomes terminal. A new TCP connection must create a fresh owner; a failed
 * owner cannot be reset or reused.
 */
class ControlBootstrapSequenceV1 final {
public:
    explicit ControlBootstrapSequenceV1(
        ControlBootstrapRoleV1 local_role) noexcept;

    [[nodiscard]] ControlBootstrapAdvanceStatusV1 advance_outbound(
        ControlBootstrapMessageTypeV1 message_type) noexcept;
    [[nodiscard]] ControlBootstrapAdvanceStatusV1 advance_inbound(
        ControlBootstrapMessageTypeV1 message_type) noexcept;
    [[nodiscard]] ControlBootstrapExpectedEventV1 expected_next() const noexcept;
    [[nodiscard]] ControlBootstrapSequencePhaseV1 phase() const noexcept;
    [[nodiscard]] std::size_t accepted_event_count() const noexcept;

private:
    [[nodiscard]] ControlBootstrapAdvanceStatusV1 advance(
        ControlBootstrapFlowV1 flow,
        ControlBootstrapMessageTypeV1 message_type) noexcept;

    ControlBootstrapRoleV1 local_role_{ControlBootstrapRoleV1::invalid};
    ControlBootstrapSequencePhaseV1 phase_{
        ControlBootstrapSequencePhaseV1::failed};
    std::size_t next_event_index_{};
};

}  // namespace vfdual
