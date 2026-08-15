#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace vfdual {

inline constexpr std::uint32_t kUsageAuthorizationProtocolVersion = 2U;
inline constexpr std::string_view kActivationConfirmDomain{
    "visionforge-dual-machine-card-activate-v1"};
inline constexpr std::string_view kUsageStartChallengeDomain{
    "visionforge-dual-machine-usage-start-challenge-v1"};
inline constexpr std::string_view kUsageStartDomain{
    "visionforge-dual-machine-usage-start-v1"};
inline constexpr std::string_view kUsageHeartbeatDomain{
    "visionforge-dual-machine-usage-heartbeat-v1"};
inline constexpr std::string_view kUsageStopDomain{
    "visionforge-dual-machine-usage-stop-v1"};
inline constexpr std::string_view kEntitlementStatusDomain{
    "visionforge-dual-machine-entitlement-status-v1"};

/**
 * Inputs are already-normalized server contract fields. Token digests are
 * computed by the platform boundary from the exact raw token before entering
 * these pure builders.
 */
struct ActivationConfirmationProof final {
    std::string activation_mode;
    std::string android_client_version;
    std::string android_device_code;
    std::string android_device_profile_sha256;
    std::string android_key_sha256;
    std::string challenge_id;
    std::string challenge_token_sha256;
    std::string host_client_version;
    std::string host_device_code;
    std::string host_key_sha256;
    std::string pair_id;
    std::uint32_t protocol_version{kUsageAuthorizationProtocolVersion};
    std::string request_id;
    std::string target_entitlement_id;
};

struct UsageStartChallengeProof final {
    std::string channel_binding_sha256;
    std::string entitlement_id;
    std::string pair_id;
    std::uint32_t protocol_version{kUsageAuthorizationProtocolVersion};
    std::string request_id;
    std::string request_nonce;
    std::uint64_t revocation_version{};
};

struct UsageStartProof final {
    std::uint64_t android_frames_total{};
    bool android_runtime_ready{};
    std::string channel_binding_sha256;
    std::string entitlement_id;
    std::uint64_t host_frames_total{};
    bool host_runtime_ready{};
    std::string pair_id;
    std::uint32_t protocol_version{kUsageAuthorizationProtocolVersion};
    std::string request_id;
    std::string request_nonce;
    std::uint64_t revocation_version{};
    std::string start_challenge_id;
    std::string start_challenge_token_sha256;
};

struct UsageHeartbeatProof final {
    std::uint64_t android_frames_total{};
    std::string channel_binding_sha256;
    std::string entitlement_id;
    std::uint64_t host_frames_total{};
    std::string pair_id;
    std::string previous_lease_sha256;
    std::uint32_t protocol_version{kUsageAuthorizationProtocolVersion};
    std::string request_id;
    std::string request_nonce;
    std::uint64_t revocation_version{};
    std::uint64_t sequence{};
    std::string session_id;
};

struct UsageStopProof final {
    std::string channel_binding_sha256;
    std::string entitlement_id;
    std::string pair_id;
    std::string previous_lease_sha256;
    std::uint32_t protocol_version{kUsageAuthorizationProtocolVersion};
    std::string request_id;
    std::string request_nonce;
    std::uint64_t revocation_version{};
    std::string session_id;
};

struct EntitlementStatusProof final {
    std::string entitlement_id;
    std::string pair_id;
    std::uint32_t protocol_version{kUsageAuthorizationProtocolVersion};
    std::string request_nonce;
    std::uint64_t revocation_version{};
};

/**
 * Returns the exact UTF-8 bytes signed by both P-256 identities, or nullopt
 * when a field is outside the public sidecar contract. Keys are emitted in
 * lexicographic order with no whitespace, matching Python canonical_json().
 */
[[nodiscard]] std::optional<std::string>
build_activation_confirmation_payload(
    const ActivationConfirmationProof& proof);
[[nodiscard]] std::optional<std::string>
build_usage_start_challenge_payload(
    const UsageStartChallengeProof& proof);
[[nodiscard]] std::optional<std::string> build_usage_start_payload(
    const UsageStartProof& proof);
[[nodiscard]] std::optional<std::string> build_usage_heartbeat_payload(
    const UsageHeartbeatProof& proof);
[[nodiscard]] std::optional<std::string> build_usage_stop_payload(
    const UsageStopProof& proof);
[[nodiscard]] std::optional<std::string> build_entitlement_status_payload(
    const EntitlementStatusProof& proof);

}  // namespace vfdual
