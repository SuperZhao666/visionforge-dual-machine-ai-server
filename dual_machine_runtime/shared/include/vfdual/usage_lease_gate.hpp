#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace vfdual {

inline constexpr std::uint32_t kUsageLeaseProtocolVersion = 2U;
inline constexpr std::uint64_t kMaximumUsageLeaseTtlSeconds = 10U;
inline constexpr std::uint64_t kUsageLeaseServerAheadGraceSeconds = 2U;
inline constexpr std::string_view kUsageLeaseType{
    "vf-dual-machine-usage-lease-v1"};
inline constexpr std::string_view kUsageLeaseIssuer{
    "visionforge-dual-machine-service"};
inline constexpr std::string_view kUsageLeaseAudience{
    "visionforge-dual-machine-data-plane"};
inline constexpr std::string_view kUsageLeaseActivePhase{"active"};

struct UsageLeaseBinding final {
    std::string entitlement_id;
    std::string pair_id;
    std::string session_id;
    std::uint32_t protocol_version{kUsageLeaseProtocolVersion};
    std::uint64_t revocation_version{};
    std::string host_key_sha256;
    std::string android_key_sha256;
    std::string channel_binding_sha256;
};

/**
 * Typed claims produced only after the compact token has passed strict parsing
 * and RS256 verification. This gate still revalidates every authorization
 * binding and time/sequence invariant before opening the data plane.
 */
struct VerifiedUsageLeaseClaims final {
    std::string type;
    std::string issuer;
    std::string audience;
    std::string entitlement_id;
    std::string pair_id;
    std::string session_id;
    std::uint32_t protocol_version{};
    std::uint64_t revocation_version{};
    std::string host_key_sha256;
    std::string android_key_sha256;
    std::string channel_binding_sha256;
    std::string previous_ticket_sha256;
    std::uint64_t sequence{};
    std::string phase;
    std::string authorization_kind;
    bool is_permanent{};
    std::uint64_t remaining_seconds{};
    std::string lease_id;
    std::uint64_t issued_at_epoch{};
    std::uint64_t not_before_epoch{};
    std::uint64_t expires_at_epoch{};

    bool operator==(const VerifiedUsageLeaseClaims&) const = default;
};

struct VerifiedUsageLease final {
    VerifiedUsageLeaseClaims claims;
    // SHA-256 of the exact verified compact token, used by the next pth claim.
    std::string ticket_sha256;

    bool operator==(const VerifiedUsageLease&) const = default;
};

enum class UsageLeaseAdmission {
    accepted_current,
    staged_future,
    accepted_idempotent,
    rejected_gate_closed,
    rejected_claims,
    rejected_binding,
    rejected_time,
    rejected_sequence,
    rejected_previous_ticket,
    rejected_overlap,
    rejected_gap,
    rejected_future_capacity,
};

enum class UsageLeaseGateState {
    invalid_binding,
    empty,
    active,
    stopped,
    revoked,
    expired,
    trusted_time_rollback,
};

struct UsageLeaseGateSnapshot final {
    UsageLeaseGateState state{UsageLeaseGateState::empty};
    bool permits_data_plane{};
    bool future_ticket_staged{};
    std::string current_ticket_sha256;
    std::string future_ticket_sha256;
    std::uint64_t sequence{};
    std::uint64_t not_before_epoch{};
    std::uint64_t expires_at_epoch{};
};

/**
 * Thread-safe, fail-closed semantic gate for already verified usage leases.
 *
 * The caller owns trusted epoch acquisition. This class never reads a system
 * clock. After the first non-zero trusted epoch, a lower epoch (including
 * zero) permanently closes the current session as a rollback. A new gate
 * instance is required for a new usage session.
 */
class UsageLeaseGate final {
public:
    explicit UsageLeaseGate(UsageLeaseBinding binding);

    UsageLeaseGate(const UsageLeaseGate&) = delete;
    UsageLeaseGate& operator=(const UsageLeaseGate&) = delete;

    [[nodiscard]] UsageLeaseAdmission submit_verified_ticket(
        const VerifiedUsageLease& ticket,
        std::uint64_t trusted_now_epoch);
    [[nodiscard]] UsageLeaseGateSnapshot evaluate(
        std::uint64_t trusted_now_epoch);

    void stop();
    void revoke();

private:
    struct StoredLease final {
        VerifiedUsageLeaseClaims claims;
        std::string ticket_sha256;
    };

    [[nodiscard]] UsageLeaseGateSnapshot evaluate_locked(
        std::uint64_t trusted_now_epoch);
    void expire_locked();
    void close_locked(UsageLeaseGateState state);

    UsageLeaseBinding binding_;
    UsageLeaseGateState state_{UsageLeaseGateState::invalid_binding};
    std::optional<StoredLease> current_;
    std::optional<StoredLease> future_;
    std::uint64_t last_trusted_now_epoch_{};
    std::mutex mutex_;
};

}  // namespace vfdual
