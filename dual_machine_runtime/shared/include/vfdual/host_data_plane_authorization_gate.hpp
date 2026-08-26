#pragma once

#include "vfdual/usage_lease_gate.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>

namespace vfdual {

/**
 * Host-side fail-closed composition of an authenticated peer binding and an
 * already signature-verified usage lease.
 *
 * <p>The class intentionally accepts only {@link VerifiedUsageLease}; raw JWT
 * text and signature verification belong to the platform trust boundary. A
 * caller cannot open the data plane with a boolean flag. It must first install
 * the exact Host/Android/channel binding produced by a confirmed peer
 * handshake and then submit a server-verified lease that matches it.</p>
 *
 * <p>Trusted server epoch is anchored to a monotonic clock when the first
 * current lease is accepted. Subsequent permit checks never consult the local
 * wall clock, and a monotonic-clock rollback permanently revokes the gate.</p>
 */
class HostDataPlaneAuthorizationGate final {
public:
    // Millisecond precision avoids false rollback when two independently
    // truncated second counters cross their boundaries at different times.
    using MonotonicMillisecondsSource = std::function<std::uint64_t()>;

    struct Snapshot final {
        bool peer_confirmed{};
        bool trusted_time_anchored{};
        bool monotonic_clock_rollback{};
        bool permits_data_plane{};
        UsageLeaseGateState lease_state{UsageLeaseGateState::invalid_binding};
        std::uint64_t trusted_now_epoch{};
        std::uint64_t sequence{};
        std::uint64_t expires_at_epoch{};
    };

    HostDataPlaneAuthorizationGate();
    explicit HostDataPlaneAuthorizationGate(
        MonotonicMillisecondsSource monotonic_milliseconds);

    HostDataPlaneAuthorizationGate(const HostDataPlaneAuthorizationGate&) = delete;
    HostDataPlaneAuthorizationGate& operator=(
        const HostDataPlaneAuthorizationGate&) = delete;

    /**
     * Replaces every previous session and installs the exact binding from a
     * mutually authenticated peer handshake. Invalid bindings leave the gate
     * closed and return false.
     */
    [[nodiscard]] bool install_confirmed_peer_binding(UsageLeaseBinding binding);

    /**
     * Installs or renews a lease only after the caller has verified its RS256
     * signature and supplied a trusted server epoch.
     */
    [[nodiscard]] UsageLeaseAdmission submit_verified_ticket(
        const VerifiedUsageLease& ticket,
        std::uint64_t trusted_now_epoch);

    /** Returns true only while the peer binding and current lease remain valid. */
    [[nodiscard]] bool permits_data_plane() noexcept;
    [[nodiscard]] Snapshot snapshot() noexcept;

    /** Stops the current session without accepting any later ticket. */
    void stop() noexcept;
    /** Permanently revokes the current session. */
    void revoke() noexcept;
    /** Clears all peer and lease state for an explicit new handshake. */
    void reset() noexcept;

private:
    struct TrustedTimeAnchor final {
        std::uint64_t trusted_epoch{};
        std::uint64_t monotonic_milliseconds{};
    };

    [[nodiscard]] static std::uint64_t default_monotonic_milliseconds() noexcept;
    [[nodiscard]] bool read_monotonic_locked(std::uint64_t& destination) noexcept;
    [[nodiscard]] bool derive_trusted_now_locked(
        std::uint64_t& destination) noexcept;
    [[nodiscard]] Snapshot snapshot_locked() noexcept;
    void revoke_locked() noexcept;

    MonotonicMillisecondsSource monotonic_milliseconds_;
    std::unique_ptr<UsageLeaseGate> lease_gate_;
    TrustedTimeAnchor anchor_{};
    bool peer_confirmed_{};
    bool trusted_time_anchored_{};
    bool monotonic_clock_rollback_{};
    std::mutex mutex_;
};

}  // namespace vfdual
