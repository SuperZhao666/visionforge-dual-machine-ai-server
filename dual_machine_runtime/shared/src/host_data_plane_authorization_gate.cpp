#include "vfdual/host_data_plane_authorization_gate.hpp"

#include <chrono>
#include <limits>
#include <utility>

namespace vfdual {
namespace {

[[nodiscard]] bool admission_accepts_current(
    const UsageLeaseAdmission admission) noexcept {
    return admission == UsageLeaseAdmission::accepted_current ||
        admission == UsageLeaseAdmission::accepted_idempotent ||
        admission == UsageLeaseAdmission::staged_future;
}

}  // namespace

HostDataPlaneAuthorizationGate::HostDataPlaneAuthorizationGate()
    : HostDataPlaneAuthorizationGate(&default_monotonic_seconds) {}

HostDataPlaneAuthorizationGate::HostDataPlaneAuthorizationGate(
    MonotonicSecondsSource monotonic_seconds)
    : monotonic_seconds_(std::move(monotonic_seconds)) {}

bool HostDataPlaneAuthorizationGate::install_confirmed_peer_binding(
    UsageLeaseBinding binding) {
    std::lock_guard lock(mutex_);
    auto candidate = std::make_unique<UsageLeaseGate>(std::move(binding));
    const UsageLeaseGateSnapshot initial = candidate->evaluate(0U);
    if (initial.state != UsageLeaseGateState::empty) {
        lease_gate_.reset();
        anchor_ = {};
        peer_confirmed_ = false;
        trusted_time_anchored_ = false;
        monotonic_clock_rollback_ = false;
        return false;
    }
    lease_gate_ = std::move(candidate);
    anchor_ = {};
    peer_confirmed_ = true;
    trusted_time_anchored_ = false;
    monotonic_clock_rollback_ = false;
    return true;
}

UsageLeaseAdmission HostDataPlaneAuthorizationGate::submit_verified_ticket(
    const VerifiedUsageLease& ticket,
    const std::uint64_t trusted_now_epoch) {
    std::lock_guard lock(mutex_);
    if (!peer_confirmed_ || lease_gate_ == nullptr ||
        monotonic_clock_rollback_ || trusted_now_epoch == 0U) {
        return UsageLeaseAdmission::rejected_gate_closed;
    }

    std::uint64_t monotonic_now{};
    if (!read_monotonic_locked(monotonic_now)) {
        revoke_locked();
        return UsageLeaseAdmission::rejected_gate_closed;
    }

    if (trusted_time_anchored_) {
        if (monotonic_now < anchor_.monotonic_seconds) {
            monotonic_clock_rollback_ = true;
            revoke_locked();
            return UsageLeaseAdmission::rejected_gate_closed;
        }
        const std::uint64_t elapsed = monotonic_now - anchor_.monotonic_seconds;
        if (elapsed > (std::numeric_limits<std::uint64_t>::max)() -
                anchor_.trusted_epoch) {
            revoke_locked();
            return UsageLeaseAdmission::rejected_gate_closed;
        }
        const std::uint64_t derived_now = anchor_.trusted_epoch + elapsed;
        if (trusted_now_epoch < derived_now) {
            revoke_locked();
            return UsageLeaseAdmission::rejected_time;
        }
    }

    const UsageLeaseAdmission admission =
        lease_gate_->submit_verified_ticket(ticket, trusted_now_epoch);
    if (admission_accepts_current(admission)) {
        // Re-anchor only to a non-decreasing server-authenticated epoch. This
        // bounds drift without accepting local wall-clock rollback.
        anchor_ = TrustedTimeAnchor{trusted_now_epoch, monotonic_now};
        trusted_time_anchored_ = true;
    }
    return admission;
}

bool HostDataPlaneAuthorizationGate::permits_data_plane() noexcept {
    return snapshot().permits_data_plane;
}

HostDataPlaneAuthorizationGate::Snapshot
HostDataPlaneAuthorizationGate::snapshot() noexcept {
    std::lock_guard lock(mutex_);
    return snapshot_locked();
}

void HostDataPlaneAuthorizationGate::stop() noexcept {
    std::lock_guard lock(mutex_);
    if (lease_gate_ != nullptr) lease_gate_->stop();
}

void HostDataPlaneAuthorizationGate::revoke() noexcept {
    std::lock_guard lock(mutex_);
    revoke_locked();
}

void HostDataPlaneAuthorizationGate::reset() noexcept {
    std::lock_guard lock(mutex_);
    if (lease_gate_ != nullptr) lease_gate_->stop();
    lease_gate_.reset();
    anchor_ = {};
    peer_confirmed_ = false;
    trusted_time_anchored_ = false;
    monotonic_clock_rollback_ = false;
}

std::uint64_t HostDataPlaneAuthorizationGate::default_monotonic_seconds()
    noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

bool HostDataPlaneAuthorizationGate::read_monotonic_locked(
    std::uint64_t& destination) noexcept {
    if (!monotonic_seconds_) return false;
    try {
        destination = monotonic_seconds_();
        return true;
    } catch (...) {
        destination = 0U;
        return false;
    }
}

bool HostDataPlaneAuthorizationGate::derive_trusted_now_locked(
    std::uint64_t& destination) noexcept {
    destination = 0U;
    if (!trusted_time_anchored_) return false;
    std::uint64_t monotonic_now{};
    if (!read_monotonic_locked(monotonic_now)) {
        revoke_locked();
        return false;
    }
    if (monotonic_now < anchor_.monotonic_seconds) {
        monotonic_clock_rollback_ = true;
        revoke_locked();
        return false;
    }
    const std::uint64_t elapsed = monotonic_now - anchor_.monotonic_seconds;
    if (elapsed > (std::numeric_limits<std::uint64_t>::max)() -
            anchor_.trusted_epoch) {
        revoke_locked();
        return false;
    }
    destination = anchor_.trusted_epoch + elapsed;
    return true;
}

HostDataPlaneAuthorizationGate::Snapshot
HostDataPlaneAuthorizationGate::snapshot_locked() noexcept {
    Snapshot result{};
    result.peer_confirmed = peer_confirmed_;
    result.trusted_time_anchored = trusted_time_anchored_;
    result.monotonic_clock_rollback = monotonic_clock_rollback_;
    if (!peer_confirmed_ || lease_gate_ == nullptr ||
        !trusted_time_anchored_ || monotonic_clock_rollback_) {
        return result;
    }

    std::uint64_t trusted_now{};
    if (!derive_trusted_now_locked(trusted_now)) {
        result.monotonic_clock_rollback = monotonic_clock_rollback_;
        return result;
    }
    const UsageLeaseGateSnapshot lease = lease_gate_->evaluate(trusted_now);
    result.trusted_now_epoch = trusted_now;
    result.lease_state = lease.state;
    result.permits_data_plane = lease.permits_data_plane;
    result.sequence = lease.sequence;
    result.expires_at_epoch = lease.expires_at_epoch;
    return result;
}

void HostDataPlaneAuthorizationGate::revoke_locked() noexcept {
    if (lease_gate_ != nullptr) lease_gate_->revoke();
}

}  // namespace vfdual
