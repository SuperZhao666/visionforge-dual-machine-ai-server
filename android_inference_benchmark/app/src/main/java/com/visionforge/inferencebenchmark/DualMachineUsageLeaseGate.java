package com.visionforge.inferencebenchmark;

/**
 * Process-memory-only fail-closed gate for one active and at most one future
 * verified dual-machine usage lease.
 */
public final class DualMachineUsageLeaseGate {
    /** Server contract sentinel; this is intentionally not SHA-256(empty). */
    public static final String EMPTY_PREVIOUS_LEASE_SHA256 =
            DualMachineUsageLeaseVerifier.EMPTY_PREVIOUS_LEASE_SHA256;

    public enum InstallResult {
        CURRENT_INSTALLED,
        FUTURE_STAGED,
        IDEMPOTENT
    }

    @FunctionalInterface
    public interface MonotonicClock {
        long nowNanos();
    }

    private final MonotonicClock clock;
    private boolean accepting;
    private boolean generationBegun;
    private boolean monotonicObserved;
    private long highestMonotonicNanos;
    private LeaseSlot current;
    private LeaseSlot future;

    public DualMachineUsageLeaseGate(MonotonicClock clock) {
        if (clock == null) throw rejected("usage_lease_clock_missing");
        this.clock = clock;
    }

    /**
     * Explicitly starts this one formal-use generation.
     *
     * <p>A stopped/revoked gate is never reusable; a later formal start must
     * allocate a new instance so an old still-unexpired ticket cannot be
     * reinstalled by an accidental recovery path.</p>
     */
    public synchronized void beginSession() {
        if (generationBegun) {
            throw rejected("usage_lease_generation_already_begun");
        }
        generationBegun = true;
        current = null;
        future = null;
        accepting = true;
    }

    /**
     * Installs a verified ticket. The first ticket must be sequence zero and
     * bind the SHA-256 of the empty previous ticket.
     */
    public synchronized InstallResult install(
            DualMachineUsageLeaseVerifier.VerifiedLease lease) {
        if (!accepting) throw rejected("usage_lease_gate_not_accepting");
        if (lease == null) throw rejected("usage_lease_missing");
        long monotonicNowNanos = observeMonotonic();
        promoteIfDue(monotonicNowNanos);
        InstallResult duplicate = duplicateResult(lease);
        if (duplicate != null) return duplicate;
        if (reached(monotonicNowNanos, lease.expiresAtMonotonicNanos())) {
            throw rejected("usage_lease_already_expired");
        }
        if (current == null) return installInitial(lease, monotonicNowNanos);
        if (future != null) throw rejected("usage_lease_future_slot_occupied");
        return installRenewal(lease, monotonicNowNanos);
    }

    /** Returns true only inside the monotonic interval of the current ticket. */
    public synchronized boolean isOpen() {
        if (!accepting) return false;
        final long monotonicNowNanos;
        try {
            monotonicNowNanos = observeMonotonic();
        } catch (IllegalArgumentException exception) {
            return false;
        }
        promoteIfDue(monotonicNowNanos);
        return isOpenAt(monotonicNowNanos);
    }

    public synchronized DualMachineUsageLeaseVerifier.VerifiedLease activeLease() {
        if (!accepting) return null;
        final long monotonicNowNanos;
        try {
            monotonicNowNanos = observeMonotonic();
        } catch (IllegalArgumentException exception) {
            return null;
        }
        promoteIfDue(monotonicNowNanos);
        return isOpenAt(monotonicNowNanos) ? current.lease : null;
    }

    /** Immediate local stop. A later formal start must call beginSession(). */
    public synchronized void stop() {
        failClosed();
    }

    /** Immediate local revocation. A later reauthorization must call beginSession(). */
    public synchronized void revoke() {
        failClosed();
    }

    public synchronized boolean isAccepting() {
        return accepting;
    }

    private InstallResult installInitial(
            DualMachineUsageLeaseVerifier.VerifiedLease lease,
            long monotonicNowNanos) {
        if (lease.sequence() != 0L
                || !EMPTY_PREVIOUS_LEASE_SHA256.equals(lease.previousLeaseSha256())) {
            throw rejected("usage_lease_initial_chain_invalid");
        }
        if (!reached(monotonicNowNanos, lease.notBeforeMonotonicNanos())) {
            throw rejected("usage_lease_initial_not_yet_active");
        }
        current = new LeaseSlot(lease, lease.notBeforeMonotonicNanos());
        return InstallResult.CURRENT_INSTALLED;
    }

    private InstallResult installRenewal(
            DualMachineUsageLeaseVerifier.VerifiedLease lease,
            long monotonicNowNanos) {
        DualMachineUsageLeaseVerifier.VerifiedLease previous = current.lease;
        if (!sameStaticBinding(previous, lease)
                || lease.sequence() != previous.sequence() + 1L
                || !previous.tokenSha256().equals(lease.previousLeaseSha256())
                || lease.notBeforeEpochSeconds() < previous.expiresAtEpochSeconds()) {
            throw rejected("usage_lease_renewal_chain_invalid");
        }
        boolean previousExpired =
                reached(monotonicNowNanos, previous.expiresAtMonotonicNanos());
        if (!previousExpired
                && lease.notBeforeEpochSeconds() != previous.expiresAtEpochSeconds()) {
            throw rejected("usage_lease_early_renewal_boundary_invalid");
        }
        long activationNanos = laterDeadline(
                previous.expiresAtMonotonicNanos(),
                lease.notBeforeMonotonicNanos());
        LeaseSlot next = new LeaseSlot(lease, activationNanos);
        if (reached(monotonicNowNanos, activationNanos)) {
            current = next;
            return InstallResult.CURRENT_INSTALLED;
        }
        future = next;
        return InstallResult.FUTURE_STAGED;
    }

    private InstallResult duplicateResult(
            DualMachineUsageLeaseVerifier.VerifiedLease lease) {
        if (current != null
                && current.lease.tokenSha256().equals(lease.tokenSha256())) {
            return InstallResult.IDEMPOTENT;
        }
        if (future != null
                && future.lease.tokenSha256().equals(lease.tokenSha256())) {
            return InstallResult.IDEMPOTENT;
        }
        if (current != null && lease.sequence() <= current.lease.sequence()) {
            throw rejected("usage_lease_stale_or_replayed");
        }
        if (future != null && lease.sequence() <= future.lease.sequence()) {
            throw rejected("usage_lease_stale_or_replayed");
        }
        return null;
    }

    private void promoteIfDue(long monotonicNowNanos) {
        if (future != null && reached(monotonicNowNanos, future.activationNanos)) {
            current = future;
            future = null;
        }
    }

    private void failClosed() {
        accepting = false;
        current = null;
        future = null;
    }

    private long observeMonotonic() {
        final long monotonicNowNanos;
        try {
            monotonicNowNanos = clock.nowNanos();
        } catch (RuntimeException exception) {
            failClosed();
            throw rejected("usage_lease_monotonic_clock_failed");
        }
        if (monotonicObserved
                && monotonicNowNanos < highestMonotonicNanos) {
            failClosed();
            throw rejected("usage_lease_monotonic_time_reversed");
        }
        monotonicObserved = true;
        highestMonotonicNanos = monotonicNowNanos;
        return monotonicNowNanos;
    }

    private boolean isOpenAt(long monotonicNowNanos) {
        return current != null
                && reached(monotonicNowNanos, current.activationNanos)
                && !reached(
                        monotonicNowNanos,
                        current.lease.expiresAtMonotonicNanos());
    }

    private static boolean sameStaticBinding(
            DualMachineUsageLeaseVerifier.VerifiedLease first,
            DualMachineUsageLeaseVerifier.VerifiedLease second) {
        return first.entitlementId().equals(second.entitlementId())
                && first.pairId().equals(second.pairId())
                && first.sessionId().equals(second.sessionId())
                && first.protocolVersion() == second.protocolVersion()
                && first.revocationVersion() == second.revocationVersion()
                && first.hostKeySha256().equals(second.hostKeySha256())
                && first.androidKeySha256().equals(second.androidKeySha256())
                && first.channelTranscriptSha256().equals(
                        second.channelTranscriptSha256());
    }

    private static long laterDeadline(long first, long second) {
        return reached(first, second) ? first : second;
    }

    /** Safe for monotonic deadlines whose distance is far below 2^63 nanoseconds. */
    private static boolean reached(long now, long deadline) {
        return now - deadline >= 0L;
    }

    private static IllegalArgumentException rejected(String reason) {
        return new IllegalArgumentException(reason);
    }

    private static final class LeaseSlot {
        final DualMachineUsageLeaseVerifier.VerifiedLease lease;
        final long activationNanos;

        LeaseSlot(
                DualMachineUsageLeaseVerifier.VerifiedLease lease,
                long activationNanos) {
            this.lease = lease;
            this.activationNanos = activationNanos;
        }
    }
}
