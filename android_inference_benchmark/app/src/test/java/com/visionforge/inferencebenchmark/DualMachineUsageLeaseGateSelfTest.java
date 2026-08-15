package com.visionforge.inferencebenchmark;

import java.security.KeyPair;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Dependency-free regression contract for the monotonic short-lease gate. */
public final class DualMachineUsageLeaseGateSelfTest {
    private static final long SECOND = 1_000_000_000L;

    private DualMachineUsageLeaseGateSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        require(DualMachineUsageLeaseGate.EMPTY_PREVIOUS_LEASE_SHA256.equals(
                "0000000000000000000000000000000000000000000000000000000000000000"));
        KeyPair keyPair = DualMachineUsageLeaseSelfTestSupport.rsaKeyPair(3072);
        verifiesInitialFailClosedAndExactExpiry(keyPair);
        verifiesFutureStagingAndEarlyPromotion(keyPair);
        verifiesLateRenewalLeavesAClosedGap(keyPair);
        verifiesDuplicateReplayAndChainRejection(keyPair);
        verifiesGenerationAndMonotonicTimeCannotReopen(keyPair);
        verifiesConcurrentCallersCannotSubmitStaleClockSnapshots(keyPair);
        verifiesStopAndRevokeFailClosed(keyPair);
        System.out.println("DUAL_MACHINE_USAGE_LEASE_GATE_SELF_TEST_OK");
    }

    private static void verifiesInitialFailClosedAndExactExpiry(KeyPair keyPair)
            throws Exception {
        MutableClock clock = new MutableClock();
        DualMachineUsageLeaseGate gate =
                new DualMachineUsageLeaseGate(clock);
        require(!gate.isOpen());
        DualMachineUsageLeaseVerifier.VerifiedLease lease =
                verified(keyPair, initial(), 100L, 0L);
        expectRejected(() -> gate.install(lease));
        gate.beginSession();
        require(gate.install(lease)
                == DualMachineUsageLeaseGate.InstallResult.CURRENT_INSTALLED);
        require(gate.isOpen());
        clock.set(5L * SECOND - 1L);
        require(gate.isOpen());
        clock.set(5L * SECOND);
        require(!gate.isOpen());

        MutableClock delayedClock = new MutableClock();
        DualMachineUsageLeaseGate delayed =
                new DualMachineUsageLeaseGate(delayedClock);
        delayed.beginSession();
        delayedClock.set(5L * SECOND);
        expectRejected(() -> delayed.install(lease));
    }

    private static void verifiesFutureStagingAndEarlyPromotion(KeyPair keyPair)
            throws Exception {
        MutableClock clock = new MutableClock();
        DualMachineUsageLeaseGate gate =
                new DualMachineUsageLeaseGate(clock);
        gate.beginSession();
        DualMachineUsageLeaseVerifier.VerifiedLease first =
                verified(keyPair, initial(), 100L, 0L);
        gate.install(first);

        DualMachineUsageLeaseSelfTestSupport.LeaseData renewal =
                renewal(first, 102L, 105L, 110L);
        DualMachineUsageLeaseVerifier.VerifiedLease second =
                verified(keyPair, renewal, 102L, 2L * SECOND);
        clock.set(2L * SECOND);
        require(gate.install(second)
                == DualMachineUsageLeaseGate.InstallResult.FUTURE_STAGED);
        require(gate.install(second)
                == DualMachineUsageLeaseGate.InstallResult.IDEMPOTENT);
        clock.set(5L * SECOND - 1L);
        require(gate.activeLease().sequence() == 0L);
        clock.set(5L * SECOND);
        require(gate.activeLease().sequence() == 1L);
        clock.set(10L * SECOND - 1L);
        require(gate.isOpen());
        clock.set(10L * SECOND);
        require(!gate.isOpen());

        MutableClock futureClock = new MutableClock();
        DualMachineUsageLeaseGate futureInitial =
                new DualMachineUsageLeaseGate(futureClock);
        futureInitial.beginSession();
        DualMachineUsageLeaseSelfTestSupport.LeaseData future =
                DualMachineUsageLeaseSelfTestSupport.initial(100L, 102L, 107L);
        DualMachineUsageLeaseVerifier.VerifiedLease futureLease =
                verified(keyPair, future, 100L, 0L);
        expectRejected(() -> futureInitial.install(futureLease));
        futureClock.set(2L * SECOND);
        require(!futureInitial.isOpen());
    }

    private static void verifiesLateRenewalLeavesAClosedGap(KeyPair keyPair)
            throws Exception {
        MutableClock clock = new MutableClock();
        DualMachineUsageLeaseGate gate =
                new DualMachineUsageLeaseGate(clock);
        gate.beginSession();
        DualMachineUsageLeaseVerifier.VerifiedLease first =
                verified(keyPair, initial(), 100L, 0L);
        gate.install(first);
        clock.set(6L * SECOND);
        require(!gate.isOpen());

        DualMachineUsageLeaseSelfTestSupport.LeaseData late =
                renewal(first, 107L, 107L, 112L);
        DualMachineUsageLeaseVerifier.VerifiedLease lateLease =
                verified(keyPair, late, 107L, 7L * SECOND);
        clock.set(7L * SECOND);
        require(gate.install(lateLease)
                == DualMachineUsageLeaseGate.InstallResult.CURRENT_INSTALLED);
        require(gate.isOpen());
        clock.set(12L * SECOND);
        require(!gate.isOpen());
    }

    private static void verifiesDuplicateReplayAndChainRejection(KeyPair keyPair)
            throws Exception {
        MutableClock clock = new MutableClock();
        DualMachineUsageLeaseGate gate =
                new DualMachineUsageLeaseGate(clock);
        gate.beginSession();
        DualMachineUsageLeaseVerifier.VerifiedLease first =
                verified(keyPair, initial(), 100L, 0L);
        gate.install(first);
        require(gate.install(first)
                == DualMachineUsageLeaseGate.InstallResult.IDEMPOTENT);

        DualMachineUsageLeaseSelfTestSupport.LeaseData renewal =
                renewal(first, 102L, 105L, 110L);
        DualMachineUsageLeaseVerifier.VerifiedLease second =
                verified(keyPair, renewal, 102L, 2L * SECOND);
        clock.set(2L * SECOND);
        gate.install(second);
        clock.set(5L * SECOND);
        require(gate.activeLease().sequence() == 1L);
        expectRejected(() -> gate.install(first));

        DualMachineUsageLeaseSelfTestSupport.LeaseData skipped =
                renewal(second, 106L, 110L, 115L);
        skipped.sequence = 3L;
        DualMachineUsageLeaseVerifier.VerifiedLease skippedLease =
                verified(keyPair, skipped, 106L, 6L * SECOND);
        clock.set(6L * SECOND);
        expectRejected(() -> gate.install(skippedLease));

        DualMachineUsageLeaseSelfTestSupport.LeaseData wrongSession =
                renewal(second, 106L, 110L, 115L);
        wrongSession.sessionId = "a".repeat(32);
        DualMachineUsageLeaseVerifier.VerifiedLease wrongBinding =
                verified(keyPair, wrongSession, 106L, 6L * SECOND);
        expectRejected(() -> gate.install(wrongBinding));
    }

    private static void verifiesStopAndRevokeFailClosed(KeyPair keyPair)
            throws Exception {
        DualMachineUsageLeaseVerifier.VerifiedLease first =
                verified(keyPair, initial(), 100L, 0L);
        MutableClock clock = new MutableClock();
        DualMachineUsageLeaseGate gate =
                new DualMachineUsageLeaseGate(clock);
        gate.beginSession();
        gate.install(first);
        gate.stop();
        require(!gate.isOpen());
        require(!gate.isAccepting());
        expectRejected(() -> gate.install(first));
        expectRejected(gate::beginSession);

        DualMachineUsageLeaseGate revoked =
                new DualMachineUsageLeaseGate(new MutableClock());
        revoked.beginSession();
        revoked.install(first);
        revoked.revoke();
        require(!revoked.isOpen());
        expectRejected(() -> revoked.install(first));
        expectRejected(revoked::beginSession);
    }

    private static void verifiesGenerationAndMonotonicTimeCannotReopen(
            KeyPair keyPair) throws Exception {
        DualMachineUsageLeaseVerifier.VerifiedLease lease =
                verified(keyPair, initial(), 100L, 10L * SECOND);

        MutableClock clock = new MutableClock(10L * SECOND);
        DualMachineUsageLeaseGate rollback =
                new DualMachineUsageLeaseGate(clock);
        rollback.beginSession();
        rollback.install(lease);
        clock.set(11L * SECOND);
        require(rollback.isOpen());
        clock.set(10L * SECOND);
        require(!rollback.isOpen());
        require(!rollback.isAccepting());
        clock.set(11L * SECOND);
        expectRejected(() -> rollback.install(lease));
    }

    private static void verifiesConcurrentCallersCannotSubmitStaleClockSnapshots(
            KeyPair keyPair) throws Exception {
        AtomicLong clockNanos = new AtomicLong();
        DualMachineUsageLeaseGate gate =
                new DualMachineUsageLeaseGate(clockNanos::incrementAndGet);
        gate.beginSession();
        gate.install(verified(keyPair, initial(), 100L, 0L));
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Runnable caller = () -> {
            try {
                for (int index = 0; index < 2_000; index++) {
                    if (!gate.isOpen()) {
                        throw new AssertionError("concurrent gate unexpectedly closed");
                    }
                }
            } catch (Throwable throwable) {
                failure.compareAndSet(null, throwable);
            }
        };
        Thread first = new Thread(caller, "lease-gate-caller-1");
        Thread second = new Thread(caller, "lease-gate-caller-2");
        first.start();
        second.start();
        first.join();
        second.join();
        require(failure.get() == null);
        require(gate.isAccepting());
    }

    private static DualMachineUsageLeaseSelfTestSupport.LeaseData initial() {
        return DualMachineUsageLeaseSelfTestSupport.initial(100L, 100L, 105L);
    }

    private static DualMachineUsageLeaseSelfTestSupport.LeaseData renewal(
            DualMachineUsageLeaseVerifier.VerifiedLease previous,
            long issuedAt,
            long notBefore,
            long expiresAt) {
        DualMachineUsageLeaseSelfTestSupport.LeaseData data =
                DualMachineUsageLeaseSelfTestSupport.initial(
                        issuedAt, notBefore, expiresAt);
        data.sequence = previous.sequence() + 1L;
        data.previousLeaseSha256 = previous.tokenSha256();
        return data;
    }

    private static DualMachineUsageLeaseVerifier.VerifiedLease verified(
            KeyPair keyPair,
            DualMachineUsageLeaseSelfTestSupport.LeaseData data,
            long wallTime,
            long monotonicNanos) throws Exception {
        return new DualMachineUsageLeaseVerifier(keyPair.getPublic()).verify(
                DualMachineUsageLeaseSelfTestSupport.token(keyPair, data),
                DualMachineUsageLeaseSelfTestSupport.expected(data),
                wallTime,
                monotonicNanos);
    }

    private static void expectRejected(CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected gate rejection");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("usage lease gate contract failed");
    }

    @FunctionalInterface
    private interface CheckedAction {
        void run() throws Exception;
    }

    private static final class MutableClock
            implements DualMachineUsageLeaseGate.MonotonicClock {
        private long nowNanos;

        MutableClock() {
        }

        MutableClock(long nowNanos) {
            this.nowNanos = nowNanos;
        }

        void set(long value) {
            nowNanos = value;
        }

        @Override
        public long nowNanos() {
            return nowNanos;
        }
    }
}
