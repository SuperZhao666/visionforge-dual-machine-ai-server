package com.visionforge.inferencebenchmark;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * User-rights regressions: activation/status/restore cost zero and only an
 * explicit formal start can install the first paid lease.
 */
public final class DualMachineFormalUsageStateMachineSelfTest {
    private static final String HOST_PUBLIC_KEY_BASE64 =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt"
                    + "6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==";
    private static final String HOST_KEY_SHA256 =
            "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3";
    private DualMachineFormalUsageStateMachineSelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        activationDoesNotStartBilling();
        restoreDoesNotResumeBilling();
        formalStartRequiresReadinessAndPaidVerifiedLease();
        expiryClosesBeforeLateRenewal();
        stopClosesLocallyBeforeNetworkResult();
        concurrentResumeCannotReleaseAnotherActivationReservation();
        statusRefreshReservesAuthorizationState();
        staleStatusCleanupCannotClearNewToken();
        statusReservationRacesFormalStartAtomically();
        authenticatedRevocationCommitFailureStaysTerminal();
        revokedRevisionIsTerminalAndRestorable();
        confirmedExhaustionCanReturnToActivationOnlyAfterConfirmation();
        futureRenewalActivatesWithoutAnotherDebit();
        permanentEntitlementNeverDebitsOrExhausts();
        System.out.println("ANDROID_FORMAL_USAGE_STATE_MACHINE_OK");
    }

    private static void
            confirmedExhaustionCanReturnToActivationOnlyAfterConfirmation() {
        DualMachineFormalUsageStateMachine machine = activated();
        expectState(machine::releaseConfirmedExhaustedEntitlement);
        long token = machine.beginStatusRefresh();
        machine.statusConfirmed(token, record(), "exhausted", 0L, 3_600L);
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.EXHAUSTED);
        machine.releaseConfirmedExhaustedEntitlement();
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.UNACTIVATED);
        check(machine.snapshot().entitlement == null);
        check(machine.snapshot().canActivate());
        check(!machine.snapshot().balanceKnown);
        check(!machine.snapshot().permitsDataPlane);
    }

    private static void permanentEntitlementNeverDebitsOrExhausts() {
        DualMachineFormalUsageStateMachine machine =
                new DualMachineFormalUsageStateMachine();
        machine.beginCardActivation();
        machine.activationConfirmed(permanentRecord(), 0L, 0L, false);
        check(machine.snapshot().canFormalStart());
        machine.runtimeRequestedFormalStart(true);
        machine.verifiedInitialLeaseInstalled(
                repeated('f', 32), 0L, 0L, 0L, 0L, true);
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVE);
        machine.verifiedFutureRenewalStaged(1L, 0L, 0L, 0L);
        machine.closeLocalForRuntimeStop();
        machine.stopFinished(0L);
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(machine.snapshot().canFormalStart());
        check(machine.snapshot().remainingSeconds == 0L);
        check(machine.snapshot().totalConsumedSeconds == 0L);
    }

    private static void activationDoesNotStartBilling() {
        DualMachineFormalUsageStateMachine machine =
                new DualMachineFormalUsageStateMachine();
        machine.beginCardActivation();
        machine.activationConfirmed(record(), 3_600L, 0L, false);
        DualMachineFormalUsageStateMachine.Snapshot snapshot = machine.snapshot();
        check(snapshot.state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(snapshot.remainingSeconds == 3_600L);
        check(snapshot.balanceKnown);
        check(!snapshot.billingStarted);
        check(!snapshot.permitsDataPlane);
        expectState(machine::beginCardActivation);
        DualMachineFormalUsageStateMachine invalidBilling =
                new DualMachineFormalUsageStateMachine();
        invalidBilling.beginCardActivation();
        expectSecurity(() -> invalidBilling.activationConfirmed(
                record(), 3_595L, 5L, true));
    }

    private static void restoreDoesNotResumeBilling() {
        DualMachineFormalUsageStateMachine machine =
                new DualMachineFormalUsageStateMachine();
        machine.restoreBoundEntitlement(record());
        DualMachineFormalUsageStateMachine.Snapshot snapshot = machine.snapshot();
        check(snapshot.state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(snapshot.sessionId.isEmpty());
        check(snapshot.leaseSequence == -1L);
        check(!snapshot.balanceKnown);
        check(!snapshot.canActivate());
        check(!snapshot.canFormalStart());
        check(!snapshot.billingStarted);
        check(!snapshot.permitsDataPlane);
    }

    private static void formalStartRequiresReadinessAndPaidVerifiedLease() {
        DualMachineFormalUsageStateMachine machine = activated();
        expectState(() -> machine.runtimeRequestedFormalStart(false));
        machine.runtimeRequestedFormalStart(true);
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STARTING);
        check(!machine.snapshot().permitsDataPlane);
        expectSecurity(() -> machine.verifiedInitialLeaseInstalled(
                repeated('e', 32), 0L, 0L, 3_600L, 0L, false));
        machine.verifiedInitialLeaseInstalled(
                repeated('e', 32), 0L, 5L, 3_595L, 5L, true);
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVE);
        check(machine.snapshot().permitsDataPlane);
        check(machine.snapshot().billingStarted);
    }

    private static void expiryClosesBeforeLateRenewal() {
        DualMachineFormalUsageStateMachine machine = active();
        machine.leaseExpiredLocally();
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.RENEWAL_GAP);
        check(!machine.snapshot().permitsDataPlane);
        machine.verifiedRenewalInstalled(1L, 5L, 3_590L, 10L);
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVE);
        check(machine.snapshot().permitsDataPlane);
        expectSecurity(() -> machine.verifiedRenewalInstalled(
                3L, 5L, 3_585L, 15L));
    }

    private static void stopClosesLocallyBeforeNetworkResult() {
        DualMachineFormalUsageStateMachine machine = active();
        machine.closeLocalForRuntimeStop();
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STOPPING);
        check(!machine.snapshot().permitsDataPlane);
        machine.stopFinished(3_595L);
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(!machine.snapshot().billingStarted);
    }

    private static void
            concurrentResumeCannotReleaseAnotherActivationReservation() {
        DualMachineFormalUsageStateMachine machine =
                new DualMachineFormalUsageStateMachine();
        machine.beginCardActivation();
        expectState(machine::beginPendingCardActivationResume);
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATING);
        machine.markCardActivationPending();
        machine.beginPendingCardActivationResume();
        machine.activationFailedBeforeConfirmation();
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.UNACTIVATED);
    }

    private static void statusRefreshReservesAuthorizationState() {
        DualMachineFormalUsageStateMachine machine = activated();
        long token = machine.beginStatusRefresh();
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STATUS_REFRESHING);
        expectState(() -> machine.runtimeRequestedFormalStart(true));
        expectState(machine::beginCardActivation);
        machine.statusRefreshFailed(token);
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(machine.snapshot().remainingSeconds == 3_600L);
    }

    private static void staleStatusCleanupCannotClearNewToken() {
        DualMachineFormalUsageStateMachine machine = activated();
        long tokenA = machine.beginStatusRefresh();
        check(machine.statusRefreshFailedIfCurrent(tokenA));
        long tokenB = machine.beginStatusRefresh();
        check(tokenB > tokenA);
        check(!machine.statusRefreshFailedIfCurrent(tokenA));
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STATUS_REFRESHING);
        check(machine.statusRefreshFailedIfCurrent(tokenB));
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
    }

    private static void statusReservationRacesFormalStartAtomically()
            throws Exception {
        for (int attempt = 0; attempt < 32; attempt++) {
            DualMachineFormalUsageStateMachine machine = activated();
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger winners = new AtomicInteger();
            AtomicLong statusToken = new AtomicLong();
            Thread status = new Thread(() -> {
                await(start);
                try {
                    statusToken.set(machine.beginStatusRefresh());
                    winners.incrementAndGet();
                } catch (IllegalStateException expected) {
                    // The formal start won the one shared state transition.
                }
            });
            Thread formal = new Thread(() -> {
                await(start);
                try {
                    machine.runtimeRequestedFormalStart(true);
                    winners.incrementAndGet();
                } catch (IllegalStateException expected) {
                    // The status reservation won the shared transition.
                }
            });
            status.start();
            formal.start();
            start.countDown();
            status.join();
            formal.join();
            check(winners.get() == 1);
            if (statusToken.get() != 0L) {
                machine.statusRefreshFailed(statusToken.get());
            } else {
                machine.formalStartFailed();
            }
        }
    }

    private static void authenticatedRevocationCommitFailureStaysTerminal() {
        DualMachineFormalUsageStateMachine machine = activated();
        DualMachineEntitlementRecord revoked =
                record().withRevocationVersion(8L);
        long token = machine.beginStatusRefresh();
        expectSecurity(() -> machine.statusConfirmed(
                token, revoked, "active", 3_600L, 0L));
        check(machine.failClosedFromAuthenticatedRevocationIfCurrent(
                token, revoked, 3_600L, 0L));
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.REVOKED);
        check(!machine.snapshot().canFormalStart());
        check(!machine.statusRefreshFailedIfCurrent(token));
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new AssertionError(failure);
        }
    }

    private static void revokedRevisionIsTerminalAndRestorable() {
        DualMachineFormalUsageStateMachine machine = activated();
        DualMachineEntitlementRecord revoked =
                record().withRevocationVersion(8L);
        long token = machine.beginStatusRefresh();
        machine.statusConfirmed(token, revoked, "revoked", 3_600L, 0L);
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.REVOKED);
        check(machine.snapshot().entitlement.revoked);
        check(machine.snapshot().entitlement.revocationVersion == 8L);

        long rollbackToken = machine.beginStatusRefresh();
        expectSecurity(() -> machine.statusConfirmed(
                rollbackToken, revoked, "active", 3_600L, 0L));
        machine.statusRefreshFailed(rollbackToken);
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.REVOKED);

        DualMachineFormalUsageStateMachine restored =
                new DualMachineFormalUsageStateMachine();
        restored.restoreBoundEntitlement(revoked);
        check(restored.snapshot().state
                == DualMachineFormalUsageStateMachine.State.REVOKED);
        check(!restored.snapshot().canFormalStart());
        check(!restored.snapshot().canActivate());
    }

    private static void futureRenewalActivatesWithoutAnotherDebit() {
        DualMachineFormalUsageStateMachine machine = active();
        machine.leaseExpiredLocally();
        machine.verifiedFutureRenewalStaged(
                1L, 5L, 3_590L, 10L);
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.RENEWAL_GAP);
        check(machine.snapshot().leaseSequence == 1L);
        check(!machine.snapshot().permitsDataPlane);
        machine.stagedRenewalActivated(1L);
        check(machine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVE);
        check(machine.snapshot().permitsDataPlane);
    }

    private static DualMachineFormalUsageStateMachine activated() {
        DualMachineFormalUsageStateMachine machine =
                new DualMachineFormalUsageStateMachine();
        machine.beginCardActivation();
        machine.activationConfirmed(record(), 3_600L, 0L, false);
        return machine;
    }

    private static DualMachineFormalUsageStateMachine active() {
        DualMachineFormalUsageStateMachine machine = activated();
        machine.runtimeRequestedFormalStart(true);
        machine.verifiedInitialLeaseInstalled(
                repeated('e', 32), 0L, 5L, 3_595L, 5L, true);
        return machine;
    }

    private static DualMachineEntitlementRecord record() {
        return new DualMachineEntitlementRecord(
                repeated('a', 32),
                repeated('b', 32),
                2,
                7L,
                HOST_KEY_SHA256,
                HOST_PUBLIC_KEY_BASE64,
                repeated('d', 64),
                "visionforge-dual-machine-pairing-identity");
    }

    private static DualMachineEntitlementRecord permanentRecord() {
        return new DualMachineEntitlementRecord(
                repeated('a', 32),
                repeated('b', 32),
                2,
                7L,
                HOST_KEY_SHA256,
                HOST_PUBLIC_KEY_BASE64,
                repeated('d', 64),
                "visionforge-dual-machine-pairing-identity",
                "permanent",
                "permanent",
                true,
                false);
    }

    private static void expectSecurity(Runnable action) {
        try {
            action.run();
            throw new AssertionError("security violation was accepted");
        } catch (SecurityException expected) {
            // Expected.
        }
    }

    private static void expectState(Runnable action) {
        try {
            action.run();
            throw new AssertionError("invalid state transition was accepted");
        } catch (IllegalStateException expected) {
            // Expected.
        }
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("check failed");
    }

    private static String repeated(char character, int count) {
        StringBuilder value = new StringBuilder(count);
        for (int index = 0; index < count; index++) value.append(character);
        return value.toString();
    }
}
