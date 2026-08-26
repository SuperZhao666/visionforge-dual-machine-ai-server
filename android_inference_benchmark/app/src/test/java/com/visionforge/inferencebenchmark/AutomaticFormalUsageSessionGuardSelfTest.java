package com.visionforge.inferencebenchmark;

/** Regression contract for single-session automatic billing generations. */
final class AutomaticFormalUsageSessionGuardSelfTest {
    private static final String START_A =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String START_B =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static final String CHANNEL =
            "cccccccccccccccccccccccccccccccc"
                    + "cccccccccccccccccccccccccccccccc";
    private static final long CONNECTION_A = 0x1020_3040_5060_7080L;

    static void run() {
        initialGenerationIsArmed();
        preDebitReservationIsFailClosedAndCancellable();
        exactRetryRetainsItsReservationOwner();
        replacementCannotInheritAnOlderReservation();
        staleSettlementCannotMutateReplacementOwner();
        boundaryCloseDoesNotConsumeAnUnbilledExactRetry();
        startupWithoutProgressNeverTriggersProactiveStop();
        sustainedNoProgressStopsOnceOnlyAfterAProgressRenewal();
        rawVideoNeverRearmsBlockedBilling();
        authenticatedIntentRequiresConfirmedAbsence();
        authenticatedIntentRearmsExactlyOnce();
        duplicateAuthenticatedIntentCannotRearmAgain();
        invalidIntentEvidenceFailsClosed();
        restoredProcessStateRequiresAuthenticatedIntent();
        bothBlockedStatesRequestHostRearmProbes();
    }

    private static void initialGenerationIsArmed() {
        AutomaticFormalUsageSessionGuard guard =
                new AutomaticFormalUsageSessionGuard();
        require(guard.isAutomaticStartAllowed());
        require(guard.recordHostFrame(500L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome.RECORDED);
        guard.reserveFormalStart(START_A, CHANNEL);
        guard.markFormalSessionOpened(START_A, CHANNEL);
        require(!guard.isAutomaticStartAllowed());
        require(guard.snapshot().state
                == AutomaticFormalUsageSessionGuard.State.ACTIVE);
        require(!guard.requiresHostRearmProbe());
    }

    private static void bothBlockedStatesRequestHostRearmProbes() {
        AutomaticFormalUsageSessionGuard strict =
                new AutomaticFormalUsageSessionGuard();
        strict.restoreBlocked(100L, false);
        require(strict.requiresHostRearmProbe());

        AutomaticFormalUsageSessionGuard resumable =
                new AutomaticFormalUsageSessionGuard();
        resumable.restoreBlocked(100L, true);
        require(resumable.requiresHostRearmProbe());

        AutomaticFormalUsageSessionGuard armed =
                new AutomaticFormalUsageSessionGuard();
        require(!armed.requiresHostRearmProbe());
    }

    private static void startupWithoutProgressNeverTriggersProactiveStop() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(100L);
        require(!guard.shouldStopAfterNoProgress(3_000L, 1_500L));
        require(!guard.shouldStopAfterNoProgress(3_500L, 1_500L));
        require(!guard.shouldStopAfterNoProgress(4_000L, 1_500L));
        require(!guard.shouldStopAfterNoProgress(4_500L, 1_500L));
        require(!guard.snapshot().progressObserved);
    }

    private static void preDebitReservationIsFailClosedAndCancellable() {
        AutomaticFormalUsageSessionGuard guard =
                new AutomaticFormalUsageSessionGuard();
        guard.recordHostFrame(80L);
        guard.reserveFormalStart(START_A, CHANNEL);
        require(!guard.isAutomaticStartAllowed());
        require(guard.snapshot().state
                == AutomaticFormalUsageSessionGuard.State.START_RESERVED);
        require(guard.cancelUnbilledStartReservation(START_A, CHANNEL));
        require(!guard.cancelUnbilledStartReservation(START_A, CHANNEL));
        require(guard.isAutomaticStartAllowed());

        guard.reserveFormalStart(START_A, CHANNEL);
        guard.markFormalSessionOpened(START_A, CHANNEL);
        require(!guard.cancelUnbilledStartReservation(START_A, CHANNEL));
    }

    private static void exactRetryRetainsItsReservationOwner() {
        AutomaticFormalUsageSessionGuard guard =
                new AutomaticFormalUsageSessionGuard();
        require(guard.reserveFormalStart(START_A, CHANNEL));
        require(!guard.reserveFormalStart(START_A, CHANNEL));
        require(START_A.equals(guard.snapshot().startRequestId));
    }

    private static void replacementCannotInheritAnOlderReservation() {
        AutomaticFormalUsageSessionGuard guard =
                new AutomaticFormalUsageSessionGuard();
        guard.reserveFormalStart(START_A, CHANNEL);
        boolean rejected = false;
        try {
            guard.reserveFormalStart(START_B, CHANNEL);
        } catch (IllegalStateException expected) {
            rejected = true;
        }
        require(rejected);
        require(START_A.equals(guard.snapshot().startRequestId));
    }

    private static void staleSettlementCannotMutateReplacementOwner() {
        AutomaticFormalUsageSessionGuard guard =
                new AutomaticFormalUsageSessionGuard();
        guard.reserveFormalStart(START_A, CHANNEL);
        require(guard.cancelUnbilledStartReservation(START_A, CHANNEL));
        guard.reserveFormalStart(START_B, CHANNEL);
        require(!guard.cancelUnbilledStartReservation(START_A, CHANNEL));
        require(!guard.blockPotentiallyBilledGeneration(START_A, CHANNEL));
        require(guard.snapshot().state
                == AutomaticFormalUsageSessionGuard.State.START_RESERVED);
        require(START_B.equals(guard.snapshot().startRequestId));
    }

    private static void boundaryCloseDoesNotConsumeAnUnbilledExactRetry() {
        AutomaticFormalUsageSessionGuard guard =
                new AutomaticFormalUsageSessionGuard();
        guard.recordHostFrame(95L);
        guard.reserveFormalStart(START_A, CHANNEL);
        require(!guard.markFormalSessionClosed(START_A, CHANNEL));
        require(guard.snapshot().state
                == AutomaticFormalUsageSessionGuard.State.START_RESERVED);
        require(guard.blockPotentiallyBilledGeneration(START_A, CHANNEL));
        require(guard.snapshot().state
                == AutomaticFormalUsageSessionGuard.State
                        .BLOCKED_UNTIL_NEW_HOST_STREAM);
    }

    private static void sustainedNoProgressStopsOnceOnlyAfterAProgressRenewal() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(200L);
        guard.markProgressRenewed();
        require(!guard.shouldStopAfterNoProgress(10_000L, 1_500L));
        require(!guard.shouldStopAfterNoProgress(11_499L, 1_500L));
        require(guard.shouldStopAfterNoProgress(11_500L, 1_500L));
        require(!guard.shouldStopAfterNoProgress(11_750L, 1_500L));
    }

    private static void rawVideoNeverRearmsBlockedBilling() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(50_000L);
        require(guard.markFormalSessionClosed(START_A, CHANNEL));
        require(!guard.recordHostAbsent(1_000L, 1_000L));
        require(guard.recordHostAbsent(2_000L, 1_000L));

        long[] attackerOrStaleFrames = {50_001L, 5L, 6L, 49_000L, 7L};
        for (long frame : attackerOrStaleFrames) {
            require(guard.recordHostFrame(frame)
                    == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                            .SAME_STREAM_BLOCKED);
            require(!guard.isAutomaticStartAllowed());
        }
    }

    private static void authenticatedIntentRequiresConfirmedAbsence() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(900L);
        require(guard.markFormalSessionClosed(START_A, CHANNEL));
        require(guard.recordAuthenticatedHostStartIntent(CONNECTION_A, 1L)
                == AutomaticFormalUsageSessionGuard.HostStartIntentOutcome
                        .HOST_ABSENCE_NOT_CONFIRMED);
        require(!guard.recordHostAbsent(10_000L, 1_000L));
        require(guard.recordAuthenticatedHostStartIntent(CONNECTION_A, 1L)
                == AutomaticFormalUsageSessionGuard.HostStartIntentOutcome
                        .HOST_ABSENCE_NOT_CONFIRMED);
        require(guard.recordHostAbsent(11_000L, 1_000L));
        require(!guard.isAutomaticStartAllowed());
    }

    private static void authenticatedIntentRearmsExactlyOnce() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(1_000L);
        require(guard.markFormalSessionClosed(START_A, CHANNEL));
        confirmAbsence(guard, 20_000L);
        require(guard.recordAuthenticatedHostStartIntent(CONNECTION_A, 7L)
                == AutomaticFormalUsageSessionGuard.HostStartIntentOutcome
                        .NEW_START_INTENT_REARMED);
        require(guard.isAutomaticStartAllowed());
        require(guard.snapshot().lastHostStartIntentConnectionId
                == CONNECTION_A);
        require(guard.snapshot().lastHostStartIntentToken == 7L);
        require(guard.recordAuthenticatedHostStartIntent(CONNECTION_A, 7L)
                == AutomaticFormalUsageSessionGuard.HostStartIntentOutcome
                        .STATE_IGNORED);
    }

    private static void duplicateAuthenticatedIntentCannotRearmAgain() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(2_000L);
        require(guard.markFormalSessionClosed(START_A, CHANNEL));
        confirmAbsence(guard, 30_000L);
        require(guard.recordAuthenticatedHostStartIntent(CONNECTION_A, 9L)
                == AutomaticFormalUsageSessionGuard.HostStartIntentOutcome
                        .NEW_START_INTENT_REARMED);

        guard.reserveFormalStart(START_A, CHANNEL);
        guard.markFormalSessionOpened(START_A, CHANNEL);
        require(guard.markFormalSessionClosed(START_A, CHANNEL));
        confirmAbsence(guard, 40_000L);
        require(guard.recordAuthenticatedHostStartIntent(CONNECTION_A, 9L)
                == AutomaticFormalUsageSessionGuard.HostStartIntentOutcome
                        .DUPLICATE_IGNORED);
        require(!guard.isAutomaticStartAllowed());
        require(guard.recordAuthenticatedHostStartIntent(CONNECTION_A, 10L)
                == AutomaticFormalUsageSessionGuard.HostStartIntentOutcome
                        .NEW_START_INTENT_REARMED);
    }

    private static void invalidIntentEvidenceFailsClosed() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(300L);
        require(guard.blockPotentiallyBilledGeneration(START_A, CHANNEL));
        confirmAbsence(guard, 50_000L);
        require(guard.recordAuthenticatedHostStartIntent(0L, 1L)
                == AutomaticFormalUsageSessionGuard.HostStartIntentOutcome
                        .INVALID_IGNORED);
        require(guard.recordAuthenticatedHostStartIntent(CONNECTION_A, 0L)
                == AutomaticFormalUsageSessionGuard.HostStartIntentOutcome
                        .INVALID_IGNORED);
        require(guard.recordAuthenticatedHostStartIntent(CONNECTION_A, -1L)
                == AutomaticFormalUsageSessionGuard.HostStartIntentOutcome
                        .INVALID_IGNORED);
        require(!guard.isAutomaticStartAllowed());
    }

    private static void restoredProcessStateRequiresAuthenticatedIntent() {
        AutomaticFormalUsageSessionGuard guard =
                new AutomaticFormalUsageSessionGuard();
        guard.restoreBlocked(9_000L, true);
        require(!guard.isAutomaticStartAllowed());
        confirmAbsence(guard, 60_000L);
        require(guard.recordHostFrame(50L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                        .SAME_STREAM_BLOCKED);
        require(!guard.isAutomaticStartAllowed());
        confirmAbsence(guard, 70_000L);
        require(guard.recordAuthenticatedHostStartIntent(
                        CONNECTION_A + 1L, 1L)
                == AutomaticFormalUsageSessionGuard.HostStartIntentOutcome
                        .NEW_START_INTENT_REARMED);
        require(guard.isAutomaticStartAllowed());
    }

    private static void confirmAbsence(
            AutomaticFormalUsageSessionGuard guard,
            long startedAt) {
        require(!guard.recordHostAbsent(startedAt, 1_000L));
        require(guard.recordHostAbsent(startedAt + 1_000L, 1_000L));
    }

    private static AutomaticFormalUsageSessionGuard activeGuard(
            long frameSequence) {
        AutomaticFormalUsageSessionGuard guard =
                new AutomaticFormalUsageSessionGuard();
        guard.recordHostFrame(frameSequence);
        guard.reserveFormalStart(START_A, CHANNEL);
        guard.markFormalSessionOpened(START_A, CHANNEL);
        return guard;
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError(
                    "automatic formal usage session guard contract failed");
        }
    }
}
