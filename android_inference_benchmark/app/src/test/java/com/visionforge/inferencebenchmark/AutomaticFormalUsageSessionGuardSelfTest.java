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

    static void run() {
        initialGenerationIsArmed();
        preDebitReservationIsFailClosedAndCancellable();
        exactRetryRetainsItsReservationOwner();
        replacementCannotInheritAnOlderReservation();
        staleSettlementCannotMutateReplacementOwner();
        boundaryCloseDoesNotConsumeAnUnbilledExactRetry();
        startupWithoutProgressNeverTriggersProactiveStop();
        sustainedNoProgressStopsOnceOnlyAfterAProgressRenewal();
        sameHostStreamCannotCreateAnotherSession();
        boundaryClosedStreamRearmsAfterVerifiedPauseAndFreshProgress();
        delayedOldFrameCannotRearmSameStream();
        confirmedFrameResetRearmsExactlyOnce();
        rapidSecondRestartReplacesCandidateWithoutSequenceCatchup();
        lowSequenceGenerationCanStillRearm();
        naturalFrameWrapDoesNotRearm();
        unknownFrameEvidenceFailsClosed();
        restoredProcessStateRemainsBlocked();
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
        require(!guard.blockPotentiallyBilledGeneration(
                START_A, CHANNEL));
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

    private static void sameHostStreamCannotCreateAnotherSession() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(1_000L);
        guard.markProgressRenewed();
        guard.recordHostFrame(1_900L);
        require(guard.blockPotentiallyBilledGeneration(START_A, CHANNEL));
        require(!guard.blockPotentiallyBilledGeneration(START_A, CHANNEL));

        for (int maintenanceTick = 0; maintenanceTick < 40;
                maintenanceTick++) {
            require(!guard.isAutomaticStartAllowed());
            long frame = 1_901L + maintenanceTick;
            require(guard.recordHostFrame(frame)
                    == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                    .SAME_STREAM_BLOCKED);
        }
        require(!guard.isAutomaticStartAllowed());
        require(!guard.recordHostAbsent(1_000L, 1_000L));
        require(guard.recordHostAbsent(21_000L, 1_000L));
        require(guard.recordHostFrame(5_000L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .SAME_STREAM_BLOCKED);
        require(guard.recordHostFrame(1_925L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .SAME_STREAM_BLOCKED);
    }

    private static void boundaryClosedStreamRearmsAfterVerifiedPauseAndFreshProgress() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(1_000L);
        guard.markProgressRenewed();
        guard.recordHostFrame(1_900L);
        require(guard.markFormalSessionClosed(START_A, CHANNEL));

        // A continuously advancing stream cannot immediately create another
        // billable generation.  Once the Host has been absent long enough,
        // however, two strictly-forward observations prove that real work
        // resumed and must not leave control permanently fail-closed.
        require(guard.recordHostFrame(1_901L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .SAME_STREAM_BLOCKED);
        require(!guard.recordHostAbsent(10_000L, 1_000L));
        require(guard.recordHostAbsent(11_000L, 1_000L));
        require(guard.recordHostFrame(2_000L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .RESTART_CANDIDATE_RECORDED);
        require(!guard.isAutomaticStartAllowed());
        require(guard.recordHostFrame(2_001L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .NEW_STREAM_REARMED);
        require(guard.isAutomaticStartAllowed());
    }

    private static void confirmedFrameResetRearmsExactlyOnce() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(5_000L);
        guard.recordHostFrame(5_900L);
        require(guard.markFormalSessionClosed(START_A, CHANNEL));
        require(guard.recordHostFrame(5_850L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .SAME_STREAM_BLOCKED);
        require(!guard.recordHostAbsent(10_000L, 1_000L));
        require(guard.recordHostAbsent(11_000L, 1_000L));
        require(guard.recordHostFrame(20L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .RESTART_CANDIDATE_RECORDED);
        require(!guard.isAutomaticStartAllowed());
        require(guard.recordHostFrame(21L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .NEW_STREAM_REARMED);
        require(guard.isAutomaticStartAllowed());
        require(guard.recordHostFrame(22L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome.RECORDED);

        guard.reserveFormalStart(START_A, CHANNEL);
        guard.markFormalSessionOpened(START_A, CHANNEL);
        guard.recordHostFrame(800L);
        require(guard.markFormalSessionClosed(START_A, CHANNEL));
        require(!guard.isAutomaticStartAllowed());
        require(!guard.recordHostAbsent(20_000L, 1_000L));
        require(guard.recordHostAbsent(21_000L, 1_000L));
        require(guard.recordHostFrame(12L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .RESTART_CANDIDATE_RECORDED);
        require(guard.recordHostFrame(13L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .NEW_STREAM_REARMED);
    }

    private static void delayedOldFrameCannotRearmSameStream() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(1_000L);
        require(guard.blockPotentiallyBilledGeneration(START_A, CHANNEL));
        require(!guard.recordHostAbsent(1_000L, 1_000L));
        require(guard.recordHostAbsent(2_000L, 1_000L));
        require(guard.recordHostFrame(900L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .RESTART_CANDIDATE_RECORDED);
        require(guard.recordHostFrame(1_200L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .SAME_STREAM_BLOCKED);
        require(!guard.isAutomaticStartAllowed());
    }

    private static void rapidSecondRestartReplacesCandidateWithoutSequenceCatchup() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(50_000L);
        require(guard.markFormalSessionClosed(START_A, CHANNEL));
        require(!guard.recordHostAbsent(1_000L, 1_000L));
        require(guard.recordHostAbsent(2_000L, 1_000L));
        require(guard.recordHostFrame(5_000L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .RESTART_CANDIDATE_RECORDED);

        // A second click/restart can reset the Host sequence again before the
        // 5,000 candidate is confirmed.  Keep the absence proof, replace the
        // candidate, and require a distinct forward observation.
        require(guard.recordHostFrame(100L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .RESTART_CANDIDATE_RECORDED);
        require(guard.recordHostFrame(100L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .RESTART_CANDIDATE_RECORDED);
        require(!guard.isAutomaticStartAllowed());
        require(guard.recordHostFrame(101L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .NEW_STREAM_REARMED);
        require(guard.isAutomaticStartAllowed());
    }

    private static void lowSequenceGenerationCanStillRearm() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(50L);
        require(guard.markFormalSessionClosed(START_A, CHANNEL));
        require(!guard.recordHostAbsent(5_000L, 1_000L));
        require(guard.recordHostAbsent(6_000L, 1_000L));
        require(guard.recordHostFrame(5L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .RESTART_CANDIDATE_RECORDED);
        require(guard.recordHostFrame(15L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .NEW_STREAM_REARMED);
    }

    private static void naturalFrameWrapDoesNotRearm() {
        AutomaticFormalUsageSessionGuard guard = activeGuard(
                AutomaticFormalUsageSessionGuard.MAX_LOGICAL_FRAME_SEQUENCE
                        - 5L);
        require(guard.blockPotentiallyBilledGeneration(START_A, CHANNEL));
        require(!guard.recordHostAbsent(30_000L, 1_000L));
        require(guard.recordHostAbsent(31_000L, 1_000L));
        require(guard.recordHostFrame(5_000L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .SAME_STREAM_BLOCKED);
        require(!guard.isAutomaticStartAllowed());
        require(guard.recordHostFrame(90L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .SAME_STREAM_BLOCKED);
    }

    private static void unknownFrameEvidenceFailsClosed() {
        AutomaticFormalUsageSessionGuard guard =
                new AutomaticFormalUsageSessionGuard();
        guard.reserveFormalStart(START_A, CHANNEL);
        guard.markFormalSessionOpened(START_A, CHANNEL);
        require(guard.blockPotentiallyBilledGeneration(START_A, CHANNEL));
        require(!guard.recordHostAbsent(40_000L, 1_000L));
        require(guard.recordHostAbsent(41_000L, 1_000L));
        require(guard.recordHostFrame(-1L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .INVALID_IGNORED);
        require(guard.recordHostFrame(5L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .SAME_STREAM_BLOCKED);
        require(!guard.isAutomaticStartAllowed());
    }

    private static void restoredProcessStateRemainsBlocked() {
        AutomaticFormalUsageSessionGuard guard =
                new AutomaticFormalUsageSessionGuard();
        guard.restoreBlocked(9_000L);
        require(!guard.isAutomaticStartAllowed());

        // A long packet gap followed by the same forward-moving stream is not
        // a new billable generation.
        require(!guard.recordHostAbsent(50_000L, 1_000L));
        require(guard.recordHostAbsent(70_000L, 1_000L));
        require(guard.recordHostFrame(12_000L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .SAME_STREAM_BLOCKED);
        require(!guard.isAutomaticStartAllowed());

        // Only a later silence plus a confirmed sequence reset can re-arm.
        require(!guard.recordHostAbsent(80_000L, 1_000L));
        require(guard.recordHostAbsent(81_000L, 1_000L));
        require(guard.recordHostFrame(50L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .RESTART_CANDIDATE_RECORDED);
        require(guard.recordHostFrame(51L)
                == AutomaticFormalUsageSessionGuard.HostFrameOutcome
                .NEW_STREAM_REARMED);
        require(guard.isAutomaticStartAllowed());
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
