package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

/** Paid-start, progress-gated renewal, expiry and local-first stop contract. */
public final class DualMachineFormalUsageCoordinatorSelfTest {
    private static final String CHANNEL = "66".repeat(32);
    private static final String ENTITLEMENT_ID = "11".repeat(16);
    private static final String PAIR_ID = "22".repeat(16);
    private static final String SESSION_ID = "33".repeat(16);
    private static final String START_CHALLENGE_ID = "44".repeat(16);
    private static final String START_CHALLENGE_TOKEN = "A".repeat(43);
    private static final long SECOND_NANOS = 1_000_000_000L;

    private DualMachineFormalUsageCoordinatorSelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        verifiesExplicitPaidStartProgressRenewalAndLocalFirstStop();
        verifiesRenewalTimingSeparatesProofSidecarAndInstall();
        verifiesIndependentHostAndAndroidProgressEvidence();
        verifiesKnownAndroidPipelineRestartDoesNotLoseNextProgress();
        verifiesNoProgressMeansNoRenewalChargeAndExpiryCloses();
        verifiesAmbiguousStartRetriesExactRequestWithoutDoubleCharge();
        verifiesRepeatedAmbiguousStartRecoversExactRequestWithoutDoubleCharge();
        verifiesStaleRetryAdmissionCannotReplayLaterGeneration();
        verifiesAmbiguousStartRetry429CancelsOriginalExactly();
        verifiesAmbiguousStartRetryRuntimeFailureCancelsOriginalExactly();
        verifiesFreshHostVideoIsRequiredBeforeFirstDebit();
        verifiesPendingStartRetryRequiresFreshHostVideo();
        verifiesDeterministicStartRejectionClearsPendingGeneration();
        verifiesAmbiguousRenewalRetriesExactRequestWithoutDoubleCharge();
        verifiesUnsignedResponseMismatchNeverOpensDataPlane();
        verifiesInvalidCommittedLeaseSignatureCancelsExactly();
        verifiesRuntimeOpenFailureFailsClosed();
        verifiesStopRacingRuntimeOpenCannotReopenDataPlane();
        verifiesStagedLeaseBlocksSecondDebitUntilPromotion();
        verifiesFailedStagedLeaseActivationRetainsExactStopOwner();
        verifiesBothDeadlineOrdersContinueContiguousRenewal();
        verifiesLateFutureLeaseReopensAtNotBeforeWithoutAnotherDebit();
        verifiesDeadlineWatchdogAndRuntimeWindowContract();
        verifiesCancelledDeadlineCannotEnforceAfterLockHandoff();
        verifiesStopReportsRuntimeCloseFailureButStillClearsGate();
        verifiesAuthenticatedRevocationImmediatelyClosesRuntime();
        verifiesRuntimeLossStopsActiveSessionAfterLocalClosure();
        verifiesStopDuringReadinessNeverStartsBilling();
        verifiesCrossThreadStopCancelsBlockedReadiness();
        verifiesStopAfterChallengeNeverStartsBilling();
        verifiesStopBeforeCoordinatorEntryRequiresExplicitRearm();
        verifiesLaterRearmCannotReviveSupersededAdmission();
        verifiesStopBeforeGenerationPublicationConvergesExactly();
        verifiesBlockingStartReceivesExactCancellationBeforeReturning();
        verifiesPendingStartCancellationPreventsDebit();
        verifiesUndispatchedStartConvergesWithoutServerResponse();
        verifiesActiveLifecycleStopNeverCancelsCompletedStart();
        verifiesActiveStopResponseLossRetriesStopWithoutCancellation();
        verifiesRuntimeLossReusesPreparedStopAfterHostSignerDetaches();
        verifiesAuthoritativeCancellationBalanceDriftConverges();
        verifiesAmbiguousCancellationRetainsExactPendingUntilConfirmed();
        verifiesRuntimeLossRetainsAmbiguousExactCancellation();
        verifiesLateLeaseFallsBackToStartCancellationAndCachesConfirmation();
        verifiesDelayedCancellationHandleCannotTouchLaterGeneration();
        verifiesDelayedLifecycleHandleCannotCloseLaterGeneration();
        verifiesPermanentLeaseNeverDebits();
        System.out.println("DUAL_MACHINE_FORMAL_USAGE_COORDINATOR_OK");
    }

    private static void verifiesRenewalTimingSeparatesProofSidecarAndInstall()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);
        fixture.hostProgress.incrementAndGet();
        fixture.androidProgress.incrementAndGet();
        fixture.epoch.set(103L);
        fixture.monotonic.set(3L * SECOND_NANOS);
        fixture.runtime.usageSignerHook = () -> fixture.monotonic.addAndGet(
                TimeUnit.MILLISECONDS.toNanos(11L));
        fixture.sidecar.heartbeatHook = () -> fixture.monotonic.addAndGet(
                TimeUnit.MILLISECONDS.toNanos(22L));
        fixture.runtime.stageHook = () -> fixture.monotonic.addAndGet(
                TimeUnit.MILLISECONDS.toNanos(33L));

        check(fixture.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .FUTURE_STAGED);
        DualMachineFormalUsageCoordinator.RenewalTiming timing =
                fixture.coordinator.latestRenewalTiming();
        check(timing.attempted);
        check(timing.sequence == 1L);
        check(timing.proofMillis == 11L);
        check(timing.sidecarMillis == 22L);
        check(timing.installMillis == 33L);
        check(timing.totalMillis == 66L);
        check("completed".equals(timing.terminalPhase));
    }

    private static void verifiesPermanentLeaseNeverDebits()
            throws Exception {
        Fixture fixture = new Fixture(true);
        start(fixture.coordinator);
        check(fixture.state.snapshot().billingStarted);
        check(fixture.state.snapshot().remainingSeconds == 0L);
        check(fixture.state.snapshot().totalConsumedSeconds == 0L);
        fixture.hostProgress.incrementAndGet();
        fixture.androidProgress.incrementAndGet();
        fixture.epoch.set(103L);
        fixture.monotonic.set(3L * SECOND_NANOS);
        check(fixture.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .FUTURE_STAGED);
        check(fixture.state.snapshot().remainingSeconds == 0L);
        check(fixture.state.snapshot().totalConsumedSeconds == 0L);
        fixture.coordinator.stopForRuntimeLifecycle();
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(fixture.state.snapshot().canFormalStart());
    }

    private static void
            verifiesActiveLifecycleStopNeverCancelsCompletedStart()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);

        check(fixture.coordinator.capturePendingStartCancellation() == null);
        check(!fixture.coordinator.hasPendingStartCancellation());
        check(fixture.sidecar.startCancellations == 0);
        check(fixture.sidecar.serverSessionActive);

        DualMachineFormalUsageCoordinator.StopOutcome stopped =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(stopped.serverConfirmed);
        check(fixture.sidecar.stops == 1);
        check(fixture.sidecar.startCancellations == 0);
        check(!fixture.sidecar.serverSessionActive);
    }

    private static void
            verifiesActiveStopResponseLossRetriesStopWithoutCancellation()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);
        fixture.sidecar.stopResponsesToLoseAfterCommit = 1;

        DualMachineFormalUsageCoordinator.StopOutcome ambiguous =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(!ambiguous.serverConfirmed);
        check(fixture.sidecar.stops == 1);
        check(fixture.sidecar.startCancellations == 0);
        check(fixture.runtime.closeCalls == 1);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STOPPING);

        DualMachineFormalUsageCoordinator.StopOutcome recovered =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(recovered.serverConfirmed);
        check(fixture.sidecar.stops == 2);
        check(fixture.sidecar.startCancellations == 0);
        check(fixture.runtime.closeCalls == 1);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
    }

    private static void
            verifiesRuntimeLossReusesPreparedStopAfterHostSignerDetaches()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);
        fixture.sidecar.stopResponsesToLoseAfterCommit = 1;
        fixture.hostSignerAvailable.set(false);

        fixture.coordinator.failCloseFromRuntimeLoss();

        check(fixture.sidecar.stops == 1);
        check(fixture.sidecar.committedStopRequest != null);
        DualMachineSidecarPort.StopRequest prepared =
                fixture.sidecar.committedStopRequest;
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STOPPING);

        DualMachineFormalUsageCoordinator.StopOutcome recovered =
                fixture.coordinator.stopForRuntimeLifecycle();

        check(recovered.serverConfirmed);
        check(fixture.sidecar.stops == 2);
        check(fixture.sidecar.committedStopRequest == prepared);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
    }

    private static void
            verifiesCancelledDeadlineCannotEnforceAfterLockHandoff()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);
        fixture.monotonic.set(5L * SECOND_NANOS);
        Runnable deadline = fixture.deadlines.action;
        check(deadline != null);
        Field lockField = DualMachineFormalUsageCoordinator.class
                .getDeclaredField("runtimeTransitionLock");
        lockField.setAccessible(true);
        Object runtimeTransitionLock = lockField.get(fixture.coordinator);
        Thread deadlineThread = new Thread(deadline, "stale-deadline");
        int enforceBefore = fixture.runtime.enforceCalls;
        synchronized (runtimeTransitionLock) {
            deadlineThread.start();
            long waitUntil = System.nanoTime()
                    + TimeUnit.SECONDS.toNanos(5L);
            while (deadlineThread.getState() != Thread.State.BLOCKED
                    && System.nanoTime() < waitUntil) {
                Thread.onSpinWait();
            }
            check(deadlineThread.getState() == Thread.State.BLOCKED);
            fixture.coordinator.stopForRuntimeLifecycle();
        }
        deadlineThread.join(TimeUnit.SECONDS.toMillis(5L));
        check(!deadlineThread.isAlive());
        check(fixture.runtime.enforceCalls == enforceBefore);
    }

    private static void verifiesStopDuringReadinessNeverStartsBilling()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.runtime.prepareHook =
                fixture.coordinator::requestImmediateLocalStop;
        expectIo(() -> start(fixture.coordinator));
        check(fixture.sidecar.startChallenges == 0);
        check(fixture.sidecar.starts == 0);
        check(fixture.sidecar.startDebits == 0);
        check(fixture.runtime.openCalls == 0);
    }

    private static void verifiesCrossThreadStopCancelsBlockedReadiness()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.runtime.blockPreparationUntilClose = true;
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<Boolean> startFailedClosed = executor.submit(() -> {
                try {
                    start(fixture.coordinator);
                    return false;
                } catch (IOException expected) {
                    return true;
                } catch (GeneralSecurityException unexpected) {
                    throw new AssertionError(unexpected);
                }
            });
            check(fixture.runtime.preparationEntered.await(
                    5L, TimeUnit.SECONDS));
            fixture.coordinator.requestImmediateLocalStop();
            check(startFailedClosed.get(2L, TimeUnit.SECONDS));
            check(fixture.runtime.preparationCancellationObserved);
            check(fixture.runtime.closeCalls == 1);
            check(fixture.sidecar.startChallenges == 0);
            check(fixture.sidecar.starts == 0);
            check(fixture.sidecar.startDebits == 0);
        } finally {
            executor.shutdownNow();
        }
    }

    private static void verifiesStopAfterChallengeNeverStartsBilling()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.afterChallengeHook =
                fixture.coordinator::requestImmediateLocalStop;
        expectIo(() -> start(fixture.coordinator));
        check(fixture.sidecar.startChallenges == 1);
        check(fixture.sidecar.starts == 0);
        check(fixture.sidecar.startDebits == 0);
        check(fixture.runtime.openCalls == 0);
    }

    private static void
            verifiesStopBeforeGenerationPublicationConvergesExactly()
            throws Exception {
        AtomicReference<DualMachineFormalUsageCoordinator> coordinator =
                new AtomicReference<>();
        AtomicBoolean capturedNullGeneration = new AtomicBoolean();
        Fixture fixture = new Fixture(false, () -> {
            DualMachineFormalUsageCoordinator current = coordinator.get();
            current.requestImmediateLocalStop();
            check(current.capturePendingStartCancellation() == null);
            check(current.captureLifecycleStop() == null);
            capturedNullGeneration.set(true);
        }, 3);
        coordinator.set(fixture.coordinator);

        expectIo(() -> start(fixture.coordinator));

        check(capturedNullGeneration.get());
        check(fixture.sidecar.startDebits == 0);
        check(fixture.sidecar.starts == 0);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STOPPING);
        check(fixture.coordinator.capturePendingStartCancellation()
                != null);
        check(fixture.coordinator.captureLifecycleStop() != null);
        DualMachineFormalUsageCoordinator.StopOutcome stopped =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(stopped.serverConfirmed);
        check(fixture.sidecar.startCancellations == 1);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
    }

    private static void
            verifiesStopBeforeCoordinatorEntryRequiresExplicitRearm()
            throws Exception {
        Fixture fixture = new Fixture();
        DualMachineFormalUsageCoordinator.StartAdmissionToken staleAdmission =
                fixture.coordinator.prepareForNewFormalStart();
        fixture.coordinator.requestImmediateLocalStop();
        check(fixture.coordinator.capturePendingStartCancellation() == null);
        check(fixture.coordinator.captureLifecycleStop() == null);
        expectState(() -> fixture.coordinator
                .startAfterVerifiedHostVideo(staleAdmission));
        check(fixture.sidecar.startChallenges == 0);
        check(fixture.sidecar.starts == 0);
        check(fixture.sidecar.startDebits == 0);
        check(fixture.runtime.openCalls == 0);

        start(fixture.coordinator);
        check(fixture.sidecar.startDebits == 1);
        check(fixture.runtime.openCalls == 1);
    }

    private static void verifiesLaterRearmCannotReviveSupersededAdmission()
            throws Exception {
        Fixture fixture = new Fixture();
        ExecutorService executor = Executors.newFixedThreadPool(3);
        CountDownLatch firstPrepared = new CountDownLatch(1);
        CountDownLatch allowFirstEntry = new CountDownLatch(1);
        CountDownLatch stopCompleted = new CountDownLatch(1);
        CountDownLatch replacementPrepared = new CountDownLatch(1);
        CountDownLatch allowReplacementEntry = new CountDownLatch(1);
        try {
            Future<Throwable> firstStart = executor.submit(() -> {
                DualMachineFormalUsageCoordinator.StartAdmissionToken token =
                        fixture.coordinator.prepareForNewFormalStart();
                firstPrepared.countDown();
                awaitLatch(allowFirstEntry);
                try {
                    fixture.coordinator.startAfterVerifiedHostVideo(token);
                    return null;
                } catch (Throwable failure) {
                    return failure;
                }
            });
            Future<?> stop = executor.submit(() -> {
                awaitLatch(firstPrepared);
                fixture.coordinator.requestImmediateLocalStop();
                fixture.coordinator.stopForRuntimeLifecycle();
                stopCompleted.countDown();
            });
            Future<Throwable> replacementStart = executor.submit(() -> {
                awaitLatch(stopCompleted);
                DualMachineFormalUsageCoordinator.StartAdmissionToken token =
                        fixture.coordinator.prepareForNewFormalStart();
                replacementPrepared.countDown();
                awaitLatch(allowReplacementEntry);
                try {
                    fixture.coordinator.startAfterVerifiedHostVideo(token);
                    return null;
                } catch (Throwable failure) {
                    return failure;
                }
            });

            check(replacementPrepared.await(5L, TimeUnit.SECONDS));
            allowFirstEntry.countDown();
            check(firstStart.get(5L, TimeUnit.SECONDS)
                    instanceof IllegalStateException);
            check(fixture.sidecar.startChallenges == 0);
            check(fixture.sidecar.starts == 0);
            check(fixture.sidecar.startDebits == 0);
            check(fixture.runtime.openCalls == 0);

            allowReplacementEntry.countDown();
            check(replacementStart.get(5L, TimeUnit.SECONDS) == null);
            stop.get(5L, TimeUnit.SECONDS);
            check(fixture.sidecar.startChallenges == 1);
            check(fixture.sidecar.startDebits == 1);
            check(fixture.runtime.openCalls == 1);
        } finally {
            allowFirstEntry.countDown();
            stopCompleted.countDown();
            allowReplacementEntry.countDown();
            executor.shutdownNow();
            check(executor.awaitTermination(5L, TimeUnit.SECONDS));
        }
    }

    private static void verifiesPendingStartCancellationPreventsDebit()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.runtime.freshVideoHook = () -> {
            fixture.coordinator.requestImmediateLocalStop();
            check(fixture.coordinator.cancelPendingStart());
        };
        expectIo(() -> start(fixture.coordinator));
        check(fixture.sidecar.starts == 0);
        check(fixture.sidecar.startDebits == 0);
        check(fixture.sidecar.startCancellations == 1);
        check(fixture.sidecar.sawClosedBeforeCancellation);
        DualMachineFormalUsageCoordinator.StopOutcome stopped =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(stopped.serverConfirmed);
        check(stopped.remainingSeconds == 100L);
        check(fixture.sidecar.startCancellations == 2);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        expectState(() -> retry(fixture.coordinator));
    }

    private static void
            verifiesUndispatchedStartConvergesWithoutServerResponse()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.cancellationResponsesToLoseAfterCommit = 4;
        fixture.runtime.freshVideoHook =
                fixture.coordinator::requestImmediateLocalStop;

        expectIo(() -> start(fixture.coordinator));
        check(fixture.sidecar.starts == 0);
        check(fixture.sidecar.startDebits == 0);
        DualMachineFormalUsageCoordinator.StopOutcome stopped =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(!stopped.serverConfirmed);
        check(stopped.definitelyNotStarted);
        check(fixture.sidecar.startCancellations == 3);
        check(!fixture.coordinator.hasPendingStartCancellation());
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(fixture.state.snapshot().canFormalStart());
    }

    private static void
            verifiesBlockingStartReceivesExactCancellationBeforeReturning()
            throws Exception {
        Fixture fixture = new Fixture();
        CountDownLatch startUsageEntered = new CountDownLatch(1);
        CountDownLatch cancellationCommitted = new CountDownLatch(1);
        CountDownLatch allowStartUsageToReturn = new CountDownLatch(1);
        fixture.sidecar.beforeStartCommitHook = () -> {
            startUsageEntered.countDown();
            awaitLatch(cancellationCommitted);
            awaitLatch(allowStartUsageToReturn);
        };
        fixture.sidecar.afterCancellationCommitHook =
                cancellationCommitted::countDown;

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Throwable> start = executor.submit(() -> {
                try {
                    start(fixture.coordinator);
                    return null;
                } catch (Throwable failure) {
                    return failure;
                }
            });
            check(startUsageEntered.await(5L, TimeUnit.SECONDS));
            Future<DualMachineFormalUsageCoordinator.StopOutcome> stop =
                    executor.submit(
                            fixture.coordinator::stopForRuntimeLifecycle);

            check(cancellationCommitted.await(5L, TimeUnit.SECONDS));
            check(fixture.runtime.closed);
            check(fixture.sidecar.sawClosedBeforeCancellation);
            check(fixture.sidecar.committedCancellationRequest != null);
            check(fixture.sidecar.committedCancellationRequest.startRequestId
                    .equals(fixture.sidecar.startUsageRequestId));
            check(!fixture.sidecar.committedCancellationRequest.proof
                    .hostSignatureBase64.isEmpty());
            check(!fixture.sidecar.committedCancellationRequest.proof
                    .androidSignatureBase64.isEmpty());
            // cancelStart has returned while startUsage remains deliberately
            // blocked. The stop owner may now wait only for monitor-protected
            // state finalization, never for the tombstone itself.
            check(!start.isDone());
            check(!stop.isDone());

            allowStartUsageToReturn.countDown();
            check(start.get(5L, TimeUnit.SECONDS)
                    instanceof DualMachineFormalUsageCoordinator
                    .GenerationBoundRejectedException);
            DualMachineFormalUsageCoordinator.StopOutcome outcome =
                    stop.get(5L, TimeUnit.SECONDS);
            check(outcome.serverConfirmed);
            check(outcome.definitelyNotStarted);
            check(fixture.sidecar.startCancellations == 1);
            check(fixture.sidecar.startDebits == 0);
            check(!fixture.sidecar.serverSessionActive);
            check(fixture.runtime.openCalls == 0);
            check(!fixture.coordinator.hasPendingStartCancellation());
            check(fixture.state.snapshot().state
                    == DualMachineFormalUsageStateMachine.State
                    .ACTIVATED_IDLE);
        } finally {
            cancellationCommitted.countDown();
            allowStartUsageToReturn.countDown();
            executor.shutdownNow();
            check(executor.awaitTermination(5L, TimeUnit.SECONDS));
        }
    }

    private static void
            verifiesAuthoritativeCancellationBalanceDriftConverges()
            throws Exception {
        verifiesAuthoritativeNotStartedBalance(40L);
        verifiesAuthoritativeNotStartedBalance(140L);
    }

    private static void verifiesAuthoritativeNotStartedBalance(
            long authoritativeRemaining) throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.cancellationRemainingOverride =
                authoritativeRemaining;
        fixture.runtime.freshVideoHook = () -> {
            fixture.coordinator.requestImmediateLocalStop();
            check(fixture.coordinator.cancelPendingStart());
        };
        expectIo(() -> start(fixture.coordinator));
        DualMachineFormalUsageCoordinator.StopOutcome stopped =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(stopped.serverConfirmed);
        check(stopped.remainingSeconds == authoritativeRemaining);
        check(fixture.state.snapshot().remainingSeconds
                == authoritativeRemaining);
        check(fixture.sidecar.startDebits == 0);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
    }

    private static void
            verifiesAmbiguousCancellationRetainsExactPendingUntilConfirmed()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.startResponsesToLoseAfterCommit = 1;
        expectIo(() -> start(fixture.coordinator));
        check(fixture.sidecar.startDebits == 1);
        fixture.sidecar.cancellationResponsesToLoseAfterCommit = 4;
        fixture.coordinator.requestImmediateLocalStop();
        check(!fixture.coordinator.cancelPendingStart());
        DualMachineFormalUsageCoordinator.StopOutcome ambiguous =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(!ambiguous.serverConfirmed);
        check(fixture.sidecar.startCancellations == 4);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STOPPING);
        expectState(() -> retry(fixture.coordinator));

        DualMachineFormalUsageCoordinator.StopOutcome recovered =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(recovered.serverConfirmed);
        check(recovered.remainingSeconds == 95L);
        check(fixture.sidecar.startCancellations == 5);
        check(fixture.sidecar.starts == 1);
        check(fixture.sidecar.startDebits == 1);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
    }

    private static void
            verifiesLateLeaseFallsBackToStartCancellationAndCachesConfirmation()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.stopResponsesToLoseAfterCommit = 1;
        fixture.sidecar.afterStartCommitHook =
                fixture.coordinator::requestImmediateLocalStop;
        DualMachineFormalUsageCoordinator.StartCancelledException cancelled =
                expectStartCancelled(
                        () -> start(fixture.coordinator));
        check(cancelled.billingStarted);
        check(cancelled.serverConfirmed);
        check(fixture.sidecar.startDebits == 1);
        check(fixture.sidecar.stops == 0);
        check(fixture.sidecar.startCancellations == 1);
        check(fixture.runtime.openCalls == 0);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(fixture.coordinator.cancelPendingStart());

        DualMachineFormalUsageCoordinator.StopOutcome queuedOwner =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(queuedOwner.serverConfirmed);
        check(queuedOwner.remainingSeconds == 95L);
        check(fixture.sidecar.stops == 0);
        check(fixture.sidecar.startCancellations == 1);
    }

    private static void verifiesRuntimeLossRetainsAmbiguousExactCancellation()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.startResponsesToLoseAfterCommit = 1;
        expectIo(() -> start(fixture.coordinator));
        fixture.sidecar.cancellationResponsesToLoseAfterCommit = 3;

        fixture.coordinator.failCloseFromRuntimeLoss();

        check(fixture.runtime.closed);
        check(fixture.coordinator.hasPendingStartCancellation());
        check(fixture.sidecar.startCancellations == 3);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STOPPING);
        DualMachineFormalUsageCoordinator.StopOutcome recovered =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(recovered.serverConfirmed);
        check(fixture.sidecar.startCancellations == 4);
        check(!fixture.coordinator.hasPendingStartCancellation());
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
    }

    private static void
            verifiesDelayedCancellationHandleCannotTouchLaterGeneration()
            throws Exception {
        Fixture retired = new Fixture();
        retired.sidecar.startResponsesToLoseAfterCommit = 1;
        expectIo(() -> start(retired.coordinator));
        DualMachineFormalUsageCoordinator.StartCancellationHandle handle =
                retired.coordinator.capturePendingStartCancellation();
        check(handle != null);
        check(handle.startRequestId.equals(
                retired.sidecar.startUsageRequestId));

        ExecutorService cancellationExecutor =
                Executors.newSingleThreadExecutor();
        CountDownLatch blockerStarted = new CountDownLatch(1);
        CountDownLatch releaseBlocker = new CountDownLatch(1);
        try {
            Future<?> blocker = cancellationExecutor.submit(() -> {
                blockerStarted.countDown();
                try {
                    check(releaseBlocker.await(5L, TimeUnit.SECONDS));
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError(interrupted);
                }
            });
            Future<Boolean> delayedCancellation =
                    cancellationExecutor.submit(
                            handle::sendExactCancellation);
            check(blockerStarted.await(5L, TimeUnit.SECONDS));

            DualMachineFormalUsageCoordinator.StopOutcome retiredStop =
                    retired.coordinator.stopForRuntimeLifecycle();
            check(retiredStop.serverConfirmed);
            check(retired.sidecar.startCancellations == 1);

            Fixture current = new Fixture();
            start(current.coordinator);
            check(!current.runtime.closed);
            check(current.sidecar.startCancellations == 0);

            releaseBlocker.countDown();
            blocker.get(5L, TimeUnit.SECONDS);
            check(delayedCancellation.get(5L, TimeUnit.SECONDS));
            check(retired.sidecar.startCancellations == 2);
            check(current.sidecar.startCancellations == 0);
            check(!current.runtime.closed);
            check(current.state.snapshot().state
                    == DualMachineFormalUsageStateMachine.State.ACTIVE);
        } finally {
            releaseBlocker.countDown();
            cancellationExecutor.shutdownNow();
        }
    }

    private static void
            verifiesDelayedLifecycleHandleCannotCloseLaterGeneration()
            throws Exception {
        Fixture fixture = new Fixture();
        DualMachineFormalUsageCoordinator.DataPlanePermit first =
                start(fixture.coordinator);
        DualMachineFormalUsageCoordinator.LifecycleStopHandle stale =
                fixture.coordinator.captureLifecycleStop();
        check(stale != null);
        check(stale.startRequestId.equals(first.startRequestId));
        Field generationLockField = DualMachineFormalUsageCoordinator.class
                .getDeclaredField("generationStopLock");
        generationLockField.setAccessible(true);
        Object generationStopLock = generationLockField.get(
                fixture.coordinator);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        AtomicReference<Thread> delayedThread = new AtomicReference<>();
        CountDownLatch delayedEntered = new CountDownLatch(1);
        try {
            Future<DualMachineFormalUsageCoordinator.StopOutcome> delayedStop;
            DualMachineFormalUsageCoordinator.StopOutcome firstStop;
            int closesAfterReplacementOpen;
            int opensAfterReplacementOpen;
            synchronized (generationStopLock) {
                delayedStop = executor.submit(() -> {
                    delayedThread.set(Thread.currentThread());
                    delayedEntered.countDown();
                    return stale.stopFormalUsage();
                });
                check(delayedEntered.await(5L, TimeUnit.SECONDS));
                long waitUntil = System.nanoTime()
                        + TimeUnit.SECONDS.toNanos(5L);
                while (delayedThread.get().getState() != Thread.State.BLOCKED
                        && System.nanoTime() < waitUntil) {
                    Thread.onSpinWait();
                }
                check(delayedThread.get().getState() == Thread.State.BLOCKED);

                // Reentrant ownership lets the controller deterministically
                // complete A, publish B's admission, and open B while the old A
                // exact claim is queued at the same generation boundary.
                firstStop = fixture.coordinator.stopForRuntimeLifecycle();
                check(firstStop.serverConfirmed);
                fixture.sidecar.resetCommittedStartGeneration(
                        firstStop.remainingSeconds);
                fixture.sidecar.nextStartTotalConsumed = 10L;
                DualMachineFormalUsageCoordinator.StartAdmissionToken
                        replacementAdmission = fixture.coordinator
                        .prepareForNewFormalStart();
                int closesWhileReplacementPrepared =
                        fixture.runtime.closeCalls;
                check(stale.stopFormalUsage() == firstStop);
                check(fixture.runtime.closeCalls
                        == closesWhileReplacementPrepared);
                DualMachineFormalUsageCoordinator.DataPlanePermit replacement =
                        fixture.coordinator.startAfterVerifiedHostVideo(
                                replacementAdmission);
                check(!replacement.startRequestId.equals(stale.startRequestId));
                closesAfterReplacementOpen = fixture.runtime.closeCalls;
                opensAfterReplacementOpen = fixture.runtime.openCalls;
            }

            check(delayedStop.get(5L, TimeUnit.SECONDS) == firstStop);
            check(fixture.runtime.closeCalls == closesAfterReplacementOpen);
            check(fixture.runtime.openCalls == opensAfterReplacementOpen);
            check(!fixture.runtime.closed);
            check(fixture.state.snapshot().state
                    == DualMachineFormalUsageStateMachine.State.ACTIVE);
            check(fixture.coordinator.enforceAndGetDataPlanePermitState()
                    == DualMachineFormalUsageCoordinator
                    .DataPlanePermitState.OPEN);
        } finally {
            executor.shutdownNow();
            check(executor.awaitTermination(5L, TimeUnit.SECONDS));
        }
    }

    private static void
            verifiesAmbiguousStartRetriesExactRequestWithoutDoubleCharge()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.startResponsesToLoseAfterCommit = 1;
        expectIo(() -> start(fixture.coordinator));
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STARTING);
        check(fixture.runtime.openCalls == 0);
        DualMachineFormalUsageCoordinator.DataPlanePermit recovered =
                retry(fixture.coordinator);
        check(recovered.sequence == 0L);
        check(fixture.sidecar.starts == 2);
        check(fixture.sidecar.startDebits == 1);
        check(fixture.state.snapshot().remainingSeconds == 95L);
        check(fixture.runtime.openCalls == 1);
    }

    private static void
            verifiesStaleRetryAdmissionCannotReplayLaterGeneration()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.startResponsesToLoseAfterCommit = 1;
        expectIo(() -> start(fixture.coordinator));
        DualMachineFormalUsageCoordinator.RetryAdmissionToken staleRetry =
                fixture.coordinator.capturePendingStartRetryAdmission();
        DualMachineFormalUsageCoordinator.StopOutcome oldStop =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(oldStop.serverConfirmed);
        check(fixture.sidecar.startCancellations == 1);

        fixture.sidecar.resetCommittedStartGeneration(95L);
        fixture.sidecar.startResponsesToLoseAfterCommit = 1;
        expectIo(() -> start(fixture.coordinator));
        check(fixture.sidecar.starts == 2);
        check(fixture.sidecar.startDebits == 2);
        check(fixture.runtime.openCalls == 0);

        expectState(() -> fixture.coordinator.retryPendingStart(staleRetry));
        check(fixture.sidecar.starts == 2);
        check(fixture.sidecar.startDebits == 2);
        check(fixture.runtime.openCalls == 0);

        DualMachineFormalUsageCoordinator.DataPlanePermit current =
                retry(fixture.coordinator);
        check(current.sequence == 0L);
        check(fixture.sidecar.starts == 3);
        check(fixture.sidecar.startDebits == 2);
        check(fixture.runtime.openCalls == 1);
    }

    private static void
            verifiesRepeatedAmbiguousStartRecoversExactRequestWithoutDoubleCharge()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.startResponsesToLoseAfterCommit = 2;
        expectIo(() -> start(fixture.coordinator));
        expectIo(() -> retry(fixture.coordinator));
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STARTING);
        DualMachineFormalUsageCoordinator.DataPlanePermit recovered =
                retry(fixture.coordinator);
        check(recovered.sequence == 0L);
        check(fixture.sidecar.starts == 3);
        check(fixture.sidecar.startDebits == 1);
        check(fixture.state.snapshot().remainingSeconds == 95L);
        check(fixture.runtime.openCalls == 1);
    }

    private static void verifiesAmbiguousStartRetry429CancelsOriginalExactly()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.startResponsesToLoseAfterCommit = 1;
        expectIo(() -> start(fixture.coordinator));
        fixture.sidecar.rejectCommittedReplayStatus = 429;
        expectIo(() -> retry(fixture.coordinator));
        verifyAmbiguousRetryFailureCancelsOriginal(fixture);
    }

    private static void
            verifiesAmbiguousStartRetryRuntimeFailureCancelsOriginalExactly()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.startResponsesToLoseAfterCommit = 1;
        expectIo(() -> start(fixture.coordinator));
        fixture.sidecar.failCommittedReplayWithRuntime = true;
        expectRuntime(() -> retry(fixture.coordinator));
        verifyAmbiguousRetryFailureCancelsOriginal(fixture);
    }

    private static void verifyAmbiguousRetryFailureCancelsOriginal(
            Fixture fixture) {
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STOPPING);
        check(fixture.coordinator.hasPendingStartCancellation());
        check(fixture.runtime.closed);
        check(fixture.runtime.openCalls == 0);
        check(fixture.sidecar.starts == 2);
        check(fixture.sidecar.startDebits == 1);
        DualMachineFormalUsageCoordinator.StopOutcome stopped =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(stopped.serverConfirmed);
        check(fixture.sidecar.startCancellations == 1);
        check(!fixture.sidecar.serverSessionActive);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
    }

    private static void verifiesFreshHostVideoIsRequiredBeforeFirstDebit()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.runtime.failFreshVideoVerification = true;
        expectIo(() -> start(fixture.coordinator));
        check(fixture.sidecar.startChallenges == 1);
        check(fixture.sidecar.starts == 0);
        check(fixture.sidecar.startDebits == 0);
        check(fixture.runtime.freshVideoVerificationCalls == 1);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STARTING);

        fixture.runtime.failFreshVideoVerification = false;
        retry(fixture.coordinator);
        check(fixture.sidecar.starts == 1);
        check(fixture.sidecar.startDebits == 1);
        check(fixture.runtime.freshVideoVerificationCalls == 2);
    }

    private static void verifiesPendingStartRetryRequiresFreshHostVideo()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.startResponsesToLoseAfterCommit = 1;
        expectIo(() -> start(fixture.coordinator));
        check(fixture.sidecar.starts == 1);
        check(fixture.sidecar.startDebits == 1);

        fixture.runtime.failFreshVideoVerification = true;
        expectIo(() -> retry(fixture.coordinator));
        check(fixture.sidecar.starts == 1);
        check(fixture.sidecar.startDebits == 1);

        fixture.runtime.failFreshVideoVerification = false;
        retry(fixture.coordinator);
        check(fixture.sidecar.starts == 2);
        check(fixture.sidecar.startDebits == 1);
    }

    private static void
            verifiesDeterministicStartRejectionClearsPendingGeneration()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.rejectNextStartStatus = 409;
        try {
            start(fixture.coordinator);
            throw new AssertionError("dispatched rejection was accepted");
        } catch (DualMachineFormalUsageCoordinator
                         .GenerationBoundRejectedException rejected) {
            check(rejected.statusCode == 409);
            DualMachineFormalUsageCoordinator.StopOutcome settled =
                    rejected.terminalStartFailureHandle().settle();
            check(settled.serverConfirmed);
            check(settled.definitelyNotStarted);
        }
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(fixture.sidecar.startDebits == 0);
        check(fixture.runtime.openCalls == 0);
        expectState(() -> retry(fixture.coordinator));
    }

    private static void
            verifiesAmbiguousRenewalRetriesExactRequestWithoutDoubleCharge()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);
        fixture.hostProgress.incrementAndGet();
        fixture.androidProgress.incrementAndGet();
        fixture.epoch.set(103L);
        fixture.monotonic.set(3L * SECOND_NANOS);
        fixture.sidecar.loseFirstHeartbeatResponseAfterCommit = true;
        expectIo(fixture.coordinator::renewAfterObservedProgress);
        check(fixture.state.snapshot().remainingSeconds == 95L);
        expectState(fixture.coordinator::renewAfterObservedProgress);
        fixture.sidecar.heartbeatHook = () -> fixture.monotonic.addAndGet(
                TimeUnit.MILLISECONDS.toNanos(22L));
        fixture.runtime.stageHook = () -> fixture.monotonic.addAndGet(
                TimeUnit.MILLISECONDS.toNanos(33L));
        check(fixture.coordinator.retryPendingRenewal()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .FUTURE_STAGED);
        DualMachineFormalUsageCoordinator.RenewalTiming retryTiming =
                fixture.coordinator.latestRenewalTiming();
        check(retryTiming.attempted);
        check(retryTiming.sequence == 1L);
        check(retryTiming.proofMillis == 0L);
        check(retryTiming.sidecarMillis == 22L);
        check(retryTiming.installMillis == 33L);
        check(retryTiming.totalMillis == 55L);
        check("completed".equals(retryTiming.terminalPhase));
        check(fixture.sidecar.heartbeats == 2);
        check(fixture.sidecar.heartbeatDebits == 1);
        check(fixture.state.snapshot().remainingSeconds == 90L);
        check(fixture.runtime.stageCalls == 1);
    }

    private static void
            verifiesIndependentHostAndAndroidProgressEvidence()
            throws Exception {
        Fixture hostOnly = new Fixture();
        start(hostOnly.coordinator);
        hostOnly.hostProgress.incrementAndGet();
        check(hostOnly.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .NO_PROGRESS);
        DualMachineFormalUsageCoordinator.RenewalProgressObservation
                hostOnlyObservation = hostOnly.coordinator
                .latestRenewalProgressObservation();
        check(hostOnlyObservation.observedHostProgress == 1L);
        check(hostOnlyObservation.lastHostProgress == 0L);
        check(hostOnlyObservation.observedAndroidProgress == 0L);
        check(hostOnlyObservation.lastAndroidProgress == 0L);
        check(hostOnly.sidecar.heartbeats == 0);

        hostOnly.androidProgress.incrementAndGet();
        hostOnly.epoch.set(103L);
        hostOnly.monotonic.set(3L * SECOND_NANOS);
        check(hostOnly.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .FUTURE_STAGED);
        check(hostOnly.sidecar.heartbeats == 1);

        Fixture androidOnly = new Fixture();
        start(androidOnly.coordinator);
        androidOnly.androidProgress.incrementAndGet();
        check(androidOnly.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .NO_PROGRESS);
        DualMachineFormalUsageCoordinator.RenewalProgressObservation
                androidOnlyObservation = androidOnly.coordinator
                .latestRenewalProgressObservation();
        check(androidOnlyObservation.observedHostProgress == 0L);
        check(androidOnlyObservation.lastHostProgress == 0L);
        check(androidOnlyObservation.observedAndroidProgress == 1L);
        check(androidOnlyObservation.lastAndroidProgress == 0L);
        check(androidOnly.sidecar.heartbeats == 0);
    }

    private static void
            verifiesKnownAndroidPipelineRestartDoesNotLoseNextProgress()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);

        fixture.androidProgress.set(0L);
        fixture.coordinator.reconcileKnownAndroidPipelineRestart();

        fixture.hostProgress.incrementAndGet();
        fixture.androidProgress.incrementAndGet();
        fixture.epoch.set(103L);
        fixture.monotonic.set(3L * SECOND_NANOS);
        check(fixture.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .FUTURE_STAGED);
        check(fixture.sidecar.heartbeats == 1);
    }

    private static void
            verifiesExplicitPaidStartProgressRenewalAndLocalFirstStop()
            throws Exception {
        Fixture fixture = new Fixture();
        check(fixture.sidecar.startChallenges == 0);
        check(fixture.runtime.openCalls == 0);

        DualMachineFormalUsageCoordinator.DataPlanePermit permit =
                start(fixture.coordinator);
        check(permit.sequence == 0L);
        check(permit.sessionId.equals(SESSION_ID));
        check(permit.copySignedUsageLeaseUtf8().length > 100);
        check(!permit.toString().contains(
                new String(
                        permit.copySignedUsageLeaseUtf8(),
                        java.nio.charset.StandardCharsets.US_ASCII)));
        check(fixture.runtime.openCalls == 1);
        check(fixture.runtime.stageCalls == 0);
        check(fixture.coordinator.enforceAndGetDataPlanePermitState()
                == DualMachineFormalUsageCoordinator.DataPlanePermitState
                .OPEN);
        check(fixture.state.snapshot().billingStarted);
        check(fixture.state.snapshot().remainingSeconds == 95L);
        check(fixture.sidecar.startChallenges == 1);
        check(fixture.sidecar.starts == 1);
        check(fixture.sidecar.startChallengeRequestId.equals(
                fixture.sidecar.startUsageRequestId));
        check(fixture.sidecar.startChallengeRequestNonce.equals(
                fixture.sidecar.startUsageRequestNonce));
        check(!fixture.sidecar.startUsageRequestId.equals(
                fixture.sidecar.startUsageRequestNonce));

        check(fixture.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .NO_PROGRESS);
        check(fixture.sidecar.heartbeats == 0);
        fixture.hostProgress.incrementAndGet();
        fixture.androidProgress.incrementAndGet();
        fixture.epoch.set(103L);
        fixture.monotonic.set(3L * SECOND_NANOS);
        check(fixture.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .FUTURE_STAGED);
        check(fixture.runtime.openCalls == 1);
        check(fixture.runtime.stageCalls == 1);
        check(fixture.runtime.staged.sequence == 1L);
        check(fixture.runtime.staged.notBeforeMonotonicNanos
                == 5L * SECOND_NANOS);
        check(fixture.sidecar.heartbeats == 1);
        check(!fixture.sidecar.heartbeatRequestId.equals(
                fixture.sidecar.heartbeatRequestNonce));
        check(!fixture.sidecar.heartbeatRequestId.equals(
                fixture.sidecar.startUsageRequestId));
        check(!fixture.sidecar.heartbeatRequestNonce.equals(
                fixture.sidecar.startUsageRequestNonce));
        check(fixture.state.snapshot().remainingSeconds == 90L);

        fixture.monotonic.set(5L * SECOND_NANOS);
        fixture.deadlines.runDue();
        check(fixture.coordinator.enforceAndGetDataPlanePermitState()
                == DualMachineFormalUsageCoordinator.DataPlanePermitState
                .OPEN);
        check(fixture.runtime.openCalls == 2);
        DualMachineFormalUsageCoordinator.StopOutcome stopped =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(stopped.localClosed);
        check(stopped.serverConfirmed);
        check(stopped.remainingSeconds == 90L);
        check(fixture.sidecar.sawClosedBeforeStop);
        check(fixture.sidecar.stops == 1);
        check(fixture.sidecar.startCancellations == 0);
        check(!fixture.sidecar.stopRequestId.equals(
                fixture.sidecar.stopRequestNonce));
        check(!fixture.sidecar.stopRequestId.equals(
                fixture.sidecar.startUsageRequestId));
        check(!fixture.sidecar.stopRequestNonce.equals(
                fixture.sidecar.startUsageRequestNonce));
        check(!fixture.sidecar.stopRequestId.equals(
                fixture.sidecar.heartbeatRequestId));
        check(!fixture.sidecar.stopRequestNonce.equals(
                fixture.sidecar.heartbeatRequestNonce));
        check(fixture.runtime.closeCalls > 0);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(!fixture.state.snapshot().billingStarted);
        check(!fixture.state.snapshot().permitsDataPlane);
    }

    private static void
            verifiesNoProgressMeansNoRenewalChargeAndExpiryCloses()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);
        fixture.epoch.set(104L);
        fixture.monotonic.set(4L * SECOND_NANOS);
        check(fixture.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .NO_PROGRESS);
        check(fixture.sidecar.heartbeats == 0);
        check(fixture.state.snapshot().remainingSeconds == 95L);

        fixture.epoch.set(105L);
        fixture.monotonic.set(5L * SECOND_NANOS);
        fixture.deadlines.runDue();
        check(fixture.runtime.closed);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.RENEWAL_GAP);
        check(fixture.coordinator.enforceAndGetDataPlanePermitState()
                == DualMachineFormalUsageCoordinator.DataPlanePermitState
                .CLOSED);
        check(fixture.state.snapshot().remainingSeconds == 95L);
    }

    private static void verifiesUnsignedResponseMismatchNeverOpensDataPlane()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.mismatchUnsignedRemaining = true;
        expectSecurity(
                () -> start(fixture.coordinator));
        check(fixture.runtime.openCalls == 0);
        check(fixture.runtime.closed);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STOPPING);
        check(!fixture.state.snapshot().billingStarted);
        check(fixture.coordinator.hasPendingStartCancellation());
        check(fixture.sidecar.startDebits == 1);
        DualMachineFormalUsageCoordinator.StopOutcome stopped =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(stopped.serverConfirmed);
        check(fixture.sidecar.startCancellations == 1);
        check(!fixture.sidecar.serverSessionActive);
        check(!fixture.coordinator.hasPendingStartCancellation());
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
    }

    private static void verifiesInvalidCommittedLeaseSignatureCancelsExactly()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.sidecar.tamperInitialLeaseSignature = true;
        expectSecurity(() -> start(fixture.coordinator));
        check(fixture.runtime.openCalls == 0);
        check(fixture.runtime.closed);
        check(fixture.sidecar.startDebits == 1);
        check(fixture.coordinator.hasPendingStartCancellation());
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STOPPING);
        DualMachineFormalUsageCoordinator.StopOutcome stopped =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(stopped.serverConfirmed);
        check(fixture.sidecar.startCancellations == 1);
        check(fixture.sidecar.starts == 1);
        check(!fixture.sidecar.serverSessionActive);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
    }

    private static void verifiesRuntimeOpenFailureFailsClosed()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.runtime.failOpen = true;
        expectIo(() -> start(fixture.coordinator));
        check(fixture.runtime.openCalls == 1);
        check(fixture.runtime.closed);
        check(fixture.sidecar.startDebits == 1);
        check(fixture.sidecar.stops == 0);
        check(fixture.sidecar.startCancellations == 1);
        check(!fixture.sidecar.serverSessionActive);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(!fixture.state.snapshot().permitsDataPlane);
    }

    private static void verifiesStopRacingRuntimeOpenCannotReopenDataPlane()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.runtime.openHook =
                fixture.coordinator::requestImmediateLocalStop;
        expectIo(() -> start(fixture.coordinator));
        check(fixture.runtime.openCalls == 1);
        check(fixture.runtime.closed);
        check(fixture.sidecar.startDebits == 1);
        check(fixture.sidecar.stops == 0);
        check(fixture.sidecar.startCancellations == 1);
        check(!fixture.sidecar.serverSessionActive);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(!fixture.state.snapshot().permitsDataPlane);
    }

    private static void
            verifiesStagedLeaseBlocksSecondDebitUntilPromotion()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);
        fixture.hostProgress.incrementAndGet();
        fixture.androidProgress.incrementAndGet();
        fixture.epoch.set(103L);
        fixture.monotonic.set(3L * SECOND_NANOS);
        check(fixture.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .FUTURE_STAGED);
        fixture.hostProgress.incrementAndGet();
        fixture.androidProgress.incrementAndGet();
        fixture.epoch.set(104L);
        fixture.monotonic.set(4L * SECOND_NANOS);
        check(fixture.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .FUTURE_STAGED);
        check(fixture.sidecar.heartbeats == 1);
        check(fixture.sidecar.heartbeatDebits == 1);
    }

    private static void
            verifiesLateFutureLeaseReopensAtNotBeforeWithoutAnotherDebit()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);
        fixture.epoch.set(105L);
        fixture.monotonic.set(5L * SECOND_NANOS);
        fixture.deadlines.runDue();
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.RENEWAL_GAP);
        check(fixture.runtime.closed);

        fixture.hostProgress.incrementAndGet();
        fixture.androidProgress.incrementAndGet();
        fixture.sidecar.heartbeatIssuedAt = 106L;
        fixture.sidecar.heartbeatNotBefore = 107L;
        fixture.sidecar.heartbeatExpiresAt = 112L;
        fixture.epoch.set(106L);
        fixture.monotonic.set(6L * SECOND_NANOS);
        check(fixture.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .FUTURE_STAGED);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.RENEWAL_GAP);
        check(fixture.state.snapshot().leaseSequence == 1L);
        check(!fixture.state.snapshot().permitsDataPlane);
        check(fixture.deadlines.deadline == 7L * SECOND_NANOS);
        check(fixture.coordinator.enforceAndGetDataPlanePermitState()
                == DualMachineFormalUsageCoordinator.DataPlanePermitState
                .STAGED_WAITING);
        check(fixture.runtime.staged != null);
        check(fixture.sidecar.heartbeatDebits == 1);
        check(fixture.sidecar.stops == 0);

        fixture.epoch.set(107L);
        fixture.monotonic.set(7L * SECOND_NANOS);
        fixture.deadlines.runDue();
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVE);
        check(fixture.state.snapshot().permitsDataPlane);
        check(fixture.coordinator.enforceAndGetDataPlanePermitState()
                == DualMachineFormalUsageCoordinator.DataPlanePermitState
                .OPEN);
        check(fixture.runtime.openCalls == 2);
        check(SESSION_ID.equals(fixture.runtime.active.sessionId));
        check(fixture.sidecar.heartbeats == 1);
        check(fixture.sidecar.heartbeatDebits == 1);
        check(fixture.sidecar.stops == 0);
        check(fixture.deadlines.deadline == 12L * SECOND_NANOS);
    }

    private static void
            verifiesFailedStagedLeaseActivationRetainsExactStopOwner()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);
        fixture.hostProgress.incrementAndGet();
        fixture.androidProgress.incrementAndGet();
        fixture.epoch.set(103L);
        fixture.monotonic.set(3L * SECOND_NANOS);
        check(fixture.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .FUTURE_STAGED);
        check(fixture.sidecar.serverSessionActive);

        fixture.runtime.failOpen = true;
        fixture.epoch.set(105L);
        fixture.monotonic.set(5L * SECOND_NANOS);
        check(fixture.coordinator.enforceAndGetDataPlanePermitState()
                == DualMachineFormalUsageCoordinator.DataPlanePermitState
                .CLOSED);
        check(fixture.runtime.closed);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STOPPING);
        check(fixture.coordinator.captureLifecycleStop() != null);
        check(fixture.sidecar.serverSessionActive);

        DualMachineFormalUsageCoordinator.StopOutcome stopped =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(stopped.serverConfirmed);
        check(fixture.sidecar.stops == 1);
        check(!fixture.sidecar.serverSessionActive);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
    }

    private static void verifiesBothDeadlineOrdersContinueContiguousRenewal()
            throws Exception {
        verifyDeadlineOrderContinuesContiguousRenewal(false);
        verifyDeadlineOrderContinuesContiguousRenewal(true);
    }

    private static void verifyDeadlineOrderContinuesContiguousRenewal(
            boolean coordinatorHealthFirst) throws Exception {
        Fixture fixture = new Fixture();
        DualMachineFormalUsageCoordinator.DataPlanePermit initial =
                start(fixture.coordinator);
        fixture.hostProgress.incrementAndGet();
        fixture.androidProgress.incrementAndGet();
        fixture.sidecar.heartbeatIssuedAt = 101L;
        fixture.sidecar.heartbeatNotBefore = 105L;
        fixture.sidecar.heartbeatExpiresAt = 110L;
        fixture.epoch.set(101L);
        fixture.monotonic.set(3L * SECOND_NANOS);
        check(fixture.coordinator.renewAfterObservedProgress()
                == DualMachineFormalUsageCoordinator.RenewalOutcome
                .FUTURE_STAGED);

        fixture.epoch.set(103L);
        fixture.monotonic.set(5L * SECOND_NANOS);
        if (coordinatorHealthFirst) {
            check(fixture.coordinator.enforceAndGetDataPlanePermitState()
                    == DualMachineFormalUsageCoordinator
                    .DataPlanePermitState.OPEN);
        } else {
            fixture.deadlines.runDue();
            check(fixture.coordinator.enforceAndGetDataPlanePermitState()
                    == DualMachineFormalUsageCoordinator
                    .DataPlanePermitState.OPEN);
        }
        check(!fixture.runtime.closed);
        check(fixture.runtime.staged == null);
        check(fixture.runtime.closeCalls == 0);
        check(fixture.runtime.openCalls == 2);
        check(fixture.runtime.active != null);
        check(fixture.runtime.active.notBeforeMonotonicNanos
                == 5L * SECOND_NANOS);
        check(fixture.runtime.active.expiresAtMonotonicNanos
                == 10L * SECOND_NANOS);
        check(fixture.deadlines.deadline == 10L * SECOND_NANOS);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVE);
        check(initial.sessionId.equals(
                fixture.state.snapshot().sessionId));
        check(fixture.sidecar.heartbeats == 1);
        check(fixture.sidecar.heartbeatDebits == 1);
        check(fixture.sidecar.stops == 0);
    }

    private static void verifiesDeadlineWatchdogAndRuntimeWindowContract()
            throws Exception {
        Fixture fixture = new Fixture();
        DualMachineFormalUsageCoordinator.DataPlanePermit initial =
                start(fixture.coordinator);
        check(initial.notBeforeMonotonicNanos == 0L);
        check(initial.expiresAtMonotonicNanos == 5L * SECOND_NANOS);
        check(fixture.deadlines.deadline == 5L * SECOND_NANOS);
        fixture.epoch.set(105L);
        fixture.monotonic.set(5L * SECOND_NANOS);
        fixture.deadlines.runDue();
        check(fixture.runtime.closed);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.RENEWAL_GAP);
    }

    private static void
            verifiesStopReportsRuntimeCloseFailureButStillClearsGate()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);
        fixture.runtime.failClose = true;
        DualMachineFormalUsageCoordinator.StopOutcome stopped =
                fixture.coordinator.stopForRuntimeLifecycle();
        check(!stopped.localClosed);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(!fixture.state.snapshot().permitsDataPlane);
        check(fixture.deadlines.action == null);
    }

    private static void
            verifiesAuthenticatedRevocationImmediatelyClosesRuntime()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);
        fixture.coordinator.failCloseFromEntitlementRevocation();
        check(fixture.runtime.closed);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.REVOKED);
        check(!fixture.state.snapshot().permitsDataPlane);
        check(fixture.deadlines.action == null);
        expectIo(fixture.coordinator::renewAfterObservedProgress);
    }

    private static void
            verifiesRuntimeLossStopsActiveSessionAfterLocalClosure()
            throws Exception {
        Fixture fixture = new Fixture();
        start(fixture.coordinator);
        fixture.coordinator.failCloseFromRuntimeLoss();
        check(fixture.runtime.closed);
        check(fixture.sidecar.stops == 1);
        check(fixture.sidecar.sawClosedBeforeStop);
        check(!fixture.sidecar.serverSessionActive);
        check(fixture.state.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(!fixture.state.snapshot().billingStarted);
        check(!fixture.state.snapshot().permitsDataPlane);
        check(fixture.deadlines.action == null);
        expectIo(fixture.coordinator::renewAfterObservedProgress);
    }

    private static final class Fixture {
        final KeyPair hostIdentity = ecKeyPair();
        final KeyPair androidIdentity = ecKeyPair();
        final KeyPair leaseSigningKey = rsaKeyPair();
        final AtomicLong epoch = new AtomicLong(100L);
        final AtomicLong monotonic = new AtomicLong();
        final AtomicLong hostProgress = new AtomicLong(10L);
        final AtomicLong androidProgress = new AtomicLong(20L);
        final AtomicBoolean hostSignerAvailable = new AtomicBoolean(true);
        final FakeRuntime runtime = new FakeRuntime(monotonic);
        final FakeDeadlineScheduler deadlines =
                new FakeDeadlineScheduler(monotonic);
        final DualMachineFormalUsageStateMachine state =
                new DualMachineFormalUsageStateMachine();
        final DualMachineEntitlementRecord entitlement;
        final FakeSidecar sidecar;
        final DualMachineFormalUsageCoordinator coordinator;

        Fixture() throws Exception {
            this(false);
        }

        Fixture(boolean permanent) throws Exception {
            this(permanent, null, -1);
        }

        Fixture(
                boolean permanent,
                Runnable idSourceHook,
                int hookCall) throws Exception {
            DualMachineCardAuthorizationCoordinator.IdentityBinding host =
                    identity(
                            "HOST-DEVICE",
                            "17.8.81",
                            hostIdentity,
                            hostSignerAvailable,
                            runtime);
            DualMachineCardAuthorizationCoordinator.IdentityBinding android =
                    identity("ANDROID-DEVICE", "1.0.0", androidIdentity);
            entitlement = new DualMachineEntitlementRecord(
                    ENTITLEMENT_ID,
                    PAIR_ID,
                    2,
                    1L,
                    host.keyFingerprintSha256,
                    host.peerIdentity.identityPublicKeyBase64,
                    android.keyFingerprintSha256,
                    "visionforge-dual-machine-pairing-identity",
                    permanent ? "permanent" : "day",
                    permanent ? "permanent" : "day",
                    permanent,
                    false);
            state.beginCardActivation();
            state.activationConfirmed(
                    entitlement, permanent ? 0L : 100L, 0L, false);
            sidecar = new FakeSidecar(
                    leaseSigningKey,
                    runtime,
                    host.keyFingerprintSha256,
                    android.keyFingerprintSha256,
                    permanent);
            ArrayDeque<String> ids = new ArrayDeque<>();
            for (int value = 7; value < 30; value++) {
                ids.add(String.format(
                        java.util.Locale.ROOT, "%02x", value)
                        .repeat(16));
            }
            AtomicInteger idCalls = new AtomicInteger();
            coordinator = new DualMachineFormalUsageCoordinator(
                    sidecar,
                    state,
                    new DualMachineUsageLeaseKeyring(
                            Collections.singletonList(
                                    leaseSigningKey.getPublic()),
                            5),
                    host,
                    android,
                    runtime,
                    () -> {
                        int call = idCalls.incrementAndGet();
                        if (idSourceHook != null && call == hookCall) {
                            idSourceHook.run();
                        }
                        return ids.remove();
                    },
                    epoch::get,
                    monotonic::get,
                    deadlines,
                    hostProgress::get,
                    androidProgress::get);
        }
    }

    private static final class FakeRuntime
            implements DualMachineFormalUsageCoordinator.RuntimeBoundary {
        int openCalls;
        int stageCalls;
        int closeCalls;
        int enforceCalls;
        boolean closed = true;
        boolean failOpen;
        boolean failClose;
        boolean failFreshVideoVerification;
        boolean blockPreparationUntilClose;
        volatile boolean preparationCancellationObserved;
        int freshVideoVerificationCalls;
        final CountDownLatch preparationEntered = new CountDownLatch(1);
        final CountDownLatch preparationClosed = new CountDownLatch(1);
        Runnable prepareHook;
        Runnable freshVideoHook;
        Runnable openHook;
        Runnable stageHook;
        Runnable usageSignerHook;
        private final AtomicLong monotonic;
        DualMachineFormalUsageCoordinator.DataPlanePermit active;
        DualMachineFormalUsageCoordinator.DataPlanePermit staged;
        volatile String installedUsageLeaseSha256 = "";

        FakeRuntime(AtomicLong monotonic) {
            this.monotonic = monotonic;
        }

        @Override
        public DualMachineFormalUsageCoordinator.StartReadiness
                prepareWithDataPlaneClosed(
                BooleanSupplier cancellationRequested) throws IOException {
            check(closed);
            if (prepareHook != null) {
                Runnable hook = prepareHook;
                prepareHook = null;
                hook.run();
            }
            if (blockPreparationUntilClose) {
                preparationEntered.countDown();
                try {
                    if (!preparationClosed.await(5L, TimeUnit.SECONDS)) {
                        throw new IOException(
                                "simulated preparation close timed out");
                    }
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IOException(
                            "simulated preparation was interrupted",
                            interrupted);
                }
            }
            if (cancellationRequested.getAsBoolean()) {
                preparationCancellationObserved = true;
                throw new IOException("simulated preparation cancellation");
            }
            return new DualMachineFormalUsageCoordinator.StartReadiness(
                    CHANNEL, true, true);
        }

        @Override
        public void verifyFreshHostVideoBeforePotentialDebit(
                String expectedChannelBindingSha256,
                String expectedStartRequestId,
                BooleanSupplier cancellationRequested) throws IOException {
            freshVideoVerificationCalls++;
            if (cancellationRequested.getAsBoolean()) {
                throw new IOException("simulated video verification cancellation");
            }
            check(CHANNEL.equals(expectedChannelBindingSha256));
            check(expectedStartRequestId != null
                    && !expectedStartRequestId.isEmpty());
            if (freshVideoHook != null) {
                Runnable hook = freshVideoHook;
                freshVideoHook = null;
                hook.run();
            }
            if (failFreshVideoVerification) {
                throw new IOException("simulated Host video loss");
            }
        }

        @Override
        public void openDataPlane(
                DualMachineFormalUsageCoordinator.DataPlanePermit permit)
                throws IOException {
            openCalls++;
            if (failOpen) throw new IOException("simulated open failure");
            check(permit != null);
            check(monotonic.get() >= permit.notBeforeMonotonicNanos);
            check(monotonic.get() < permit.expiresAtMonotonicNanos);
            active = permit;
            if (staged != null && staged.sequence == permit.sequence) {
                staged = null;
            }
            installedUsageLeaseSha256 = permit.leaseSha256;
            closed = false;
            if (openHook != null) {
                Runnable hook = openHook;
                openHook = null;
                hook.run();
            }
        }

        @Override
        public void stageFutureLease(
                DualMachineFormalUsageCoordinator.DataPlanePermit permit) {
            stageCalls++;
            check(permit.notBeforeMonotonicNanos > monotonic.get());
            check(permit.expiresAtMonotonicNanos
                    > permit.notBeforeMonotonicNanos);
            if (stageHook != null) stageHook.run();
            staged = permit;
            installedUsageLeaseSha256 = permit.leaseSha256;
        }

        @Override
        public DualMachineFormalUsageCoordinator.DataPlanePermitState
                enforceLeaseWindow() {
            enforceCalls++;
            long now = monotonic.get();
            if (staged != null
                    && now >= staged.notBeforeMonotonicNanos) {
                active = staged;
                staged = null;
                closed = false;
            }
            if (active == null
                    || now < active.notBeforeMonotonicNanos
                    || now >= active.expiresAtMonotonicNanos) {
                active = null;
                closed = true;
                if (staged != null
                        && now < staged.notBeforeMonotonicNanos
                        && now < staged.expiresAtMonotonicNanos) {
                    return DualMachineFormalUsageCoordinator
                            .DataPlanePermitState.STAGED_WAITING;
                }
                return DualMachineFormalUsageCoordinator
                        .DataPlanePermitState.CLOSED;
            }
            return closed
                    ? DualMachineFormalUsageCoordinator
                    .DataPlanePermitState.CLOSED
                    : DualMachineFormalUsageCoordinator
                    .DataPlanePermitState.OPEN;
        }

        @Override
        public void closeDataPlane() {
            closeCalls++;
            preparationClosed.countDown();
            if (failClose) {
                throw new IllegalStateException(
                        "simulated close failure");
            }
            active = null;
            staged = null;
            closed = true;
        }

        @Override
        public void finalizeFormalGeneration(
                String expectedStartRequestId,
                String expectedChannelBindingSha256,
                DualMachineFormalUsageCoordinator.StopOutcome outcome) {
            check(expectedStartRequestId != null
                    && !expectedStartRequestId.isEmpty());
        }
    }

    private static final class FakeDeadlineScheduler
            implements DualMachineFormalUsageCoordinator.DeadlineScheduler {
        private final AtomicLong monotonic;
        long deadline = -1L;
        Runnable action;

        FakeDeadlineScheduler(AtomicLong monotonic) {
            this.monotonic = monotonic;
        }

        @Override
        public ScheduledDeadline scheduleAt(
                long deadlineMonotonicNanos,
                Runnable scheduledAction) {
            check(deadlineMonotonicNanos > monotonic.get());
            check(scheduledAction != null);
            deadline = deadlineMonotonicNanos;
            action = scheduledAction;
            return () -> {
                action = null;
                deadline = -1L;
            };
        }

        void runDue() {
            check(action != null);
            check(monotonic.get() >= deadline);
            Runnable due = action;
            action = null;
            deadline = -1L;
            due.run();
        }
    }

    private static final class FakeSidecar
            implements DualMachineSidecarPort {
        private final KeyPair signingKey;
        private final FakeRuntime runtime;
        private final String hostFingerprint;
        private final String androidFingerprint;
        private final boolean permanent;
        private String currentToken = "";
        int startChallenges;
        int starts;
        int heartbeats;
        int startDebits;
        int heartbeatDebits;
        int stops;
        int startCancellations;
        boolean mismatchUnsignedRemaining;
        boolean tamperInitialLeaseSignature;
        long cancellationRemainingOverride = -1L;
        int startResponsesToLoseAfterCommit;
        int cancellationResponsesToLoseAfterCommit;
        int stopResponsesToLoseAfterCommit;
        int rejectNextStartStatus;
        int rejectCommittedReplayStatus;
        boolean failCommittedReplayWithRuntime;
        boolean loseFirstHeartbeatResponseAfterCommit;
        boolean serverSessionActive;
        Runnable heartbeatHook;
        Runnable afterChallengeHook;
        Runnable beforeStartCommitHook;
        Runnable afterStartCommitHook;
        Runnable afterCancellationCommitHook;
        boolean sawClosedBeforeStop;
        boolean sawClosedBeforeCancellation;
        long heartbeatIssuedAt = 103L;
        long heartbeatNotBefore = 105L;
        long heartbeatExpiresAt = 110L;
        String startChallengeRequestId = "";
        String startChallengeRequestNonce = "";
        String startUsageRequestId = "";
        String startUsageRequestNonce = "";
        String heartbeatRequestId = "";
        String heartbeatRequestNonce = "";
        String stopRequestId = "";
        String stopRequestNonce = "";
        StartUsageRequest committedStartRequest;
        StartCancellationRequest committedCancellationRequest;
        StopRequest committedStopRequest;
        StartCancellationRequest retiredCancellationRequest;
        HeartbeatRequest committedHeartbeatRequest;
        UsageLeaseResponse committedStartResponse;
        StartCancellationResponse committedCancellationResponse;
        StartCancellationResponse retiredCancellationResponse;
        UsageLeaseResponse committedHeartbeatResponse;
        long currentRemaining = 100L;
        long initialLeaseRemaining = 95L;
        long nextStartTotalConsumed = -1L;

        FakeSidecar(
                KeyPair signingKey,
                FakeRuntime runtime,
                String hostFingerprint,
                String androidFingerprint,
                boolean permanent) {
            this.signingKey = signingKey;
            this.runtime = runtime;
            this.hostFingerprint = hostFingerprint;
            this.androidFingerprint = androidFingerprint;
            this.permanent = permanent;
        }

        @Override
        public PairGenerationChallengeResponse createPairGenerationChallenge(
                PairGenerationChallengeRequest request) {
            throw new AssertionError("unexpected pair-generation challenge");
        }

        @Override
        public PairGenerationCredentialResponse issuePairGenerationCredential(
                PairGenerationCredentialRequest request) {
            throw new AssertionError("unexpected pair-generation credential");
        }

        void resetCommittedStartGeneration(long remainingBeforeStart) {
            retiredCancellationRequest = committedCancellationRequest;
            retiredCancellationResponse = committedCancellationResponse;
            currentToken = "";
            startChallengeRequestId = "";
            startChallengeRequestNonce = "";
            startUsageRequestId = "";
            startUsageRequestNonce = "";
            committedStartRequest = null;
            committedCancellationRequest = null;
            committedStopRequest = null;
            committedStartResponse = null;
            committedCancellationResponse = null;
            serverSessionActive = false;
            currentRemaining = remainingBeforeStart;
            initialLeaseRemaining = remainingBeforeStart - 5L;
        }

        @Override
        public StartChallengeResponse createStartChallenge(
                StartChallengeRequest request) {
            startChallenges++;
            check(request.channelBindingSha256.equals(CHANNEL));
            checkDistinctRequestIdentity(request.requestId,
                    request.requestNonce);
            startChallengeRequestId = request.requestId;
            startChallengeRequestNonce = request.requestNonce;
            if (afterChallengeHook != null) {
                Runnable hook = afterChallengeHook;
                afterChallengeHook = null;
                hook.run();
            }
            return new StartChallengeResponse(
                    START_CHALLENGE_ID,
                    START_CHALLENGE_TOKEN,
                    200L);
        }

        @Override
        public UsageLeaseResponse startUsage(StartUsageRequest request)
                throws IOException {
            starts++;
            if (rejectNextStartStatus > 0
                    && committedStartResponse == null) {
                int status = rejectNextStartStatus;
                rejectNextStartStatus = 0;
                throw new DualMachineSidecarPort.RejectedException(status);
            }
            if (committedStartResponse != null) {
                check(request == committedStartRequest);
                if (rejectCommittedReplayStatus > 0) {
                    int status = rejectCommittedReplayStatus;
                    rejectCommittedReplayStatus = 0;
                    throw new DualMachineSidecarPort.RejectedException(
                            status);
                }
                if (failCommittedReplayWithRuntime) {
                    failCommittedReplayWithRuntime = false;
                    throw new IllegalStateException(
                            "simulated post-commit replay failure");
                }
                if (startResponsesToLoseAfterCommit > 0) {
                    startResponsesToLoseAfterCommit--;
                    throw new IOException(
                            "simulated replayed start response loss");
                }
                return committedStartResponse;
            }
            if (committedCancellationResponse != null
                    && "not_started".equals(
                    committedCancellationResponse.sessionStatus)) {
                throw new DualMachineSidecarPort.RejectedException(
                        409, "usage_start_cancelled");
            }
            check(request.hostFramesTotal == 0L);
            check(request.androidFramesTotal == 0L);
            check(request.hostRuntimeReady);
            check(request.androidRuntimeReady);
            checkDistinctRequestIdentity(request.requestId,
                    request.requestNonce);
            check(request.requestId.equals(startChallengeRequestId));
            check(request.requestNonce.equals(startChallengeRequestNonce));
            startUsageRequestId = request.requestId;
            startUsageRequestNonce = request.requestNonce;
            if (beforeStartCommitHook != null) {
                Runnable hook = beforeStartCommitHook;
                beforeStartCommitHook = null;
                hook.run();
            }
            // A cancelStart tombstone that wins while startUsage is in flight
            // prevents the server fixture from creating a late paid session.
            if (committedCancellationResponse != null
                    && "not_started".equals(
                    committedCancellationResponse.sessionStatus)) {
                throw new DualMachineSidecarPort.RejectedException(
                        409, "usage_start_cancelled");
            }
            try {
                committedStartRequest = request;
                committedStartResponse = lease(
                        0L, 100L, 100L, 105L,
                        DualMachineUsageLeaseGate
                                .EMPTY_PREVIOUS_LEASE_SHA256,
                        permanent ? 0L
                                : (mismatchUnsignedRemaining
                                ? initialLeaseRemaining - 1L
                                : initialLeaseRemaining),
                        permanent ? 0L
                                : (nextStartTotalConsumed >= 0L
                                ? nextStartTotalConsumed : 5L));
                if (tamperInitialLeaseSignature) {
                    committedStartResponse = tamperedLease(
                            committedStartResponse);
                }
                startDebits++;
                nextStartTotalConsumed = -1L;
                serverSessionActive = true;
                if (afterStartCommitHook != null) {
                    Runnable hook = afterStartCommitHook;
                    afterStartCommitHook = null;
                    hook.run();
                }
                if (startResponsesToLoseAfterCommit > 0) {
                    startResponsesToLoseAfterCommit--;
                    throw new IOException(
                            "simulated start response loss");
                }
                return committedStartResponse;
            } catch (Exception exception) {
                if (exception instanceof IOException) {
                    throw (IOException) exception;
                }
                throw new IOException(exception);
            }
        }

        @Override
        public StartCancellationResponse cancelStart(
                StartCancellationRequest request) throws IOException {
            startCancellations++;
            if (request == retiredCancellationRequest) {
                check(retiredCancellationResponse != null);
                return retiredCancellationResponse;
            }
            sawClosedBeforeCancellation = runtime.closed;
            checkDistinctRequestIdentity(
                    request.requestId, request.requestNonce);
            check(request.startRequestId.equals(startChallengeRequestId));
            check(!request.requestId.equals(request.startRequestId));
            check(!request.requestNonce.equals(request.startRequestId));
            check(!request.requestId.equals(startChallengeRequestNonce));
            check(!request.requestNonce.equals(startChallengeRequestNonce));
            if (committedCancellationRequest != null) {
                check(request == committedCancellationRequest);
            } else {
                committedCancellationRequest = request;
                boolean started = committedStartResponse != null;
                serverSessionActive = false;
                long cancellationRemaining =
                        cancellationRemainingOverride >= 0L
                                ? cancellationRemainingOverride
                                : (started ? currentRemaining : 100L);
                committedCancellationResponse = new StartCancellationResponse(
                        request.startRequestId,
                        started ? SESSION_ID : "",
                        started ? "ended" : "not_started",
                        permanent ? 0L
                                : cancellationRemaining,
                        0L,
                        started,
                        permanent ? "permanent" : "day",
                        permanent);
            }
            if (afterCancellationCommitHook != null) {
                Runnable hook = afterCancellationCommitHook;
                afterCancellationCommitHook = null;
                hook.run();
            }
            if (cancellationResponsesToLoseAfterCommit > 0) {
                cancellationResponsesToLoseAfterCommit--;
                throw new IOException(
                        "simulated start cancellation response loss");
            }
            return committedCancellationResponse;
        }

        private UsageLeaseResponse tamperedLease(
                UsageLeaseResponse response) throws Exception {
            int lastIndex = response.usageLease.length() - 1;
            char replacement = response.usageLease.charAt(lastIndex) == 'A'
                    ? 'B' : 'A';
            String tampered = response.usageLease.substring(0, lastIndex)
                    + replacement;
            return new UsageLeaseResponse(
                    response.sessionId,
                    response.sequence,
                    response.chargedSeconds,
                    response.remainingSeconds,
                    response.totalConsumedSeconds,
                    tampered,
                    sha256(tampered),
                    response.notBeforeEpoch,
                    response.expiresAtEpoch,
                    response.ttlSeconds,
                    response.billingStarted,
                    response.authorizationKind,
                    response.productKey,
                    response.permanent);
        }

        @Override
        public UsageLeaseResponse heartbeat(HeartbeatRequest request)
                throws IOException {
            heartbeats++;
            if (heartbeatHook != null) heartbeatHook.run();
            if (committedHeartbeatResponse != null) {
                check(request == committedHeartbeatRequest);
                return committedHeartbeatResponse;
            }
            check(request.sequence == 1L);
            check(request.hostFramesTotal > 0L);
            check(request.androidFramesTotal > 0L);
            check(request.previousLease.equals(currentToken));
            checkDistinctRequestIdentity(request.requestId,
                    request.requestNonce);
            check(!request.requestId.equals(startUsageRequestId));
            check(!request.requestNonce.equals(startUsageRequestNonce));
            heartbeatRequestId = request.requestId;
            heartbeatRequestNonce = request.requestNonce;
            try {
                committedHeartbeatRequest = request;
                committedHeartbeatResponse = lease(
                        1L,
                        heartbeatIssuedAt,
                        heartbeatNotBefore,
                        heartbeatExpiresAt,
                        sha256(currentToken),
                        permanent ? 0L : 90L,
                        permanent ? 0L : 10L);
                heartbeatDebits++;
                if (loseFirstHeartbeatResponseAfterCommit) {
                    throw new IOException(
                            "simulated heartbeat response loss");
                }
                return committedHeartbeatResponse;
            } catch (Exception exception) {
                if (exception instanceof IOException) {
                    throw (IOException) exception;
                }
                throw new IOException(exception);
            }
        }

        @Override
        public StopResponse stop(StopRequest request) throws IOException {
            stops++;
            if (committedStopRequest == null) {
                committedStopRequest = request;
            } else {
                check(request == committedStopRequest);
            }
            serverSessionActive = false;
            sawClosedBeforeStop = runtime.closed;
            check(request.previousLease.equals(currentToken));
            checkDistinctRequestIdentity(request.requestId,
                    request.requestNonce);
            check(!request.requestId.equals(startUsageRequestId));
            check(!request.requestNonce.equals(startUsageRequestNonce));
            stopRequestId = request.requestId;
            stopRequestNonce = request.requestNonce;
            if (stopResponsesToLoseAfterCommit > 0) {
                stopResponsesToLoseAfterCommit--;
                throw new IOException("simulated stop response loss");
            }
            return new StopResponse(
                    SESSION_ID,
                    "ended",
                    currentRemaining,
                    0L,
                    true,
                    permanent ? "permanent" : "day",
                    permanent);
        }

        private UsageLeaseResponse lease(
                long sequence,
                long issuedAt,
                long notBefore,
                long expiresAt,
                String previousSha256,
                long responseRemaining,
                long totalConsumed) throws Exception {
            DualMachineUsageLeaseSelfTestSupport.LeaseData data =
                    DualMachineUsageLeaseSelfTestSupport.initial(
                            issuedAt, notBefore, expiresAt);
            data.entitlementId = ENTITLEMENT_ID;
            data.pairId = PAIR_ID;
            data.sessionId = SESSION_ID;
            return finishLease(
                    data,
                    sequence,
                    previousSha256,
                    responseRemaining,
                    totalConsumed);
        }

        private UsageLeaseResponse finishLease(
                DualMachineUsageLeaseSelfTestSupport.LeaseData data,
                long sequence,
                String previousSha256,
                long responseRemaining,
                long totalConsumed) throws Exception {
            data.hostKeySha256 = hostFingerprint;
            data.androidKeySha256 = androidFingerprint;
            data.channelBindingSha256 = CHANNEL;
            data.previousLeaseSha256 = previousSha256;
            data.sequence = sequence;
            data.authorizationKind = permanent ? "permanent" : "day";
            data.permanent = permanent;
            data.remainingSeconds = permanent
                    ? 0L : (sequence == 0L
                    ? initialLeaseRemaining : responseRemaining);
            currentRemaining = data.remainingSeconds;
            currentToken = DualMachineUsageLeaseSelfTestSupport.token(
                    signingKey, data);
            return new UsageLeaseResponse(
                    SESSION_ID,
                    sequence,
                    permanent ? 0L : 5L,
                    responseRemaining,
                    totalConsumed,
                    currentToken,
                    sha256(currentToken),
                    data.notBefore,
                    data.expiresAt,
                    5L,
                    true,
                    permanent ? "permanent" : "day",
                    permanent ? "permanent" : "day",
                    permanent);
        }

        @Override
        public ActivationChallengeResponse createActivationChallenge(
                ActivationChallengeRequest request) {
            throw new AssertionError("formal use cannot activate cards");
        }

        @Override
        public ActivationResponse confirmActivation(
                ActivationConfirmationRequest request) {
            throw new AssertionError("formal use cannot activate cards");
        }

        @Override
        public EntitlementStatusResponse fetchEntitlementStatus(
                EntitlementStatusRequest request) {
            throw new AssertionError("formal use cannot refresh status");
        }
    }

    private static DualMachineCardAuthorizationCoordinator.IdentityBinding
            identity(String device, String version, KeyPair pair)
            throws Exception {
        return identity(device, version, pair, new AtomicBoolean(true));
    }

    private static DualMachineCardAuthorizationCoordinator.IdentityBinding
            identity(
                    String device,
                    String version,
                    KeyPair pair,
                    AtomicBoolean signerAvailable)
            throws Exception {
        return identity(
                device, version, pair, signerAvailable, null);
    }

    private static DualMachineCardAuthorizationCoordinator.IdentityBinding
            identity(
                    String device,
                    String version,
                    KeyPair pair,
                    AtomicBoolean signerAvailable,
                    FakeRuntime hostRuntime)
            throws Exception {
        DualMachineCardAuthorizationCoordinator.IdentityBinding binding =
                new DualMachineCardAuthorizationCoordinator.IdentityBinding(
                        device,
                        version,
                        DualMachinePairingIdentityCodec.encodePublicKeyBase64(
                                pair.getPublic().getEncoded()),
                        payload -> {
                            if (!signerAvailable.get()) {
                                throw new GeneralSecurityException(
                                        "simulated detached Host signer");
                            }
                            String canonical = new String(
                                    payload, StandardCharsets.UTF_8);
                            if (hostRuntime != null
                                    && canonical.contains(
                                    DualMachineUsageAuthorizationContract
                                            .USAGE_HEARTBEAT_DOMAIN)
                                    && hostRuntime.usageSignerHook != null) {
                                hostRuntime.usageSignerHook.run();
                            }
                            if (hostRuntime != null
                                    && canonical.contains(
                                    DualMachineUsageAuthorizationContract
                                            .USAGE_STOP_DOMAIN)) {
                                String installedLease = hostRuntime
                                        .installedUsageLeaseSha256;
                                if (installedLease.isEmpty()
                                        || !canonical.contains(
                                        "\"previous_lease_sha256\":\""
                                                + installedLease + "\"")) {
                                    throw new GeneralSecurityException(
                                            "Host stop signer has no matching "
                                            + "installed usage lease");
                                }
                            }
                            return DualMachinePairingIdentityCodec.sign(
                                    pair.getPrivate(), payload);
                        });
        return binding;
    }

    private static KeyPair ecKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(
                    DualMachinePairingIdentityCodec.CURVE_NAME));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new AssertionError(exception);
        }
    }

    private static KeyPair rsaKeyPair() {
        try {
            return DualMachineUsageLeaseSelfTestSupport.rsaKeyPair(3072);
        } catch (Exception exception) {
            throw new AssertionError(exception);
        }
    }

    private static String sha256(String value) throws Exception {
        return DualMachineUsageLeaseSelfTestSupport.sha256Hex(
                value.getBytes(StandardCharsets.US_ASCII));
    }

    private static DualMachineFormalUsageCoordinator.DataPlanePermit start(
            DualMachineFormalUsageCoordinator coordinator)
            throws Exception {
        DualMachineFormalUsageCoordinator.StartAdmissionToken admission =
                coordinator.prepareForNewFormalStart();
        return coordinator.startAfterVerifiedHostVideo(admission);
    }

    private static DualMachineFormalUsageCoordinator.DataPlanePermit retry(
            DualMachineFormalUsageCoordinator coordinator)
            throws Exception {
        DualMachineFormalUsageCoordinator.RetryAdmissionToken admission =
                coordinator.capturePendingStartRetryAdmission();
        return coordinator.retryPendingStart(admission);
    }

    private static void awaitLatch(CountDownLatch latch) {
        try {
            check(latch.await(5L, TimeUnit.SECONDS));
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new AssertionError(failure);
        }
    }

    private static void expectSecurity(Action action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected security rejection");
        } catch (GeneralSecurityException expected) {
            // Expected.
        }
    }

    private static void expectIo(Action action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected runtime failure");
        } catch (IOException expected) {
            // Expected.
        }
    }

    private static void expectRuntime(Action action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected runtime failure");
        } catch (RuntimeException expected) {
            // Expected.
        }
    }

    private static DualMachineFormalUsageCoordinator.StartCancelledException
            expectStartCancelled(Action action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected late start cancellation");
        } catch (DualMachineFormalUsageCoordinator
                         .StartCancelledException expected) {
            return expected;
        }
    }

    private static void expectState(Action action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected pending-state rejection");
        } catch (IllegalStateException expected) {
            // Expected.
        }
    }

    private static void check(boolean condition) {
        if (!condition) {
            throw new AssertionError("formal usage check failed");
        }
    }

    private static void checkDistinctRequestIdentity(
            String requestId,
            String requestNonce) {
        check(requestId != null);
        check(requestNonce != null);
        check(!requestId.equals(requestNonce));
    }

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }
}
