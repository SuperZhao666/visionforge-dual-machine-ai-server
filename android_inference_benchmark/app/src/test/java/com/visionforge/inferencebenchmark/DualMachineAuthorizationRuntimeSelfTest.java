package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.lang.reflect.Field;
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
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;

/** Service facade restore, attachment, activation and detach contracts. */
public final class DualMachineAuthorizationRuntimeSelfTest {
    private static final String CARD =
            "VFD2-9FW4B-TVHCV-B7EKW-YHVHR-E77GF-Z5MYW";
    private static final String CHANNEL = "66".repeat(32);
    private static final String ENTITLEMENT_ID = "11".repeat(16);

    private DualMachineAuthorizationRuntimeSelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        KeyPair hostPair = ecKeyPair();
        KeyPair androidPair = ecKeyPair();
        DualMachineCardAuthorizationCoordinator.IdentityBinding host =
                identity("HOST-DEVICE", "17.8.81", hostPair);
        DualMachineCardAuthorizationCoordinator.IdentityBinding android =
                identity("ANDROID-DEVICE", "1.0.0", androidPair);
        InMemoryEntitlementStore entitlementStore =
                new InMemoryEntitlementStore();
        InMemoryPendingStore pendingStore = new InMemoryPendingStore();
        ActivationSidecar sidecar = new ActivationSidecar(host, android);
        FakeRuntimeBoundary boundary = new FakeRuntimeBoundary();
        AtomicBoolean authenticated = new AtomicBoolean(true);
        AtomicLong hostProgress = new AtomicLong();
        AtomicLong androidProgress = new AtomicLong();
        AtomicLong monotonicNanos = new AtomicLong();
        ArrayDeque<String> ids = new ArrayDeque<>();
        for (int value = 0x22; value < 0x80; value++) {
            ids.add(String.format("%032x", value));
        }

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(DualMachineUsageLeaseVerifier.MINIMUM_RSA_BITS);
        DualMachineAuthorizationRuntime runtime =
                new DualMachineAuthorizationRuntime(
                        sidecar,
                        new DualMachineFormalUsageStateMachine(),
                        new DualMachineUsageLeaseKeyring(
                                Collections.singletonList(
                                        rsa.generateKeyPair().getPublic()),
                                5),
                        entitlementStore,
                        pendingStore,
                        android,
                        "visionforge-dual-machine-pairing-identity",
                        ids::remove,
                        monotonicNanos::get,
                        (deadline, action) -> () -> { },
                        androidProgress::get);

        expectSecurity(() -> runtime.activateCard(CARD));
        runtime.attachAuthenticatedHost(
                new DualMachineAuthorizationRuntime.Attachment(
                        host,
                        CHANNEL,
                        boundary,
                        authenticated::get,
                        hostProgress::get,
                        () -> 100L));
        check(runtime.hasAuthenticatedHost());
        runtime.activateCard(CARD);
        DualMachineFormalUsageStateMachine.Snapshot activated =
                runtime.snapshot();
        check(activated.state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(activated.remainingSeconds == 86_400L);
        check(!activated.billingStarted);
        check(!activated.permitsDataPlane);
        check(entitlementStore.record != null);

        verifiesStatusErrorReleasesRuntimeOwner(runtime, sidecar);
        verifiesCompletedStopEpochSupersedesStaleStartAdmission(
                runtime, sidecar, boundary);
        verifiesHostReplacementSupersedesStaleStartAdmission(
                runtime,
                sidecar,
                host,
                authenticated,
                hostProgress);
        verifiesStaleRevocationCannotReachReplacement(
                runtime,
                sidecar,
                entitlementStore,
                host,
                authenticated,
                hostProgress);
        verifiesReplacementDoesNotPublishNewOwnerBeforeOldCleanup(
                runtime,
                sidecar,
                host,
                authenticated,
                hostProgress);
        verifiesDetachCancelsInFlightReplacementPublication(
                runtime,
                sidecar,
                host,
                authenticated,
                hostProgress);
        verifiesDetachCleanupBlocksConcurrentReattachment(
                runtime,
                sidecar,
                host,
                authenticated,
                hostProgress);
        verifiesRetiredCoordinatorCannotCloseReplacement(
                runtime,
                host,
                authenticated,
                hostProgress);
        verifiesReceiptBoundStopClaimCannotReachReplacement(
                runtime,
                host,
                authenticated,
                hostProgress);
        verifiesCurrentStopRetryBackoff(
                runtime,
                sidecar,
                monotonicNanos);
        verifiesRetiringCancellationRetriesThroughMaintenance(
                runtime,
                sidecar,
                host,
                authenticated,
                hostProgress,
                monotonicNanos);

        runtime.detachAuthenticatedHost();
        check(!runtime.hasAuthenticatedHost());
        check(boundary.closeCalls > 0);
        check(runtime.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(!runtime.snapshot().permitsDataPlane);

        KeyPair wrongHostPair = ecKeyPair();
        DualMachineCardAuthorizationCoordinator.IdentityBinding wrongHost =
                identity("HOST-OTHER", "17.8.81", wrongHostPair);
        expectSecurity(() -> runtime.attachAuthenticatedHost(
                new DualMachineAuthorizationRuntime.Attachment(
                        wrongHost,
                        CHANNEL,
                        boundary,
                        () -> true,
                        hostProgress::get,
                        () -> 100L)));
        runtime.attachAuthenticatedHost(
                new DualMachineAuthorizationRuntime.Attachment(
                        host,
                        CHANNEL,
                        new FakeRuntimeBoundary(),
                        authenticated::get,
                        hostProgress::get,
                        () -> 100L));
        verifiesClosedRuntimeRejectsGenerationReceipt(runtime, sidecar);
        check(!runtime.hasAuthenticatedHost());
        verifiesCrashSafePersistedActivationReconciliation(
                host, android, rsa);
        System.out.println("DUAL_MACHINE_AUTHORIZATION_RUNTIME_OK");
    }

    private static void
            verifiesCompletedStopEpochSupersedesStaleStartAdmission(
            DualMachineAuthorizationRuntime runtime,
            ActivationSidecar sidecar,
            FakeRuntimeBoundary boundary) throws Exception {
        CountDownLatch statusEntered = new CountDownLatch(1);
        CountDownLatch releaseStatus = new CountDownLatch(1);
        sidecar.statusHook = () -> {
            statusEntered.countDown();
            awaitUnchecked(releaseStatus);
        };
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<Throwable> staleStart = executor.submit(() -> {
                try {
                    runtime.startFormalUsage();
                    return null;
                } catch (Throwable failure) {
                    return failure;
                }
            });
            check(statusEntered.await(5L, TimeUnit.SECONDS));

            DualMachineAuthorizationRuntime.FormalUsageLifecycleHandle
                    emptyStop = runtime.beginFormalUsageLifecycleStop();
            check(!emptyStop.hasFormalGeneration());
            check(emptyStop.startCancellationHandle() == null);
            check(emptyStop.stopFormalUsage() == null);

            releaseStatus.countDown();
            Throwable staleFailure = staleStart.get(5L, TimeUnit.SECONDS);
            check(staleFailure instanceof IllegalStateException);
            check(sidecar.startChallenges == 0);
            check(sidecar.starts == 0);
            check(sidecar.startDebits == 0);
            check(boundary.openCalls == 0);

            expectRejected(runtime::startFormalUsage, 409);
            check(sidecar.startChallenges == 1);
            check(sidecar.starts == 0);
            check(sidecar.startDebits == 0);
            check(boundary.openCalls == 0);
        } finally {
            releaseStatus.countDown();
            executor.shutdownNow();
            check(executor.awaitTermination(5L, TimeUnit.SECONDS));
        }
    }

    private static void
            verifiesHostReplacementSupersedesStaleStartAdmission(
            DualMachineAuthorizationRuntime runtime,
            ActivationSidecar sidecar,
            DualMachineCardAuthorizationCoordinator.IdentityBinding host,
            AtomicBoolean authenticated,
            AtomicLong hostProgress) throws Exception {
        CountDownLatch statusEntered = new CountDownLatch(1);
        CountDownLatch releaseStatus = new CountDownLatch(1);
        CountDownLatch replacementStatusEntered = new CountDownLatch(1);
        CountDownLatch releaseReplacementStatus = new CountDownLatch(1);
        sidecar.statusHook = () -> {
            statusEntered.countDown();
            awaitUnchecked(releaseStatus);
        };
        int challengesBefore = sidecar.startChallenges;
        int startsBefore = sidecar.starts;
        int debitsBefore = sidecar.startDebits;
        FakeRuntimeBoundary replacementBoundary =
                new FakeRuntimeBoundary();
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Throwable> staleStart = executor.submit(() -> {
                try {
                    runtime.startFormalUsage();
                    return null;
                } catch (Throwable failure) {
                    return failure;
                }
            });
            check(statusEntered.await(5L, TimeUnit.SECONDS));

            runtime.attachAuthenticatedHost(
                    new DualMachineAuthorizationRuntime.Attachment(
                            host,
                            CHANNEL,
                            replacementBoundary,
                            authenticated::get,
                            hostProgress::get,
                            () -> 100L));

            check(runtime.snapshot().state
                    == DualMachineFormalUsageStateMachine.State
                    .ACTIVATED_IDLE);
            check(replacementBoundary.closeCalls == 0);

            sidecar.statusHook = () -> {
                replacementStatusEntered.countDown();
                awaitUnchecked(releaseReplacementStatus);
            };
            Future<DualMachineFormalUsageStateMachine.Snapshot>
                    replacementStatus = executor.submit(
                    runtime::refreshStatus);
            check(replacementStatusEntered.await(5L, TimeUnit.SECONDS));
            check(runtime.snapshot().state
                    == DualMachineFormalUsageStateMachine.State
                    .STATUS_REFRESHING);

            releaseStatus.countDown();
            Throwable staleFailure = staleStart.get(5L, TimeUnit.SECONDS);
            check(staleFailure instanceof IllegalStateException);
            check(runtime.snapshot().state
                    == DualMachineFormalUsageStateMachine.State
                    .STATUS_REFRESHING);
            releaseReplacementStatus.countDown();
            check(replacementStatus.get(5L, TimeUnit.SECONDS).state
                    == DualMachineFormalUsageStateMachine.State
                    .ACTIVATED_IDLE);
            check(sidecar.startChallenges == challengesBefore);
            check(sidecar.starts == startsBefore);
            check(sidecar.startDebits == debitsBefore);
            check(replacementBoundary.openCalls == 0);
            check(replacementBoundary.closeCalls == 0);

            expectRejected(runtime::startFormalUsage, 409);
            check(sidecar.startChallenges == challengesBefore + 1);
            check(sidecar.starts == startsBefore);
            check(sidecar.startDebits == debitsBefore);
            check(replacementBoundary.openCalls == 0);
        } finally {
            releaseStatus.countDown();
            releaseReplacementStatus.countDown();
            executor.shutdownNow();
            check(executor.awaitTermination(5L, TimeUnit.SECONDS));
        }
    }

    private static void verifiesStatusErrorReleasesRuntimeOwner(
            DualMachineAuthorizationRuntime runtime,
            ActivationSidecar sidecar) throws Exception {
        Error injected = new AssertionError("injected runtime status error");
        sidecar.statusHook = () -> {
            throw injected;
        };
        expectError(runtime::refreshStatus, injected);
        check(runtime.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(runtime.refreshStatus().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
    }

    private static void verifiesStaleRevocationCannotReachReplacement(
            DualMachineAuthorizationRuntime runtime,
            ActivationSidecar sidecar,
            InMemoryEntitlementStore entitlementStore,
            DualMachineCardAuthorizationCoordinator.IdentityBinding host,
            AtomicBoolean authenticated,
            AtomicLong hostProgress) throws Exception {
        CountDownLatch statusEntered = new CountDownLatch(1);
        CountDownLatch releaseStatus = new CountDownLatch(1);
        sidecar.statusHook = () -> {
            statusEntered.countDown();
            awaitUnchecked(releaseStatus);
        };
        int challengesBefore = sidecar.startChallenges;
        int startsBefore = sidecar.starts;
        int debitsBefore = sidecar.startDebits;
        FakeRuntimeBoundary replacementBoundary =
                new FakeRuntimeBoundary();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<Throwable> staleStart = executor.submit(() -> {
                try {
                    runtime.startFormalUsage();
                    return null;
                } catch (Throwable failure) {
                    return failure;
                }
            });
            check(statusEntered.await(5L, TimeUnit.SECONDS));
            runtime.attachAuthenticatedHost(
                    new DualMachineAuthorizationRuntime.Attachment(
                            host,
                            CHANNEL,
                            replacementBoundary,
                            authenticated::get,
                            hostProgress::get,
                            () -> 100L));
            check(runtime.snapshot().state
                    == DualMachineFormalUsageStateMachine.State
                    .ACTIVATED_IDLE);

            sidecar.status = "revoked";
            sidecar.statusRevision = 2L;
            releaseStatus.countDown();
            check(staleStart.get(5L, TimeUnit.SECONDS)
                    instanceof IllegalStateException);
            check(!entitlementStore.record.revoked);
            check(entitlementStore.record.revocationVersion == 1L);
            check(runtime.snapshot().state
                    == DualMachineFormalUsageStateMachine.State
                    .ACTIVATED_IDLE);
            check(replacementBoundary.closeCalls == 0);
            check(sidecar.startChallenges == challengesBefore);
            check(sidecar.starts == startsBefore);
            check(sidecar.startDebits == debitsBefore);

            sidecar.status = "active";
            sidecar.statusRevision = 1L;
            check(runtime.refreshStatus().state
                    == DualMachineFormalUsageStateMachine.State
                    .ACTIVATED_IDLE);
            expectRejected(runtime::startFormalUsage, 409);
            check(sidecar.startChallenges == challengesBefore + 1);
            check(sidecar.starts == startsBefore);
            check(sidecar.startDebits == debitsBefore);
        } finally {
            sidecar.status = "active";
            sidecar.statusRevision = 1L;
            releaseStatus.countDown();
            executor.shutdownNow();
            check(executor.awaitTermination(5L, TimeUnit.SECONDS));
        }
    }

    private static void verifiesRetiredCoordinatorCannotCloseReplacement(
            DualMachineAuthorizationRuntime runtime,
            DualMachineCardAuthorizationCoordinator.IdentityBinding host,
            AtomicBoolean authenticated,
            AtomicLong hostProgress) throws Exception {
        AtomicLong physicalCloseCalls = new AtomicLong();
        FakeRuntimeBoundary retiringBoundary =
                new FakeRuntimeBoundary(physicalCloseCalls);
        runtime.attachAuthenticatedHost(
                new DualMachineAuthorizationRuntime.Attachment(
                        host,
                        CHANNEL,
                        retiringBoundary,
                        authenticated::get,
                        hostProgress::get,
                        () -> 100L));
        Field formalField = DualMachineAuthorizationRuntime.class
                .getDeclaredField("formalCoordinator");
        formalField.setAccessible(true);
        DualMachineFormalUsageCoordinator retired =
                (DualMachineFormalUsageCoordinator)
                        formalField.get(runtime);

        FakeRuntimeBoundary replacementBoundary =
                new FakeRuntimeBoundary(physicalCloseCalls);
        runtime.attachAuthenticatedHost(
                new DualMachineAuthorizationRuntime.Attachment(
                        host,
                        CHANNEL,
                        replacementBoundary,
                        authenticated::get,
                        hostProgress::get,
                        () -> 100L));
        int replacementCloses = replacementBoundary.closeCalls;
        long physicalCloses = physicalCloseCalls.get();
        retired.requestImmediateLocalStop();
        retired.failCloseFromRuntimeLoss();
        retired.failCloseFromEntitlementRevocation();
        check(retired.enforceAndGetDataPlanePermitState()
                == DualMachineFormalUsageCoordinator
                .DataPlanePermitState.CLOSED);
        check(replacementBoundary.closeCalls == replacementCloses);
        check(physicalCloseCalls.get() == physicalCloses);
        check(runtime.hasAuthenticatedHost());
    }

    private static void verifiesClosedRuntimeRejectsGenerationReceipt(
            DualMachineAuthorizationRuntime runtime,
            ActivationSidecar sidecar) throws Exception {
        DualMachineAuthorizationRuntime.CurrentGenerationReceipt receipt =
                runtime.captureCurrentGenerationReceipt();
        int challengesBefore = sidecar.startChallenges;
        int startsBefore = sidecar.starts;
        int debitsBefore = sidecar.startDebits;
        runtime.close();

        AtomicBoolean committed = new AtomicBoolean();
        check(!runtime.commitIfCurrent(
                receipt, () -> committed.set(true)));
        check(!runtime.commitCheckedIfCurrent(
                receipt, () -> committed.set(true)));
        check(!committed.get());
        expectIllegalState(() -> runtime.startFormalUsage(receipt));
        check(sidecar.startChallenges == challengesBefore);
        check(sidecar.starts == startsBefore);
        check(sidecar.startDebits == debitsBefore);
    }

    private static void
            verifiesReceiptBoundStopClaimCannotReachReplacement(
            DualMachineAuthorizationRuntime runtime,
            DualMachineCardAuthorizationCoordinator.IdentityBinding host,
            AtomicBoolean authenticated,
            AtomicLong hostProgress) throws Exception {
        AtomicLong physicalCloseCalls = new AtomicLong();
        FakeRuntimeBoundary generationA =
                new FakeRuntimeBoundary(physicalCloseCalls);
        runtime.attachAuthenticatedHost(
                new DualMachineAuthorizationRuntime.Attachment(
                        host,
                        CHANNEL,
                        generationA,
                        authenticated::get,
                        hostProgress::get,
                        () -> 100L));
        DualMachineAuthorizationRuntime.CurrentGenerationReceipt receiptA =
                runtime.captureCurrentGenerationReceipt();
        long stopEpochBefore = readLongField(
                runtime, "lifecycleStopEpoch");
        int generationACloses = generationA.closeCalls;
        AtomicBoolean falsePredicateCalled = new AtomicBoolean();
        check(runtime.beginFormalUsageLifecycleStopIfCurrent(
                receiptA,
                () -> {
                    falsePredicateCalled.set(true);
                    return false;
                }) == null);
        check(falsePredicateCalled.get());
        check(readLongField(runtime, "lifecycleStopEpoch")
                == stopEpochBefore);
        check(generationA.closeCalls == generationACloses);

        FakeRuntimeBoundary generationB =
                new FakeRuntimeBoundary(physicalCloseCalls);
        runtime.attachAuthenticatedHost(
                new DualMachineAuthorizationRuntime.Attachment(
                        host,
                        CHANNEL,
                        generationB,
                        authenticated::get,
                        hostProgress::get,
                        () -> 100L));
        long physicalClosesAfterBPublished = physicalCloseCalls.get();
        int generationBCloses = generationB.closeCalls;
        long stopEpochAfterBPublished = readLongField(
                runtime, "lifecycleStopEpoch");
        AtomicBoolean staleClaimCalled = new AtomicBoolean();
        check(runtime.beginFormalUsageLifecycleStopIfCurrent(
                receiptA,
                () -> {
                    staleClaimCalled.set(true);
                    return true;
                }) == null);
        check(!staleClaimCalled.get());
        check(readLongField(runtime, "lifecycleStopEpoch")
                == stopEpochAfterBPublished);
        check(generationB.closeCalls == generationBCloses);
        check(physicalCloseCalls.get() == physicalClosesAfterBPublished);
        DualMachineAuthorizationRuntime.CurrentGenerationReceipt receiptB =
                runtime.captureCurrentGenerationReceipt();
        AtomicBoolean generationBCommitted = new AtomicBoolean();
        check(runtime.commitIfCurrent(
                receiptB, () -> generationBCommitted.set(true)));
        check(generationBCommitted.get());
    }

    private static long readLongField(
            Object target,
            String fieldName) throws Exception {
        Field field = target.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.getLong(target);
    }

    private static void verifiesCurrentStopRetryBackoff(
            DualMachineAuthorizationRuntime runtime,
            ActivationSidecar sidecar,
            AtomicLong monotonicNanos) throws Exception {
        int cancellationsBefore = sidecar.cancellations;
        sidecar.allowAmbiguousStart = true;
        try {
            try {
                runtime.startFormalUsage();
                throw new AssertionError("ambiguous start was expected");
            } catch (IOException expected) {
                check(expected instanceof DualMachineFormalUsageCoordinator
                        .GenerationBoundStartFailure);
            }
            sidecar.cancellationFailuresRemaining = 3;
            DualMachineAuthorizationRuntime.FormalUsageLifecycleHandle first =
                    runtime.beginFormalUsageLifecycleStop();
            String startRequestId = first.startRequestId;
            DualMachineFormalUsageCoordinator.StopOutcome ambiguous =
                    first.stopFormalUsage();
            check(!ambiguous.serverConfirmed);
            check(sidecar.cancellations == cancellationsBefore + 3);
            check(runtime.snapshot().state
                    == DualMachineFormalUsageStateMachine.State.STOPPING);

            DualMachineAuthorizationRuntime.CurrentGenerationReceipt receipt =
                    runtime.captureCurrentGenerationReceipt();
            AtomicBoolean earlyClaim = new AtomicBoolean();
            check(runtime.beginFormalUsageLifecycleStopRetryIfCurrent(
                    receipt,
                    () -> {
                        earlyClaim.set(true);
                        return true;
                    }) == null);
            check(!earlyClaim.get());

            monotonicNanos.addAndGet(
                    FormalUsageStopRetryPolicy.INITIAL_RETRY_DELAY_NANOS);
            sidecar.cancellationFailuresRemaining = 0;
            AtomicBoolean dueClaim = new AtomicBoolean();
            DualMachineAuthorizationRuntime.FormalUsageLifecycleHandle retry =
                    runtime.beginFormalUsageLifecycleStopRetryIfCurrent(
                            receipt,
                            () -> {
                                dueClaim.set(true);
                                return true;
                            });
            check(retry != null && dueClaim.get());
            check(retry.startRequestId.equals(startRequestId));
            DualMachineFormalUsageCoordinator.StopOutcome recovered =
                    retry.stopFormalUsage();
            check(recovered.serverConfirmed);
            check(sidecar.cancellations == cancellationsBefore + 4);
            check(runtime.snapshot().state
                    == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);

            AtomicBoolean idleClaim = new AtomicBoolean();
            check(runtime.beginFormalUsageLifecycleStopRetryIfCurrent(
                    runtime.captureCurrentGenerationReceipt(),
                    () -> {
                        idleClaim.set(true);
                        return true;
                    }) == null);
            check(!idleClaim.get());
        } finally {
            sidecar.allowAmbiguousStart = false;
            sidecar.cancellationFailuresRemaining = 0;
        }
    }

    private static void
            verifiesRetiringCancellationRetriesThroughMaintenance(
            DualMachineAuthorizationRuntime runtime,
            ActivationSidecar sidecar,
            DualMachineCardAuthorizationCoordinator.IdentityBinding host,
            AtomicBoolean authenticated,
            AtomicLong hostProgress,
            AtomicLong monotonicNanos) throws Exception {
        int challengesBefore = sidecar.startChallenges;
        int startsBefore = sidecar.starts;
        int debitsBefore = sidecar.startDebits;
        int cancellationsBefore = sidecar.cancellations;
        sidecar.allowAmbiguousStart = true;
        try {
            try {
                runtime.startFormalUsage();
                throw new AssertionError("ambiguous start was expected");
            } catch (IOException expected) {
                check(expected instanceof DualMachineFormalUsageCoordinator
                        .GenerationBoundStartFailure);
            }
            check(runtime.snapshot().state
                    == DualMachineFormalUsageStateMachine.State.STARTING);
            check(sidecar.startChallenges == challengesBefore + 1);
            check(sidecar.starts == startsBefore + 1);
            check(sidecar.startDebits == debitsBefore + 1);

            sidecar.cancellationFailuresRemaining = 6;
            FakeRuntimeBoundary replacementBoundary =
                    new FakeRuntimeBoundary();
            expectSecurity(() -> runtime.attachAuthenticatedHost(
                    new DualMachineAuthorizationRuntime.Attachment(
                            host,
                            CHANNEL,
                            replacementBoundary,
                            authenticated::get,
                            hostProgress::get,
                            () -> 100L)));
            check(!runtime.hasAuthenticatedHost());
            check(sidecar.cancellations == cancellationsBefore + 3);
            check(replacementBoundary.prepareCalls == 0);
            check(replacementBoundary.openCalls == 0);

            DualMachineAuthorizationRuntime.FormalUsageLifecycleHandle
                    firstMaintenance = runtime
                    .captureRetiringFormalUsageStopForMaintenance(
                            () -> true);
            check(firstMaintenance != null);
            String startRequestId = firstMaintenance.startRequestId;
            DualMachineFormalUsageCoordinator.StopOutcome firstOutcome =
                    firstMaintenance.stopFormalUsage();
            check(firstOutcome != null);
            check(!firstOutcome.serverConfirmed);
            check(sidecar.cancellations == cancellationsBefore + 6);
            check(runtime.hasPendingFormalStartCancellation());

            AtomicBoolean earlyClaim = new AtomicBoolean();
            check(runtime.captureRetiringFormalUsageStopForMaintenance(
                    () -> {
                        earlyClaim.set(true);
                        return true;
                    }) == null);
            check(!earlyClaim.get());
            monotonicNanos.addAndGet(
                    FormalUsageStopRetryPolicy.INITIAL_RETRY_DELAY_NANOS);

            sidecar.cancellationFailuresRemaining = 0;
            DualMachineAuthorizationRuntime.FormalUsageLifecycleHandle
                    retryMaintenance = runtime
                    .captureRetiringFormalUsageStopForMaintenance(
                            () -> true);
            check(retryMaintenance != null);
            check(retryMaintenance.startRequestId.equals(startRequestId));
            DualMachineFormalUsageCoordinator.StopOutcome retryOutcome =
                    retryMaintenance.stopFormalUsage();
            check(retryOutcome != null);
            check(retryOutcome.serverConfirmed);
            check(retryOutcome.definitelyNotStarted);
            check(sidecar.cancellations == cancellationsBefore + 7);
            AtomicBoolean resolvedClaim = new AtomicBoolean();
            check(runtime.captureRetiringFormalUsageStopForMaintenance(
                    () -> {
                        resolvedClaim.set(true);
                        return true;
                    }) == null);
            check(!resolvedClaim.get());

            runtime.attachAuthenticatedHost(
                    new DualMachineAuthorizationRuntime.Attachment(
                            host,
                            CHANNEL,
                            replacementBoundary,
                            authenticated::get,
                            hostProgress::get,
                            () -> 100L));
            check(runtime.hasAuthenticatedHost());
            check(sidecar.startChallenges == challengesBefore + 1);
            check(sidecar.starts == startsBefore + 1);
            check(sidecar.startDebits == debitsBefore + 1);
        } finally {
            sidecar.allowAmbiguousStart = false;
            sidecar.cancellationFailuresRemaining = 0;
        }
    }

    private static void
            verifiesReplacementDoesNotPublishNewOwnerBeforeOldCleanup(
            DualMachineAuthorizationRuntime runtime,
            ActivationSidecar sidecar,
            DualMachineCardAuthorizationCoordinator.IdentityBinding host,
            AtomicBoolean authenticated,
            AtomicLong hostProgress) throws Exception {
        FakeRuntimeBoundary retiringBoundary = new FakeRuntimeBoundary();
        runtime.attachAuthenticatedHost(
                new DualMachineAuthorizationRuntime.Attachment(
                        host,
                        CHANNEL,
                        retiringBoundary,
                        authenticated::get,
                        hostProgress::get,
                        () -> 100L));

        CountDownLatch oldPreparationEntered = new CountDownLatch(1);
        CountDownLatch releaseOldPreparation = new CountDownLatch(1);
        CountDownLatch oldStopLatched = new CountDownLatch(1);
        retiringBoundary.prepareHook = () -> {
            oldPreparationEntered.countDown();
            awaitUnchecked(releaseOldPreparation);
        };
        retiringBoundary.closeHook = oldStopLatched::countDown;
        FakeRuntimeBoundary replacementBoundary =
                new FakeRuntimeBoundary();
        int challengesBefore = sidecar.startChallenges;
        int startsBefore = sidecar.starts;
        int debitsBefore = sidecar.startDebits;
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Throwable> oldStart = executor.submit(() -> {
                try {
                    runtime.startFormalUsage();
                    return null;
                } catch (Throwable failure) {
                    return failure;
                }
            });
            check(oldPreparationEntered.await(5L, TimeUnit.SECONDS));
            Future<Throwable> replacement = executor.submit(() -> {
                try {
                    runtime.attachAuthenticatedHost(
                            new DualMachineAuthorizationRuntime.Attachment(
                                    host,
                                    CHANNEL,
                                    replacementBoundary,
                                    authenticated::get,
                                    hostProgress::get,
                                    () -> 100L));
                    return null;
                } catch (Throwable failure) {
                    return failure;
                }
            });
            check(oldStopLatched.await(5L, TimeUnit.SECONDS));

            check(sidecar.startChallenges == challengesBefore);
            check(sidecar.starts == startsBefore);
            check(sidecar.startDebits == debitsBefore);
            check(replacementBoundary.prepareCalls == 0);
            check(replacementBoundary.openCalls == 0);

            releaseOldPreparation.countDown();
            check(isExpectedStaleStartFailure(
                    oldStart.get(5L, TimeUnit.SECONDS)));
            check(replacement.get(5L, TimeUnit.SECONDS) == null);
            check(runtime.hasAuthenticatedHost());

            expectRejected(runtime::startFormalUsage, 409);
            check(sidecar.startChallenges == challengesBefore + 1);
            check(sidecar.starts == startsBefore);
            check(sidecar.startDebits == debitsBefore);
            check(replacementBoundary.prepareCalls == 1);
            check(replacementBoundary.openCalls == 0);
        } finally {
            releaseOldPreparation.countDown();
            executor.shutdownNow();
            check(executor.awaitTermination(5L, TimeUnit.SECONDS));
        }
    }

    private static void
            verifiesDetachCancelsInFlightReplacementPublication(
            DualMachineAuthorizationRuntime runtime,
            ActivationSidecar sidecar,
            DualMachineCardAuthorizationCoordinator.IdentityBinding host,
            AtomicBoolean authenticated,
            AtomicLong hostProgress) throws Exception {
        FakeRuntimeBoundary retiringBoundary = new FakeRuntimeBoundary();
        runtime.attachAuthenticatedHost(
                new DualMachineAuthorizationRuntime.Attachment(
                        host,
                        CHANNEL,
                        retiringBoundary,
                        authenticated::get,
                        hostProgress::get,
                        () -> 100L));

        CountDownLatch oldPreparationEntered = new CountDownLatch(1);
        CountDownLatch releaseOldPreparation = new CountDownLatch(1);
        CountDownLatch oldStopLatched = new CountDownLatch(1);
        CountDownLatch replacementCleanupEntered = new CountDownLatch(1);
        CountDownLatch releaseReplacementCleanup = new CountDownLatch(1);
        retiringBoundary.prepareHook = () -> {
            oldPreparationEntered.countDown();
            awaitUnchecked(releaseOldPreparation);
        };
        retiringBoundary.closeHook = oldStopLatched::countDown;
        FakeRuntimeBoundary cancelledReplacementBoundary =
                new FakeRuntimeBoundary();
        int challengesBefore = sidecar.startChallenges;
        int startsBefore = sidecar.starts;
        int debitsBefore = sidecar.startDebits;
        ExecutorService executor = Executors.newFixedThreadPool(3);
        try {
            Future<Throwable> oldStart = executor.submit(() -> {
                try {
                    runtime.startFormalUsage();
                    return null;
                } catch (Throwable failure) {
                    return failure;
                }
            });
            check(oldPreparationEntered.await(5L, TimeUnit.SECONDS));
            Future<Throwable> replacement = executor.submit(() -> {
                try {
                    runtime.attachAuthenticatedHost(
                            new DualMachineAuthorizationRuntime.Attachment(
                                    host,
                                    CHANNEL,
                                    cancelledReplacementBoundary,
                                    authenticated::get,
                                    hostProgress::get,
                                    () -> 100L));
                    return null;
                } catch (Throwable failure) {
                    return failure;
                }
            });
            check(oldStopLatched.await(5L, TimeUnit.SECONDS));

            // The coordinator collapses the old start's abort cleanup into the
            // monitor-free stop latch. Runtime's stale-boundary cleanup is the
            // second physical close after failCloseReplacedGeneration releases
            // attachmentLock. Block only that lock-free cleanup.
            retiringBoundary.targetedCloseCall = 2;
            retiringBoundary.targetedCloseHook = () -> {
                replacementCleanupEntered.countDown();
                awaitUnchecked(releaseReplacementCleanup);
            };
            releaseOldPreparation.countDown();
            check(replacementCleanupEntered.await(5L, TimeUnit.SECONDS));
            Future<Throwable> detach = executor.submit(() -> {
                try {
                    runtime.detachAuthenticatedHost();
                    return null;
                } catch (Throwable failure) {
                    return failure;
                }
            });
            // Detach changes the mutation epoch while replacement is stalled in
            // lock-free cleanup; no tested thread depends on a timeout to
            // release either coordinator or attachment locks.
            check(detach.get(5L, TimeUnit.SECONDS) == null);
            releaseReplacementCleanup.countDown();
            Throwable oldFailure = oldStart.get(5L, TimeUnit.SECONDS);
            if (!isExpectedStaleStartFailure(oldFailure)) {
                throw new AssertionError(
                        "unexpected stale start result: " + oldFailure);
            }
            check(replacement.get(5L, TimeUnit.SECONDS)
                    instanceof GeneralSecurityException);
            check(!runtime.hasAuthenticatedHost());
            expectIllegalState(runtime::startFormalUsage);
            check(sidecar.startChallenges == challengesBefore);
            check(sidecar.starts == startsBefore);
            check(sidecar.startDebits == debitsBefore);
            check(cancelledReplacementBoundary.prepareCalls == 0);
            check(cancelledReplacementBoundary.openCalls == 0);

            runtime.attachAuthenticatedHost(
                    new DualMachineAuthorizationRuntime.Attachment(
                            host,
                            CHANNEL,
                            new FakeRuntimeBoundary(),
                            authenticated::get,
                            hostProgress::get,
                            () -> 100L));
            check(runtime.hasAuthenticatedHost());
        } finally {
            releaseOldPreparation.countDown();
            releaseReplacementCleanup.countDown();
            executor.shutdownNow();
            check(executor.awaitTermination(5L, TimeUnit.SECONDS));
        }
    }

    private static void
            verifiesDetachCleanupBlocksConcurrentReattachment(
            DualMachineAuthorizationRuntime runtime,
            ActivationSidecar sidecar,
            DualMachineCardAuthorizationCoordinator.IdentityBinding host,
            AtomicBoolean authenticated,
            AtomicLong hostProgress) throws Exception {
        FakeRuntimeBoundary retiringBoundary = new FakeRuntimeBoundary();
        runtime.attachAuthenticatedHost(
                new DualMachineAuthorizationRuntime.Attachment(
                        host,
                        CHANNEL,
                        retiringBoundary,
                        authenticated::get,
                        hostProgress::get,
                        () -> 100L));

        CountDownLatch oldPreparationEntered = new CountDownLatch(1);
        CountDownLatch releaseOldPreparation = new CountDownLatch(1);
        CountDownLatch oldStopLatched = new CountDownLatch(1);
        retiringBoundary.prepareHook = () -> {
            oldPreparationEntered.countDown();
            awaitUnchecked(releaseOldPreparation);
        };
        retiringBoundary.closeHook = oldStopLatched::countDown;
        FakeRuntimeBoundary rejectedBoundary = new FakeRuntimeBoundary();
        int challengesBefore = sidecar.startChallenges;
        int startsBefore = sidecar.starts;
        int debitsBefore = sidecar.startDebits;
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Throwable> oldStart = executor.submit(() -> {
                try {
                    runtime.startFormalUsage();
                    return null;
                } catch (Throwable failure) {
                    return failure;
                }
            });
            check(oldPreparationEntered.await(5L, TimeUnit.SECONDS));
            Future<Throwable> detach = executor.submit(() -> {
                try {
                    runtime.detachAuthenticatedHost();
                    return null;
                } catch (Throwable failure) {
                    return failure;
                }
            });
            check(oldStopLatched.await(5L, TimeUnit.SECONDS));

            check(!runtime.hasAuthenticatedHost());
            expectSecurity(() -> runtime.attachAuthenticatedHost(
                    new DualMachineAuthorizationRuntime.Attachment(
                            host,
                            CHANNEL,
                            rejectedBoundary,
                            authenticated::get,
                            hostProgress::get,
                            () -> 100L)));
            check(!detach.isDone());
            check(rejectedBoundary.prepareCalls == 0);
            check(rejectedBoundary.openCalls == 0);
            check(sidecar.startChallenges == challengesBefore);
            check(sidecar.starts == startsBefore);
            check(sidecar.startDebits == debitsBefore);

            releaseOldPreparation.countDown();
            check(isExpectedStaleStartFailure(
                    oldStart.get(5L, TimeUnit.SECONDS)));
            check(detach.get(5L, TimeUnit.SECONDS) == null);

            runtime.attachAuthenticatedHost(
                    new DualMachineAuthorizationRuntime.Attachment(
                            host,
                            CHANNEL,
                            new FakeRuntimeBoundary(),
                            authenticated::get,
                            hostProgress::get,
                            () -> 100L));
            check(runtime.hasAuthenticatedHost());
        } finally {
            releaseOldPreparation.countDown();
            executor.shutdownNow();
            check(executor.awaitTermination(5L, TimeUnit.SECONDS));
        }
    }

    private static void verifiesCrashSafePersistedActivationReconciliation(
            DualMachineCardAuthorizationCoordinator.IdentityBinding host,
            DualMachineCardAuthorizationCoordinator.IdentityBinding android,
            KeyPairGenerator rsa) throws Exception {
        String pairId = "44".repeat(16);
        String alias = "visionforge-dual-machine-pairing-identity";
        DualMachineEntitlementRecord committed =
                new DualMachineEntitlementRecord(
                        ENTITLEMENT_ID,
                        pairId,
                        DualMachineEntitlementRecord.PROTOCOL_VERSION,
                        1L,
                        host.keyFingerprintSha256,
                        host.peerIdentity.identityPublicKeyBase64,
                        android.keyFingerprintSha256,
                        alias,
                        "day",
                        "day",
                        false,
                        false);
        DualMachineCardAuthorizationCoordinator.PendingActivation matching =
                pendingActivation(
                        pairId,
                        host,
                        android,
                        alias,
                        "activate",
                        "");
        InMemoryEntitlementStore entitlementStore =
                new InMemoryEntitlementStore();
        entitlementStore.record = committed;
        InMemoryPendingStore pendingStore = new InMemoryPendingStore();
        pendingStore.pending = matching;
        DualMachineAuthorizationRuntime recovered = newRuntimeForRestore(
                host, android, rsa, entitlementStore, pendingStore);
        check(pendingStore.pending == null);
        check(recovered.snapshot().state
                == DualMachineFormalUsageStateMachine.State.ACTIVATED_IDLE);
        check(recovered.snapshot().entitlement.equals(committed));
        recovered.close();

        InMemoryEntitlementStore conflictEntitlementStore =
                new InMemoryEntitlementStore();
        conflictEntitlementStore.record = committed;
        InMemoryPendingStore conflictPendingStore =
                new InMemoryPendingStore();
        conflictPendingStore.pending = pendingActivation(
                pairId,
                host,
                android,
                alias,
                "reactivate",
                "99".repeat(16));
        expectSecurity(() -> newRuntimeForRestore(
                host,
                android,
                rsa,
                conflictEntitlementStore,
                conflictPendingStore));
        check(conflictPendingStore.pending != null);
    }

    private static DualMachineAuthorizationRuntime newRuntimeForRestore(
            DualMachineCardAuthorizationCoordinator.IdentityBinding host,
            DualMachineCardAuthorizationCoordinator.IdentityBinding android,
            KeyPairGenerator rsa,
            InMemoryEntitlementStore entitlementStore,
            InMemoryPendingStore pendingStore) throws Exception {
        return new DualMachineAuthorizationRuntime(
                new ActivationSidecar(host, android),
                new DualMachineFormalUsageStateMachine(),
                new DualMachineUsageLeaseKeyring(
                        Collections.singletonList(
                                rsa.generateKeyPair().getPublic()),
                        5),
                entitlementStore,
                pendingStore,
                android,
                "visionforge-dual-machine-pairing-identity",
                () -> "aa".repeat(16),
                System::nanoTime,
                (deadline, action) -> () -> { },
                () -> 0L);
    }

    private static DualMachineCardAuthorizationCoordinator.PendingActivation
            pendingActivation(
            String pairId,
            DualMachineCardAuthorizationCoordinator.IdentityBinding host,
            DualMachineCardAuthorizationCoordinator.IdentityBinding android,
            String alias,
            String activationMode,
            String targetEntitlementId) {
        return new DualMachineCardAuthorizationCoordinator.PendingActivation(
                "55".repeat(16),
                pairId,
                "66".repeat(16),
                "A".repeat(43),
                200L,
                "AAAAAAAAAAA=",
                "AAAAAAAAAAA=",
                host.keyFingerprintSha256,
                android.keyFingerprintSha256,
                alias,
                activationMode,
                targetEntitlementId);
    }

    private static DualMachineCardAuthorizationCoordinator.IdentityBinding
            identity(String deviceCode, String version, KeyPair pair)
            throws GeneralSecurityException {
        return new DualMachineCardAuthorizationCoordinator.IdentityBinding(
                deviceCode,
                version,
                DualMachinePairingIdentityCodec.encodePublicKeyBase64(
                        pair.getPublic().getEncoded()),
                payload -> DualMachinePairingIdentityCodec.sign(
                        pair.getPrivate(), payload));
    }

    private static KeyPair ecKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static void expectSecurity(CheckedAction action)
            throws Exception {
        try {
            action.run();
            throw new AssertionError("security failure was expected");
        } catch (GeneralSecurityException expected) {
            // Expected.
        }
    }

    private static void expectRejected(
            CheckedAction action,
            int expectedStatus) throws Exception {
        try {
            action.run();
            throw new AssertionError("sidecar rejection was expected");
        } catch (DualMachineSidecarPort.RejectedException expected) {
            check(expected.statusCode == expectedStatus);
        }
    }

    private static void expectIllegalState(CheckedAction action)
            throws Exception {
        try {
            action.run();
            throw new AssertionError("illegal state was expected");
        } catch (IllegalStateException expected) {
            // Expected.
        }
    }

    private static void expectError(CheckedAction action, Error expected)
            throws Exception {
        try {
            action.run();
        } catch (Error failure) {
            check(failure == expected);
            return;
        }
        throw new AssertionError("injected Error was expected");
    }

    private static boolean isExpectedStaleStartFailure(Throwable failure) {
        return failure instanceof IOException
                || failure instanceof GeneralSecurityException
                || failure instanceof IllegalStateException;
    }

    private static void awaitUnchecked(CountDownLatch latch) {
        try {
            check(latch.await(5L, TimeUnit.SECONDS));
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new AssertionError(failure);
        }
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("condition failed");
    }

    @FunctionalInterface
    private interface CheckedAction {
        void run() throws Exception;
    }

    private static final class InMemoryEntitlementStore
            implements DualMachineEntitlementStore {
        DualMachineEntitlementRecord record;

        @Override
        public DualMachineEntitlementRecord load() {
            return record;
        }

        @Override
        public void save(DualMachineEntitlementRecord value) {
            record = value;
        }

        @Override
        public void clear() {
            record = null;
        }
    }

    private static final class InMemoryPendingStore
            implements DualMachineCardAuthorizationCoordinator
            .PendingActivationStore {
        DualMachineCardAuthorizationCoordinator.PendingActivation pending;

        @Override
        public DualMachineCardAuthorizationCoordinator.PendingActivation
                load() {
            return pending;
        }

        @Override
        public void save(
                DualMachineCardAuthorizationCoordinator.PendingActivation
                        pending) {
            this.pending = pending;
        }

        @Override
        public void clear() {
            pending = null;
        }
    }

    private static final class FakeRuntimeBoundary
            implements DualMachineFormalUsageCoordinator.RuntimeBoundary {
        private final AtomicLong physicalCloseCalls;
        int closeCalls;
        int openCalls;
        int prepareCalls;
        Runnable prepareHook;
        Runnable closeHook;
        volatile int targetedCloseCall = -1;
        volatile Runnable targetedCloseHook;

        FakeRuntimeBoundary() {
            this(new AtomicLong());
        }

        FakeRuntimeBoundary(AtomicLong physicalCloseCalls) {
            this.physicalCloseCalls = physicalCloseCalls;
        }

        @Override
        public DualMachineFormalUsageCoordinator.StartReadiness
                prepareWithDataPlaneClosed(
                BooleanSupplier cancellationRequested) throws IOException {
            prepareCalls++;
            Runnable hook = prepareHook;
            prepareHook = null;
            if (hook != null) hook.run();
            if (cancellationRequested.getAsBoolean()) {
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
            if (cancellationRequested.getAsBoolean()) {
                throw new IOException("simulated video verification cancellation");
            }
            check(CHANNEL.equals(expectedChannelBindingSha256));
            check(expectedStartRequestId != null
                    && !expectedStartRequestId.isEmpty());
        }

        @Override
        public void openDataPlane(
                DualMachineFormalUsageCoordinator.DataPlanePermit permit) {
            openCalls++;
        }

        @Override
        public void stageFutureLease(
                DualMachineFormalUsageCoordinator.DataPlanePermit permit) {
        }

        @Override
        public DualMachineFormalUsageCoordinator.DataPlanePermitState
                enforceLeaseWindow() {
            return DualMachineFormalUsageCoordinator
                    .DataPlanePermitState.CLOSED;
        }

        @Override
        public void closeDataPlane() {
            closeCalls++;
            physicalCloseCalls.incrementAndGet();
            if (closeCalls == targetedCloseCall) {
                Runnable targeted = targetedCloseHook;
                targetedCloseHook = null;
                if (targeted != null) targeted.run();
            }
            Runnable hook = closeHook;
            closeHook = null;
            if (hook != null) hook.run();
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

    private static final class ActivationSidecar
            implements DualMachineSidecarPort {
        private static final String CHALLENGE_ID = "44".repeat(16);
        private static final String CHALLENGE_TOKEN = "A".repeat(43);
        private final DualMachineCardAuthorizationCoordinator.IdentityBinding
                host;
        private final DualMachineCardAuthorizationCoordinator.IdentityBinding
                android;
        private ActivationChallengeRequest activationRequest;
        private volatile Runnable statusHook;
        private volatile String status = "active";
        private volatile long statusRevision = 1L;
        private int startChallenges;
        private int starts;
        private int startDebits;
        private int cancellations;
        private int cancellationFailuresRemaining;
        private boolean allowAmbiguousStart;

        ActivationSidecar(
                DualMachineCardAuthorizationCoordinator.IdentityBinding host,
                DualMachineCardAuthorizationCoordinator.IdentityBinding
                        android) {
            this.host = host;
            this.android = android;
        }

        @Override
        public ActivationChallengeResponse createActivationChallenge(
                ActivationChallengeRequest request)
                throws IOException {
            activationRequest = request;
            try {
                String profileSha256 = profileSha256(request);
                return new ActivationChallengeResponse(
                        CHALLENGE_ID,
                        CHALLENGE_TOKEN,
                        200L,
                        "activate",
                        "",
                        profileSha256,
                        activationPayload(request));
            } catch (GeneralSecurityException failure) {
                throw new IOException(failure);
            }
        }

        @Override
        public ActivationResponse confirmActivation(
                ActivationConfirmationRequest request) {
            check(activationRequest != null);
            check(request.challengeId.equals(CHALLENGE_ID));
            check(!request.hostSignatureBase64.isEmpty());
            check(!request.androidSignatureBase64.isEmpty());
            return new ActivationResponse(
                    ENTITLEMENT_ID,
                    activationRequest.pairId,
                    "89aabbccddeeff001122334455667788",
                    1L,
                    "active",
                    1L,
                    86_400L,
                    86_400L,
                    86_400L,
                    0L,
                    false);
        }

        @Override
        public EntitlementStatusResponse fetchEntitlementStatus(
                EntitlementStatusRequest request) {
            Runnable hook = statusHook;
            statusHook = null;
            if (hook != null) hook.run();
            return new EntitlementStatusResponse(
                    status,
                    statusRevision,
                    86_400L,
                    86_400L,
                    0L,
                    "");
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

        @Override
        public StartChallengeResponse createStartChallenge(
                StartChallengeRequest request) throws IOException {
            startChallenges++;
            if (allowAmbiguousStart) {
                return new StartChallengeResponse(
                        CHALLENGE_ID,
                        CHALLENGE_TOKEN,
                        200L);
            }
            throw new DualMachineSidecarPort.RejectedException(409);
        }

        @Override
        public UsageLeaseResponse startUsage(StartUsageRequest request)
                throws IOException {
            starts++;
            startDebits++;
            if (allowAmbiguousStart) {
                throw new IOException("ambiguous formal start");
            }
            throw new UnsupportedOperationException();
        }

        @Override
        public StartCancellationResponse cancelStart(
                StartCancellationRequest request) throws IOException {
            cancellations++;
            if (cancellationFailuresRemaining > 0) {
                cancellationFailuresRemaining--;
                throw new IOException("start cancellation unavailable");
            }
            return new StartCancellationResponse(
                    request.startRequestId,
                    "",
                    "not_started",
                    86_400L,
                    0L,
                    false,
                    "day",
                    false);
        }

        @Override
        public UsageLeaseResponse heartbeat(HeartbeatRequest request) {
            throw new UnsupportedOperationException();
        }

        @Override
        public StopResponse stop(StopRequest request) {
            throw new UnsupportedOperationException();
        }

        private byte[] activationPayload(
                ActivationChallengeRequest request)
                throws GeneralSecurityException {
            DualMachineUsageAuthorizationContract.ActivationConfirmation
                    value = new DualMachineUsageAuthorizationContract
                    .ActivationConfirmation();
            value.activationMode = "activate";
            value.androidClientVersion = request.android.clientVersion;
            value.androidDeviceCode = request.android.deviceCode;
            value.androidDeviceProfileSha256 = profileSha256(request);
            value.androidKeySha256 = android.keyFingerprintSha256;
            value.challengeId = CHALLENGE_ID;
            value.challengeTokenSha256 = sha256Hex(
                    CHALLENGE_TOKEN.getBytes(
                            java.nio.charset.StandardCharsets.US_ASCII));
            value.hostClientVersion = request.host.clientVersion;
            value.hostDeviceCode = request.host.deviceCode;
            value.hostKeySha256 = host.keyFingerprintSha256;
            value.pairId = request.pairId;
            value.protocolVersion = request.protocolVersion;
            value.requestId = request.requestId;
            value.targetEntitlementId = "";
            return DualMachineUsageAuthorizationContract
                    .activationConfirmation(value);
        }

        private static String profileSha256(
                ActivationChallengeRequest request)
                throws GeneralSecurityException {
            byte[] profile = request.android.deviceProfile == null
                    ? "{}".getBytes(
                            java.nio.charset.StandardCharsets.UTF_8)
                    : request.android.deviceProfile.canonicalJson();
            return sha256Hex(profile);
        }

        private static String sha256Hex(byte[] value)
                throws GeneralSecurityException {
            byte[] digest = java.security.MessageDigest
                    .getInstance("SHA-256").digest(value);
            StringBuilder result = new StringBuilder(64);
            for (byte part : digest) {
                result.append(String.format(
                        java.util.Locale.ROOT,
                        "%02x",
                        part & 0xff));
            }
            return result.toString();
        }
    }
}
