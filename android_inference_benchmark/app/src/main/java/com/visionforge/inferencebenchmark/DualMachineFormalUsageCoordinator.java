package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;

/**
 * Sole Android orchestration boundary for paid dual-machine formal use.
 *
 * <p>Call this class from one service-owned worker, never from the UI thread.
 * It prepares both runtimes with the data plane closed, obtains two verified
 * device proofs, installs a pinned short RS256 lease, and only then exposes an
 * unforgeable runtime permit. Every local stop closes the gate and data plane
 * before attempting the best-effort server stop.</p>
 */
public final class DualMachineFormalUsageCoordinator {
    /** Atomic result of enforcing both the signed lease and runtime boundary. */
    public enum DataPlanePermitState {
        OPEN,
        STAGED_WAITING,
        CLOSED,
        SUPERSEDED
    }

    private static final long MAXIMUM_LEASE_SECONDS = 5L;

    public enum RenewalOutcome {
        CURRENT_INSTALLED,
        FUTURE_STAGED,
        IDEMPOTENT,
        NO_PROGRESS
    }

    /** Immutable counters sampled by the latest renewal decision. */
    public static final class RenewalProgressObservation {
        public final long observedHostProgress;
        public final long lastHostProgress;
        public final long observedAndroidProgress;
        public final long lastAndroidProgress;

        private RenewalProgressObservation(
                long observedHostProgress,
                long lastHostProgress,
                long observedAndroidProgress,
                long lastAndroidProgress) {
            this.observedHostProgress = observedHostProgress;
            this.lastHostProgress = lastHostProgress;
            this.observedAndroidProgress = observedAndroidProgress;
            this.lastAndroidProgress = lastAndroidProgress;
        }
    }

    /** Privacy-safe monotonic timing for the latest paid-renewal attempt. */
    public static final class RenewalTiming {
        public final boolean attempted;
        public final long sequence;
        public final long proofMillis;
        public final long sidecarMillis;
        public final long installMillis;
        public final long totalMillis;
        public final String terminalPhase;

        private RenewalTiming(
                boolean attempted,
                long sequence,
                long proofMillis,
                long sidecarMillis,
                long installMillis,
                long totalMillis,
                String terminalPhase) {
            this.attempted = attempted;
            this.sequence = sequence;
            this.proofMillis = proofMillis;
            this.sidecarMillis = sidecarMillis;
            this.installMillis = installMillis;
            this.totalMillis = totalMillis;
            this.terminalPhase = terminalPhase;
        }

        private static RenewalTiming skipped(String terminalPhase) {
            return new RenewalTiming(
                    false, -1L, 0L, 0L, 0L, 0L, terminalPhase);
        }
    }

    @FunctionalInterface
    public interface TimeSource {
        long nowEpochSeconds();
    }

    @FunctionalInterface
    public interface HexIdSource {
        String nextHex128();
    }

    public interface RuntimeBoundary {
        /**
         * Establishes local runtime and authenticated-control readiness before
         * billing while both data planes remain closed. It must not wait for
         * Host video because the Host is forbidden to emit video before the
         * signed lease commit. Every blocking wait must observe
         * {@code cancellationRequested}; the signal remains live even when a
         * local stop wins immediately before the boundary method is entered.
         */
        StartReadiness prepareWithDataPlaneClosed(
                BooleanSupplier cancellationRequested)
                throws IOException, GeneralSecurityException;

        /**
         * Revalidates the mutually authenticated Host control channel, route,
         * display readiness, and reservation immediately before a start request
         * that may create the first paid lease. Continuous video remains closed
         * until Offer/Accept/Commit completes.
         */
        void verifyFreshHostVideoBeforePotentialDebit(
                String expectedChannelBindingSha256,
                String expectedStartRequestId,
                BooleanSupplier cancellationRequested)
                throws IOException, GeneralSecurityException;

        /**
         * Opens or promotes exactly this permit. The runtime must independently
         * reject use before {@code notBeforeMonotonicNanos} and synchronously
         * fail closed at {@code expiresAtMonotonicNanos}, even if the
         * coordinator watchdog is delayed.
         */
        void openDataPlane(DataPlanePermit permit) throws IOException;

        /**
         * Installs the next lease/key epoch without activating it before its
         * monotonic not-before deadline.
         */
        void stageFutureLease(DataPlanePermit permit) throws IOException;

        /**
         * Atomically promotes a due staged permit or closes an expired one.
         * This method is invoked outside the coordinator monitor so HTTP I/O
         * can never delay the runtime's five-second fail-closed boundary.
         */
        DataPlanePermitState enforceLeaseWindow();

        /** Must be synchronous, idempotent and safe during partial startup. */
        void closeDataPlane();

        /**
         * Finalizes only the exact automatic-usage reservation owner. The first
         * ambiguous local close invokes this callback once so automatic start
         * remains fail-closed; the coordinator still retains and retries the
         * immutable server request without repeating the callback.
         */
        void finalizeFormalGeneration(
                String expectedStartRequestId,
                String expectedChannelBindingSha256,
                StopOutcome outcome);
    }

    /**
     * One-shot monotonic watchdog used in addition to the runtime's own lease
     * deadline enforcement.
     */
    public interface DeadlineScheduler {
        @FunctionalInterface
        interface ScheduledDeadline {
            void cancel();
        }

        ScheduledDeadline scheduleAt(
                long deadlineMonotonicNanos,
                Runnable action);
    }

    public static final class StartReadiness {
        public final String channelBindingSha256;
        public final boolean hostRuntimeReady;
        public final boolean androidRuntimeReady;

        public StartReadiness(
                String channelBindingSha256,
                boolean hostRuntimeReady,
                boolean androidRuntimeReady) {
            this.channelBindingSha256 = DualMachineSidecarValues.sha256(
                    channelBindingSha256, "channelBindingSha256");
            if (!hostRuntimeReady || !androidRuntimeReady) {
                throw new IllegalArgumentException(
                        "both runtimes must be ready");
            }
            this.hostRuntimeReady = true;
            this.androidRuntimeReady = true;
        }
    }

    /**
     * Capability passed only after a ticket has been cryptographically
     * verified and installed. Its constructor is inaccessible to adapters.
     */
    public static final class DataPlanePermit {
        public final String sessionId;
        public final long sequence;
        public final String leaseSha256;
        public final String channelBindingSha256;
        public final String startRequestId;
        public final long notBeforeMonotonicNanos;
        public final long expiresAtMonotonicNanos;
        private final byte[] signedUsageLeaseUtf8;

        private DataPlanePermit(
                DualMachineUsageLeaseVerifier.VerifiedLease lease,
                String signedUsageLease,
                String expectedStartRequestId) {
            sessionId = lease.sessionId();
            sequence = lease.sequence();
            leaseSha256 = lease.tokenSha256();
            channelBindingSha256 = lease.channelTranscriptSha256();
            startRequestId = DualMachineSidecarValues.hex128(
                    expectedStartRequestId, "startRequestId");
            notBeforeMonotonicNanos =
                    lease.notBeforeMonotonicNanos();
            expiresAtMonotonicNanos = lease.expiresAtMonotonicNanos();
            String canonicalLease = DualMachineSidecarValues.usageLease(
                    signedUsageLease, "signedUsageLease");
            signedUsageLeaseUtf8 = canonicalLease.getBytes(
                    StandardCharsets.US_ASCII);
            if (!leaseSha256.equals(
                    sha256HexRequired(signedUsageLeaseUtf8))) {
                throw new IllegalArgumentException(
                        "signed usage lease does not match permit");
            }
        }

        /**
         * Package-private handoff for the Host verifier. The signed ticket is
         * never exposed through UI state or {@link #toString()}.
         */
        byte[] copySignedUsageLeaseUtf8() {
            return signedUsageLeaseUtf8.clone();
        }

        @Override
        public String toString() {
            return "DataPlanePermit{sessionId=" + sessionId
                    + ", sequence=" + sequence
                    + ", leaseSha256=" + leaseSha256 + "}";
        }
    }

    public static final class StopOutcome {
        public final boolean localClosed;
        public final boolean serverConfirmed;
        public final long remainingSeconds;
        public final boolean definitelyNotStarted;

        private StopOutcome(
                boolean localClosed,
                boolean serverConfirmed,
                long remainingSeconds,
                boolean definitelyNotStarted) {
            this.localClosed = localClosed;
            this.serverConfirmed = serverConfirmed;
            this.remainingSeconds = remainingSeconds;
            this.definitelyNotStarted = definitelyNotStarted;
        }
    }

    /** One coordinator-bound, single-use admission into formal start. */
    static final class StartAdmissionToken {
        private final DualMachineFormalUsageCoordinator owner;

        private StartAdmissionToken(
                DualMachineFormalUsageCoordinator owner) {
            this.owner = owner;
        }
    }

    /** Immutable expected generation for one exact pending-start retry. */
    static final class RetryAdmissionToken {
        private final DualMachineFormalUsageCoordinator owner;
        private final PendingStart generation;

        private RetryAdmissionToken(
                DualMachineFormalUsageCoordinator owner,
                PendingStart generation) {
            this.owner = owner;
            this.generation = generation;
        }
    }

    /**
     * Immutable capability for exactly one pre-signed start cancellation.
     *
     * <p>The handle deliberately captures the private {@link PendingStart}
     * instance instead of looking up the coordinator's current generation when
     * it eventually runs. A delayed executor task can therefore replay only
     * the original request and can never close or cancel a later formal-start
     * generation.</p>
     */
    public static final class StartCancellationHandle {
        public final String startRequestId;
        private final DualMachineFormalUsageCoordinator owner;
        private final PendingStart generation;

        private StartCancellationHandle(
                DualMachineFormalUsageCoordinator owner,
                PendingStart generation) {
            this.owner = owner;
            this.generation = generation;
            startRequestId = generation.request.requestId;
        }

        /** Replays the exact immutable request without touching local state. */
        public boolean sendExactCancellation() {
            return owner.sendAndRecordStartCancellation(generation)
                    != null;
        }
    }

    /** Immutable owner for one formal-use generation's lifecycle stop. */
    public static final class LifecycleStopHandle {
        public final String startRequestId;
        public final String channelBindingSha256;
        private final DualMachineFormalUsageCoordinator owner;
        private final PendingStart generation;
        private final PendingStart startToCancel;

        private LifecycleStopHandle(
                DualMachineFormalUsageCoordinator owner,
                PendingStart generation,
                PendingStart startToCancel) {
            if (startToCancel != null && startToCancel != generation) {
                throw new IllegalArgumentException(
                        "start cancellation must belong to lifecycle owner");
            }
            this.owner = owner;
            this.generation = generation;
            this.startToCancel = startToCancel;
            startRequestId = generation.request.requestId;
            channelBindingSha256 = generation.request.channelBindingSha256;
        }

        /** Cancellation exists only when this stop claimed a pending start. */
        public StartCancellationHandle startCancellationHandle() {
            return startToCancel == null ? null
                    : new StartCancellationHandle(owner, startToCancel);
        }

        /** Stops only the captured generation, never a later generation. */
        public StopOutcome stopFormalUsage() {
            return owner.stopForRuntimeLifecycle(
                    generation, startToCancel);
        }
    }

    /** Marker exposed by failures which own one exact reserved start. */
    public interface GenerationBoundStartFailure {
        TerminalStartFailureHandle terminalStartFailureHandle();
    }

    /** Immutable terminal cleanup capability for exactly one start request. */
    public static final class TerminalStartFailureHandle {
        public final String startRequestId;
        public final String channelBindingSha256;
        public final boolean wasStartDispatched;
        private final DualMachineFormalUsageCoordinator owner;
        private final PendingStart generation;

        private TerminalStartFailureHandle(
                DualMachineFormalUsageCoordinator owner,
                PendingStart generation) {
            this.owner = owner;
            this.generation = generation;
            startRequestId = generation.request.requestId;
            channelBindingSha256 = generation.request.channelBindingSha256;
            wasStartDispatched = generation.startRequestDispatched;
        }

        /** Settles only the captured generation; a later one is untouched. */
        public StopOutcome settle() {
            return owner.stopForRuntimeLifecycle(generation, generation);
        }
    }

    public static final class GenerationBoundIOException
            extends IOException implements GenerationBoundStartFailure {
        private final TerminalStartFailureHandle handle;

        private GenerationBoundIOException(
                IOException cause,
                TerminalStartFailureHandle handle) {
            super(cause.getMessage(), cause);
            this.handle = handle;
        }

        @Override
        public TerminalStartFailureHandle terminalStartFailureHandle() {
            return handle;
        }
    }

    public static final class GenerationBoundRejectedException
            extends IOException implements GenerationBoundStartFailure {
        public final int statusCode;
        public final String safeErrorCode;
        private final TerminalStartFailureHandle handle;

        private GenerationBoundRejectedException(
                DualMachineSidecarPort.RejectedException cause,
                TerminalStartFailureHandle handle) {
            super(cause.getMessage(), cause);
            statusCode = cause.statusCode;
            safeErrorCode = cause.safeErrorCode;
            this.handle = handle;
        }

        @Override
        public TerminalStartFailureHandle terminalStartFailureHandle() {
            return handle;
        }
    }

    public static final class GenerationBoundSecurityException
            extends GeneralSecurityException
            implements GenerationBoundStartFailure {
        private final TerminalStartFailureHandle handle;

        private GenerationBoundSecurityException(
                GeneralSecurityException cause,
                TerminalStartFailureHandle handle) {
            super(cause.getMessage());
            initCause(cause);
            this.handle = handle;
        }

        @Override
        public TerminalStartFailureHandle terminalStartFailureHandle() {
            return handle;
        }
    }

    public static final class GenerationBoundRuntimeException
            extends RuntimeException implements GenerationBoundStartFailure {
        private final TerminalStartFailureHandle handle;

        private GenerationBoundRuntimeException(
                RuntimeException cause,
                TerminalStartFailureHandle handle) {
            super(cause.getMessage(), cause);
            this.handle = handle;
        }

        @Override
        public TerminalStartFailureHandle terminalStartFailureHandle() {
            return handle;
        }
    }

    /**
     * A verified initial lease arrived after the lifecycle stop latch closed.
     * The lease was accounted for and immediately stopped; callers must never
     * treat this exception as permission to reopen the data plane or replay the
     * start request.
     */
    public static final class StartCancelledException extends IOException {
        public final boolean serverConfirmed;
        public final boolean billingStarted;

        private StartCancelledException(
                boolean serverConfirmed,
                boolean billingStarted,
                Throwable cause) {
            super("formal start completed after local cancellation", cause);
            this.serverConfirmed = serverConfirmed;
            this.billingStarted = billingStarted;
        }
    }

    /** A stale caller lost ownership before entering a formal generation. */
    public static final class AdmissionSupersededException
            extends IllegalStateException {
        AdmissionSupersededException(String message) {
            super(message);
        }
    }

    private final DualMachineSidecarPort sidecar;
    private final DualMachineFormalUsageStateMachine stateMachine;
    private final DualMachineUsageLeaseKeyring leaseKeyring;
    private final DualMachineCardAuthorizationCoordinator.IdentityBinding
            hostIdentity;
    private final DualMachineCardAuthorizationCoordinator.IdentityBinding
            androidIdentity;
    private final RuntimeBoundary runtimeBoundary;
    private final HexIdSource idSource;
    private final TimeSource timeSource;
    private final DualMachineUsageLeaseGate.MonotonicClock monotonicClock;
    private final DeadlineScheduler deadlineScheduler;
    private final LongSupplier hostProgressSource;
    private final LongSupplier androidProgressSource;

    private DualMachineUsageLeaseGate leaseGate;
    private DualMachineSessionProgressCounter hostProgress;
    private DualMachineSessionProgressCounter androidProgress;
    private volatile DualMachineUsageLeaseVerifier.VerifiedLease lastLease;
    private String lastLeaseToken = "";
    private String channelBindingSha256 = "";
    private long lastHostProgress;
    private long lastAndroidProgress;
    private RenewalProgressObservation lastRenewalProgressObservation =
            new RenewalProgressObservation(0L, 0L, 0L, 0L);
    private volatile RenewalTiming lastRenewalTiming =
            RenewalTiming.skipped("not_attempted");
    private volatile boolean dataPlaneOpen;
    private volatile PendingStart pendingStart;
    private volatile PendingStart lifecycleStart;
    private PendingHeartbeat pendingHeartbeat;
    private DeadlineScheduler.ScheduledDeadline scheduledDeadline;
    private volatile StopOutcome completedLifecycleStop;
    private volatile StartAdmissionToken preparedStartAdmission;
    private final AtomicLong deadlineGeneration = new AtomicLong();
    private final AtomicBoolean immediateStopRequested =
            new AtomicBoolean();
    private final AtomicBoolean runtimeBoundaryCloseRequired =
            new AtomicBoolean();
    /** Serializes start rearm/admission publication with local stop claims. */
    private final Object generationStopLock = new Object();
    private final Object runtimeTransitionLock = new Object();
    private volatile boolean futureLeaseStaged;
    private volatile long stagedNotBeforeMonotonicNanos = -1L;

    public DualMachineFormalUsageCoordinator(
            DualMachineSidecarPort sidecar,
            DualMachineFormalUsageStateMachine stateMachine,
            DualMachineUsageLeaseKeyring leaseKeyring,
            DualMachineCardAuthorizationCoordinator.IdentityBinding
                    hostIdentity,
            DualMachineCardAuthorizationCoordinator.IdentityBinding
                    androidIdentity,
            RuntimeBoundary runtimeBoundary,
            HexIdSource idSource,
            TimeSource timeSource,
            DualMachineUsageLeaseGate.MonotonicClock monotonicClock,
            DeadlineScheduler deadlineScheduler,
            LongSupplier hostProgressSource,
            LongSupplier androidProgressSource) {
        if (sidecar == null || stateMachine == null || leaseKeyring == null
                || hostIdentity == null || androidIdentity == null
                || runtimeBoundary == null || idSource == null
                || timeSource == null || monotonicClock == null
                || deadlineScheduler == null
                || hostProgressSource == null
                || androidProgressSource == null) {
            throw new IllegalArgumentException(
                    "formal usage dependencies are required");
        }
        this.sidecar = sidecar;
        this.stateMachine = stateMachine;
        this.leaseKeyring = leaseKeyring;
        this.hostIdentity = hostIdentity;
        this.androidIdentity = androidIdentity;
        this.runtimeBoundary = runtimeBoundary;
        this.idSource = idSource;
        this.timeSource = timeSource;
        this.monotonicClock = monotonicClock;
        this.deadlineScheduler = deadlineScheduler;
        this.hostProgressSource = hostProgressSource;
        this.androidProgressSource = androidProgressSource;
    }

    /**
     * The only paid start entrypoint. The authenticated Host is revalidated
     * while its data plane remains closed, then the raw lease is committed.
     */
    synchronized DataPlanePermit startAfterVerifiedHostVideo(
            StartAdmissionToken admission)
            throws IOException, GeneralSecurityException {
        if (admission == null || admission.owner != this
                || preparedStartAdmission != admission) {
            throw new AdmissionSupersededException(
                    "formal start admission was superseded");
        }
        // Consume before any readiness or network operation. A duplicate call
        // and every token invalidated by a stop are permanently unusable.
        preparedStartAdmission = null;
        requireNotStopped();
        DualMachineFormalUsageStateMachine.Snapshot before =
                stateMachine.snapshot();
        if (!before.canFormalStart() || before.entitlement == null) {
            throw new IllegalStateException("formal start is unavailable");
        }
        requireIdentityBinding(before.entitlement);
        try {
            // Preparation configures decoder/native state even though UDP is
            // still closed. Publish its close obligation before entering the
            // boundary so a concurrent lifecycle stop cannot miss it.
            runtimeBoundaryCloseRequired.set(true);
            StartReadiness readiness =
                    runtimeBoundary.prepareWithDataPlaneClosed(
                            immediateStopRequested::get);
            requireNotStopped();
            stateMachine.runtimeRequestedFormalStart(
                    readiness.hostRuntimeReady
                            && readiness.androidRuntimeReady);
            initializeGeneration(readiness.channelBindingSha256);
            return requestAndInstallInitialLease(before);
        } catch (StartCancelledException cancelled) {
            throw cancelled;
        } catch (DualMachineSidecarPort.RejectedException rejected) {
            PendingStart failedGeneration = pendingStart;
            if (failedGeneration != null) {
                preservePendingStartForCancellation();
                throw generationBoundRejectedException(
                        rejected, failedGeneration);
            } else if (isDeterministicClientRejection(rejected)) {
                abortStartingGeneration();
            } else {
                abortStartingGeneration();
            }
            throw rejected;
        } catch (IOException networkFailure) {
            PendingStart failedGeneration = pendingStart;
            if (failedGeneration != null) {
                if (mustPreservePendingStartForCancellation()
                        || hasReceivedInitialStartResponse()) {
                    preservePendingStartForCancellation();
                } else {
                    closeDataPlaneOnly();
                }
                throw generationBoundIOException(
                        networkFailure, failedGeneration);
            } else {
                abortStartingGeneration();
            }
            throw networkFailure;
        } catch (GeneralSecurityException failure) {
            PendingStart failedGeneration = pendingStart;
            if (failedGeneration != null) {
                preservePendingStartForCancellation();
                throw generationBoundSecurityException(
                        failure, failedGeneration);
            } else {
                abortStartingGeneration();
            }
            throw failure;
        } catch (RuntimeException failure) {
            PendingStart failedGeneration = pendingStart;
            if (failedGeneration != null) {
                preservePendingStartForCancellation();
                throw generationBoundRuntimeException(
                        failure, failedGeneration);
            } else {
                abortStartingGeneration();
            }
            throw failure;
        }
    }

    /**
     * Explicitly replays the exact idempotency key and signed bytes retained
     * after an ambiguous start response. It never creates a second debit.
     */
    synchronized RetryAdmissionToken capturePendingStartRetryAdmission() {
        if (immediateStopRequested.get() || pendingStart == null
                || stateMachine.snapshot().state
                != DualMachineFormalUsageStateMachine.State.STARTING) {
            throw new IllegalStateException(
                    "no pending formal start response");
        }
        return new RetryAdmissionToken(this, pendingStart);
    }

    synchronized DataPlanePermit retryPendingStart(
            RetryAdmissionToken admission)
            throws IOException, GeneralSecurityException {
        if (admission == null || admission.owner != this
                || pendingStart != admission.generation
                || stateMachine.snapshot().state
                != DualMachineFormalUsageStateMachine.State.STARTING) {
            throw new AdmissionSupersededException(
                    "pending formal start admission was superseded");
        }
        requireNotStopped();
        PendingStart pending = admission.generation;
        try {
        runtimeBoundary.verifyFreshHostVideoBeforePotentialDebit(
                channelBindingSha256,
                pending.request.requestId,
                immediateStopRequested::get);
        requireNotStopped();
        } catch (IOException failure) {
            throw generationBoundIOException(failure, pending);
        } catch (GeneralSecurityException failure) {
            throw generationBoundSecurityException(failure, pending);
        } catch (RuntimeException failure) {
            throw generationBoundRuntimeException(failure, pending);
        }
        final DualMachineSidecarPort.UsageLeaseResponse response;
        try {
            pending.startRequestDispatched = true;
            response = sidecar.startUsage(pending.request);
            pending.startResponseReceived = true;
        } catch (DualMachineSidecarPort.RejectedException rejected) {
            // A retry follows an already ambiguous original request. Generic
            // 4xx/429 cannot prove that original request was never committed.
            preservePendingStartForCancellation();
            throw generationBoundRejectedException(rejected, pending);
        } catch (IOException networkFailure) {
            closeDataPlaneOnly();
            throw generationBoundIOException(networkFailure, pending);
        } catch (RuntimeException postDispatchFailure) {
            preservePendingStartForCancellation();
            throw generationBoundRuntimeException(
                    postDispatchFailure, pending);
        }
        try {
            return installInitialResponse(pending.before, response);
        } catch (StartCancelledException cancelled) {
            throw cancelled;
        } catch (IOException failure) {
            preservePendingStartForCancellation();
            throw generationBoundIOException(failure, pending);
        } catch (GeneralSecurityException failure) {
            preservePendingStartForCancellation();
            throw generationBoundSecurityException(failure, pending);
        } catch (RuntimeException failure) {
            preservePendingStartForCancellation();
            throw generationBoundRuntimeException(failure, pending);
        }
    }

    /**
     * Requests one next five-second segment only after both session progress
     * counters have strictly advanced. No progress means no network debit.
     */
    public synchronized RenewalOutcome renewAfterObservedProgress()
            throws IOException, GeneralSecurityException {
        requireNotStopped();
        requireRenewableSession();
        if (pendingHeartbeat != null) {
            throw new IllegalStateException(
                    "pending renewal must be retried exactly");
        }
        if (futureLeaseStaged) {
            synchronizeStagedLeaseIfDue();
            if (futureLeaseStaged) {
                lastRenewalTiming = RenewalTiming.skipped(
                        "future_already_staged");
                return RenewalOutcome.FUTURE_STAGED;
            }
        }
        long hostTotal = hostProgress.observe();
        long androidTotal = androidProgress.observe();
        lastRenewalProgressObservation = new RenewalProgressObservation(
                hostTotal,
                lastHostProgress,
                androidTotal,
                lastAndroidProgress);
        if (hostTotal <= lastHostProgress
                || androidTotal <= lastAndroidProgress) {
            lastRenewalTiming = RenewalTiming.skipped("no_progress");
            return RenewalOutcome.NO_PROGRESS;
        }
        DualMachineFormalUsageStateMachine.Snapshot before =
                stateMachine.snapshot();
        String requestId = nextId("heartbeat requestId");
        String requestNonce = nextDistinctId(
                requestId, "heartbeat requestNonce");
        long sequence = Math.addExact(lastLease.sequence(), 1L);
        long attemptStartedNanos = monotonicClock.nowNanos();
        long proofStartedNanos = attemptStartedNanos;
        long proofFinishedNanos = proofStartedNanos;
        boolean proofSucceeded = false;
        final DualMachineSidecarPort.HeartbeatRequest request;
        try {
            request = heartbeatRequest(
                    before.entitlement,
                    requestId,
                    requestNonce,
                    sequence,
                    hostTotal,
                    androidTotal);
            proofSucceeded = true;
        } finally {
            proofFinishedNanos = monotonicClock.nowNanos();
            recordRenewalTiming(
                    sequence,
                    proofSucceeded ? "proof_completed" : "proof_failed",
                    attemptStartedNanos,
                    proofStartedNanos,
                    proofFinishedNanos,
                    -1L,
                    -1L,
                    -1L,
                    -1L);
        }
        PendingHeartbeat pending = new PendingHeartbeat(
                before, request, hostTotal, androidTotal, sequence);
        pendingHeartbeat = pending;
        long sidecarStartedNanos = proofFinishedNanos;
        long sidecarFinishedNanos = sidecarStartedNanos;
        boolean sidecarSucceeded = false;
        final DualMachineSidecarPort.UsageLeaseResponse response;
        try {
            response = sidecar.heartbeat(request);
            sidecarSucceeded = true;
        } catch (IOException networkFailure) {
            // The already installed ticket remains authoritative until its
            // monotonic expiry. The health timer will close it automatically.
            throw networkFailure;
        } finally {
            sidecarFinishedNanos = monotonicClock.nowNanos();
            recordRenewalTiming(
                    sequence,
                    sidecarSucceeded ? "sidecar_completed" : "sidecar_failed",
                    attemptStartedNanos,
                    proofStartedNanos,
                    proofFinishedNanos,
                    sidecarStartedNanos,
                    sidecarFinishedNanos,
                    -1L,
                    -1L);
        }
        long installStartedNanos = sidecarFinishedNanos;
        boolean installSucceeded = false;
        try {
            RenewalOutcome outcome = installRenewalResponse(pending, response);
            installSucceeded = true;
            return outcome;
        } catch (IOException | GeneralSecurityException
                 | RuntimeException failure) {
            failClosedLocally();
            throw failure;
        } finally {
            long installFinishedNanos = monotonicClock.nowNanos();
            recordRenewalTiming(
                    sequence,
                    installSucceeded ? "completed" : "install_failed",
                    attemptStartedNanos,
                    proofStartedNanos,
                    proofFinishedNanos,
                    sidecarStartedNanos,
                    sidecarFinishedNanos,
                    installStartedNanos,
                    installFinishedNanos);
        }
    }

    /**
     * Reconciles the Android native counter after an explicitly owned pipeline
     * restart while preserving the session's monotonic progress total.
     *
     * <p>The reset sample adds no progress. Sampling it before the data plane
     * reopens lets the next genuinely processed frame advance the session total
     * instead of being consumed only as a reset baseline at lease expiry.</p>
     */
    public synchronized long reconcileKnownAndroidPipelineRestart()
            throws IOException {
        requireNotStopped();
        requireRenewableSession();
        if (pendingHeartbeat != null) {
            throw new IllegalStateException(
                    "pending renewal must be retried exactly");
        }
        return androidProgress.observe();
    }

    public synchronized RenewalProgressObservation
            latestRenewalProgressObservation() {
        return lastRenewalProgressObservation;
    }

    public synchronized RenewalTiming latestRenewalTiming() {
        return lastRenewalTiming;
    }

    private void recordRenewalTiming(
            long sequence,
            String terminalPhase,
            long attemptStartedNanos,
            long proofStartedNanos,
            long proofFinishedNanos,
            long sidecarStartedNanos,
            long sidecarFinishedNanos,
            long installStartedNanos,
            long installFinishedNanos) {
        long finishedNanos = installFinishedNanos >= 0L
                ? installFinishedNanos
                : sidecarFinishedNanos >= 0L
                ? sidecarFinishedNanos
                : proofFinishedNanos;
        lastRenewalTiming = new RenewalTiming(
                true,
                sequence,
                elapsedMillis(proofStartedNanos, proofFinishedNanos),
                elapsedMillis(sidecarStartedNanos, sidecarFinishedNanos),
                elapsedMillis(installStartedNanos, installFinishedNanos),
                elapsedMillis(attemptStartedNanos, finishedNanos),
                terminalPhase);
    }

    private static long elapsedMillis(long startedNanos, long finishedNanos) {
        if (startedNanos < 0L || finishedNanos < startedNanos) return 0L;
        return TimeUnit.NANOSECONDS.toMillis(finishedNanos - startedNanos);
    }

    /** Replays one ambiguous heartbeat using the exact original signed body. */
    public synchronized RenewalOutcome retryPendingRenewal()
            throws IOException, GeneralSecurityException {
        requireNotStopped();
        requireRenewableSession();
        if (pendingHeartbeat == null) {
            throw new IllegalStateException(
                    "no pending renewal response");
        }
        PendingHeartbeat pending = pendingHeartbeat;
        long sequence = pending.sequence;
        long attemptStartedNanos = monotonicClock.nowNanos();
        long sidecarStartedNanos = attemptStartedNanos;
        long sidecarFinishedNanos = sidecarStartedNanos;
        boolean sidecarSucceeded = false;
        final DualMachineSidecarPort.UsageLeaseResponse response;
        try {
            response = sidecar.heartbeat(pending.request);
            sidecarSucceeded = true;
        } catch (IOException networkFailure) {
            throw networkFailure;
        } finally {
            sidecarFinishedNanos = monotonicClock.nowNanos();
            recordRenewalTiming(
                    sequence,
                    sidecarSucceeded
                            ? "retry_sidecar_completed"
                            : "retry_sidecar_failed",
                    attemptStartedNanos,
                    -1L,
                    -1L,
                    sidecarStartedNanos,
                    sidecarFinishedNanos,
                    -1L,
                    -1L);
        }
        long installStartedNanos = sidecarFinishedNanos;
        boolean installSucceeded = false;
        try {
            RenewalOutcome outcome = installRenewalResponse(pending, response);
            installSucceeded = true;
            return outcome;
        } catch (IOException | GeneralSecurityException
                 | RuntimeException failure) {
            failClosedLocally();
            throw failure;
        } finally {
            long installFinishedNanos = monotonicClock.nowNanos();
            recordRenewalTiming(
                    sequence,
                    installSucceeded ? "completed" : "retry_install_failed",
                    attemptStartedNanos,
                    -1L,
                    -1L,
                    sidecarStartedNanos,
                    sidecarFinishedNanos,
                    installStartedNanos,
                    installFinishedNanos);
        }
    }

    public synchronized long millisUntilRenewalWindow(
            long renewalWindowSeconds) {
        if (lastLease == null || renewalWindowSeconds < 0L) {
            return 0L;
        }
        long windowNanos = TimeUnit.SECONDS.toNanos(renewalWindowSeconds);
        long opensAtNanos = lastLease.expiresAtMonotonicNanos()
                - windowNanos;
        long nowNanos = monotonicClock.nowNanos();
        if (opensAtNanos <= nowNanos) {
            return 0L;
        }
        return TimeUnit.NANOSECONDS.toMillis(opensAtNanos - nowNanos);
    }

    /**
     * Called by the exact lease deadline timer and by a short health fallback.
     */
    public synchronized DataPlanePermitState
            enforceAndGetDataPlanePermitState() {
        if (immediateStopRequested.get()) {
            // A retired coordinator shares the service boundary and state
            // machine with its replacement. Once retirement is latched it may
            // report only CLOSED; it must not invoke or mutate shared B state.
            return DataPlanePermitState.CLOSED;
        }
        DualMachineFormalUsageStateMachine.Snapshot current =
                stateMachine.snapshot();
        boolean stagedGap = current.state
                == DualMachineFormalUsageStateMachine.State.RENEWAL_GAP
                && futureLeaseStaged;
        if ((current.state
                != DualMachineFormalUsageStateMachine.State.ACTIVE
                && !stagedGap) || leaseGate == null) {
            closeDataPlaneOnly();
            if (current.state
                    == DualMachineFormalUsageStateMachine.State.ACTIVE) {
                stateMachine.leaseExpiredLocally();
            }
            return DataPlanePermitState.CLOSED;
        }

        DataPlanePermitState runtimeState = enforceRuntimeLeaseWindow();
        if (runtimeState == DataPlanePermitState.STAGED_WAITING) {
            if (!futureLeaseStaged) {
                closeDataPlaneOnly();
                cancelScheduledDeadline();
                return DataPlanePermitState.CLOSED;
            }
            dataPlaneOpen = false;
            if (current.state
                    == DualMachineFormalUsageStateMachine.State.ACTIVE) {
                stateMachine.leaseExpiredLocally();
            }
            scheduleStagedActivationIfNeeded();
            return DataPlanePermitState.STAGED_WAITING;
        }
        if (runtimeState != DataPlanePermitState.OPEN) {
            closeDataPlaneOnly();
            cancelScheduledDeadline();
            if (current.state
                    == DualMachineFormalUsageStateMachine.State.ACTIVE) {
                stateMachine.leaseExpiredLocally();
            }
            return DataPlanePermitState.CLOSED;
        }
        try {
            synchronizeStagedLeaseIfDue();
        } catch (IOException | RuntimeException failure) {
            failClosedLocally();
            return DataPlanePermitState.CLOSED;
        }
        if (leaseGate.activeLease() == null) {
            closeDataPlaneOnly();
            cancelScheduledDeadline();
            if (stateMachine.snapshot().state
                    == DualMachineFormalUsageStateMachine.State.ACTIVE) {
                stateMachine.leaseExpiredLocally();
            }
            return DataPlanePermitState.CLOSED;
        }
        DualMachineFormalUsageStateMachine.Snapshot after =
                stateMachine.snapshot();
        return after.permitsDataPlane && dataPlaneOpen
                ? DataPlanePermitState.OPEN
                : DataPlanePermitState.CLOSED;
    }

    /**
     * Stops locally first. Network confirmation is deliberately best effort
     * and can never keep the video/control path open.
     */
    public StopOutcome stopForRuntimeLifecycle() {
        requestImmediateLocalStop();
        LifecycleStopHandle handle = captureLifecycleStop();
        if (handle != null) {
            return handle.stopFormalUsage();
        }
        synchronized (this) {
            if (completedLifecycleStop != null) {
                return completedLifecycleStop;
            }
            return finishRuntimeStop(false, null, null);
        }
    }

    private StopOutcome stopForRuntimeLifecycle(
            PendingStart expectedGeneration,
            PendingStart startToCancel) {
        latchImmediateLocalStop(expectedGeneration);
        // A delayed handle is bound to expectedGeneration, so this request can
        // neither latch nor cancel a later lifecycle owner. Send it before the
        // monitor acquisition to break a startUsage/cancelStart dependency.
        DualMachineSidecarPort.StartCancellationResponse earlyResponse = null;
        if (startToCancel != null) {
            earlyResponse = sendAndRecordStartCancellation(startToCancel);
        }
        synchronized (this) {
            StopOutcome completed =
                    expectedGeneration.completedStopOutcome;
            if (completed != null) return completed;
            if (lifecycleStart == expectedGeneration) {
                return finishRuntimeStop(
                        false, expectedGeneration, startToCancel);
            }
        }
        DualMachineSidecarPort.StartCancellationResponse response =
                earlyResponse;
        if (response == null && startToCancel != null) {
            response = sendAndRecordStartCancellation(startToCancel);
        }
        if (response == null && startToCancel != null) {
            response = startToCancel.cancellationResponse.get();
            if (!validStartCancellationResponse(
                    response, startToCancel)) {
                response = null;
            }
        }
        StopOutcome outcome = new StopOutcome(
                true,
                response != null,
                response == null
                        ? expectedGeneration.before.remainingSeconds
                        : response.remainingSeconds,
                startToCancel != null
                        && (!startToCancel.startRequestDispatched
                        || response != null
                        && "not_started".equals(response.sessionStatus)
                        && !response.billingStarted));
        if (response != null) {
            expectedGeneration.completedStopOutcome = outcome;
        }
        finalizeAutomaticUsageGeneration(expectedGeneration, outcome);
        return outcome;
    }

    /**
     * Sets the stop latch and synchronously closes the local capability before
     * a service queues the potentially blocking best-effort server stop.
     */
    public void requestImmediateLocalStop() {
        latchImmediateLocalStop();
    }

    private boolean latchImmediateLocalStop() {
        synchronized (generationStopLock) {
            synchronized (runtimeTransitionLock) {
                if (!immediateStopRequested.compareAndSet(false, true)) {
                    return false;
                }
                // This is the cross-thread kill path. It must never acquire the
                // coordinator monitor: startAfterVerifiedHostVideo may hold that
                // monitor while startUsage is blocked, and the pre-signed
                // cancellation must be able to race that request. The volatile
                // admission write also invalidates a token whose synchronized
                // start entry has not consumed it yet.
                preparedStartAdmission = null;
                closeRuntimeBoundaryIgnoringFailure();
                dataPlaneOpen = false;
                return true;
            }
        }
    }

    /**
     * Exact-generation variant for delayed lifecycle handles. The ownership
     * check, generation clear, new-start rearm and lifecycle publication share
     * generationStopLock, so an A handle cannot poison replacement B after an
     * earlier ownership check. The nested runtimeTransitionLock separately
     * orders the exact physical close against data-plane open.
     */
    private boolean latchImmediateLocalStop(PendingStart expectedGeneration) {
        synchronized (generationStopLock) {
            synchronized (runtimeTransitionLock) {
                if (lifecycleStart != expectedGeneration) return false;
                immediateStopRequested.compareAndSet(false, true);
                preparedStartAdmission = null;
                closeRuntimeBoundaryIgnoringFailure();
                dataPlaneOpen = false;
                return true;
            }
        }
    }

    /**
     * Rearms only after the Runtime has linearized completion of every older
     * lifecycle-stop owner. Never call this directly from a start worker.
     */
    StartAdmissionToken prepareForNewFormalStart() {
        synchronized (this) {
            if (lifecycleStart != null
                    || !stateMachine.snapshot().canFormalStart()) {
                throw new AdmissionSupersededException(
                        "previous formal generation is unresolved");
            }
            synchronized (generationStopLock) {
                // Rearm and token publication are one short transaction with
                // every local stop claim. No HTTP or coordinator-state cleanup
                // occurs while generationStopLock is held.
                completedLifecycleStop = null;
                immediateStopRequested.set(false);
                preparedStartAdmission = new StartAdmissionToken(this);
                return preparedStartAdmission;
            }
        }
    }

    /**
     * Sends the immutable, pre-signed cancellation for an in-flight start.
     * This method deliberately does not take the coordinator monitor, allowing
     * lifecycle cancellation to race a blocking start HTTP call. A later
     * {@link #stopForRuntimeLifecycle()} still replays the same request at least
     * once and owns the final state transition.
     */
    public boolean cancelPendingStart() {
        requestImmediateLocalStop();
        StartCancellationHandle handle = capturePendingStartCancellation();
        if (handle == null) {
            StopOutcome completed = completedLifecycleStop;
            return completed != null && completed.serverConfirmed;
        }
        return handle.sendExactCancellation();
    }

    /**
     * Captures the current immutable cancellation generation for queue handoff.
     * The returned handle remains bound to its startRequestId after a later
     * generation begins.
     */
    public StartCancellationHandle capturePendingStartCancellation() {
        synchronized (generationStopLock) {
            PendingStart pending = pendingStart;
            return pending == null || pending != lifecycleStart ? null
                    : new StartCancellationHandle(this, pending);
        }
    }

    /** Captures the exact lifecycle generation for queued ordinary stop. */
    public LifecycleStopHandle captureLifecycleStop() {
        synchronized (generationStopLock) {
            PendingStart generation = lifecycleStart;
            if (generation == null) return null;
            PendingStart startToCancel = pendingStart == generation
                    ? generation : null;
            return new LifecycleStopHandle(
                    this, generation, startToCancel);
        }
    }

    /** True only while the exact pre-signed cancellation must be retained. */
    public boolean hasPendingStartCancellation() {
        PendingStart generation = lifecycleStart;
        return generation != null
                && (pendingStart != null
                || immediateStopRequested.get()
                || stateMachine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STOPPING);
    }

    /**
     * Immediate local kill switch for an authenticated revoked status. The
     * service owner must invoke this in the same serialized command that
     * accepts the card coordinator's revoked snapshot.
     */
    public void failCloseFromEntitlementRevocation() {
        boolean firstStop = latchImmediateLocalStop();
        LifecycleStopHandle lifecycle = captureLifecycleStop();
        StartCancellationHandle cancellation = lifecycle == null ? null
                : lifecycle.startCancellationHandle();
        if (cancellation != null) {
            cancellation.sendExactCancellation();
        }
        synchronized (this) {
            if (!firstStop && lifecycleStart == null) return;
            if (leaseGate != null) leaseGate.revoke();
            if (lifecycle != null && lifecycleStart == lifecycle.generation) {
                finishRuntimeStop(
                        false,
                        lifecycle.generation,
                        lifecycle.startToCancel);
            } else {
                cancelScheduledDeadline();
                closeDataPlaneOnly();
                failProgressCounters();
                clearGeneration();
            }
            stateMachine.revoke();
        }
    }

    /**
     * Immediate local-only kill switch for loss or replacement of the
     * authenticated Host session, CAT6 route, or secure channel binding.
     *
     * <p>The exact stop for the latest verified lease and every in-flight-start
     * cancellation are dual-signed while the attachment is still valid. Runtime
     * loss therefore replays immutable requests and never depends on a detached
     * Host signer.</p>
     */
    public void failCloseFromRuntimeLoss() {
        boolean firstStop = latchImmediateLocalStop();
        LifecycleStopHandle lifecycle = captureLifecycleStop();
        StartCancellationHandle cancellation = lifecycle == null ? null
                : lifecycle.startCancellationHandle();
        if (cancellation != null) {
            cancellation.sendExactCancellation();
        }
        synchronized (this) {
            if (!firstStop && lifecycleStart == null) return;
            if (lifecycle != null && lifecycleStart == lifecycle.generation) {
                finishRuntimeStop(
                        false,
                        lifecycle.generation,
                        lifecycle.startToCancel);
            } else {
                failClosedLocally();
            }
        }
    }

    private StopOutcome finishRuntimeStop(
            boolean cacheForQueuedStopOwner,
            PendingStart lifecycleGeneration,
            PendingStart startToCancel) {
        if (startToCancel != null
                && startToCancel != lifecycleGeneration) {
            throw new IllegalArgumentException(
                    "start cancellation must belong to lifecycle owner");
        }
        DualMachineFormalUsageStateMachine.Snapshot before =
                stateMachine.snapshot();
        if (leaseGate != null) leaseGate.stop();
        cancelScheduledDeadline();
        boolean localClosed = closeDataPlaneOnly();
        failProgressCounters();
        if (before.canFormalStop()) {
            stateMachine.closeLocalForRuntimeStop();
        }

        boolean serverConfirmed = false;
        boolean serverRevoked = false;
        long remaining = before.remainingSeconds;
        PendingStart stopGeneration = lifecycleGeneration != null
                ? lifecycleGeneration : lifecycleStart;
        DualMachineSidecarPort.StopRequest preparedStopRequest =
                stopGeneration == null ? null
                : stopGeneration.preparedStopRequest;
        if (preparedStopRequest != null) {
            try {
                DualMachineSidecarPort.StopResponse response =
                        sidecar.stop(preparedStopRequest);
                serverConfirmed = validStopResponse(response, before);
                if (serverConfirmed) remaining = response.remainingSeconds;
            } catch (IOException | RuntimeException ignored) {
                // Local closure is the primary user-rights guarantee.
            }
        }
        if (!serverConfirmed && startToCancel != null) {
            DualMachineSidecarPort.StartCancellationResponse response =
                    startToCancel.cancellationResponse.get();
            if (!validStartCancellationResponse(response, startToCancel)) {
                response = null;
            }
            if (response == null) {
                response = sendAndRecordStartCancellation(startToCancel);
            }
            if (response == null) {
                // Exact retry: the immutable request object, signatures,
                // request id and nonce are deliberately reused byte-for-byte.
                response = sendAndRecordStartCancellation(startToCancel);
            }
            if (response == null) {
                response = startToCancel.cancellationResponse.get();
                if (!validStartCancellationResponse(
                        response, startToCancel)) {
                    response = null;
                }
            }
            if (response != null) {
                serverConfirmed = true;
                remaining = response.remainingSeconds;
                serverRevoked = "revoked".equals(response.sessionStatus);
            }
        }
        boolean definitelyNotStarted = startToCancel != null
                && (!startToCancel.startRequestDispatched
                || serverConfirmed
                && startToCancel.cancellationResponse.get() != null
                && "not_started".equals(
                startToCancel.cancellationResponse.get().sessionStatus)
                && !startToCancel.cancellationResponse.get().billingStarted);
        boolean pendingCancellationAmbiguous = lifecycleGeneration != null
                && !serverConfirmed && !definitelyNotStarted;
        if (stateMachine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STOPPING) {
            if (pendingCancellationAmbiguous) {
                // Keep STOPPING and the exact immutable cancellation. Returning
                // to idle here would permit a fresh start while the server may
                // still be committing the original request.
            } else if (serverRevoked) {
                stateMachine.revoke();
            } else {
                stateMachine.stopFinished(remaining);
            }
        }
        StopOutcome outcome = new StopOutcome(
                localClosed,
                serverConfirmed,
                remaining,
                definitelyNotStarted);
        finalizeAutomaticUsageGeneration(lifecycleGeneration, outcome);
        if (serverConfirmed && lifecycleGeneration != null) {
            lifecycleGeneration.completedStopOutcome = outcome;
        }
        if (serverConfirmed
                && (cacheForQueuedStopOwner
                || lifecycleGeneration != null)) {
            completedLifecycleStop = outcome;
        }
        if (!pendingCancellationAmbiguous) {
            // Publish the same-generation terminal outcome before the volatile
            // pendingStart=null release in clearGeneration(). A concurrent
            // cancellation observer can therefore never see both as absent.
            clearGeneration();
        }
        return outcome;
    }

    private DataPlanePermit requestAndInstallInitialLease(
            DualMachineFormalUsageStateMachine.Snapshot before)
            throws IOException, GeneralSecurityException {
        String requestId = nextId("start requestId");
        String requestNonce = nextDistinctId(
                requestId, "start requestNonce");
        DualMachineSidecarPort.StartChallengeRequest challengeRequest =
                startChallengeRequest(
                        before.entitlement, requestId, requestNonce);
        DualMachineSidecarPort.StartChallengeResponse challenge =
                sidecar.createStartChallenge(challengeRequest);
        requireNotStopped();
        requireFreshChallenge(challenge);
        DualMachineSidecarPort.StartUsageRequest startRequest =
                startRequest(
                        before.entitlement,
                        requestId,
                        requestNonce,
                        challenge);
        String cancellationRequestId = nextDistinctId(
                requestId, "start cancellation requestId");
        if (requestNonce.equals(cancellationRequestId)) {
            throw new GeneralSecurityException(
                    "start and cancellation identifiers must differ");
        }
        String cancellationRequestNonce = nextDistinctId(
                cancellationRequestId, "start cancellation requestNonce");
        if (requestId.equals(cancellationRequestNonce)
                || requestNonce.equals(cancellationRequestNonce)) {
            throw new GeneralSecurityException(
                    "start and cancellation identifiers must differ");
        }
        DualMachineSidecarPort.StartCancellationRequest cancellationRequest =
                startCancellationRequest(
                        before.entitlement,
                        cancellationRequestId,
                        cancellationRequestNonce,
                        requestId);
        PendingStart generation = new PendingStart(
                before, startRequest, cancellationRequest);
        synchronized (generationStopLock) {
            // Publish the immutable lifecycle owner in the same ordering domain
            // as rearm and exact-generation stop claims. A stale A handle can
            // therefore see only A, no owner, or B; it cannot poison B using a
            // check made before B publication.
            lifecycleStart = generation;
            pendingStart = generation;
        }
        runtimeBoundary.verifyFreshHostVideoBeforePotentialDebit(
                channelBindingSha256,
                generation.request.requestId,
                immediateStopRequested::get);
        requireNotStopped();
        pendingStart.startRequestDispatched = true;
        DualMachineSidecarPort.UsageLeaseResponse response =
                sidecar.startUsage(startRequest);
        pendingStart.startResponseReceived = true;
        return installInitialResponse(before, response);
    }

    private DataPlanePermit installInitialResponse(
            DualMachineFormalUsageStateMachine.Snapshot before,
            DualMachineSidecarPort.UsageLeaseResponse response)
            throws IOException, GeneralSecurityException {
        PendingStart initialStart = pendingStart;
        if (initialStart == null) {
            throw new GeneralSecurityException(
                    "formal start generation is unavailable");
        }
        DualMachineUsageLeaseVerifier.VerifiedLease verified =
                verifyLeaseResponse(
                        response,
                        before,
                        0L,
                        DualMachineUsageLeaseGate
                                .EMPTY_PREVIOUS_LEASE_SHA256);
        requireChargeAccounting(response, before);
        initialStart.verifiedSessionId = verified.sessionId();
        leaseGate.install(verified);
        stateMachine.verifiedInitialLeaseInstalled(
                verified.sessionId(),
                verified.sequence(),
                response.chargedSeconds,
                response.remainingSeconds,
                response.totalConsumedSeconds,
                response.billingStarted);
        lastLease = verified;
        lastLeaseToken = response.usageLease;
        DataPlanePermit permit = new DataPlanePermit(
                verified,
                response.usageLease,
                initialStart.request.requestId);
        if (immediateStopRequested.get()) {
            StopOutcome stopped = finishRuntimeStop(
                    true, initialStart, initialStart);
            throw new StartCancelledException(
                    stopped.serverConfirmed, true, null);
        }
        try {
            openDataPlaneWhileNotStopped(permit);
            // The Host accepts a stop proof only after the exact raw lease is
            // installed in its authenticated usage context. Pre-sign it at
            // that point so a later transport loss can replay the immutable
            // request without depending on a detached Host signer.
            initialStart.preparedStopRequest = stopRequest(
                    before.entitlement, verified, response.usageLease);
            scheduleLeaseDeadline(verified);
        } catch (IOException | GeneralSecurityException
                 | RuntimeException failure) {
            boolean lifecycleCancellation = immediateStopRequested.get();
            try {
                requestImmediateLocalStop();
                StopOutcome stopped = finishRuntimeStop(
                        lifecycleCancellation,
                        initialStart,
                        initialStart);
                if (lifecycleCancellation) {
                    throw new StartCancelledException(
                            stopped.serverConfirmed, true, failure);
                }
            } catch (StartCancelledException cancelled) {
                throw cancelled;
            } catch (RuntimeException cleanupFailure) {
                failure.addSuppressed(cleanupFailure);
            }
            throw failure;
        }
        if (immediateStopRequested.get()) {
            StopOutcome stopped = finishRuntimeStop(
                    true, initialStart, initialStart);
            throw new StartCancelledException(
                    stopped.serverConfirmed, true, null);
        }
        synchronized (generationStopLock) {
            pendingStart = null;
        }
        return permit;
    }

    private RenewalOutcome installRenewalResponse(
            PendingHeartbeat pending,
            DualMachineSidecarPort.UsageLeaseResponse response)
            throws IOException, GeneralSecurityException {
        requireNotStopped();
        DualMachineUsageLeaseVerifier.VerifiedLease verified =
                verifyLeaseResponse(
                        response,
                        pending.before,
                        pending.sequence,
                        lastLease.tokenSha256());
        PendingStart renewalGeneration = lifecycleStart;
        if (renewalGeneration == null) {
            throw new GeneralSecurityException(
                    "formal usage generation owner is unavailable");
        }
        DualMachineUsageLeaseGate.InstallResult installed =
                leaseGate.install(verified);
        requireChargeAccounting(response, pending.before);
        requireNotStopped();
        applyRuntimeLease(installed, verified, response.usageLease);
        // stageFutureLease/openDataPlane installs this exact lease in Host's
        // authorization context; only then may Host sign its stop proof.
        DualMachineSidecarPort.StopRequest preparedStopRequest = stopRequest(
                pending.before.entitlement, verified, response.usageLease);
        if (installed
                == DualMachineUsageLeaseGate.InstallResult.FUTURE_STAGED) {
            stateMachine.verifiedFutureRenewalStaged(
                    verified.sequence(),
                    response.chargedSeconds,
                    response.remainingSeconds,
                    response.totalConsumedSeconds);
        } else if (installed
                == DualMachineUsageLeaseGate.InstallResult
                .CURRENT_INSTALLED) {
            stateMachine.verifiedRenewalInstalled(
                    verified.sequence(),
                    response.chargedSeconds,
                    response.remainingSeconds,
                    response.totalConsumedSeconds);
        } else {
            requireIdempotentRenewalState(verified, response);
        }
        lastHostProgress = pending.hostProgress;
        lastAndroidProgress = pending.androidProgress;
        renewalGeneration.preparedStopRequest = preparedStopRequest;
        lastLease = verified;
        lastLeaseToken = response.usageLease;
        pendingHeartbeat = null;
        return renewalOutcome(installed);
    }

    private DualMachineSidecarPort.StartChallengeRequest
            startChallengeRequest(
            DualMachineEntitlementRecord entitlement,
            String requestId,
            String requestNonce)
            throws IOException, GeneralSecurityException {
        DualMachineUsageAuthorizationContract.UsageStartChallenge value =
                new DualMachineUsageAuthorizationContract
                        .UsageStartChallenge();
        value.channelBindingSha256 = channelBindingSha256;
        value.entitlementId = entitlement.entitlementId;
        value.pairId = entitlement.pairId;
        value.requestId = requestId;
        value.requestNonce = requestNonce;
        value.revocationVersion = entitlement.revocationVersion;
        DualMachineDeviceProofs.SignedProof signed = sign(
                DualMachineUsageAuthorizationContract
                        .usageStartChallenge(value));
        return new DualMachineSidecarPort.StartChallengeRequest(
                usageProof(entitlement, signed),
                requestId,
                requestNonce,
                channelBindingSha256);
    }

    private DualMachineSidecarPort.StartUsageRequest startRequest(
            DualMachineEntitlementRecord entitlement,
            String requestId,
            String requestNonce,
            DualMachineSidecarPort.StartChallengeResponse challenge)
            throws IOException, GeneralSecurityException {
        DualMachineUsageAuthorizationContract.UsageStart value =
                new DualMachineUsageAuthorizationContract.UsageStart();
        value.androidFramesTotal = 0L;
        value.androidRuntimeReady = true;
        value.channelBindingSha256 = channelBindingSha256;
        value.entitlementId = entitlement.entitlementId;
        value.hostFramesTotal = 0L;
        value.hostRuntimeReady = true;
        value.pairId = entitlement.pairId;
        value.requestId = requestId;
        value.requestNonce = requestNonce;
        value.revocationVersion = entitlement.revocationVersion;
        value.startChallengeId = challenge.challengeId;
        value.startChallengeTokenSha256 = sha256Hex(
                challenge.challengeToken.getBytes(
                        StandardCharsets.US_ASCII));
        DualMachineDeviceProofs.SignedProof signed = sign(
                DualMachineUsageAuthorizationContract.usageStart(value));
        return new DualMachineSidecarPort.StartUsageRequest(
                usageProof(entitlement, signed),
                requestId,
                requestNonce,
                channelBindingSha256,
                0L,
                0L,
                challenge.challengeId,
                challenge.challengeToken);
    }

    private DualMachineSidecarPort.StartCancellationRequest
            startCancellationRequest(
            DualMachineEntitlementRecord entitlement,
            String requestId,
            String requestNonce,
            String startRequestId)
            throws IOException, GeneralSecurityException {
        DualMachineUsageAuthorizationContract.UsageStartCancel value =
                new DualMachineUsageAuthorizationContract.UsageStartCancel();
        value.channelBindingSha256 = channelBindingSha256;
        value.entitlementId = entitlement.entitlementId;
        value.pairId = entitlement.pairId;
        value.requestId = requestId;
        value.requestNonce = requestNonce;
        value.revocationVersion = entitlement.revocationVersion;
        value.startRequestId = startRequestId;
        DualMachineDeviceProofs.SignedProof signed = sign(
                DualMachineUsageAuthorizationContract
                        .usageStartCancel(value));
        return new DualMachineSidecarPort.StartCancellationRequest(
                usageProof(entitlement, signed),
                requestId,
                requestNonce,
                startRequestId,
                channelBindingSha256);
    }

    private DualMachineSidecarPort.HeartbeatRequest heartbeatRequest(
            DualMachineEntitlementRecord entitlement,
            String requestId,
            String requestNonce,
            long sequence,
            long hostFrames,
            long androidFrames)
            throws IOException, GeneralSecurityException {
        DualMachineUsageAuthorizationContract.UsageHeartbeat value =
                new DualMachineUsageAuthorizationContract.UsageHeartbeat();
        value.androidFramesTotal = androidFrames;
        value.channelBindingSha256 = channelBindingSha256;
        value.entitlementId = entitlement.entitlementId;
        value.hostFramesTotal = hostFrames;
        value.pairId = entitlement.pairId;
        value.previousLeaseSha256 = lastLease.tokenSha256();
        value.requestId = requestId;
        value.requestNonce = requestNonce;
        value.revocationVersion = entitlement.revocationVersion;
        value.sequence = sequence;
        value.sessionId = lastLease.sessionId();
        DualMachineDeviceProofs.SignedProof signed = sign(
                DualMachineUsageAuthorizationContract
                        .usageHeartbeat(value));
        return new DualMachineSidecarPort.HeartbeatRequest(
                usageProof(entitlement, signed),
                lastLease.sessionId(),
                requestId,
                requestNonce,
                channelBindingSha256,
                sequence,
                hostFrames,
                androidFrames,
                lastLeaseToken);
    }

    private DualMachineSidecarPort.StopRequest stopRequest(
            DualMachineEntitlementRecord entitlement,
            DualMachineUsageLeaseVerifier.VerifiedLease lease,
            String leaseToken)
            throws IOException, GeneralSecurityException {
        String requestId = nextId("stop requestId");
        String requestNonce = nextDistinctId(
                requestId, "stop requestNonce");
        DualMachineUsageAuthorizationContract.UsageStop value =
                new DualMachineUsageAuthorizationContract.UsageStop();
        value.channelBindingSha256 = channelBindingSha256;
        value.entitlementId = entitlement.entitlementId;
        value.pairId = entitlement.pairId;
        value.previousLeaseSha256 = lease.tokenSha256();
        value.requestId = requestId;
        value.requestNonce = requestNonce;
        value.revocationVersion = entitlement.revocationVersion;
        value.sessionId = lease.sessionId();
        DualMachineDeviceProofs.SignedProof signed = sign(
                DualMachineUsageAuthorizationContract.usageStop(value));
        return new DualMachineSidecarPort.StopRequest(
                usageProof(entitlement, signed),
                lease.sessionId(),
                requestId,
                requestNonce,
                channelBindingSha256,
                leaseToken);
    }

    private DualMachineUsageLeaseVerifier.VerifiedLease verifyLeaseResponse(
            DualMachineSidecarPort.UsageLeaseResponse response,
            DualMachineFormalUsageStateMachine.Snapshot before,
            long expectedSequence,
            String expectedPreviousLeaseSha256)
            throws GeneralSecurityException {
        if (response == null || before.entitlement == null
                || response.sequence != expectedSequence
                || !response.billingStarted
                || !before.entitlement.authorizationKind.equals(
                response.authorizationKind)
                || !before.entitlement.productKey.equals(
                response.productKey)
                || before.entitlement.permanent != response.permanent
                || (response.permanent
                ? response.chargedSeconds != 0L
                : response.chargedSeconds <= 0L)
                || response.ttlSeconds <= 0L
                || response.ttlSeconds > MAXIMUM_LEASE_SECONDS) {
            throw new GeneralSecurityException(
                    "usage lease response is incomplete");
        }
        long epochSeconds = timeSource.nowEpochSeconds();
        long monotonicNanos = monotonicClock.nowNanos();
        if (epochSeconds <= 0L || monotonicNanos < 0L) {
            throw new GeneralSecurityException(
                    "trusted time observation is invalid");
        }
        DualMachineUsageLeaseVerifier.ExpectedBinding expected =
                new DualMachineUsageLeaseVerifier.ExpectedBinding(
                        before.entitlement.entitlementId,
                        before.entitlement.pairId,
                        response.sessionId,
                        before.entitlement.protocolVersion,
                        before.entitlement.revocationVersion,
                        before.entitlement.hostKeySha256,
                        before.entitlement.androidKeySha256,
                        channelBindingSha256,
                        expectedSequence,
                        expectedPreviousLeaseSha256,
                        before.entitlement.authorizationKind,
                        before.entitlement.permanent);
        DualMachineUsageLeaseVerifier.VerifiedLease verified =
                leaseKeyring.verify(
                        response.usageLease,
                        expected,
                        epochSeconds,
                        monotonicNanos);
        if (!verified.tokenSha256().equals(
                response.usageLeaseSha256)
                || verified.sequence() != response.sequence
                || verified.remainingSeconds()
                != response.remainingSeconds
                || verified.notBeforeEpochSeconds()
                != response.notBeforeEpoch
                || verified.expiresAtEpochSeconds()
                != response.expiresAtEpoch
                || response.ttlSeconds
                != response.expiresAtEpoch - response.notBeforeEpoch
                || (response.permanent
                ? response.chargedSeconds != 0L
                : response.chargedSeconds != response.ttlSeconds)) {
            throw new GeneralSecurityException(
                    "usage lease response does not match signed claims");
        }
        if (expectedSequence > 0L) {
            if (lastLease == null) {
                throw new GeneralSecurityException(
                        "usage lease predecessor is unavailable");
            }
            verified = verified.alignContiguousRenewalAfter(lastLease);
        }
        return verified;
    }

    private void requireChargeAccounting(
            DualMachineSidecarPort.UsageLeaseResponse response,
            DualMachineFormalUsageStateMachine.Snapshot before)
            throws GeneralSecurityException {
        if (before.entitlement != null && before.entitlement.permanent) {
            if (!response.permanent
                    || response.chargedSeconds != 0L
                    || response.remainingSeconds != 0L
                    || response.totalConsumedSeconds != 0L
                    || before.remainingSeconds != 0L
                    || before.totalConsumedSeconds != 0L) {
                throw new GeneralSecurityException(
                        "permanent usage accounting is inconsistent");
            }
            return;
        }
        try {
            if (Math.addExact(
                    response.remainingSeconds,
                    response.chargedSeconds) != before.remainingSeconds
                    || Math.addExact(
                    before.totalConsumedSeconds,
                    response.chargedSeconds)
                    != response.totalConsumedSeconds) {
                throw new GeneralSecurityException(
                        "usage charge accounting is inconsistent");
            }
        } catch (ArithmeticException overflow) {
            throw new GeneralSecurityException(
                    "usage charge accounting overflow", overflow);
        }
    }

    private DualMachineDeviceProofs.SignedProof sign(byte[] payload)
            throws IOException, GeneralSecurityException {
        return DualMachineDeviceProofs.createVerified(
                payload,
                hostIdentity.publicKeyDer(),
                androidIdentity.publicKeyDer(),
                hostIdentity.signer,
                androidIdentity.signer);
    }

    private static DualMachineSidecarPort.UsageProof usageProof(
            DualMachineEntitlementRecord entitlement,
            DualMachineDeviceProofs.SignedProof signed) {
        return new DualMachineSidecarPort.UsageProof(
                entitlement.entitlementId,
                entitlement.pairId,
                entitlement.revocationVersion,
                signed.hostSignatureBase64,
                signed.androidSignatureBase64);
    }

    private void initializeGeneration(String channelBinding) {
        clearGeneration();
        channelBindingSha256 = DualMachineSidecarValues.sha256(
                channelBinding, "channelBindingSha256");
        leaseGate = new DualMachineUsageLeaseGate(monotonicClock);
        leaseGate.beginSession();
        hostProgress = new DualMachineSessionProgressCounter(
                hostProgressSource);
        androidProgress = new DualMachineSessionProgressCounter(
                androidProgressSource);
        hostProgress.beginSession();
        androidProgress.beginSession();
        lastHostProgress = 0L;
        lastAndroidProgress = 0L;
        futureLeaseStaged = false;
    }

    private void requireRenewableSession() {
        DualMachineFormalUsageStateMachine.State state =
                stateMachine.snapshot().state;
        if ((state != DualMachineFormalUsageStateMachine.State.ACTIVE
                && state
                != DualMachineFormalUsageStateMachine.State.RENEWAL_GAP)
                || leaseGate == null || !leaseGate.isAccepting()
                || lastLease == null || lastLeaseToken.isEmpty()
                || hostProgress == null || androidProgress == null) {
            throw new IllegalStateException(
                    "formal usage session is not renewable");
        }
    }

    private void requireFreshChallenge(
            DualMachineSidecarPort.StartChallengeResponse challenge)
            throws GeneralSecurityException {
        if (challenge == null
                || challenge.expiresAtEpoch
                <= requireEpochNow()) {
            throw new GeneralSecurityException(
                    "usage start challenge is missing or expired");
        }
    }

    private void requireIdentityBinding(
            DualMachineEntitlementRecord entitlement)
            throws GeneralSecurityException {
        String hostFingerprint = DualMachinePairingIdentityCodec
                .fingerprintHex(hostIdentity.publicKeyDer());
        String androidFingerprint = DualMachinePairingIdentityCodec
                .fingerprintHex(androidIdentity.publicKeyDer());
        if (!entitlement.hostKeySha256.equals(hostFingerprint)
                || !entitlement.androidKeySha256.equals(
                androidFingerprint)
                || !MessageDigest.isEqual(
                entitlement.hostIdentityPublicKeyDer(),
                hostIdentity.publicKeyDer())) {
            throw new GeneralSecurityException(
                    "formal usage identity binding changed");
        }
    }

    private void ensureDataPlaneOpen(
            DualMachineUsageLeaseVerifier.VerifiedLease verified,
            String signedUsageLease)
            throws IOException {
        if (!leaseGate.isOpen()) {
            closeDataPlaneOnly();
            return;
        }
        openDataPlaneWhileNotStopped(new DataPlanePermit(
                verified,
                signedUsageLease,
                requireLifecycleStartRequestId()));
        scheduleLeaseDeadline(verified);
    }

    private void applyRuntimeLease(
            DualMachineUsageLeaseGate.InstallResult installed,
            DualMachineUsageLeaseVerifier.VerifiedLease verified,
            String signedUsageLease)
            throws IOException {
        if (installed
                == DualMachineUsageLeaseGate.InstallResult.FUTURE_STAGED) {
            stageFutureLeaseWhileNotStopped(
                    new DataPlanePermit(
                            verified,
                            signedUsageLease,
                            requireLifecycleStartRequestId()));
            futureLeaseStaged = true;
            stagedNotBeforeMonotonicNanos =
                    verified.notBeforeMonotonicNanos();
            if (leaseGate.activeLease() == null) {
                scheduleStagedActivationIfNeeded();
            }
            return;
        }
        if (installed
                == DualMachineUsageLeaseGate.InstallResult.CURRENT_INSTALLED) {
            ensureDataPlaneOpen(verified, signedUsageLease);
        }
    }

    private void synchronizeStagedLeaseIfDue() throws IOException {
        if (!futureLeaseStaged || leaseGate == null || lastLease == null) {
            return;
        }
        DualMachineUsageLeaseVerifier.VerifiedLease active =
                leaseGate.activeLease();
        if (active == null
                || !active.tokenSha256().equals(lastLease.tokenSha256())) {
            return;
        }
        openDataPlaneWhileNotStopped(new DataPlanePermit(
                active,
                lastLeaseToken,
                requireLifecycleStartRequestId()));
        futureLeaseStaged = false;
        stagedNotBeforeMonotonicNanos = -1L;
        stateMachine.stagedRenewalActivated(active.sequence());
        lastHostProgress = hostProgress.observe();
        lastAndroidProgress = androidProgress.observe();
        scheduleLeaseDeadline(active);
    }

    private void scheduleLeaseDeadline(
            DualMachineUsageLeaseVerifier.VerifiedLease lease) {
        scheduleLeaseBoundary(lease.expiresAtMonotonicNanos());
    }

    private void scheduleLeaseBoundary(long deadlineMonotonicNanos) {
        cancelScheduledDeadline();
        final long generation = deadlineGeneration.incrementAndGet();
        DeadlineScheduler.ScheduledDeadline scheduled =
                deadlineScheduler.scheduleAt(
                        deadlineMonotonicNanos,
                        () -> runLeaseDeadline(generation));
        if (scheduled == null) {
            throw new IllegalStateException(
                    "lease deadline scheduler returned no handle");
        }
        scheduledDeadline = scheduled;
    }

    private void runLeaseDeadline(long generation) {
        if (generation != deadlineGeneration.get()) {
            return;
        }
        // Enforce the runtime boundary before acquiring the coordinator
        // monitor. A blocked HTTPS call therefore cannot extend paid use.
        final DataPlanePermitState runtimeState;
        synchronized (runtimeTransitionLock) {
            // Recheck after acquiring the same lock that protects boundary
            // closure. A cancelled A deadline must never close replacement B
            // in the check-to-lock race window.
            if (generation != deadlineGeneration.get()) {
                return;
            }
            runtimeState = enforceRuntimeLeaseWindowLocked();
        }
        if (runtimeState != DataPlanePermitState.OPEN) {
            // The boundary already closed atomically. Do not close it a
            // second time here: a concurrent renewal may stage the next
            // verified permit after the first call releases its lock.
            dataPlaneOpen = false;
        }
        synchronized (this) {
            if (generation != deadlineGeneration.get()) {
                return;
            }
            scheduledDeadline = null;
            enforceAndGetDataPlanePermitState();
        }
    }

    private void scheduleStagedActivationIfNeeded() {
        if (!futureLeaseStaged
                || stagedNotBeforeMonotonicNanos < 0L
                || scheduledDeadline != null) {
            return;
        }
        scheduleLeaseBoundary(stagedNotBeforeMonotonicNanos);
    }

    private void requireIdempotentRenewalState(
            DualMachineUsageLeaseVerifier.VerifiedLease verified,
            DualMachineSidecarPort.UsageLeaseResponse response)
            throws GeneralSecurityException {
        DualMachineFormalUsageStateMachine.Snapshot current =
                stateMachine.snapshot();
        if (current.leaseSequence != verified.sequence()
                || current.remainingSeconds != response.remainingSeconds
                || current.totalConsumedSeconds
                != response.totalConsumedSeconds) {
            throw new GeneralSecurityException(
                    "idempotent renewal state is inconsistent");
        }
    }

    private void cancelScheduledDeadline() {
        deadlineGeneration.incrementAndGet();
        DeadlineScheduler.ScheduledDeadline scheduled = scheduledDeadline;
        scheduledDeadline = null;
        if (scheduled != null) {
            try {
                scheduled.cancel();
            } catch (RuntimeException ignored) {
                // Runtime/gate closure remains authoritative.
            }
        }
    }

    private DataPlanePermitState enforceRuntimeLeaseWindow() {
        synchronized (runtimeTransitionLock) {
            return enforceRuntimeLeaseWindowLocked();
        }
    }

    private DataPlanePermitState enforceRuntimeLeaseWindowLocked() {
        if (immediateStopRequested.get()) {
            closeRuntimeBoundaryIgnoringFailure();
            return DataPlanePermitState.CLOSED;
        }
        try {
            return runtimeBoundary.enforceLeaseWindow();
        } catch (RuntimeException ignored) {
            return DataPlanePermitState.CLOSED;
        }
    }

    private void openDataPlaneWhileNotStopped(DataPlanePermit permit)
            throws IOException {
        synchronized (runtimeTransitionLock) {
            requireNotStopped();
            runtimeBoundaryCloseRequired.set(true);
            runtimeBoundary.openDataPlane(permit);
            if (immediateStopRequested.get()) {
                closeRuntimeBoundaryIgnoringFailure();
                throw new IOException(
                        "formal usage was stopped while opening data plane");
            }
            dataPlaneOpen = true;
        }
    }

    private void stageFutureLeaseWhileNotStopped(DataPlanePermit permit)
            throws IOException {
        synchronized (runtimeTransitionLock) {
            requireNotStopped();
            runtimeBoundary.stageFutureLease(permit);
            if (immediateStopRequested.get()) {
                closeRuntimeBoundaryIgnoringFailure();
                throw new IOException(
                        "formal usage was stopped while staging lease");
            }
        }
    }

    private void closeRuntimeBoundaryIgnoringFailure() {
        closeRuntimeBoundaryOnce();
    }

    private DualMachineSidecarPort.StartCancellationResponse
            sendAndRecordStartCancellation(PendingStart pending) {
        try {
            DualMachineSidecarPort.StartCancellationResponse response =
                    sidecar.cancelStart(pending.cancellationRequest);
            if (!validStartCancellationResponse(response, pending)) {
                return null;
            }
            pending.cancellationResponse.compareAndSet(null, response);
            DualMachineSidecarPort.StartCancellationResponse recorded =
                    pending.cancellationResponse.get();
            return validStartCancellationResponse(recorded, pending)
                    ? recorded : null;
        } catch (IOException | RuntimeException ignored) {
            return null;
        }
    }

    private boolean validStartCancellationResponse(
            DualMachineSidecarPort.StartCancellationResponse response,
            PendingStart pending) {
        if (response == null || pending == null
                || pending.before.entitlement == null
                || !response.startRequestId.equals(pending.request.requestId)
                || !pending.before.entitlement.authorizationKind.equals(
                response.authorizationKind)
                || pending.before.entitlement.permanent != response.permanent
                || response.chargedSeconds != 0L) {
            return false;
        }
        if (!pending.verifiedSessionId.isEmpty()) {
            return response.billingStarted
                    && response.sessionId.equals(
                    pending.verifiedSessionId)
                    && !response.sessionStatus.isEmpty();
        }
        if (response.permanent) {
            return response.remainingSeconds == 0L;
        }
        if ("not_started".equals(response.sessionStatus)) {
            return !response.billingStarted
                    && response.sessionId.isEmpty();
        }
        return response.billingStarted
                && !response.sessionId.isEmpty();
    }

    private boolean validStopResponse(
            DualMachineSidecarPort.StopResponse response,
            DualMachineFormalUsageStateMachine.Snapshot before) {
        return response != null
                && response.sessionId.equals(before.sessionId)
                && "ended".equals(response.status)
                && response.remainingSeconds == before.remainingSeconds
                && response.chargedSeconds == 0L
                && response.billingStarted == before.billingStarted
                && before.entitlement != null
                && before.entitlement.authorizationKind.equals(
                response.authorizationKind)
                && before.entitlement.permanent == response.permanent;
    }

    private static RenewalOutcome renewalOutcome(
            DualMachineUsageLeaseGate.InstallResult result) {
        switch (result) {
            case CURRENT_INSTALLED:
                return RenewalOutcome.CURRENT_INSTALLED;
            case FUTURE_STAGED:
                return RenewalOutcome.FUTURE_STAGED;
            case IDEMPOTENT:
                return RenewalOutcome.IDEMPOTENT;
            default:
                throw new IllegalArgumentException(
                        "unsupported lease install result");
        }
    }

    private void abortStartingGeneration() {
        closeDataPlaneOnly();
        if (leaseGate != null) leaseGate.stop();
        failProgressCounters();
        if (stateMachine.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STARTING) {
            stateMachine.formalStartFailed();
        } else {
            finishRunningStateLocally();
        }
        clearGeneration();
    }

    private static boolean isDeterministicClientRejection(
            DualMachineSidecarPort.RejectedException rejected) {
        return rejected.statusCode >= 400 && rejected.statusCode < 500;
    }

    private boolean mustPreservePendingStartForCancellation() {
        return immediateStopRequested.get() && pendingStart != null;
    }

    private boolean hasReceivedInitialStartResponse() {
        PendingStart pending = pendingStart;
        return pending != null && pending.startResponseReceived;
    }

    private TerminalStartFailureHandle terminalStartFailureHandle(
            PendingStart generation) {
        return new TerminalStartFailureHandle(this, generation);
    }

    private GenerationBoundIOException generationBoundIOException(
            IOException failure,
            PendingStart generation) {
        return new GenerationBoundIOException(
                failure, terminalStartFailureHandle(generation));
    }

    private GenerationBoundRejectedException
            generationBoundRejectedException(
            DualMachineSidecarPort.RejectedException failure,
            PendingStart generation) {
        return new GenerationBoundRejectedException(
                failure, terminalStartFailureHandle(generation));
    }

    private GenerationBoundSecurityException
            generationBoundSecurityException(
            GeneralSecurityException failure,
            PendingStart generation) {
        return new GenerationBoundSecurityException(
                failure, terminalStartFailureHandle(generation));
    }

    private GenerationBoundRuntimeException generationBoundRuntimeException(
            RuntimeException failure,
            PendingStart generation) {
        return new GenerationBoundRuntimeException(
                failure, terminalStartFailureHandle(generation));
    }

    private void preservePendingStartForCancellation() {
        immediateStopRequested.set(true);
        if (leaseGate != null) leaseGate.stop();
        cancelScheduledDeadline();
        closeDataPlaneOnly();
        failProgressCounters();
        DualMachineFormalUsageStateMachine.Snapshot current =
                stateMachine.snapshot();
        if (current.canFormalStop()) {
            stateMachine.closeLocalForRuntimeStop();
        }
    }

    private void finalizeAutomaticUsageGeneration(
            PendingStart generation,
            StopOutcome outcome) {
        if (generation == null || outcome == null
                || !generation.terminalFinalized.compareAndSet(
                false, true)) {
            return;
        }
        runtimeBoundary.finalizeFormalGeneration(
                generation.request.requestId,
                generation.request.channelBindingSha256,
                outcome);
    }

    private void failClosedLocally() {
        immediateStopRequested.set(true);
        if (leaseGate != null) leaseGate.stop();
        cancelScheduledDeadline();
        closeDataPlaneOnly();
        failProgressCounters();
        DualMachineFormalUsageStateMachine.Snapshot current =
                stateMachine.snapshot();
        if (current.canFormalStop()) {
            // Local capability closure is immediate, but the immutable
            // lifecycle generation must survive in STOPPING. The service can
            // then replay its already signed stop request even after Host
            // authentication disappears. Finishing and clearing here used to
            // orphan an active server session in ACTIVATED_IDLE.
            stateMachine.closeLocalForRuntimeStop();
        }
    }

    private void finishRunningStateLocally() {
        DualMachineFormalUsageStateMachine.Snapshot current =
                stateMachine.snapshot();
        if (current.canFormalStop()) {
            stateMachine.closeLocalForRuntimeStop();
            stateMachine.stopFinished(current.remainingSeconds);
        }
    }

    private boolean closeDataPlaneOnly() {
        synchronized (runtimeTransitionLock) {
            boolean closed = closeRuntimeBoundaryOnce();
            dataPlaneOpen = false;
            return closed;
        }
    }

    /**
     * Performs physical teardown once per prepared/open boundary generation.
     * A failed close restores the obligation so a later retry can finish it;
     * a successful close makes repeated stop/cancellation paths silent no-ops.
     */
    private boolean closeRuntimeBoundaryOnce() {
        if (!runtimeBoundaryCloseRequired.compareAndSet(true, false)) {
            return true;
        }
        try {
            runtimeBoundary.closeDataPlane();
            return true;
        } catch (RuntimeException | LinkageError ignored) {
            runtimeBoundaryCloseRequired.set(true);
            return false;
        }
    }

    private void requireNotStopped() throws IOException {
        if (immediateStopRequested.get()) {
            throw new IOException("formal usage was stopped locally");
        }
    }

    private String requireLifecycleStartRequestId() {
        PendingStart generation = lifecycleStart;
        if (generation == null) {
            throw new IllegalStateException(
                    "formal usage generation owner is unavailable");
        }
        return generation.request.requestId;
    }

    private void failProgressCounters() {
        if (hostProgress != null) hostProgress.failClosed();
        if (androidProgress != null) androidProgress.failClosed();
    }

    private void clearGeneration() {
        cancelScheduledDeadline();
        synchronized (generationStopLock) {
            leaseGate = null;
            hostProgress = null;
            androidProgress = null;
            lastLease = null;
            lastLeaseToken = "";
            channelBindingSha256 = "";
            lastHostProgress = 0L;
            lastAndroidProgress = 0L;
            lastRenewalProgressObservation =
                    new RenewalProgressObservation(0L, 0L, 0L, 0L);
            dataPlaneOpen = false;
            pendingStart = null;
            preparedStartAdmission = null;
            lifecycleStart = null;
            pendingHeartbeat = null;
            futureLeaseStaged = false;
            stagedNotBeforeMonotonicNanos = -1L;
        }
    }

    private String nextId(String name) {
        return DualMachineSidecarValues.hex128(
                idSource.nextHex128(), name);
    }

    private long requireEpochNow() throws GeneralSecurityException {
        long epochSeconds = timeSource.nowEpochSeconds();
        if (epochSeconds <= 0L) {
            throw new GeneralSecurityException(
                    "trusted epoch time is invalid");
        }
        return epochSeconds;
    }

    private String nextDistinctId(String first, String name)
            throws GeneralSecurityException {
        String second = nextId(name);
        if (first.equals(second)) {
            throw new GeneralSecurityException(
                    "request identifier and nonce must differ");
        }
        return second;
    }

    private static String sha256Hex(byte[] value)
            throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder result = new StringBuilder(digest.length * 2);
        for (byte current : digest) {
            result.append(String.format(
                    java.util.Locale.ROOT, "%02x", current & 0xff));
        }
        return result.toString();
    }

    private static String sha256HexRequired(byte[] value) {
        try {
            return sha256Hex(value);
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException(
                    "SHA-256 is unavailable", unavailable);
        }
    }

    private static final class PendingStart {
        final DualMachineFormalUsageStateMachine.Snapshot before;
        final DualMachineSidecarPort.StartUsageRequest request;
        final DualMachineSidecarPort.StartCancellationRequest
                cancellationRequest;
        final AtomicReference<DualMachineSidecarPort.StartCancellationResponse>
                cancellationResponse = new AtomicReference<>();
        final AtomicBoolean terminalFinalized = new AtomicBoolean();
        volatile boolean startRequestDispatched;
        volatile boolean startResponseReceived;
        volatile String verifiedSessionId = "";
        volatile DualMachineSidecarPort.StopRequest preparedStopRequest;
        volatile StopOutcome completedStopOutcome;

        PendingStart(
                DualMachineFormalUsageStateMachine.Snapshot before,
                DualMachineSidecarPort.StartUsageRequest request,
                DualMachineSidecarPort.StartCancellationRequest
                        cancellationRequest) {
            this.before = before;
            this.request = request;
            this.cancellationRequest = cancellationRequest;
        }
    }

    private static final class PendingHeartbeat {
        final DualMachineFormalUsageStateMachine.Snapshot before;
        final DualMachineSidecarPort.HeartbeatRequest request;
        final long hostProgress;
        final long androidProgress;
        final long sequence;

        PendingHeartbeat(
                DualMachineFormalUsageStateMachine.Snapshot before,
                DualMachineSidecarPort.HeartbeatRequest request,
                long hostProgress,
                long androidProgress,
                long sequence) {
            this.before = before;
            this.request = request;
            this.hostProgress = hostProgress;
            this.androidProgress = androidProgress;
            this.sequence = sequence;
        }
    }
}
