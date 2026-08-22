package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;

/**
 * Service-owned composition boundary for card authorization and formal use.
 *
 * <p>The object restores only the non-secret entitlement binding and an
 * AndroidKeyStore-sealed pending confirmation. Host proof signing and data
 * plane authority exist only while an authenticated Secure-v2 attachment is
 * installed. A detach always closes the process-local formal-use generation
 * first and may replay only an already dual-signed immutable start
 * cancellation.</p>
 */
public final class DualMachineAuthorizationRuntime implements AutoCloseable {
    @FunctionalInterface
    public interface HexIdSource {
        String nextHex128();
    }

    /** Runtime-owned generation handle with compare-and-clear completion. */
    public static final class FormalUsageLifecycleHandle {
        public final String startRequestId;
        public final String channelBindingSha256;
        private final DualMachineAuthorizationRuntime runtime;
        private final DualMachineFormalUsageCoordinator coordinator;
        private final DualMachineFormalUsageCoordinator
                .StartCancellationHandle cancellationHandle;
        private final DualMachineFormalUsageCoordinator.LifecycleStopHandle
                delegate;
        private final long stopEpoch;

        private FormalUsageLifecycleHandle(
                DualMachineAuthorizationRuntime runtime,
                DualMachineFormalUsageCoordinator coordinator,
                DualMachineFormalUsageCoordinator.StartCancellationHandle
                        cancellationHandle,
                DualMachineFormalUsageCoordinator.LifecycleStopHandle
                        delegate,
                long stopEpoch) {
            this.runtime = runtime;
            this.coordinator = coordinator;
            this.cancellationHandle = cancellationHandle;
            this.delegate = delegate;
            this.stopEpoch = stopEpoch;
            startRequestId = delegate == null
                    ? "" : delegate.startRequestId;
            channelBindingSha256 = delegate == null
                    ? "" : delegate.channelBindingSha256;
        }

        public DualMachineFormalUsageCoordinator.StartCancellationHandle
                startCancellationHandle() {
            return cancellationHandle;
        }

        public boolean hasFormalGeneration() {
            return delegate != null;
        }

        public DualMachineFormalUsageCoordinator.StopOutcome
                stopFormalUsage() {
            DualMachineFormalUsageCoordinator.StopOutcome outcome = null;
            try {
                outcome = delegate == null
                        ? null : delegate.stopFormalUsage();
                return outcome;
            } finally {
                runtime.completeFormalUsageLifecycleStop(
                        stopEpoch, coordinator, delegate, outcome);
            }
        }
    }

    /** One already-authenticated Host generation; never persisted. */
    public static final class Attachment {
        public final DualMachineCardAuthorizationCoordinator.IdentityBinding
                hostIdentity;
        public final String channelBindingSha256;
        private final DualMachineFormalUsageCoordinator.RuntimeBoundary
                runtimeBoundary;
        private final BooleanSupplier authenticatedSource;
        private final LongSupplier hostProgressSource;
        private final LongSupplier trustedEpochSecondsSource;

        public Attachment(
                DualMachineCardAuthorizationCoordinator.IdentityBinding
                        hostIdentity,
                String channelBindingSha256,
                DualMachineFormalUsageCoordinator.RuntimeBoundary
                        runtimeBoundary,
                BooleanSupplier authenticatedSource,
                LongSupplier hostProgressSource,
                LongSupplier trustedEpochSecondsSource) {
            if (hostIdentity == null || runtimeBoundary == null
                    || authenticatedSource == null
                    || hostProgressSource == null
                    || trustedEpochSecondsSource == null) {
                throw new IllegalArgumentException(
                        "authenticated Host attachment is incomplete");
            }
            this.hostIdentity = hostIdentity;
            this.channelBindingSha256 = DualMachineSidecarValues.sha256(
                    channelBindingSha256, "channelBindingSha256");
            this.runtimeBoundary = runtimeBoundary;
            this.authenticatedSource = authenticatedSource;
            this.hostProgressSource = hostProgressSource;
            this.trustedEpochSecondsSource = trustedEpochSecondsSource;
        }

        boolean isAuthenticated() {
            try {
                return authenticatedSource.getAsBoolean();
            } catch (RuntimeException failure) {
                return false;
            }
        }

        long trustedEpochSeconds() {
            long value = trustedEpochSecondsSource.getAsLong();
            if (value <= 0L) {
                throw new SecurityException(
                        "authenticated trusted time is unavailable");
            }
            return value;
        }
    }

    private final Object attachmentLock = new Object();
    private final DualMachineSidecarPort sidecar;
    private final DualMachineFormalUsageStateMachine stateMachine;
    private final DualMachineUsageLeaseKeyring leaseKeyring;
    private final DualMachineEntitlementStore entitlementStore;
    private final DualMachineCardAuthorizationCoordinator
            .PendingActivationStore pendingActivationStore;
    private final DualMachineCardAuthorizationCoordinator.IdentityBinding
            androidIdentity;
    private final String androidIdentityAlias;
    private final HexIdSource idSource;
    private final DualMachineUsageLeaseGate.MonotonicClock monotonicClock;
    private final DualMachineFormalUsageCoordinator.DeadlineScheduler
            deadlineScheduler;
    private final LongSupplier androidProgressSource;
    private final FormalUsageStopRetryPolicy formalStopRetryPolicy =
            new FormalUsageStopRetryPolicy();

    private volatile Attachment attachment;
    private volatile DualMachineCardAuthorizationCoordinator cardCoordinator;
    private volatile DualMachineFormalUsageCoordinator formalCoordinator;
    private volatile DualMachineFormalUsageCoordinator
            retiringFormalCoordinator;
    private long lifecycleStopEpoch;
    private long completedLifecycleStopEpoch;
    private long attachmentMutationEpoch;
    private boolean attachmentMutationInProgress;
    private StatusRefreshOwner activeStatusRefreshOwner;
    private volatile boolean closed;

    /** Immutable owner snapshot for one formal-start entry attempt. */
    private static final class FormalStartAdmission {
        final long lifecycleEpoch;
        final Attachment attachment;
        final DualMachineCardAuthorizationCoordinator cardCoordinator;
        final DualMachineFormalUsageCoordinator formalCoordinator;

        FormalStartAdmission(
                long lifecycleEpoch,
                Attachment attachment,
                DualMachineCardAuthorizationCoordinator cardCoordinator,
                DualMachineFormalUsageCoordinator formalCoordinator) {
            this.lifecycleEpoch = lifecycleEpoch;
            this.attachment = attachment;
            this.cardCoordinator = cardCoordinator;
            this.formalCoordinator = formalCoordinator;
        }
    }

    /** One exact status reservation owned by one attachment generation. */
    private static final class StatusRefreshOwner {
        final FormalStartAdmission admission;
        final DualMachineCardAuthorizationCoordinator
                .StatusRefreshReservation reservation;

        StatusRefreshOwner(
                FormalStartAdmission admission,
                DualMachineCardAuthorizationCoordinator
                        .StatusRefreshReservation reservation) {
            this.admission = admission;
            this.reservation = reservation;
        }
    }

    /** Immutable attachment/formal-generation receipt for service follow-up. */
    public static final class CurrentGenerationReceipt {
        private final DualMachineAuthorizationRuntime owner;
        private final long lifecycleEpoch;
        private final Attachment attachment;
        private final DualMachineCardAuthorizationCoordinator cardCoordinator;
        private final DualMachineFormalUsageCoordinator formalCoordinator;

        private CurrentGenerationReceipt(
                DualMachineAuthorizationRuntime owner,
                long lifecycleEpoch,
                Attachment attachment,
                DualMachineCardAuthorizationCoordinator cardCoordinator,
                DualMachineFormalUsageCoordinator formalCoordinator) {
            this.owner = owner;
            this.lifecycleEpoch = lifecycleEpoch;
            this.attachment = attachment;
            this.cardCoordinator = cardCoordinator;
            this.formalCoordinator = formalCoordinator;
        }
    }

    @FunctionalInterface
    public interface CheckedGenerationCommit {
        void run() throws IOException, GeneralSecurityException;
    }

    public DualMachineAuthorizationRuntime(
            DualMachineSidecarPort sidecar,
            DualMachineFormalUsageStateMachine stateMachine,
            DualMachineUsageLeaseKeyring leaseKeyring,
            DualMachineEntitlementStore entitlementStore,
            DualMachineCardAuthorizationCoordinator.PendingActivationStore
                    pendingActivationStore,
            DualMachineCardAuthorizationCoordinator.IdentityBinding
                    androidIdentity,
            String androidIdentityAlias,
            HexIdSource idSource,
            DualMachineUsageLeaseGate.MonotonicClock monotonicClock,
            DualMachineFormalUsageCoordinator.DeadlineScheduler
                    deadlineScheduler,
            LongSupplier androidProgressSource)
            throws IOException, GeneralSecurityException {
        if (sidecar == null || stateMachine == null || leaseKeyring == null
                || entitlementStore == null
                || pendingActivationStore == null
                || androidIdentity == null || idSource == null
                || monotonicClock == null
                || deadlineScheduler == null
                || androidProgressSource == null) {
            throw new IllegalArgumentException(
                    "authorization runtime dependencies are required");
        }
        this.sidecar = sidecar;
        this.stateMachine = stateMachine;
        this.leaseKeyring = leaseKeyring;
        this.entitlementStore = entitlementStore;
        this.pendingActivationStore = pendingActivationStore;
        this.androidIdentity = androidIdentity;
        this.androidIdentityAlias = requireAlias(androidIdentityAlias);
        this.idSource = idSource;
        this.monotonicClock = monotonicClock;
        this.deadlineScheduler = deadlineScheduler;
        this.androidProgressSource = androidProgressSource;
        restorePersistedState();
    }

    public void attachAuthenticatedHost(Attachment next)
            throws GeneralSecurityException {
        if (next == null || !next.isAuthenticated()) {
            throw new GeneralSecurityException(
                    "authenticated Host session is unavailable");
        }
        requireStoredBindingMatches(next.hostIdentity);
        DualMachineFormalUsageCoordinator.RuntimeBoundary boundBoundary =
                new ChannelBoundRuntimeBoundary(next);
        DualMachineCardAuthorizationCoordinator nextCard =
                new DualMachineCardAuthorizationCoordinator(
                        sidecar,
                        stateMachine,
                        entitlementStore,
                        pendingActivationStore,
                        next.hostIdentity,
                        androidIdentity,
                        androidIdentityAlias,
                        idSource::nextHex128,
                        next::trustedEpochSeconds);
        DualMachineFormalUsageCoordinator nextFormal =
                new DualMachineFormalUsageCoordinator(
                        sidecar,
                        stateMachine,
                        leaseKeyring,
                        next.hostIdentity,
                        androidIdentity,
                        boundBoundary,
                        idSource::nextHex128,
                        next::trustedEpochSeconds,
                        monotonicClock,
                        deadlineScheduler,
                        next.hostProgressSource,
                        androidProgressSource);
        DualMachineFormalUsageCoordinator previousFormal;
        Attachment previousAttachment;
        long replacementEpoch;
        synchronized (attachmentLock) {
            requireOpen();
            if (attachmentMutationInProgress
                    || retiringFormalCoordinator != null) {
                throw new GeneralSecurityException(
                        "older formal usage generation is unresolved");
            }
            previousFormal = formalCoordinator;
            previousAttachment = attachment;
            if (previousFormal == null) {
                if (previousAttachment != null || cardCoordinator != null
                        || activeStatusRefreshOwner != null) {
                    throw new IllegalStateException(
                            "authorization attachment is inconsistent");
                }
                cardCoordinator = nextCard;
                formalCoordinator = nextFormal;
                attachment = next;
                attachmentMutationEpoch++;
                return;
            }
            // A is made unavailable and stop-latched before replacement B can
            // become observable. The retiring slot is the only owner visible
            // to concurrent lifecycle maintenance during the slow I/O phase.
            cancelActiveStatusRefreshLocked();
            markRetiringBeforeReplacement(previousFormal);
            attachment = null;
            cardCoordinator = null;
            formalCoordinator = null;
            attachmentMutationInProgress = true;
            replacementEpoch = ++attachmentMutationEpoch;
        }
        try {
            failCloseReplacedGeneration(previousFormal, previousAttachment);
        } catch (RuntimeException | Error failure) {
            synchronized (attachmentLock) {
                attachmentMutationInProgress = false;
            }
            throw failure;
        }
        synchronized (attachmentLock) {
            try {
                requireOpen();
                if (attachmentMutationEpoch != replacementEpoch
                        || retiringFormalCoordinator != null
                        || attachment != null || cardCoordinator != null
                        || formalCoordinator != null
                        || activeStatusRefreshOwner != null) {
                    throw new GeneralSecurityException(
                            "previous formal usage generation is unresolved");
                }
                cardCoordinator = nextCard;
                formalCoordinator = nextFormal;
                attachment = next;
            } finally {
                attachmentMutationInProgress = false;
            }
        }
    }

    /** Removes Host authority while retaining any ambiguous exact cancel. */
    public void detachAuthenticatedHost() {
        DualMachineFormalUsageCoordinator detachedFormal;
        Attachment detachedAttachment;
        boolean ownsMutationBarrier = false;
        synchronized (attachmentLock) {
            attachmentMutationEpoch++;
            cancelActiveStatusRefreshLocked();
            detachedFormal = formalCoordinator;
            detachedAttachment = attachment;
            if (detachedFormal != null) {
                if (attachmentMutationInProgress) {
                    throw new IllegalStateException(
                            "attachment mutation owner is inconsistent");
                }
                markRetiringBeforeReplacement(detachedFormal);
                attachmentMutationInProgress = true;
                ownsMutationBarrier = true;
            }
            attachment = null;
            cardCoordinator = null;
            formalCoordinator = null;
        }
        try {
            failCloseReplacedGeneration(detachedFormal, detachedAttachment);
        } finally {
            if (ownsMutationBarrier) {
                synchronized (attachmentLock) {
                    attachmentMutationInProgress = false;
                }
            }
        }
    }

    public boolean hasAuthenticatedHost() {
        Attachment current = attachment;
        return !closed
                && retiringFormalCoordinator == null
                && !attachmentMutationInProgress
                && current != null
                && current.isAuthenticated();
    }

    /**
     * Returns the exact channel binding owned by the currently authenticated
     * Host generation. The value is never reconstructed from route metadata.
     */
    public String authenticatedHostChannelBindingSha256()
            throws GeneralSecurityException {
        final Attachment current;
        synchronized (attachmentLock) {
            if (closed || retiringFormalCoordinator != null
                    || attachmentMutationInProgress || attachment == null) {
                throw new GeneralSecurityException(
                        "authenticated Host generation is unavailable");
            }
            current = attachment;
        }
        if (!current.isAuthenticated()) {
            throw new GeneralSecurityException(
                    "authenticated Host session was lost");
        }
        synchronized (attachmentLock) {
            if (closed || retiringFormalCoordinator != null
                    || attachmentMutationInProgress
                    || attachment != current) {
                throw new GeneralSecurityException(
                        "authenticated Host generation was superseded");
            }
        }
        return current.channelBindingSha256;
    }

    public DualMachineFormalUsageStateMachine.Snapshot snapshot() {
        return stateMachine.snapshot();
    }

    public void reloadPersistedEntitlementBinding()
            throws GeneralSecurityException {
        synchronized (attachmentLock) {
            requireOpen();
        }
        detachAuthenticatedHost();
        DualMachineEntitlementRecord restored = entitlementStore.load();
        if (restored == null) {
            throw new GeneralSecurityException(
                    "persisted dual-machine entitlement is missing");
        }
        stateMachine.restoreBoundEntitlement(restored);
    }

    public DualMachineEntitlementRecord activateCard(String cardCode)
            throws IOException, GeneralSecurityException {
        return requireCardCoordinator().activateCard(cardCode);
    }

    public DualMachineEntitlementRecord resumePendingActivation()
            throws IOException, GeneralSecurityException {
        return requireCardCoordinator().resumePendingActivation();
    }

    public DualMachineFormalUsageStateMachine.Snapshot refreshStatus()
            throws IOException, GeneralSecurityException {
        return refreshStatus(captureFormalStartAdmission());
    }

    public DualMachineFormalUsageCoordinator.DataPlanePermit
            startFormalUsage()
            throws IOException, GeneralSecurityException {
        return startFormalUsage(captureFormalStartAdmission());
    }

    public DualMachineFormalUsageCoordinator.DataPlanePermit
            startFormalUsage(CurrentGenerationReceipt receipt)
            throws IOException, GeneralSecurityException {
        return startFormalUsage(formalStartAdmissionForReceipt(receipt));
    }

    private DualMachineFormalUsageCoordinator.DataPlanePermit
            startFormalUsage(FormalStartAdmission admission)
            throws IOException, GeneralSecurityException {
        refreshStatus(admission);
        DualMachineFormalUsageCoordinator.StartAdmissionToken startToken;
        synchronized (attachmentLock) {
            requireCurrentStartAdmission(admission);
            startToken = admission.formalCoordinator
                    .prepareForNewFormalStart();
        }
        return admission.formalCoordinator
                .startAfterVerifiedHostVideo(startToken);
    }

    public DualMachineFormalUsageCoordinator.DataPlanePermit
            retryPendingFormalStart()
            throws IOException, GeneralSecurityException {
        return retryPendingFormalStart(captureFormalStartAdmission());
    }

    public DualMachineFormalUsageCoordinator.DataPlanePermit
            retryPendingFormalStart(CurrentGenerationReceipt receipt)
            throws IOException, GeneralSecurityException {
        return retryPendingFormalStart(
                formalStartAdmissionForReceipt(receipt));
    }

    private DualMachineFormalUsageCoordinator.DataPlanePermit
            retryPendingFormalStart(FormalStartAdmission admission)
            throws IOException, GeneralSecurityException {
        DualMachineFormalUsageCoordinator.RetryAdmissionToken retryToken;
        synchronized (attachmentLock) {
            requireCurrentStartAdmission(admission);
            retryToken = admission.formalCoordinator
                    .capturePendingStartRetryAdmission();
        }
        return admission.formalCoordinator.retryPendingStart(retryToken);
    }

    /** Fast local half of a lifecycle stop; safe to call before queueing I/O. */
    public void requestImmediateLocalStop() {
        synchronized (attachmentLock) {
            DualMachineFormalUsageCoordinator current = formalCoordinator;
            DualMachineFormalUsageCoordinator retiring =
                    retiringFormalCoordinator;
            if (current != null) current.requestImmediateLocalStop();
            if (retiring != null && retiring != current) {
                retiring.requestImmediateLocalStop();
            }
        }
    }

    /**
     * Captures an immutable generation-bound cancellation for executor handoff.
     * A task holding the result can never resolve to a later Host generation.
     */
    public DualMachineFormalUsageCoordinator.StartCancellationHandle
            capturePendingFormalStartCancellation() {
        DualMachineFormalUsageCoordinator retiring =
                retiringFormalCoordinator;
        DualMachineFormalUsageCoordinator.StartCancellationHandle handle =
                retiring == null ? null
                        : retiring.capturePendingStartCancellation();
        if (handle != null) return handle;
        DualMachineFormalUsageCoordinator current = formalCoordinator;
        return current == null ? null
                : current.capturePendingStartCancellation();
    }

    /**
     * Linearizes a lifecycle stop even when no formal generation exists yet.
     * The returned empty barrier prevents an already queued start from
     * clearing or stepping over this stop owner.
     */
    public FormalUsageLifecycleHandle beginFormalUsageLifecycleStop() {
        final DualMachineFormalUsageCoordinator coordinator;
        final long stopEpoch;
        synchronized (attachmentLock) {
            cancelActiveStatusRefreshLocked();
            stopEpoch = ++lifecycleStopEpoch;
            coordinator = lifecycleStopCoordinatorOrNull();
        }
        requestImmediateLocalStop();
        DualMachineFormalUsageCoordinator.LifecycleStopHandle lifecycle =
                coordinator == null ? null
                        : coordinator.captureLifecycleStop();
        DualMachineFormalUsageCoordinator.StartCancellationHandle
                cancellation = lifecycle == null ? null
                        : lifecycle.startCancellationHandle();
        return new FormalUsageLifecycleHandle(
                this,
                coordinator,
                cancellation,
                lifecycle,
                stopEpoch);
    }

    /**
     * Claims a stop only for one still-current receipt. The claim callback is
     * invoked while {@code attachmentLock} is held, so a service may acquire
     * its downstream pipeline lock and atomically recheck/claim that exact
     * generation without ever taking the locks in reverse order.
     */
    public FormalUsageLifecycleHandle
            beginFormalUsageLifecycleStopIfCurrent(
            CurrentGenerationReceipt receipt,
            BooleanSupplier claimCurrentGeneration) {
        if (receipt == null || claimCurrentGeneration == null) {
            throw new IllegalArgumentException(
                    "generation receipt and stop claim are required");
        }
        synchronized (attachmentLock) {
            if (!isCurrentReceipt(receipt)
                    || !claimCurrentGeneration.getAsBoolean()) {
                return null;
            }
            cancelActiveStatusRefreshLocked();
            long stopEpoch = ++lifecycleStopEpoch;
            DualMachineFormalUsageCoordinator coordinator =
                    receipt.formalCoordinator;
            coordinator.requestImmediateLocalStop();
            DualMachineFormalUsageCoordinator.LifecycleStopHandle lifecycle =
                    coordinator.captureLifecycleStop();
            return new FormalUsageLifecycleHandle(
                    this,
                    coordinator,
                    lifecycle == null ? null
                            : lifecycle.startCancellationHandle(),
                    lifecycle,
                    stopEpoch);
        }
    }

    /**
     * Claims a due retry only for the exact still-current formal generation.
     * A maintenance tick inside the retry window neither advances the
     * lifecycle epoch nor acquires the service-owned stop latch.
     */
    public FormalUsageLifecycleHandle
            beginFormalUsageLifecycleStopRetryIfCurrent(
            CurrentGenerationReceipt receipt,
            BooleanSupplier claimCurrentGeneration) {
        if (receipt == null || claimCurrentGeneration == null) {
            throw new IllegalArgumentException(
                    "generation receipt and stop claim are required");
        }
        synchronized (attachmentLock) {
            if (!isCurrentReceipt(receipt)) return null;
            DualMachineFormalUsageCoordinator coordinator =
                    receipt.formalCoordinator;
            DualMachineFormalUsageCoordinator.LifecycleStopHandle lifecycle =
                    coordinator.captureLifecycleStop();
            if (lifecycle == null
                    || !formalStopRetryPolicy.canAttempt(
                    lifecycle.startRequestId,
                    lifecycle.channelBindingSha256,
                    monotonicNowNanos())
                    || !claimCurrentGeneration.getAsBoolean()) {
                return null;
            }
            cancelActiveStatusRefreshLocked();
            long stopEpoch = ++lifecycleStopEpoch;
            coordinator.requestImmediateLocalStop();
            return new FormalUsageLifecycleHandle(
                    this,
                    coordinator,
                    lifecycle.startCancellationHandle(),
                    lifecycle,
                    stopEpoch);
        }
    }

    /** Captures the exact retiring generation before current-receipt work. */
    public FormalUsageLifecycleHandle
            captureRetiringFormalUsageStopForMaintenance(
            BooleanSupplier claimRetiringGeneration) {
        if (claimRetiringGeneration == null) {
            throw new IllegalArgumentException(
                    "retiring stop claim is required");
        }
        synchronized (attachmentLock) {
            DualMachineFormalUsageCoordinator retiring =
                    retiringFormalCoordinator;
            if (retiring == null) return null;
            DualMachineFormalUsageCoordinator.LifecycleStopHandle lifecycle =
                    retiring.captureLifecycleStop();
            if (lifecycle != null
                    && !formalStopRetryPolicy.canAttempt(
                    lifecycle.startRequestId,
                    lifecycle.channelBindingSha256,
                    monotonicNowNanos())) {
                return null;
            }
            if (!claimRetiringGeneration.getAsBoolean()) return null;
            cancelActiveStatusRefreshLocked();
            long stopEpoch = ++lifecycleStopEpoch;
            return new FormalUsageLifecycleHandle(
                    this,
                    retiring,
                    lifecycle == null ? null
                            : lifecycle.startCancellationHandle(),
                    lifecycle,
                    stopEpoch);
        }
    }

    public boolean hasRetiringFormalUsageGeneration() {
        synchronized (attachmentLock) {
            return retiringFormalCoordinator != null;
        }
    }

    public boolean hasPendingFormalStartCancellation() {
        DualMachineFormalUsageCoordinator retiring =
                retiringFormalCoordinator;
        if (retiring != null
                && retiring.hasPendingStartCancellation()) {
            return true;
        }
        DualMachineFormalUsageCoordinator current = formalCoordinator;
        return current != null
                && current.hasPendingStartCancellation();
    }

    /**
     * Concurrent lifecycle half of STARTING cancellation. The coordinator owns
     * the immutable pre-signed request, so this call never invents a second
     * idempotency key even when the original start call is still blocked.
     */
    public boolean cancelPendingFormalStart() {
        DualMachineFormalUsageCoordinator.StartCancellationHandle handle =
                capturePendingFormalStartCancellation();
        if (handle != null) return handle.sendExactCancellation();
        DualMachineFormalUsageCoordinator formal =
                lifecycleStopCoordinatorOrNull();
        return formal != null && formal.cancelPendingStart();
    }

    public DualMachineFormalUsageCoordinator.StopOutcome stopFormalUsage() {
        requestImmediateLocalStop();
        DualMachineFormalUsageCoordinator formal =
                lifecycleStopCoordinatorOrNull();
        if (formal == null) {
            throw new IllegalStateException(
                    "formal usage generation is unavailable");
        }
        DualMachineFormalUsageCoordinator.StopOutcome outcome =
                formal.stopForRuntimeLifecycle();
        clearRetiringCoordinatorIfResolved(formal);
        return outcome;
    }

    public DualMachineFormalUsageCoordinator.RenewalOutcome
            renewAfterObservedProgress()
            throws IOException, GeneralSecurityException {
        return requireFormalCoordinator().renewAfterObservedProgress();
    }

    public DualMachineFormalUsageCoordinator.RenewalOutcome
            renewAfterObservedProgress(CurrentGenerationReceipt receipt)
            throws IOException, GeneralSecurityException {
        return formalCoordinatorForReceipt(receipt)
                .renewAfterObservedProgress();
    }

    public DualMachineFormalUsageCoordinator.RenewalOutcome
            retryPendingRenewal()
            throws IOException, GeneralSecurityException {
        return requireFormalCoordinator().retryPendingRenewal();
    }

    public DualMachineFormalUsageCoordinator.RenewalOutcome
            retryPendingRenewal(CurrentGenerationReceipt receipt)
            throws IOException, GeneralSecurityException {
        return formalCoordinatorForReceipt(receipt).retryPendingRenewal();
    }

    public DualMachineFormalUsageCoordinator.RenewalProgressObservation
            latestRenewalProgressObservation(
            CurrentGenerationReceipt receipt) {
        return formalCoordinatorForReceipt(receipt)
                .latestRenewalProgressObservation();
    }

    public long millisUntilRenewalWindow(long renewalWindowSeconds) {
        return requireFormalCoordinator().millisUntilRenewalWindow(
                renewalWindowSeconds);
    }

    public DualMachineFormalUsageCoordinator.DataPlanePermitState
            enforceDataPlanePermitState() {
        final Attachment expectedAttachment;
        final DualMachineFormalUsageCoordinator formal;
        synchronized (attachmentLock) {
            expectedAttachment = attachment;
            formal = formalCoordinator;
            if (formal == null || expectedAttachment == null
                    || !expectedAttachment.isAuthenticated()) {
                if (formal != null && formal == formalCoordinator
                        && expectedAttachment == attachment) {
                    formal.failCloseFromRuntimeLoss();
                }
                return DualMachineFormalUsageCoordinator
                        .DataPlanePermitState.CLOSED;
            }
        }
        DualMachineFormalUsageCoordinator.DataPlanePermitState result =
                formal.enforceAndGetDataPlanePermitState();
        synchronized (attachmentLock) {
            if (attachment != expectedAttachment
                    || formalCoordinator != formal) {
                return DualMachineFormalUsageCoordinator
                        .DataPlanePermitState.SUPERSEDED;
            }
        }
        return result;
    }

    public CurrentGenerationReceipt captureCurrentGenerationReceipt() {
        synchronized (attachmentLock) {
            if (retiringFormalCoordinator != null) {
                throw new DualMachineFormalUsageCoordinator
                        .AdmissionSupersededException(
                        "retiring formal generation is unresolved");
            }
            if (closed || attachment == null || cardCoordinator == null
                    || formalCoordinator == null
                    || !attachment.isAuthenticated()) {
                throw new DualMachineFormalUsageCoordinator
                        .AdmissionSupersededException(
                        "formal generation is unavailable");
            }
            return new CurrentGenerationReceipt(
                    this,
                    lifecycleStopEpoch,
                    attachment,
                    cardCoordinator,
                    formalCoordinator);
        }
    }

    /** Runs a service-side follow-up only while the receipt is still current. */
    public boolean commitIfCurrent(
            CurrentGenerationReceipt receipt,
            Runnable commit) {
        if (receipt == null || commit == null) {
            throw new IllegalArgumentException(
                    "generation receipt and commit are required");
        }
        synchronized (attachmentLock) {
            if (!isCurrentReceipt(receipt)) return false;
            commit.run();
            return true;
        }
    }

    public boolean commitCheckedIfCurrent(
            CurrentGenerationReceipt receipt,
            CheckedGenerationCommit commit)
            throws IOException, GeneralSecurityException {
        if (receipt == null || commit == null) {
            throw new IllegalArgumentException(
                    "generation receipt and commit are required");
        }
        synchronized (attachmentLock) {
            if (!isCurrentReceipt(receipt)) return false;
            commit.run();
            return true;
        }
    }

    private boolean isCurrentReceipt(CurrentGenerationReceipt receipt) {
        return !closed
                && receipt.owner == this
                && retiringFormalCoordinator == null
                && lifecycleStopEpoch == receipt.lifecycleEpoch
                && completedLifecycleStopEpoch == receipt.lifecycleEpoch
                && attachment == receipt.attachment
                && cardCoordinator == receipt.cardCoordinator
                && formalCoordinator == receipt.formalCoordinator
                && receipt.attachment.isAuthenticated();
    }

    private DualMachineFormalUsageCoordinator formalCoordinatorForReceipt(
            CurrentGenerationReceipt receipt) {
        if (receipt == null || receipt.owner != this) {
            throw new DualMachineFormalUsageCoordinator
                    .AdmissionSupersededException(
                    "formal generation receipt is invalid");
        }
        synchronized (attachmentLock) {
            if (closed || retiringFormalCoordinator != null
                    || lifecycleStopEpoch != receipt.lifecycleEpoch
                    || completedLifecycleStopEpoch != receipt.lifecycleEpoch
                    || attachment != receipt.attachment
                    || cardCoordinator != receipt.cardCoordinator
                    || formalCoordinator != receipt.formalCoordinator
                    || !receipt.attachment.isAuthenticated()) {
                throw new DualMachineFormalUsageCoordinator
                        .AdmissionSupersededException(
                        "formal generation receipt was superseded");
            }
            return receipt.formalCoordinator;
        }
    }

    private FormalStartAdmission formalStartAdmissionForReceipt(
            CurrentGenerationReceipt receipt) {
        formalCoordinatorForReceipt(receipt);
        return new FormalStartAdmission(
                receipt.lifecycleEpoch,
                receipt.attachment,
                receipt.cardCoordinator,
                receipt.formalCoordinator);
    }

    @Override
    public void close() {
        synchronized (attachmentLock) {
            if (closed) return;
            closed = true;
        }
        detachAuthenticatedHost();
    }

    private void restorePersistedState()
            throws IOException, GeneralSecurityException {
        DualMachineEntitlementRecord restored = entitlementStore.load();
        if (restored != null) stateMachine.restoreBoundEntitlement(restored);
        DualMachineCardAuthorizationCoordinator.PendingActivation pending =
                pendingActivationStore.load();
        if (pending == null) return;
        if (restored != null) {
            if (!pending.pairId.equals(restored.pairId)
                    || !pending.hostKeyFingerprintSha256.equals(
                    restored.hostKeySha256)
                    || !pending.androidKeyFingerprintSha256.equals(
                    restored.androidKeySha256)
                    || !pending.androidIdentityAlias.equals(
                    restored.androidIdentityAlias)
                    || (!DualMachineUsageAuthorizationContract
                    .ACTIVATION_MODE_ACTIVATE.equals(pending.activationMode)
                    && !pending.targetEntitlementId.equals(
                    restored.entitlementId))) {
                throw new GeneralSecurityException(
                        "persisted entitlement conflicts with pending activation");
            }
            // Crash-safe commit reconciliation: the entitlement write is the
            // durable commit point. A matching sealed confirmation left by a
            // process death after that write is stale and must not re-enter
            // ACTIVATING or block startup.
            pendingActivationStore.clear();
            return;
        }
        stateMachine.beginPendingCardActivationResume();
        stateMachine.markCardActivationPending();
    }

    private DualMachineCardAuthorizationCoordinator requireCardCoordinator()
            throws GeneralSecurityException {
        Attachment current = attachment;
        DualMachineCardAuthorizationCoordinator coordinator = cardCoordinator;
        if (closed || current == null || coordinator == null
                || !current.isAuthenticated()) {
            detachAuthenticatedHost();
            throw new GeneralSecurityException(
                    "authenticated Host session is unavailable");
        }
        return coordinator;
    }

    private DualMachineFormalUsageCoordinator requireFormalCoordinator() {
        Attachment current = attachment;
        DualMachineFormalUsageCoordinator coordinator = formalCoordinator;
        if (closed || current == null || coordinator == null
                || !current.isAuthenticated()) {
            detachAuthenticatedHost();
            throw new IllegalStateException(
                    "authenticated Host session is unavailable");
        }
        return coordinator;
    }

    private void requireStoredBindingMatches(
            DualMachineCardAuthorizationCoordinator.IdentityBinding host)
            throws GeneralSecurityException {
        DualMachineEntitlementRecord entitlement = stateMachine
                .snapshot().entitlement;
        if (entitlement == null) return;
        if (!entitlement.hostKeySha256.equals(
                host.keyFingerprintSha256)
                || !MessageDigest.isEqual(
                entitlement.hostIdentityPublicKeyDer(),
                host.publicKeyDer())
                || !entitlement.matchesAndroidIdentity(
                androidIdentityAlias,
                androidIdentity.keyFingerprintSha256)) {
            throw new GeneralSecurityException(
                    "authenticated devices do not match saved entitlement");
        }
    }

    private void failCloseReplacedGeneration(
            DualMachineFormalUsageCoordinator formal,
            Attachment staleAttachment) {
        if (formal != null) {
            // The replacement path pre-publishes and latches this coordinator
            // while holding attachmentLock. Retain is idempotent for recovery
            // callers that did not replace an attachment.
            retainRetiringCoordinator(formal);
            formal.failCloseFromRuntimeLoss();
            if (!formal.hasPendingStartCancellation()) {
                discardRetiringCoordinator(formal);
            }
        }
        if (staleAttachment != null) {
            try {
                staleAttachment.runtimeBoundary.closeDataPlane();
            } catch (RuntimeException ignored) {
                // The formal coordinator already cleared its capability.
            }
        }
    }

    /** Caller holds attachmentLock; latch A before publishing/detaching B. */
    private void markRetiringBeforeReplacement(
            DualMachineFormalUsageCoordinator formal) {
        if (formal == null) return;
        if (retiringFormalCoordinator != null
                && retiringFormalCoordinator != formal) {
            throw new IllegalStateException(
                    "multiple retiring formal generations are forbidden");
        }
        retiringFormalCoordinator = formal;
        formal.requestImmediateLocalStop();
    }

    private DualMachineFormalUsageCoordinator
            lifecycleStopCoordinatorOrNull() {
        DualMachineFormalUsageCoordinator retiring =
                retiringFormalCoordinator;
        return retiring != null ? retiring : formalCoordinator;
    }

    private void retainRetiringCoordinator(
            DualMachineFormalUsageCoordinator formal) {
        synchronized (attachmentLock) {
            if (retiringFormalCoordinator == null
                    || retiringFormalCoordinator == formal) {
                retiringFormalCoordinator = formal;
            }
        }
    }

    private void clearRetiringCoordinatorIfResolved(
            DualMachineFormalUsageCoordinator formal) {
        if (formal.hasPendingStartCancellation()) return;
        discardRetiringCoordinator(formal);
    }

    private void completeFormalUsageLifecycleStop(
            long stopEpoch,
            DualMachineFormalUsageCoordinator formal,
            DualMachineFormalUsageCoordinator.LifecycleStopHandle lifecycle,
            DualMachineFormalUsageCoordinator.StopOutcome outcome) {
        if (formal != null) {
            updateFormalStopRetryPolicy(formal, lifecycle, outcome);
            clearRetiringCoordinatorIfResolved(formal);
        }
        synchronized (attachmentLock) {
            if (stopEpoch > completedLifecycleStopEpoch) {
                completedLifecycleStopEpoch = stopEpoch;
            }
        }
    }

    private void updateFormalStopRetryPolicy(
            DualMachineFormalUsageCoordinator formal,
            DualMachineFormalUsageCoordinator.LifecycleStopHandle lifecycle,
            DualMachineFormalUsageCoordinator.StopOutcome outcome) {
        if (lifecycle == null) return;
        if ((outcome != null && outcome.serverConfirmed)
                || !formal.hasPendingStartCancellation()) {
            formalStopRetryPolicy.recordResolved(
                    lifecycle.startRequestId,
                    lifecycle.channelBindingSha256);
            return;
        }
        formalStopRetryPolicy.recordUnconfirmed(
                lifecycle.startRequestId,
                lifecycle.channelBindingSha256,
                monotonicNowNanos());
    }

    private long monotonicNowNanos() {
        return Math.max(0L, monotonicClock.nowNanos());
    }

    private void discardRetiringCoordinator(
            DualMachineFormalUsageCoordinator formal) {
        synchronized (attachmentLock) {
            if (retiringFormalCoordinator == formal) {
                retiringFormalCoordinator = null;
            }
        }
    }

    private void requireNoRetiringLifecycleGeneration() {
        if (retiringFormalCoordinator != null) {
            throw new IllegalStateException(
                    "retiring formal usage generation is unresolved");
        }
    }

    private FormalStartAdmission captureFormalStartAdmission() {
        synchronized (attachmentLock) {
            requireNoRetiringLifecycleGeneration();
            if (lifecycleStopEpoch != completedLifecycleStopEpoch) {
                throw new IllegalStateException(
                        "formal lifecycle stop is unresolved");
            }
            Attachment currentAttachment = attachment;
            DualMachineCardAuthorizationCoordinator currentCard =
                    cardCoordinator;
            DualMachineFormalUsageCoordinator currentFormal =
                    formalCoordinator;
            if (closed || currentAttachment == null
                    || currentCard == null || currentFormal == null
                    || !currentAttachment.isAuthenticated()) {
                throw new IllegalStateException(
                        "authenticated Host session is unavailable");
            }
            return new FormalStartAdmission(
                    lifecycleStopEpoch,
                    currentAttachment,
                    currentCard,
                    currentFormal);
        }
    }

    private DualMachineFormalUsageStateMachine.Snapshot refreshStatus(
            FormalStartAdmission admission)
            throws IOException, GeneralSecurityException {
        final StatusRefreshOwner owner;
        synchronized (attachmentLock) {
            requireCurrentStartAdmission(admission);
            if (activeStatusRefreshOwner != null) {
                throw new IllegalStateException(
                        "status refresh owner is already active");
            }
            DualMachineCardAuthorizationCoordinator.StatusRefreshReservation
                    reservation = admission.cardCoordinator
                    .beginStatusRefresh();
            owner = new StatusRefreshOwner(admission, reservation);
            activeStatusRefreshOwner = owner;
        }
        try {
            return admission.cardCoordinator.refreshStatus(
                    owner.reservation, commit -> {
                        synchronized (attachmentLock) {
                            requireCurrentStatusRefreshOwner(owner);
                            commit.run();
                            activeStatusRefreshOwner = null;
                            if (stateMachine.snapshot().state
                                    == DualMachineFormalUsageStateMachine.State
                                    .REVOKED) {
                                // A stale refresh can neither commit into B
                                // nor close B's data plane.
                                owner.admission.formalCoordinator
                                        .failCloseFromEntitlementRevocation();
                            }
                        }
                    });
        } finally {
            synchronized (attachmentLock) {
                failStatusRefreshIfCurrentLocked(owner);
            }
        }
    }

    /** Caller holds attachmentLock; never enters the Card monitor or I/O. */
    private void cancelActiveStatusRefreshLocked() {
        StatusRefreshOwner owner = activeStatusRefreshOwner;
        if (owner == null) return;
        owner.admission.cardCoordinator.statusRefreshFailedIfCurrent(
                owner.reservation);
        activeStatusRefreshOwner = null;
    }

    private void failStatusRefreshIfCurrentLocked(
            StatusRefreshOwner owner) {
        if (activeStatusRefreshOwner != owner) return;
        owner.admission.cardCoordinator.statusRefreshFailedIfCurrent(
                owner.reservation);
        activeStatusRefreshOwner = null;
    }

    private void requireCurrentStatusRefreshOwner(
            StatusRefreshOwner owner) {
        if (activeStatusRefreshOwner != owner) {
            throw new DualMachineFormalUsageCoordinator
                    .AdmissionSupersededException(
                    "status refresh reservation was superseded");
        }
        requireCurrentStartAdmission(owner.admission);
    }

    private void requireCurrentStartAdmission(
            FormalStartAdmission admission) {
        requireNoRetiringLifecycleGeneration();
        if (closed
                || lifecycleStopEpoch != admission.lifecycleEpoch
                || completedLifecycleStopEpoch
                != admission.lifecycleEpoch
                || attachment != admission.attachment
                || cardCoordinator != admission.cardCoordinator
                || formalCoordinator != admission.formalCoordinator
                || !admission.attachment.isAuthenticated()) {
            throw new DualMachineFormalUsageCoordinator
                    .AdmissionSupersededException(
                    "formal start admission was superseded");
        }
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException(
                    "authorization runtime is closed");
        }
    }

    private static String requireAlias(String value) {
        if (value == null || value.isEmpty() || value.length() > 128) {
            throw new IllegalArgumentException(
                    "Android identity alias is invalid");
        }
        return value;
    }

    private static final class ChannelBoundRuntimeBoundary
            implements DualMachineFormalUsageCoordinator.RuntimeBoundary {
        private final Attachment attachment;

        private ChannelBoundRuntimeBoundary(Attachment attachment) {
            this.attachment = attachment;
        }

        @Override
        public DualMachineFormalUsageCoordinator.StartReadiness
                prepareWithDataPlaneClosed(
                BooleanSupplier cancellationRequested)
                throws IOException, GeneralSecurityException {
            requireAuthenticated();
            DualMachineFormalUsageCoordinator.StartReadiness readiness =
                    attachment.runtimeBoundary
                            .prepareWithDataPlaneClosed(cancellationRequested);
            requireAuthenticated();
            if (readiness == null) {
                closeDataPlane();
                throw new GeneralSecurityException(
                        "runtime readiness is unavailable");
            }
            if (!attachment.channelBindingSha256.equals(
                    readiness.channelBindingSha256)) {
                closeDataPlane();
                throw new GeneralSecurityException(
                        "runtime readiness channel binding is invalid");
            }
            return readiness;
        }

        @Override
        public void verifyFreshHostVideoBeforePotentialDebit(
                String expectedChannelBindingSha256,
                String expectedStartRequestId,
                BooleanSupplier cancellationRequested)
                throws IOException, GeneralSecurityException {
            requireAuthenticated();
            requireChannelBinding(expectedChannelBindingSha256);
            attachment.runtimeBoundary
                    .verifyFreshHostVideoBeforePotentialDebit(
                            expectedChannelBindingSha256,
                            expectedStartRequestId,
                            cancellationRequested);
            requireAuthenticated();
            requireChannelBinding(expectedChannelBindingSha256);
        }

        @Override
        public void openDataPlane(
                DualMachineFormalUsageCoordinator.DataPlanePermit permit)
                throws IOException {
            try {
                requireAuthenticated();
                requireChannelBinding(permit == null
                        ? null : permit.channelBindingSha256);
            } catch (GeneralSecurityException failure) {
                throw new IOException(failure);
            }
            attachment.runtimeBoundary.openDataPlane(permit);
            if (!attachment.isAuthenticated()) {
                closeDataPlane();
                throw new IOException(
                        "authenticated Host session was lost");
            }
        }

        @Override
        public void stageFutureLease(
                DualMachineFormalUsageCoordinator.DataPlanePermit permit)
                throws IOException {
            if (!attachment.isAuthenticated()
                    || permit == null
                    || !attachment.channelBindingSha256.equals(
                    permit.channelBindingSha256)) {
                closeDataPlane();
                throw new IOException(
                        "authenticated Host session or channel binding was lost");
            }
            attachment.runtimeBoundary.stageFutureLease(permit);
        }

        @Override
        public DualMachineFormalUsageCoordinator.DataPlanePermitState
                enforceLeaseWindow() {
            if (!attachment.isAuthenticated()) {
                closeDataPlane();
                return DualMachineFormalUsageCoordinator
                        .DataPlanePermitState.CLOSED;
            }
            return attachment.runtimeBoundary.enforceLeaseWindow();
        }

        @Override
        public void closeDataPlane() {
            attachment.runtimeBoundary.closeDataPlane();
        }

        @Override
        public void finalizeFormalGeneration(
                String expectedStartRequestId,
                String expectedChannelBindingSha256,
                DualMachineFormalUsageCoordinator.StopOutcome outcome) {
            if (!attachment.channelBindingSha256.equals(
                    expectedChannelBindingSha256)) {
                closeDataPlane();
                return;
            }
            attachment.runtimeBoundary.finalizeFormalGeneration(
                    expectedStartRequestId,
                    expectedChannelBindingSha256,
                    outcome);
        }

        private void requireAuthenticated()
                throws GeneralSecurityException {
            if (!attachment.isAuthenticated()) {
                closeDataPlane();
                throw new GeneralSecurityException(
                        "authenticated Host session was lost");
            }
        }

        private void requireChannelBinding(String candidate)
                throws GeneralSecurityException {
            if (!attachment.channelBindingSha256.equals(candidate)) {
                closeDataPlane();
                throw new GeneralSecurityException(
                        "authenticated Host channel binding changed");
            }
        }
    }
}
