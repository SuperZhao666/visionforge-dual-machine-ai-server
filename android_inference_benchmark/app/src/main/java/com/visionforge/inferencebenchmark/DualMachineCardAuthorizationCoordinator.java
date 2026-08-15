package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * Explicit card activation and zero-cost status orchestration.
 *
 * <p>This coordinator has no username/password dependency. It never persists a
 * card code; a replayable challenge token exists only in the sealed,
 * short-lived pending-confirmation store. Neither activation nor status can
 * enter a formal-use state. Both device signatures are reconstructed and
 * verified locally before an operation reaches the independent sidecar.</p>
 */
public final class DualMachineCardAuthorizationCoordinator {
    @FunctionalInterface
    interface StatusRefreshCommit {
        void run() throws IOException, GeneralSecurityException;
    }

    @FunctionalInterface
    interface StatusRefreshCommitGate {
        void commit(StatusRefreshCommit commit)
                throws IOException, GeneralSecurityException;
    }

    /** Opaque exact-token reservation captured before status network I/O. */
    static final class StatusRefreshReservation {
        private final DualMachineCardAuthorizationCoordinator owner;
        final long operationToken;
        final DualMachineEntitlementRecord entitlement;

        private StatusRefreshReservation(
                DualMachineCardAuthorizationCoordinator owner,
                long operationToken,
                DualMachineEntitlementRecord entitlement) {
            this.owner = owner;
            this.operationToken = operationToken;
            this.entitlement = entitlement;
        }
    }

    @FunctionalInterface
    public interface HexIdSource {
        String nextHex128();
    }

    @FunctionalInterface
    public interface EpochClock {
        long nowEpochSeconds();
    }

    public interface PendingActivationStore {
        PendingActivation load()
                throws IOException, GeneralSecurityException;

        void save(PendingActivation pending)
                throws IOException, GeneralSecurityException;

        void clear() throws IOException, GeneralSecurityException;
    }

    /**
     * Short-lived recovery material for an idempotent confirmation. It never
     * contains the card code or either private key.
     */
    public static final class PendingActivation {
        public final String requestId;
        public final String pairId;
        public final String challengeId;
        public final String challengeToken;
        public final long challengeExpiresAtEpoch;
        public final String hostSignatureBase64;
        public final String androidSignatureBase64;
        public final String hostKeyFingerprintSha256;
        public final String androidKeyFingerprintSha256;
        public final String androidIdentityAlias;
        public final String activationMode;
        public final String targetEntitlementId;

        public PendingActivation(
                String requestId,
                String pairId,
                String challengeId,
                String challengeToken,
                long challengeExpiresAtEpoch,
                String hostSignatureBase64,
                String androidSignatureBase64,
                String hostKeyFingerprintSha256,
                String androidKeyFingerprintSha256,
                String androidIdentityAlias,
                String activationMode,
                String targetEntitlementId) {
            this.requestId = DualMachineSidecarValues.hex128(
                    requestId, "requestId");
            this.pairId = DualMachineSidecarValues.hex128(
                    pairId, "pairId");
            this.challengeId = DualMachineSidecarValues.hex128(
                    challengeId, "challengeId");
            this.challengeToken = DualMachineSidecarValues.challengeToken(
                    challengeToken);
            if (challengeExpiresAtEpoch <= 0L) {
                throw new IllegalArgumentException(
                        "challenge expiry must be positive");
            }
            this.challengeExpiresAtEpoch = challengeExpiresAtEpoch;
            this.hostSignatureBase64 = DualMachineSidecarValues.signature(
                    hostSignatureBase64, "hostSignatureBase64");
            this.androidSignatureBase64 =
                    DualMachineSidecarValues.signature(
                            androidSignatureBase64,
                            "androidSignatureBase64");
            this.hostKeyFingerprintSha256 =
                    DualMachineSidecarValues.sha256(
                            hostKeyFingerprintSha256,
                            "hostKeyFingerprintSha256");
            this.androidKeyFingerprintSha256 =
                    DualMachineSidecarValues.sha256(
                            androidKeyFingerprintSha256,
                            "androidKeyFingerprintSha256");
            this.androidIdentityAlias = requireAlias(androidIdentityAlias);
            this.activationMode = requireActivationMode(activationMode);
            this.targetEntitlementId = requireActivationTarget(
                    this.activationMode, targetEntitlementId);
        }
    }

    public static final class IdentityBinding {
        public final DualMachineSidecarPort.PeerIdentity peerIdentity;
        public final String keyFingerprintSha256;
        private final byte[] publicKeyDer;
        public final DualMachineDeviceProofs.ProofSigner signer;

        public IdentityBinding(
                String deviceCode,
                String clientVersion,
                String identityPublicKeyBase64,
                DualMachineDeviceProofs.ProofSigner signer)
                throws GeneralSecurityException {
            this(
                    deviceCode,
                    clientVersion,
                    identityPublicKeyBase64,
                    null,
                    signer);
        }

        public IdentityBinding(
                String deviceCode,
                String clientVersion,
                String identityPublicKeyBase64,
                DualMachineAndroidDeviceProfile deviceProfile,
                DualMachineDeviceProofs.ProofSigner signer)
                throws GeneralSecurityException {
            if (signer == null) {
                throw new IllegalArgumentException("identity signer is required");
            }
            peerIdentity = new DualMachineSidecarPort.PeerIdentity(
                    deviceCode,
                    clientVersion,
                    identityPublicKeyBase64,
                    deviceProfile);
            publicKeyDer = DualMachinePairingIdentityCodec
                    .decodePublicKeyBase64(
                            peerIdentity.identityPublicKeyBase64);
            keyFingerprintSha256 = DualMachinePairingIdentityCodec
                    .fingerprintHex(publicKeyDer);
            this.signer = signer;
        }

        public byte[] publicKeyDer() {
            return publicKeyDer.clone();
        }
    }

    private final DualMachineSidecarPort sidecar;
    private final DualMachineFormalUsageStateMachine stateMachine;
    private final DualMachineEntitlementStore entitlementStore;
    private final PendingActivationStore pendingActivationStore;
    private final IdentityBinding hostIdentity;
    private final IdentityBinding androidIdentity;
    private final String androidIdentityAlias;
    private final HexIdSource idSource;
    private final EpochClock epochClock;

    public DualMachineCardAuthorizationCoordinator(
            DualMachineSidecarPort sidecar,
            DualMachineFormalUsageStateMachine stateMachine,
            DualMachineEntitlementStore entitlementStore,
            PendingActivationStore pendingActivationStore,
            IdentityBinding hostIdentity,
            IdentityBinding androidIdentity,
            String androidIdentityAlias,
            HexIdSource idSource,
            EpochClock epochClock) {
        if (sidecar == null || stateMachine == null
                || entitlementStore == null || pendingActivationStore == null
                || hostIdentity == null
                || androidIdentity == null || idSource == null
                || epochClock == null) {
            throw new IllegalArgumentException(
                    "card authorization dependencies are required");
        }
        if (MessageDigest.isEqual(
                hostIdentity.publicKeyDer,
                androidIdentity.publicKeyDer)) {
            throw new IllegalArgumentException(
                    "host and Android identities must differ");
        }
        this.sidecar = sidecar;
        this.stateMachine = stateMachine;
        this.entitlementStore = entitlementStore;
        this.pendingActivationStore = pendingActivationStore;
        this.hostIdentity = hostIdentity;
        this.androidIdentity = androidIdentity;
        this.androidIdentityAlias = requireAlias(androidIdentityAlias);
        this.idSource = idSource;
        this.epochClock = epochClock;
    }

    /**
     * Consumes one card only after a direct caller request. A successful
     * activation stores the non-secret binding and remains idle at zero cost.
     */
    public synchronized DualMachineEntitlementRecord activateCard(
            String cardCode)
            throws IOException, GeneralSecurityException {
        stateMachine.beginCardActivation();
        boolean confirmationPersisted = false;
        try {
            if (pendingActivationStore.load() != null) {
                throw new IllegalStateException(
                        "a pending activation must be resumed first");
            }
            String requestId = nextId("activation requestId");
            String pairId = nextDistinctId(
                    requestId, "activation pairId");
            DualMachineSidecarPort.ActivationChallengeRequest request =
                    new DualMachineSidecarPort.ActivationChallengeRequest(
                            requestId,
                            pairId,
                            cardCode,
                            hostIdentity.peerIdentity,
                            androidIdentity.peerIdentity);
            DualMachineSidecarPort.ActivationChallengeResponse challenge =
                    sidecar.createActivationChallenge(request);
            if (challenge == null) {
                throw new GeneralSecurityException(
                        "activation challenge response is missing");
            }
            byte[] canonicalPayload = activationPayload(request, challenge);
            long nowEpoch = epochClock.nowEpochSeconds();
            if (nowEpoch <= 0L
                    || challenge.expiresAtEpoch <= nowEpoch) {
                throw new GeneralSecurityException(
                        "activation challenge is already expired");
            }
            if (!MessageDigest.isEqual(
                    canonicalPayload, challenge.proofPayload())) {
                throw new GeneralSecurityException(
                        "activation challenge proof payload mismatch");
            }
            DualMachineDeviceProofs.SignedProof proof = sign(
                    canonicalPayload);
            PendingActivation pending = pendingActivation(
                    requestId, pairId, challenge, proof);
            pendingActivationStore.save(pending);
            confirmationPersisted = true;
            return confirmAndCommitPending(pending);
        } catch (IOException | GeneralSecurityException
                 | RuntimeException failure) {
            if (!confirmationPersisted) {
                stateMachine.activationFailedBeforeConfirmation();
            } else if (stateMachine.snapshot().isActivationInFlight()) {
                stateMachine.markCardActivationPending();
            }
            throw failure;
        }
    }

    /**
     * Replays only the exact saved confirmation. This recovers safely when the
     * server committed a card but its response or the local entitlement write
     * was interrupted.
     */
    public synchronized DualMachineEntitlementRecord
            resumePendingActivation()
            throws IOException, GeneralSecurityException {
        stateMachine.beginPendingCardActivationResume();
        try {
            PendingActivation pending = pendingActivationStore.load();
            if (pending == null) {
                stateMachine.activationFailedBeforeConfirmation();
                throw new IllegalStateException("no pending activation");
            }
            return confirmAndCommitPending(pending);
        } catch (IOException | GeneralSecurityException
                 | RuntimeException failure) {
            if (stateMachine.snapshot().isActivationInFlight()) {
                stateMachine.markCardActivationPending();
            }
            throw failure;
        }
    }

    private DualMachineEntitlementRecord confirmAndCommitPending(
            PendingActivation pending)
            throws IOException, GeneralSecurityException {
        requirePendingIdentity(pending);
        final DualMachineSidecarPort.ActivationResponse response;
        try {
            response = sidecar.confirmActivation(
                    new DualMachineSidecarPort
                            .ActivationConfirmationRequest(
                            pending.challengeId,
                            pending.challengeToken,
                            pending.hostSignatureBase64,
                            pending.androidSignatureBase64));
        } catch (DualMachineSidecarPort.RejectedException
                 rejected) {
            if (rejected.statusCode == 409
                    && "activation_challenge_invalid".equals(
                    rejected.safeErrorCode)) {
                // A consumed challenge remains idempotently replayable on the
                // server. This exact error therefore proves no activation was
                // committed and the stale sealed challenge can be discarded.
                pendingActivationStore.clear();
                stateMachine.activationFailedBeforeConfirmation();
            }
            throw rejected;
        }
        requireActivationResponse(response, pending);
        DualMachineEntitlementRecord entitlement =
                new DualMachineEntitlementRecord(
                        response.entitlementId,
                        response.pairId,
                        DualMachineEntitlementRecord.PROTOCOL_VERSION,
                        response.revocationVersion,
                        hostIdentity.keyFingerprintSha256,
                        hostIdentity.peerIdentity.identityPublicKeyBase64,
                        androidIdentity.keyFingerprintSha256,
                        androidIdentityAlias,
                        response.authorizationKind,
                        response.productKey,
                        response.permanent,
                        false);
        entitlementStore.save(entitlement);
        stateMachine.activationConfirmed(
                entitlement,
                response.remainingSeconds,
                response.totalConsumedSeconds,
                response.billingStarted);
        pendingActivationStore.clear();
        return entitlement;
    }

    /**
     * Refreshes balance/revocation state without opening a session or billing.
     */
    public DualMachineFormalUsageStateMachine.Snapshot
            refreshStatus()
            throws IOException, GeneralSecurityException {
        StatusRefreshReservation reservation = beginStatusRefresh();
        try {
            return refreshStatus(
                    reservation, StatusRefreshCommit::run);
        } finally {
            statusRefreshFailedIfCurrent(reservation);
        }
    }

    /**
     * Short state-only reservation. Runtime may call this under its attachment
     * gate; this method never takes the coordinator monitor or performs I/O.
     */
    StatusRefreshReservation beginStatusRefresh()
            throws GeneralSecurityException {
        long operationToken = stateMachine.beginStatusRefresh();
        boolean reservationReturned = false;
        try {
            DualMachineFormalUsageStateMachine.Snapshot reserved =
                    stateMachine.snapshot();
            if (reserved.state
                    != DualMachineFormalUsageStateMachine.State
                    .STATUS_REFRESHING
                    || reserved.entitlement == null) {
                throw new IllegalStateException(
                        "status refresh reservation is inconsistent");
            }
            requireCurrentIdentity(reserved.entitlement);
            StatusRefreshReservation reservation =
                    new StatusRefreshReservation(
                    this, operationToken, reserved.entitlement);
            reservationReturned = true;
            return reservation;
        } finally {
            if (!reservationReturned) {
                stateMachine.statusRefreshFailedIfCurrent(operationToken);
            }
        }
    }

    boolean statusRefreshFailedIfCurrent(
            StatusRefreshReservation reservation) {
        requireOwnedReservation(reservation);
        return stateMachine.statusRefreshFailedIfCurrent(
                reservation.operationToken);
    }

    DualMachineFormalUsageStateMachine.Snapshot refreshStatus(
            StatusRefreshReservation reservation,
            StatusRefreshCommitGate commitGate)
            throws IOException, GeneralSecurityException {
        requireOwnedReservation(reservation);
        if (commitGate == null) {
            throw new IllegalArgumentException(
                    "status refresh commit gate is required");
        }
        DualMachineEntitlementRecord entitlement = reservation.entitlement;
        String requestNonce = nextId("status requestNonce");
        DualMachineUsageAuthorizationContract.EntitlementStatus contract =
                new DualMachineUsageAuthorizationContract
                        .EntitlementStatus();
        contract.entitlementId = entitlement.entitlementId;
        contract.pairId = entitlement.pairId;
        contract.protocolVersion = entitlement.protocolVersion;
        contract.requestNonce = requestNonce;
        contract.revocationVersion = entitlement.revocationVersion;
        DualMachineDeviceProofs.SignedProof signed = sign(
                DualMachineUsageAuthorizationContract.entitlementStatus(
                        contract));
        DualMachineSidecarPort.UsageProof proof = usageProof(
                entitlement, signed);
        DualMachineSidecarPort.EntitlementStatusResponse response =
                sidecar.fetchEntitlementStatus(
                        new DualMachineSidecarPort
                                .EntitlementStatusRequest(
                                proof, requestNonce));
        requireStatusResponse(response, entitlement);
        boolean revoked = "revoked".equals(response.status);
        boolean releaseExhaustedBinding = "exhausted".equals(response.status)
                && !"active".equals(response.usageSessionStatus);
        boolean metadataMigrated = "legacy_balance".equals(
                entitlement.authorizationKind);
        DualMachineEntitlementRecord committedEntitlement = metadataMigrated
                ? new DualMachineEntitlementRecord(
                entitlement.entitlementId,
                entitlement.pairId,
                entitlement.protocolVersion,
                entitlement.revocationVersion,
                entitlement.hostKeySha256,
                entitlement.hostIdentityPublicKeyBase64,
                entitlement.androidKeySha256,
                entitlement.androidIdentityAlias,
                response.authorizationKind,
                response.productKey,
                response.permanent,
                entitlement.revoked)
                : entitlement;
        if (revoked) {
            committedEntitlement = committedEntitlement.withRevocationVersion(
                    response.revocationVersion);
        }
        final DualMachineEntitlementRecord entitlementToCommit =
                committedEntitlement;
        try {
            commitGate.commit(() -> {
                try {
                    if ((revoked || metadataMigrated)
                            && !releaseExhaustedBinding) {
                        // Persist the monotonic terminal marker before
                        // exposing the in-memory state. The same ordering
                        // upgrades legacy authorization metadata safely.
                        entitlementStore.save(entitlementToCommit);
                    }
                    stateMachine.statusConfirmed(
                            reservation.operationToken,
                            entitlementToCommit,
                            response.status,
                            response.remainingSeconds,
                            response.totalConsumedSeconds);
                    if (releaseExhaustedBinding) {
                        // Storage is the recovery authority. Clear it before
                        // exposing UNACTIVATED in memory; a clear failure
                        // deliberately leaves the fail-closed EXHAUSTED state.
                        entitlementStore.clear();
                        stateMachine.releaseConfirmedExhaustedEntitlement();
                    }
                } catch (RuntimeException | Error failure) {
                    if (revoked) {
                        stateMachine
                                .failClosedFromAuthenticatedRevocationIfCurrent(
                                reservation.operationToken,
                                entitlementToCommit,
                                response.remainingSeconds,
                                response.totalConsumedSeconds);
                    } else {
                        stateMachine.statusRefreshFailedIfCurrent(
                                reservation.operationToken);
                    }
                    throw failure;
                }
            });
        } catch (IOException | GeneralSecurityException
                 | RuntimeException | Error failure) {
            if (revoked) {
                stateMachine.failClosedFromAuthenticatedRevocationIfCurrent(
                        reservation.operationToken,
                        entitlementToCommit,
                        response.remainingSeconds,
                        response.totalConsumedSeconds);
            }
            throw failure;
        }
        return stateMachine.snapshot();
    }

    private void requireOwnedReservation(
            StatusRefreshReservation reservation) {
        if (reservation == null || reservation.owner != this) {
            throw new IllegalArgumentException(
                    "status refresh reservation owner is invalid");
        }
    }

    private byte[] activationPayload(
            DualMachineSidecarPort.ActivationChallengeRequest request,
            DualMachineSidecarPort.ActivationChallengeResponse challenge)
            throws GeneralSecurityException {
        DualMachineUsageAuthorizationContract.ActivationConfirmation value =
                new DualMachineUsageAuthorizationContract
                        .ActivationConfirmation();
        value.activationMode = challenge.activationMode;
        value.androidClientVersion = request.android.clientVersion;
        value.androidDeviceCode = request.android.deviceCode;
        byte[] profileJson = request.android.deviceProfile == null
                ? "{}".getBytes(StandardCharsets.UTF_8)
                : request.android.deviceProfile.canonicalJson();
        String expectedProfileSha256 = sha256Hex(profileJson);
        if (!expectedProfileSha256.equals(
                challenge.androidDeviceProfileSha256)) {
            throw new GeneralSecurityException(
                    "activation challenge changed Android device profile");
        }
        value.androidDeviceProfileSha256 = expectedProfileSha256;
        value.androidKeySha256 = androidIdentity.keyFingerprintSha256;
        value.challengeId = challenge.challengeId;
        value.challengeTokenSha256 = sha256Hex(
                challenge.challengeToken.getBytes(
                        StandardCharsets.US_ASCII));
        value.hostClientVersion = request.host.clientVersion;
        value.hostDeviceCode = request.host.deviceCode;
        value.hostKeySha256 = hostIdentity.keyFingerprintSha256;
        value.pairId = request.pairId;
        value.protocolVersion = request.protocolVersion;
        value.requestId = request.requestId;
        value.targetEntitlementId = challenge.targetEntitlementId;
        return DualMachineUsageAuthorizationContract
                .activationConfirmation(value);
    }

    private DualMachineDeviceProofs.SignedProof sign(byte[] payload)
            throws IOException, GeneralSecurityException {
        return DualMachineDeviceProofs.createVerified(
                payload,
                hostIdentity.publicKeyDer,
                androidIdentity.publicKeyDer,
                hostIdentity.signer,
                androidIdentity.signer);
    }

    private static DualMachineSidecarPort.UsageProof usageProof(
            DualMachineEntitlementRecord entitlement,
            DualMachineDeviceProofs.SignedProof proof) {
        return new DualMachineSidecarPort.UsageProof(
                entitlement.entitlementId,
                entitlement.pairId,
                entitlement.revocationVersion,
                proof.hostSignatureBase64,
                proof.androidSignatureBase64);
    }

    private PendingActivation pendingActivation(
            String requestId,
            String pairId,
            DualMachineSidecarPort.ActivationChallengeResponse challenge,
            DualMachineDeviceProofs.SignedProof proof) {
        return new PendingActivation(
                requestId,
                pairId,
                challenge.challengeId,
                challenge.challengeToken,
                challenge.expiresAtEpoch,
                proof.hostSignatureBase64,
                proof.androidSignatureBase64,
                hostIdentity.keyFingerprintSha256,
                androidIdentity.keyFingerprintSha256,
                androidIdentityAlias,
                challenge.activationMode,
                challenge.targetEntitlementId);
    }

    private void requireCurrentIdentity(
            DualMachineEntitlementRecord entitlement)
            throws GeneralSecurityException {
        if (!entitlement.hostKeySha256.equals(
                hostIdentity.keyFingerprintSha256)
                || !entitlement.androidKeySha256.equals(
                androidIdentity.keyFingerprintSha256)
                || !entitlement.matchesAndroidIdentity(
                androidIdentityAlias,
                androidIdentity.keyFingerprintSha256)
                || !MessageDigest.isEqual(
                entitlement.hostIdentityPublicKeyDer(),
                hostIdentity.publicKeyDer)) {
            throw new GeneralSecurityException(
                    "activated device identity binding changed");
        }
    }

    private void requirePendingIdentity(PendingActivation pending)
            throws GeneralSecurityException {
        if (pending == null
                || !pending.hostKeyFingerprintSha256.equals(
                hostIdentity.keyFingerprintSha256)
                || !pending.androidKeyFingerprintSha256.equals(
                androidIdentity.keyFingerprintSha256)
                || !pending.androidIdentityAlias.equals(
                androidIdentityAlias)) {
            throw new GeneralSecurityException(
                    "pending activation device identity binding changed");
        }
    }

    private static void requireActivationResponse(
            DualMachineSidecarPort.ActivationResponse response,
            PendingActivation pending) throws GeneralSecurityException {
        boolean creditsAuthorization = response != null
                && isCreditingActivationMode(response.activationMode);
        boolean activationModeValid = response != null
                && pending.activationMode.equals(response.activationMode)
                && (creditsAuthorization != response.bindingUpdated);
        boolean entitlementTargetValid = response != null
                && (DualMachineUsageAuthorizationContract
                .ACTIVATION_MODE_ACTIVATE.equals(pending.activationMode)
                || pending.targetEntitlementId.equals(
                response.entitlementId));
        boolean balanceValid = response != null
                && balanceIsConsistent(
                response.remainingSeconds,
                response.totalConsumedSeconds,
                response.totalCreditedSeconds);
        long expectedInitialCredit = response == null
                ? -1L : authorizationDurationSeconds(
                response.authorizationKind);
        boolean creditValid = response != null && (response.permanent
                ? response.creditedSeconds == 0L
                && response.remainingSeconds == 0L
                && response.totalCreditedSeconds == 0L
                && response.totalConsumedSeconds == 0L
                : (creditsAuthorization
                ? expectedInitialCredit > 0L
                && response.creditedSeconds == expectedInitialCredit
                && response.remainingSeconds == expectedInitialCredit
                && response.totalCreditedSeconds == expectedInitialCredit
                && response.totalConsumedSeconds == 0L
                : response.creditedSeconds == 0L));
        if (response == null
                || response.billingStarted
                || !pending.pairId.equals(response.pairId)
                || response.revocationVersion <= 0L
                || !activationModeValid
                || !entitlementTargetValid
                || !authorizationMetadataValid(
                response.authorizationKind,
                response.productKey,
                response.permanent)
                || !creditValid
                || response.remainingSeconds < 0L
                || response.totalCreditedSeconds < response.creditedSeconds
                || response.totalConsumedSeconds < 0L
                || !balanceValid) {
            throw new GeneralSecurityException(
                    "activation response violates zero-cost contract");
        }
    }

    private static void requireStatusResponse(
            DualMachineSidecarPort.EntitlementStatusResponse response,
            DualMachineEntitlementRecord entitlement)
            throws GeneralSecurityException {
        boolean authorizationMatches = response != null
                && authorizationMetadataValid(
                response.authorizationKind,
                response.productKey,
                response.permanent)
                && (entitlement.authorizationKind.equals(
                response.authorizationKind)
                && entitlement.productKey.equals(response.productKey)
                && entitlement.permanent == response.permanent
                || "legacy_balance".equals(entitlement.authorizationKind));
        if (response == null
                || ("revoked".equals(response.status)
                ? response.revocationVersion
                < entitlement.revocationVersion
                : response.revocationVersion
                != entitlement.revocationVersion)
                || (!"active".equals(response.status)
                && !"exhausted".equals(response.status)
                && !"revoked".equals(response.status))
                || (entitlement.revoked
                && !"revoked".equals(response.status))
                || !authorizationMatches
                || response.remainingSeconds < 0L
                || response.totalCreditedSeconds < 0L
                || response.totalConsumedSeconds < 0L
                || !balanceIsConsistent(
                response.remainingSeconds,
                response.totalConsumedSeconds,
                response.totalCreditedSeconds)
                || (!response.permanent
                && "active".equals(response.status)
                && response.remainingSeconds == 0L)
                || ("exhausted".equals(response.status)
                && response.remainingSeconds != 0L)
                || (response.permanent
                && ("exhausted".equals(response.status)
                || response.remainingSeconds != 0L
                || response.totalCreditedSeconds != 0L
                || response.totalConsumedSeconds != 0L))
                || response.usageSessionStatus == null
                || (!response.usageSessionStatus.isEmpty()
                && !"active".equals(response.usageSessionStatus)
                && !"ended".equals(response.usageSessionStatus))) {
            throw new GeneralSecurityException(
                    "entitlement status response is inconsistent");
        }
    }

    private static boolean balanceIsConsistent(
            long remaining,
            long consumed,
            long credited) {
        try {
            return Math.addExact(remaining, consumed) == credited;
        } catch (ArithmeticException overflow) {
            return false;
        }
    }

    private static boolean authorizationMetadataValid(
            String authorizationKind,
            String productKey,
            boolean permanent) {
        return authorizationKind != null
                && authorizationKind.equals(productKey)
                && ("day".equals(authorizationKind)
                || "week".equals(authorizationKind)
                || "month".equals(authorizationKind)
                || "permanent".equals(authorizationKind))
                && permanent == "permanent".equals(authorizationKind);
    }

    private static long authorizationDurationSeconds(String kind) {
        if ("day".equals(kind)) return 86_400L;
        if ("week".equals(kind)) return 604_800L;
        if ("month".equals(kind)) return 2_592_000L;
        if ("permanent".equals(kind)) return 0L;
        return -1L;
    }

    private String nextId(String name) {
        return DualMachineSidecarValues.hex128(idSource.nextHex128(), name);
    }

    private String nextDistinctId(String first, String name)
            throws GeneralSecurityException {
        String second = nextId(name);
        if (first.equals(second)) {
            throw new GeneralSecurityException(
                    "activation identifiers must be unique");
        }
        return second;
    }

    private static String sha256Hex(byte[] input)
            throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(input);
        StringBuilder result = new StringBuilder(digest.length * 2);
        for (byte value : digest) {
            result.append(String.format(
                    java.util.Locale.ROOT, "%02x", value & 0xff));
        }
        return result.toString();
    }

    private static String requireAlias(String value) {
        if (value == null || value.isEmpty() || value.length() > 128) {
            throw new IllegalArgumentException(
                    "android identity alias has invalid length");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= 'A' && character <= 'Z')
                    || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9')
                    || character == '.' || character == '_'
                    || character == ':' || character == '-')) {
                throw new IllegalArgumentException(
                        "android identity alias has invalid characters");
            }
        }
        return value;
    }

    private static String requireActivationMode(String value) {
        if (!DualMachineUsageAuthorizationContract.ACTIVATION_MODE_ACTIVATE
                .equals(value)
                && !DualMachineUsageAuthorizationContract
                .ACTIVATION_MODE_REACTIVATE.equals(value)
                && !DualMachineUsageAuthorizationContract
                .ACTIVATION_MODE_BIND_DEVICE.equals(value)) {
            throw new IllegalArgumentException("activation mode is invalid");
        }
        return value;
    }

    private static String requireActivationTarget(
            String activationMode,
            String targetEntitlementId) {
        String target = targetEntitlementId == null
                ? "" : targetEntitlementId;
        if (DualMachineUsageAuthorizationContract.ACTIVATION_MODE_ACTIVATE
                .equals(activationMode)) {
            if (!target.isEmpty()) {
                throw new IllegalArgumentException(
                        "initial activation target must be empty");
            }
            return "";
        }
        return DualMachineSidecarValues.hex128(
                target, "targetEntitlementId");
    }

    private static boolean isCreditingActivationMode(String value) {
        return DualMachineUsageAuthorizationContract.ACTIVATION_MODE_ACTIVATE
                .equals(value)
                || DualMachineUsageAuthorizationContract
                .ACTIVATION_MODE_REACTIVATE.equals(value);
    }
}
