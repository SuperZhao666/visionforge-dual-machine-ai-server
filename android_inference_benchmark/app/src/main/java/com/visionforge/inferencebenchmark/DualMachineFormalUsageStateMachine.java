package com.visionforge.inferencebenchmark;

/**
 * Local user-rights state machine for card activation and paid formal use.
 *
 * <p>It deliberately has no network, storage, crypto or pipeline dependency.
 * Only {@link #runtimeRequestedFormalStart(boolean)} can enter STARTING.
 * Activation/status refresh and process restore can never start billing or
 * reopen a data-plane permit.</p>
 */
public final class DualMachineFormalUsageStateMachine {
    public enum State {
        UNACTIVATED,
        ACTIVATING,
        ACTIVATED_IDLE,
        STATUS_REFRESHING,
        STARTING,
        ACTIVE,
        RENEWAL_GAP,
        STOPPING,
        EXHAUSTED,
        REVOKED
    }

    public static final class Snapshot {
        public final State state;
        public final DualMachineEntitlementRecord entitlement;
        public final long remainingSeconds;
        public final long totalConsumedSeconds;
        public final boolean balanceKnown;
        public final String sessionId;
        public final long leaseSequence;
        public final boolean billingStarted;
        public final boolean permitsDataPlane;
        public final boolean activationOperationInFlight;
        public final boolean activationConfirmationPending;

        private Snapshot(
                State state,
                DualMachineEntitlementRecord entitlement,
                long remainingSeconds,
                long totalConsumedSeconds,
                boolean balanceKnown,
                String sessionId,
                long leaseSequence,
                boolean billingStarted,
                boolean permitsDataPlane,
                boolean activationOperationInFlight,
                boolean activationConfirmationPending) {
            this.state = state;
            this.entitlement = entitlement;
            this.remainingSeconds = remainingSeconds;
            this.totalConsumedSeconds = totalConsumedSeconds;
            this.balanceKnown = balanceKnown;
            this.sessionId = sessionId;
            this.leaseSequence = leaseSequence;
            this.billingStarted = billingStarted;
            this.permitsDataPlane = permitsDataPlane;
            this.activationOperationInFlight =
                    activationOperationInFlight;
            this.activationConfirmationPending =
                    activationConfirmationPending;
        }

        public boolean canActivate() {
            return state == State.UNACTIVATED;
        }

        public boolean isActivationInFlight() {
            return state == State.ACTIVATING
                    && activationOperationInFlight;
        }

        public boolean hasPendingActivationConfirmation() {
            return state == State.ACTIVATING
                    && activationConfirmationPending;
        }

        public boolean canRefreshStatus() {
            return state == State.ACTIVATED_IDLE
                    || state == State.EXHAUSTED
                    || state == State.REVOKED;
        }

        public boolean canFormalStart() {
            return state == State.ACTIVATED_IDLE
                    && balanceKnown && entitlement != null
                    && (entitlement.permanent || remainingSeconds > 0L);
        }

        public boolean canFormalStop() {
            return state == State.STARTING
                    || state == State.ACTIVE
                    || state == State.RENEWAL_GAP;
        }
    }

    private State state = State.UNACTIVATED;
    private DualMachineEntitlementRecord entitlement;
    private long remainingSeconds;
    private long totalConsumedSeconds;
    private boolean balanceKnown;
    private String sessionId = "";
    private long leaseSequence = -1L;
    private boolean billingStarted;
    private boolean permitsDataPlane;
    private State stateBeforeActivation;
    private boolean activationOperationInFlight;
    private State stateBeforeStatusRefresh;
    private long statusRefreshGeneration;
    private long activeStatusRefreshToken;

    /**
     * Restores only the non-secret activation binding after process restart.
     * Active leases and billing sessions are intentionally never restored.
     */
    public synchronized void restoreBoundEntitlement(
            DualMachineEntitlementRecord restored) {
        requireEntitlement(restored);
        entitlement = restored;
        remainingSeconds = 0L;
        totalConsumedSeconds = 0L;
        balanceKnown = false;
        clearSession();
        stateBeforeActivation = null;
        activationOperationInFlight = false;
        clearStatusRefresh();
        state = restored.revoked ? State.REVOKED : State.ACTIVATED_IDLE;
    }

    /**
     * Atomically reserves the shared authorization state for the one allowed
     * card activation. This is the cross-coordinator exclusion boundary:
     * formal use cannot start after this transition, even when the two
     * coordinators are invoked concurrently.
     */
    public synchronized void beginCardActivation() {
        if (!snapshot().canActivate()) {
            throw new IllegalStateException(
                    "card activation is unavailable during formal use");
        }
        stateBeforeActivation = state;
        activationOperationInFlight = true;
        state = State.ACTIVATING;
    }

    /**
     * Reserves a previously persisted pending confirmation. A concurrent
     * activation owner cannot be mistaken for an idle pending operation.
     */
    public synchronized void beginPendingCardActivationResume() {
        if (state != State.ACTIVATING) {
            if (state != State.UNACTIVATED) {
                throw new IllegalStateException(
                        "pending card activation cannot be resumed now");
            }
            stateBeforeActivation = state;
            activationOperationInFlight = true;
            state = State.ACTIVATING;
            return;
        }
        if (activationOperationInFlight) {
            throw new IllegalStateException(
                    "another card activation operation is in flight");
        }
        activationOperationInFlight = true;
    }

    /**
     * Marks that an exact sealed confirmation remains replayable after an
     * ambiguous result. Formal start stays blocked while no operation owns it.
     */
    public synchronized void markCardActivationPending() {
        if (state != State.ACTIVATING || !activationOperationInFlight) {
            throw new IllegalStateException(
                    "card activation operation is not in flight");
        }
        activationOperationInFlight = false;
    }

    /**
     * Releases an activation reservation only when no replayable confirmation
     * has been persisted. Ambiguous confirmations deliberately stay reserved.
     */
    public synchronized void activationFailedBeforeConfirmation() {
        if (state != State.ACTIVATING || stateBeforeActivation == null
                || !activationOperationInFlight) {
            throw new IllegalStateException(
                    "card activation is not reserved");
        }
        state = stateBeforeActivation;
        stateBeforeActivation = null;
        activationOperationInFlight = false;
    }

    /**
     * Applies the first activation response. The server must explicitly state
     * that this operation did not start billing.
     */
    public synchronized void activationConfirmed(
            DualMachineEntitlementRecord activated,
            long remaining,
            long totalConsumed,
            boolean activationStartedBilling) {
        requireEntitlement(activated);
        requireBalances(remaining, totalConsumed);
        if (state != State.ACTIVATING || !activationOperationInFlight) {
            throw new IllegalStateException(
                    "card activation was not reserved");
        }
        if (stateBeforeActivation != State.UNACTIVATED
                || entitlement != null) {
            throw new SecurityException(
                    "an activated entitlement cannot accept another card");
        }
        if (activationStartedBilling) {
            throw new SecurityException(
                    "card activation must never start billing");
        }
        entitlement = activated;
        remainingSeconds = remaining;
        totalConsumedSeconds = totalConsumed;
        balanceKnown = true;
        clearSession();
        stateBeforeActivation = null;
        activationOperationInFlight = false;
        state = authorizationState(activated, remaining);
    }

    /**
     * Applies a signed-request HTTPS status result without starting a session.
     */
    public synchronized long beginStatusRefresh() {
        if (!snapshot().canRefreshStatus() || entitlement == null) {
            throw new IllegalStateException(
                    "status refresh is unavailable");
        }
        stateBeforeStatusRefresh = state;
        statusRefreshGeneration = Math.addExact(
                statusRefreshGeneration, 1L);
        activeStatusRefreshToken = statusRefreshGeneration;
        state = State.STATUS_REFRESHING;
        return activeStatusRefreshToken;
    }

    public synchronized void statusRefreshFailed(long operationToken) {
        requireStatusRefreshToken(operationToken);
        rollbackStatusRefresh();
    }

    /** Exact stale-safe rollback; a newer reservation is never affected. */
    public synchronized boolean statusRefreshFailedIfCurrent(
            long operationToken) {
        if (!isCurrentStatusRefreshToken(operationToken)) return false;
        rollbackStatusRefresh();
        return true;
    }

    /**
     * Keeps an authenticated revocation terminal when its persistence or
     * ordinary commit path fails. A stale token cannot revoke a newer owner.
     */
    public synchronized boolean
            failClosedFromAuthenticatedRevocationIfCurrent(
            long operationToken,
            DualMachineEntitlementRecord revokedEntitlement,
            long remaining,
            long totalConsumed) {
        if (!isCurrentStatusRefreshToken(operationToken)) return false;
        requireBalances(remaining, totalConsumed);
        requireSameEntitlementBinding(revokedEntitlement);
        if (!revokedEntitlement.revoked
                || revokedEntitlement.revocationVersion
                < entitlement.revocationVersion) {
            throw new SecurityException(
                    "authenticated revocation marker is invalid");
        }
        entitlement = revokedEntitlement;
        remainingSeconds = remaining;
        totalConsumedSeconds = totalConsumed;
        balanceKnown = true;
        clearSession();
        state = State.REVOKED;
        clearStatusRefresh();
        return true;
    }

    private void rollbackStatusRefresh() {
        state = stateBeforeStatusRefresh;
        clearStatusRefresh();
    }

    public synchronized void statusConfirmed(
            long operationToken,
            DualMachineEntitlementRecord confirmedEntitlement,
            String entitlementStatus,
            long remaining,
            long totalConsumed) {
        requireBalances(remaining, totalConsumed);
        requireStatusRefreshToken(operationToken);
        requireSameEntitlementBinding(confirmedEntitlement);
        if (confirmedEntitlement.revocationVersion
                < entitlement.revocationVersion) {
            throw new SecurityException(
                    "revocationVersion must not decrease");
        }
        State previousState = stateBeforeStatusRefresh;
        boolean wasRevoked = entitlement.revoked
                || previousState == State.REVOKED;
        if ("revoked".equals(entitlementStatus)) {
            if (!confirmedEntitlement.revoked) {
                throw new SecurityException(
                        "revoked status must persist its marker");
            }
            entitlement = confirmedEntitlement;
            remainingSeconds = remaining;
            totalConsumedSeconds = totalConsumed;
            balanceKnown = true;
            clearSession();
            state = State.REVOKED;
            clearStatusRefresh();
            return;
        }
        if (!"active".equals(entitlementStatus)
                && !"exhausted".equals(entitlementStatus)) {
            throw new IllegalArgumentException(
                    "unsupported entitlement status");
        }
        if (wasRevoked || confirmedEntitlement.revoked
                || confirmedEntitlement.revocationVersion
                != entitlement.revocationVersion) {
            throw new SecurityException(
                    "non-revoked status cannot clear revocation");
        }
        entitlement = confirmedEntitlement;
        remainingSeconds = remaining;
        totalConsumedSeconds = totalConsumed;
        balanceKnown = true;
        clearSession();
        state = authorizationState(confirmedEntitlement, remaining);
        clearStatusRefresh();
    }

    /**
     * Releases a server-confirmed exhausted binding after its durable record
     * has already been cleared. An active final prepaid usage session must be
     * stopped and confirmed by the server before this transition is allowed.
     */
    public synchronized void releaseConfirmedExhaustedEntitlement() {
        if (state != State.EXHAUSTED || entitlement == null
                || entitlement.permanent || !balanceKnown
                || remainingSeconds != 0L || billingStarted
                || permitsDataPlane || !sessionId.isEmpty()) {
            throw new IllegalStateException(
                    "confirmed exhausted entitlement cannot be released");
        }
        entitlement = null;
        remainingSeconds = 0L;
        totalConsumedSeconds = 0L;
        balanceKnown = false;
        stateBeforeActivation = null;
        activationOperationInFlight = false;
        clearSession();
        clearStatusRefresh();
        state = State.UNACTIVATED;
    }

    /**
     * The sole transition into STARTING. Call only after Host video, both
     * runtimes and the authenticated channel are verified ready.
     */
    public synchronized void runtimeRequestedFormalStart(
            boolean bothRuntimesAndChannelReady) {
        if (state != State.ACTIVATED_IDLE || entitlement == null
                || (!entitlement.permanent && remainingSeconds <= 0L)) {
            throw new IllegalStateException("formal start is unavailable");
        }
        if (!bothRuntimesAndChannelReady) {
            throw new IllegalStateException(
                    "both runtimes and secure channel must be ready");
        }
        clearSession();
        state = State.STARTING;
    }

    public synchronized void formalStartFailed() {
        if (state != State.STARTING) {
            throw new IllegalStateException("no formal start is in flight");
        }
        clearSession();
        state = authorizationState(entitlement, remainingSeconds);
    }

    /**
     * Installs an already verified initial paid lease.
     */
    public synchronized void verifiedInitialLeaseInstalled(
            String verifiedSessionId,
            long verifiedSequence,
            long chargedSeconds,
            long remaining,
            long totalConsumed,
            boolean serverBillingStarted) {
        if (state != State.STARTING) {
            throw new IllegalStateException("formal start was not requested");
        }
        if (verifiedSequence != 0L
                || !validLeaseCharge(chargedSeconds)
                || !serverBillingStarted) {
            throw new SecurityException("initial paid lease is invalid");
        }
        requireBalances(remaining, totalConsumed);
        sessionId = requireIdentifier(verifiedSessionId, "sessionId");
        leaseSequence = verifiedSequence;
        remainingSeconds = remaining;
        totalConsumedSeconds = totalConsumed;
        balanceKnown = true;
        billingStarted = true;
        permitsDataPlane = true;
        state = State.ACTIVE;
    }

    public synchronized void leaseExpiredLocally() {
        if (state != State.ACTIVE) {
            throw new IllegalStateException("no active lease");
        }
        permitsDataPlane = false;
        state = State.RENEWAL_GAP;
    }

    /**
     * Installs an already verified early or late chained renewal.
     */
    public synchronized void verifiedRenewalInstalled(
            long verifiedSequence,
            long chargedSeconds,
            long remaining,
            long totalConsumed) {
        if (state != State.ACTIVE && state != State.RENEWAL_GAP) {
            throw new IllegalStateException("no renewable session");
        }
        if (verifiedSequence != leaseSequence + 1L
                || !validLeaseCharge(chargedSeconds)) {
            throw new SecurityException("renewal sequence or charge is invalid");
        }
        requireBalances(remaining, totalConsumed);
        leaseSequence = verifiedSequence;
        remainingSeconds = remaining;
        totalConsumedSeconds = totalConsumed;
        balanceKnown = true;
        billingStarted = true;
        permitsDataPlane = true;
        state = State.ACTIVE;
    }

    /**
     * Accounts for a verified next segment which is not active yet. The
     * current lease remains authoritative until the staged boundary.
     */
    public synchronized void verifiedFutureRenewalStaged(
            long verifiedSequence,
            long chargedSeconds,
            long remaining,
            long totalConsumed) {
        if (state != State.ACTIVE && state != State.RENEWAL_GAP) {
            throw new IllegalStateException("no renewable session");
        }
        if (verifiedSequence != leaseSequence + 1L
                || !validLeaseCharge(chargedSeconds)) {
            throw new SecurityException("renewal sequence or charge is invalid");
        }
        requireBalances(remaining, totalConsumed);
        leaseSequence = verifiedSequence;
        remainingSeconds = remaining;
        totalConsumedSeconds = totalConsumed;
        balanceKnown = true;
        billingStarted = true;
    }

    public synchronized void stagedRenewalActivated(long verifiedSequence) {
        if ((state != State.ACTIVE && state != State.RENEWAL_GAP)
                || verifiedSequence != leaseSequence) {
            throw new IllegalStateException(
                    "staged renewal is not current");
        }
        permitsDataPlane = true;
        state = State.ACTIVE;
    }

    /**
     * Synchronously closes the local permit before any best-effort network
     * stop request is attempted.
     */
    public synchronized void closeLocalForRuntimeStop() {
        if (state != State.STARTING && state != State.ACTIVE
                && state != State.RENEWAL_GAP) {
            throw new IllegalStateException("formal usage is not running");
        }
        permitsDataPlane = false;
        state = State.STOPPING;
    }

    public synchronized void stopFinished(long remaining) {
        if (state != State.STOPPING) {
            throw new IllegalStateException("formal stop was not requested");
        }
        if (remaining < 0L) {
            throw new IllegalArgumentException("remaining must not be negative");
        }
        remainingSeconds = remaining;
        clearSession();
        state = authorizationState(entitlement, remaining);
    }

    public synchronized void revoke() {
        clearSession();
        stateBeforeActivation = null;
        activationOperationInFlight = false;
        clearStatusRefresh();
        state = State.REVOKED;
    }

    public synchronized Snapshot snapshot() {
        return new Snapshot(
                state,
                entitlement,
                remainingSeconds,
                totalConsumedSeconds,
                balanceKnown,
                sessionId,
                leaseSequence,
                billingStarted,
                permitsDataPlane,
                activationOperationInFlight,
                state == State.ACTIVATING
                        && !activationOperationInFlight);
    }

    private void clearSession() {
        sessionId = "";
        leaseSequence = -1L;
        billingStarted = false;
        permitsDataPlane = false;
    }

    private void requireStatusRefreshToken(long operationToken) {
        if (!isCurrentStatusRefreshToken(operationToken)) {
            throw new IllegalStateException(
                    "status refresh operation is not current");
        }
    }

    private boolean isCurrentStatusRefreshToken(long operationToken) {
        return state == State.STATUS_REFRESHING
                && activeStatusRefreshToken != 0L
                && operationToken == activeStatusRefreshToken
                && stateBeforeStatusRefresh != null;
    }

    private void clearStatusRefresh() {
        stateBeforeStatusRefresh = null;
        activeStatusRefreshToken = 0L;
    }

    private void requireSameEntitlementBinding(
            DualMachineEntitlementRecord confirmed) {
        requireEntitlement(confirmed);
        boolean authorizationUnchanged = entitlement != null
                && entitlement.authorizationKind.equals(
                confirmed.authorizationKind)
                && entitlement.productKey.equals(confirmed.productKey)
                && entitlement.permanent == confirmed.permanent;
        boolean legacyAuthorizationUpgraded = entitlement != null
                && "legacy_balance".equals(entitlement.authorizationKind)
                && !"legacy_balance".equals(confirmed.authorizationKind)
                && DualMachineEntitlementRecord.isSupportedAuthorizationKind(
                confirmed.authorizationKind);
        if (entitlement == null
                || !entitlement.entitlementId.equals(confirmed.entitlementId)
                || !entitlement.pairId.equals(confirmed.pairId)
                || entitlement.protocolVersion != confirmed.protocolVersion
                || !entitlement.hostKeySha256.equals(confirmed.hostKeySha256)
                || !entitlement.hostIdentityPublicKeyBase64.equals(
                confirmed.hostIdentityPublicKeyBase64)
                || !entitlement.androidKeySha256.equals(
                confirmed.androidKeySha256)
                || !entitlement.androidIdentityAlias.equals(
                confirmed.androidIdentityAlias)
                || (!authorizationUnchanged
                && !legacyAuthorizationUpgraded)) {
            throw new SecurityException(
                    "status response changed entitlement binding");
        }
    }

    private static void requireEntitlement(DualMachineEntitlementRecord value) {
        if (value == null) {
            throw new IllegalArgumentException("entitlement is required");
        }
    }

    private boolean validLeaseCharge(long chargedSeconds) {
        return entitlement != null && (entitlement.permanent
                ? chargedSeconds == 0L : chargedSeconds > 0L);
    }

    private static State authorizationState(
            DualMachineEntitlementRecord entitlement,
            long remainingSeconds) {
        if (entitlement == null) {
            throw new IllegalStateException("entitlement is unavailable");
        }
        return entitlement.permanent || remainingSeconds > 0L
                ? State.ACTIVATED_IDLE : State.EXHAUSTED;
    }

    private static void requireBalances(long remaining, long totalConsumed) {
        if (remaining < 0L || totalConsumed < 0L) {
            throw new IllegalArgumentException("balances must not be negative");
        }
    }

    private static String requireIdentifier(String value, String name) {
        if (value == null || value.length() != 32) {
            throw new IllegalArgumentException(name + " has invalid length");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f'))) {
                throw new IllegalArgumentException(name + " is not lowercase hex");
            }
        }
        return value;
    }
}
