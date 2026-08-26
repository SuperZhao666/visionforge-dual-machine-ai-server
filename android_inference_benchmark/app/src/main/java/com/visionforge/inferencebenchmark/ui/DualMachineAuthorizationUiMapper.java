package com.visionforge.inferencebenchmark.ui;

import com.visionforge.inferencebenchmark.DualMachineFormalUsageStateMachine;
import com.visionforge.inferencebenchmark.DualMachinePresentationBalance;

/**
 * Pure mapping from the authorization domain state to non-secret UI state.
 *
 * <p>Card activation accepts either a real authenticated Host session or the
 * narrow capability installed after both users confirm a fresh pairing. Status
 * refresh and formal use still require the authenticated Host session. Video
 * streaming remains a later, separately leased boundary. A persisted revoked
 * marker remains visible even while CAT6/video is offline, so a process restart
 * cannot make a revoked entitlement look activatable.</p>
 */
public final class DualMachineAuthorizationUiMapper {
    private DualMachineAuthorizationUiMapper() {
    }

    public static DualMachineAuthorizationUiState map(
            DualMachineFormalUsageStateMachine.Snapshot snapshot,
            boolean authorizationReady,
            boolean fatalSecurityError,
            String detail) {
        return map(
                snapshot,
                authorizationReady,
                authorizationReady,
                fatalSecurityError,
                detail);
    }

    public static DualMachineAuthorizationUiState map(
            DualMachineFormalUsageStateMachine.Snapshot snapshot,
            boolean authorizationReady,
            boolean activationReady,
            boolean fatalSecurityError,
            String detail) {
        return map(
                snapshot,
                authorizationReady,
                activationReady,
                fatalSecurityError,
                detail,
                null);
    }

    public static DualMachineAuthorizationUiState map(
            DualMachineFormalUsageStateMachine.Snapshot snapshot,
            boolean authorizationReady,
            boolean activationReady,
            boolean fatalSecurityError,
            String detail,
            DualMachinePresentationBalance cachedBalance) {
        if (snapshot == null) {
            throw new IllegalArgumentException(
                    "authorization snapshot is required");
        }
        String safeDetail = detail == null ? "" : detail;
        boolean cachedBalanceMatches = !snapshot.balanceKnown
                && cachedBalance != null
                && cachedBalance.matches(snapshot.entitlement);
        long remaining = snapshot.balanceKnown
                ? snapshot.remainingSeconds
                : cachedBalanceMatches
                ? cachedBalance.remainingSeconds : 0L;
        long consumed = snapshot.balanceKnown
                ? snapshot.totalConsumedSeconds
                : cachedBalanceMatches
                ? cachedBalance.totalConsumedSeconds : 0L;
        boolean displayBalanceKnown = snapshot.balanceKnown
                || cachedBalanceMatches;
        long synchronizedAtEpochSeconds = cachedBalanceMatches
                ? cachedBalance.synchronizedAtEpochSeconds : 0L;
        boolean permanent = snapshot.entitlement != null
                && snapshot.entitlement.permanent;
        if (snapshot.state
                == DualMachineFormalUsageStateMachine.State.REVOKED) {
            return state(
                    DualMachineAuthorizationUiState.Status.REVOKED,
                    authorizationReady,
                    activationReady,
                    remaining,
                    consumed,
                    snapshot.balanceKnown,
                    displayBalanceKnown,
                    cachedBalanceMatches,
                    synchronizedAtEpochSeconds,
                    permanent,
                    safeDetail);
        }
        if (fatalSecurityError) {
            return state(
                    DualMachineAuthorizationUiState.Status
                            .SECURITY_CONFIGURATION_ERROR,
                    false,
                    false,
                    remaining,
                    consumed,
                    snapshot.balanceKnown,
                    displayBalanceKnown,
                    cachedBalanceMatches,
                    synchronizedAtEpochSeconds,
                    permanent,
                    safeDetail);
        }
        DualMachineAuthorizationUiState.Status status;
        switch (snapshot.state) {
            case UNACTIVATED:
                status = activationReady
                        ? DualMachineAuthorizationUiState.Status
                        .READY_FOR_ACTIVATION
                        : DualMachineAuthorizationUiState.Status
                        .WAITING_FOR_HOST;
                break;
            case ACTIVATING:
                status = snapshot.hasPendingActivationConfirmation()
                        ? DualMachineAuthorizationUiState.Status
                        .ACTIVATION_PENDING
                        : DualMachineAuthorizationUiState.Status.ACTIVATING;
                break;
            case ACTIVATED_IDLE:
                status = DualMachineAuthorizationUiState.Status.ACTIVE_IDLE;
                break;
            case STATUS_REFRESHING:
                status = DualMachineAuthorizationUiState.Status.REFRESHING;
                break;
            case STARTING:
                status = DualMachineAuthorizationUiState.Status.STARTING;
                break;
            case ACTIVE:
            case RENEWAL_GAP:
                status = DualMachineAuthorizationUiState.Status.IN_USE;
                break;
            case STOPPING:
                status = DualMachineAuthorizationUiState.Status.STOPPING;
                break;
            case EXHAUSTED:
                status = DualMachineAuthorizationUiState.Status.EXHAUSTED;
                break;
            case REVOKED:
                status = DualMachineAuthorizationUiState.Status.REVOKED;
                break;
            default:
                throw new IllegalStateException(
                        "unsupported authorization state");
        }
        return state(
                status,
                authorizationReady,
                activationReady,
                remaining,
                consumed,
                snapshot.balanceKnown,
                displayBalanceKnown,
                cachedBalanceMatches,
                synchronizedAtEpochSeconds,
                permanent,
                safeDetail);
    }

    private static DualMachineAuthorizationUiState state(
            DualMachineAuthorizationUiState.Status status,
            boolean authorizationReady,
            boolean activationReady,
            long remaining,
            long consumed,
            boolean balanceKnown,
            boolean displayBalanceKnown,
            boolean balanceStale,
            long balanceSynchronizedAtEpochSeconds,
            boolean permanent,
            String detail) {
        return new DualMachineAuthorizationUiState(
                status,
                authorizationReady,
                activationReady,
                remaining,
                consumed,
                balanceKnown,
                displayBalanceKnown,
                balanceStale,
                balanceSynchronizedAtEpochSeconds,
                permanent,
                detail);
    }
}
