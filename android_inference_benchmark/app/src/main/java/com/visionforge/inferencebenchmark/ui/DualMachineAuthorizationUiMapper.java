package com.visionforge.inferencebenchmark.ui;

import com.visionforge.inferencebenchmark.DualMachineFormalUsageStateMachine;

/**
 * Pure mapping from the authorization domain state to non-secret UI state.
 *
 * <p>Host streaming is intentionally not part of card activation. A persisted
 * revoked marker remains visible even while CAT6/video is offline, so a
 * process restart cannot make a revoked entitlement look activatable.</p>
 */
public final class DualMachineAuthorizationUiMapper {
    private DualMachineAuthorizationUiMapper() {
    }

    public static DualMachineAuthorizationUiState map(
            DualMachineFormalUsageStateMachine.Snapshot snapshot,
            boolean authorizationReady,
            boolean fatalSecurityError,
            String detail) {
        if (snapshot == null) {
            throw new IllegalArgumentException(
                    "authorization snapshot is required");
        }
        String safeDetail = detail == null ? "" : detail;
        long remaining = snapshot.balanceKnown
                ? snapshot.remainingSeconds : 0L;
        long consumed = snapshot.balanceKnown
                ? snapshot.totalConsumedSeconds : 0L;
        boolean permanent = snapshot.entitlement != null
                && snapshot.entitlement.permanent;
        if (snapshot.state
                == DualMachineFormalUsageStateMachine.State.REVOKED) {
            return state(
                    DualMachineAuthorizationUiState.Status.REVOKED,
                    authorizationReady,
                    remaining,
                    consumed,
                    snapshot.balanceKnown,
                    permanent,
                    safeDetail);
        }
        if (fatalSecurityError) {
            return state(
                    DualMachineAuthorizationUiState.Status.ERROR,
                    false,
                    remaining,
                    consumed,
                    snapshot.balanceKnown,
                    permanent,
                    safeDetail);
        }
        DualMachineAuthorizationUiState.Status status;
        switch (snapshot.state) {
            case UNACTIVATED:
                status = DualMachineAuthorizationUiState.Status
                        .READY_FOR_ACTIVATION;
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
                true,
                remaining,
                consumed,
                snapshot.balanceKnown,
                permanent,
                safeDetail);
    }

    private static DualMachineAuthorizationUiState state(
            DualMachineAuthorizationUiState.Status status,
            boolean authorizationReady,
            long remaining,
            long consumed,
            boolean balanceKnown,
            boolean permanent,
            String detail) {
        return new DualMachineAuthorizationUiState(
                status,
                authorizationReady,
                remaining,
                consumed,
                balanceKnown,
                permanent,
                detail);
    }
}
