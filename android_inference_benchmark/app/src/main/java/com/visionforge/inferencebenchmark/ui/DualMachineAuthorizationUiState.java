package com.visionforge.inferencebenchmark.ui;

import java.util.Objects;

/** Immutable, non-secret presentation state for card authorization and billing. */
public final class DualMachineAuthorizationUiState {
    public enum Status {
        READY_FOR_ACTIVATION,
        ACTIVATING,
        ACTIVATION_PENDING,
        ACTIVE_IDLE,
        REFRESHING,
        STARTING,
        IN_USE,
        STOPPING,
        EXHAUSTED,
        REVOKED,
        ERROR
    }

    public final Status status;
    public final boolean authorizationReady;
    public final long remainingSeconds;
    public final long totalConsumedSeconds;
    public final boolean balanceKnown;
    public final boolean permanent;
    public final String detail;

    public DualMachineAuthorizationUiState(
            Status status,
            boolean authorizationReady,
            long remainingSeconds,
            long totalConsumedSeconds,
            String detail) {
        this(
                status,
                authorizationReady,
                remainingSeconds,
                totalConsumedSeconds,
                inferLegacyBalanceKnown(
                        remainingSeconds, totalConsumedSeconds, false),
                false,
                detail);
    }

    public DualMachineAuthorizationUiState(
            Status status,
            boolean authorizationReady,
            long remainingSeconds,
            long totalConsumedSeconds,
            boolean permanent,
            String detail) {
        this(
                status,
                authorizationReady,
                remainingSeconds,
                totalConsumedSeconds,
                inferLegacyBalanceKnown(
                        remainingSeconds, totalConsumedSeconds, permanent),
                permanent,
                detail);
    }

    public DualMachineAuthorizationUiState(
            Status status,
            boolean authorizationReady,
            long remainingSeconds,
            long totalConsumedSeconds,
            boolean balanceKnown,
            boolean permanent,
            String detail) {
        if (status == null || remainingSeconds < 0L
                || totalConsumedSeconds < 0L) {
            throw new IllegalArgumentException(
                    "authorization presentation state is invalid");
        }
        this.status = status;
        this.authorizationReady = authorizationReady;
        this.remainingSeconds = remainingSeconds;
        this.totalConsumedSeconds = totalConsumedSeconds;
        this.balanceKnown = balanceKnown;
        this.permanent = permanent;
        this.detail = detail == null ? "" : detail;
    }

    public static DualMachineAuthorizationUiState readyForActivation() {
        return new DualMachineAuthorizationUiState(
                Status.READY_FOR_ACTIVATION,
                true,
                0L,
                0L,
                false,
                false,
                "");
    }

    public boolean entitlementBound() {
        return status == Status.ACTIVE_IDLE
                || status == Status.STARTING
                || status == Status.IN_USE
                || status == Status.STOPPING
                || status == Status.EXHAUSTED
                || status == Status.REVOKED;
    }

    public boolean operationInFlight() {
        return status == Status.ACTIVATING
                || status == Status.ACTIVATION_PENDING
                || status == Status.REFRESHING
                || status == Status.STARTING
                || status == Status.STOPPING;
    }

    public boolean formalUseActive() {
        return status == Status.STARTING
                || status == Status.IN_USE
                || status == Status.STOPPING;
    }

    public boolean canActivateCard() {
        return authorizationReady
                && !operationInFlight()
                && status == Status.READY_FOR_ACTIVATION;
    }

    public boolean canResumeActivation() {
        return authorizationReady && status == Status.ACTIVATION_PENDING;
    }

    public boolean canRefreshStatus() {
        return authorizationReady
                && (status == Status.ACTIVE_IDLE
                || status == Status.EXHAUSTED);
    }

    public boolean canStartFormalUse() {
        return authorizationReady && status == Status.ACTIVE_IDLE
                && balanceKnown
                && (permanent || remainingSeconds > 0L);
    }

    public boolean canStopFormalUse() {
        return status == Status.STARTING || status == Status.IN_USE;
    }

    public boolean isActivationCardVisible() {
        return status == Status.READY_FOR_ACTIVATION
                || status == Status.ACTIVATING
                || status == Status.ACTIVATION_PENDING;
    }

    private static boolean inferLegacyBalanceKnown(
            long remainingSeconds,
            long totalConsumedSeconds,
            boolean permanent) {
        // Legacy transient-state callers cannot represent a known zero.
        // Keep that case unknown so the UI never invents a confirmed balance.
        return permanent || remainingSeconds > 0L
                || totalConsumedSeconds > 0L;
    }

    @Override
    public boolean equals(Object candidate) {
        if (this == candidate) return true;
        if (!(candidate instanceof DualMachineAuthorizationUiState)) {
            return false;
        }
        DualMachineAuthorizationUiState other =
                (DualMachineAuthorizationUiState) candidate;
        return status == other.status
                && authorizationReady == other.authorizationReady
                && remainingSeconds == other.remainingSeconds
                && totalConsumedSeconds == other.totalConsumedSeconds
                && balanceKnown == other.balanceKnown
                && permanent == other.permanent
                && Objects.equals(detail, other.detail);
    }

    @Override
    public int hashCode() {
        return Objects.hash(status, authorizationReady, remainingSeconds,
                totalConsumedSeconds, balanceKnown, permanent, detail);
    }
}
