package com.visionforge.inferencebenchmark.ui;

import java.util.Objects;

/** Immutable, non-secret presentation state for card authorization and billing. */
public final class DualMachineAuthorizationUiState {
    public enum Status {
        WAITING_FOR_HOST,
        CARD_SAVED_WAITING_FOR_HOST,
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
        SECURITY_CONFIGURATION_ERROR,
        ERROR
    }

    public final Status status;
    public final boolean authorizationReady;
    public final boolean activationReady;
    public final long remainingSeconds;
    public final long totalConsumedSeconds;
    public final boolean balanceKnown;
    public final boolean displayBalanceKnown;
    public final boolean balanceStale;
    public final long balanceSynchronizedAtEpochSeconds;
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
        this(
                status,
                authorizationReady,
                authorizationReady,
                remainingSeconds,
                totalConsumedSeconds,
                balanceKnown,
                permanent,
                detail);
    }

    public DualMachineAuthorizationUiState(
            Status status,
            boolean authorizationReady,
            boolean activationReady,
            long remainingSeconds,
            long totalConsumedSeconds,
            boolean balanceKnown,
            boolean permanent,
            String detail) {
        this(
                status,
                authorizationReady,
                activationReady,
                remainingSeconds,
                totalConsumedSeconds,
                balanceKnown,
                balanceKnown,
                false,
                0L,
                permanent,
                detail);
    }

    public DualMachineAuthorizationUiState(
            Status status,
            boolean authorizationReady,
            boolean activationReady,
            long remainingSeconds,
            long totalConsumedSeconds,
            boolean balanceKnown,
            boolean displayBalanceKnown,
            boolean balanceStale,
            long balanceSynchronizedAtEpochSeconds,
            boolean permanent,
            String detail) {
        if (status == null || remainingSeconds < 0L
                || totalConsumedSeconds < 0L
                || (balanceKnown && !displayBalanceKnown)
                || (balanceStale && (!displayBalanceKnown || balanceKnown
                || balanceSynchronizedAtEpochSeconds <= 0L))) {
            throw new IllegalArgumentException(
                    "authorization presentation state is invalid");
        }
        this.status = status;
        this.authorizationReady = authorizationReady;
        this.activationReady = activationReady;
        this.remainingSeconds = remainingSeconds;
        this.totalConsumedSeconds = totalConsumedSeconds;
        this.balanceKnown = balanceKnown;
        this.displayBalanceKnown = displayBalanceKnown;
        this.balanceStale = balanceStale;
        this.balanceSynchronizedAtEpochSeconds =
                balanceSynchronizedAtEpochSeconds;
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

    public static DualMachineAuthorizationUiState
            cardSavedWaitingForHost() {
        return new DualMachineAuthorizationUiState(
                Status.CARD_SAVED_WAITING_FOR_HOST,
                false,
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
        return activationReady
                && !operationInFlight()
                && status == Status.READY_FOR_ACTIVATION;
    }

    /**
     * Card text may be submitted before Host authentication so the UI never
     * presents a visible but inert input. The service seals that submitted
     * value and resumes activation automatically once a proof-producing Host
     * is available; queued and in-flight states deliberately hide this form.
     */
    public boolean canEnterCardCode() {
        return status == Status.WAITING_FOR_HOST
                || status == Status.READY_FOR_ACTIVATION;
    }

    public boolean canResumeActivation() {
        return activationReady && status == Status.ACTIVATION_PENDING;
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
        return status == Status.WAITING_FOR_HOST
                || status == Status.READY_FOR_ACTIVATION;
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
                && activationReady == other.activationReady
                && remainingSeconds == other.remainingSeconds
                && totalConsumedSeconds == other.totalConsumedSeconds
                && balanceKnown == other.balanceKnown
                && displayBalanceKnown == other.displayBalanceKnown
                && balanceStale == other.balanceStale
                && balanceSynchronizedAtEpochSeconds
                == other.balanceSynchronizedAtEpochSeconds
                && permanent == other.permanent
                && Objects.equals(detail, other.detail);
    }

    @Override
    public int hashCode() {
        return Objects.hash(status, authorizationReady, activationReady,
                remainingSeconds, totalConsumedSeconds, balanceKnown,
                displayBalanceKnown, balanceStale,
                balanceSynchronizedAtEpochSeconds, permanent, detail);
    }
}
