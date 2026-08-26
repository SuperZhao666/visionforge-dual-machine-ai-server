package com.visionforge.inferencebenchmark.runtime;

import java.util.Objects;

/** Immutable, ephemeral presentation state for one two-sided SAS decision. */
public final class FirstPairingUiState {
    public final boolean pending;
    public final String decimalSas;
    public final String hostIpv4;
    public final long expiresAtEpoch;

    private FirstPairingUiState(
            boolean pending,
            String decimalSas,
            String hostIpv4,
            long expiresAtEpoch) {
        if (pending
                && (decimalSas == null
                    || !decimalSas.matches("[0-9]{6}")
                    || hostIpv4 == null
                    || hostIpv4.isBlank()
                    || expiresAtEpoch <= 0L)) {
            throw new IllegalArgumentException(
                    "pending first-pair presentation state is invalid");
        }
        this.pending = pending;
        this.decimalSas = pending ? decimalSas : "";
        this.hostIpv4 = pending ? hostIpv4 : "";
        this.expiresAtEpoch = pending ? expiresAtEpoch : 0L;
    }

    public static FirstPairingUiState none() {
        return new FirstPairingUiState(false, "", "", 0L);
    }

    public static FirstPairingUiState pending(
            String decimalSas,
            String hostIpv4,
            long expiresAtEpoch) {
        return new FirstPairingUiState(
                true, decimalSas, hostIpv4, expiresAtEpoch);
    }

    public long remainingSeconds(long nowEpoch) {
        return pending ? Math.max(0L, expiresAtEpoch - nowEpoch) : 0L;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof FirstPairingUiState)) return false;
        FirstPairingUiState state = (FirstPairingUiState) other;
        return pending == state.pending
                && expiresAtEpoch == state.expiresAtEpoch
                && decimalSas.equals(state.decimalSas)
                && hostIpv4.equals(state.hostIpv4);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pending, decimalSas, hostIpv4, expiresAtEpoch);
    }
}
