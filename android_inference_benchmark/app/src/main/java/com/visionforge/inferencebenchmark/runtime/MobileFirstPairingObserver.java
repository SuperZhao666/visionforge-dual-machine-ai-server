package com.visionforge.inferencebenchmark.runtime;

/** Same-process observer for an ephemeral, user-visible SAS decision. */
@FunctionalInterface
public interface MobileFirstPairingObserver {
    void onFirstPairingChanged(FirstPairingUiState state);
}
