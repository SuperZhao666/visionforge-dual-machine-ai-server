package com.visionforge.inferencebenchmark.runtime;

import com.visionforge.inferencebenchmark.ui.DualMachineAuthorizationUiState;

/** Stable read-only surface exposed to the Activity. */
public interface MobileRuntimeStatePort {
    void setAuthorizationObserver(MobileRuntimeAuthorizationObserver observer);
    void setFirstPairingObserver(MobileFirstPairingObserver observer);
    DualMachineAuthorizationUiState authorizationState();
    FirstPairingUiState firstPairingState();
    String outputRouteReport();
}
