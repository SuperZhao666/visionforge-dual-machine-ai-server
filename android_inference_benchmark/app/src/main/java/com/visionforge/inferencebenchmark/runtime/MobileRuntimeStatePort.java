package com.visionforge.inferencebenchmark.runtime;

import com.visionforge.inferencebenchmark.ui.DualMachineAuthorizationUiState;

/** Stable read-only surface exposed to the Activity. */
public interface MobileRuntimeStatePort {
    void setAuthorizationObserver(MobileRuntimeAuthorizationObserver observer);
    DualMachineAuthorizationUiState authorizationState();
    String outputRouteReport();
}
