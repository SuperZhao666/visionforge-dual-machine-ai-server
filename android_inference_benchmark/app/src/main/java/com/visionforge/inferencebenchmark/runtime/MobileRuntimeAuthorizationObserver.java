package com.visionforge.inferencebenchmark.runtime;

import com.visionforge.inferencebenchmark.ui.DualMachineAuthorizationUiState;

/** 授权状态的只读通知端口；Activity 不需要知道 Service 如何计算该状态。 */
@FunctionalInterface
public interface MobileRuntimeAuthorizationObserver {
    void onAuthorizationChanged(
            DualMachineAuthorizationUiState state,
            String note);
}
