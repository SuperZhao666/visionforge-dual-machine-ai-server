package com.visionforge.inferencebenchmark.ui;

import com.visionforge.inferencebenchmark.ControlTrigger;

/** Dependency-free contract for the debug-only UI preview surface. */
public final class UiPreviewStateSelfTest {
    private UiPreviewStateSelfTest() {
    }

    public static void run() {
        previewStateIsDeterministicAndFailClosed();
    }

    private static void previewStateIsDeterministicAndFailClosed() {
        MobileUiState first = UiPreviewState.disconnected();
        MobileUiState second = UiPreviewState.disconnected();
        require(first.equals(second));
        require(first.hashCode() == second.hashCode());
        require(!first.receiverRunning);
        require(!first.videoLinkLive);
        require(!first.decoderReady);
        require(!first.qnnReady);
        require(!first.makcuReady);
        require(!first.controlOutputEnabled);
        require(!first.controlOutputRecoverySuspended);
        require(!first.pipelineRunning());
        // The preview must keep the safe default trigger instead of silently
        // widening into an always-on surface.
        require(first.controlTrigger == ControlTrigger.SIDE_BUTTON_2);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("UI preview state contract failed");
    }
}
