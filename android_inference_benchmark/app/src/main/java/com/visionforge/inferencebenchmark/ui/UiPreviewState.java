package com.visionforge.inferencebenchmark.ui;

import com.visionforge.inferencebenchmark.ControlTrigger;

/**
 * Debug-only, side-effect-free UI preview state factory.
 *
 * <p>The preview surface lets a debuggable build render the formal UI on a
 * device for visual inspection without starting the foreground service, AI,
 * MediaCodec, UDP, USB or any wakelock. Every value is constructed here in
 * the pure UI layer; no runtime observation is ever read and no hardware is
 * touched. Release builds never enter this path.</p>
 */
public final class UiPreviewState {
    private UiPreviewState() {
    }

    /**
     * Representative idle surface: receiver stopped, every stage waiting and
     * the automatic control gate fail-closed. Mirrors the accepted
     * first-launch device evidence so preview captures stay comparable with
     * the design QA baseline.
     */
    public static MobileUiState disconnected() {
        MobileUiStateMapper.Input input = new MobileUiStateMapper.Input();
        input.qnnRuntimeLabel = "手机端 AI";
        input.accessUnitFps = "0.0 FPS";
        input.decodedFrameFps = "0.0 FPS";
        input.qnnFps = "0.0 FPS";
        input.completedAccessUnits = "0";
        input.renderedFrames = "0";
        input.qnnExecutions = "0";
        input.qnnFailures = "0";
        input.controlTrigger = ControlTrigger.SIDE_BUTTON_2;
        return MobileUiStateMapper.map(input);
    }
}
