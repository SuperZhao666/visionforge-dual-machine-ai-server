package com.visionforge.inferencebenchmark.ui;

import com.visionforge.inferencebenchmark.ControlTrigger;
import com.visionforge.inferencebenchmark.MobileAimTarget;
import com.visionforge.inferencebenchmark.MobileModelCatalog;
import com.visionforge.inferencebenchmark.MobileControlTuning;

import java.util.Locale;

/** Pure mapping boundary from runtime observations to immutable UI state. */
public final class MobileUiStateMapper {
    private static final double EPSILON = 0.0001;

    private MobileUiStateMapper() {
    }

    public static MobileUiState map(Input input) {
        double inferenceTotal = input.inferenceTotalP50Millis >= 0.0
                ? input.inferenceTotalP50Millis : input.qnnP50Millis;
        String processing = sumLatency(input.preprocessP50Millis, inferenceTotal,
                input.decodeQueueP50Millis);
        return new MobileUiState(input, processing, selectedPreset(input));
    }

    private static String sumLatency(double preprocess, double qnn, double queue) {
        if (preprocess < 0.0 || qnn < 0.0 || queue < 0.0) return "--";
        return String.format(Locale.US, "%.2f ms", preprocess + qnn + queue);
    }

    private static ControlPreset selectedPreset(Input input) {
        if (matches(input, ControlPreset.STANDARD)) return ControlPreset.STANDARD;
        if (matches(input, ControlPreset.PRECISE)) return ControlPreset.PRECISE;
        return ControlPreset.CUSTOM;
    }

    private static boolean matches(Input input, ControlPreset preset) {
        MobileControlTuning.Values values = preset.valuesFor(input.activeModel);
        return Math.abs(input.controlGain - values.gain) < EPSILON
                && Math.abs(input.controlDeadzonePixels - values.deadzonePixels) < EPSILON
                && input.maximumAxisDelta == values.maximumAxisDelta
                && input.switchConfirmationMillis ==
                        values.switchConfirmationMillis;
    }

    /** Mutable assembly DTO; confined to one refresh call before mapping. */
    public static final class Input {
        public boolean receiverServiceReady;
        public boolean receiverRunning;
        public boolean videoLinkLive;
        public boolean decoderReady;
        public boolean qnnReady;
        public boolean makcuReady;
        public boolean controlOutputEnabled;
        public boolean controlOutputRecoverySuspended;
        public boolean bluetoothHidOutputRouteActive;
        public boolean bluetoothHidOutputRouteAvailable;
        public boolean bluetoothHidSessionReady;
        public boolean bluetoothHidPermissionGranted;
        public boolean nativePostprocessApplied;
        public DualMachineAuthorizationUiState authorization =
                DualMachineAuthorizationUiState.readyForActivation();
        public String qnnRuntimeLabel = "手机端 AI";
        public String accessUnitFps = "--";
        public String decodedFrameFps = "--";
        public String qnnFps = "--";
        public String preprocessP50 = "--";
        public String qnnP50 = "--";
        public String qnnP95 = "--";
        public String decodeQueueP50 = "--";
        public double preprocessP50Millis = -1.0;
        public double qnnP50Millis = -1.0;
        public double inferenceTotalP50Millis = -1.0;
        public double decodeQueueP50Millis = -1.0;
        public String completedAccessUnits = "--";
        public String renderedFrames = "--";
        public String qnnExecutions = "--";
        public String qnnFailures = "--";
        public MobileModelCatalog.Profile activeModel = MobileModelCatalog.DEFAULT;
        public MobileAimTarget aimTarget = MobileModelCatalog.DEFAULT.defaultAimTarget;
        public float confidence = MobileModelCatalog.DEFAULT.defaultConfidence;
        public float nmsIou = 0.45f;
        public float controlGain = MobileModelCatalog.DEFAULT.defaultControlGain;
        public float controlDeadzonePixels = MobileModelCatalog.DEFAULT.defaultDeadzonePixels;
        public int maximumAxisDelta = 127;
        public int switchConfirmationMillis = 25;
        public int effectiveUncalibratedMaximumAxisDelta = -1;
        public float maximumStepCountsPerTick = -1.0f;
        public float maximumJerkCountsPerTick2 = -1.0f;
        public ControlTrigger controlTrigger = ControlTrigger.SIDE_BUTTON_2;
        public boolean controlTriggerPressed;
        public boolean controlTriggerStreamReady;
        public boolean personalTrajectoryEnabled;
        public String personalTrajectoryProfileId = "";
        public float personalTrajectorySpeedScale = 1.0f;
        public float personalTrajectoryStabilityScale = 1.0f;
        public float personalTrajectoryVariationScale = 1.0f;
        public String note = "";
        public String ethernetDetail = "";
    }
}
