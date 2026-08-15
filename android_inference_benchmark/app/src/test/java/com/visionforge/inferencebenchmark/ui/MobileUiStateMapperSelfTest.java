package com.visionforge.inferencebenchmark.ui;

/** Dependency-free regression coverage for presentation derivation. */
public final class MobileUiStateMapperSelfTest {
    private MobileUiStateMapperSelfTest() {
    }

    public static void run() {
        verifiesLatencyAndObservedRateRemainDistinct();
        verifiesPresetRecognitionUsesAllValues();
        verifiesPresentationEqualityTracksVisibleChanges();
        verifiesModelAndAimTargetAreVisibleState();
        verifiesSelectedOutputReadinessFollowsRoute();
        verifiesEffectiveMotionLimitsAreVisibleState();
    }

    private static void verifiesLatencyAndObservedRateRemainDistinct() {
        MobileUiStateMapper.Input input = new MobileUiStateMapper.Input();
        input.preprocessP50Millis = 1.20;
        input.qnnP50Millis = 2.00;
        input.decodeQueueP50Millis = 3.30;
        input.accessUnitFps = "148.0 FPS";
        input.qnnFps = "61.5 FPS";
        MobileUiState state = MobileUiStateMapper.map(input);

        require("6.50 ms".equals(state.phoneProcessingP50));
        require("61.5 FPS".equals(state.qnnFps));
        require("148.0 FPS".equals(state.accessUnitFps));
    }

    private static void verifiesPresetRecognitionUsesAllValues() {
        MobileUiStateMapper.Input input = new MobileUiStateMapper.Input();
        MobileUiState standard = MobileUiStateMapper.map(input);
        require(standard.selectedPreset == ControlPreset.STANDARD);
        input.switchConfirmationMillis++;
        require(MobileUiStateMapper.map(input).selectedPreset == ControlPreset.CUSTOM);
        input.switchConfirmationMillis =
                ControlPreset.STANDARD.switchConfirmationMillis;
        input.maximumAxisDelta = 126;
        require(MobileUiStateMapper.map(input).selectedPreset == ControlPreset.CUSTOM);
        input.controlGain = ControlPreset.PRECISE.gain;
        input.controlDeadzonePixels = ControlPreset.PRECISE.deadzonePixels;
        input.maximumAxisDelta = ControlPreset.PRECISE.maximumAxisDelta;
        input.switchConfirmationMillis =
                ControlPreset.PRECISE.switchConfirmationMillis;
        input.confidence = ControlPreset.PRECISE.confidence;
        require(MobileUiStateMapper.map(input).selectedPreset == ControlPreset.PRECISE);

        input.activeModel =
                com.visionforge.inferencebenchmark.MobileModelCatalog.OVERWATCH_2;
        com.visionforge.inferencebenchmark.MobileControlTuning.Values overwatch =
                ControlPreset.STANDARD.valuesFor(input.activeModel);
        input.controlGain = overwatch.gain;
        input.controlDeadzonePixels = overwatch.deadzonePixels;
        input.maximumAxisDelta = overwatch.maximumAxisDelta;
        input.switchConfirmationMillis = overwatch.switchConfirmationMillis;
        require(MobileUiStateMapper.map(input).selectedPreset == ControlPreset.STANDARD);
    }

    private static void verifiesPresentationEqualityTracksVisibleChanges() {
        MobileUiStateMapper.Input input = new MobileUiStateMapper.Input();
        MobileUiState first = MobileUiStateMapper.map(input);
        MobileUiState same = MobileUiStateMapper.map(input);
        require(first.equals(same));
        require(first.hashCode() == same.hashCode());

        input.qnnFps = "149.2 FPS";
        require(!first.equals(MobileUiStateMapper.map(input)));

        input.qnnFps = first.qnnFps;
        input.controlOutputEnabled = true;
        require(!first.equals(MobileUiStateMapper.map(input)));

        input.controlOutputEnabled = false;
        input.controlOutputRecoverySuspended = true;
        require(!first.equals(MobileUiStateMapper.map(input)));

        input.controlOutputRecoverySuspended = false;
        input.bluetoothHidOutputRouteAvailable = true;
        require(!first.equals(MobileUiStateMapper.map(input)));

        input.bluetoothHidOutputRouteAvailable = false;
        input.bluetoothHidSessionReady = true;
        require(!first.equals(MobileUiStateMapper.map(input)));

        input.bluetoothHidSessionReady = false;
        input.bluetoothHidPermissionGranted = true;
        require(!first.equals(MobileUiStateMapper.map(input)));

        input.bluetoothHidPermissionGranted = false;
        input.bluetoothHidOutputRouteActive = true;
        require(!first.equals(MobileUiStateMapper.map(input)));

        input.bluetoothHidOutputRouteActive = false;
        input.ethernetDetail = "eth0 has no IPv4";
        require(!first.equals(MobileUiStateMapper.map(input)));

        input.ethernetDetail = first.ethernetDetail;
        input.receiverServiceReady = true;
        require(!first.equals(MobileUiStateMapper.map(input)));

        input.receiverServiceReady = false;
        input.switchConfirmationMillis++;
        require(!first.equals(MobileUiStateMapper.map(input)));

    }

    private static void verifiesModelAndAimTargetAreVisibleState() {
        MobileUiStateMapper.Input input = new MobileUiStateMapper.Input();
        MobileUiState valorant = MobileUiStateMapper.map(input);
        require(valorant.activeModel
                == com.visionforge.inferencebenchmark.MobileModelCatalog.VALORANT);
        require(valorant.aimTarget == com.visionforge.inferencebenchmark.MobileAimTarget.HEAD);

        input.activeModel = com.visionforge.inferencebenchmark.MobileModelCatalog.OVERWATCH_2;
        input.aimTarget = com.visionforge.inferencebenchmark.MobileAimTarget.BODY;
        MobileUiState ow2 = MobileUiStateMapper.map(input);
        require(!valorant.equals(ow2));
        require(ow2.activeModel
                == com.visionforge.inferencebenchmark.MobileModelCatalog.OVERWATCH_2);
        require(ow2.aimTarget == com.visionforge.inferencebenchmark.MobileAimTarget.BODY);

        input.activeModel = com.visionforge.inferencebenchmark.MobileModelCatalog.DELTA_FORCE;
        input.aimTarget = com.visionforge.inferencebenchmark.MobileAimTarget.CROSSHAIR;
        MobileUiState delta = MobileUiStateMapper.map(input);
        require(!ow2.equals(delta));
        require(delta.activeModel
                == com.visionforge.inferencebenchmark.MobileModelCatalog.DELTA_FORCE);
        require(delta.aimTarget == com.visionforge.inferencebenchmark.MobileAimTarget.CROSSHAIR);
    }

    private static void verifiesSelectedOutputReadinessFollowsRoute() {
        MobileUiStateMapper.Input input = new MobileUiStateMapper.Input();
        input.makcuReady = true;
        MobileUiState makcu = MobileUiStateMapper.map(input);
        require(makcu.selectedOutputTransportReady());

        input.bluetoothHidOutputRouteActive = true;
        MobileUiState disconnectedBluetooth = MobileUiStateMapper.map(input);
        require(!disconnectedBluetooth.selectedOutputTransportReady());

        input.bluetoothHidSessionReady = true;
        MobileUiState connectedBluetooth = MobileUiStateMapper.map(input);
        require(connectedBluetooth.selectedOutputTransportReady());
    }

    private static void verifiesEffectiveMotionLimitsAreVisibleState() {
        MobileUiStateMapper.Input input = new MobileUiStateMapper.Input();
        input.effectiveUncalibratedMaximumAxisDelta = 32;
        input.maximumStepCountsPerTick = 24.0f;
        input.maximumJerkCountsPerTick2 = 12.0f;
        MobileUiState state = MobileUiStateMapper.map(input);
        require(state.effectiveUncalibratedMaximumAxisDelta == 32);
        require(Float.compare(state.maximumStepCountsPerTick, 24.0f) == 0);
        require(Float.compare(state.maximumJerkCountsPerTick2, 12.0f) == 0);

        input.maximumStepCountsPerTick = 20.0f;
        require(!state.equals(MobileUiStateMapper.map(input)));
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Mobile UI state mapping contract failed");
    }
}
