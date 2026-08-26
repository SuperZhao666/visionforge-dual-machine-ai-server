package com.visionforge.inferencebenchmark.ui;

import com.visionforge.inferencebenchmark.ControlTrigger;
import com.visionforge.inferencebenchmark.MobileAimTarget;
import com.visionforge.inferencebenchmark.MobileModelCatalog;

import java.util.Objects;

/** Immutable screen-ready state. Views never parse native diagnostic strings. */
public final class MobileUiState {
    public final boolean receiverServiceReady;
    public final boolean receiverRunning;
    public final boolean videoLinkLive;
    public final boolean decoderReady;
    public final boolean qnnReady;
    public final boolean makcuReady;
    public final boolean controlOutputEnabled;
    public final boolean controlOutputRecoverySuspended;
    public final boolean bluetoothHidOutputRouteActive;
    public final boolean bluetoothHidOutputRouteAvailable;
    public final boolean bluetoothHidSessionReady;
    public final boolean bluetoothHidPermissionGranted;
    public final boolean nativePostprocessApplied;
    public final DualMachineAuthorizationUiState authorization;
    public final String qnnRuntimeLabel;
    public final String accessUnitFps;
    public final String decodedFrameFps;
    public final String qnnFps;
    public final String preprocessP50;
    public final String qnnP50;
    public final String qnnP95;
    public final String decodeQueueP50;
    public final String phoneProcessingP50;
    public final String completedAccessUnits;
    public final String renderedFrames;
    public final String qnnExecutions;
    public final String qnnFailures;
    public final MobileModelCatalog.Profile activeModel;
    public final MobileAimTarget aimTarget;
    public final float confidence;
    public final float nmsIou;
    public final float controlGain;
    public final float controlDeadzonePixels;
    public final int maximumAxisDelta;
    public final int switchConfirmationMillis;
    public final int effectiveUncalibratedMaximumAxisDelta;
    public final float maximumStepCountsPerTick;
    public final float maximumJerkCountsPerTick2;
    public final ControlTrigger controlTrigger;
    public final boolean controlTriggerPressed;
    public final boolean controlTriggerStreamReady;
    public final boolean personalTrajectoryEnabled;
    public final String personalTrajectoryProfileId;
    public final float personalTrajectorySpeedScale;
    public final float personalTrajectoryStabilityScale;
    public final float personalTrajectoryVariationScale;
    public final ControlPreset selectedPreset;
    public final String note;
    public final String ethernetDetail;

    MobileUiState(MobileUiStateMapper.Input input, String phoneProcessingP50,
                  ControlPreset selectedPreset) {
        receiverServiceReady = input.receiverServiceReady;
        receiverRunning = input.receiverRunning;
        videoLinkLive = input.videoLinkLive;
        decoderReady = input.decoderReady;
        qnnReady = input.qnnReady;
        makcuReady = input.makcuReady;
        controlOutputEnabled = input.controlOutputEnabled;
        controlOutputRecoverySuspended = input.controlOutputRecoverySuspended;
        bluetoothHidOutputRouteActive = input.bluetoothHidOutputRouteActive;
        bluetoothHidOutputRouteAvailable = input.bluetoothHidOutputRouteAvailable;
        bluetoothHidSessionReady = input.bluetoothHidSessionReady;
        bluetoothHidPermissionGranted = input.bluetoothHidPermissionGranted;
        nativePostprocessApplied = input.nativePostprocessApplied;
        authorization = input.authorization;
        qnnRuntimeLabel = input.qnnRuntimeLabel;
        accessUnitFps = input.accessUnitFps;
        decodedFrameFps = input.decodedFrameFps;
        qnnFps = input.qnnFps;
        preprocessP50 = input.preprocessP50;
        qnnP50 = input.qnnP50;
        qnnP95 = input.qnnP95;
        decodeQueueP50 = input.decodeQueueP50;
        this.phoneProcessingP50 = phoneProcessingP50;
        completedAccessUnits = input.completedAccessUnits;
        renderedFrames = input.renderedFrames;
        qnnExecutions = input.qnnExecutions;
        qnnFailures = input.qnnFailures;
        activeModel = input.activeModel;
        aimTarget = input.aimTarget;
        confidence = input.confidence;
        nmsIou = input.nmsIou;
        controlGain = input.controlGain;
        controlDeadzonePixels = input.controlDeadzonePixels;
        maximumAxisDelta = input.maximumAxisDelta;
        switchConfirmationMillis = input.switchConfirmationMillis;
        effectiveUncalibratedMaximumAxisDelta =
                input.effectiveUncalibratedMaximumAxisDelta;
        maximumStepCountsPerTick = input.maximumStepCountsPerTick;
        maximumJerkCountsPerTick2 = input.maximumJerkCountsPerTick2;
        controlTrigger = input.controlTrigger;
        controlTriggerPressed = input.controlTriggerPressed;
        controlTriggerStreamReady = input.controlTriggerStreamReady;
        personalTrajectoryEnabled = input.personalTrajectoryEnabled;
        personalTrajectoryProfileId = input.personalTrajectoryProfileId;
        personalTrajectorySpeedScale = input.personalTrajectorySpeedScale;
        personalTrajectoryStabilityScale = input.personalTrajectoryStabilityScale;
        personalTrajectoryVariationScale = input.personalTrajectoryVariationScale;
        this.selectedPreset = selectedPreset;
        note = input.note;
        ethernetDetail = input.ethernetDetail;
    }

    public boolean pipelineRunning() {
        return receiverRunning && videoLinkLive && qnnReady;
    }

    public boolean selectedOutputTransportReady() {
        return bluetoothHidOutputRouteActive ? bluetoothHidSessionReady : makcuReady;
    }

    /**
     * Presentation equality prevents a periodic native-status poll from
     * invalidating the complete view hierarchy when nothing visible changed.
     */
    @Override
    public boolean equals(Object candidate) {
        if (this == candidate) return true;
        if (!(candidate instanceof MobileUiState)) return false;
        MobileUiState other = (MobileUiState) candidate;
        return receiverServiceReady == other.receiverServiceReady
                && receiverRunning == other.receiverRunning
                && videoLinkLive == other.videoLinkLive
                && decoderReady == other.decoderReady
                && qnnReady == other.qnnReady
                && makcuReady == other.makcuReady
                && controlOutputEnabled == other.controlOutputEnabled
                && controlOutputRecoverySuspended == other.controlOutputRecoverySuspended
                && bluetoothHidOutputRouteActive == other.bluetoothHidOutputRouteActive
                && bluetoothHidOutputRouteAvailable == other.bluetoothHidOutputRouteAvailable
                && bluetoothHidSessionReady == other.bluetoothHidSessionReady
                && bluetoothHidPermissionGranted == other.bluetoothHidPermissionGranted
                && nativePostprocessApplied == other.nativePostprocessApplied
                && Objects.equals(authorization, other.authorization)
                && activeModel == other.activeModel
                && aimTarget == other.aimTarget
                && Float.compare(confidence, other.confidence) == 0
                && Float.compare(nmsIou, other.nmsIou) == 0
                && Float.compare(controlGain, other.controlGain) == 0
                && Float.compare(controlDeadzonePixels, other.controlDeadzonePixels) == 0
                && maximumAxisDelta == other.maximumAxisDelta
                && switchConfirmationMillis == other.switchConfirmationMillis
                && effectiveUncalibratedMaximumAxisDelta
                        == other.effectiveUncalibratedMaximumAxisDelta
                && Float.compare(maximumStepCountsPerTick,
                        other.maximumStepCountsPerTick) == 0
                && Float.compare(maximumJerkCountsPerTick2,
                        other.maximumJerkCountsPerTick2) == 0
                && controlTrigger == other.controlTrigger
                && controlTriggerPressed == other.controlTriggerPressed
                && controlTriggerStreamReady == other.controlTriggerStreamReady
                && personalTrajectoryEnabled == other.personalTrajectoryEnabled
                && Float.compare(personalTrajectorySpeedScale,
                        other.personalTrajectorySpeedScale) == 0
                && Float.compare(personalTrajectoryStabilityScale,
                        other.personalTrajectoryStabilityScale) == 0
                && Float.compare(personalTrajectoryVariationScale,
                        other.personalTrajectoryVariationScale) == 0
                && selectedPreset == other.selectedPreset
                && Objects.equals(qnnRuntimeLabel, other.qnnRuntimeLabel)
                && Objects.equals(accessUnitFps, other.accessUnitFps)
                && Objects.equals(decodedFrameFps, other.decodedFrameFps)
                && Objects.equals(qnnFps, other.qnnFps)
                && Objects.equals(preprocessP50, other.preprocessP50)
                && Objects.equals(qnnP50, other.qnnP50)
                && Objects.equals(qnnP95, other.qnnP95)
                && Objects.equals(decodeQueueP50, other.decodeQueueP50)
                && Objects.equals(phoneProcessingP50, other.phoneProcessingP50)
                && Objects.equals(completedAccessUnits, other.completedAccessUnits)
                && Objects.equals(renderedFrames, other.renderedFrames)
                && Objects.equals(qnnExecutions, other.qnnExecutions)
                && Objects.equals(qnnFailures, other.qnnFailures)
                && Objects.equals(personalTrajectoryProfileId,
                        other.personalTrajectoryProfileId)
                && Objects.equals(note, other.note)
                && Objects.equals(ethernetDetail, other.ethernetDetail);
    }

    @Override
    public int hashCode() {
        return Objects.hash(receiverServiceReady, receiverRunning, videoLinkLive,
                decoderReady, qnnReady, makcuReady,
                controlOutputEnabled, controlOutputRecoverySuspended,
                bluetoothHidOutputRouteActive, bluetoothHidOutputRouteAvailable,
                bluetoothHidSessionReady, bluetoothHidPermissionGranted,
                nativePostprocessApplied, qnnRuntimeLabel,
                authorization,
                accessUnitFps, decodedFrameFps, qnnFps, preprocessP50, qnnP50, qnnP95,
                decodeQueueP50, phoneProcessingP50, completedAccessUnits,
                renderedFrames, qnnExecutions, qnnFailures, confidence, nmsIou, controlGain,
                activeModel, aimTarget,
                controlDeadzonePixels, maximumAxisDelta, switchConfirmationMillis,
                effectiveUncalibratedMaximumAxisDelta,
                maximumStepCountsPerTick, maximumJerkCountsPerTick2, controlTrigger,
                controlTriggerPressed, controlTriggerStreamReady,
                personalTrajectoryEnabled, personalTrajectoryProfileId,
                personalTrajectorySpeedScale, personalTrajectoryStabilityScale,
                personalTrajectoryVariationScale, selectedPreset, note, ethernetDetail);
    }
}
