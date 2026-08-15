package com.visionforge.inferencebenchmark.ui;

import com.visionforge.inferencebenchmark.ControlTrigger;
import com.visionforge.inferencebenchmark.MobileAimTarget;
import com.visionforge.inferencebenchmark.MobileModelCatalog;

/** Explicit event contract from presentation views back to the activity owner. */
public interface MobileAppActions {
    void onDestinationSelected(MobileDestination destination);

    void onActivateCard(String cardCode);

    void onResumePendingActivation();

    void onRetryOutputDevice();

    void onSelectMakcuOutputRoute();

    void onSelectBluetoothHidOutputRoute();

    void onSelectGameModel(MobileModelCatalog.Profile model);

    void onSetAimTarget(MobileAimTarget target);

    void onSetInferenceConfidence(float confidence);

    void onSetControlGain(float gain);

    void onSetControlDeadzone(float deadzonePixels);

    void onSetMaximumAxisDelta(int maximumAxisDelta);

    void onSetSwitchConfirmationMillis(int switchConfirmationMillis);

    void onApplyControlPreset(ControlPreset preset);

    void onRestoreControlDefaults();

    void onSetControlTrigger(ControlTrigger trigger);

    void onImportPersonalTrajectory();

    void onSetPersonalTrajectoryEnabled(boolean enabled);

    void onSetPersonalTrajectorySpeed(float speedScale);

    void onSetPersonalTrajectoryStability(float stabilityScale);

    void onSetPersonalTrajectoryVariation(float variationScale);

    void onExportRuntimeLog();
}
