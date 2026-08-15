package com.visionforge.inferencebenchmark;

/** Validated native control-profile operations required by the output gate. */
interface ControlProfilePort {
    void selectTargetProfile(
            MobileModelCatalog.Profile model, MobileAimTarget aimTarget);

    void setGain(float value);

    void setDeadzone(float value);

    void setMaximumAxisDelta(int value);

    void setSwitchConfirmationMillis(int value);

    void setValues(float gain, float deadzonePixels, int maximumAxisDelta,
                   int switchConfirmationMillis);

    float gain();

    float deadzonePixels();

    int maximumAxisDelta();

    int switchConfirmationMillis();

    void setControlTrigger(ControlTrigger trigger);

    ControlTrigger controlTrigger();

    void setPersonalTrajectoryEnabled(boolean enabled);

    void setPersonalTrajectoryScales(
            float speedScale, float stabilityScale, float variationScale);

    boolean importPersonalTrajectory(String profileJson);

    boolean personalTrajectoryEnabled();

    String personalTrajectoryProfileId();

    float personalTrajectorySpeedScale();

    float personalTrajectoryStabilityScale();

    float personalTrajectoryVariationScale();

    boolean apply(boolean outputEnabled);
}
