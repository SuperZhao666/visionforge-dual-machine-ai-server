package com.visionforge.inferencebenchmark;

import android.content.Context;
import android.content.SharedPreferences;

/** Persistent, validated parameters for the phone-to-MAKCU control path. */
final class ControlProfile implements ControlProfilePort {
    private static final String LEGACY_GAIN = "gain";
    private static final String LEGACY_DEADZONE = "deadzone";
    private static final String LEGACY_MAXIMUM_DELTA = "maximum_delta";
    private static final float MIN_GAIN = 0.01f;
    private static final float MAX_GAIN = 2.00f;
    private static final float MAX_DEADZONE = 64.0f;
    private static final float MIN_PERSONAL_SCALE = 0.50f;
    private static final float MAX_PERSONAL_SCALE = 1.50f;
    private static final int PERSONAL_MAXIMUM_EXTRA_COUNTS = 2;
    private static final float PERSONAL_MINIMUM_ERROR_PIXELS = 24.0f;

    private final SharedPreferences store;
    private MobileModelCatalog.Profile model;
    private MobileAimTarget aimTarget;
    private float gain;
    private float deadzonePixels;
    private int maximumAxisDelta;
    private int switchConfirmationMillis;
    private ControlTrigger controlTrigger;
    private PersonalTrajectoryProfile personalTrajectory;
    private boolean personalTrajectoryEnabled;
    private float personalSpeedScale;
    private float personalStabilityScale;
    private float personalVariationScale;

    ControlProfile(
            Context context,
            MobileModelCatalog.Profile initialModel,
            MobileAimTarget initialAimTarget) {
        store = context.getSharedPreferences(
                MobileProfileStorageKeys.CONTROL_STORE, Context.MODE_PRIVATE);
        migrateLegacyControlTuning();
        selectTargetProfileInternal(initialModel, initialAimTarget, true);
        String persistedControlTrigger = store.getString(
                MobileProfileStorageKeys.CONTROL_TRIGGER, null);
        controlTrigger = ControlTrigger.fromPersistedStorageToken(persistedControlTrigger);
        if (ControlTrigger.persistedTokenNeedsMigration(persistedControlTrigger)) {
            store.edit().putString(
                    MobileProfileStorageKeys.CONTROL_TRIGGER, controlTrigger.storageToken)
                    .apply();
        }
        personalTrajectory = restorePersonalTrajectory(
                store.getString(MobileProfileStorageKeys.PERSONAL_PROFILE_JSON, ""));
        personalTrajectoryEnabled = personalTrajectory.enabled
                && store.getBoolean(MobileProfileStorageKeys.PERSONAL_ENABLED, false);
        personalSpeedScale = clamp(store.getFloat(
                MobileProfileStorageKeys.PERSONAL_SPEED_SCALE,
                personalTrajectory.recommendedSpeedScale),
                MIN_PERSONAL_SCALE, MAX_PERSONAL_SCALE);
        personalStabilityScale = clamp(store.getFloat(
                MobileProfileStorageKeys.PERSONAL_STABILITY_SCALE,
                personalTrajectory.recommendedStabilityScale),
                MIN_PERSONAL_SCALE, MAX_PERSONAL_SCALE);
        personalVariationScale = clamp(store.getFloat(
                MobileProfileStorageKeys.PERSONAL_VARIATION_SCALE,
                personalTrajectory.recommendedVariationScale),
                MIN_PERSONAL_SCALE, MAX_PERSONAL_SCALE);
    }

    @Override
    public void selectTargetProfile(
            MobileModelCatalog.Profile selectedModel,
            MobileAimTarget selectedAimTarget) {
        selectTargetProfileInternal(selectedModel, selectedAimTarget, false);
        persistModelValues();
    }

    @Override
    public void setGain(float value) { gain = clamp(value, MIN_GAIN, MAX_GAIN); persist(); }

    @Override
    public void setDeadzone(float value) { deadzonePixels = clamp(value, 0.0f, MAX_DEADZONE); persist(); }

    @Override
    public void setMaximumAxisDelta(int value) { maximumAxisDelta = clamp(value, 1, 127); persist(); }

    @Override
    public void setSwitchConfirmationMillis(int value) {
        switchConfirmationMillis = MobileControlTuning.sanitizeSwitchConfirmationMillis(value);
        persist();
    }

    @Override
    public void setValues(float gain, float deadzonePixels, int maximumAxisDelta,
                          int switchConfirmationMillis) {
        this.gain = clamp(gain, MIN_GAIN, MAX_GAIN);
        this.deadzonePixels = clamp(deadzonePixels, 0.0f, MAX_DEADZONE);
        this.maximumAxisDelta = clamp(maximumAxisDelta, 1, 127);
        this.switchConfirmationMillis =
                MobileControlTuning.sanitizeSwitchConfirmationMillis(
                        switchConfirmationMillis);
        persist();
    }

    @Override
    public float gain() { return gain; }

    @Override
    public float deadzonePixels() { return deadzonePixels; }

    @Override
    public int maximumAxisDelta() { return maximumAxisDelta; }

    @Override
    public int switchConfirmationMillis() { return switchConfirmationMillis; }

    @Override
    public void setControlTrigger(ControlTrigger trigger) {
        if (trigger == null) return;
        controlTrigger = trigger;
        persist();
    }

    @Override
    public ControlTrigger controlTrigger() {
        return controlTrigger;
    }

    @Override
    public void setPersonalTrajectoryEnabled(boolean enabled) {
        personalTrajectoryEnabled = enabled && personalTrajectory.enabled;
        persist();
    }

    @Override
    public void setPersonalTrajectoryScales(
            float speedScale, float stabilityScale, float variationScale) {
        personalSpeedScale = clamp(speedScale, MIN_PERSONAL_SCALE, MAX_PERSONAL_SCALE);
        personalStabilityScale = clamp(
                stabilityScale, MIN_PERSONAL_SCALE, MAX_PERSONAL_SCALE);
        personalVariationScale = clamp(
                variationScale, MIN_PERSONAL_SCALE, MAX_PERSONAL_SCALE);
        persist();
    }

    @Override
    public boolean importPersonalTrajectory(String profileJson) {
        PersonalTrajectoryProfile parsed = PersonalTrajectoryProfile.parse(profileJson);
        personalTrajectory = parsed;
        personalTrajectoryEnabled = true;
        personalSpeedScale = parsed.recommendedSpeedScale;
        personalStabilityScale = parsed.recommendedStabilityScale;
        personalVariationScale = parsed.recommendedVariationScale;
        persist();
        return true;
    }

    @Override
    public boolean personalTrajectoryEnabled() {
        return personalTrajectoryEnabled && personalTrajectory.enabled;
    }

    @Override
    public String personalTrajectoryProfileId() {
        return personalTrajectory.profileId;
    }

    @Override
    public float personalTrajectorySpeedScale() {
        return personalSpeedScale;
    }

    @Override
    public float personalTrajectoryStabilityScale() {
        return personalStabilityScale;
    }

    @Override
    public float personalTrajectoryVariationScale() {
        return personalVariationScale;
    }

    @Override
    public boolean apply(boolean outputEnabled) {
        boolean personalEnabled = personalTrajectoryEnabled();
        return QnnHtpBridge.configureNativeMakcuControl(
                gain,
                deadzonePixels,
                maximumAxisDelta,
                switchConfirmationMillis,
                outputEnabled,
                personalEnabled,
                stableSeed(personalTrajectory.profileId),
                personalSpeedScale,
                personalStabilityScale,
                personalVariationScale,
                personalTrajectory.medianMovementDurationMillis,
                personalTrajectory.peakTimeFraction,
                personalTrajectory.bellCorrelation,
                personalTrajectory.jitterAmplitudePixels,
                personalTrajectory.jitterMaximumPixels,
                PERSONAL_MAXIMUM_EXTRA_COUNTS,
                PERSONAL_MINIMUM_ERROR_PIXELS,
                personalTrajectory.speedEnvelope,
                model.token,
                model.bodyClassIdFor(aimTarget),
                model.headClassIdFor(aimTarget),
                model.classIdFor(aimTarget),
                model.usesHeadBox(aimTarget),
                model.usesGeometricHead(aimTarget),
                model.targetYRatio(aimTarget));
    }

    private void persist() {
        store.edit().putFloat(gainKey(model), gain).putFloat(deadzoneKey(model), deadzonePixels)
                .putInt(maximumDeltaKey(model), maximumAxisDelta)
                .putInt(switchConfirmationKey(model), switchConfirmationMillis)
                .putString(MobileProfileStorageKeys.CONTROL_TRIGGER,
                        controlTrigger.storageToken)
                .putString(MobileProfileStorageKeys.PERSONAL_PROFILE_JSON,
                        personalTrajectory.sourceJson)
                .putBoolean(MobileProfileStorageKeys.PERSONAL_ENABLED,
                        personalTrajectoryEnabled)
                .putFloat(MobileProfileStorageKeys.PERSONAL_SPEED_SCALE,
                        personalSpeedScale)
                .putFloat(MobileProfileStorageKeys.PERSONAL_STABILITY_SCALE,
                        personalStabilityScale)
                .putFloat(MobileProfileStorageKeys.PERSONAL_VARIATION_SCALE,
                        personalVariationScale)
                .apply();
    }

    private void persistModelValues() {
        store.edit()
                .putFloat(gainKey(model), gain)
                .putFloat(deadzoneKey(model), deadzonePixels)
                .putInt(maximumDeltaKey(model), maximumAxisDelta)
                .putInt(switchConfirmationKey(model), switchConfirmationMillis)
                .apply();
    }

    private void migrateLegacyControlTuning() {
        if (store.getInt(MobileProfileStorageKeys.CONTROL_TUNING_VERSION, 0)
                >= MobileControlTuning.PERSISTENCE_VERSION) {
            return;
        }
        MobileModelCatalog.Profile overwatch = MobileModelCatalog.OVERWATCH_2;
        String gainKey = gainKey(overwatch);
        String deadzoneKey = deadzoneKey(overwatch);
        String maximumKey = maximumDeltaKey(overwatch);
        String switchConfirmationKey = switchConfirmationKey(overwatch);
        android.content.SharedPreferences.Editor editor = store.edit().putInt(
                MobileProfileStorageKeys.CONTROL_TUNING_VERSION,
                MobileControlTuning.PERSISTENCE_VERSION);
        if (store.contains(gainKey) && store.contains(deadzoneKey)
                && store.contains(maximumKey)) {
            float currentGain = store.getFloat(gainKey, overwatch.defaultControlGain);
            float currentDeadzone = store.getFloat(
                    deadzoneKey, overwatch.defaultDeadzonePixels);
            int currentMaximum = store.getInt(
                    maximumKey, overwatch.defaultMaximumAxisDelta);
            MobileControlTuning.Values migrated =
                    MobileControlTuning.migrateLegacyOverwatch(
                            currentGain, currentDeadzone, currentMaximum);
            if (migrated.differsFrom(currentGain, currentDeadzone, currentMaximum)) {
                editor.putFloat(gainKey, migrated.gain)
                        .putFloat(deadzoneKey, migrated.deadzonePixels)
                        .putInt(maximumKey, migrated.maximumAxisDelta);
            }
            if (!store.contains(switchConfirmationKey)) {
                editor.putInt(switchConfirmationKey,
                        migrated.switchConfirmationMillis);
            }
        }
        editor.apply();
    }

    private void selectTargetProfileInternal(
            MobileModelCatalog.Profile selectedModel,
            MobileAimTarget selectedAimTarget,
            boolean allowLegacyValorantFallback) {
        model = selectedModel == null ? MobileModelCatalog.DEFAULT : selectedModel;
        aimTarget = model.supports(selectedAimTarget)
                ? selectedAimTarget : model.defaultAimTarget;
        float gainFallback = model.defaultControlGain;
        float deadzoneFallback = model.defaultDeadzonePixels;
        int maximumFallback = model.defaultMaximumAxisDelta;
        int switchConfirmationFallback =
                MobileControlTuning.standard(model).switchConfirmationMillis;
        if (allowLegacyValorantFallback && model == MobileModelCatalog.VALORANT) {
            gainFallback = store.getFloat(LEGACY_GAIN, gainFallback);
            deadzoneFallback = store.getFloat(LEGACY_DEADZONE, deadzoneFallback);
            maximumFallback = store.getInt(LEGACY_MAXIMUM_DELTA, maximumFallback);
        }
        gain = clamp(store.getFloat(gainKey(model), gainFallback), MIN_GAIN, MAX_GAIN);
        deadzonePixels = clamp(store.getFloat(deadzoneKey(model), deadzoneFallback),
                0.0f, MAX_DEADZONE);
        maximumAxisDelta = clamp(store.getInt(maximumDeltaKey(model), maximumFallback), 1, 127);
        switchConfirmationMillis = MobileControlTuning.sanitizeSwitchConfirmationMillis(
                store.getInt(switchConfirmationKey(model), switchConfirmationFallback));
    }

    private static String gainKey(MobileModelCatalog.Profile profile) {
        return MobileProfileStorageKeys.controlGain(profile);
    }

    private static String deadzoneKey(MobileModelCatalog.Profile profile) {
        return MobileProfileStorageKeys.controlDeadzone(profile);
    }

    private static String maximumDeltaKey(MobileModelCatalog.Profile profile) {
        return MobileProfileStorageKeys.controlMaximumDelta(profile);
    }

    private static String switchConfirmationKey(MobileModelCatalog.Profile profile) {
        return MobileProfileStorageKeys.controlSwitchConfirmation(profile);
    }

    private static PersonalTrajectoryProfile restorePersonalTrajectory(String profileJson) {
        if (profileJson == null || profileJson.isBlank()) {
            return PersonalTrajectoryProfile.disabled();
        }
        try {
            return PersonalTrajectoryProfile.parse(profileJson);
        } catch (IllegalArgumentException ignored) {
            return PersonalTrajectoryProfile.disabled();
        }
    }

    private static long stableSeed(String value) {
        if (value == null || value.isEmpty()) return 0L;
        long hash = 0xcbf29ce484222325L;
        for (int index = 0; index < value.length(); index++) {
            hash ^= value.charAt(index);
            hash *= 0x100000001b3L;
        }
        return hash;
    }

    private static float clamp(float value, float minimum, float maximum) {
        return Math.max(minimum, Math.min(maximum, value));
    }

    private static int clamp(int value, int minimum, int maximum) {
        return Math.max(minimum, Math.min(maximum, value));
    }
}
