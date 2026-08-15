package com.visionforge.inferencebenchmark;

/** Shared persistent-key contract for per-model inference and control settings. */
final class MobileProfileStorageKeys {
    static final String CONTROL_STORE = "visionforge_control_profile";
    static final String INFERENCE_STORE = "visionforge_inference_profile";
    static final String ACTIVE_MODEL = "active_model";
    static final String CONTROL_TRIGGER = "control_trigger";
    static final String PERSONAL_PROFILE_JSON = "personal_profile_json";
    static final String PERSONAL_ENABLED = "personal_enabled";
    static final String PERSONAL_SPEED_SCALE = "personal_speed_scale";
    static final String PERSONAL_STABILITY_SCALE = "personal_stability_scale";
    static final String PERSONAL_VARIATION_SCALE = "personal_variation_scale";
    static final String CONTROL_TUNING_VERSION = "control_tuning_version";

    private static final String GAIN_PREFIX = "gain.";
    private static final String DEADZONE_PREFIX = "deadzone.";
    private static final String MAXIMUM_DELTA_PREFIX = "maximum_delta.";
    private static final String SWITCH_CONFIRMATION_PREFIX = "switch_confirmation_ms.";
    private static final String CONFIDENCE_PREFIX = "confidence.";
    private static final String AIM_TARGET_PREFIX = "aim_target.";

    private MobileProfileStorageKeys() {
    }

    static String controlGain(MobileModelCatalog.Profile profile) {
        return GAIN_PREFIX + profile.token;
    }

    static String controlDeadzone(MobileModelCatalog.Profile profile) {
        return DEADZONE_PREFIX + profile.token;
    }

    static String controlMaximumDelta(MobileModelCatalog.Profile profile) {
        return MAXIMUM_DELTA_PREFIX + profile.token;
    }

    static String controlSwitchConfirmation(MobileModelCatalog.Profile profile) {
        return SWITCH_CONFIRMATION_PREFIX + profile.token;
    }

    static String inferenceConfidence(MobileModelCatalog.Profile profile) {
        return CONFIDENCE_PREFIX + profile.token;
    }

    static String inferenceAimTarget(MobileModelCatalog.Profile profile) {
        return AIM_TARGET_PREFIX + profile.token;
    }
}
