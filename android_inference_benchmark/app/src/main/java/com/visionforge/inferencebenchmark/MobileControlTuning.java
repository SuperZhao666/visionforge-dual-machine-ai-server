package com.visionforge.inferencebenchmark;

/** Pure per-model control tuning and one-time legacy-value migration policy. */
public final class MobileControlTuning {
    public static final int PERSISTENCE_VERSION = 2;
    public static final int MINIMUM_SWITCH_CONFIRMATION_MILLIS = 10;
    public static final int MAXIMUM_SWITCH_CONFIRMATION_MILLIS = 100;

    private static final float LEGACY_DEFAULT_GAIN = 0.36f;
    private static final float LEGACY_STANDARD_GAIN = 0.10f;
    private static final float LEGACY_STANDARD_DEADZONE = 2.0f;
    private static final int LEGACY_STANDARD_MAXIMUM_DELTA = 127;
    private static final float LEGACY_PRECISE_GAIN = 0.08f;
    private static final float LEGACY_PRECISE_DEADZONE = 1.5f;
    private static final int LEGACY_PRECISE_MAXIMUM_DELTA = 96;

    private static final int DEFAULT_SWITCH_CONFIRMATION_MILLIS = 25;
    private static final Values OVERWATCH_STANDARD =
            new Values(0.60f, 0.5f, 127, 45);
    private static final Values OVERWATCH_PRECISE =
            new Values(0.50f, 0.35f, 96, 35);
    private static final Values DEFAULT_PRECISE =
            new Values(0.30f, 0.35f, 96, 20);

    private MobileControlTuning() {}

    public static Values standard(MobileModelCatalog.Profile model) {
        MobileModelCatalog.Profile selected = model == null
                ? MobileModelCatalog.DEFAULT : model;
        if (selected == MobileModelCatalog.OVERWATCH_2) return OVERWATCH_STANDARD;
        return new Values(selected.defaultControlGain, selected.defaultDeadzonePixels,
                selected.defaultMaximumAxisDelta, DEFAULT_SWITCH_CONFIRMATION_MILLIS);
    }

    public static Values precise(MobileModelCatalog.Profile model) {
        return model == MobileModelCatalog.OVERWATCH_2
                ? OVERWATCH_PRECISE : DEFAULT_PRECISE;
    }

    /** Migrates only exact former defaults/presets; user-authored values are preserved. */
    public static Values migrateLegacyOverwatch(
            float gain, float deadzonePixels, int maximumAxisDelta) {
        if (matches(gain, deadzonePixels, maximumAxisDelta,
                LEGACY_DEFAULT_GAIN, OVERWATCH_STANDARD.deadzonePixels,
                OVERWATCH_STANDARD.maximumAxisDelta)
                || matches(gain, deadzonePixels, maximumAxisDelta,
                LEGACY_STANDARD_GAIN, LEGACY_STANDARD_DEADZONE,
                LEGACY_STANDARD_MAXIMUM_DELTA)) {
            return OVERWATCH_STANDARD;
        }
        if (matches(gain, deadzonePixels, maximumAxisDelta,
                LEGACY_PRECISE_GAIN, LEGACY_PRECISE_DEADZONE,
                LEGACY_PRECISE_MAXIMUM_DELTA)) {
            return OVERWATCH_PRECISE;
        }
        return new Values(gain, deadzonePixels, maximumAxisDelta,
                OVERWATCH_STANDARD.switchConfirmationMillis);
    }

    public static int sanitizeSwitchConfirmationMillis(int value) {
        return Math.max(MINIMUM_SWITCH_CONFIRMATION_MILLIS,
                Math.min(MAXIMUM_SWITCH_CONFIRMATION_MILLIS, value));
    }

    private static boolean matches(
            float gain, float deadzonePixels, int maximumAxisDelta,
            float expectedGain, float expectedDeadzone, int expectedMaximumDelta) {
        return Float.compare(gain, expectedGain) == 0
                && Float.compare(deadzonePixels, expectedDeadzone) == 0
                && maximumAxisDelta == expectedMaximumDelta;
    }

    public static final class Values {
        public final float gain;
        public final float deadzonePixels;
        public final int maximumAxisDelta;
        public final int switchConfirmationMillis;

        private Values(float gain, float deadzonePixels, int maximumAxisDelta,
                       int switchConfirmationMillis) {
            this.gain = gain;
            this.deadzonePixels = deadzonePixels;
            this.maximumAxisDelta = maximumAxisDelta;
            this.switchConfirmationMillis =
                    sanitizeSwitchConfirmationMillis(switchConfirmationMillis);
        }

        public boolean differsFrom(float currentGain, float currentDeadzone, int currentMaximum) {
            return Float.compare(gain, currentGain) != 0
                    || Float.compare(deadzonePixels, currentDeadzone) != 0
                    || maximumAxisDelta != currentMaximum;
        }
    }
}
