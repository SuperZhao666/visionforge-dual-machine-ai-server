package com.visionforge.inferencebenchmark.ui;

import com.visionforge.inferencebenchmark.MobileModelCatalog;
import com.visionforge.inferencebenchmark.MobileControlTuning;

/** User-visible control presets; selecting one applies its complete values. */
public enum ControlPreset {
    STANDARD(0.36f, 0.5f, 127, 25, MobileModelCatalog.DEFAULT.defaultConfidence),
    PRECISE(0.30f, 0.35f, 96, 20, MobileModelCatalog.DEFAULT.defaultConfidence),
    CUSTOM(Float.NaN, Float.NaN, -1, -1, Float.NaN);

    public final float gain;
    public final float deadzonePixels;
    public final int maximumAxisDelta;
    public final int switchConfirmationMillis;
    public final float confidence;

    ControlPreset(float gain, float deadzonePixels, int maximumAxisDelta,
                  int switchConfirmationMillis, float confidence) {
        this.gain = gain;
        this.deadzonePixels = deadzonePixels;
        this.maximumAxisDelta = maximumAxisDelta;
        this.switchConfirmationMillis = switchConfirmationMillis;
        this.confidence = confidence;
    }

    public boolean hasValues() {
        return this != CUSTOM;
    }

    public MobileControlTuning.Values valuesFor(MobileModelCatalog.Profile model) {
        if (this == STANDARD) return MobileControlTuning.standard(model);
        if (this == PRECISE) return MobileControlTuning.precise(model);
        throw new IllegalStateException("custom preset has no fixed values");
    }
}
