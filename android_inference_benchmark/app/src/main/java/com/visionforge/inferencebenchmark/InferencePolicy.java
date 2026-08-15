package com.visionforge.inferencebenchmark;

/** Immutable, framework-free detector post-process policy. */
final class InferencePolicy {
    static final float DEFAULT_CONFIDENCE = MobileModelCatalog.DEFAULT.defaultConfidence;
    static final float NMS_IOU = MobileModelCatalog.DEFAULT.nmsIou;
    static final float MIN_CONFIDENCE = MobileModelCatalog.DEFAULT.minimumConfidence;
    static final float MAX_CONFIDENCE = MobileModelCatalog.DEFAULT.maximumConfidence;

    private final MobileModelCatalog.Profile profile;
    private final float confidence;

    private InferencePolicy(MobileModelCatalog.Profile profile, float confidence) {
        this.profile = profile == null ? MobileModelCatalog.DEFAULT : profile;
        this.confidence = clamp(confidence, this.profile);
    }

    static InferencePolicy fromStoredConfidence(float confidence) {
        return new InferencePolicy(MobileModelCatalog.DEFAULT, confidence);
    }

    static InferencePolicy forProfile(
            MobileModelCatalog.Profile profile, float confidence) {
        return new InferencePolicy(profile, confidence);
    }

    InferencePolicy withConfidence(float value) {
        return new InferencePolicy(profile, value);
    }

    float confidence() {
        return confidence;
    }

    float nmsIou() {
        return profile.nmsIou;
    }

    private static float clamp(float value, MobileModelCatalog.Profile profile) {
        float clamped = Math.max(profile.minimumConfidence,
                Math.min(profile.maximumConfidence, value));
        // The product exposes hundredth increments. Normalise at the policy
        // boundary so the top visible step reaches the real cap rather than
        // an adjacent binary-float value that merely renders as that cap.
        return Math.round(clamped * 100f) / 100f;
    }
}
