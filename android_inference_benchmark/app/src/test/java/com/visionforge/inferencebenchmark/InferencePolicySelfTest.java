package com.visionforge.inferencebenchmark;

/** Regression coverage for the detector policy independent of Android or JNI. */
public final class InferencePolicySelfTest {
    private InferencePolicySelfTest() {
    }

    static void run() {
        require(InferencePolicy.fromStoredConfidence(0.27f).confidence() == 0.27f);
        require(InferencePolicy.fromStoredConfidence(-1f).confidence() == InferencePolicy.MIN_CONFIDENCE);
        require(InferencePolicy.fromStoredConfidence(2f).confidence() == InferencePolicy.MAX_CONFIDENCE);
        require(InferencePolicy.fromStoredConfidence(0.27f).withConfidence(1f).confidence()
                == InferencePolicy.MAX_CONFIDENCE);
        require(InferencePolicy.fromStoredConfidence(0.25f).withConfidence(-1f).confidence()
                == InferencePolicy.MIN_CONFIDENCE);
        require(InferencePolicy.fromStoredConfidence(0.5f).withConfidence(0.27f).confidence() == 0.27f);
        require(InferencePolicy.fromStoredConfidence(0.5f).nmsIou() == 0.45f);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Inference policy contract failed");
    }
}
