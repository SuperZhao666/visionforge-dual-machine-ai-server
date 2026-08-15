package com.visionforge.inferencebenchmark;

import java.util.HashSet;
import java.util.Set;

/** Regression coverage for per-game/per-model persisted tuning keys. */
final class MobileProfileStorageKeysSelfTest {
    private MobileProfileStorageKeysSelfTest() {
    }

    static void run() {
        verifiesKnownStoreNamesRemainStable();
        verifiesEveryModelHasIndependentControlKeys();
        verifiesEveryModelHasIndependentInferenceKeys();
    }

    private static void verifiesKnownStoreNamesRemainStable() {
        require("visionforge_control_profile".equals(MobileProfileStorageKeys.CONTROL_STORE));
        require("visionforge_inference_profile".equals(MobileProfileStorageKeys.INFERENCE_STORE));
        require("active_model".equals(MobileProfileStorageKeys.ACTIVE_MODEL));
        require("control_trigger".equals(MobileProfileStorageKeys.CONTROL_TRIGGER));
    }

    private static void verifiesEveryModelHasIndependentControlKeys() {
        Set<String> keys = new HashSet<>();
        for (MobileModelCatalog.Profile model : MobileModelCatalog.ALL) {
            require(keys.add(MobileProfileStorageKeys.controlGain(model)));
            require(keys.add(MobileProfileStorageKeys.controlDeadzone(model)));
            require(keys.add(MobileProfileStorageKeys.controlMaximumDelta(model)));
            require(MobileProfileStorageKeys.controlGain(model).equals("gain." + model.token));
            require(MobileProfileStorageKeys.controlDeadzone(model)
                    .equals("deadzone." + model.token));
            require(MobileProfileStorageKeys.controlMaximumDelta(model)
                    .equals("maximum_delta." + model.token));
        }
        require(keys.size() == MobileModelCatalog.ALL.length * 3);
    }

    private static void verifiesEveryModelHasIndependentInferenceKeys() {
        Set<String> keys = new HashSet<>();
        for (MobileModelCatalog.Profile model : MobileModelCatalog.ALL) {
            require(keys.add(MobileProfileStorageKeys.inferenceConfidence(model)));
            require(keys.add(MobileProfileStorageKeys.inferenceAimTarget(model)));
            require(MobileProfileStorageKeys.inferenceConfidence(model)
                    .equals("confidence." + model.token));
            require(MobileProfileStorageKeys.inferenceAimTarget(model)
                    .equals("aim_target." + model.token));
        }
        require(keys.size() == MobileModelCatalog.ALL.length * 2);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Mobile profile storage key contract failed");
    }
}
