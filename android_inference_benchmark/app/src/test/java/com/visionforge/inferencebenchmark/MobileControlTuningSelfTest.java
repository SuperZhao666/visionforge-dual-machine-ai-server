package com.visionforge.inferencebenchmark;

/** Dependency-free contract for model-specific control presets and migration. */
final class MobileControlTuningSelfTest {
    private MobileControlTuningSelfTest() {}

    static void run() {
        verifiesOverwatchUsesFastTightPresets();
        verifiesOtherModelsKeepTheirStandardDefaults();
        verifiesOnlyExactLegacyOverwatchValuesMigrate();
    }

    private static void verifiesOverwatchUsesFastTightPresets() {
        MobileControlTuning.Values standard =
                MobileControlTuning.standard(MobileModelCatalog.OVERWATCH_2);
        require(standard.gain == 0.60f);
        require(standard.deadzonePixels == 0.5f);
        require(standard.maximumAxisDelta == 127);
        require(standard.switchConfirmationMillis == 45);

        MobileControlTuning.Values precise =
                MobileControlTuning.precise(MobileModelCatalog.OVERWATCH_2);
        require(precise.gain == 0.50f);
        require(precise.deadzonePixels == 0.35f);
        require(precise.maximumAxisDelta == 96);
        require(precise.switchConfirmationMillis == 35);
    }

    private static void verifiesOtherModelsKeepTheirStandardDefaults() {
        MobileControlTuning.Values valorant =
                MobileControlTuning.standard(MobileModelCatalog.VALORANT);
        require(valorant.gain == MobileModelCatalog.VALORANT.defaultControlGain);
        require(valorant.deadzonePixels
                == MobileModelCatalog.VALORANT.defaultDeadzonePixels);
        require(valorant.maximumAxisDelta
                == MobileModelCatalog.VALORANT.defaultMaximumAxisDelta);
        require(valorant.switchConfirmationMillis == 25);
    }

    private static void verifiesOnlyExactLegacyOverwatchValuesMigrate() {
        MobileControlTuning.Values oldDefault =
                MobileControlTuning.migrateLegacyOverwatch(0.36f, 0.5f, 127);
        require(oldDefault.gain == 0.60f && oldDefault.deadzonePixels == 0.5f);

        MobileControlTuning.Values oldStandard =
                MobileControlTuning.migrateLegacyOverwatch(0.10f, 2.0f, 127);
        require(oldStandard.gain == 0.60f && oldStandard.deadzonePixels == 0.5f);

        MobileControlTuning.Values oldPrecise =
                MobileControlTuning.migrateLegacyOverwatch(0.08f, 1.5f, 96);
        require(oldPrecise.gain == 0.50f && oldPrecise.deadzonePixels == 0.35f);

        MobileControlTuning.Values custom =
                MobileControlTuning.migrateLegacyOverwatch(0.37f, 0.7f, 80);
        require(custom.gain == 0.37f && custom.deadzonePixels == 0.7f
                && custom.maximumAxisDelta == 80);
        require(custom.switchConfirmationMillis == 45);
        require(MobileControlTuning.sanitizeSwitchConfirmationMillis(0) == 10);
        require(MobileControlTuning.sanitizeSwitchConfirmationMillis(500) == 100);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Mobile control tuning contract failed");
    }
}
