package com.visionforge.inferencebenchmark;

/** Deterministic vendor, generation and backend-routing simulation matrix. */
final class MobileSocCompatibilityPolicySelfTest {
    private static final int ALIAS_BOUNDARY_STRESS_VARIANTS = 4_096;

    private MobileSocCompatibilityPolicySelfTest() {}

    static void run() {
        verifiesSnapdragonGenerations();
        verifiesDimensityGenerations();
        verifiesKirinGenerations();
        verifiesMarketingSocNames();
        verifiesTensorMarketingGenerations();
        verifiesOtherAndroidFamiliesAndEmulator();
        verifiesStrongSocTokensOutrankConflictingPlatformAliases();
        verifiesPlatformAliasBoundariesCannotPromoteQnn();
        verifiesNullEvidenceRemainsPortableAndProbeDriven();
        unknownHardwareRemainsRuntimeProbeOnly();
    }

    private static void verifiesSnapdragonGenerations() {
        assertProfile(
                "MSM8998", "Qualcomm", "msm8998",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.LEGACY_2018_AND_EARLIER,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "MSM8998", "none");
        assertProfile(
                "unknown", "Qualcomm", "APQ8096",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.LEGACY_2018_AND_EARLIER,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "APQ8096", "none");
        assertProfile(
                "Qualcomm SDM845", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.LEGACY_2018_AND_EARLIER,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "SDM845", "none");
        assertProfile(
                "Qualcomm SM8250", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2019_2021,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "SM8250", "none");
        assertProfile(
                "Qualcomm SM8350", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2019_2021,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "SM8350", "v68");
        assertProfile(
                "Qualcomm SM8350P", "QTI", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2019_2021,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "SM8350", "v68");
        assertProfile(
                "QCM6490", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2019_2021,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "QCM6490", "v68");
        assertProfile(
                "SM8650-AC", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "SM8650", "v75");
        assertProfile(
                "SM8850", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "SM8850", "v81");
        assertSnapdragonPlatform(
                "lahaina", MobileSocCompatibilityPolicy.Era.GENERATION_2019_2021,
                "SM8350", "v68");
        assertSnapdragonPlatform(
                "taro", MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                "SM8450", "v69");
        assertSnapdragonPlatform(
                "waipio", MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                "SM8450", "v69");
        assertSnapdragonPlatform(
                "cape", MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                "SM8475", "v69");
        assertSnapdragonPlatform(
                "kalama", MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                "SM8550", "v73");
        assertSnapdragonPlatform(
                "pineapple", MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                "SM8650", "v75");
        assertSnapdragonPlatform(
                "sun", MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                "SM8750", "v79");
        assertProfile(
                "qcom", "Samsung", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.UNKNOWN,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "unknown-snapdragon", "none");
        assertProfile(
                "unknown", "QTI", "unknown",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.UNKNOWN,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "unknown-snapdragon", "none");
    }

    private static void verifiesDimensityGenerations() {
        assertPortable(
                "MT6797",
                MobileSocCompatibilityPolicy.Era.LEGACY_2018_AND_EARLIER,
                "MT6797");
        assertPortable(
                "MT6873",
                MobileSocCompatibilityPolicy.Era.GENERATION_2019_2021,
                "MT6873");
        assertPortable(
                "MT6893Z/CZA",
                MobileSocCompatibilityPolicy.Era.GENERATION_2019_2021,
                "MT6893");
        assertPortable(
                "MediaTek MT6989W/CZA",
                MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                "MT6989");
        assertPortable(
                "Dimensity MT6991Z/TCZA",
                MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                "MT6991");
        assertProfile(
                "unknown", "MTK", "unknown",
                MobileSocCompatibilityPolicy.Family.DIMENSITY,
                MobileSocCompatibilityPolicy.Era.UNKNOWN,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "unknown-dimensity", "none");
    }

    private static void verifiesKirinGenerations() {
        assertKirin(
                "Kirin 970", MobileSocCompatibilityPolicy.Era.LEGACY_2018_AND_EARLIER,
                "KIRIN970");
        assertKirin(
                "Kirin 980", MobileSocCompatibilityPolicy.Era.LEGACY_2018_AND_EARLIER,
                "KIRIN980");
        assertKirin(
                "Kirin 990", MobileSocCompatibilityPolicy.Era.GENERATION_2019_2021,
                "KIRIN990");
        assertKirin(
                "Kirin 710A", MobileSocCompatibilityPolicy.Era.GENERATION_2019_2021,
                "KIRIN710A");
        assertKirin(
                "Kirin 9000E", MobileSocCompatibilityPolicy.Era.GENERATION_2019_2021,
                "KIRIN9000E");
        assertKirin(
                "Kirin 9000S", MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                "KIRIN9000S");
        assertKirin(
                "Kirin 9020", MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                "KIRIN9020");
        assertKirin(
                "Kirin 9000S1", MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                "KIRIN9000S1");
    }

    private static void verifiesMarketingSocNames() {
        assertProfile(
                "Qualcomm Snapdragon 888+ Mobile Platform", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2019_2021,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "SM8350", "v68");
        assertProfile(
                "Snapdragon 8 Gen 1", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "SM8450", "v69");
        assertProfile(
                "Snapdragon 8+ Gen 1", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "SM8475", "v69");
        assertProfile(
                "Snapdragon 8 Gen 2", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "SM8550", "v73");
        assertProfile(
                "Snapdragon 8 Gen 3 Mobile Platform", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "SM8650", "v75");
        assertProfile(
                "Snapdragon 8 Elite", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "SM8750", "v79");
        assertProfile(
                "Snapdragon 8 Elite Gen 5", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "SM8850", "v81");
        String[][] dimensityModels = {
                {"9000", "MT6983", "GENERATION_2019_2021"},
                {"9200", "MT6985", "GENERATION_2022_2023"},
                {"9300", "MT6989", "GENERATION_2022_2023"},
                {"9400+", "MT6991", "GENERATION_2024_PLUS"},
                {"9500", "MT6993", "GENERATION_2024_PLUS"}
        };
        for (String[] model : dimensityModels) {
            assertProfile(
                    "MediaTek Dimensity " + model[0], "MediaTek", "mtk",
                    MobileSocCompatibilityPolicy.Family.DIMENSITY,
                    MobileSocCompatibilityPolicy.Era.valueOf(model[2]),
                    MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                    model[1], "none");
        }

        assertProfile(
                "Snapdragon 8s Gen 3", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.UNKNOWN,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "unknown-snapdragon", "none");
        assertProfile(
                "Snapdragon 8 Elite Gen 6", "Qualcomm", "qcom",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.UNKNOWN,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "unknown-snapdragon", "none");
    }

    private static void verifiesTensorMarketingGenerations() {
        String[][] generations = {
                {"1", "GS101", "GENERATION_2019_2021"},
                {"2", "GS201", "GENERATION_2022_2023"},
                {"3", "GS301", "GENERATION_2022_2023"},
                {"4", "GS401", "GENERATION_2024_PLUS"},
                {"5", "GS501", "GENERATION_2024_PLUS"}
        };
        for (String[] generation : generations) {
            assertProfile(
                    "Tensor G" + generation[0], "Google", "unknown",
                    MobileSocCompatibilityPolicy.Family.TENSOR,
                    MobileSocCompatibilityPolicy.Era.valueOf(generation[2]),
                    MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                    generation[1], "none");
            assertProfile(
                    "Google Tensor G" + generation[0], "Google", "unknown",
                    MobileSocCompatibilityPolicy.Family.TENSOR,
                    MobileSocCompatibilityPolicy.Era.valueOf(generation[2]),
                    MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                    generation[1], "none");
        }
    }

    private static void verifiesOtherAndroidFamiliesAndEmulator() {
        assertProfile(
                "Exynos 2400", "Samsung", "s5e9945",
                MobileSocCompatibilityPolicy.Family.EXYNOS,
                MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "EXYNOS2400", "none");
        assertProfile(
                "unknown", "Samsung", "s5e9945",
                MobileSocCompatibilityPolicy.Family.EXYNOS,
                MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "S5E9945", "none");
        assertProfile(
                "Exynos 1380", "Samsung", "s5e8835",
                MobileSocCompatibilityPolicy.Family.EXYNOS,
                MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "EXYNOS1380", "none");
        assertProfile(
                "Exynos 1480", "Samsung", "s5e8845",
                MobileSocCompatibilityPolicy.Family.EXYNOS,
                MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "EXYNOS1480", "none");
        assertProfile(
                "Google Tensor G4", "Google", "gs401",
                MobileSocCompatibilityPolicy.Family.TENSOR,
                MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "GS401", "none");
        assertProfile(
                "unknown", "Google", "ranchu",
                MobileSocCompatibilityPolicy.Family.ANDROID_EMULATOR,
                MobileSocCompatibilityPolicy.Era.UNKNOWN,
                MobileSocCompatibilityPolicy.RequiredBackend.EMULATOR_REFERENCE,
                "android-emulator", "none");
        assertProfile(
                "unknown", "Samsung", "universal-future",
                MobileSocCompatibilityPolicy.Family.UNKNOWN,
                MobileSocCompatibilityPolicy.Era.UNKNOWN,
                MobileSocCompatibilityPolicy.RequiredBackend.RUNTIME_PROBE,
                "unknown", "none");
        assertProfile(
                "unknown", "Samsung", "samsung",
                MobileSocCompatibilityPolicy.Family.UNKNOWN,
                MobileSocCompatibilityPolicy.Era.UNKNOWN,
                MobileSocCompatibilityPolicy.RequiredBackend.RUNTIME_PROBE,
                "unknown", "none");
    }

    private static void unknownHardwareRemainsRuntimeProbeOnly() {
        assertProfile(
                "future-soc", "future-vendor", "future-hardware",
                MobileSocCompatibilityPolicy.Family.UNKNOWN,
                MobileSocCompatibilityPolicy.Era.UNKNOWN,
                MobileSocCompatibilityPolicy.RequiredBackend.RUNTIME_PROBE,
                "unknown", "none");
    }

    private static void verifiesStrongSocTokensOutrankConflictingPlatformAliases() {
        assertProfile(
                "MT6989", "MediaTek", "pineapple",
                MobileSocCompatibilityPolicy.Family.DIMENSITY,
                MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "MT6989", "none");
        assertProfile(
                "Kirin 9010", "HiSilicon", "kalama",
                MobileSocCompatibilityPolicy.Family.KIRIN,
                MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "KIRIN9010", "none");
        assertProfile(
                "Exynos 2400", "Samsung", "sun",
                MobileSocCompatibilityPolicy.Family.EXYNOS,
                MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "EXYNOS2400", "none");
        assertProfile(
                "GS401", "Google", "pineapple",
                MobileSocCompatibilityPolicy.Family.TENSOR,
                MobileSocCompatibilityPolicy.Era.GENERATION_2024_PLUS,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "GS401", "none");
        assertProfile(
                "unknown", "MediaTek", "sun",
                MobileSocCompatibilityPolicy.Family.DIMENSITY,
                MobileSocCompatibilityPolicy.Era.UNKNOWN,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                "unknown-dimensity", "none");
        assertProfile(
                "unknown", "Xiaomi", "pineapple",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "SM8650", "v75");
        assertProfile(
                "unknown", "Xiaomi", "qcom pineapple",
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                MobileSocCompatibilityPolicy.Era.GENERATION_2022_2023,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                "SM8650", "v75");
        assertProfile(
                "unknown", "Xiaomi", "pineapple_backup",
                MobileSocCompatibilityPolicy.Family.UNKNOWN,
                MobileSocCompatibilityPolicy.Era.UNKNOWN,
                MobileSocCompatibilityPolicy.RequiredBackend.RUNTIME_PROBE,
                "unknown", "none");
    }

    private static void verifiesPlatformAliasBoundariesCannotPromoteQnn() {
        String[] aliases = {
                "lahaina", "taro", "waipio", "cape",
                "kalama", "pineapple", "sun"
        };
        String[] decorations = {
                "prefix%s", "%s_backup", "%s-backup",
                "backup/%s", "%s.backup"
        };
        for (int index = 0;
                index < ALIAS_BOUNDARY_STRESS_VARIANTS;
                index++) {
            String alias = aliases[index % aliases.length];
            String hardware = String.format(
                    decorations[index % decorations.length], alias)
                    + index;
            MobileSocCompatibilityPolicy.Result neutral =
                    MobileSocCompatibilityPolicy.evaluate(
                            "unknown", "Xiaomi", hardware);
            require(neutral.requiredBackend
                    != MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP);
            require("none".equals(neutral.expectedHtpArchitecture));

            MobileSocCompatibilityPolicy.Result nonQualcomm =
                    MobileSocCompatibilityPolicy.evaluate(
                            "unknown", "MediaTek", alias);
            require(nonQualcomm.family
                    == MobileSocCompatibilityPolicy.Family.DIMENSITY);
            require(nonQualcomm.requiredBackend
                    == MobileSocCompatibilityPolicy.RequiredBackend
                    .PORTABLE_NNAPI);
        }
    }

    private static void verifiesNullEvidenceRemainsPortableAndProbeDriven() {
        MobileSocCompatibilityPolicy.Result compatibility =
                MobileSocCompatibilityPolicy.evaluate(null, null, null);
        require(compatibility.family
                == MobileSocCompatibilityPolicy.Family.UNKNOWN);
        require(compatibility.requiredBackend
                == MobileSocCompatibilityPolicy.RequiredBackend.RUNTIME_PROBE);
        MobileInferenceBackendPolicy.Plan plan =
                MobileInferenceBackendPolicy.evaluate(compatibility);
        require(plan.candidates.length == 2);
        require(plan.candidates[0]
                == MobileInferenceBackend.ONNXRUNTIME_NNAPI);
        require(plan.candidates[1]
                == MobileInferenceBackend.ONNXRUNTIME_CPU);
    }

    private static void assertPortable(
            String model,
            MobileSocCompatibilityPolicy.Era era,
            String canonical) {
        MobileSocCompatibilityPolicy.Result result =
                MobileSocCompatibilityPolicy.evaluate(
                        model, "MediaTek", "mtk");
        require(result.family == MobileSocCompatibilityPolicy.Family.DIMENSITY);
        require(result.era == era);
        require(result.requiredBackend
                == MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI);
        require(canonical.equals(result.canonicalSocModel));
        require("none".equals(result.expectedHtpArchitecture));
    }

    private static void assertSnapdragonPlatform(
            String platform,
            MobileSocCompatibilityPolicy.Era era,
            String canonical,
            String htpArchitecture) {
        assertProfile(
                "unknown", "Qualcomm", platform,
                MobileSocCompatibilityPolicy.Family.SNAPDRAGON,
                era,
                MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP,
                canonical, htpArchitecture);
    }

    private static void assertKirin(
            String model,
            MobileSocCompatibilityPolicy.Era era,
            String canonical) {
        assertProfile(
                model, "HiSilicon", "kirin",
                MobileSocCompatibilityPolicy.Family.KIRIN,
                era,
                MobileSocCompatibilityPolicy.RequiredBackend.PORTABLE_NNAPI,
                canonical, "none");
    }

    private static void assertProfile(
            String model,
            String manufacturer,
            String hardware,
            MobileSocCompatibilityPolicy.Family family,
            MobileSocCompatibilityPolicy.Era era,
            MobileSocCompatibilityPolicy.RequiredBackend backend,
            String canonical,
            String htpArchitecture) {
        MobileSocCompatibilityPolicy.Result result =
                MobileSocCompatibilityPolicy.evaluate(
                        model, manufacturer, hardware);
        require(result.family == family);
        require(result.era == era);
        require(result.requiredBackend == backend);
        require(canonical.equals(result.canonicalSocModel));
        require(htpArchitecture.equals(result.expectedHtpArchitecture));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError(
                    "mobile SoC compatibility policy contract failed");
        }
    }
}
