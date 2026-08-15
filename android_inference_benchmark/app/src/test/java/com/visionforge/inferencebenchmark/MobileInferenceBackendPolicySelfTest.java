package com.visionforge.inferencebenchmark;

/** Regression matrix for QNN, NNAPI and emulator/reference backend order. */
final class MobileInferenceBackendPolicySelfTest {
    private MobileInferenceBackendPolicySelfTest() {}

    static void run() {
        verifiesModernSnapdragonKeepsQnnFirst();
        verifiesMissingV81RetainsPortableFallbackCandidates();
        verifiesDimensityAndKirinUsePortableBackends();
        verifiesMarketingNamesKeepTheSameFallbackContracts();
        verifiesOldSnapdragonDoesNotAttemptUnavailableHtp();
        verifiesPreAndroid12QcomMarkerUsesSafePortableRoute();
        verifiesPreAndroid12KnownPlatformUsesQnnProbeFirst();
        verifiesEmulatorUsesReferenceCpuOnly();
        verifiesUnknownFutureSocProbesPortableRuntime();
        verifiesHotReloadStartsFromProvenBackend();
        verifiesEveryFamilyAndEraHasAUniqueCpuFallbackPlan();
    }

    private static void verifiesModernSnapdragonKeepsQnnFirst() {
        MobileInferenceBackendPolicy.Plan plan = plan("SM8650", "QTI", "qcom");
        require(plan.candidates.length == 3);
        require(plan.candidates[0] == MobileInferenceBackend.QNN_HTP);
        require(plan.candidates[1] == MobileInferenceBackend.ONNXRUNTIME_NNAPI);
        require(plan.candidates[2] == MobileInferenceBackend.ONNXRUNTIME_CPU);
        require(plan.detail().contains(
                "readiness_proof=backend_init_and_real_graph_execution"));

        MobileInferenceBackendPolicy.Plan suffixed = plan(
                "SM8350P", "QTI", "qcom");
        require(suffixed.candidates[0] == MobileInferenceBackend.QNN_HTP);
    }

    private static void verifiesMissingV81RetainsPortableFallbackCandidates() {
        MobileSocCompatibilityPolicy.Result compatibility =
                MobileSocCompatibilityPolicy.evaluate(
                        "SM8850", "Qualcomm", "qcom");
        QnnHtpCompatibilityPolicy.Result qnnCompatibility =
                QnnHtpCompatibilityPolicy.evaluate(
                        compatibility.canonicalSocModel,
                        java.util.Arrays.asList(
                                "v68", "v69", "v73", "v75", "v79"));
        MobileInferenceBackendPolicy.Plan plan =
                MobileInferenceBackendPolicy.evaluate(compatibility);

        require(!qnnCompatibility.canAttemptBackend);
        require("v81".equals(qnnCompatibility.expectedArchitecture));
        require(plan.candidates.length == 3);
        require(plan.candidates[0] == MobileInferenceBackend.QNN_HTP);
        require(plan.candidates[1]
                == MobileInferenceBackend.ONNXRUNTIME_NNAPI);
        require(plan.candidates[2]
                == MobileInferenceBackend.ONNXRUNTIME_CPU);
    }

    private static void verifiesDimensityAndKirinUsePortableBackends() {
        for (String[] identity : new String[][]{
                {"MT6989", "MediaTek", "mt6989"},
                {"Kirin 9010", "HiSilicon", "kirin9010"}}) {
            MobileInferenceBackendPolicy.Plan plan = plan(
                    identity[0], identity[1], identity[2]);
            require(plan.candidates.length == 2);
            require(plan.candidates[0]
                    == MobileInferenceBackend.ONNXRUNTIME_NNAPI);
            require(plan.candidates[1]
                    == MobileInferenceBackend.ONNXRUNTIME_CPU);
            require(!plan.contains(MobileInferenceBackend.QNN_HTP));
        }
    }

    private static void verifiesMarketingNamesKeepTheSameFallbackContracts() {
        MobileInferenceBackendPolicy.Plan snapdragon = plan(
                "Snapdragon 8 Gen 3 Mobile Platform", "Qualcomm", "qcom");
        require(snapdragon.candidates.length == 3);
        require(snapdragon.candidates[0] == MobileInferenceBackend.QNN_HTP);
        require(snapdragon.candidates[1]
                == MobileInferenceBackend.ONNXRUNTIME_NNAPI);
        require(snapdragon.candidates[2]
                == MobileInferenceBackend.ONNXRUNTIME_CPU);

        MobileSocCompatibilityPolicy.Result futureSnapdragon =
                MobileSocCompatibilityPolicy.evaluate(
                        "Snapdragon 8 Elite Gen 5", "Qualcomm", "qcom");
        QnnHtpCompatibilityPolicy.Result packaged =
                QnnHtpCompatibilityPolicy.evaluate(
                        futureSnapdragon.canonicalSocModel,
                        java.util.Arrays.asList("v68", "v69", "v73", "v75", "v79"));
        MobileInferenceBackendPolicy.Plan futurePlan =
                MobileInferenceBackendPolicy.evaluate(futureSnapdragon);
        require(!packaged.canAttemptBackend);
        require("v81".equals(packaged.expectedArchitecture));
        require(futurePlan.candidates[1]
                == MobileInferenceBackend.ONNXRUNTIME_NNAPI);
        require(futurePlan.candidates[2]
                == MobileInferenceBackend.ONNXRUNTIME_CPU);

        MobileInferenceBackendPolicy.Plan dimensity = plan(
                "MediaTek Dimensity 9400+", "MediaTek", "mtk");
        require(dimensity.candidates.length == 2);
        require(dimensity.candidates[0]
                == MobileInferenceBackend.ONNXRUNTIME_NNAPI);
        require(dimensity.candidates[1]
                == MobileInferenceBackend.ONNXRUNTIME_CPU);
        require(!dimensity.contains(MobileInferenceBackend.QNN_HTP));
    }

    private static void verifiesOldSnapdragonDoesNotAttemptUnavailableHtp() {
        MobileInferenceBackendPolicy.Plan plan = plan(
                "SM8250", "Qualcomm", "qcom");
        require(plan.candidates[0]
                == MobileInferenceBackend.ONNXRUNTIME_NNAPI);
        require(!plan.contains(MobileInferenceBackend.QNN_HTP));
    }

    private static void verifiesPreAndroid12QcomMarkerUsesSafePortableRoute() {
        MobileInferenceBackendPolicy.Plan plan = plan(
                "qcom", "Samsung", "qcom");
        require(plan.candidates.length == 2);
        require(plan.candidates[0]
                == MobileInferenceBackend.ONNXRUNTIME_NNAPI);
        require(plan.candidates[1]
                == MobileInferenceBackend.ONNXRUNTIME_CPU);
        require(!plan.contains(MobileInferenceBackend.QNN_HTP));
    }

    private static void verifiesPreAndroid12KnownPlatformUsesQnnProbeFirst() {
        MobileInferenceBackendPolicy.Plan plan = plan(
                "unknown", "Qualcomm", "pineapple");
        require(plan.candidates.length == 3);
        require(plan.candidates[0] == MobileInferenceBackend.QNN_HTP);
        require(plan.candidates[1] == MobileInferenceBackend.ONNXRUNTIME_NNAPI);
        require(plan.candidates[2] == MobileInferenceBackend.ONNXRUNTIME_CPU);
    }

    private static void verifiesEmulatorUsesReferenceCpuOnly() {
        MobileInferenceBackendPolicy.Plan plan = plan(
                "unknown", "Google", "ranchu");
        require(plan.candidates.length == 1);
        require(plan.candidates[0]
                == MobileInferenceBackend.ONNXRUNTIME_CPU);
    }

    private static void verifiesUnknownFutureSocProbesPortableRuntime() {
        MobileInferenceBackendPolicy.Plan plan = plan(
                "FutureChip 1", "FutureVendor", "futurehw");
        require(plan.candidates.length == 2);
        require(plan.candidates[0]
                == MobileInferenceBackend.ONNXRUNTIME_NNAPI);
        require(plan.candidates[1]
                == MobileInferenceBackend.ONNXRUNTIME_CPU);
    }

    private static void verifiesHotReloadStartsFromProvenBackend() {
        MobileInferenceBackendPolicy.Plan nnapi =
                MobileInferenceBackendPolicy.resumeFrom(
                        MobileInferenceBackend.ONNXRUNTIME_NNAPI);
        require(nnapi.candidates.length == 2);
        require(nnapi.candidates[0]
                == MobileInferenceBackend.ONNXRUNTIME_NNAPI);
        require(!nnapi.contains(MobileInferenceBackend.QNN_HTP));

        MobileInferenceBackendPolicy.Plan cpu =
                MobileInferenceBackendPolicy.resumeFrom(
                        MobileInferenceBackend.ONNXRUNTIME_CPU);
        require(cpu.candidates.length == 1);
        require(cpu.candidates[0]
                == MobileInferenceBackend.ONNXRUNTIME_CPU);
    }

    private static void verifiesEveryFamilyAndEraHasAUniqueCpuFallbackPlan() {
        String[][] evidenceMatrix = {
                {"MSM8998", "Qualcomm", "msm8998"},
                {"SM8350", "Qualcomm", "lahaina"},
                {"SM8650", "Qualcomm", "pineapple"},
                {"SM8850", "Qualcomm", "qcom"},
                {"MT6797", "MediaTek", "mt6797"},
                {"MT6893", "MediaTek", "mt6893"},
                {"MT6991", "MediaTek", "mt6991"},
                {"Kirin 970", "HiSilicon", "kirin970"},
                {"Kirin 9000S", "HiSilicon", "kirin9000s"},
                {"Kirin 9020", "HiSilicon", "kirin9020"},
                {"Exynos 9810", "Samsung", "s5e9810"},
                {"Exynos 2400", "Samsung", "s5e9945"},
                {"Google Tensor G4", "Google", "gs401"},
                {"future-soc", "future-vendor", "future-board"}
        };
        for (String[] evidence : evidenceMatrix) {
            MobileSocCompatibilityPolicy.Result compatibility =
                    MobileSocCompatibilityPolicy.evaluate(
                            evidence[0], evidence[1], evidence[2]);
            MobileInferenceBackendPolicy.Plan plan =
                    MobileInferenceBackendPolicy.evaluate(compatibility);
            require(plan.candidates[plan.candidates.length - 1]
                    == MobileInferenceBackend.ONNXRUNTIME_CPU);
            for (int candidate = 0;
                    candidate < plan.candidates.length;
                    candidate++) {
                for (int earlier = 0; earlier < candidate; earlier++) {
                    require(plan.candidates[candidate]
                            != plan.candidates[earlier]);
                }
            }
            boolean qnnRequired = compatibility.requiredBackend
                    == MobileSocCompatibilityPolicy.RequiredBackend.QNN_HTP;
            require(plan.contains(MobileInferenceBackend.QNN_HTP)
                    == qnnRequired);
            if (qnnRequired) {
                require(plan.candidates[0]
                        == MobileInferenceBackend.QNN_HTP);
            }
        }
    }

    private static MobileInferenceBackendPolicy.Plan plan(
            String model,
            String manufacturer,
            String hardware) {
        return MobileInferenceBackendPolicy.evaluate(
                MobileSocCompatibilityPolicy.evaluate(
                        model, manufacturer, hardware));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError(
                    "Mobile inference backend routing contract failed");
        }
    }
}
