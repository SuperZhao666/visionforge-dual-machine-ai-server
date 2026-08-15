package com.visionforge.inferencebenchmark;

/** Candidate aggregation contracts for terminal versus retryable recovery. */
final class MobileInferenceFailurePolicySelfTest {
    private MobileInferenceFailurePolicySelfTest() {}

    static void run() {
        verifiesNoAttemptFailsClosed();
        verifiesSingleFailurePreservesNativeEvidence();
        verifiesNnapiPermanentFailureStillAllowsCpuOutcome();
        verifiesAnyRetryableCandidateKeepsOverallRecoveryOpen();
        verifiesAllPermanentCandidatesBecomeTerminal();
    }

    private static void verifiesNoAttemptFailsClosed() {
        MobilePipelineCoordinator.PrepareResult result =
                new MobileInferenceFailurePolicy.Accumulator().resolve();
        require(result.disposition
                == MobilePipelineCoordinator.FailureDisposition
                .TERMINAL_INCOMPATIBLE);
        require("inference_backend_unavailable".equals(result.failureCode));
    }

    private static void verifiesSingleFailurePreservesNativeEvidence() {
        MobileInferenceFailurePolicy.Accumulator failures =
                new MobileInferenceFailurePolicy.Accumulator();
        MobilePipelineCoordinator.PrepareResult original = retryable(
                "nnapi_driver_temporarily_unavailable");
        failures.record(MobileInferenceBackend.ONNXRUNTIME_NNAPI, original);
        require(failures.resolve() == original);
    }

    private static void verifiesNnapiPermanentFailureStillAllowsCpuOutcome() {
        MobileInferenceFailurePolicy.Accumulator failures =
                new MobileInferenceFailurePolicy.Accumulator();
        failures.record(
                MobileInferenceBackend.ONNXRUNTIME_NNAPI,
                terminal("portable_model_contract_invalid"));
        failures.record(
                MobileInferenceBackend.ONNXRUNTIME_CPU,
                retryable("onnxruntime_initialization_failed"));

        MobilePipelineCoordinator.PrepareResult result = failures.resolve();
        require(result.disposition
                == MobilePipelineCoordinator.FailureDisposition.RETRYABLE);
        require("onnxruntime_initialization_failed".equals(result.failureCode));
        require(result.message.contains("onnxruntime_nnapi:"));
        require(result.message.contains("onnxruntime_cpu:"));
    }

    private static void verifiesAnyRetryableCandidateKeepsOverallRecoveryOpen() {
        MobileInferenceFailurePolicy.Accumulator failures =
                new MobileInferenceFailurePolicy.Accumulator();
        failures.record(
                MobileInferenceBackend.ONNXRUNTIME_NNAPI,
                retryable("nnapi_driver_temporarily_unavailable"));
        failures.record(
                MobileInferenceBackend.ONNXRUNTIME_CPU,
                terminal("portable_model_contract_invalid"));

        MobilePipelineCoordinator.PrepareResult result = failures.resolve();
        require(result.disposition
                == MobilePipelineCoordinator.FailureDisposition.RETRYABLE);
        require("nnapi_driver_temporarily_unavailable".equals(
                result.failureCode));
        require(result.message.contains("retryable_candidate_present=true"));
    }

    private static void verifiesAllPermanentCandidatesBecomeTerminal() {
        MobileInferenceFailurePolicy.Accumulator failures =
                new MobileInferenceFailurePolicy.Accumulator();
        failures.record(
                MobileInferenceBackend.QNN_HTP,
                terminal("qnn_htp_architecture_not_packaged"));
        failures.record(
                MobileInferenceBackend.ONNXRUNTIME_NNAPI,
                terminal("portable_model_contract_invalid"));
        failures.record(
                MobileInferenceBackend.ONNXRUNTIME_CPU,
                terminal("portable_probe_non_finite_output"));

        MobilePipelineCoordinator.PrepareResult result = failures.resolve();
        require(result.disposition
                == MobilePipelineCoordinator.FailureDisposition
                .TERMINAL_INCOMPATIBLE);
        require("portable_probe_non_finite_output".equals(result.failureCode));
        require(result.message.contains(
                "inference_backend_candidates_permanently_unavailable"));
    }

    private static MobilePipelineCoordinator.PrepareResult retryable(
            String failureCode) {
        return failure(
                MobilePipelineCoordinator.FailureDisposition.RETRYABLE,
                failureCode);
    }

    private static MobilePipelineCoordinator.PrepareResult terminal(
            String failureCode) {
        return failure(
                MobilePipelineCoordinator.FailureDisposition
                        .TERMINAL_INCOMPATIBLE,
                failureCode);
    }

    private static MobilePipelineCoordinator.PrepareResult failure(
            MobilePipelineCoordinator.FailureDisposition disposition,
            String failureCode) {
        return MobilePipelineCoordinator.PrepareResult.failure(
                "failure_code=" + failureCode, disposition, failureCode);
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError(
                    "Mobile inference failure aggregation contract failed");
        }
    }
}
