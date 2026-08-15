package com.visionforge.inferencebenchmark;

import java.util.Arrays;
import java.util.Locale;

/**
 * Pure SoC-to-backend routing policy.
 *
 * <p>Every candidate must still initialize its real runtime and execute the
 * selected graph once before it can become ready. A marketing SoC name is
 * never treated as accelerator proof.</p>
 */
final class MobileInferenceBackendPolicy {
    private MobileInferenceBackendPolicy() {}

    static Plan evaluate(MobileSocCompatibilityPolicy.Result compatibility) {
        if (compatibility == null) {
            return new Plan(
                    "missing_soc_profile",
                    MobileInferenceBackend.ONNXRUNTIME_NNAPI,
                    MobileInferenceBackend.ONNXRUNTIME_CPU);
        }
        switch (compatibility.requiredBackend) {
            case QNN_HTP:
                return new Plan(
                        "modern_snapdragon_qnn_then_portable",
                        MobileInferenceBackend.QNN_HTP,
                        MobileInferenceBackend.ONNXRUNTIME_NNAPI,
                        MobileInferenceBackend.ONNXRUNTIME_CPU);
            case EMULATOR_REFERENCE:
                return new Plan(
                        "emulator_reference_cpu",
                        MobileInferenceBackend.ONNXRUNTIME_CPU);
            case PORTABLE_NNAPI:
            case RUNTIME_PROBE:
            default:
                return new Plan(
                        "portable_nnapi_then_cpu",
                        MobileInferenceBackend.ONNXRUNTIME_NNAPI,
                        MobileInferenceBackend.ONNXRUNTIME_CPU);
        }
    }

    /** Keeps hot reload on the backend family proven for the active session. */
    static Plan resumeFrom(MobileInferenceBackend selected) {
        if (selected == null) {
            throw new IllegalArgumentException(
                    "selected inference backend is required");
        }
        if (selected == MobileInferenceBackend.QNN_HTP) {
            return new Plan(
                    "active_qnn_session",
                    MobileInferenceBackend.QNN_HTP,
                    MobileInferenceBackend.ONNXRUNTIME_NNAPI,
                    MobileInferenceBackend.ONNXRUNTIME_CPU);
        }
        if (selected == MobileInferenceBackend.ONNXRUNTIME_NNAPI) {
            return new Plan(
                    "active_nnapi_session",
                    MobileInferenceBackend.ONNXRUNTIME_NNAPI,
                    MobileInferenceBackend.ONNXRUNTIME_CPU);
        }
        return new Plan(
                "active_cpu_session",
                MobileInferenceBackend.ONNXRUNTIME_CPU);
    }

    static final class Plan {
        final String reason;
        final MobileInferenceBackend[] candidates;

        Plan(String reason, MobileInferenceBackend... candidates) {
            if (reason == null || reason.isBlank()
                    || candidates == null || candidates.length == 0) {
                throw new IllegalArgumentException("invalid inference backend plan");
            }
            for (int index = 0; index < candidates.length; index++) {
                if (candidates[index] == null) {
                    throw new IllegalArgumentException("null inference backend candidate");
                }
                for (int earlier = 0; earlier < index; earlier++) {
                    if (candidates[earlier] == candidates[index]) {
                        throw new IllegalArgumentException(
                                "duplicate inference backend candidate");
                    }
                }
            }
            this.reason = reason;
            this.candidates = candidates.clone();
        }

        boolean contains(MobileInferenceBackend backend) {
            for (MobileInferenceBackend candidate : candidates) {
                if (candidate == backend) return true;
            }
            return false;
        }

        String detail() {
            String[] tokens = new String[candidates.length];
            for (int index = 0; index < candidates.length; index++) {
                tokens[index] = candidates[index].token;
            }
            return "reason=" + reason.toLowerCase(Locale.ROOT)
                    + " candidates=" + String.join(",", Arrays.asList(tokens))
                    + " readiness_proof=backend_init_and_real_graph_execution";
        }
    }
}
