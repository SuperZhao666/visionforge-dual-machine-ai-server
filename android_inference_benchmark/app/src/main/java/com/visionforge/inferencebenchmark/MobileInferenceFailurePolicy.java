package com.visionforge.inferencebenchmark;

import java.util.Locale;

/** Aggregates backend-local failures only after every planned candidate ran. */
final class MobileInferenceFailurePolicy {
    private MobileInferenceFailurePolicy() {}

    static final class Accumulator {
        private final StringBuilder attempts = new StringBuilder();
        private MobilePipelineCoordinator.PrepareResult firstRetryable;
        private MobilePipelineCoordinator.PrepareResult lastTerminal;
        private int attemptCount;

        void record(
                MobileInferenceBackend backend,
                MobilePipelineCoordinator.PrepareResult failure) {
            if (backend == null || failure == null || failure.prepared
                    || failure.disposition
                    == MobilePipelineCoordinator.FailureDisposition.NONE) {
                throw new IllegalArgumentException(
                        "a failed inference backend attempt is required");
            }
            if (attempts.length() > 0) attempts.append(',');
            attempts.append(backend.token)
                    .append(':')
                    .append(failure.failureCode)
                    .append(':')
                    .append(failure.disposition.name().toLowerCase(Locale.ROOT));
            attemptCount++;
            if (failure.disposition
                    == MobilePipelineCoordinator.FailureDisposition.RETRYABLE) {
                if (firstRetryable == null) firstRetryable = failure;
            } else {
                lastTerminal = failure;
            }
        }

        MobilePipelineCoordinator.PrepareResult resolve() {
            if (attemptCount == 0) {
                return MobilePipelineCoordinator.PrepareResult.failure(
                        "no_inference_backend_attempted",
                        MobilePipelineCoordinator.FailureDisposition
                                .TERMINAL_INCOMPATIBLE,
                        "inference_backend_unavailable");
            }
            if (attemptCount == 1) {
                return firstRetryable == null ? lastTerminal : firstRetryable;
            }
            if (firstRetryable != null) {
                return MobilePipelineCoordinator.PrepareResult.failure(
                        "inference_backend_candidates_exhausted "
                                + "retryable_candidate_present=true attempts={"
                                + attempts + "}",
                        MobilePipelineCoordinator.FailureDisposition.RETRYABLE,
                        firstRetryable.failureCode);
            }
            return MobilePipelineCoordinator.PrepareResult.failure(
                    "inference_backend_candidates_permanently_unavailable "
                            + "attempts={" + attempts + "}",
                    MobilePipelineCoordinator.FailureDisposition
                            .TERMINAL_INCOMPATIBLE,
                    lastTerminal.failureCode);
        }
    }
}
