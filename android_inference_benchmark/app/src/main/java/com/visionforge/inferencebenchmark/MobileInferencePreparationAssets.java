package com.visionforge.inferencebenchmark;

/** Immutable resolved file inputs for one explicit inference backend attempt. */
final class MobileInferencePreparationAssets {
    final boolean ready;
    final String vendorRuntimeDirectory;
    final String portableModelPath;
    final String detail;
    final Throwable failure;
    final MobilePipelineCoordinator.FailureDisposition disposition;
    final String failureCode;

    private MobileInferencePreparationAssets(
            boolean ready,
            String vendorRuntimeDirectory,
            String portableModelPath,
            String detail,
            Throwable failure,
            MobilePipelineCoordinator.FailureDisposition disposition,
            String failureCode) {
        this.ready = ready;
        this.vendorRuntimeDirectory = vendorRuntimeDirectory == null
                ? "" : vendorRuntimeDirectory;
        this.portableModelPath = portableModelPath == null
                ? "" : portableModelPath;
        this.detail = detail == null ? "" : detail;
        this.failure = failure;
        this.disposition = disposition;
        this.failureCode = failureCode;
    }

    static MobileInferencePreparationAssets qnn(
            String vendorRuntimeDirectory,
            String detail) {
        return new MobileInferencePreparationAssets(
                true, vendorRuntimeDirectory, "", detail, null,
                MobilePipelineCoordinator.FailureDisposition.NONE, "none");
    }

    static MobileInferencePreparationAssets portable(
            String portableModelPath,
            String detail) {
        return new MobileInferencePreparationAssets(
                true, "", portableModelPath, detail, null,
                MobilePipelineCoordinator.FailureDisposition.NONE, "none");
    }

    static MobileInferencePreparationAssets failure(
            String detail,
            Throwable failure) {
        return failure(
                detail,
                failure,
                MobilePipelineCoordinator.FailureDisposition.RETRYABLE,
                "inference_asset_resolution_failed");
    }

    static MobileInferencePreparationAssets failure(
            String detail,
            Throwable failure,
            MobilePipelineCoordinator.FailureDisposition disposition,
            String failureCode) {
        if (disposition == null
                || disposition
                == MobilePipelineCoordinator.FailureDisposition.NONE
                || failureCode == null || failureCode.isBlank()) {
            throw new IllegalArgumentException(
                    "failed inference assets require a disposition and code");
        }
        return new MobileInferencePreparationAssets(
                false, "", "", detail, failure, disposition, failureCode);
    }
}
