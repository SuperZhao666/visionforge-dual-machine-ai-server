package com.visionforge.inferencebenchmark;

/**
 * Owns only the ordered lifecycle of UDP reception, MediaCodec and inference.
 * UI state and MAKCU control are deliberately kept outside this coordinator.
 */
final class MobilePipelineCoordinator {
    static final int VIDEO_PORT = 5000;
    static final String UNSUPPORTED_SNAPDRAGON_FAILURE_CODE =
            "qnn_htp_unsupported_snapdragon_model";

    private final NativeVideoInferencePipeline pipeline;
    private final MobileRuntimeEventSink events;
    private boolean preparedDataPlaneClosed;
    private boolean decoderPrepared;
    private boolean dataPlaneCloseRequired;
    private String preparedModelToken = "";
    private String preparedBackendToken = "";

    MobilePipelineCoordinator(NativeVideoInferencePipeline pipeline, MobileRuntimeEventSink events) {
        this.pipeline = pipeline;
        this.events = events;
    }

    /**
     * Loads QNN and configures the decoder while UDP video remains closed.
     * This is readiness work only and must complete before a paid lease is
     * requested.
     */
    synchronized PrepareResult prepareDataPlaneClosed(
            String nativeLibraryDirectory,
            String skeletonDirectory,
            MobileModelCatalog.Profile model) {
        return prepareDataPlaneClosed(
                MobileInferenceBackend.QNN_HTP,
                nativeLibraryDirectory,
                skeletonDirectory,
                "",
                model);
    }

    synchronized PrepareResult prepareDataPlaneClosed(
            MobileInferenceBackend backend,
            String nativeLibraryDirectory,
            String vendorRuntimeDirectory,
            String portableModelPath,
            MobileModelCatalog.Profile model) {
        if (backend == null) {
            events.write(
                    "mobile_pipeline_prepare_rejected",
                    "inference_backend_missing");
            return PrepareResult.failure(
                    "Inference backend unavailable",
                    FailureDisposition.TERMINAL_INCOMPATIBLE,
                    "inference_backend_missing");
        }
        if (backend.requiresQnnRuntime && isBlank(vendorRuntimeDirectory)) {
            events.write(
                    "mobile_pipeline_prepare_rejected",
                    "qnn_skeleton_unavailable");
            return PrepareResult.failure(
                    "QNN HTP skeleton unavailable",
                    FailureDisposition.RETRYABLE,
                    "transient_start_failure");
        }
        if (backend.requiresPortableModel && isBlank(portableModelPath)) {
            events.write(
                    "mobile_pipeline_prepare_rejected",
                    "portable_model_unavailable backend=" + backend.token);
            return PrepareResult.failure(
                    "Portable ONNX model unavailable",
                    FailureDisposition.TERMINAL_INCOMPATIBLE,
                    "portable_model_unavailable");
        }
        events.write(
                "mobile_pipeline_prepare_requested",
                "backend=" + backend.token
                        + " decoder_requested=true data_plane=closed");
        try {
            PrepareResult result = prepareDataPlaneClosedInternal(
                    backend,
                    nativeLibraryDirectory,
                    vendorRuntimeDirectory,
                    portableModelPath,
                    model);
            events.write(
                    result.prepared
                            ? "mobile_pipeline_prepared"
                            : "mobile_pipeline_prepare_failed",
                    result.message);
            return result;
        } catch (RuntimeException | LinkageError failure) {
            String detail = "pipeline_prepare_exception stack={"
                    + MobileThrowableDiagnostics.format(failure) + "}";
            events.write("mobile_pipeline_prepare_failed", detail);
            preparedDataPlaneClosed = false;
            decoderPrepared = false;
            dataPlaneCloseRequired = false;
            preparedModelToken = "";
            preparedBackendToken = "";
            return PrepareResult.failure(
                    detail,
                    FailureDisposition.RETRYABLE,
                    "transient_start_failure");
        }
    }

    /**
     * Opens only the UDP data plane after the caller has installed a verified
     * short lease. It never loads a model or silently prepares missing state.
     */
    synchronized StartResult openPreparedDataPlane(
            MobileTransportEndpoint endpoint,
            MobileModelCatalog.Profile expectedModel) {
        events.write(
                "mobile_pipeline_data_plane_open_requested",
                "verified_lease_required=true");
        try {
            StartResult result =
                    openPreparedDataPlaneInternal(endpoint, expectedModel);
            events.write(
                    result.started
                            ? "mobile_pipeline_data_plane_opened"
                            : "mobile_pipeline_data_plane_open_failed",
                    result.message);
            return result;
        } catch (RuntimeException | LinkageError failure) {
            String detail = "pipeline_data_plane_open_exception stack={"
                    + MobileThrowableDiagnostics.format(failure) + "}";
            events.write("mobile_pipeline_data_plane_open_failed", detail);
            return StartResult.failure(detail);
        }
    }

    /** Closes traffic and MediaCodec while retaining the prepared graph. */
    synchronized void closeDataPlane() {
        if (!dataPlaneCloseRequired) return;
        try {
            pipeline.stopVideoReceiver();
        } finally {
            decoderPrepared = false;
            pipeline.stopInferenceDecoder();
        }
        dataPlaneCloseRequired = false;
        events.write(
                "mobile_pipeline_data_plane_closed",
                "qnn_prepared=" + preparedDataPlaneClosed
                        + " inference_backend="
                        + (preparedBackendToken.isEmpty()
                        ? "none" : preparedBackendToken)
                        + " decoder_running=false");
    }

    synchronized void stop() {
        try {
            pipeline.stop();
        } finally {
            preparedDataPlaneClosed = false;
            decoderPrepared = false;
            dataPlaneCloseRequired = false;
            preparedModelToken = "";
            preparedBackendToken = "";
        }
        events.write("mobile_pipeline_stopped", "qnn_decoder_receiver_stopped");
    }

    synchronized boolean isPreparedDataPlaneClosed() {
        return preparedDataPlaneClosed;
    }

    synchronized String preparedBackendToken() {
        return preparedBackendToken;
    }

    private PrepareResult prepareDataPlaneClosedInternal(
            MobileInferenceBackend backend,
            String nativeLibraryDirectory,
            String vendorRuntimeDirectory,
            String portableModelPath,
            MobileModelCatalog.Profile model) {
        pipeline.stop();
        preparedDataPlaneClosed = false;
        decoderPrepared = false;
        dataPlaneCloseRequired = false;
        preparedModelToken = "";
        preparedBackendToken = "";
        if (model == null) {
            return PrepareResult.failure(
                    "mobile_model_not_selected",
                    FailureDisposition.TERMINAL_INCOMPATIBLE,
                    "qnn_model_selection_invalid");
        }
        if (!pipeline.prepareInference(
                backend.token,
                nativeLibraryDirectory,
                vendorRuntimeDirectory,
                portableModelPath,
                model.token)) {
            String inferenceReport = pipeline.inferenceReport();
            String retryable = MobileDiagnosticFieldParser.valueOr(
                    inferenceReport, "retryable", "");
            if ("false".equalsIgnoreCase(retryable)) {
                String failureCode = MobileDiagnosticFieldParser.valueOr(
                        inferenceReport, "failure_code", "");
                if (failureCode.isEmpty()) {
                    failureCode =
                            backend == MobileInferenceBackend.QNN_HTP
                                    ? "qnn_permanent_initialization_failure"
                                    : "portable_permanent_initialization_failure";
                }
                return PrepareResult.failure(
                        "inference_graph_load_failed backend="
                                + backend.token + ": " + inferenceReport,
                        FailureDisposition.TERMINAL_INCOMPATIBLE,
                        failureCode);
            }
            return PrepareResult.failure(
                    (backend == MobileInferenceBackend.QNN_HTP
                            ? "qnn_graph_load_failed: "
                            : "inference_graph_load_failed backend="
                                    + backend.token + ": ")
                            + inferenceReport,
                    FailureDisposition.RETRYABLE,
                    backend == MobileInferenceBackend.QNN_HTP
                            ? "qnn_graph_load_failed"
                            : "portable_graph_load_failed");
        }
        if (!pipeline.configureInferenceDecoder(
                model.inputWidth,
                model.inputHeight)) {
            return PrepareResult.failure(
                    "mediacodec_inference_output_configuration_failed",
                    FailureDisposition.RETRYABLE,
                    "transient_start_failure");
        }
        decoderPrepared = true;
        dataPlaneCloseRequired = true;
        preparedDataPlaneClosed = true;
        preparedModelToken = model.token;
        preparedBackendToken = backend.token;
        return PrepareResult.success();
    }

    private StartResult openPreparedDataPlaneInternal(
            MobileTransportEndpoint endpoint,
            MobileModelCatalog.Profile expectedModel) {
        if (!preparedDataPlaneClosed) {
            return StartResult.failure(
                    "pipeline_not_prepared_with_data_plane_closed");
        }
        if (expectedModel == null
                || !preparedModelToken.equals(expectedModel.token)) {
            return StartResult.failure(
                    "prepared_qnn_model_mismatch");
        }
        if (endpoint == null || !endpoint.isReadyForDataPlane()) {
            return StartResult.failure(
                    "Required transport unavailable");
        }
        if (!decoderPrepared) {
            if (!pipeline.configureInferenceDecoder(
                    expectedModel.inputWidth,
                    expectedModel.inputHeight)) {
                return StartResult.failure(
                        "mediacodec_inference_output_configuration_failed");
            }
            decoderPrepared = true;
            dataPlaneCloseRequired = true;
        }
        if (!pipeline.startVideoReceiver(
                endpoint.localIpv4,
                endpoint.hostIpv4,
                VIDEO_PORT,
                endpoint.networkHandle)) {
            return StartResult.failure(
                    "udp_bind_failed "
                            + endpoint.detail()
                            + ":" + VIDEO_PORT
                            + " receiver={"
                            + pipeline.videoReceiverReport() + "}");
        }
        return StartResult.success();
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    enum FailureDisposition { NONE, RETRYABLE, TERMINAL_INCOMPATIBLE }

    static final class PrepareResult {
        final boolean prepared;
        final String message;
        final FailureDisposition disposition;
        final String failureCode;

        private PrepareResult(
                boolean prepared,
                String message,
                FailureDisposition disposition,
                String failureCode) {
            this.prepared = prepared;
            this.message = message;
            this.disposition = disposition;
            this.failureCode = failureCode;
        }

        static PrepareResult success() {
            return new PrepareResult(
                    true,
                    "Local inference graph and decoder prepared with data plane closed.",
                    FailureDisposition.NONE,
                    "none");
        }

        static PrepareResult failure(
                String message,
                FailureDisposition disposition,
                String failureCode) {
            return new PrepareResult(
                    false, message, disposition, failureCode);
        }
    }

    static final class StartResult {
        final boolean started;
        final String message;
        final FailureDisposition disposition;
        final String failureCode;

        private StartResult(boolean started, String message,
                            FailureDisposition disposition, String failureCode) {
            this.started = started;
            this.message = message;
            this.disposition = disposition;
            this.failureCode = failureCode;
        }

        static StartResult success() {
            return new StartResult(
                    true, "Local pipeline started.", FailureDisposition.NONE, "none");
        }

        static StartResult failure(String message) {
            return failure(message, FailureDisposition.RETRYABLE, "transient_start_failure");
        }

        static StartResult failure(
                String message, FailureDisposition disposition, String failureCode) {
            return new StartResult(false, message, disposition, failureCode);
        }
    }
}
