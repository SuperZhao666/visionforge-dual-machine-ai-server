package com.visionforge.inferencebenchmark;

/** Dependency-free contract for the ordered native pipeline lifecycle. */
final class MobilePipelineCoordinatorSelfTest {
    private static final String PREPARE_CALL =
            "prepare:/native:/skeleton:" + MobileModelCatalog.DEFAULT.token;
    static void run() {
        verifiesSuccessfulStartOrder();
        verifiesFailedQnnPreparationStopsBeforeDecoder();
        verifiesUnsupportedSnapdragonSuppressesAutomaticRecovery();
        verifiesPermanentQnnPackageFailureSuppressesAutomaticRecovery();
        verifiesPermanentQnnFailureWithoutCodeUsesStableFallback();
        verifiesDiagnosticFieldsRequireExactTokens();
        verifiesFailedDecoderStopsBeforeReceiver();
        verifiesFailedReceiverIsNotReportedAsStarted();
        verifiesMissingSkeletonDoesNotTouchNativePipeline();
        verifiesMissingEthernetDoesNotTouchNativePipeline();
        verifiesCompleteThrowableStackIsPersisted();
        verifiesPrepareOpenAndLeaseCloseAreSeparate();
        verifiesFailedCloseRemainsRetryable();
        verifiesPreparedModelMismatchFailsClosed();
        verifiesPortableBackendUsesExplicitModelPath();
        verifiesPortableBackendRejectsMissingModelBeforeNativeCall();
    }

    private static void verifiesSuccessfulStartOrder() {
        FakePipeline pipeline = new FakePipeline(true, true, true);
        FakeEvents events = new FakeEvents();
        MobilePipelineCoordinator.StartResult result = prepareAndOpen(
                new MobilePipelineCoordinator(pipeline, events),
                "/native", "/skeleton", 57L);

        require(result.started);
        require(("stop," + PREPARE_CALL + ",configure:416:416,"
                + "receiver:10.57.23.2:10.57.23.1:5000:57")
                .equals(pipeline.calls));
        require(("mobile_pipeline_prepare_requested,mobile_pipeline_prepared,"
                + "mobile_pipeline_data_plane_open_requested,"
                + "mobile_pipeline_data_plane_opened").equals(events.events));
    }

    private static void verifiesFailedQnnPreparationStopsBeforeDecoder() {
        FakePipeline pipeline = new FakePipeline(false, true, true);
        FakeEvents events = new FakeEvents();
        MobilePipelineCoordinator.StartResult result = prepareAndOpen(
                new MobilePipelineCoordinator(pipeline, events),
                "/native", "/skeleton", 57L);

        require(!result.started && result.message.contains("qnn_graph_load_failed"));
        require(result.disposition
                == MobilePipelineCoordinator.FailureDisposition.RETRYABLE);
        require(("stop," + PREPARE_CALL).equals(pipeline.calls));
        require("mobile_pipeline_prepare_requested,mobile_pipeline_prepare_failed"
                .equals(events.events));
    }

    private static void verifiesUnsupportedSnapdragonSuppressesAutomaticRecovery() {
        FakePipeline pipeline = new FakePipeline(
                false, true, true,
                "ready=0 failure_code=qnn_htp_unsupported_snapdragon_model "
                        + "retryable=false backend_status=1004");
        FakeEvents events = new FakeEvents();
        MobilePipelineCoordinator.StartResult result = prepareAndOpen(
                new MobilePipelineCoordinator(pipeline, events),
                "/native", "/skeleton", 57L);

        require(!result.started);
        require(result.disposition
                == MobilePipelineCoordinator.FailureDisposition.TERMINAL_INCOMPATIBLE);
        require(MobilePipelineCoordinator.UNSUPPORTED_SNAPDRAGON_FAILURE_CODE.equals(
                result.failureCode));
        require(("stop," + PREPARE_CALL).equals(pipeline.calls));
    }

    private static void verifiesPermanentQnnPackageFailureSuppressesAutomaticRecovery() {
        FakePipeline pipeline = new FakePipeline(
                false, true, true,
                "FAILED dlopen HTP backend failure_code=qnn_htp_runtime_unavailable "
                        + "retryable=false");
        MobilePipelineCoordinator.StartResult result = prepareAndOpen(
                new MobilePipelineCoordinator(pipeline, new FakeEvents()),
                "/native", "/skeleton", 57L);

        require(!result.started);
        require(result.disposition
                == MobilePipelineCoordinator.FailureDisposition.TERMINAL_INCOMPATIBLE);
        require("qnn_htp_runtime_unavailable".equals(result.failureCode));
        require(("stop," + PREPARE_CALL).equals(pipeline.calls));
    }

    private static void verifiesPermanentQnnFailureWithoutCodeUsesStableFallback() {
        FakePipeline pipeline = new FakePipeline(
                false, true, true, "ready=0 retryable=false");
        MobilePipelineCoordinator.StartResult result = prepareAndOpen(
                new MobilePipelineCoordinator(pipeline, new FakeEvents()),
                "/native", "/skeleton", 57L);

        require(!result.started);
        require(result.disposition
                == MobilePipelineCoordinator.FailureDisposition.TERMINAL_INCOMPATIBLE);
        require("qnn_permanent_initialization_failure".equals(result.failureCode));
    }

    private static void verifiesDiagnosticFieldsRequireExactTokens() {
        FakePipeline retryable = new FakePipeline(
                false, true, true,
                "ready=0 not_retryable=false retryable=true "
                        + "shadow_failure_code=terminal_imposter");
        MobilePipelineCoordinator.StartResult retryableResult = prepareAndOpen(
                new MobilePipelineCoordinator(retryable, new FakeEvents()),
                "/native", "/skeleton", 57L);
        require(!retryableResult.started);
        require(retryableResult.disposition
                == MobilePipelineCoordinator.FailureDisposition.RETRYABLE);
        require("qnn_graph_load_failed".equals(retryableResult.failureCode));

        FakePipeline terminal = new FakePipeline(
                false, true, true,
                "ready=0 shadow_failure_code=terminal_imposter "
                        + "retryable=false failure_code=qnn_real_terminal");
        MobilePipelineCoordinator.StartResult terminalResult = prepareAndOpen(
                new MobilePipelineCoordinator(terminal, new FakeEvents()),
                "/native", "/skeleton", 57L);
        require(!terminalResult.started);
        require(terminalResult.disposition
                == MobilePipelineCoordinator.FailureDisposition
                .TERMINAL_INCOMPATIBLE);
        require("qnn_real_terminal".equals(terminalResult.failureCode));
    }

    private static void verifiesFailedDecoderStopsBeforeReceiver() {
        FakePipeline pipeline = new FakePipeline(true, false, true);
        FakeEvents events = new FakeEvents();
        MobilePipelineCoordinator.StartResult result = prepareAndOpen(
                new MobilePipelineCoordinator(pipeline, events),
                "/native", "/skeleton", 57L);

        require(!result.started && result.message.contains("mediacodec"));
        require(("stop," + PREPARE_CALL + ",configure:416:416").equals(pipeline.calls));
        require("mobile_pipeline_prepare_requested,mobile_pipeline_prepare_failed"
                .equals(events.events));
    }

    private static void verifiesFailedReceiverIsNotReportedAsStarted() {
        FakePipeline pipeline = new FakePipeline(true, true, false);
        FakeEvents events = new FakeEvents();
        MobilePipelineCoordinator.StartResult result = prepareAndOpen(
                new MobilePipelineCoordinator(pipeline, events),
                "/native", "/skeleton", 57L);

        require(!result.started && result.message.contains("udp_bind_failed"));
        require(result.message.contains("startup_stage=local_bind_failed startup_errno=98"));
        require(("stop," + PREPARE_CALL + ",configure:416:416,"
                + "receiver:10.57.23.2:10.57.23.1:5000:57")
                .equals(pipeline.calls));
        require(("mobile_pipeline_prepare_requested,mobile_pipeline_prepared,"
                + "mobile_pipeline_data_plane_open_requested,"
                + "mobile_pipeline_data_plane_open_failed").equals(events.events));
    }

    private static void verifiesMissingSkeletonDoesNotTouchNativePipeline() {
        FakePipeline pipeline = new FakePipeline(true, true, true);
        FakeEvents events = new FakeEvents();
        MobilePipelineCoordinator.StartResult result = prepareAndOpen(
                new MobilePipelineCoordinator(pipeline, events),
                "/native", " ", 57L);

        require(!result.started && result.message.contains("skeleton"));
        require(pipeline.calls.isEmpty());
        require("mobile_pipeline_prepare_rejected".equals(events.events));
    }

    private static void verifiesMissingEthernetDoesNotTouchNativePipeline() {
        FakePipeline pipeline = new FakePipeline(true, true, true);
        FakeEvents events = new FakeEvents();
        MobilePipelineCoordinator.StartResult result = prepareAndOpen(
                new MobilePipelineCoordinator(pipeline, events),
                "/native", "/skeleton", 0L);

        require(!result.started && result.message.contains("Required transport unavailable"));
        require(("stop," + PREPARE_CALL + ",configure:416:416")
                .equals(pipeline.calls));
        require(("mobile_pipeline_prepare_requested,mobile_pipeline_prepared,"
                + "mobile_pipeline_data_plane_open_requested,"
                + "mobile_pipeline_data_plane_open_failed").equals(events.events));
    }

    private static void verifiesCompleteThrowableStackIsPersisted() {
        FakeEvents events = new FakeEvents();
        MobilePipelineCoordinator.StartResult result = prepareAndOpen(
                new MobilePipelineCoordinator(new ThrowingPipeline(), events),
                "/native", "/skeleton", 57L);

        require(!result.started);
        require(result.message.contains("java.lang.IllegalStateException: native-outer"));
        require(result.message.contains("Caused by: java.lang.IllegalArgumentException: native-inner"));
        require(result.message.contains("ThrowingPipeline.prepareQnn"));
        require(events.details.contains("Caused by: java.lang.IllegalArgumentException: native-inner"));
    }

    private static void verifiesPrepareOpenAndLeaseCloseAreSeparate() {
        FakePipeline pipeline = new FakePipeline(true, true, true);
        FakeEvents events = new FakeEvents();
        MobilePipelineCoordinator coordinator =
                new MobilePipelineCoordinator(pipeline, events);
        MobilePipelineCoordinator.PrepareResult prepared =
                coordinator.prepareDataPlaneClosed(
                        "/native", "/skeleton", MobileModelCatalog.DEFAULT);
        require(prepared.prepared);
        require(coordinator.isPreparedDataPlaneClosed());
        require(("stop,prepare:/native:/skeleton:"
                + MobileModelCatalog.DEFAULT.token + ",configure:416:416")
                .equals(pipeline.calls));
        MobilePipelineCoordinator.StartResult opened =
                coordinator.openPreparedDataPlane(
                        endpoint(57L), MobileModelCatalog.DEFAULT);
        require(opened.started);
        require(pipeline.calls.endsWith(
                "receiver:10.57.23.2:10.57.23.1:5000:57"));
        coordinator.closeDataPlane();
        require(pipeline.calls.endsWith("stop_receiver,stop_decoder"));
        require(coordinator.isPreparedDataPlaneClosed());
        String callsAfterFirstClose = pipeline.calls;
        String eventsAfterFirstClose = events.events;
        coordinator.closeDataPlane();
        require(pipeline.calls.equals(callsAfterFirstClose));
        require(events.events.equals(eventsAfterFirstClose));

        MobilePipelineCoordinator.StartResult reopened =
                coordinator.openPreparedDataPlane(
                        endpoint(57L), MobileModelCatalog.DEFAULT);
        require(reopened.started);
        require(pipeline.calls.endsWith(
                "stop_receiver,stop_decoder,configure:416:416,"
                        + "receiver:10.57.23.2:10.57.23.1:5000:57"));
        require(pipeline.calls.indexOf("prepare:")
                == pipeline.calls.lastIndexOf("prepare:"));
    }

    private static void verifiesPreparedModelMismatchFailsClosed() {
        FakePipeline pipeline = new FakePipeline(true, true, true);
        MobilePipelineCoordinator coordinator =
                new MobilePipelineCoordinator(pipeline, new FakeEvents());
        MobilePipelineCoordinator.PrepareResult prepared =
                coordinator.prepareDataPlaneClosed(
                        "/native", "/skeleton", MobileModelCatalog.VALORANT);
        require(prepared.prepared);
        MobilePipelineCoordinator.StartResult opened =
                coordinator.openPreparedDataPlane(
                        endpoint(57L), MobileModelCatalog.DELTA_FORCE);
        require(!opened.started);
        require(opened.message.contains("prepared_qnn_model_mismatch"));
        require(!pipeline.calls.contains("receiver:"));
    }

    private static void verifiesFailedCloseRemainsRetryable() {
        RetryingClosePipeline pipeline = new RetryingClosePipeline();
        FakeEvents events = new FakeEvents();
        MobilePipelineCoordinator coordinator =
                new MobilePipelineCoordinator(pipeline, events);
        require(prepareAndOpen(
                coordinator, "/native", "/skeleton", 57L).started);
        try {
            coordinator.closeDataPlane();
            throw new AssertionError("first close failure was expected");
        } catch (IllegalStateException expected) {
            require(pipeline.closeAttempts == 1);
            require(!events.events.contains(
                    "mobile_pipeline_data_plane_closed"));
        }
        coordinator.closeDataPlane();
        require(pipeline.closeAttempts == 2);
        require(events.events.endsWith(
                "mobile_pipeline_data_plane_closed"));
        coordinator.closeDataPlane();
        require(pipeline.closeAttempts == 2);
    }

    private static void verifiesPortableBackendUsesExplicitModelPath() {
        PortableFakePipeline pipeline = new PortableFakePipeline();
        MobilePipelineCoordinator coordinator =
                new MobilePipelineCoordinator(pipeline, new FakeEvents());
        MobilePipelineCoordinator.PrepareResult prepared =
                coordinator.prepareDataPlaneClosed(
                        MobileInferenceBackend.ONNXRUNTIME_NNAPI,
                        "/native",
                        "",
                        "/models/valorant.onnx",
                        MobileModelCatalog.VALORANT);
        require(prepared.prepared);
        require(pipeline.calls.contains(
                "prepare:onnxruntime_nnapi:/native::/models/valorant.onnx:"
                        + MobileModelCatalog.VALORANT.token));
        require(MobileInferenceBackend.ONNXRUNTIME_NNAPI.token.equals(
                coordinator.preparedBackendToken()));
    }

    private static void verifiesPortableBackendRejectsMissingModelBeforeNativeCall() {
        PortableFakePipeline pipeline = new PortableFakePipeline();
        MobilePipelineCoordinator coordinator =
                new MobilePipelineCoordinator(pipeline, new FakeEvents());
        MobilePipelineCoordinator.PrepareResult prepared =
                coordinator.prepareDataPlaneClosed(
                        MobileInferenceBackend.ONNXRUNTIME_CPU,
                        "/native",
                        "",
                        " ",
                        MobileModelCatalog.VALORANT);
        require(!prepared.prepared);
        require("portable_model_unavailable".equals(prepared.failureCode));
        require(pipeline.calls.isEmpty());
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Mobile pipeline lifecycle contract failed");
    }

    private static MobilePipelineCoordinator.StartResult prepareAndOpen(
            MobilePipelineCoordinator coordinator,
            String nativeDirectory,
            String skeletonDirectory,
            long networkHandle) {
        MobilePipelineCoordinator.PrepareResult prepared =
                coordinator.prepareDataPlaneClosed(
                        nativeDirectory, skeletonDirectory, MobileModelCatalog.DEFAULT);
        if (!prepared.prepared) {
            return MobilePipelineCoordinator.StartResult.failure(
                    prepared.message,
                    prepared.disposition,
                    prepared.failureCode);
        }
        return coordinator.openPreparedDataPlane(
                networkHandle <= 0L ? null : endpoint(networkHandle),
                MobileModelCatalog.DEFAULT);
    }

    private static MobileTransportEndpoint endpoint(long networkHandle) {
        return MobileTransportEndpointTestFixtures.cat6(networkHandle);
    }

    private static class FakePipeline implements NativeVideoInferencePipeline {
        private final boolean qnnPrepared;
        private final boolean decoderConfigured;
        private final boolean receiverStarted;
        private final String qnnReport;
        private String calls = "";

        FakePipeline(boolean qnnPrepared, boolean decoderConfigured, boolean receiverStarted) {
            this(qnnPrepared, decoderConfigured, receiverStarted, "ready=0");
        }

        FakePipeline(boolean qnnPrepared, boolean decoderConfigured, boolean receiverStarted,
                     String qnnReport) {
            this.qnnPrepared = qnnPrepared;
            this.decoderConfigured = decoderConfigured;
            this.receiverStarted = receiverStarted;
            this.qnnReport = qnnReport;
        }

        @Override public boolean prepareQnn(
                String nativeDirectory, String skeletonDirectory, String modelToken) {
            append("prepare:" + nativeDirectory + ":" + skeletonDirectory + ":" + modelToken);
            return qnnPrepared;
        }
        @Override public boolean configureInferenceDecoder(int width, int height) {
            append("configure:" + width + ":" + height);
            return decoderConfigured;
        }
        @Override public boolean startVideoReceiver(
                String localIpv4, String expectedSourceIpv4, int port, long networkHandle) {
            append("receiver:" + localIpv4 + ":" + expectedSourceIpv4
                    + ":" + port + ":" + networkHandle);
            return receiverStarted;
        }
        @Override public void stopVideoReceiver() { append("stop_receiver"); }
        @Override public void stopInferenceDecoder() { append("stop_decoder"); }
        @Override public void stop() { append("stop"); }
        @Override public String qnnReport() { return qnnReport; }
        @Override public String videoReceiverReport() {
            return "startup_stage=local_bind_failed startup_errno=98";
        }
        private void append(String value) { calls = calls.isEmpty() ? value : calls + "," + value; }
    }

    private static final class RetryingClosePipeline extends FakePipeline {
        int closeAttempts;

        RetryingClosePipeline() {
            super(true, true, true);
        }

        @Override
        public void stopVideoReceiver() {
            super.stopVideoReceiver();
            closeAttempts++;
            if (closeAttempts == 1) {
                throw new IllegalStateException(
                        "simulated receiver close failure");
            }
        }
    }

    private static final class FakeEvents implements MobileRuntimeEventSink {
        private String events = "";
        private String details = "";

        @Override public void write(String event, String detail) {
            events = events.isEmpty() ? event : events + "," + event;
            details = details.isEmpty() ? detail : details + "\n" + detail;
        }
    }

    private static final class PortableFakePipeline
            implements NativeVideoInferencePipeline {
        private String calls = "";

        @Override public boolean prepareQnn(
                String nativeDirectory,
                String skeletonDirectory,
                String modelToken) {
            return false;
        }

        @Override public boolean prepareInference(
                String backendToken,
                String nativeDirectory,
                String vendorRuntimeDirectory,
                String portableModelPath,
                String modelToken) {
            append("prepare:" + backendToken + ":" + nativeDirectory
                    + ":" + vendorRuntimeDirectory + ":" + portableModelPath
                    + ":" + modelToken);
            return true;
        }

        @Override public boolean configureInferenceDecoder(int width, int height) {
            append("configure:" + width + ":" + height);
            return true;
        }

        @Override public boolean startVideoReceiver(
                String localIpv4,
                String expectedSourceIpv4,
                int port,
                long networkHandle) {
            return true;
        }

        @Override public void stopVideoReceiver() {
        }

        @Override public void stopInferenceDecoder() {
        }

        @Override public void stop() {
            append("stop");
        }

        @Override public String qnnReport() {
            return "ready=1";
        }

        @Override public String videoReceiverReport() {
            return "running=0";
        }

        private void append(String value) {
            calls = calls.isEmpty() ? value : calls + "," + value;
        }
    }

    private static final class ThrowingPipeline implements NativeVideoInferencePipeline {
        @Override public boolean prepareQnn(
                String nativeDirectory, String skeletonDirectory, String modelToken) {
            throw new IllegalStateException(
                    "native-outer", new IllegalArgumentException("native-inner"));
        }
        @Override public boolean configureInferenceDecoder(int width, int height) { return true; }
        @Override public boolean startVideoReceiver(
                String localIpv4, String expectedSourceIpv4,
                int port, long networkHandle) { return true; }
        @Override public void stopVideoReceiver() {
        }
        @Override public void stopInferenceDecoder() {
        }
        @Override public void stop() {
        }
        @Override public String qnnReport() { return "unreachable"; }
        @Override public String videoReceiverReport() { return "unreachable"; }
    }
}
