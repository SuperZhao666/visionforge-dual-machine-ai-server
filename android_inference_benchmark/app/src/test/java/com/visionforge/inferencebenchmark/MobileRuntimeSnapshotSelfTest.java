package com.visionforge.inferencebenchmark;

/**
 * Dependency-free regression test. Run with JDK 17 alongside
 * {@link MobileRuntimeSnapshot}; it intentionally avoids an online JUnit
 * dependency so this Android project remains buildable offline.
 */
public final class MobileRuntimeSnapshotSelfTest {
    public static void main(String[] args) throws Exception {
        verifiesLivePipelineSnapshot();
        verifiesStaleAndIncompleteReportsAreOffline();
        verifiesQnnFailureClosesExecutionHealth();
        verifiesQnnModelIdentityUsesNativeEvidence();
        verifiesPortableBackendIdentityUsesNativeEvidence();
        verifiesDiagnosticFieldsRequireExactTokens();
        MobileModelCatalogSelfTest.run();
        MobileControlTuningSelfTest.run();
        MobileProfileStorageKeysSelfTest.run();
        MobilePipelineCoordinatorSelfTest.run();
        HostVideoPresenceProbeSelfTest.run();
        com.visionforge.inferencebenchmark.video.VideoWireProtocolSelfTest.main(args);
        com.visionforge.inferencebenchmark.video.VideoPreflightReassemblyWindowSelfTest.main(args);
        com.visionforge.inferencebenchmark.video.DecoderRestartCoordinatorSelfTest.main(args);
        com.visionforge.inferencebenchmark.runtime.MobileRuntimeArchitectureSelfTest.main(args);
        AutomaticFormalUsageSessionGuardSelfTest.run();
        AutomaticUsageGuardCheckpointPolicySelfTest.run();
        AutomaticFormalStartRetryPolicySelfTest.run();
        HostVideoPreflightLogPolicySelfTest.run();
        FormalUsageStopRetryPolicySelfTest.run();
        MobilePipelineRetryGateSelfTest.run();
        ControlOutputCoordinatorSelfTest.run();
        BluetoothHidOutputFailClosedPolicySelfTest.run();
        ControlOutputRoutePolicySelfTest.run();
        Cat6MouseButtonProtocolSelfTest.run();
        Cat6MouseButtonEndpointPolicySelfTest.run();
        Cat6MouseButtonLeaseStateSelfTest.run();
        Cat6MouseButtonNotificationDispatcherSelfTest.run();
        Cat6MouseButtonWorkerRecoveryPolicySelfTest.run();
        BluetoothHidMouseTransportCoreSelfTest.run();
        BluetoothHidPendingOperationPolicySelfTest.run();
        BluetoothHidDebugMoveProbePolicySelfTest.run();
        BluetoothHidFailureModeSelfTest.run();
        BluetoothHidDeviceAdapterSourceContractSelfTest.run();
        MakcuDeviceIdentityPolicySelfTest.run();
        MakcuUsbInterfaceSelectorSelfTest.run();
        MakcuCdcLineCodingSelfTest.run();
        MakcuProtocolNegotiatorSelfTest.run();
        MakcuConnectionAttemptTrackerSelfTest.run();
        MakcuDeliveryCircuitSelfTest.run();
        MakcuDeliveryGateSelfTest.run();
        ControlMoveDeadlineSelfTest.run();
        MakcuResponseStreamParserSelfTest.run();
        ControlTriggerSelfTest.run();
        MakcuJniContractSelfTest.run();
        MobileThroughputTrackerSelfTest.run();
        MobileRuntimeMetricsSamplerSelfTest.run();
        MobileExternalHealthSnapshotPolicySelfTest.run();
        MobileExternalHealthSnapshotFormatterSelfTest.run();
        MobileExternalHealthSnapshotWriterSelfTest.run();
        MobilePreviousExitPolicySelfTest.run();
        MobileServiceDestroyCleanupSelfTest.run();
        MobileRuntimeFailureMessagePolicySelfTest.run();
        MobileRuntimePresentationUpdatePolicySelfTest.run();
        AuthorizationFailureMessagePolicySelfTest.run();
        DecoderAccessUnitQueueSelfTest.run();
        FlexibleYuvMediaCodecDecoderContractSelfTest.run();
        MobileDetectionTraceCoordinatorSelfTest.run();
        InferencePolicySelfTest.run();
        DecoderOutputStallPolicySelfTest.run();
        QnnAssetBundleInstallerSelfTest.run();
        MobileSocCompatibilityPolicySelfTest.run();
        MobileInferenceBackendPolicySelfTest.run();
        MobileInferenceFailurePolicySelfTest.run();
        PortableModelAssetInstallerSelfTest.run();
        QnnHtpCompatibilityPolicySelfTest.run();
        MobileInstallCompatibilityManifestSelfTest.run();
        MobileEthernetRecoveryCoordinatorSelfTest.run();
        DualMachineAuthorizationCardModeContractSelfTest.run();
        MobileRuntimeServiceCommandContractSelfTest.run();
        MobileRuntimeHealthLogPolicySelfTest.run();
        MobileControlHealthSummarySelfTest.run();
        MobileEthernetDiagnosticsLogPolicySelfTest.run();
        Cat6ReadyAgentLogPolicySelfTest.run();
        AutomaticUsageReservationLogPolicySelfTest.run();
        MobileLogSanitizerSelfTest.run();
        MobileProcessLoggingSourceContractSelfTest.run();
        com.visionforge.inferencebenchmark.ui.MobileUiStateMapperSelfTest.run();
        com.visionforge.inferencebenchmark.ui.UiPreviewStateSelfTest.run();
        com.visionforge.inferencebenchmark.ui.FxParticleEngineSelfTest.run();
        com.visionforge.inferencebenchmark.ui.FxTransitionPolicySelfTest.run();
    }

    private static void verifiesLivePipelineSnapshot() {
        MobileRuntimeSnapshot snapshot = MobileRuntimeSnapshot.from(
                "UDP receiver running=1 accepted_datagrams=90 reassembled_access_units=44 "
                        + "decoder_accepted_access_units=42 completed_access_units=42 "
                        + "repeated_content_access_units=10 "
                        + "last_logical_frame_sequence=912 "
                        + "dropped_access_units=0 idr_requests=0 "
                        + "last_reassembled_access_unit_age_ms=9 last_completed_access_unit_age_ms=13",
                "configured=1 rendered_frames=40 fresh_content_outputs=30 "
                        + "repeated_content_outputs=10 qnn_executions=30 qnn_failures=0 "
                        + "consecutive_qnn_failures=0 last_qnn_success_age_ms=7 "
                        + "preprocess{n=40 p50_us=2560 p95_us=3300} "
                        + "qnn{n=40 p50_us=1700 p95_us=2100} "
                        + "decode_queue{n=40 p50_us=6200 p95_us=8500} "
                        + "makcu_bridge{output_requested=1 output_recovery_suspended=1 "
                        + "output_enabled=0 motion_uncalibrated_maximum_axis_delta=32 "
                        + "motion_maximum_step_counts_per_tick=24 "
                        + "motion_maximum_jerk_counts_per_tick2=12}",
                "ready=1 backend=QNN HTP",
                "MAKCU protocol verified serial_open=1 adapter_identity_verified=1 "
                        + "protocol_identity_verified=1 delivery_circuit_open=0");

        require(snapshot.receiverRunning && snapshot.decoderReady && snapshot.qnnReady);
        require(snapshot.qnnExecutionLive && snapshot.consecutiveQnnFailures == 0L
                && snapshot.lastQnnSuccessAgeMillis == 7L);
        require("QNN HTP".equals(snapshot.qnnRuntimeLabel));
        require(snapshot.makcuReady && snapshot.videoLinkLive);
        require(snapshot.reassembledAccessUnits == 44L
                && snapshot.decoderAcceptedAccessUnits == 42L
                && snapshot.completedAccessUnits == 42L
                && snapshot.repeatedContentAccessUnits == 10L
                && snapshot.freshContentAccessUnits == 32L
                && snapshot.freshDecodedFrameCount == 30L
                && snapshot.qnnExecutionCount == 30L
                && snapshot.lastLogicalFrameSequence == 912L
                && snapshot.lastVideoAgeMillis == 9L);
        require("40".equals(snapshot.renderedFrames) && "2.56 ms".equals(snapshot.preprocessP50));
        require("1.70 ms".equals(snapshot.qnnP50) && "2.10 ms".equals(snapshot.qnnP95));
        require("6.20 ms".equals(snapshot.decodeQueueP50));
        require(snapshot.effectiveUncalibratedMaximumAxisDelta == 32
                && Float.compare(snapshot.maximumStepCountsPerTick, 24.0f) == 0
                && Float.compare(snapshot.maximumJerkCountsPerTick2, 12.0f) == 0);
        require(snapshot.nativeControlOutputRequestedKnown
                && snapshot.nativeControlOutputRequested
                && snapshot.nativeControlOutputRecoverySuspended
                && !snapshot.nativeControlOutputEffective);
    }

    private static void verifiesQnnFailureClosesExecutionHealth() {
        MobileRuntimeSnapshot snapshot = MobileRuntimeSnapshot.from(
                "running=1 last_reassembled_access_unit_age_ms=3",
                "configured=1 qnn_executions=90 qnn_failures=3 "
                        + "consecutive_qnn_failures=1 last_qnn_success_age_ms=11",
                "ready=1", "");
        require(snapshot.qnnReady && !snapshot.qnnExecutionLive);

        MobileRuntimeSnapshot stale = MobileRuntimeSnapshot.from(
                "running=1 last_reassembled_access_unit_age_ms=3",
                "configured=1 qnn_executions=90 qnn_failures=0 "
                        + "consecutive_qnn_failures=0 last_qnn_success_age_ms=2001",
                "ready=1", "");
        require(!stale.qnnExecutionLive);
    }

    private static void verifiesStaleAndIncompleteReportsAreOffline() {
        MobileRuntimeSnapshot snapshot = MobileRuntimeSnapshot.from(
                "UDP receiver running=1 completed_access_units=7 last_completed_access_unit_age_ms=2001",
                "configured=0", "ready=0", "MAKCU not connected");

        require(snapshot.receiverRunning && !snapshot.videoLinkLive);
        require(!snapshot.decoderReady && !snapshot.qnnReady && !snapshot.makcuReady);
        require(snapshot.reassembledAccessUnits == 7L
                && snapshot.decoderAcceptedAccessUnits == 7L
                && snapshot.completedAccessUnits == 7L);
        require("--".equals(snapshot.preprocessP50) && "--".equals(snapshot.qnnExecutions));
    }

    private static void verifiesQnnModelIdentityUsesNativeEvidence() {
        MobileRuntimeSnapshot snapshot = MobileRuntimeSnapshot.from("running=0", "configured=0",
                "ready=1 backend=QNN HTP; model=valorant-yellow-416-v11s-no-flash; "
                        + "precision=W8A16; outputs=FP32 split; graph=1", "");
        require(snapshot.qnnUsesSplitOutput && "QNN HTP / W8A16".equals(snapshot.qnnRuntimeLabel));
    }

    private static void verifiesPortableBackendIdentityUsesNativeEvidence() {
        MobileRuntimeSnapshot nnapi = MobileRuntimeSnapshot.from(
                "running=0", "configured=0",
                "ready=1 backend=ONNX Runtime NNAPI "
                        + "backend_token=onnxruntime_nnapi "
                        + "outputs=FP32_split probe_execution=success", "");
        require(nnapi.qnnReady && nnapi.qnnUsesSplitOutput);
        require("ONNX Runtime / NNAPI".equals(nnapi.qnnRuntimeLabel));

        MobileRuntimeSnapshot cpu = MobileRuntimeSnapshot.from(
                "running=0", "configured=0",
                "ready=1 backend_token=onnxruntime_cpu "
                        + "outputs=FP32_split probe_execution=success", "");
        require("ONNX Runtime / CPU".equals(cpu.qnnRuntimeLabel));
    }

    private static void verifiesDiagnosticFieldsRequireExactTokens() {
        MobileRuntimeSnapshot prefixed = MobileRuntimeSnapshot.from(
                "not_running=1 running=0 "
                        + "shadow_reassembled_access_units=99 reassembled_access_units=7 "
                        + "last_reassembled_access_unit_age_ms=5",
                "decoder_configured=1 configured=0 "
                        + "shadow_output_requested=1 output_requested=0 "
                        + "shadow_output_enabled=1 output_enabled=0 "
                        + "preprocess{shadow_p50_us=9999 p50_us=1000}",
                "graph_ready=1 ready=0",
                "backup_serial_open=1 serial_open=0 "
                        + "adapter_identity_verified=1 protocol_identity_verified=1 "
                        + "delivery_circuit_open=0");

        require(!prefixed.receiverRunning
                && !prefixed.decoderReady
                && !prefixed.qnnReady
                && !prefixed.makcuReady);
        require(prefixed.reassembledAccessUnits == 7L);
        require(prefixed.nativeControlOutputRequestedKnown
                && !prefixed.nativeControlOutputRequested
                && !prefixed.nativeControlOutputEffective);
        require("1.00 ms".equals(prefixed.preprocessP50));

        MobileRuntimeSnapshot nonBoolean = MobileRuntimeSnapshot.from(
                "running=10 last_reassembled_access_unit_age_ms=1",
                "configured=10", "ready=10", null);
        require(!nonBoolean.receiverRunning
                && !nonBoolean.decoderReady
                && !nonBoolean.qnnReady
                && !nonBoolean.makcuReady);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Mobile runtime snapshot contract failed");
    }
}
