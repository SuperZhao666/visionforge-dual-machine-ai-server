package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Guards decoder stop/restart drain accounting without requiring MediaCodec. */
final class FlexibleYuvMediaCodecDecoderContractSelfTest {
    private static final String PROJECT_DIRECTORY_PROPERTY =
            "visionforge.android.project.dir";

    private FlexibleYuvMediaCodecDecoderContractSelfTest() {
    }

    static void run() throws Exception {
        String projectDirectory = System.getProperty(PROJECT_DIRECTORY_PROPERTY, "");
        require(!projectDirectory.isEmpty());
        Path decoderPath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "FlexibleYuvMediaCodecDecoder.java");
        String source = new String(Files.readAllBytes(decoderPath), StandardCharsets.UTF_8);
        Path nativeDecoderPath = Paths.get(
                projectDirectory, "src", "main", "cpp", "NativeH264Decoder.cpp");
        String nativeSource = new String(
                Files.readAllBytes(nativeDecoderPath), StandardCharsets.UTF_8);
        Path nativeDecoderHeaderPath = Paths.get(
                projectDirectory, "src", "main", "cpp", "NativeH264Decoder.hpp");
        String nativeHeader = new String(
                Files.readAllBytes(nativeDecoderHeaderPath), StandardCharsets.UTF_8);
        Path inputQueuePath = Paths.get(projectDirectory, "src", "main", "java", "com",
                "visionforge", "inferencebenchmark", "DecoderAccessUnitQueue.java");
        String inputQueueSource = new String(
                Files.readAllBytes(inputQueuePath), StandardCharsets.UTF_8);
        Path qnnBridgePath = Paths.get(
                projectDirectory, "src", "main", "cpp", "QnnHtpBridge.cpp");
        String qnnBridgeSource = new String(
                Files.readAllBytes(qnnBridgePath), StandardCharsets.UTF_8);
        Path makcuBridgePath = Paths.get(
                projectDirectory, "src", "main", "cpp", "MakcuMoveBridge.cpp");
        String makcuBridgeSource = new String(
                Files.readAllBytes(makcuBridgePath), StandardCharsets.UTF_8);

        require(source.contains("MediaFormat.KEY_PRIORITY"));
        require(source.contains("MediaFormat.KEY_OPERATING_RATE"));
        require(source.contains("MediaFormat.KEY_LOW_LATENCY"));
        require(source.contains("maximumAdvertisedOperatingRate(created, width, height)"));
        require(source.contains("getSupportedFrameRatesFor(width, height)"));
        require(source.contains(".getUpper()"));
        require(!source.contains("MAXIMUM_EXPECTED_INPUT_FPS"));
        require(source.contains("private static final class DecoderOutputState"));
        require(!source.contains("private int consecutiveOutputFailures;"));
        require(!source.contains(
                "private final DecoderOutputProgressTracker outputProgress"));

        String replacementMethod = methodSlice(
                source, "private boolean startReplacement(",
                "/** Copies into a bounded FIFO;");
        int lockedGenerationCheck = replacementMethod.lastIndexOf(
                "lifecycleGeneration.get() != generation");
        int fatalReset = replacementMethod.indexOf("fatalFailure.set(false)");
        require(lockedGenerationCheck >= 0 && fatalReset > lockedGenerationCheck);
        require(replacementMethod.indexOf(
                "decoderOutputState = activeOutputState") < fatalReset);

        String outputLoop = methodSlice(
                source, "private void drainOutput(",
                "private void offerImageToNative(");
        require(outputLoop.contains("DecoderOutputState activeOutputState"));
        require(outputLoop.contains("activeOutputState.progress"));
        require(outputLoop.contains("failActiveDecoder("));
        require(!outputLoop.contains("running.set(false)"));

        String activeFailureCommit = methodSlice(
                source, "private boolean failActiveDecoder(",
                "boolean hasFatalFailure()");
        require(activeFailureCommit.contains("synchronized (lifecycleLock)"));
        require(activeFailureCommit.indexOf("codec != candidate")
                < activeFailureCommit.indexOf("running.set(false)"));
        require(activeFailureCommit.indexOf("running.set(false)")
                < activeFailureCommit.indexOf("recordDecoderFailure("));

        String detachMethod = methodSlice(
                source, "private void detachAndReleaseActiveCodec(String reason)",
                "private void drainInput(");
        require(detachMethod.contains("oldInputQueue.closeAndDrain()"));
        require(detachMethod.contains("\"input_restart_flush\" : \"input_stop_flush\""));

        String discardHelper = methodSlice(
                source, "private void discardDrainedInputs(",
                "private static void releaseCodecAfterWorkersExitAsync(");
        require(discardHelper.contains("QnnHtpBridge.discardNativeCompressedAccessUnit("));
        require(discardHelper.contains("owner.recycle(accessUnit);"));
        require(discardHelper.contains("inputStopFlushDrops.addAndGet(discarded.size())"));
        require(source.contains("stop_flush_drops="));

        String queueInputMethod = methodSlice(
                source, "private boolean queueInputWhenAvailable(",
                "private void discardStaleBeforeCodec(");
        require(queueInputMethod.indexOf("DecoderAccessUnitQueue.isStale(")
                < queueInputMethod.indexOf("activeCodec.dequeueInputBuffer("));
        require(source.contains("activeInputQueue.enterReferenceRecoveryAndDrain()"));
        require(source.contains("stale_before_codec_drops="));
        require(inputQueueSource.contains("takeReusableAccessUnit(size)"));
        require(inputQueueSource.contains("copyWithoutChangingSource("));
        require(!inputQueueSource.contains("source.duplicate()"));

        String failedInput = methodSlice(
                source, "private void failInput(",
                "private void discardDrainedInputs(");
        require(failedInput.contains("failActiveDecoder(activeCodec"));
        require(failedInput.contains("input_stale_generation"));
        require(!failedInput.contains("running.set(false)"));

        require(nativeSource.contains("kInferenceQueueCapacity = 1;"));
        String inferenceLoop = methodSlice(
                nativeSource, "void NativeH264Decoder::inference_loop()",
                "std::optional<std::uint64_t> NativeH264Decoder::commit_qnn_failure(");
        int executeQnn = inferenceLoop.indexOf("execute_realtime_inference(");
        require(inferenceLoop.indexOf("kMobileControlMaximumFrameAgeUs")
                < executeQnn);
        int preQnnGenerationCheck = inferenceLoop.indexOf(
                "is_current_stream_generation_locked(frame.stream_generation)");
        require(preQnnGenerationCheck >= 0 && preQnnGenerationCheck < executeQnn);
        require(inferenceLoop.indexOf("commit_qnn_failure(") > executeQnn);
        require(inferenceLoop.indexOf("commit_qnn_success(") > executeQnn);
        require(inferenceLoop.indexOf("++stale_generation_inference_suppressions_")
                < executeQnn);
        String qnnFailureCommit = methodSlice(
                nativeSource,
                "std::optional<std::uint64_t> NativeH264Decoder::commit_qnn_failure(",
                "NativeH264Decoder::QnnSuccessCommit NativeH264Decoder::commit_qnn_success(");
        require(qnnFailureCommit.indexOf("is_current_stream_generation_locked(generation)")
                < qnnFailureCommit.indexOf("++qnn_failures_"));
        require(qnnFailureCommit.contains("++stale_generation_result_suppressions_"));
        String qnnSuccessCommit = methodSlice(
                nativeSource,
                "NativeH264Decoder::QnnSuccessCommit NativeH264Decoder::commit_qnn_success(",
                "void NativeH264Decoder::process_output_locked(");
        require(qnnSuccessCommit.indexOf(
                "is_current_stream_generation_locked(frame.stream_generation)")
                < qnnSuccessCommit.indexOf("++qnn_executions_"));
        require(qnnSuccessCommit.contains("++stale_generation_result_suppressions_"));
        require(qnnSuccessCommit.contains("last_detections_.swap(detections)"));
        require(nativeSource.contains("stale_pre_inference_frames="));
        require(nativeSource.contains("stale_generation_inference_suppressions="));
        require(nativeSource.contains("stale_generation_result_suppressions="));
        require(nativeHeader.contains(
                "FixedMetricRing<std::uint64_t, kLatencySampleCapacity> qnn_samples_us_"));
        require(nativeHeader.contains(
                "FixedMetricRing<PipelineMetric, kPipelineMetricCapacity> pipeline_metrics_"));
        require(nativeSource.contains("samples.push(value)"));
        require(nativeSource.contains("pipeline_metrics_.push({"));
        require(!nativeSource.contains("samples.erase(samples.begin())"));

        String makcuSuspend = methodSlice(
                makcuBridgeSource, "void suspend_makcu_output_for_recovery(",
                "bool resume_makcu_output_after_valid_frame(");
        require(makcuSuspend.indexOf("std::scoped_lock publish_lock(g_publish_mutex)")
                < makcuSuspend.indexOf(
                "g_stream_generation_gate.activate(generation)"));
        String makcuPublish = methodSlice(
                makcuBridgeSource, "void publish_makcu_move_for_detections(",
                "void report_makcu_move_result(");
        require(makcuPublish.contains("std::uint64_t stream_generation"));
        require(makcuPublish.indexOf(
                "g_stream_generation_gate.accepts(stream_generation)")
                < makcuPublish.indexOf("++g_processed_frames"));
        require(makcuPublish.indexOf("++g_stale_stream_generation_suppressed")
                < makcuPublish.indexOf("g_control_core.process("));

        String javaYuvOutput = methodSlice(
                nativeSource, "bool NativeH264Decoder::process_java_yuv420(",
                "void NativeH264Decoder::update_java_decoder_format(");
        int repeatSuppression = javaYuvOutput.indexOf(
                "if (!pending_metadata->content_updated)");
        require(repeatSuppression >= 0);
        require(repeatSuppression < javaYuvOutput.indexOf(
                "preprocess_yuv420_to_model_rgb("));
        require(javaYuvOutput.contains(
                "++repeated_content_inference_suppressions_"));
        int stateUnlock = javaYuvOutput.indexOf("lock.unlock();");
        int preprocess = javaYuvOutput.indexOf("preprocess_yuv420_to_model_rgb(");
        int stateRelock = javaYuvOutput.indexOf("lock.lock();", preprocess);
        require(javaYuvOutput.contains(
                "std::scoped_lock callback_lock(java_output_callback_mutex_)"));
        require(stateUnlock >= 0 && stateUnlock < preprocess);
        require(stateRelock > preprocess);
        require(javaYuvOutput.indexOf(
                "is_current_stream_generation_locked(pending_metadata->stream_generation)")
                > stateRelock);
        String nativeStop = methodSlice(
                nativeSource, "void NativeH264Decoder::stop()",
                "void NativeH264Decoder::recycle_pending_inference_frames_locked()");
        require(nativeStop.contains(
                "std::scoped_lock callback_lock(java_output_callback_mutex_)"));

        String realtimeQnn = methodSlice(
                qnnBridgeSource, "bool executeRealtime(", " private:");
        int directInputBinding = realtimeQnn.indexOf(
                "const_cast<uint8_t*>(input.data())");
        int graphExecute = realtimeQnn.indexOf("qnn_.graphExecute(");
        int ownedInputRestore = realtimeQnn.indexOf(
                "input_, inputBuffer_.data()", graphExecute);
        require(directInputBinding >= 0 && directInputBinding < graphExecute);
        require(ownedInputRestore > graphExecute);
        require(!realtimeQnn.contains(
                "std::memcpy(inputBuffer_.data(), input.data(), input.size())"));
    }

    private static String methodSlice(String source, String start, String end) {
        int startIndex = source.indexOf(start);
        int endIndex = source.indexOf(end, startIndex + start.length());
        require(startIndex >= 0 && endIndex > startIndex);
        return source.substring(startIndex, endIndex);
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("Flexible YUV decoder contract failed");
        }
    }
}
