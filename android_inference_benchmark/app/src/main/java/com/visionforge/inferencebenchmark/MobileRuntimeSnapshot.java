package com.visionforge.inferencebenchmark;

import java.util.Locale;

/**
 * Immutable runtime snapshot parsed from native subsystem reports.
 * Native reports stay diagnostic text; this class is the shared service/UI
 * parser, preventing lifecycle owners and views from interpreting them
 * differently.
 */
final class MobileRuntimeSnapshot {
    static final long LIVE_VIDEO_MAX_AGE_MILLIS = 2_000L;
    static final long LIVE_QNN_MAX_AGE_MILLIS = 2_000L;

    final String videoReport;
    final String decoderReport;
    final String qnnReport;
    final String makcuReport;
    final boolean receiverRunning;
    final boolean decoderReady;
    final boolean qnnReady;
    final String qnnRuntimeLabel;
    final boolean qnnUsesSplitOutput;
    final boolean makcuReady;
    final boolean nativeControlOutputRequestedKnown;
    final boolean nativeControlOutputRequested;
    final boolean nativeControlOutputEffective;
    final boolean nativeControlOutputRecoverySuspended;
    final long reassembledAccessUnits;
    final long decoderAcceptedAccessUnits;
    final long completedAccessUnits;
    final long repeatedContentAccessUnits;
    final long freshContentAccessUnits;
    final long lastLogicalFrameSequence;
    final long lastVideoAgeMillis;
    final boolean videoLinkLive;
    final long renderedFrameCount;
    final long freshDecodedFrameCount;
    final long repeatedDecodedFrameCount;
    final long qnnExecutionCount;
    final long consecutiveQnnFailures;
    final long lastQnnSuccessAgeMillis;
    final boolean qnnExecutionLive;
    final String renderedFrames;
    final String qnnExecutions;
    final String qnnFailures;
    final String preprocessP50;
    final String qnnP50;
    final String qnnP95;
    final String inferenceTotalP50;
    final String decodeQueueP50;
    final double preprocessP50Millis;
    final double qnnP50Millis;
    final double inferenceTotalP50Millis;
    final double decodeQueueP50Millis;
    final int effectiveUncalibratedMaximumAxisDelta;
    final float maximumStepCountsPerTick;
    final float maximumJerkCountsPerTick2;

    private MobileRuntimeSnapshot(String videoReport, String decoderReport, String qnnReport,
                                  String makcuReport) {
        videoReport = safeReport(videoReport);
        decoderReport = safeReport(decoderReport);
        qnnReport = safeReport(qnnReport);
        makcuReport = safeReport(makcuReport);
        this.videoReport = videoReport;
        this.decoderReport = decoderReport;
        this.qnnReport = qnnReport;
        this.makcuReport = makcuReport;
        receiverRunning = containsReady(videoReport, "running");
        decoderReady = containsReady(decoderReport, "configured");
        qnnReady = containsReady(qnnReport, "ready");
        qnnUsesSplitOutput = qnnReport.contains("outputs=FP32 split")
                || qnnReport.contains("outputs=FP32_split")
                || qnnReport.contains("model=QNN W8A16 split-output");
        if (qnnReport.contains("backend_token=onnxruntime_nnapi")
                || qnnReport.contains("backend=ONNX Runtime NNAPI")) {
            qnnRuntimeLabel = "ONNX Runtime / NNAPI";
        } else if (qnnReport.contains("backend_token=onnxruntime_cpu")
                || qnnReport.contains("backend=ONNX Runtime CPU")) {
            qnnRuntimeLabel = "ONNX Runtime / CPU";
        } else {
            qnnRuntimeLabel = qnnUsesSplitOutput
                    ? "QNN HTP / W8A16" : "QNN HTP";
        }
        makcuReady = containsReady(makcuReport, "serial_open")
                && containsReady(makcuReport, "adapter_identity_verified")
                && containsReady(makcuReport, "protocol_identity_verified")
                && !containsReady(makcuReport, "delivery_circuit_open");
        nativeControlOutputRequestedKnown = MobileDiagnosticFieldParser.hasField(
                decoderReport, "output_requested");
        nativeControlOutputRequested = containsReady(decoderReport, "output_requested");
        nativeControlOutputEffective = containsReady(decoderReport, "output_enabled");
        nativeControlOutputRecoverySuspended =
                containsReady(decoderReport, "output_recovery_suspended");
        long reassembled = longValue(videoReport, "reassembled_access_units");
        long decoderAccepted = longValue(videoReport, "decoder_accepted_access_units");
        completedAccessUnits = longValue(videoReport, "completed_access_units");
        long repeatedAccessUnits = longValue(
                videoReport, "repeated_content_access_units");
        repeatedContentAccessUnits = repeatedAccessUnits >= 0L
                ? repeatedAccessUnits : 0L;
        freshContentAccessUnits = completedAccessUnits >= repeatedContentAccessUnits
                ? completedAccessUnits - repeatedContentAccessUnits : -1L;
        lastLogicalFrameSequence = longValue(
                videoReport, "last_logical_frame_sequence");
        reassembledAccessUnits = reassembled >= 0L ? reassembled : completedAccessUnits;
        decoderAcceptedAccessUnits = decoderAccepted >= 0L ? decoderAccepted : completedAccessUnits;
        long reassembledAge = longValue(videoReport, "last_reassembled_access_unit_age_ms");
        lastVideoAgeMillis = reassembledAge >= 0L
                ? reassembledAge : longValue(videoReport, "last_completed_access_unit_age_ms");
        videoLinkLive = lastVideoAgeMillis >= 0 && lastVideoAgeMillis <= LIVE_VIDEO_MAX_AGE_MILLIS;
        renderedFrames = value(decoderReport, "rendered_frames");
        qnnExecutions = value(decoderReport, "qnn_executions");
        renderedFrameCount = longValue(decoderReport, "rendered_frames");
        long parsedFreshDecodedFrames = longValue(
                decoderReport, "fresh_content_outputs");
        freshDecodedFrameCount = parsedFreshDecodedFrames >= 0L
                ? parsedFreshDecodedFrames : renderedFrameCount;
        long parsedRepeatedDecodedFrames = longValue(
                decoderReport, "repeated_content_outputs");
        repeatedDecodedFrameCount = parsedRepeatedDecodedFrames >= 0L
                ? parsedRepeatedDecodedFrames
                : renderedFrameCount >= freshDecodedFrameCount
                ? renderedFrameCount - freshDecodedFrameCount : -1L;
        qnnExecutionCount = longValue(decoderReport, "qnn_executions");
        consecutiveQnnFailures = longValue(decoderReport, "consecutive_qnn_failures");
        lastQnnSuccessAgeMillis = longValue(decoderReport, "last_qnn_success_age_ms");
        qnnExecutionLive = qnnExecutionCount > 0L
                && consecutiveQnnFailures == 0L
                && lastQnnSuccessAgeMillis >= 0L
                && lastQnnSuccessAgeMillis <= LIVE_QNN_MAX_AGE_MILLIS;
        qnnFailures = value(decoderReport, "qnn_failures");
        preprocessP50 = latencyP50Millis(decoderReport, "preprocess{");
        qnnP50 = latencyP50Millis(decoderReport, "qnn{");
        qnnP95 = latencyMillis(decoderReport, "qnn{", "p95_us");
        inferenceTotalP50 = latencyP50Millis(decoderReport, "inference_total{");
        decodeQueueP50 = latencyP50Millis(decoderReport, "decode_queue{");
        preprocessP50Millis = latencyMillisValue(decoderReport, "preprocess{", "p50_us");
        qnnP50Millis = latencyMillisValue(decoderReport, "qnn{", "p50_us");
        inferenceTotalP50Millis = latencyMillisValue(
                decoderReport, "inference_total{", "p50_us");
        decodeQueueP50Millis = latencyMillisValue(decoderReport, "decode_queue{", "p50_us");
        effectiveUncalibratedMaximumAxisDelta = boundedAxisDelta(
                decoderReport, "motion_uncalibrated_maximum_axis_delta");
        maximumStepCountsPerTick = nonnegativeFloatValue(
                decoderReport, "motion_maximum_step_counts_per_tick");
        maximumJerkCountsPerTick2 = nonnegativeFloatValue(
                decoderReport, "motion_maximum_jerk_counts_per_tick2");
    }

    static MobileRuntimeSnapshot from(String videoReport, String decoderReport, String qnnReport,
                                      String makcuReport) {
        return new MobileRuntimeSnapshot(videoReport, decoderReport, qnnReport, makcuReport);
    }

    private static boolean containsReady(String report, String key) {
        return MobileDiagnosticFieldParser.isTrue(report, key);
    }

    private static String value(String report, String field) {
        return MobileDiagnosticFieldParser.valueOr(report, field, "--");
    }

    private static String safeReport(String report) {
        return report == null ? "" : report;
    }

    private static long longValue(String report, String key) {
        try {
            return Long.parseLong(value(report, key));
        } catch (NumberFormatException ignored) {
            return -1L;
        }
    }

    private static int boundedAxisDelta(String report, String key) {
        long parsed = longValue(report, key);
        return parsed >= 1L && parsed <= 127L ? (int) parsed : -1;
    }

    private static float nonnegativeFloatValue(String report, String key) {
        try {
            float parsed = Float.parseFloat(value(report, key));
            return Float.isFinite(parsed) && parsed >= 0.0f ? parsed : -1.0f;
        } catch (NumberFormatException ignored) {
            return -1.0f;
        }
    }

    private static String latencyP50Millis(String report, String section) {
        return latencyMillis(report, section, "p50_us");
    }

    private static String latencyMillis(String report, String section, String key) {
        double value = latencyMillisValue(report, section, key);
        return value >= 0.0 ? String.format(Locale.US, "%.2f ms", value) : "--";
    }

    private static double latencyMillisValue(String report, String section, String key) {
        int sectionStart = report.indexOf(section);
        if (sectionStart < 0) return -1.0;
        String microseconds = value(report.substring(sectionStart), key);
        try {
            return Long.parseLong(microseconds) / 1000.0;
        } catch (NumberFormatException ignored) {
            return -1.0;
        }
    }
}
