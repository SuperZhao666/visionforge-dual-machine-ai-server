package com.visionforge.inferencebenchmark;

/** Produces a bounded-rate, privacy-preserving runtime metric event payload. */
final class MobileRuntimeMetricsSampler {
    static final long SAMPLE_INTERVAL_MILLIS = 5_000L;
    static final long IDLE_HEARTBEAT_MILLIS = 300_000L;
    private long lastSampleMillis = -1L;
    private long lastWriteMillis = -1L;
    private long lastReassembledAccessUnits = -1L;
    private long lastFreshContentAccessUnits = -1L;
    private long lastDecoderAcceptedAccessUnits = -1L;
    private long lastRenderedFrames = -1L;
    private long lastFreshDecodedFrames = -1L;
    private long lastQnnExecutions = -1L;
    private boolean lastObservationChanged;

    String sampleIfDue(MobileRuntimeSnapshot snapshot, long monotonicMillis) {
        if (!snapshot.receiverRunning || !isDue(monotonicMillis)) return null;
        boolean firstSample = lastSampleMillis < 0L;
        MobileThroughputTracker.Rates windowRates = ratesForWindow(snapshot, monotonicMillis);
        boolean countersChanged = !firstSample && countersChanged(snapshot);
        boolean becameIdle = lastObservationChanged && !countersChanged;
        boolean heartbeatDue = lastWriteMillis >= 0L
                && nonNegativeDifference(monotonicMillis, lastWriteMillis)
                >= IDLE_HEARTBEAT_MILLIS;
        lastSampleMillis = monotonicMillis;
        lastReassembledAccessUnits = snapshot.reassembledAccessUnits;
        lastFreshContentAccessUnits = snapshot.freshContentAccessUnits;
        lastDecoderAcceptedAccessUnits = snapshot.decoderAcceptedAccessUnits;
        lastRenderedFrames = snapshot.renderedFrameCount;
        lastFreshDecodedFrames = snapshot.freshDecodedFrameCount;
        lastQnnExecutions = snapshot.qnnExecutionCount;
        lastObservationChanged = countersChanged;
        if (!firstSample && !countersChanged && !becameIdle && !heartbeatDue) return null;
        lastWriteMillis = monotonicMillis;
        return formatCurrent(snapshot, windowRates);
    }

    /** Formats the latest counters when a lifecycle snapshot must be written without a rate sample. */
    String formatCurrent(MobileRuntimeSnapshot snapshot) {
        return formatCurrent(snapshot, MobileThroughputTracker.Rates.unavailable());
    }

    private static String formatCurrent(
            MobileRuntimeSnapshot snapshot, MobileThroughputTracker.Rates windowRates) {
        return "reassembled_access_units=" + snapshot.reassembledAccessUnits
                + " decoder_accepted_access_units=" + snapshot.decoderAcceptedAccessUnits
                + " access_units=" + snapshot.completedAccessUnits
                + " repeated_content_access_units=" + snapshot.repeatedContentAccessUnits
                + " fresh_content_access_units=" + snapshot.freshContentAccessUnits
                + " rendered_frames=" + snapshot.renderedFrameCount
                + " fresh_decoded_frames=" + snapshot.freshDecodedFrameCount
                + " repeated_decoded_frames=" + snapshot.repeatedDecodedFrameCount
                + " qnn_executions=" + snapshot.qnnExecutionCount
                + " qnn_failures=" + snapshot.qnnFailures
                + " wire_reassembly_fps=" + windowRates.reassembledFps
                + " network_reassembly_fps=" + windowRates.reassembledFps
                + " fresh_content_fps=" + windowRates.freshContentFps
                + " repeated_content_fps=" + windowRates.repeatedContentFps
                + " decoder_submit_fps=" + windowRates.decoderAcceptedFps
                + " decoder_output_fps=" + windowRates.decodedFrameFps
                + " fresh_decoder_fps=" + windowRates.freshDecodedFrameFps
                + " receiver_fps=" + windowRates.reassembledFps
                + " decoder_fps=" + windowRates.decodedFrameFps
                + " qnn_fps=" + windowRates.qnnFps
                + " fresh_qnn_fps=" + windowRates.qnnFps
                + " preprocess_p50=" + snapshot.preprocessP50
                + " qnn_p50=" + snapshot.qnnP50
                + " inference_total_p50=" + snapshot.inferenceTotalP50
                + " decode_queue_p50=" + snapshot.decodeQueueP50;
    }

    private boolean isDue(long monotonicMillis) {
        return lastSampleMillis < 0L || monotonicMillis - lastSampleMillis >= SAMPLE_INTERVAL_MILLIS;
    }

    private boolean countersChanged(MobileRuntimeSnapshot snapshot) {
        return snapshot.reassembledAccessUnits != lastReassembledAccessUnits
                || snapshot.freshContentAccessUnits != lastFreshContentAccessUnits
                || snapshot.decoderAcceptedAccessUnits != lastDecoderAcceptedAccessUnits
                || snapshot.renderedFrameCount != lastRenderedFrames
                || snapshot.freshDecodedFrameCount != lastFreshDecodedFrames
                || snapshot.qnnExecutionCount != lastQnnExecutions;
    }

    private MobileThroughputTracker.Rates ratesForWindow(MobileRuntimeSnapshot snapshot, long monotonicMillis) {
        if (lastSampleMillis < 0L || monotonicMillis <= lastSampleMillis
                || snapshot.reassembledAccessUnits < lastReassembledAccessUnits
                || snapshot.freshContentAccessUnits < lastFreshContentAccessUnits
                || snapshot.decoderAcceptedAccessUnits < lastDecoderAcceptedAccessUnits
                || snapshot.renderedFrameCount < lastRenderedFrames
                || snapshot.freshDecodedFrameCount < lastFreshDecodedFrames
                || snapshot.qnnExecutionCount < lastQnnExecutions) {
            return MobileThroughputTracker.Rates.unavailable();
        }
        double elapsedSeconds = (monotonicMillis - lastSampleMillis) / 1000.0;
        return MobileThroughputTracker.Rates.from(
                (snapshot.reassembledAccessUnits - lastReassembledAccessUnits) / elapsedSeconds,
                (snapshot.freshContentAccessUnits - lastFreshContentAccessUnits) / elapsedSeconds,
                (snapshot.decoderAcceptedAccessUnits - lastDecoderAcceptedAccessUnits) / elapsedSeconds,
                (snapshot.renderedFrameCount - lastRenderedFrames) / elapsedSeconds,
                (snapshot.freshDecodedFrameCount - lastFreshDecodedFrames) / elapsedSeconds,
                (snapshot.qnnExecutionCount - lastQnnExecutions) / elapsedSeconds);
    }

    private static long nonNegativeDifference(long newer, long older) {
        return newer >= older ? newer - older : 0L;
    }
}
