package com.visionforge.inferencebenchmark;

/**
 * Decides when the ADB-readable latest-health file must replace older session data.
 * This policy runs on the five-second health executor, never on the frame hot path.
 */
final class MobileExternalHealthSnapshotPolicy {
    static final long IDLE_HEARTBEAT_MILLIS = 300_000L;

    private long lastSuccessfulWriteMillis = -1L;
    private String lastWrittenPhase = "";
    private String lastWrittenInference = "";
    private boolean lastWrittenReceiverRunning;
    private boolean lastWrittenDecoderReady;
    private boolean lastWrittenQnnReady;
    private boolean lastWrittenQnnExecutionLive;
    private boolean writePending;

    boolean shouldWrite(
            String phase,
            String inferenceReport,
            MobileRuntimeSnapshot snapshot,
            boolean metricsSampleAvailable,
            long monotonicMillis) {
        if (snapshot == null) return false;
        boolean firstWrite = lastSuccessfulWriteMillis < 0L;
        boolean stateChanged = !normalized(phase).equals(lastWrittenPhase)
                || !normalized(inferenceReport).equals(lastWrittenInference)
                || snapshot.receiverRunning != lastWrittenReceiverRunning
                || snapshot.decoderReady != lastWrittenDecoderReady
                || snapshot.qnnReady != lastWrittenQnnReady
                || snapshot.qnnExecutionLive != lastWrittenQnnExecutionLive;
        boolean heartbeatDue = lastSuccessfulWriteMillis >= 0L
                && nonNegativeDifference(monotonicMillis, lastSuccessfulWriteMillis)
                >= IDLE_HEARTBEAT_MILLIS;
        if (firstWrite || stateChanged || metricsSampleAvailable || heartbeatDue) {
            writePending = true;
        }
        return writePending;
    }

    void recordSuccessfulWrite(
            String phase,
            String inferenceReport,
            MobileRuntimeSnapshot snapshot,
            long monotonicMillis) {
        if (snapshot == null) return;
        lastSuccessfulWriteMillis = monotonicMillis;
        lastWrittenPhase = normalized(phase);
        lastWrittenInference = normalized(inferenceReport);
        lastWrittenReceiverRunning = snapshot.receiverRunning;
        lastWrittenDecoderReady = snapshot.decoderReady;
        lastWrittenQnnReady = snapshot.qnnReady;
        lastWrittenQnnExecutionLive = snapshot.qnnExecutionLive;
        writePending = false;
    }

    private static String normalized(String value) {
        return value == null ? "" : value;
    }

    private static long nonNegativeDifference(long newer, long older) {
        return newer >= older ? newer - older : 0L;
    }
}
