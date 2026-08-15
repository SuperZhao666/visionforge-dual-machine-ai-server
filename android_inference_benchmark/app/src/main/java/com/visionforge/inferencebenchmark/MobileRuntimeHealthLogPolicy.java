package com.visionforge.inferencebenchmark;

/** Pure policy that preserves health transitions without repeating unchanged idle reports. */
final class MobileRuntimeHealthLogPolicy {
    static final long IDLE_HEARTBEAT_MILLIS = 300_000L;

    private boolean initialized;
    private boolean lastObservationProgressed;
    private long lastAcceptedDatagrams = -1L;
    private long lastWriteMillis;
    private String lastState = "";

    synchronized boolean shouldWrite(String phase, String videoReport, String decoderReport,
                                     String qnnReport, long monotonicMillis) {
        long acceptedDatagrams = longValue(videoReport, "accepted_datagrams");
        String state = phase
                + "|receiver=" + value(videoReport, "running")
                + "|socket_errors=" + value(videoReport, "fatal_socket_errors")
                + "|source_restart_failures=" + value(videoReport, "source_restart_failures")
                + "|decoder=" + value(decoderReport, "configured")
                + "|decoder_failed=" + value(decoderReport, "decoder_failed")
                + "|qnn=" + value(qnnReport, "ready");
        boolean progressed = initialized && acceptedDatagrams >= 0L
                && lastAcceptedDatagrams >= 0L
                && acceptedDatagrams != lastAcceptedDatagrams;
        boolean stateChanged = initialized && !state.equals(lastState);
        boolean becameIdle = initialized && lastObservationProgressed && !progressed;
        boolean heartbeatDue = initialized
                && nonNegativeDifference(monotonicMillis, lastWriteMillis)
                >= IDLE_HEARTBEAT_MILLIS;
        boolean write = !initialized || stateChanged || progressed || becameIdle || heartbeatDue;

        initialized = true;
        lastObservationProgressed = progressed;
        lastAcceptedDatagrams = acceptedDatagrams;
        lastState = state;
        if (write) lastWriteMillis = monotonicMillis;
        return write;
    }

    private static String value(String report, String field) {
        return MobileDiagnosticFieldParser.valueOr(
                report, field, "missing");
    }

    private static long longValue(String report, String key) {
        try {
            return Long.parseLong(value(report, key));
        } catch (NumberFormatException ignored) {
            return -1L;
        }
    }

    private static long nonNegativeDifference(long newer, long older) {
        return newer >= older ? newer - older : 0L;
    }
}
