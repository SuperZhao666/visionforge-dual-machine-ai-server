package com.visionforge.inferencebenchmark;

/** Formats the single latest mobile runtime record consumed by ADB evidence collection. */
final class MobileExternalHealthSnapshotFormatter {
    private MobileExternalHealthSnapshotFormatter() {}

    static String format(
            long timestampUnixMillis,
            long monotonicMillis,
            String phase,
            String inferenceReport,
            String metrics,
            String controlSummary) {
        return "timestamp_unix_ms=" + timestampUnixMillis
                + " monotonic_ms=" + monotonicMillis
                + " phase=" + normalized(phase)
                + " " + normalized(inferenceReport)
                + " " + normalized(metrics)
                + " " + normalized(controlSummary)
                + "\n";
    }

    private static String normalized(String value) {
        return value == null ? "" : value.trim();
    }
}
