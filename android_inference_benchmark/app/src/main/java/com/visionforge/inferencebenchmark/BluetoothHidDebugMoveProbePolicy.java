package com.visionforge.inferencebenchmark;

/** Bounds debug-only Bluetooth HID movement probes to tiny move-only reports. */
final class BluetoothHidDebugMoveProbePolicy {
    static final int MAX_ABSOLUTE_DELTA = 8;
    static final int MAX_REPORTS = 8;
    static final int MAX_INTERVAL_MILLIS = 250;

    private BluetoothHidDebugMoveProbePolicy() {
    }

    static Request sanitize(int deltaX, int deltaY, int reports, int intervalMillis) {
        int boundedX = clamp(deltaX, -MAX_ABSOLUTE_DELTA, MAX_ABSOLUTE_DELTA);
        int boundedY = clamp(deltaY, -MAX_ABSOLUTE_DELTA, MAX_ABSOLUTE_DELTA);
        int boundedReports = clamp(reports, 1, MAX_REPORTS);
        int boundedIntervalMillis = clamp(intervalMillis, 0, MAX_INTERVAL_MILLIS);
        return new Request(
                boundedX,
                boundedY,
                boundedReports,
                boundedIntervalMillis,
                boundedX != 0 || boundedY != 0);
    }

    private static int clamp(int value, int minimum, int maximum) {
        return Math.max(minimum, Math.min(maximum, value));
    }

    static final class Request {
        final int deltaX;
        final int deltaY;
        final int reports;
        final int intervalMillis;
        final boolean hasMovement;

        Request(
                int deltaX,
                int deltaY,
                int reports,
                int intervalMillis,
                boolean hasMovement) {
            this.deltaX = deltaX;
            this.deltaY = deltaY;
            this.reports = reports;
            this.intervalMillis = intervalMillis;
            this.hasMovement = hasMovement;
        }
    }
}
