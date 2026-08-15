package com.visionforge.inferencebenchmark;

/**
 * Keeps Host-video preflight failure transitions observable without writing
 * the same idle condition after every bounded probe.
 */
final class HostVideoPreflightLogPolicy {
    static final long STABLE_HEARTBEAT_MILLIS = 300_000L;

    private boolean failureActive;
    private long lastWriteMillis;
    private String lastFailureKey = "";

    synchronized boolean shouldWriteFailure(
            String routeIdentity,
            String reason,
            long monotonicMillis) {
        String failureKey = normalize(routeIdentity)
                + "\n" + normalize(reason);
        boolean failureChanged = failureActive
                && !failureKey.equals(lastFailureKey);
        boolean heartbeatDue = failureActive
                && nonNegativeDifference(monotonicMillis, lastWriteMillis)
                >= STABLE_HEARTBEAT_MILLIS;
        boolean write = !failureActive || failureChanged || heartbeatDue;

        failureActive = true;
        lastFailureKey = failureKey;
        if (write) lastWriteMillis = monotonicMillis;
        return write;
    }

    synchronized void clearFailure() {
        failureActive = false;
        lastWriteMillis = 0L;
        lastFailureKey = "";
    }

    private static String normalize(String value) {
        return value == null || value.isBlank() ? "unspecified" : value;
    }

    private static long nonNegativeDifference(long newer, long older) {
        return newer >= older ? newer - older : 0L;
    }
}
