package com.visionforge.inferencebenchmark;

/** Preserves reservation-state transitions without repeating the same no-op every tick. */
final class AutomaticUsageReservationLogPolicy {
    static final long STABLE_HEARTBEAT_MILLIS = 300_000L;

    private boolean initialized;
    private long lastWriteMillis;
    private String lastReason = "";

    synchronized boolean shouldWrite(String reason, long monotonicMillis) {
        String normalizedReason = reason == null ? "unspecified" : reason;
        boolean reasonChanged = initialized && !normalizedReason.equals(lastReason);
        boolean heartbeatDue = initialized
                && nonNegativeDifference(monotonicMillis, lastWriteMillis)
                >= STABLE_HEARTBEAT_MILLIS;
        boolean write = !initialized || reasonChanged || heartbeatDue;

        initialized = true;
        lastReason = normalizedReason;
        if (write) lastWriteMillis = monotonicMillis;
        return write;
    }

    private static long nonNegativeDifference(long newer, long older) {
        return newer >= older ? newer - older : 0L;
    }
}
