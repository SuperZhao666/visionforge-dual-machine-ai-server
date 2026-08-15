package com.visionforge.inferencebenchmark;

/** Pure decoder watchdog policy shared by production code and the offline regression gate. */
final class DecoderOutputStallPolicy {
    private static final long MINIMUM_BACKLOG = 3L;
    private static final long MINIMUM_STALL_NANOS = 500_000_000L;
    private static final long MAXIMUM_RECENT_INPUT_IDLE_NANOS = 200_000_000L;

    private DecoderOutputStallPolicy() {
    }

    static boolean isStalled(long backlog, long stalledNanos, long inputIdleNanos) {
        return backlog >= MINIMUM_BACKLOG
                && stalledNanos >= MINIMUM_STALL_NANOS
                && inputIdleNanos <= MAXIMUM_RECENT_INPUT_IDLE_NANOS;
    }

    static boolean beginsNewInputBurst(long inputIdleNanos) {
        return inputIdleNanos > MAXIMUM_RECENT_INPUT_IDLE_NANOS;
    }
}
