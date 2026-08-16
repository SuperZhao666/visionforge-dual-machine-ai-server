package com.visionforge.inferencebenchmark;

/** Shared bounded lifetime helpers for one native control-move ticket. */
final class ControlMoveDeadline {
    static final long DEFAULT_BUDGET_US = 250_000L;
    private static final long NANOS_PER_MICRO = 1_000L;
    private static final long NANOS_PER_MILLI = 1_000_000L;

    private ControlMoveDeadline() {
    }

    static long deadlineNanos(long nowNanos, long remainingBudgetUs) {
        if (remainingBudgetUs <= 0L) return nowNanos;
        if (remainingBudgetUs > Long.MAX_VALUE / NANOS_PER_MICRO) {
            return Long.MAX_VALUE;
        }
        long deltaNanos = remainingBudgetUs * NANOS_PER_MICRO;
        if (nowNanos > Long.MAX_VALUE - deltaNanos) return Long.MAX_VALUE;
        return nowNanos + deltaNanos;
    }

    static long boundedDeadlineNanos(long startedNanos, long maximumDurationNanos) {
        if (maximumDurationNanos <= 0L) return startedNanos;
        if (startedNanos > Long.MAX_VALUE - maximumDurationNanos) {
            return Long.MAX_VALUE;
        }
        return startedNanos + maximumDurationNanos;
    }

    static long earlierDeadline(long first, long second) {
        if (first <= 0L) return second;
        if (second <= 0L) return first;
        return Math.min(first, second);
    }

    static boolean isExpired(long nowNanos, long deadlineNanos) {
        return deadlineNanos <= 0L || nowNanos >= deadlineNanos;
    }

    static long remainingNanos(long nowNanos, long deadlineNanos) {
        return isExpired(nowNanos, deadlineNanos) ? 0L : deadlineNanos - nowNanos;
    }

    /**
     * Converts the remaining absolute deadline into a bounded blocking API
     * timeout. A positive sub-millisecond budget is rounded up to one
     * millisecond so callers do not accidentally request an unbounded or
     * immediate operation from APIs where zero has special semantics.
     */
    static int boundedTimeoutMillis(
            long nowNanos, long deadlineNanos, int maximumMillis) {
        if (maximumMillis <= 0) return 0;
        long remaining = remainingNanos(nowNanos, deadlineNanos);
        if (remaining <= 0L) return 0;
        long roundedUpMillis = ((remaining - 1L) / NANOS_PER_MILLI) + 1L;
        return (int) Math.max(1L, Math.min((long) maximumMillis, roundedUpMillis));
    }
}
