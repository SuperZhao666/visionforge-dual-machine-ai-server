package com.visionforge.inferencebenchmark;

/** Bounded failure-only retry state for the CAT6 mouse-button receiver. */
final class Cat6MouseButtonWorkerRecoveryPolicy {
    private static final long INITIAL_RETRY_NANOS = 1_000_000_000L;
    private static final long MAXIMUM_RETRY_NANOS = 30_000_000_000L;

    static final class Failure {
        final int consecutiveFailures;
        final long retryDelayNanos;

        private Failure(int consecutiveFailures, long retryDelayNanos) {
            this.consecutiveFailures = consecutiveFailures;
            this.retryDelayNanos = retryDelayNanos;
        }
    }

    private int consecutiveFailures;
    private long nextAttemptNanos;

    synchronized boolean canAttempt(long nowNanos) {
        requireMonotonicTime(nowNanos);
        return nextAttemptNanos == 0L || nowNanos >= nextAttemptNanos;
    }

    synchronized Failure recordFailure(long nowNanos) {
        requireMonotonicTime(nowNanos);
        if (consecutiveFailures < Integer.MAX_VALUE) {
            consecutiveFailures++;
        }
        long delayNanos = retryDelayNanos(consecutiveFailures);
        nextAttemptNanos = nowNanos > Long.MAX_VALUE - delayNanos
                ? Long.MAX_VALUE : nowNanos + delayNanos;
        return new Failure(consecutiveFailures, delayNanos);
    }

    synchronized void recordHealthyPacket() {
        reset();
    }

    synchronized void reset() {
        consecutiveFailures = 0;
        nextAttemptNanos = 0L;
    }

    synchronized int consecutiveFailures() {
        return consecutiveFailures;
    }

    static long retryDelayNanos(int consecutiveFailures) {
        int exponent = Math.max(0, Math.min(5, consecutiveFailures - 1));
        return Math.min(
                MAXIMUM_RETRY_NANOS,
                INITIAL_RETRY_NANOS << exponent);
    }

    private static void requireMonotonicTime(long nowNanos) {
        if (nowNanos < 0L) {
            throw new IllegalArgumentException("nowNanos");
        }
    }
}
