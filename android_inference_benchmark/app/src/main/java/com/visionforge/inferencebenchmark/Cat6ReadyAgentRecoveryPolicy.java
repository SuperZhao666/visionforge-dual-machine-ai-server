package com.visionforge.inferencebenchmark;

/** Failure-only exponential retry state for the native CAT6/Wi-Fi Ready agent. */
final class Cat6ReadyAgentRecoveryPolicy {
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
    private boolean retryScheduled;

    synchronized boolean canAttempt(long nowNanos) {
        // nanoTime has an arbitrary origin and may wrap. Signed subtraction is
        // correct as long as a scheduled interval stays below 2^63 ns.
        return !retryScheduled || nowNanos - nextAttemptNanos >= 0L;
    }

    synchronized Failure recordFailure(long nowNanos) {
        if (consecutiveFailures < Integer.MAX_VALUE) consecutiveFailures++;
        long delayNanos = retryDelayNanos(consecutiveFailures);
        nextAttemptNanos = nowNanos + delayNanos;
        retryScheduled = true;
        return new Failure(consecutiveFailures, delayNanos);
    }

    synchronized void recordHealthyObservation() {
        reset();
    }

    synchronized void reset() {
        consecutiveFailures = 0;
        nextAttemptNanos = 0L;
        retryScheduled = false;
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
}
