package com.visionforge.inferencebenchmark;

/** Bounded retry cadence for a definitively rejected automatic usage start. */
final class AutomaticFormalStartRetryPolicy {
    static final long INITIAL_RETRY_DELAY_MILLIS = 1_000L;
    static final long MAXIMUM_RETRY_DELAY_MILLIS = 30_000L;

    private int consecutiveRejections;

    synchronized Decision recordRejection() {
        if (consecutiveRejections < Integer.MAX_VALUE) {
            consecutiveRejections++;
        }
        return new Decision(
                consecutiveRejections,
                retryDelayMillis(consecutiveRejections));
    }

    synchronized void reset() {
        consecutiveRejections = 0;
    }

    static long retryDelayMillis(int consecutiveRejections) {
        int boundedRejections = Math.max(1, consecutiveRejections);
        int exponent = Math.min(5, boundedRejections - 1);
        return Math.min(
                MAXIMUM_RETRY_DELAY_MILLIS,
                INITIAL_RETRY_DELAY_MILLIS << exponent);
    }

    static final class Decision {
        final int consecutiveRejections;
        final long retryDelayMillis;

        Decision(int consecutiveRejections, long retryDelayMillis) {
            this.consecutiveRejections = consecutiveRejections;
            this.retryDelayMillis = retryDelayMillis;
        }
    }
}
