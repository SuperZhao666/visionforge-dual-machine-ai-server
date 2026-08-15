package com.visionforge.inferencebenchmark;

import java.util.concurrent.TimeUnit;

/**
 * Generation-bound retry cadence for an ambiguous formal-usage stop.
 *
 * <p>The same immutable stop owner is retried indefinitely because an
 * unconfirmed paid session must remain fail-closed until the server settles
 * it. The capped exponential delay bounds request, log and teardown pressure
 * without allowing a different generation to inherit an older delay.</p>
 */
final class FormalUsageStopRetryPolicy {
    static final long INITIAL_RETRY_DELAY_NANOS =
            TimeUnit.SECONDS.toNanos(1L);
    static final long MAXIMUM_RETRY_DELAY_NANOS =
            TimeUnit.SECONDS.toNanos(30L);

    private String ownerKey = "";
    private int consecutiveUnconfirmedAttempts;
    private long nextAttemptNanos;

    synchronized boolean canAttempt(
            String startRequestId,
            String channelBindingSha256,
            long nowNanos) {
        requireOwner(startRequestId, channelBindingSha256);
        requireMonotonicTime(nowNanos);
        selectOwner(startRequestId, channelBindingSha256);
        return nowNanos >= nextAttemptNanos;
    }

    synchronized Decision recordUnconfirmed(
            String startRequestId,
            String channelBindingSha256,
            long nowNanos) {
        requireOwner(startRequestId, channelBindingSha256);
        requireMonotonicTime(nowNanos);
        selectOwner(startRequestId, channelBindingSha256);
        if (consecutiveUnconfirmedAttempts < Integer.MAX_VALUE) {
            consecutiveUnconfirmedAttempts++;
        }
        long delayNanos = retryDelayNanos(
                consecutiveUnconfirmedAttempts);
        nextAttemptNanos = saturatedAdd(nowNanos, delayNanos);
        return new Decision(
                consecutiveUnconfirmedAttempts,
                delayNanos,
                nextAttemptNanos);
    }

    synchronized void recordResolved(
            String startRequestId,
            String channelBindingSha256) {
        requireOwner(startRequestId, channelBindingSha256);
        if (!ownerKey.equals(ownerKey(
                startRequestId, channelBindingSha256))) {
            return;
        }
        reset();
    }

    static long retryDelayNanos(int consecutiveUnconfirmedAttempts) {
        int boundedAttempts = Math.max(1, consecutiveUnconfirmedAttempts);
        int exponent = Math.min(5, boundedAttempts - 1);
        return Math.min(
                MAXIMUM_RETRY_DELAY_NANOS,
                INITIAL_RETRY_DELAY_NANOS << exponent);
    }

    private void selectOwner(
            String startRequestId,
            String channelBindingSha256) {
        String requestedOwner = ownerKey(
                startRequestId, channelBindingSha256);
        if (ownerKey.equals(requestedOwner)) return;
        ownerKey = requestedOwner;
        consecutiveUnconfirmedAttempts = 0;
        nextAttemptNanos = 0L;
    }

    private void reset() {
        ownerKey = "";
        consecutiveUnconfirmedAttempts = 0;
        nextAttemptNanos = 0L;
    }

    private static String ownerKey(
            String startRequestId,
            String channelBindingSha256) {
        return startRequestId + ':' + channelBindingSha256;
    }

    private static void requireOwner(
            String startRequestId,
            String channelBindingSha256) {
        if (startRequestId == null || startRequestId.isEmpty()
                || channelBindingSha256 == null
                || channelBindingSha256.isEmpty()) {
            throw new IllegalArgumentException(
                    "formal stop retry owner is required");
        }
    }

    private static void requireMonotonicTime(long nowNanos) {
        if (nowNanos < 0L) {
            throw new IllegalArgumentException(
                    "formal stop retry time must not be negative");
        }
    }

    private static long saturatedAdd(long left, long right) {
        if (Long.MAX_VALUE - left < right) return Long.MAX_VALUE;
        return left + right;
    }

    static final class Decision {
        final int consecutiveUnconfirmedAttempts;
        final long retryDelayNanos;
        final long nextAttemptNanos;

        Decision(
                int consecutiveUnconfirmedAttempts,
                long retryDelayNanos,
                long nextAttemptNanos) {
            this.consecutiveUnconfirmedAttempts =
                    consecutiveUnconfirmedAttempts;
            this.retryDelayNanos = retryDelayNanos;
            this.nextAttemptNanos = nextAttemptNanos;
        }
    }
}
