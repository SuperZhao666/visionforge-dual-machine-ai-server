package com.visionforge.inferencebenchmark;

/**
 * Bounded persistence policy for automatic-usage frame progress.
 *
 * <p>Billing-boundary transitions are persisted synchronously by the service
 * and do not use this cadence.  This policy only coalesces repeated progress
 * checkpoints.  The first observation is due immediately, ordinary forward
 * progress is checkpointed every 30 seconds, and an encoder reset or natural
 * 31-bit sequence wrap is persisted immediately so a process restart cannot
 * mistake that reset for a new Host stream.</p>
 */
final class AutomaticUsageGuardCheckpointPolicy {
    static final long CHECKPOINT_INTERVAL_MILLIS = 30_000L;

    enum Decision {
        NOT_DUE("not_due"),
        PERIODIC_DUE("periodic_due"),
        FRAME_SEQUENCE_REGRESSED("frame_sequence_regressed");

        final String reasonToken;

        Decision(String reasonToken) {
            this.reasonToken = reasonToken;
        }

        boolean shouldPersist() {
            return this != NOT_DUE;
        }
    }

    private long nextCheckpointElapsedMillis;
    private long lastPersistedFrameSequence = -1L;

    synchronized Decision evaluate(
            long nowElapsedMillis,
            long currentFrameSequence) {
        requireMonotonicTime(nowElapsedMillis);
        if (isValidFrameSequence(currentFrameSequence)
                && isValidFrameSequence(lastPersistedFrameSequence)
                && currentFrameSequence < lastPersistedFrameSequence) {
            return Decision.FRAME_SEQUENCE_REGRESSED;
        }
        if (nextCheckpointElapsedMillis == 0L
                || nowElapsedMillis >= nextCheckpointElapsedMillis) {
            return Decision.PERIODIC_DUE;
        }
        return Decision.NOT_DUE;
    }

    /** Records any successful synchronous guard persistence. */
    synchronized void recordPersistence(long frameSequence) {
        lastPersistedFrameSequence = normalizeFrameSequence(frameSequence);
    }

    /** Advances the cadence only after a scheduled checkpoint commits. */
    synchronized void recordCheckpointSucceeded(long nowElapsedMillis) {
        requireMonotonicTime(nowElapsedMillis);
        nextCheckpointElapsedMillis = saturatedAdd(
                nowElapsedMillis,
                CHECKPOINT_INTERVAL_MILLIS);
    }

    /** Restored state keeps its persisted sequence but checkpoints once live. */
    synchronized void restorePersisted(long frameSequence) {
        lastPersistedFrameSequence = normalizeFrameSequence(frameSequence);
        nextCheckpointElapsedMillis = 0L;
    }

    /** A cleared generation gives the next generation an immediate checkpoint. */
    synchronized void clearPersisted() {
        lastPersistedFrameSequence = -1L;
        nextCheckpointElapsedMillis = 0L;
    }

    private static long normalizeFrameSequence(long frameSequence) {
        return isValidFrameSequence(frameSequence) ? frameSequence : -1L;
    }

    private static boolean isValidFrameSequence(long frameSequence) {
        return frameSequence >= 0L
                && frameSequence
                <= AutomaticFormalUsageSessionGuard.MAX_LOGICAL_FRAME_SEQUENCE;
    }

    private static void requireMonotonicTime(long nowElapsedMillis) {
        if (nowElapsedMillis < 0L) {
            throw new IllegalArgumentException(
                    "monotonic checkpoint time must be non-negative");
        }
    }

    private static long saturatedAdd(long value, long increment) {
        if (value > Long.MAX_VALUE - increment) return Long.MAX_VALUE;
        return value + increment;
    }
}
