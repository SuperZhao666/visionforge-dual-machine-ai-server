package com.visionforge.inferencebenchmark;

/**
 * Tracks one continuous MediaCodec input burst for the decoder watchdog.
 *
 * <p>A static DXGI source can legitimately stop producing access units for
 * seconds. The first access units after that quiet period must receive a fresh
 * watchdog grace window; an output timestamp from the previous burst is not a
 * valid stall reference.</p>
 */
final class DecoderOutputProgressTracker {
    private long queuedInputs;
    private long decodedOutputs;
    private long burstStartedNanos;
    private long lastQueuedInputNanos;
    private long lastDecodedOutputNanos;

    synchronized void reset() {
        queuedInputs = 0L;
        decodedOutputs = 0L;
        burstStartedNanos = 0L;
        lastQueuedInputNanos = 0L;
        lastDecodedOutputNanos = 0L;
    }

    synchronized void recordQueuedInput(long nowNanos) {
        long previousInputIdleNanos = lastQueuedInputNanos == 0L
                ? Long.MAX_VALUE : nonNegativeDifference(nowNanos, lastQueuedInputNanos);
        long backlogBeforeInput = queuedInputs - decodedOutputs;
        if (backlogBeforeInput <= 0L
                || DecoderOutputStallPolicy.beginsNewInputBurst(previousInputIdleNanos)) {
            burstStartedNanos = nowNanos;
        }
        queuedInputs++;
        lastQueuedInputNanos = nowNanos;
    }

    synchronized void recordDecodedOutput(long nowNanos) {
        decodedOutputs++;
        lastDecodedOutputNanos = nowNanos;
        if (decodedOutputs >= queuedInputs) {
            burstStartedNanos = 0L;
        }
    }

    synchronized Snapshot snapshot(long nowNanos) {
        long backlog = queuedInputs - decodedOutputs;
        long referenceNanos = Math.max(burstStartedNanos, lastDecodedOutputNanos);
        long stalledNanos = referenceNanos == 0L
                ? 0L : nonNegativeDifference(nowNanos, referenceNanos);
        long inputIdleNanos = lastQueuedInputNanos == 0L
                ? Long.MAX_VALUE : nonNegativeDifference(nowNanos, lastQueuedInputNanos);
        return new Snapshot(queuedInputs, decodedOutputs, backlog, stalledNanos, inputIdleNanos);
    }

    synchronized long queuedInputs() {
        return queuedInputs;
    }

    synchronized long decodedOutputs() {
        return decodedOutputs;
    }

    private static long nonNegativeDifference(long newer, long older) {
        return newer >= older ? newer - older : 0L;
    }

    static final class Snapshot {
        final long queuedInputs;
        final long decodedOutputs;
        final long backlog;
        final long stalledNanos;
        final long inputIdleNanos;

        Snapshot(long queuedInputs, long decodedOutputs, long backlog,
                 long stalledNanos, long inputIdleNanos) {
            this.queuedInputs = queuedInputs;
            this.decodedOutputs = decodedOutputs;
            this.backlog = backlog;
            this.stalledNanos = stalledNanos;
            this.inputIdleNanos = inputIdleNanos;
        }
    }
}
