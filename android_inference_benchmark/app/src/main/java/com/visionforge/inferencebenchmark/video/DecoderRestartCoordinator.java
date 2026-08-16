package com.visionforge.inferencebenchmark.video;

/**
 * 合并解码器重建期间连续到达的 epoch 变化。
 *
 * <p>只有一个重建动作在途；后续新会话仅更新目标。旧回调不能覆盖最新目标，
 * 也不能因为“已有重建在途”被当成致命失败。</p>
 */
public final class DecoderRestartCoordinator {
    public static final class Request {
        public final long generation;
        public final long targetEpoch;
        public final boolean startNow;

        Request(long generation, long targetEpoch, boolean startNow) {
            this.generation = generation;
            this.targetEpoch = targetEpoch;
            this.startNow = startNow;
        }
    }

    private long generation;
    private long latestTargetEpoch;
    private boolean inProgress;

    public synchronized Request request(long targetEpoch) {
        if (targetEpoch <= 0L) throw new IllegalArgumentException("positive epoch required");
        latestTargetEpoch = targetEpoch;
        if (inProgress) return new Request(generation, latestTargetEpoch, false);
        inProgress = true;
        generation++;
        return new Request(generation, latestTargetEpoch, true);
    }

    public synchronized long complete(long completedGeneration, boolean success) {
        if (!inProgress || completedGeneration != generation) return -1L;
        inProgress = false;
        return success ? latestTargetEpoch : -1L;
    }

    public synchronized boolean inProgress() { return inProgress; }
    public synchronized long latestTargetEpoch() { return latestTargetEpoch; }
    public synchronized long generation() { return generation; }
}
