package com.visionforge.mobile.domain.video;

import java.util.OptionalLong;

/**
 * 单调 stream_epoch 高水位。
 *
 * <p>与“只保存有限个 retired epoch”相比，高水位不会因历史集合被挤出而重新接纳
 * 很久以前的 UDP 包。协议要求 Host 每次重建流都分配更大的正 epoch。</p>
 */
public final class StreamEpochGuard {
    public enum Decision {
        INITIALIZED,
        CURRENT,
        ADVANCED,
        STALE
    }

    private Long current;

    public synchronized Decision observe(long epoch) {
        if (epoch <= 0L) {
            throw new IllegalArgumentException("epoch must be positive");
        }
        if (current == null) {
            current = epoch;
            return Decision.INITIALIZED;
        }
        if (epoch == current.longValue()) {
            return Decision.CURRENT;
        }
        if (epoch < current.longValue()) {
            return Decision.STALE;
        }
        current = epoch;
        return Decision.ADVANCED;
    }

    public synchronized OptionalLong currentEpoch() {
        return current == null ? OptionalLong.empty() : OptionalLong.of(current.longValue());
    }
}
