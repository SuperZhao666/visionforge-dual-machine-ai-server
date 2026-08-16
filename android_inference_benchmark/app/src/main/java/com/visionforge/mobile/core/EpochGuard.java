package com.visionforge.mobile.core;

import com.visionforge.mobile.domain.video.StreamEpochGuard;

import java.util.OptionalLong;

/**
 * 旧 API 兼容门面。retiredCapacity 参数仅为源码兼容保留；安全语义已经升级为单调高水位，
 * 因而不再存在“有限退休环被挤出后旧 epoch 复活”的问题。
 */
public final class EpochGuard {
    public enum Decision {
        CURRENT,
        SWITCHED,
        RETIRED
    }

    private final StreamEpochGuard delegate = new StreamEpochGuard();

    public EpochGuard(int retiredCapacity) {
        if (retiredCapacity < 1) {
            throw new IllegalArgumentException("retiredCapacity must be positive");
        }
    }

    public synchronized Decision observe(long epoch) {
        return switch (delegate.observe(epoch)) {
            case CURRENT -> Decision.CURRENT;
            case INITIALIZED, ADVANCED -> Decision.SWITCHED;
            case STALE -> Decision.RETIRED;
        };
    }

    public synchronized OptionalLong currentEpoch() {
        return delegate.currentEpoch();
    }

    public synchronized boolean isRetired(long epoch) {
        return delegate.currentEpoch().isPresent() && epoch < delegate.currentEpoch().getAsLong();
    }
}
