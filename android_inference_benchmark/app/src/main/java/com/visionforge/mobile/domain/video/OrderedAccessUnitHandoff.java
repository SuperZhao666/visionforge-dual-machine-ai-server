package com.visionforge.mobile.domain.video;

import java.util.Arrays;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * 面向预测编码的有序压缩帧交接队列。
 *
 * <p>解码前不能采用“最新帧覆盖旧帧”的策略，因为 P/B 帧依赖此前参考帧。队列容量
 * 达到上限、同序号内容冲突或序号耗尽时都 fail-closed，等待新 epoch 的新鲜 IDR。</p>
 */
public final class OrderedAccessUnitHandoff {
    public enum State { WAITING_IDR, RUNNING, OVERFLOW_WAITING_IDR, EPOCH_EXHAUSTED }
    public enum OfferDecision {
        ACCEPTED,
        STALE,
        DUPLICATE,
        CONFLICT,
        NEED_IDR,
        OVERFLOW,
        EPOCH_ADVANCED,
        EPOCH_EXHAUSTED
    }

    public record AccessUnit(
            long streamEpoch,
            long frameSequence,
            boolean idr,
            boolean repeatedContent,
            byte[] bytes) {
        public AccessUnit {
            if (streamEpoch <= 0L || frameSequence < 0L
                    || frameSequence > VideoFragmentHeader.UINT32_MAX) {
                throw new IllegalArgumentException("invalid access-unit identity");
            }
            Objects.requireNonNull(bytes, "bytes");
            if (bytes.length == 0) {
                throw new IllegalArgumentException("access unit must not be empty");
            }
            bytes = bytes.clone();
        }

        @Override
        public byte[] bytes() {
            return bytes.clone();
        }
    }

    private final int capacity;
    private final NavigableMap<Long, AccessUnit> pending = new TreeMap<>();
    private State state = State.WAITING_IDR;
    private long epoch;
    private Long nextSequence;

    public OrderedAccessUnitHandoff(int capacity) {
        if (capacity < 1) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        this.capacity = capacity;
    }

    public synchronized OfferDecision offer(AccessUnit unit) {
        Objects.requireNonNull(unit, "unit");
        boolean epochAdvanced = false;
        if (epoch == 0L || unit.streamEpoch() > epoch) {
            epoch = unit.streamEpoch();
            pending.clear();
            nextSequence = null;
            state = State.WAITING_IDR;
            epochAdvanced = true;
        } else if (unit.streamEpoch() < epoch) {
            return OfferDecision.STALE;
        } else if (state == State.EPOCH_EXHAUSTED) {
            return OfferDecision.EPOCH_EXHAUSTED;
        }

        if (state != State.RUNNING) {
            if (!unit.idr()) {
                return OfferDecision.NEED_IDR;
            }
            state = State.RUNNING;
            nextSequence = unit.frameSequence();
        }

        if (nextSequence != null && unit.frameSequence() < nextSequence.longValue()) {
            return OfferDecision.STALE;
        }
        AccessUnit existing = pending.get(unit.frameSequence());
        if (existing != null) {
            if (existing.idr() == unit.idr()
                    && existing.repeatedContent() == unit.repeatedContent()
                    && Arrays.equals(existing.bytes(), unit.bytes())) {
                return OfferDecision.DUPLICATE;
            }
            requireFreshIdr();
            return OfferDecision.CONFLICT;
        }
        if (pending.size() >= capacity) {
            pending.clear();
            nextSequence = null;
            state = State.OVERFLOW_WAITING_IDR;
            return OfferDecision.OVERFLOW;
        }
        pending.put(unit.frameSequence(), unit);
        return epochAdvanced ? OfferDecision.EPOCH_ADVANCED : OfferDecision.ACCEPTED;
    }

    public synchronized Optional<AccessUnit> pollReady() {
        if (state != State.RUNNING || nextSequence == null) {
            return Optional.empty();
        }
        AccessUnit unit = pending.remove(nextSequence);
        if (unit == null) {
            return Optional.empty();
        }
        if (nextSequence == VideoFragmentHeader.UINT32_MAX) {
            pending.clear();
            nextSequence = null;
            state = State.EPOCH_EXHAUSTED;
        } else {
            nextSequence = nextSequence + 1L;
        }
        return Optional.of(unit);
    }

    public synchronized void requireFreshIdr() {
        pending.clear();
        nextSequence = null;
        if (state != State.EPOCH_EXHAUSTED) {
            state = State.WAITING_IDR;
        }
    }

    public synchronized State state() {
        return state;
    }

    public synchronized int pendingCount() {
        return pending.size();
    }

    public synchronized long currentEpoch() {
        return epoch;
    }
}
