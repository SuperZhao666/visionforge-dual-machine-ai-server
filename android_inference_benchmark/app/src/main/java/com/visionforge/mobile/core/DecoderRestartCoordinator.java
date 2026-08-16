package com.visionforge.mobile.core;

import java.util.OptionalLong;

/**
 * 合并 MediaCodec 重启请求，并把迟到回调与真正的协议错配区分开。
 *
 * <p>同一时刻最多有一次物理重启。重启期间出现更高 epoch 时只更新目标；较低 epoch
 * 属于陈旧输入，不得把目标倒退。迟到的旧完成回调只被忽略，绝不能误伤正在进行的
 * 新重启。</p>
 */
public final class DecoderRestartCoordinator {
    public enum RequestDecision {
        START_NOW,
        COALESCED,
        ALREADY_TARGETED,
        STALE
    }

    public enum CompletionDecision {
        SETTLED,
        START_NEXT,
        STALE_CALLBACK,
        INVALID_FUTURE_CALLBACK
    }

    public record Completion(CompletionDecision decision, OptionalLong nextEpoch) {
        public Completion {
            if ((decision == CompletionDecision.START_NEXT) != nextEpoch.isPresent()) {
                throw new IllegalArgumentException("nextEpoch must exist only for START_NEXT");
            }
        }

        public boolean settled() {
            return decision == CompletionDecision.SETTLED;
        }

        public static Completion settledResult() {
            return new Completion(CompletionDecision.SETTLED, OptionalLong.empty());
        }

        public static Completion restartAt(long epoch) {
            return new Completion(CompletionDecision.START_NEXT, OptionalLong.of(epoch));
        }

        public static Completion staleCallback() {
            return new Completion(CompletionDecision.STALE_CALLBACK, OptionalLong.empty());
        }

        public static Completion invalidFutureCallback() {
            return new Completion(CompletionDecision.INVALID_FUTURE_CALLBACK, OptionalLong.empty());
        }
    }

    private boolean inFlight;
    private long activeEpoch;
    private long latestEpoch;

    public synchronized RequestDecision request(long epoch) {
        requirePositiveEpoch(epoch);
        if (!inFlight) {
            inFlight = true;
            activeEpoch = epoch;
            latestEpoch = epoch;
            return RequestDecision.START_NOW;
        }
        if (epoch < latestEpoch) {
            return RequestDecision.STALE;
        }
        if (epoch == latestEpoch) {
            return RequestDecision.ALREADY_TARGETED;
        }
        latestEpoch = epoch;
        return RequestDecision.COALESCED;
    }

    public synchronized Completion complete(long completedEpoch) {
        requirePositiveEpoch(completedEpoch);
        if (!inFlight) {
            return Completion.staleCallback();
        }
        if (completedEpoch < activeEpoch) {
            return Completion.staleCallback();
        }
        if (completedEpoch > activeEpoch) {
            return Completion.invalidFutureCallback();
        }
        if (latestEpoch > activeEpoch) {
            activeEpoch = latestEpoch;
            return Completion.restartAt(activeEpoch);
        }
        clear();
        return Completion.settledResult();
    }

    /**
     * 适配器确认当前物理重启失败时清空协调状态。旧 epoch 的迟到失败回调不会终止
     * 更新 epoch 的重启。
     */
    public synchronized boolean abort(long failedEpoch) {
        requirePositiveEpoch(failedEpoch);
        if (!inFlight || failedEpoch != activeEpoch) {
            return false;
        }
        clear();
        return true;
    }

    public synchronized boolean inFlight() {
        return inFlight;
    }

    public synchronized OptionalLong activeEpoch() {
        return inFlight ? OptionalLong.of(activeEpoch) : OptionalLong.empty();
    }

    public synchronized OptionalLong targetEpoch() {
        return inFlight ? OptionalLong.of(latestEpoch) : OptionalLong.empty();
    }

    private void clear() {
        inFlight = false;
        activeEpoch = 0L;
        latestEpoch = 0L;
    }

    private static void requirePositiveEpoch(long epoch) {
        if (epoch <= 0L) {
            throw new IllegalArgumentException("epoch must be within positive signed-long range");
        }
    }
}
