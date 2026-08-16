package com.visionforge.mobile.domain.control;

import com.visionforge.mobile.domain.runtime.AbsoluteDeadline;
import com.visionforge.mobile.domain.video.VideoFragmentHeader;

import java.util.Objects;

/**
 * ACK 后必须看到更晚且确实更新的画面；超时只进入恢复，不会自动放行旧检测。
 * 身份使用 (streamEpoch, frameSequence)，因此新 epoch 的序号归零不会被误判为回退。
 */
public final class PostAckVisibilityGate {
    public enum Decision { ALLOWED, BLOCKED, RECOVERY_REQUIRED }

    private boolean armed;
    private boolean recoveryRequired;
    private long sourceEpoch;
    private long sourceSequence;
    private long ackNanos;
    private AbsoluteDeadline deadline;

    public synchronized void arm(
            long sourceEpoch,
            long sourceSequence,
            long ackNanos,
            AbsoluteDeadline absoluteDeadline) {
        validateIdentity(sourceEpoch, sourceSequence);
        if (ackNanos < 0L) {
            throw new IllegalArgumentException("ACK time must be non-negative");
        }
        AbsoluteDeadline checked = Objects.requireNonNull(absoluteDeadline, "absoluteDeadline");
        if (checked.deadlineNanos() <= ackNanos) {
            throw new IllegalArgumentException("deadline must be strictly later than ACK time");
        }
        this.sourceEpoch = sourceEpoch;
        this.sourceSequence = sourceSequence;
        this.ackNanos = ackNanos;
        deadline = checked;
        recoveryRequired = false;
        armed = true;
    }

    /** 旧版同 epoch 调用兼容入口。 */
    public synchronized void arm(
            long sourceSequence,
            long ackNanos,
            AbsoluteDeadline absoluteDeadline) {
        arm(1L, sourceSequence, ackNanos, absoluteDeadline);
    }

    public synchronized Decision evaluate(
            boolean contentUpdated,
            long observedEpoch,
            long frameSequence,
            long observedAtNanos,
            long nowNanos) {
        validateIdentity(observedEpoch, frameSequence);
        if (observedAtNanos < 0L || nowNanos < 0L) {
            throw new IllegalArgumentException("observation time must be non-negative");
        }
        if (!armed) {
            return Decision.ALLOWED;
        }
        if (recoveryRequired || deadline.expiredAt(nowNanos)) {
            recoveryRequired = true;
            return Decision.RECOVERY_REQUIRED;
        }
        boolean identityAdvanced = observedEpoch > sourceEpoch
                || (observedEpoch == sourceEpoch && frameSequence > sourceSequence);
        boolean timestampValid = observedAtNanos >= ackNanos && observedAtNanos <= nowNanos;
        if (contentUpdated && identityAdvanced && timestampValid) {
            reset();
            return Decision.ALLOWED;
        }
        return Decision.BLOCKED;
    }

    /** 旧版同 epoch 调用兼容入口。 */
    public synchronized Decision evaluate(
            boolean contentUpdated,
            long frameSequence,
            long observedAtNanos,
            long nowNanos) {
        return evaluate(contentUpdated, sourceEpoch == 0L ? 1L : sourceEpoch,
                frameSequence, observedAtNanos, nowNanos);
    }

    public synchronized void reset() {
        armed = false;
        recoveryRequired = false;
        sourceEpoch = 0L;
        sourceSequence = 0L;
        ackNanos = 0L;
        deadline = null;
    }

    public synchronized boolean armed() {
        return armed;
    }

    private static void validateIdentity(long epoch, long sequence) {
        if (epoch <= 0L || sequence < 0L || sequence > VideoFragmentHeader.UINT32_MAX) {
            throw new IllegalArgumentException("frame identity is outside protocol range");
        }
    }
}
