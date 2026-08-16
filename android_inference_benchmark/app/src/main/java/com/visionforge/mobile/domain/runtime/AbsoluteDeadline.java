package com.visionforge.mobile.domain.runtime;

/**
 * 统一绝对 deadline。调用方只传单调时钟纳秒值，避免 Java/C++ 各自重复做相对超时
 * 换算而产生 late ACK 竞态。
 */
public record AbsoluteDeadline(long deadlineNanos) {
    public AbsoluteDeadline {
        if (deadlineNanos < 0L) {
            throw new IllegalArgumentException("deadline must be non-negative");
        }
    }

    public static AbsoluteDeadline after(long nowNanos, long timeoutNanos) {
        if (nowNanos < 0L || timeoutNanos <= 0L) {
            throw new IllegalArgumentException("now and timeout are invalid");
        }
        long deadline = Long.MAX_VALUE - nowNanos < timeoutNanos
                ? Long.MAX_VALUE
                : nowNanos + timeoutNanos;
        return new AbsoluteDeadline(deadline);
    }

    public boolean expiredAt(long nowNanos) {
        if (nowNanos < 0L) {
            throw new IllegalArgumentException("nowNanos must be non-negative");
        }
        return nowNanos >= deadlineNanos;
    }
}
