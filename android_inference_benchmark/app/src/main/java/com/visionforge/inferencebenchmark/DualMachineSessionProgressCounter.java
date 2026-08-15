package com.visionforge.inferencebenchmark;

import java.util.function.LongSupplier;

/**
 * Session-memory-only reconciler for a native frame counter that may reset.
 *
 * <p>The source is sampled while holding this object's monitor, so concurrent
 * callers cannot submit stale snapshots out of order. A native restart is
 * treated as a new zero point and never fabricates progress. Overflow or an
 * invalid source value permanently fails this session closed.</p>
 */
public final class DualMachineSessionProgressCounter {
    private final LongSupplier source;
    private boolean begun;
    private boolean failed;
    private long lastSourceValue;
    private long sessionTotal;

    public DualMachineSessionProgressCounter(LongSupplier source) {
        if (source == null) {
            throw new IllegalArgumentException("progress source is required");
        }
        this.source = source;
    }

    /** Captures the pre-use baseline without counting or persisting it. */
    public synchronized void beginSession() {
        if (begun || failed) {
            throw new IllegalStateException(
                    "progress generation cannot be begun");
        }
        lastSourceValue = readSource();
        sessionTotal = 0L;
        begun = true;
    }

    /** Returns the continuous session total after one in-lock source sample. */
    public synchronized long observe() {
        requireUsable();
        long current = readSource();
        if (current < lastSourceValue) {
            // Native pipeline restarted. The unknown interval is deliberately
            // under-counted; only future observed growth can authorize renewal.
            lastSourceValue = current;
            return sessionTotal;
        }
        long delta = current - lastSourceValue;
        try {
            sessionTotal = Math.addExact(sessionTotal, delta);
        } catch (ArithmeticException overflow) {
            failed = true;
            throw new SecurityException(
                    "session progress counter overflow", overflow);
        }
        lastSourceValue = current;
        return sessionTotal;
    }

    public synchronized long currentTotal() {
        requireUsable();
        return sessionTotal;
    }

    public synchronized boolean isUsable() {
        return begun && !failed;
    }

    public synchronized void failClosed() {
        failed = true;
        sessionTotal = 0L;
        lastSourceValue = 0L;
    }

    private long readSource() {
        final long value;
        try {
            value = source.getAsLong();
        } catch (RuntimeException exception) {
            failed = true;
            throw new SecurityException(
                    "session progress source failed", exception);
        }
        if (value < 0L) {
            failed = true;
            throw new SecurityException(
                    "session progress source is negative");
        }
        return value;
    }

    private void requireUsable() {
        if (!begun || failed) {
            throw new IllegalStateException(
                    "session progress counter is not usable");
        }
    }
}
