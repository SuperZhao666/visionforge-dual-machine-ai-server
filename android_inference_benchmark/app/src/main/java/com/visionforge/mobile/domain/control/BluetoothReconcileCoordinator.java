package com.visionforge.mobile.domain.control;

import java.util.Objects;

/** Bluetooth 恢复事件立即触发一次幂等 reconcile，周期检查仅作为后备。 */
public final class BluetoothReconcileCoordinator {
    public enum Cause { BLUETOOTH_RECOVERED, PERIODIC_HEALTH_CHECK }
    public record Request(long generation, Cause cause, boolean newlyScheduled) {
        public Request {
            if (generation <= 0L) {
                throw new IllegalArgumentException("generation must be positive");
            }
            Objects.requireNonNull(cause, "cause");
        }
    }

    private final long periodicIntervalNanos;
    private String lastRecoveryEventId;
    private long generation;
    private long lastReconciledGeneration;
    private long pendingGeneration;
    private Cause pendingCause;
    private long nextPeriodicNanos;

    public BluetoothReconcileCoordinator(long periodicIntervalNanos, long nowNanos) {
        if (periodicIntervalNanos <= 0L || nowNanos < 0L) {
            throw new IllegalArgumentException("invalid reconcile timing");
        }
        this.periodicIntervalNanos = periodicIntervalNanos;
        nextPeriodicNanos = saturatingAdd(nowNanos, periodicIntervalNanos);
    }

    public synchronized Request onBluetoothRecovered(String eventId) {
        Objects.requireNonNull(eventId, "eventId");
        if (eventId.isBlank()) {
            throw new IllegalArgumentException("eventId must not be blank");
        }
        if (eventId.equals(lastRecoveryEventId)) {
            long knownGeneration = pendingGeneration != 0L ? pendingGeneration : lastReconciledGeneration;
            return new Request(knownGeneration, Cause.BLUETOOTH_RECOVERED, false);
        }
        lastRecoveryEventId = eventId;
        return schedule(Cause.BLUETOOTH_RECOVERED, true);
    }

    public synchronized Request poll(long nowNanos) {
        if (nowNanos < 0L) {
            throw new IllegalArgumentException("nowNanos must be non-negative");
        }
        if (pendingGeneration != 0L) {
            return new Request(pendingGeneration, pendingCause, false);
        }
        if (nowNanos < nextPeriodicNanos) {
            return null;
        }
        nextPeriodicNanos = saturatingAdd(nowNanos, periodicIntervalNanos);
        return schedule(Cause.PERIODIC_HEALTH_CHECK, true);
    }

    public synchronized boolean acknowledge(long requestGeneration) {
        if (requestGeneration <= 0L || requestGeneration != pendingGeneration) {
            return false;
        }
        lastReconciledGeneration = requestGeneration;
        pendingGeneration = 0L;
        pendingCause = null;
        return true;
    }

    private Request schedule(Cause cause, boolean newlyScheduled) {
        if (generation == Long.MAX_VALUE) {
            // 重用 generation 会让极旧 ACK 理论上重新命中。宁可关闭控制链，也不回绕身份。
            throw new IllegalStateException("reconcile generation space exhausted");
        }
        generation++;
        pendingGeneration = generation;
        pendingCause = cause;
        return new Request(generation, cause, newlyScheduled);
    }

    private static long saturatingAdd(long left, long right) {
        return Long.MAX_VALUE - left < right ? Long.MAX_VALUE : left + right;
    }
}
