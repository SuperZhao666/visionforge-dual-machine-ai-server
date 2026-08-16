package com.visionforge.inferencebenchmark;

/**
 * Fail-closed state for Android USB-serial command delivery.
 *
 * <p>A USB write completion means Android USB bulk transfer accepted the complete
 * ASCII command locally. It is not a MAKCU/device acknowledgement and does not
 * claim that physical pointer motion was observed.</p>
 */
final class MakcuDeliveryCircuit {
    static final int DEFAULT_FAILURE_THRESHOLD = 3;

    private final int failureThreshold;
    private long usbWriteCompletionCount;
    private long failureCount;
    private long circuitTripCount;
    private long lastUsbWriteCallMicros;
    private int consecutiveFailures;
    private boolean circuitOpen;
    private String lastFailure = "";

    MakcuDeliveryCircuit() {
        this(DEFAULT_FAILURE_THRESHOLD);
    }

    MakcuDeliveryCircuit(int failureThreshold) {
        if (failureThreshold < 1) throw new IllegalArgumentException("failureThreshold");
        this.failureThreshold = failureThreshold;
    }

    synchronized void recordUsbWriteCompletion(long writeMicros) {
        usbWriteCompletionCount++;
        lastUsbWriteCallMicros = Math.max(0L, writeMicros);
        if (!circuitOpen) consecutiveFailures = 0;
    }

    synchronized void recordFailure(String reason) {
        failureCount++;
        lastFailure = normaliseReason(reason);
        if (circuitOpen) return;
        consecutiveFailures++;
        if (consecutiveFailures >= failureThreshold) {
            circuitOpen = true;
            circuitTripCount++;
        }
    }

    /** Explicit successful USB reopen is the only operation that closes a tripped circuit. */
    synchronized void resetAfterSuccessfulReconnect() {
        consecutiveFailures = 0;
        circuitOpen = false;
        lastFailure = "";
    }

    synchronized MakcuDeliveryState snapshot() {
        return new MakcuDeliveryState(
                usbWriteCompletionCount, failureCount, circuitTripCount,
                lastUsbWriteCallMicros,
                consecutiveFailures, circuitOpen, lastFailure);
    }

    private static String normaliseReason(String reason) {
        if (reason == null || reason.trim().isEmpty()) return "unknown";
        String singleLine = reason.replace('\n', ' ').replace('\r', ' ').trim();
        return singleLine.length() <= 160 ? singleLine : singleLine.substring(0, 160);
    }
}
