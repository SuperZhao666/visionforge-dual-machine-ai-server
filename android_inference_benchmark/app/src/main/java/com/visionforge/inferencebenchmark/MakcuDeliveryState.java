package com.visionforge.inferencebenchmark;

/**
 * Immutable evidence for USB/Bluetooth command delivery.
 *
 * <p>This value object records local transport completion and fail-closed circuit state.
 * It deliberately does not claim that the physical target moved; that stronger statement
 * requires device-side acknowledgement or external observation.</p>
 */
final class MakcuDeliveryState {
    final long usbWriteCompletionCount;
    final long failureCount;
    final long circuitTripCount;
    final long lastUsbWriteCallMicros;
    final int consecutiveFailures;
    final boolean circuitOpen;
    final String lastFailure;

    MakcuDeliveryState(long usbWriteCompletionCount, long failureCount,
                       long circuitTripCount, long lastUsbWriteCallMicros,
                       int consecutiveFailures, boolean circuitOpen,
                       String lastFailure) {
        this.usbWriteCompletionCount = usbWriteCompletionCount;
        this.failureCount = failureCount;
        this.circuitTripCount = circuitTripCount;
        this.lastUsbWriteCallMicros = lastUsbWriteCallMicros;
        this.consecutiveFailures = consecutiveFailures;
        this.circuitOpen = circuitOpen;
        this.lastFailure = lastFailure == null ? "" : lastFailure;
    }
}
