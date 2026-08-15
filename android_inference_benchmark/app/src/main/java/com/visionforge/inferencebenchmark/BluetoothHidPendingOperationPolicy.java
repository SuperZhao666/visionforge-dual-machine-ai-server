package com.visionforge.inferencebenchmark;

/** Detects Android Bluetooth HID API requests whose asynchronous callback was lost. */
final class BluetoothHidPendingOperationPolicy {
    static final long CALLBACK_TIMEOUT_NANOS = 10_000_000_000L;

    private BluetoothHidPendingOperationPolicy() {
    }

    static boolean hasTimedOut(boolean pending, long startedNanos, long nowNanos) {
        return pending && nowNanos - startedNanos >= CALLBACK_TIMEOUT_NANOS;
    }
}
