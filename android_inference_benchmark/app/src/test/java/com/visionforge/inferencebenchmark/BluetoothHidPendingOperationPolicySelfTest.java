package com.visionforge.inferencebenchmark;

/** Regression coverage for lost Android Bluetooth HID callback recovery. */
final class BluetoothHidPendingOperationPolicySelfTest {
    static void run() {
        long timeout = BluetoothHidPendingOperationPolicy.CALLBACK_TIMEOUT_NANOS;
        require(!BluetoothHidPendingOperationPolicy.hasTimedOut(false, 1L, Long.MAX_VALUE));
        require(!BluetoothHidPendingOperationPolicy.hasTimedOut(true, 7L, 7L + timeout - 1L));
        require(BluetoothHidPendingOperationPolicy.hasTimedOut(true, 7L, 7L + timeout));
        require(BluetoothHidPendingOperationPolicy.hasTimedOut(
                true, Long.MAX_VALUE - 4L, Long.MIN_VALUE + timeout - 5L));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("Bluetooth HID pending-operation policy failed");
        }
    }
}
