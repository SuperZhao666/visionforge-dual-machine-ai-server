package com.visionforge.inferencebenchmark;

final class BluetoothHidDebugMoveProbePolicySelfTest {
    static void run() {
        clampsProbeShapeToTinyMoveOnlyReports();
        rejectsZeroMovementAfterClamping();
        keepsValidSmallMovement();
    }

    private static void clampsProbeShapeToTinyMoveOnlyReports() {
        BluetoothHidDebugMoveProbePolicy.Request request =
                BluetoothHidDebugMoveProbePolicy.sanitize(500, -500, 500, 5_000);
        require(request.deltaX == BluetoothHidDebugMoveProbePolicy.MAX_ABSOLUTE_DELTA);
        require(request.deltaY == -BluetoothHidDebugMoveProbePolicy.MAX_ABSOLUTE_DELTA);
        require(request.reports == BluetoothHidDebugMoveProbePolicy.MAX_REPORTS);
        require(request.intervalMillis == BluetoothHidDebugMoveProbePolicy.MAX_INTERVAL_MILLIS);
        require(request.hasMovement);
    }

    private static void rejectsZeroMovementAfterClamping() {
        BluetoothHidDebugMoveProbePolicy.Request request =
                BluetoothHidDebugMoveProbePolicy.sanitize(0, 0, -1, -1);
        require(request.deltaX == 0);
        require(request.deltaY == 0);
        require(request.reports == 1);
        require(request.intervalMillis == 0);
        require(!request.hasMovement);
    }

    private static void keepsValidSmallMovement() {
        BluetoothHidDebugMoveProbePolicy.Request request =
                BluetoothHidDebugMoveProbePolicy.sanitize(2, 1, 4, 30);
        require(request.deltaX == 2);
        require(request.deltaY == 1);
        require(request.reports == 4);
        require(request.intervalMillis == 30);
        require(request.hasMovement);
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("Bluetooth HID debug move probe policy failed");
        }
    }
}
