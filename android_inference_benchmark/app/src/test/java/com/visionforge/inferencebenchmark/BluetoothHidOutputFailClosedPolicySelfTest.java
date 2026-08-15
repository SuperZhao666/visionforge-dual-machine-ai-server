package com.visionforge.inferencebenchmark;

/** Dependency-free contract for the production Bluetooth HID output path. */
final class BluetoothHidOutputFailClosedPolicySelfTest {
    static void run() {
        verifiesReadySessionAllowsOutput();
        verifiesMissingStateFailsClosed();
        verifiesCapabilityAndPermissionFailuresFailClosed();
        verifiesLifecycleAndConnectionFailuresFailClosed();
        verifiesRejectedReportFailsClosed();
        verifiesStableStatesReusePolicyObjects();
    }

    private static void verifiesReadySessionAllowsOutput() {
        BluetoothHidOutputFailClosedPolicy.Decision decision =
                BluetoothHidOutputFailClosedPolicy.evaluate(
                        BluetoothHidOutputFailClosedPolicy.SessionState.ready());
        require(decision.outputAllowed);
        require(BluetoothHidOutputFailClosedPolicy.REASON_READY.equals(decision.reason));
    }

    private static void verifiesMissingStateFailsClosed() {
        assertLocked(null, BluetoothHidOutputFailClosedPolicy.REASON_STATE_MISSING);
    }

    private static void verifiesCapabilityAndPermissionFailuresFailClosed() {
        BluetoothHidOutputFailClosedPolicy.SessionState ready =
                BluetoothHidOutputFailClosedPolicy.SessionState.ready();
        assertLocked(
                ready.withHidDeviceProfileAvailable(false),
                BluetoothHidOutputFailClosedPolicy.REASON_HID_DEVICE_PROFILE_UNAVAILABLE);
        assertLocked(
                ready.withNearbyDevicesPermissionGranted(false),
                BluetoothHidOutputFailClosedPolicy.REASON_PERMISSION_REVOKED);
        assertLocked(
                ready.withBluetoothEnabled(false),
                BluetoothHidOutputFailClosedPolicy.REASON_BLUETOOTH_DISABLED);
    }

    private static void verifiesLifecycleAndConnectionFailuresFailClosed() {
        BluetoothHidOutputFailClosedPolicy.SessionState ready =
                BluetoothHidOutputFailClosedPolicy.SessionState.ready();
        assertLocked(
                ready.withForegroundSessionActive(false),
                BluetoothHidOutputFailClosedPolicy.REASON_FOREGROUND_SESSION_LOST);
        assertLocked(
                ready.withAppRegistered(false),
                BluetoothHidOutputFailClosedPolicy.REASON_REGISTER_APP_FAILED);
        assertLocked(
                ready.withHostConnected(false),
                BluetoothHidOutputFailClosedPolicy.REASON_HOST_DISCONNECTED);
        assertLocked(
                ready.withProfileConnected(false),
                BluetoothHidOutputFailClosedPolicy.REASON_PROFILE_DISCONNECTED);
    }

    private static void verifiesRejectedReportFailsClosed() {
        assertLocked(
                BluetoothHidOutputFailClosedPolicy.SessionState.ready()
                        .withLastSendReportAccepted(false),
                BluetoothHidOutputFailClosedPolicy.REASON_SEND_REPORT_FALSE);
    }

    private static void verifiesStableStatesReusePolicyObjects() {
        BluetoothHidOutputFailClosedPolicy.SessionState firstReady =
                BluetoothHidOutputFailClosedPolicy.SessionState.ready();
        BluetoothHidOutputFailClosedPolicy.SessionState secondReady =
                BluetoothHidOutputFailClosedPolicy.SessionState.ready();
        require(firstReady == secondReady);
        require(BluetoothHidOutputFailClosedPolicy.evaluate(firstReady)
                == BluetoothHidOutputFailClosedPolicy.evaluate(secondReady));
        require(BluetoothHidOutputFailClosedPolicy.evaluate(null)
                == BluetoothHidOutputFailClosedPolicy.evaluate(null));

        BluetoothHidOutputFailClosedPolicy.SessionState disconnected =
                firstReady.withHostConnected(false);
        require(BluetoothHidOutputFailClosedPolicy.evaluate(disconnected)
                == BluetoothHidOutputFailClosedPolicy.evaluate(disconnected));
    }

    private static void assertLocked(
            BluetoothHidOutputFailClosedPolicy.SessionState state, String reason) {
        BluetoothHidOutputFailClosedPolicy.Decision decision =
                BluetoothHidOutputFailClosedPolicy.evaluate(state);
        require(!decision.outputAllowed);
        require(reason.equals(decision.reason));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("Bluetooth HID fail-closed policy contract failed");
        }
    }
}
