package com.visionforge.inferencebenchmark;

/** Dependency-free contract proving MAKCU and Bluetooth HID remain independent routes. */
final class ControlOutputRoutePolicySelfTest {
    static void run() {
        verifiesRouteStorageTokens();
        verifiesMakcuRemainsDefault();
        verifiesBluetoothRequiresPlatformCapability();
        verifiesBluetoothTriggerUsesCat6ButtonStream();
        verifiesBluetoothSessionFailuresStayOnSelectedRoute();
        verifiesBluetoothIsReadyWhenEveryRuntimeGateIsReady();
    }

    private static void verifiesRouteStorageTokens() {
        require(ControlOutputRoute.fromStorageToken(null) == ControlOutputRoute.MAKCU_USB);
        require(ControlOutputRoute.fromStorageToken("makcu_usb")
                == ControlOutputRoute.MAKCU_USB);
        require(ControlOutputRoute.fromStorageToken("bluetooth_hid")
                == ControlOutputRoute.BLUETOOTH_HID);
        require(ControlOutputRoute.fromStorageToken("unknown") == ControlOutputRoute.NONE);
    }

    private static void verifiesMakcuRemainsDefault() {
        ControlOutputRoutePolicy.Decision implicit = ControlOutputRoutePolicy.decide(null);
        require(implicit.outputAllowed);
        require(implicit.effectiveRoute == ControlOutputRoute.MAKCU_USB);
        require(ControlOutputRoutePolicy.REASON_MAKCU_DEFAULT.equals(implicit.reason));

        ControlOutputRoutePolicy.Decision selected = ControlOutputRoutePolicy.decide(
                ControlOutputRoutePolicy.Selection.makcuSelected());
        require(selected.outputAllowed);
        require(selected.effectiveRoute == ControlOutputRoute.MAKCU_USB);
        require(ControlOutputRoutePolicy.REASON_MAKCU_SELECTED.equals(selected.reason));
    }

    private static void verifiesBluetoothRequiresPlatformCapability() {
        ControlOutputRoutePolicy.Decision decision = ControlOutputRoutePolicy.decide(
                bluetooth(false, readyBluetooth(), ControlTrigger.ALWAYS, true));
        assertLocked(
                decision,
                ControlOutputRoute.NONE,
                ControlOutputRoutePolicy.REASON_BLUETOOTH_HID_PLATFORM_UNAVAILABLE);
    }

    private static void verifiesBluetoothTriggerUsesCat6ButtonStream() {
        ControlOutputRoutePolicy.Decision decision = ControlOutputRoutePolicy.decide(
                bluetooth(true, readyBluetooth(), ControlTrigger.SIDE_BUTTON_2, false));
        assertLocked(
                decision,
                ControlOutputRoute.BLUETOOTH_HID,
                ControlOutputRoutePolicy.REASON_BLUETOOTH_HID_TRIGGER_STREAM_REQUIRED);
    }

    private static void verifiesBluetoothSessionFailuresStayOnSelectedRoute() {
        BluetoothHidOutputFailClosedPolicy.Decision disconnected =
                BluetoothHidOutputFailClosedPolicy.evaluate(
                        BluetoothHidOutputFailClosedPolicy.SessionState.ready()
                                .withHostConnected(false));
        ControlOutputRoutePolicy.Decision decision = ControlOutputRoutePolicy.decide(
                bluetooth(true, disconnected, ControlTrigger.ALWAYS, true));
        assertLocked(
                decision,
                ControlOutputRoute.BLUETOOTH_HID,
                ControlOutputRoutePolicy.REASON_BLUETOOTH_HID_SESSION_LOCKED_PREFIX
                        + BluetoothHidOutputFailClosedPolicy.REASON_HOST_DISCONNECTED);
    }

    private static void verifiesBluetoothIsReadyWhenEveryRuntimeGateIsReady() {
        ControlOutputRoutePolicy.Decision decision = ControlOutputRoutePolicy.decide(
                bluetooth(true, readyBluetooth(), ControlTrigger.SIDE_BUTTON_2, true));
        require(decision.outputAllowed);
        require(decision.effectiveRoute == ControlOutputRoute.BLUETOOTH_HID);
        require(ControlOutputRoutePolicy.REASON_BLUETOOTH_HID_READY.equals(decision.reason));
    }

    private static ControlOutputRoutePolicy.Selection bluetooth(
            boolean platformAvailable,
            BluetoothHidOutputFailClosedPolicy.Decision hidDecision,
            ControlTrigger trigger,
            boolean triggerStreamAvailable) {
        return ControlOutputRoutePolicy.Selection.bluetooth(
                platformAvailable, hidDecision, trigger, triggerStreamAvailable);
    }

    private static BluetoothHidOutputFailClosedPolicy.Decision readyBluetooth() {
        return BluetoothHidOutputFailClosedPolicy.evaluate(
                BluetoothHidOutputFailClosedPolicy.SessionState.ready());
    }

    private static void assertLocked(
            ControlOutputRoutePolicy.Decision decision,
            ControlOutputRoute expectedRoute,
            String expectedReason) {
        require(!decision.outputAllowed);
        require(decision.effectiveRoute == expectedRoute);
        require(expectedReason.equals(decision.reason));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("Control output route policy contract failed");
        }
    }
}
