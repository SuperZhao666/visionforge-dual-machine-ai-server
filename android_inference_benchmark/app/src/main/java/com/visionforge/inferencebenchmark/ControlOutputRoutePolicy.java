package com.visionforge.inferencebenchmark;

/** Production eligibility policy for the two operator-selectable output routes. */
final class ControlOutputRoutePolicy {
    static final String REASON_MAKCU_DEFAULT = "makcu_default";
    static final String REASON_MAKCU_SELECTED = "makcu_selected";
    static final String REASON_BLUETOOTH_HID_PLATFORM_UNAVAILABLE =
            "bluetooth_hid_platform_unavailable";
    static final String REASON_BLUETOOTH_HID_TRIGGER_STREAM_REQUIRED =
            "bluetooth_hid_cat6_trigger_stream_required";
    static final String REASON_BLUETOOTH_HID_SESSION_LOCKED_PREFIX =
            "bluetooth_hid_session_locked_";
    static final String REASON_BLUETOOTH_HID_READY = "bluetooth_hid_ready";

    private ControlOutputRoutePolicy() {
    }

    static Decision decide(Selection selection) {
        Selection checked = selection == null ? Selection.makcuDefault() : selection;
        ControlOutputRoute requestedRoute = checked.requestedRoute == null
                ? ControlOutputRoute.MAKCU_USB : checked.requestedRoute;
        if (requestedRoute == ControlOutputRoute.MAKCU_USB) {
            return Decision.allowed(
                    ControlOutputRoute.MAKCU_USB,
                    checked.defaultSelection ? REASON_MAKCU_DEFAULT : REASON_MAKCU_SELECTED);
        }
        if (requestedRoute != ControlOutputRoute.BLUETOOTH_HID
                || !checked.bluetoothHidPlatformAvailable) {
            return Decision.locked(
                    ControlOutputRoute.NONE,
                    REASON_BLUETOOTH_HID_PLATFORM_UNAVAILABLE);
        }
        ControlTrigger trigger = checked.trigger == null
                ? ControlTrigger.SIDE_BUTTON_2 : checked.trigger;
        if (trigger.requiresButtonStream() && !checked.triggerStreamAvailable) {
            return Decision.locked(
                    ControlOutputRoute.BLUETOOTH_HID,
                    REASON_BLUETOOTH_HID_TRIGGER_STREAM_REQUIRED);
        }
        BluetoothHidOutputFailClosedPolicy.Decision hidDecision =
                checked.bluetoothHidDecision;
        if (hidDecision == null || !hidDecision.outputAllowed) {
            String reason = hidDecision == null
                    ? BluetoothHidOutputFailClosedPolicy.REASON_STATE_MISSING
                    : hidDecision.reason;
            return Decision.locked(
                    ControlOutputRoute.BLUETOOTH_HID,
                    REASON_BLUETOOTH_HID_SESSION_LOCKED_PREFIX + reason);
        }
        return Decision.allowed(
                ControlOutputRoute.BLUETOOTH_HID,
                REASON_BLUETOOTH_HID_READY);
    }

    static final class Selection {
        final ControlOutputRoute requestedRoute;
        final boolean defaultSelection;
        final boolean bluetoothHidPlatformAvailable;
        final BluetoothHidOutputFailClosedPolicy.Decision bluetoothHidDecision;
        final ControlTrigger trigger;
        final boolean triggerStreamAvailable;

        private Selection(
                ControlOutputRoute requestedRoute,
                boolean defaultSelection,
                boolean bluetoothHidPlatformAvailable,
                BluetoothHidOutputFailClosedPolicy.Decision bluetoothHidDecision,
                ControlTrigger trigger,
                boolean triggerStreamAvailable) {
            this.requestedRoute = requestedRoute;
            this.defaultSelection = defaultSelection;
            this.bluetoothHidPlatformAvailable = bluetoothHidPlatformAvailable;
            this.bluetoothHidDecision = bluetoothHidDecision;
            this.trigger = trigger;
            this.triggerStreamAvailable = triggerStreamAvailable;
        }

        static Selection makcuDefault() {
            return new Selection(
                    ControlOutputRoute.MAKCU_USB,
                    true,
                    true,
                    null,
                    ControlTrigger.SIDE_BUTTON_2,
                    true);
        }

        static Selection makcuSelected() {
            return new Selection(
                    ControlOutputRoute.MAKCU_USB,
                    false,
                    true,
                    null,
                    ControlTrigger.SIDE_BUTTON_2,
                    true);
        }

        static Selection bluetooth(
                boolean platformAvailable,
                BluetoothHidOutputFailClosedPolicy.Decision hidDecision,
                ControlTrigger trigger,
                boolean triggerStreamAvailable) {
            return new Selection(
                    ControlOutputRoute.BLUETOOTH_HID,
                    false,
                    platformAvailable,
                    hidDecision,
                    trigger,
                    triggerStreamAvailable);
        }
    }

    static final class Decision {
        final ControlOutputRoute effectiveRoute;
        final boolean outputAllowed;
        final String reason;

        private Decision(
                ControlOutputRoute effectiveRoute,
                boolean outputAllowed,
                String reason) {
            this.effectiveRoute = effectiveRoute;
            this.outputAllowed = outputAllowed;
            this.reason = reason;
        }

        static Decision allowed(ControlOutputRoute route, String reason) {
            return new Decision(route, true, reason);
        }

        static Decision locked(ControlOutputRoute route, String reason) {
            return new Decision(route, false, reason);
        }
    }
}
