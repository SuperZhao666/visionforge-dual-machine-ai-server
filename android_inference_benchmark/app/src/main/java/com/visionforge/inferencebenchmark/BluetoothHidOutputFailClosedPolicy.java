package com.visionforge.inferencebenchmark;

/** Fail-closed eligibility policy for the production Bluetooth HID route. */
final class BluetoothHidOutputFailClosedPolicy {
    static final String REASON_READY = "ready";
    static final String REASON_STATE_MISSING = "state_missing";
    static final String REASON_HID_DEVICE_PROFILE_UNAVAILABLE = "hid_device_profile_unavailable";
    static final String REASON_PERMISSION_REVOKED = "nearby_devices_permission_revoked";
    static final String REASON_BLUETOOTH_DISABLED = "bluetooth_disabled";
    static final String REASON_FOREGROUND_SESSION_LOST = "foreground_session_lost";
    static final String REASON_REGISTER_APP_FAILED = "register_app_failed";
    static final String REASON_HOST_DISCONNECTED = "host_disconnected";
    static final String REASON_PROFILE_DISCONNECTED = "profile_disconnected";
    static final String REASON_SEND_REPORT_FALSE = "send_report_false";
    static final String REASON_NATIVE_MOVE_COMPLETION_REJECTED =
            "native_move_completion_rejected";

    private static final Decision READY_DECISION =
            new Decision(true, REASON_READY);
    private static final Decision STATE_MISSING_DECISION =
            new Decision(false, REASON_STATE_MISSING);
    private static final Decision HID_PROFILE_UNAVAILABLE_DECISION =
            new Decision(false, REASON_HID_DEVICE_PROFILE_UNAVAILABLE);
    private static final Decision PERMISSION_REVOKED_DECISION =
            new Decision(false, REASON_PERMISSION_REVOKED);
    private static final Decision BLUETOOTH_DISABLED_DECISION =
            new Decision(false, REASON_BLUETOOTH_DISABLED);
    private static final Decision FOREGROUND_SESSION_LOST_DECISION =
            new Decision(false, REASON_FOREGROUND_SESSION_LOST);
    private static final Decision REGISTER_APP_FAILED_DECISION =
            new Decision(false, REASON_REGISTER_APP_FAILED);
    private static final Decision HOST_DISCONNECTED_DECISION =
            new Decision(false, REASON_HOST_DISCONNECTED);
    private static final Decision PROFILE_DISCONNECTED_DECISION =
            new Decision(false, REASON_PROFILE_DISCONNECTED);
    private static final Decision SEND_REPORT_FALSE_DECISION =
            new Decision(false, REASON_SEND_REPORT_FALSE);

    private BluetoothHidOutputFailClosedPolicy() {
    }

    static Decision evaluate(SessionState state) {
        if (state == null) return STATE_MISSING_DECISION;
        if (!state.hidDeviceProfileAvailable) {
            return HID_PROFILE_UNAVAILABLE_DECISION;
        }
        if (!state.nearbyDevicesPermissionGranted) {
            return PERMISSION_REVOKED_DECISION;
        }
        if (!state.bluetoothEnabled) return BLUETOOTH_DISABLED_DECISION;
        if (!state.foregroundSessionActive) {
            return FOREGROUND_SESSION_LOST_DECISION;
        }
        if (!state.appRegistered) return REGISTER_APP_FAILED_DECISION;
        if (!state.hostConnected) return HOST_DISCONNECTED_DECISION;
        if (!state.profileConnected) return PROFILE_DISCONNECTED_DECISION;
        if (!state.lastSendReportAccepted) return SEND_REPORT_FALSE_DECISION;
        return READY_DECISION;
    }

    static final class SessionState {
        private static final SessionState READY =
                new SessionState(true, true, true, true, true, true, true, true);
        final boolean hidDeviceProfileAvailable;
        final boolean nearbyDevicesPermissionGranted;
        final boolean bluetoothEnabled;
        final boolean foregroundSessionActive;
        final boolean appRegistered;
        final boolean hostConnected;
        final boolean profileConnected;
        final boolean lastSendReportAccepted;

        SessionState(
                boolean hidDeviceProfileAvailable,
                boolean nearbyDevicesPermissionGranted,
                boolean bluetoothEnabled,
                boolean foregroundSessionActive,
                boolean appRegistered,
                boolean hostConnected,
                boolean profileConnected,
                boolean lastSendReportAccepted) {
            this.hidDeviceProfileAvailable = hidDeviceProfileAvailable;
            this.nearbyDevicesPermissionGranted = nearbyDevicesPermissionGranted;
            this.bluetoothEnabled = bluetoothEnabled;
            this.foregroundSessionActive = foregroundSessionActive;
            this.appRegistered = appRegistered;
            this.hostConnected = hostConnected;
            this.profileConnected = profileConnected;
            this.lastSendReportAccepted = lastSendReportAccepted;
        }

        static SessionState ready() {
            return READY;
        }

        boolean matches(
                boolean nextHidDeviceProfileAvailable,
                boolean nextNearbyDevicesPermissionGranted,
                boolean nextBluetoothEnabled,
                boolean nextForegroundSessionActive,
                boolean nextAppRegistered,
                boolean nextHostConnected,
                boolean nextProfileConnected,
                boolean nextLastSendReportAccepted) {
            return hidDeviceProfileAvailable == nextHidDeviceProfileAvailable
                    && nearbyDevicesPermissionGranted
                    == nextNearbyDevicesPermissionGranted
                    && bluetoothEnabled == nextBluetoothEnabled
                    && foregroundSessionActive == nextForegroundSessionActive
                    && appRegistered == nextAppRegistered
                    && hostConnected == nextHostConnected
                    && profileConnected == nextProfileConnected
                    && lastSendReportAccepted == nextLastSendReportAccepted;
        }

        SessionState withHidDeviceProfileAvailable(boolean value) {
            return copy(value, nearbyDevicesPermissionGranted, bluetoothEnabled,
                    foregroundSessionActive, appRegistered, hostConnected, profileConnected,
                    lastSendReportAccepted);
        }

        SessionState withNearbyDevicesPermissionGranted(boolean value) {
            return copy(hidDeviceProfileAvailable, value, bluetoothEnabled,
                    foregroundSessionActive, appRegistered, hostConnected, profileConnected,
                    lastSendReportAccepted);
        }

        SessionState withBluetoothEnabled(boolean value) {
            return copy(hidDeviceProfileAvailable, nearbyDevicesPermissionGranted, value,
                    foregroundSessionActive, appRegistered, hostConnected, profileConnected,
                    lastSendReportAccepted);
        }

        SessionState withForegroundSessionActive(boolean value) {
            return copy(hidDeviceProfileAvailable, nearbyDevicesPermissionGranted,
                    bluetoothEnabled, value, appRegistered, hostConnected, profileConnected,
                    lastSendReportAccepted);
        }

        SessionState withAppRegistered(boolean value) {
            return copy(hidDeviceProfileAvailable, nearbyDevicesPermissionGranted,
                    bluetoothEnabled, foregroundSessionActive, value, hostConnected,
                    profileConnected, lastSendReportAccepted);
        }

        SessionState withHostConnected(boolean value) {
            return copy(hidDeviceProfileAvailable, nearbyDevicesPermissionGranted,
                    bluetoothEnabled, foregroundSessionActive, appRegistered, value,
                    profileConnected, lastSendReportAccepted);
        }

        SessionState withProfileConnected(boolean value) {
            return copy(hidDeviceProfileAvailable, nearbyDevicesPermissionGranted,
                    bluetoothEnabled, foregroundSessionActive, appRegistered, hostConnected,
                    value, lastSendReportAccepted);
        }

        SessionState withLastSendReportAccepted(boolean value) {
            return copy(hidDeviceProfileAvailable, nearbyDevicesPermissionGranted,
                    bluetoothEnabled, foregroundSessionActive, appRegistered, hostConnected,
                    profileConnected, value);
        }

        private SessionState copy(
                boolean nextHidDeviceProfileAvailable,
                boolean nextNearbyDevicesPermissionGranted,
                boolean nextBluetoothEnabled,
                boolean nextForegroundSessionActive,
                boolean nextAppRegistered,
                boolean nextHostConnected,
                boolean nextProfileConnected,
                boolean nextLastSendReportAccepted) {
            return new SessionState(
                    nextHidDeviceProfileAvailable,
                    nextNearbyDevicesPermissionGranted,
                    nextBluetoothEnabled,
                    nextForegroundSessionActive,
                    nextAppRegistered,
                    nextHostConnected,
                    nextProfileConnected,
                    nextLastSendReportAccepted);
        }
    }

    static final class Decision {
        final boolean outputAllowed;
        final String reason;

        private Decision(boolean outputAllowed, String reason) {
            this.outputAllowed = outputAllowed;
            this.reason = reason;
        }

    }
}
