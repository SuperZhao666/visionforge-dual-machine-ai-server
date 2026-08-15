package com.visionforge.inferencebenchmark;

/** Product-level failure-mode contract for the production Bluetooth HID route. */
final class BluetoothHidFailureModeSelfTest {
    static void run() {
        verifiesPermissionRevocationFailsClosedBeforeReport();
        verifiesHostAndProfileDisconnectFailClosedBeforeReport();
        verifiesSendReportFalseFailsClosedAndStopsNextReport();
        verifiesVerifiedReconnectRearmsAfterSendFailure();
        verifiesServiceTeardownClearsNativeMoveDispatcher();
    }

    private static void verifiesPermissionRevocationFailsClosedBeforeReport() {
        assertSessionFailure(
                BluetoothHidOutputFailClosedPolicy.SessionState.ready()
                        .withNearbyDevicesPermissionGranted(false),
                BluetoothHidOutputFailClosedPolicy.REASON_PERMISSION_REVOKED);
    }

    private static void verifiesHostAndProfileDisconnectFailClosedBeforeReport() {
        assertSessionFailure(
                BluetoothHidOutputFailClosedPolicy.SessionState.ready()
                        .withHostConnected(false),
                BluetoothHidOutputFailClosedPolicy.REASON_HOST_DISCONNECTED);
        assertSessionFailure(
                BluetoothHidOutputFailClosedPolicy.SessionState.ready()
                        .withProfileConnected(false),
                BluetoothHidOutputFailClosedPolicy.REASON_PROFILE_DISCONNECTED);
    }

    private static void verifiesSendReportFalseFailsClosedAndStopsNextReport() {
        FakeSessionPort port = new FakeSessionPort();
        port.nextSendResult = false;
        BluetoothHidMouseTransportCore transport = createTransport(port);

        ControlOutputMoveDispatcher.clearSink(null);
        try {
            ControlOutputMoveDispatcher.registerSink(transport);
            require(transport.setOutputDeliveryAllowed(true));

            require(!ControlOutputMoveDispatcher.offerNativeMove(1, 0, 101L));
            require(port.sentReports == 1);
            require(transport.deliveryState().circuitOpen);
            require(BluetoothHidOutputFailClosedPolicy.REASON_SEND_REPORT_FALSE.equals(
                    transport.deliveryState().lastFailure));

            port.nextSendResult = true;
            require(!ControlOutputMoveDispatcher.offerNativeMove(1, 0, 102L));
            require(port.sentReports == 1);
        } finally {
            ControlOutputMoveDispatcher.clearSink(transport);
        }
    }

    private static void verifiesServiceTeardownClearsNativeMoveDispatcher() {
        FakeSessionPort port = new FakeSessionPort();
        BluetoothHidMouseTransportCore transport = createTransport(port);

        ControlOutputMoveDispatcher.clearSink(null);
        ControlOutputMoveDispatcher.registerSink(transport);
        require(transport.setOutputDeliveryAllowed(true));
        require(ControlOutputMoveDispatcher.offerNativeMove(1, 0, 201L));
        require(port.sentReports == 1);

        ControlOutputMoveDispatcher.clearSink(transport);
        require(!ControlOutputMoveDispatcher.offerNativeMove(1, 0, 202L));
        require(port.sentReports == 1);
    }

    private static void verifiesVerifiedReconnectRearmsAfterSendFailure() {
        FakeSessionPort port = new FakeSessionPort();
        port.nextSendResult = false;
        BluetoothHidMouseTransportCore transport = createTransport(port);

        require(transport.setOutputDeliveryAllowed(true));
        require(!transport.offerMoveFromNative(1, 0, 401L));
        require(transport.deliveryState().circuitOpen);

        port.nextSendResult = true;
        transport.connectFirstSupportedDevice();
        require(!transport.deliveryState().circuitOpen);
        require(transport.setOutputDeliveryAllowed(true));
        require(transport.offerMoveFromNative(1, 0, 402L));
        require(port.sentReports == 2);
    }

    private static void assertSessionFailure(
            BluetoothHidOutputFailClosedPolicy.SessionState failedState,
            String expectedReason) {
        FakeSessionPort port = new FakeSessionPort();
        BluetoothHidMouseTransportCore transport = createTransport(port);

        ControlOutputMoveDispatcher.clearSink(null);
        try {
            ControlOutputMoveDispatcher.registerSink(transport);
            require(transport.setOutputDeliveryAllowed(true));
            port.state = failedState;

            require(!ControlOutputMoveDispatcher.offerNativeMove(1, 0, 301L));
            require(port.sentReports == 0);
            require(transport.deliveryState().circuitOpen);
            require(expectedReason.equals(transport.deliveryState().lastFailure));
        } finally {
            ControlOutputMoveDispatcher.clearSink(transport);
        }
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("Bluetooth HID failure-mode contract failed");
        }
    }

    private static BluetoothHidMouseTransportCore createTransport(FakeSessionPort port) {
        return new BluetoothHidMouseTransportCore(
                port, (ticket, acceptanceMicros) -> true);
    }

    private static final class FakeSessionPort
            implements BluetoothHidMouseTransportCore.SessionPort {
        BluetoothHidOutputFailClosedPolicy.SessionState state =
                BluetoothHidOutputFailClosedPolicy.SessionState.ready();
        boolean nextSendResult = true;
        int sentReports;

        @Override
        public BluetoothHidOutputFailClosedPolicy.SessionState sessionState() {
            return state;
        }

        @Override
        public boolean sendMouseReport(byte[] report) {
            sentReports++;
            return nextSendResult;
        }

        @Override
        public void connectFirstSupportedHost() {
        }
    }
}
