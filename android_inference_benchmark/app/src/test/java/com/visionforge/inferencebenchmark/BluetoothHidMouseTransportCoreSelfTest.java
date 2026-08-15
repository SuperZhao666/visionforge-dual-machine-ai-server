package com.visionforge.inferencebenchmark;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Dependency-free transport-level contract for the production Bluetooth HID adapter. */
final class BluetoothHidMouseTransportCoreSelfTest {
    static void run() {
        verifiesMoveOnlyReportAndClamping();
        verifiesRejectedNativeApiAcceptanceFailsClosed();
        verifiesDiagnosticMoveDoesNotCompleteNativeTicket();
        verifiesDisabledAndInvalidMovesDoNotSendReports();
        verifiesSendReportFalseFailsClosedImmediately();
        verifiesSuccessfulReconnectResetsDeliveryCircuit();
        verifiesSessionLossFailsClosedBeforeMoreReports();
        verifiesNativeRecoverySuspendsAndResumesDelivery();
        verifiesSynchronousMoveBufferIsReused();
        verifiesReconnectListenerRunsOutsideTransportMonitor();
    }

    private static void verifiesMoveOnlyReportAndClamping() {
        FakeSessionPort port = new FakeSessionPort();
        FakeMoveCompletionPort completionPort = new FakeMoveCompletionPort();
        BluetoothHidMouseTransportCore transport =
                new BluetoothHidMouseTransportCore(port, completionPort);

        require(transport.setOutputDeliveryAllowed(true));
        require(transport.offerMoveFromNative(300, -300, 7L));

        require(port.sentReports == 1);
        require(port.lastReport.length == 4);
        require(port.lastReport[0] == 0);
        require(port.lastReport[1] == 127);
        require(port.lastReport[2] == -127);
        require(port.lastReport[3] == 0);
        require(transport.deliveryState().usbWriteCompletionCount == 1L);
        require(!transport.deliveryState().circuitOpen);
        require(completionPort.attempts == 1);
        require(completionPort.confirmations == 1);
        require(completionPort.lastTicket == 7L);
        require(completionPort.lastAcceptanceMicros > 0L);
    }

    private static void verifiesRejectedNativeApiAcceptanceFailsClosed() {
        FakeSessionPort port = new FakeSessionPort();
        FakeMoveCompletionPort completionPort = new FakeMoveCompletionPort();
        completionPort.nextResult = false;
        BluetoothHidMouseTransportCore transport =
                new BluetoothHidMouseTransportCore(port, completionPort);

        require(transport.setOutputDeliveryAllowed(true));
        require(!transport.offerMoveFromNative(1, 0, 17L));
        require(port.sentReports == 1);
        require(completionPort.attempts == 1);
        require(completionPort.confirmations == 0);
        require(transport.deliveryState().circuitOpen);
        require(BluetoothHidOutputFailClosedPolicy.REASON_NATIVE_MOVE_COMPLETION_REJECTED.equals(
                transport.deliveryState().lastFailure));
    }

    private static void verifiesDiagnosticMoveDoesNotCompleteNativeTicket() {
        FakeSessionPort port = new FakeSessionPort();
        FakeMoveCompletionPort completionPort = new FakeMoveCompletionPort();
        BluetoothHidMouseTransportCore transport =
                new BluetoothHidMouseTransportCore(port, completionPort);

        require(transport.setOutputDeliveryAllowed(true));
        require(transport.sendDiagnosticMove(8, 4));
        require(port.sentReports == 1);
        require(completionPort.attempts == 0);
        require(completionPort.confirmations == 0);
        require(!transport.deliveryState().circuitOpen);
    }

    private static void verifiesDisabledAndInvalidMovesDoNotSendReports() {
        FakeSessionPort port = new FakeSessionPort();
        BluetoothHidMouseTransportCore transport = createTransport(port);

        require(!transport.offerMoveFromNative(1, 0, 1L));
        require(transport.setOutputDeliveryAllowed(true));
        require(!transport.offerMoveFromNative(0, 0, 2L));
        require(!transport.offerMoveFromNative(1, 0, 0L));
        require(transport.setOutputDeliveryAllowed(false));
        require(!transport.offerMoveFromNative(1, 0, 3L));

        require(port.sentReports == 0);
        require(!transport.deliveryState().circuitOpen);
    }

    private static void verifiesSendReportFalseFailsClosedImmediately() {
        FakeSessionPort port = new FakeSessionPort();
        port.nextSendResult = false;
        FakeMoveCompletionPort completionPort = new FakeMoveCompletionPort();
        BluetoothHidMouseTransportCore transport =
                new BluetoothHidMouseTransportCore(port, completionPort);

        require(transport.setOutputDeliveryAllowed(true));
        require(!transport.offerMoveFromNative(1, 0, 1L));
        require(transport.deliveryState().failureCount == 1L);
        require(transport.deliveryState().circuitOpen);
        require(BluetoothHidOutputFailClosedPolicy.REASON_SEND_REPORT_FALSE.equals(
                transport.deliveryState().lastFailure));
        require(!transport.offerMoveFromNative(1, 0, 2L));
        require(port.sentReports == 1);
        require(completionPort.attempts == 0);
        require(completionPort.confirmations == 0);
    }

    private static void verifiesSessionLossFailsClosedBeforeMoreReports() {
        assertSessionLossFailsClosed(
                BluetoothHidOutputFailClosedPolicy.SessionState.ready()
                        .withNearbyDevicesPermissionGranted(false),
                BluetoothHidOutputFailClosedPolicy.REASON_PERMISSION_REVOKED);
        assertSessionLossFailsClosed(
                BluetoothHidOutputFailClosedPolicy.SessionState.ready()
                        .withBluetoothEnabled(false),
                BluetoothHidOutputFailClosedPolicy.REASON_BLUETOOTH_DISABLED);
        assertSessionLossFailsClosed(
                BluetoothHidOutputFailClosedPolicy.SessionState.ready()
                        .withForegroundSessionActive(false),
                BluetoothHidOutputFailClosedPolicy.REASON_FOREGROUND_SESSION_LOST);
        assertSessionLossFailsClosed(
                BluetoothHidOutputFailClosedPolicy.SessionState.ready()
                        .withAppRegistered(false),
                BluetoothHidOutputFailClosedPolicy.REASON_REGISTER_APP_FAILED);
        assertSessionLossFailsClosed(
                BluetoothHidOutputFailClosedPolicy.SessionState.ready()
                        .withHostConnected(false),
                BluetoothHidOutputFailClosedPolicy.REASON_HOST_DISCONNECTED);
        assertSessionLossFailsClosed(
                BluetoothHidOutputFailClosedPolicy.SessionState.ready()
                        .withProfileConnected(false),
                BluetoothHidOutputFailClosedPolicy.REASON_PROFILE_DISCONNECTED);
    }

    private static void verifiesSuccessfulReconnectResetsDeliveryCircuit() {
        FakeSessionPort port = new FakeSessionPort();
        port.nextSendResult = false;
        BluetoothHidMouseTransportCore transport = createTransport(port);
        require(transport.setOutputDeliveryAllowed(true));
        require(!transport.offerMoveFromNative(1, 0, 1L));
        require(transport.deliveryState().circuitOpen);

        port.nextSendResult = true;
        transport.connectFirstSupportedDevice();
        require(!transport.deliveryState().circuitOpen);
        require(transport.setOutputDeliveryAllowed(true));
        require(transport.offerMoveFromNative(2, 0, 2L));
    }

    private static void verifiesNativeRecoverySuspendsAndResumesDelivery() {
        FakeSessionPort port = new FakeSessionPort();
        BluetoothHidMouseTransportCore transport = createTransport(port);

        require(transport.setOutputDeliveryAllowed(true));
        require(transport.suspendMoveDeliveryForNativeRecovery(41L));
        require(!transport.offerMoveFromNative(1, 0, 1L));
        require(!transport.resumeMoveDeliveryAfterNativeRecovery(42L));
        require(transport.resumeMoveDeliveryAfterNativeRecovery(41L));
        require(transport.offerMoveFromNative(1, 0, 2L));
        require(port.sentReports == 1);

        require(transport.failClosedNativeMoveDelivery());
        require(!transport.offerMoveFromNative(1, 0, 3L));
        require(port.sentReports == 1);
    }

    private static void verifiesSynchronousMoveBufferIsReused() {
        FakeSessionPort port = new FakeSessionPort();
        BluetoothHidMouseTransportCore transport = createTransport(port);
        require(transport.setOutputDeliveryAllowed(true));
        require(transport.offerMoveFromNative(1, 2, 1L));
        require(transport.offerMoveFromNative(3, 4, 2L));
        require(port.firstInputReport != null);
        require(port.firstInputReport == port.lastInputReport);
        require(port.lastReport[1] == 3 && port.lastReport[2] == 4);
    }

    private static void verifiesReconnectListenerRunsOutsideTransportMonitor() {
        FakeSessionPort port = new FakeSessionPort();
        BluetoothHidMouseTransportCore transport = createTransport(port);
        AtomicBoolean stateReadCompleted = new AtomicBoolean();
        transport.setReconnectListener(succeeded -> {
            require(succeeded);
            Thread stateReader = new Thread(() -> {
                transport.isReady();
                stateReadCompleted.set(true);
            });
            stateReader.start();
            try {
                stateReader.join(TimeUnit.SECONDS.toMillis(1L));
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new AssertionError("Interrupted while checking transport lock", exception);
            }
            require(!stateReader.isAlive());
            require(stateReadCompleted.get());
        });

        transport.connectFirstSupportedDevice();
        require(stateReadCompleted.get());
    }

    private static void assertSessionLossFailsClosed(
            BluetoothHidOutputFailClosedPolicy.SessionState failedState, String expectedReason) {
        FakeSessionPort port = new FakeSessionPort();
        BluetoothHidMouseTransportCore transport = createTransport(port);
        require(transport.setOutputDeliveryAllowed(true));
        port.state = failedState;

        require(!transport.offerMoveFromNative(1, 0, 1L));
        require(port.sentReports == 0);
        require(transport.deliveryState().circuitOpen);
        require(expectedReason.equals(transport.deliveryState().lastFailure));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("Bluetooth HID mouse transport core contract failed");
        }
    }

    private static BluetoothHidMouseTransportCore createTransport(FakeSessionPort port) {
        return new BluetoothHidMouseTransportCore(port, new FakeMoveCompletionPort());
    }

    private static final class FakeMoveCompletionPort
            implements BluetoothHidMouseTransportCore.MoveCompletionPort {
        boolean nextResult = true;
        int attempts;
        int confirmations;
        long lastTicket;
        long lastAcceptanceMicros;

        @Override
        public boolean reportApiAccepted(long ticket, long acceptanceMicros) {
            attempts++;
            if (!nextResult) return false;
            confirmations++;
            lastTicket = ticket;
            lastAcceptanceMicros = acceptanceMicros;
            return true;
        }
    }

    private static final class FakeSessionPort implements BluetoothHidMouseTransportCore.SessionPort {
        BluetoothHidOutputFailClosedPolicy.SessionState state =
                BluetoothHidOutputFailClosedPolicy.SessionState.ready();
        boolean nextSendResult = true;
        int sentReports;
        byte[] lastReport = new byte[0];
        byte[] firstInputReport;
        byte[] lastInputReport;

        @Override
        public BluetoothHidOutputFailClosedPolicy.SessionState sessionState() {
            return state;
        }

        @Override
        public boolean sendMouseReport(byte[] report) {
            sentReports++;
            if (firstInputReport == null) firstInputReport = report;
            lastInputReport = report;
            lastReport = report.clone();
            return nextSendResult;
        }

        @Override
        public void connectFirstSupportedHost() {
        }
    }
}
