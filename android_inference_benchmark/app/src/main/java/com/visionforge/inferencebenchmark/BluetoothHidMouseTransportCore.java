package com.visionforge.inferencebenchmark;

/** Move-only Bluetooth HID transport core backed by Android's HID device API. */
final class BluetoothHidMouseTransportCore implements ControlOutputTransport, ControlOutputMoveSink {
    interface SessionPort {
        BluetoothHidOutputFailClosedPolicy.SessionState sessionState();

        /** Consumes this report synchronously; the caller reuses its buffer. */
        boolean sendMouseReport(byte[] report);

        void connectFirstSupportedHost();
    }

    interface MoveCompletionPort {
        boolean reportApiAccepted(long ticket, long acceptanceMicros);
    }

    private final SessionPort sessionPort;
    private final MoveCompletionPort moveCompletionPort;
    private final MakcuDeliveryCircuit deliveryCircuit = new MakcuDeliveryCircuit(1);
    private final byte[] reusableMouseReport = new byte[4];
    private boolean outputDeliveryAllowed;
    private boolean deliveryAllowedBeforeRecovery;
    private boolean nativeRecoverySuspended;
    private long recoveryGeneration;
    private ReconnectListener reconnectListener;

    BluetoothHidMouseTransportCore(
            SessionPort sessionPort,
            MoveCompletionPort moveCompletionPort) {
        if (sessionPort == null) throw new IllegalArgumentException("sessionPort");
        if (moveCompletionPort == null) throw new IllegalArgumentException("moveCompletionPort");
        this.sessionPort = sessionPort;
        this.moveCompletionPort = moveCompletionPort;
    }

    @Override
    public synchronized boolean isReady() {
        return isReadyLocked();
    }

    private boolean isReadyLocked() {
        return !deliveryCircuit.snapshot().circuitOpen
                && BluetoothHidOutputFailClosedPolicy.evaluate(sessionPort.sessionState())
                .outputAllowed;
    }

    @Override
    public void connectFirstSupportedDevice() {
        ReconnectListener listener;
        boolean ready;
        synchronized (this) {
            sessionPort.connectFirstSupportedHost();
            boolean sessionReady = BluetoothHidOutputFailClosedPolicy.evaluate(
                    sessionPort.sessionState()).outputAllowed;
            if (sessionReady) deliveryCircuit.resetAfterSuccessfulReconnect();
            listener = reconnectListener;
            ready = isReadyLocked();
        }
        // Never invoke coordinator code while holding the transport monitor:
        // coordinator reconciliation calls back into this transport and would
        // otherwise create a Coordinator -> Transport / Transport -> Coordinator
        // lock inversion across the runtime and Bluetooth callback threads.
        if (listener != null) listener.onReconnectResult(ready);
    }

    @Override
    public synchronized void setReconnectListener(ReconnectListener listener) {
        reconnectListener = listener;
    }

    @Override
    public synchronized boolean setOutputDeliveryAllowed(boolean allowed) {
        if (!allowed) {
            outputDeliveryAllowed = false;
            return true;
        }
        if (nativeRecoverySuspended || !isReady()) {
            outputDeliveryAllowed = false;
            return false;
        }
        outputDeliveryAllowed = true;
        return true;
    }

    @Override
    public synchronized MakcuDeliveryState deliveryState() {
        return deliveryCircuit.snapshot();
    }

    @Override
    public synchronized boolean offerMoveFromNative(int deltaX, int deltaY, long ticket) {
        if (ticket <= 0L) return false;
        return sendMove(deltaX, deltaY, ticket, true);
    }

    /** Debug-only direct HID send that never completes or mutates a native move ticket. */
    synchronized boolean sendDiagnosticMove(int deltaX, int deltaY) {
        return sendMove(deltaX, deltaY, 0L, false);
    }

    private boolean sendMove(
            int deltaX,
            int deltaY,
            long ticket,
            boolean reportNativeApiAcceptance) {
        int boundedX = clampMouseDelta(deltaX);
        int boundedY = clampMouseDelta(deltaY);
        if (boundedX == 0 && boundedY == 0) return false;
        if (!outputDeliveryAllowed || nativeRecoverySuspended) return false;

        BluetoothHidOutputFailClosedPolicy.Decision decision =
                BluetoothHidOutputFailClosedPolicy.evaluate(sessionPort.sessionState());
        if (!decision.outputAllowed) {
            recordDeliveryFailure(decision.reason);
            return false;
        }

        reusableMouseReport[0] = 0;
        reusableMouseReport[1] = (byte) boundedX;
        reusableMouseReport[2] = (byte) boundedY;
        reusableMouseReport[3] = 0;
        long started = System.nanoTime();
        if (!sessionPort.sendMouseReport(reusableMouseReport)) {
            recordDeliveryFailure(BluetoothHidOutputFailClosedPolicy.REASON_SEND_REPORT_FALSE);
            return false;
        }
        long acceptanceMicros = Math.max(1L, (System.nanoTime() - started) / 1_000L);
        deliveryCircuit.recordUsbWriteCompletion(acceptanceMicros);
        if (reportNativeApiAcceptance
                && !moveCompletionPort.reportApiAccepted(ticket, acceptanceMicros)) {
            recordDeliveryFailure(
                    BluetoothHidOutputFailClosedPolicy.REASON_NATIVE_MOVE_COMPLETION_REJECTED);
            return false;
        }
        return true;
    }

    @Override
    public synchronized boolean suspendMoveDeliveryForNativeRecovery(long generation) {
        if (generation <= 0L) return false;
        deliveryAllowedBeforeRecovery = outputDeliveryAllowed;
        outputDeliveryAllowed = false;
        nativeRecoverySuspended = true;
        recoveryGeneration = generation;
        return true;
    }

    @Override
    public synchronized boolean resumeMoveDeliveryAfterNativeRecovery(long generation) {
        if (!nativeRecoverySuspended || recoveryGeneration != generation) return false;
        nativeRecoverySuspended = false;
        recoveryGeneration = 0L;
        if (!isReady()) {
            outputDeliveryAllowed = false;
            deliveryAllowedBeforeRecovery = false;
            return false;
        }
        outputDeliveryAllowed = deliveryAllowedBeforeRecovery;
        deliveryAllowedBeforeRecovery = false;
        return true;
    }

    @Override
    public synchronized boolean failClosedNativeMoveDelivery() {
        outputDeliveryAllowed = false;
        deliveryAllowedBeforeRecovery = false;
        nativeRecoverySuspended = false;
        recoveryGeneration = 0L;
        return true;
    }

    private void recordDeliveryFailure(String reason) {
        deliveryCircuit.recordFailure(reason);
        outputDeliveryAllowed = false;
        deliveryAllowedBeforeRecovery = false;
        nativeRecoverySuspended = false;
        recoveryGeneration = 0L;
    }

    private static int clampMouseDelta(int value) {
        return Math.max(-127, Math.min(127, value));
    }
}
