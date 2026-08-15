package com.visionforge.inferencebenchmark;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Phone-side MAKCU transport. This class is the sole owner of Android USB
 * Host serial I/O; it has no network endpoint and cannot affect Windows
 * directly. Native QNN code submits one ticketed relative movement at a time
 * through ControlOutputMoveDispatcher; the next plan is released only by this
 * class's firmware echo + prompt result.
 */
final class MakcuSerialController implements MakcuConnection, MakcuButtonInput, ControlOutputMoveSink {
    private static final String LOG_TAG = "VisionForgeMakcu";
    private static final int CDC_CONTROL_TRANSFER_TIMEOUT_MILLIS = 500;
    private static final int RESPONSE_READER_TIMEOUT_MILLIS = 4;
    private static final long COMMAND_RESPONSE_TIMEOUT_NANOS = 50_000_000L;
    private static final String USB_PERMISSION_ACTION =
            "com.visionforge.inferencebenchmark.MAKCU_USB_PERMISSION";
    private static final String EXTRA_ATTEMPT_GENERATION =
            "com.visionforge.inferencebenchmark.MAKCU_ATTEMPT_GENERATION";
    private static final String EXTRA_EXPECTED_DEVICE_NAME =
            "com.visionforge.inferencebenchmark.MAKCU_EXPECTED_DEVICE_NAME";
    private static volatile MakcuSerialController instance;

    private final Context context;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final UsbManager usbManager;
    private final MobileRuntimeEventSink events;
    private final ExecutorService writer = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "makcu-serial-writer");
        thread.setDaemon(true);
        return thread;
    });
    private final ExecutorService reader = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "makcu-serial-reader");
        thread.setDaemon(true);
        return thread;
    });
    private final MakcuPendingMoveSlot pendingMoveSlot = new MakcuPendingMoveSlot();
    private final MakcuPendingMoveSlot.PendingMove reusablePendingMove =
            new MakcuPendingMoveSlot.PendingMove();
    private final AtomicBoolean drainQueued = new AtomicBoolean();
    private final AtomicLong offeredMoves = new AtomicLong();
    private final AtomicLong droppedDisconnected = new AtomicLong();
    private final AtomicLong droppedOutputDisabled = new AtomicLong();
    private final AtomicLong deviceCommandAcknowledgements = new AtomicLong();
    private final AtomicLong moveCommandAcknowledgements = new AtomicLong();
    private final AtomicLong deviceAcknowledgementFailures = new AtomicLong();
    private final AtomicLong unexpectedDeviceResponses = new AtomicLong();
    private final AtomicLong responseParserOverflows = new AtomicLong();
    private final AtomicLong physicalButtonSnapshots = new AtomicLong();
    private final AtomicLong lastDeviceAcknowledgementMicros = new AtomicLong();
    private final AtomicLong responseReaderLeaseGeneration = new AtomicLong();
    private final AtomicBoolean responseReaderRunning = new AtomicBoolean();
    private final AtomicBoolean buttonStreamEnabled = new AtomicBoolean();
    private final AtomicBoolean buttonStreamReady = new AtomicBoolean();
    private final AtomicBoolean buttonStreamCommandPending = new AtomicBoolean();
    private final AtomicBoolean destroyed = new AtomicBoolean();
    private final AtomicReference<MakcuButtonInput.Listener> buttonStateListener =
            new AtomicReference<>();
    private final Object responseLock = new Object();
    private final Object buttonStateLock = new Object();
    private final Object serialIoLock = new Object();
    private final MakcuDeliveryGate deliveryGate =
            new MakcuDeliveryGate(pendingMoveSlot, serialIoLock);
    private final MakcuDeliveryCircuit deliveryCircuit = new MakcuDeliveryCircuit();
    private final MakcuConnectionAttemptTracker connectionAttempts =
            new MakcuConnectionAttemptTracker();
    private final MakcuProtocolNegotiator protocolNegotiator =
            new MakcuProtocolNegotiator(SystemClock::sleep);
    private final AtomicReference<AndroidSerialPort> inFlightPort = new AtomicReference<>();
    private final BroadcastReceiver usbReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            UsbDevice device = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
            if (UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action)) {
                handleDeviceDetached(device);
            } else if (UsbManager.ACTION_USB_DEVICE_ATTACHED.equals(action)) {
                handleDeviceAttached(device);
            } else if (USB_PERMISSION_ACTION.equals(action)) {
                handlePermissionResult(intent);
            }
        }
    };

    private volatile RawUsbTransport activeTransport;
    private volatile String lastStatus = "MAKCU not connected";
    private volatile String serialReadyStatus = "MAKCU not connected";
    private volatile String activeDeviceName;
    private volatile long activeConnectionGeneration;
    private volatile boolean adapterIdentityVerified;
    private volatile boolean protocolIdentityVerified;
    private volatile int selectedBaudRate;
    private volatile ReconnectListener reconnectListener;
    private volatile String expectedResponseCommand;
    private volatile long expectedResponseConnectionGeneration;
    private volatile long expectedResponseReaderLease;
    private volatile boolean expectedResponseAcknowledged;

    MakcuSerialController(Context ownerContext, MobileRuntimeEventSink events) {
        this.context = ownerContext.getApplicationContext();
        this.events = events;
        this.usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
        IntentFilter usbFilter = new IntentFilter(USB_PERMISSION_ACTION);
        usbFilter.addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED);
        usbFilter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
        context.registerReceiver(usbReceiver, usbFilter, Context.RECEIVER_NOT_EXPORTED);
        instance = this;
        if (!QnnHtpBridge.bindNativeMakcuMoveBridge(ControlOutputMoveDispatcher.class)) {
            lastStatus = "Native MAKCU bridge binding failed; output is disabled";
            events.write("makcu_native_bridge_failed", "output_disabled=true");
        }
    }

    @Override
    public void connectFirstSupportedDevice() {
        if (destroyed.get()) return;
        if (isReady()) return;
        if (usbManager == null) {
            cancelAttemptsAndClose();
            lastStatus = "Android USB Host service unavailable";
            notifyReconnectFailure();
            return;
        }
        UsbDevice device = findFirstExpectedAdapter();
        if (device == null) {
            cancelAttemptsAndClose();
            lastStatus = "No verified MAKCU CH343 found; expected "
                    + MakcuDeviceIdentityPolicy.adapterToken(
                    MakcuDeviceIdentityPolicy.WCH_VENDOR_ID,
                    MakcuDeviceIdentityPolicy.CH343_PRODUCT_ID);
            notifyReconnectFailure();
            return;
        }
        if (!usbManager.hasPermission(device)) {
            requestPermissionIfNeeded(device);
            return;
        }
        startConnectionAttempt(device.getDeviceName());
    }

    @Override
    public void setReconnectListener(ReconnectListener listener) {
        reconnectListener = listener;
    }

    @Override
    public void setButtonStateListener(MakcuButtonInput.Listener listener) {
        buttonStateListener.set(listener);
    }

    @Override
    public void setRequiredTriggerMask(int requiredButtonMask) {
        int normalizedMask = Math.max(0, requiredButtonMask);
        boolean changed =
                deliveryGate.requiredPhysicalButtonMask() != normalizedMask;
        rejectPhysicalTriggerMove(
                deliveryGate.setRequiredPhysicalButtonMask(normalizedMask));
        boolean required = normalizedMask != 0;
        if (!required) buttonStreamReady.set(false);
        if (!changed && (!required || buttonStreamReady.get())) return;
        scheduleButtonStreamConfiguration();
    }

    @Override
    public int currentButtonMask() {
        return deliveryGate.currentPhysicalButtonMask();
    }

    @Override
    public boolean isButtonStreamReady() {
        return buttonStreamReady.get() && buttonStreamEnabled.get()
                && isReady();
    }

    private void requestPermissionIfNeeded(UsbDevice device) {
        String deviceName = device.getDeviceName();
        if (connectionAttempts.isPermissionPendingFor(deviceName)) {
            lastStatus = "Waiting for Android USB permission: " + deviceName;
            return;
        }
        MakcuConnectionAttemptTracker.Attempt attempt =
                connectionAttempts.begin(deviceName, true);
        failClosedDelivery();
        closeInFlightPort();
        closeActiveTransport();
        Intent intent = new Intent(USB_PERMISSION_ACTION)
                .setPackage(context.getPackageName())
                .putExtra(EXTRA_ATTEMPT_GENERATION, attempt.generation)
                .putExtra(EXTRA_EXPECTED_DEVICE_NAME, attempt.deviceName);
        int requestCode = (int) (attempt.generation & 0x7fff_ffffL);
        PendingIntent pendingIntent = PendingIntent.getBroadcast(context, requestCode, intent,
                PendingIntent.FLAG_CANCEL_CURRENT | PendingIntent.FLAG_ONE_SHOT
                        | PendingIntent.FLAG_IMMUTABLE);
        try {
            usbManager.requestPermission(device, pendingIntent);
            lastStatus = "Waiting for Android USB permission: " + deviceName;
            events.write("makcu_usb_permission_requested", "generation=" + attempt.generation
                    + " device=" + reportToken(deviceName));
        } catch (RuntimeException exception) {
            connectionAttempts.clearIfCurrent(attempt.generation, attempt.deviceName);
            lastStatus = "Cannot request MAKCU USB permission: "
                    + exception.getClass().getSimpleName();
            events.write("makcu_usb_permission_request_failed", "generation="
                    + attempt.generation + " exception=" + exception.getClass().getSimpleName());
            notifyReconnectFailure();
        }
    }

    private void handlePermissionResult(Intent intent) {
        long generation = intent.getLongExtra(EXTRA_ATTEMPT_GENERATION, -1L);
        String expectedDeviceName = intent.getStringExtra(EXTRA_EXPECTED_DEVICE_NAME);
        if (!connectionAttempts.consumePermission(generation, expectedDeviceName)) {
            events.write("makcu_usb_permission_result_ignored", "generation=" + generation
                    + " device=" + reportToken(expectedDeviceName) + " reason=stale_attempt");
            return;
        }
        UsbDevice attachedDevice = findExpectedAdapter(expectedDeviceName);
        boolean granted = attachedDevice != null && usbManager.hasPermission(attachedDevice);
        events.write("makcu_usb_permission_result", "generation=" + generation
                + " device=" + reportToken(expectedDeviceName) + " granted=" + granted
                + " evidence=fresh_usb_manager_permission_state");
        if (!granted || attachedDevice == null || !usbManager.hasPermission(attachedDevice)) {
            failCurrentAttempt(generation, expectedDeviceName,
                    granted ? "Authorized MAKCU adapter is no longer attached"
                            : "USB permission was denied");
            return;
        }
        scheduleConnectionAttempt(new MakcuConnectionAttemptTracker.Attempt(
                generation, expectedDeviceName));
    }

    private void handleDeviceAttached(UsbDevice device) {
        if (device == null || !MakcuDeviceIdentityPolicy.isExpectedAdapter(
                device.getVendorId(), device.getProductId())) {
            return;
        }
        events.write("makcu_usb_attached",
                "device=" + reportToken(device.getDeviceName())
                        + " identity=" + MakcuDeviceIdentityPolicy.adapterToken(
                        device.getVendorId(), device.getProductId())
                        + " automatic_connect=true");
        connectFirstSupportedDevice();
    }

    private void startConnectionAttempt(String deviceName) {
        MakcuConnectionAttemptTracker.Attempt attempt =
                connectionAttempts.begin(deviceName, false);
        failClosedDelivery();
        closeInFlightPort();
        closeActiveTransport();
        lastStatus = "Verifying MAKCU protocol asynchronously: " + deviceName;
        events.write("makcu_connection_attempt_started", "generation=" + attempt.generation
                + " device=" + reportToken(deviceName) + " output_disabled=true");
        scheduleConnectionAttempt(attempt);
    }

    private void scheduleConnectionAttempt(MakcuConnectionAttemptTracker.Attempt attempt) {
        try {
            writer.execute(() -> completeConnectionAttempt(attempt));
        } catch (RejectedExecutionException exception) {
            failCurrentAttempt(attempt.generation, attempt.deviceName,
                    "MAKCU serial executor unavailable");
        }
    }

    private void completeConnectionAttempt(MakcuConnectionAttemptTracker.Attempt attempt) {
        if (!connectionAttempts.isCurrent(attempt.generation, attempt.deviceName)) return;
        UsbDevice device = findExpectedAdapter(attempt.deviceName);
        if (device == null || !usbManager.hasPermission(device)) {
            failCurrentAttempt(attempt.generation, attempt.deviceName,
                    "MAKCU adapter disappeared before serial open");
            return;
        }
        AndroidSerialPort port = new AndroidSerialPort(attempt);
        if (!inFlightPort.compareAndSet(null, port)) {
            failCurrentAttempt(attempt.generation, attempt.deviceName,
                    "Another MAKCU negotiation still owns the serial transport");
            return;
        }
        boolean published = false;
        try {
            MakcuProtocolNegotiator.Result result = protocolNegotiator.negotiate(
                    port, () -> !connectionAttempts.isCurrent(
                            attempt.generation, attempt.deviceName));
            if (!result.succeeded) {
                events.write("makcu_protocol_negotiation_failed", "generation="
                        + attempt.generation + " device=" + reportToken(attempt.deviceName)
                        + " stage=" + result.stage + " detail=" + port.failureToken());
                failCurrentAttempt(attempt.generation, attempt.deviceName,
                        "MAKCU baud/protocol negotiation failed stage=" + result.stage
                                + " detail=" + port.failureToken());
                return;
            }
            published = publishVerifiedConnection(attempt, port, result.stage);
        } catch (RuntimeException | LinkageError exception) {
            handleUnexpectedConnectionFailure(attempt, exception);
        } finally {
            inFlightPort.compareAndSet(port, null);
            if (!published) port.close();
        }
    }

    private void handleUnexpectedConnectionFailure(
            MakcuConnectionAttemptTracker.Attempt attempt, Throwable exception) {
        Log.e(LOG_TAG, "Unexpected MAKCU connection failure generation="
                + attempt.generation + " device=" + reportToken(attempt.deviceName), exception);
        try {
            events.write("makcu_connection_attempt_exception", "generation="
                    + attempt.generation + " device=" + reportToken(attempt.deviceName)
                    + " exception=" + exception.getClass().getSimpleName()
                    + " output_disabled=true");
        } catch (Throwable eventFailure) {
            Log.e(LOG_TAG, "Cannot record MAKCU connection failure event", eventFailure);
        }
        connectionAttempts.clearIfCurrent(attempt.generation, attempt.deviceName);
        failClosedDelivery();
        try {
            closeActiveTransport();
        } catch (Throwable closeFailure) {
            Log.e(LOG_TAG, "Cannot fully close MAKCU transport after connection failure",
                    closeFailure);
        }
        lastStatus = "Unexpected MAKCU connection failure: "
                + exception.getClass().getSimpleName();
        notifyReconnectFailure();
    }

    private boolean publishVerifiedConnection(MakcuConnectionAttemptTracker.Attempt attempt,
                                              AndroidSerialPort port, String protocolStage) {
        synchronized (serialIoLock) {
            if (!connectionAttempts.isCurrent(attempt.generation, attempt.deviceName)
                    || findExpectedAdapter(attempt.deviceName) == null || !port.isOpen()) {
                return false;
            }
            activeTransport = port.releaseTransport();
            activeDeviceName = attempt.deviceName;
            activeConnectionGeneration = attempt.generation;
            adapterIdentityVerified = true;
            protocolIdentityVerified = true;
            selectedBaudRate = MakcuProtocolNegotiator.OPERATING_BAUD_RATE;
            deliveryCircuit.resetAfterSuccessfulReconnect();
            serialReadyStatus = "MAKCU protocol verified: "
                    + MakcuDeviceIdentityPolicy.adapterToken(
                    MakcuDeviceIdentityPolicy.WCH_VENDOR_ID,
                    MakcuDeviceIdentityPolicy.CH343_PRODUCT_ID)
                    + " baud=" + selectedBaudRate + " 8N1 stage=" + protocolStage;
            lastStatus = serialReadyStatus;
        }
        connectionAttempts.clearIfCurrent(attempt.generation, attempt.deviceName);
        if (!startResponseReader(attempt.generation)) {
            closeActiveTransport();
            return false;
        }
        if (deliveryGate.requiredPhysicalButtonMask() != 0) {
            scheduleButtonStreamConfiguration();
        }
        events.write("makcu_protocol_negotiation_completed", "generation="
                + attempt.generation + " device=" + reportToken(attempt.deviceName)
                + " selected_baud=" + MakcuProtocolNegotiator.OPERATING_BAUD_RATE
                + " stage=" + protocolStage + " output_enabled=false");
        notifyReconnectSuccess(attempt.generation);
        return true;
    }

    private void failCurrentAttempt(long generation, String deviceName, String reason) {
        if (!connectionAttempts.isCurrent(generation, deviceName)) return;
        connectionAttempts.clearIfCurrent(generation, deviceName);
        failClosedDelivery();
        lastStatus = reason;
        notifyReconnectFailure();
    }

    private void handleDeviceDetached(UsbDevice device) {
        if (device == null) return;
        String deviceName = device.getDeviceName();
        boolean active = MakcuDeviceIdentityPolicy.isSameDevice(activeDeviceName, deviceName);
        if (!active && !connectionAttempts.isForDevice(deviceName)) return;
        connectionAttempts.cancel();
        failClosedDelivery();
        closeInFlightPort();
        closeActiveTransport();
        lastStatus = "MAKCU USB detached; automatic output gate closed";
        events.write("makcu_usb_detached", "device=" + reportToken(deviceName)
                + " output_disabled=true authorization_revoked=true");
        notifyReconnectFailure();
    }

    private UsbDevice findFirstExpectedAdapter() {
        for (UsbDevice device : usbManager.getDeviceList().values()) {
            if (MakcuDeviceIdentityPolicy.isExpectedAdapter(
                    device.getVendorId(), device.getProductId())) return device;
        }
        return null;
    }

    private UsbDevice findExpectedAdapter(String deviceName) {
        if (deviceName == null || usbManager == null) return null;
        for (UsbDevice device : usbManager.getDeviceList().values()) {
            if (MakcuDeviceIdentityPolicy.isSameDevice(deviceName, device.getDeviceName())
                    && MakcuDeviceIdentityPolicy.isExpectedAdapter(
                    device.getVendorId(), device.getProductId())) return device;
        }
        return null;
    }

    static boolean offerNativeMove(int deltaX, int deltaY, long ticket) {
        MakcuSerialController controller = instance;
        return controller != null && controller.offerMove(deltaX, deltaY, ticket);
    }

    @Override
    public boolean offerMoveFromNative(int deltaX, int deltaY, long ticket) {
        return offerMove(deltaX, deltaY, ticket);
    }

    private boolean offerMove(int deltaX, int deltaY, long ticket) {
        int boundedX = Math.max(-127, Math.min(127, deltaX));
        int boundedY = Math.max(-127, Math.min(127, deltaY));
        if ((boundedX == 0 && boundedY == 0) || ticket <= 0L) return false;
        if (!deliveryGate.isDeliveryAllowed()
                || !deliveryGate.isPhysicalTriggerSatisfied()) {
            droppedOutputDisabled.incrementAndGet();
            return false;
        }
        offeredMoves.incrementAndGet();
        long packed = packMove(boundedX, boundedY);
        pendingMoveSlot.offer(packed, ticket);
        if (!deliveryGate.isDeliveryAllowed()
                || !deliveryGate.isPhysicalTriggerSatisfied()) {
            if (pendingMoveSlot.clearIfMatches(packed, ticket)) {
                droppedOutputDisabled.incrementAndGet();
            }
            return false;
        }
        if (drainQueued.compareAndSet(false, true)) {
            try {
                writer.execute(this::drainLatestMove);
            } catch (RejectedExecutionException exception) {
                drainQueued.set(false);
                pendingMoveSlot.clearIfMatches(packed, ticket);
                return false;
            }
        }
        return true;
    }

    private void drainLatestMove() {
        long ticket = 0L;
        try {
            if (!pendingMoveSlot.takeInto(reusablePendingMove)) return;
            long packed = reusablePendingMove.packed;
            ticket = reusablePendingMove.ticket;
            if (!deliveryGate.isDeliveryAllowed()
                    || !deliveryGate.isPhysicalTriggerSatisfied()) {
                droppedOutputDisabled.incrementAndGet();
                reportUndeliveredMoveUnlessRecoveryCancelled(ticket);
                return;
            }
            writeMoveIfStillAllowed(packed, ticket);
        } catch (Throwable exception) {
            if (ticket > 0L) {
                QnnHtpBridge.reportNativeMakcuMoveResult(ticket, false, 0L);
            }
            synchronized (serialIoLock) {
                invalidateProtocolAfterDeliveryFailureLocked(
                        "serial_exception type="
                                + exception.getClass().getSimpleName());
            }
        } finally {
            drainQueued.set(false);
            if (pendingMoveSlot.hasPending()
                    && drainQueued.compareAndSet(false, true)) {
                try {
                    writer.execute(this::drainLatestMove);
                } catch (RejectedExecutionException exception) {
                    drainQueued.set(false);
                    long rejectedTicket = pendingMoveSlot.clear();
                    if (rejectedTicket > 0L) {
                        QnnHtpBridge.reportNativeMakcuMoveResult(
                                rejectedTicket, false, 0L);
                    }
                }
            }
        }
    }

    private void writeMoveIfStillAllowed(long packed, long ticket) {
        synchronized (serialIoLock) {
            if (!deliveryGate.isDeliveryAllowed()
                    || !deliveryGate.isPhysicalTriggerSatisfied()) {
                droppedOutputDisabled.incrementAndGet();
                reportUndeliveredMoveUnlessRecoveryCancelled(ticket);
                return;
            }
            RawUsbTransport target = activeTransport;
            if (target == null) {
                droppedDisconnected.incrementAndGet();
                QnnHtpBridge.reportNativeMakcuMoveResult(ticket, false, 0L);
                invalidateProtocolAfterDeliveryFailureLocked(
                        "serial_disconnected");
                return;
            }
            String commandText =
                    "km.move(" + unpackX(packed) + "," + unpackY(packed) + ")\r\n";
            byte[] command = commandText.getBytes(StandardCharsets.US_ASCII);
            long started = SystemClock.elapsedRealtimeNanos();
            long commandConnectionGeneration = activeConnectionGeneration;
            long commandReaderLease = responseReaderLeaseGeneration.get();
            beginExpectedResponse(
                    commandText, commandConnectionGeneration, commandReaderLease);
            int wrote = target.write(command, 25);
            long writeMicros = (SystemClock.elapsedRealtimeNanos() - started) / 1_000L;
            if (wrote == command.length) {
                deliveryCircuit.recordUsbWriteCompletion(writeMicros);
                long acknowledgementMicros =
                        awaitExecutedAcknowledgement(
                                target,
                                commandText,
                                started,
                                commandConnectionGeneration,
                                commandReaderLease);
                if (acknowledgementMicros >= 0L) {
                    deviceCommandAcknowledgements.incrementAndGet();
                    moveCommandAcknowledgements.incrementAndGet();
                    lastDeviceAcknowledgementMicros.set(acknowledgementMicros);
                    lastStatus = serialReadyStatus;
                    QnnHtpBridge.reportNativeMakcuMoveResult(
                            ticket, true, acknowledgementMicros);
                } else {
                    deviceAcknowledgementFailures.incrementAndGet();
                    QnnHtpBridge.reportNativeMakcuMoveResult(ticket, false, 0L);
                    invalidateProtocolAfterDeliveryFailureLocked(
                            "device_ack_timeout_or_mismatch");
                    lastStatus =
                            "MAKCU command acknowledgement failed; reconnect required";
                    events.write("makcu_device_ack_failed",
                            "command=km.move protocol_identity_verified=false "
                                    + "output_disabled=true reconnect_required=true");
                }
            } else {
                cancelExpectedResponse(
                        commandText,
                        commandConnectionGeneration,
                        commandReaderLease);
                QnnHtpBridge.reportNativeMakcuMoveResult(ticket, false, 0L);
                invalidateProtocolAfterDeliveryFailureLocked(
                        "partial_write bytes=" + wrote
                                + " expected=" + command.length);
            }
        }
    }

    private long awaitExecutedAcknowledgement(
            RawUsbTransport target,
            String expectedCommand,
            long startedNanos,
            long connectionGeneration,
            long readerLease) {
        if (target == null) {
            cancelExpectedResponse(
                    expectedCommand, connectionGeneration, readerLease);
            return -1L;
        }
        long deadline = startedNanos + COMMAND_RESPONSE_TIMEOUT_NANOS;
        synchronized (responseLock) {
            while (isExpectedResponseLocked(
                    expectedCommand, connectionGeneration, readerLease)
                    && !expectedResponseAcknowledged) {
                long remaining = deadline - SystemClock.elapsedRealtimeNanos();
                if (remaining <= 0L) break;
                long millis = remaining / 1_000_000L;
                int nanos = (int) (remaining % 1_000_000L);
                try {
                    responseLock.wait(millis, nanos);
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            boolean acknowledged = isExpectedResponseLocked(
                    expectedCommand, connectionGeneration, readerLease)
                    && expectedResponseAcknowledged;
            clearExpectedResponseLocked();
            if (!acknowledged) return -1L;
        }
        return (SystemClock.elapsedRealtimeNanos() - startedNanos) / 1_000L;
    }

    private MakcuResponseStreamParser createResponseParser(
            long readerLease,
            long connectionGeneration,
            RawUsbTransport target) {
        return new MakcuResponseStreamParser(new MakcuResponseStreamParser.Listener() {
            @Override
            public void onButtonMask(int mask) {
                synchronized (buttonStateLock) {
                    if (!isResponseReaderLeaseCurrent(
                            readerLease, connectionGeneration, target)) {
                        return;
                    }
                    int previous = deliveryGate.currentPhysicalButtonMask();
                    rejectPhysicalTriggerMove(
                            deliveryGate.updatePhysicalButtonMask(mask));
                    physicalButtonSnapshots.incrementAndGet();
                    if (previous != mask) {
                        notifyButtonStateChanged(mask);
                    }
                }
            }

            @Override
            public void onResponse(String response) {
                synchronized (responseLock) {
                    String expected = expectedResponseCommand;
                    if (isResponseReaderLeaseCurrent(
                            readerLease, connectionGeneration, target)
                            && expected != null
                            && expectedResponseConnectionGeneration
                            == connectionGeneration
                            && expectedResponseReaderLease == readerLease
                            && MakcuResponseStreamParser.isExecutedAcknowledgement(
                            response, expected)) {
                        expectedResponseAcknowledged = true;
                        responseLock.notifyAll();
                    } else {
                        unexpectedDeviceResponses.incrementAndGet();
                    }
                }
            }

            @Override
            public void onResponseOverflow() {
                if (!isResponseReaderLeaseCurrent(
                        readerLease, connectionGeneration, target)) {
                    return;
                }
                responseParserOverflows.incrementAndGet();
                throw new IllegalStateException(
                        "MAKCU response stream exceeded the framing boundary");
            }
        });
    }

    private boolean startResponseReader(long connectionGeneration) {
        RawUsbTransport target = activeTransport;
        if (target == null || activeConnectionGeneration != connectionGeneration
                || !isVerifiedSerialTransportReady()) {
            protocolIdentityVerified = false;
            activeConnectionGeneration = 0L;
            lastStatus = "MAKCU response reader cannot bind the verified connection";
            notifyReconnectFailure();
            return false;
        }
        long readerLease = responseReaderLeaseGeneration.incrementAndGet();
        MakcuResponseStreamParser parser = createResponseParser(
                readerLease, connectionGeneration, target);
        responseReaderRunning.set(true);
        try {
            reader.execute(() -> runResponseReader(
                    readerLease, connectionGeneration, target, parser));
        } catch (RejectedExecutionException exception) {
            if (responseReaderLeaseGeneration.get() == readerLease) {
                responseReaderRunning.set(false);
            }
            if (activeConnectionGeneration == connectionGeneration
                    && activeTransport == target) {
                protocolIdentityVerified = false;
                activeConnectionGeneration = 0L;
            }
            lastStatus = "MAKCU response reader unavailable";
            notifyReconnectFailure();
            return false;
        }
        return responseReaderRunning.get()
                && activeConnectionGeneration == connectionGeneration
                && activeTransport == target;
    }

    private void runResponseReader(
            long readerLease,
            long connectionGeneration,
            RawUsbTransport target,
            MakcuResponseStreamParser parser) {
        byte[] buffer = new byte[256];
        Throwable readerFailure = null;
        try {
            while (isResponseReaderLeaseCurrent(
                    readerLease, connectionGeneration, target)) {
                int read;
                try {
                    read = target.read(buffer, RESPONSE_READER_TIMEOUT_MILLIS);
                } catch (RuntimeException exception) {
                    readerFailure = exception;
                    break;
                }
                if (read > 0) {
                    if (!isResponseReaderLeaseCurrent(
                            readerLease, connectionGeneration, target)) {
                        break;
                    }
                    parser.accept(buffer, read);
                }
                // bulkTransfer already waits RESPONSE_READER_TIMEOUT_MILLIS.
                // Restart it immediately so an acknowledgement cannot land in
                // an extra fixed polling gap between two blocking reads.
            }
        } catch (RuntimeException | LinkageError exception) {
            readerFailure = exception;
        } finally {
            if (responseReaderLeaseGeneration.get() == readerLease) {
                responseReaderRunning.set(false);
            }
            if (readerFailure != null) {
                Log.e(LOG_TAG, "MAKCU response reader failed generation="
                        + connectionGeneration, readerFailure);
            }
            synchronized (responseLock) {
                responseLock.notifyAll();
            }
            handleUnexpectedResponseReaderStop(
                    readerLease, connectionGeneration, target, readerFailure);
        }
    }

    private void handleUnexpectedResponseReaderStop(
            long readerLease,
            long connectionGeneration,
            RawUsbTransport target,
            Throwable readerFailure) {
        String failureType = readerFailure == null
                ? "unexpected_stop" : readerFailure.getClass().getSimpleName();
        boolean failedCurrentConnection = false;
        synchronized (serialIoLock) {
            if (responseReaderLeaseGeneration.get() == readerLease
                    && activeConnectionGeneration == connectionGeneration
                    && activeTransport == target) {
                protocolIdentityVerified = false;
                activeConnectionGeneration = 0L;
                recordDeliveryFailureLocked(
                        "response_reader_stopped type=" + failureType
                                + " reconnect_required=true");
                lastStatus = "MAKCU response reader stopped; reconnect required";
                failedCurrentConnection = true;
            }
        }
        if (!failedCurrentConnection) return;
        events.write("makcu_response_reader_failed",
                "generation=" + connectionGeneration
                        + " exception=" + reportToken(failureType)
                        + " protocol_identity_verified=false"
                        + " output_disabled=true reconnect_required=true");
        notifyReconnectFailure();
    }

    private boolean isResponseReaderLeaseCurrent(
            long readerLease,
            long connectionGeneration,
            RawUsbTransport target) {
        return responseReaderLeaseGeneration.get() == readerLease
                && activeConnectionGeneration == connectionGeneration
                && activeTransport == target;
    }

    private void beginExpectedResponse(
            String command, long connectionGeneration, long readerLease) {
        synchronized (responseLock) {
            expectedResponseCommand = command;
            expectedResponseConnectionGeneration = connectionGeneration;
            expectedResponseReaderLease = readerLease;
            expectedResponseAcknowledged = false;
        }
    }

    private void cancelExpectedResponse(
            String command, long connectionGeneration, long readerLease) {
        synchronized (responseLock) {
            if (isExpectedResponseLocked(
                    command, connectionGeneration, readerLease)) {
                clearExpectedResponseLocked();
                responseLock.notifyAll();
            }
        }
    }

    private boolean isExpectedResponseLocked(
            String command, long connectionGeneration, long readerLease) {
        return command.equals(expectedResponseCommand)
                && expectedResponseConnectionGeneration == connectionGeneration
                && expectedResponseReaderLease == readerLease;
    }

    private void clearExpectedResponseLocked() {
        expectedResponseCommand = null;
        expectedResponseConnectionGeneration = 0L;
        expectedResponseReaderLease = 0L;
        expectedResponseAcknowledged = false;
    }

    private void scheduleButtonStreamConfiguration() {
        if (!buttonStreamCommandPending.compareAndSet(false, true)) return;
        try {
            writer.execute(() -> {
                boolean desired = deliveryGate.requiredPhysicalButtonMask() != 0;
                try {
                    configureButtonStream(desired);
                } catch (RuntimeException | LinkageError failure) {
                    handleUnexpectedButtonStreamConfigurationFailure(failure);
                } finally {
                    buttonStreamCommandPending.set(false);
                    if ((deliveryGate.requiredPhysicalButtonMask() != 0)
                            != buttonStreamEnabled.get()
                            && isReady()) {
                        scheduleButtonStreamConfiguration();
                    }
                }
            });
        } catch (RejectedExecutionException exception) {
            buttonStreamCommandPending.set(false);
            buttonStreamReady.set(false);
            notifyButtonStateChanged(deliveryGate.currentPhysicalButtonMask());
        }
    }

    private void handleUnexpectedButtonStreamConfigurationFailure(Throwable failure) {
        Log.e(LOG_TAG, "Unexpected MAKCU button-stream configuration failure", failure);
        synchronized (serialIoLock) {
            buttonStreamReady.set(false);
            invalidateProtocolAfterDeliveryFailureLocked(
                    "button_stream_exception type="
                            + failure.getClass().getSimpleName());
        }
        events.write("makcu_button_stream_exception",
                "output_disabled=true reconnect_required=true stack={"
                        + MobileThrowableDiagnostics.format(failure) + "}");
        notifyButtonStateChanged(deliveryGate.currentPhysicalButtonMask());
    }

    private void configureButtonStream(boolean desired) {
        if (!isReady()) {
            buttonStreamReady.set(false);
            notifyButtonStateChanged(deliveryGate.currentPhysicalButtonMask());
            return;
        }
        if (buttonStreamEnabled.get() == desired) {
            buttonStreamReady.set(desired);
            notifyButtonStateChanged(deliveryGate.currentPhysicalButtonMask());
            return;
        }
        synchronized (serialIoLock) {
            RawUsbTransport target = activeTransport;
            if (target == null || !isReady()) {
                buttonStreamReady.set(false);
                notifyButtonStateChanged(deliveryGate.currentPhysicalButtonMask());
                return;
            }
            String commandText = "km.buttons(" + (desired ? 1 : 0) + ")\r\n";
            byte[] command = commandText.getBytes(StandardCharsets.US_ASCII);
            long started = SystemClock.elapsedRealtimeNanos();
            long commandConnectionGeneration = activeConnectionGeneration;
            long commandReaderLease = responseReaderLeaseGeneration.get();
            beginExpectedResponse(
                    commandText, commandConnectionGeneration, commandReaderLease);
            int wrote = target.write(command, 25);
            if (wrote != command.length) {
                cancelExpectedResponse(
                        commandText,
                        commandConnectionGeneration,
                        commandReaderLease);
                buttonStreamReady.set(false);
                invalidateProtocolAfterDeliveryFailureLocked(
                        "button_stream_partial_write bytes=" + wrote
                                + " expected=" + command.length);
                notifyButtonStateChanged(deliveryGate.currentPhysicalButtonMask());
                return;
            }
            long acknowledgementMicros =
                    awaitExecutedAcknowledgement(
                            target,
                            commandText,
                            started,
                            commandConnectionGeneration,
                            commandReaderLease);
            if (acknowledgementMicros < 0L) {
                buttonStreamReady.set(false);
                invalidateProtocolAfterDeliveryFailureLocked(
                        "button_stream_ack_timeout");
                events.write("makcu_button_stream_failed",
                        "required=" + desired
                                + " output_disabled=true reconnect_required=true");
                notifyButtonStateChanged(deliveryGate.currentPhysicalButtonMask());
                return;
            }
            deviceCommandAcknowledgements.incrementAndGet();
            lastDeviceAcknowledgementMicros.set(acknowledgementMicros);
            buttonStreamEnabled.set(desired);
            buttonStreamReady.set(desired);
            if (!desired) {
                synchronized (buttonStateLock) {
                    rejectPhysicalTriggerMove(
                            deliveryGate.updatePhysicalButtonMask(0));
                }
            }
            lastStatus = serialReadyStatus;
            events.write("makcu_button_stream_configured",
                    "enabled=" + desired + " mode=read_only_physical_snapshots");
            notifyButtonStateChanged(deliveryGate.currentPhysicalButtonMask());
        }
    }

    private void notifyButtonStateChanged(int completeMask) {
        mainHandler.post(() -> {
            MakcuButtonInput.Listener listener = buttonStateListener.get();
            if (listener != null) listener.onButtonMaskChanged(completeMask);
        });
    }

    String report() {
        MakcuDeliveryState delivery = deliveryCircuit.snapshot();
        MakcuConnectionAttemptTracker.Snapshot attempt = connectionAttempts.snapshot();
        return lastStatus + " offered_moves=" + offeredMoves.get()
                + " serial_open=" + (activeTransport != null ? 1 : 0)
                + " adapter_identity_verified=" + (adapterIdentityVerified ? 1 : 0)
                + " protocol_identity_verified=" + (protocolIdentityVerified ? 1 : 0)
                + " selected_baud=" + selectedBaudRate
                + " connection_attempt_generation=" + attempt.generation
                + " connection_attempt_in_progress=" + (attempt.deviceName != null ? 1 : 0)
                + " usb_permission_pending=" + (attempt.permissionPending ? 1 : 0)
                + " response_reader_running=" + (responseReaderRunning.get() ? 1 : 0)
                + " response_reader_generation=" + responseReaderLeaseGeneration.get()
                + " usb_write_completions=" + delivery.usbWriteCompletionCount
                + " last_usb_write_call_us=" + delivery.lastUsbWriteCallMicros
                + " legacy_delivery_acknowledgements=" + delivery.usbWriteCompletionCount
                + " legacy_last_write_us=" + delivery.lastUsbWriteCallMicros
                + " legacy_ack_semantics=usb_write_completion_not_device_or_physical_ack"
                + " device_command_acknowledgements=" + deviceCommandAcknowledgements.get()
                + " device_move_acknowledgements=" + moveCommandAcknowledgements.get()
                + " last_device_ack_us=" + lastDeviceAcknowledgementMicros.get()
                + " device_acknowledgement_failures=" + deviceAcknowledgementFailures.get()
                + " unexpected_device_responses=" + unexpectedDeviceResponses.get()
                + " response_parser_overflows=" + responseParserOverflows.get()
                + " physical_button_snapshots=" + physicalButtonSnapshots.get()
                + " last_physical_button_mask="
                + deliveryGate.currentPhysicalButtonMask()
                + " physical_button_stream_required="
                + (deliveryGate.requiredPhysicalButtonMask() != 0 ? 1 : 0)
                + " required_physical_button_mask="
                + deliveryGate.requiredPhysicalButtonMask()
                + " physical_button_stream_enabled="
                + (buttonStreamEnabled.get() ? 1 : 0)
                + " physical_button_stream_ready="
                + (isButtonStreamReady() ? 1 : 0)
                + " device_ack_semantics=firmware_echo_and_prompt_not_physical_execution"
                + " physical_execution_verified=0"
                + " dropped_disconnected=" + droppedDisconnected.get()
                + " dropped_output_disabled=" + droppedOutputDisabled.get()
                + " delivery_failures=" + delivery.failureCount
                + " consecutive_delivery_failures=" + delivery.consecutiveFailures
                + " delivery_circuit_open=" + (delivery.circuitOpen ? 1 : 0)
                + " delivery_circuit_trips=" + delivery.circuitTripCount
                + " last_delivery_failure=" + reportToken(delivery.lastFailure);
    }

    @Override
    public boolean isReady() {
        return isVerifiedSerialTransportReady() && responseReaderRunning.get();
    }

    private boolean isVerifiedSerialTransportReady() {
        return activeTransport != null && adapterIdentityVerified && protocolIdentityVerified
                && selectedBaudRate == MakcuProtocolNegotiator.OPERATING_BAUD_RATE
                && !deliveryCircuit.snapshot().circuitOpen;
    }

    @Override
    public boolean setOutputDeliveryAllowed(boolean allowed) {
        synchronized (serialIoLock) {
            if (allowed && (!isReady() || deliveryCircuit.snapshot().circuitOpen)) return false;
            if (!deliveryGate.setUserAllowed(allowed)) return false;
            if (!allowed) clearPendingMove();
            return true;
        }
    }

    @Override
    public MakcuDeliveryState deliveryState() {
        return deliveryCircuit.snapshot();
    }

    void close() {
        connectionAttempts.cancel();
        failClosedDelivery();
        closeInFlightPort();
        closeActiveTransport();
    }

    void destroy() {
        if (!destroyed.compareAndSet(false, true)) return;
        close();
        reconnectListener = null;
        buttonStateListener.set(null);
        try {
            context.unregisterReceiver(usbReceiver);
        } catch (IllegalArgumentException alreadyUnregistered) {
            // Idempotent service teardown: receiver may already be detached by
            // Android after process/service lifecycle races.
            events.write("makcu_usb_receiver_unregister_skipped",
                    "reason=already_unregistered");
        }
        writer.shutdownNow();
        reader.shutdownNow();
        if (instance == this) instance = null;
    }

    private void cancelAttemptsAndClose() {
        connectionAttempts.cancel();
        failClosedDelivery();
        closeInFlightPort();
        closeActiveTransport();
    }

    private void closeInFlightPort() {
        AndroidSerialPort pendingPort = inFlightPort.getAndSet(null);
        if (pendingPort != null) pendingPort.close();
    }

    private void closeActiveTransport() {
        RawUsbTransport active;
        long rejectedPhysicalTriggerTicket;
        responseReaderRunning.set(false);
        synchronized (responseLock) {
            responseReaderLeaseGeneration.incrementAndGet();
            clearExpectedResponseLocked();
            responseLock.notifyAll();
        }
        synchronized (serialIoLock) {
            buttonStreamReady.set(false);
            buttonStreamEnabled.set(false);
            active = activeTransport;
            activeTransport = null;
            activeDeviceName = null;
            activeConnectionGeneration = 0L;
            adapterIdentityVerified = false;
            protocolIdentityVerified = false;
            selectedBaudRate = 0;
        }
        synchronized (buttonStateLock) {
            rejectedPhysicalTriggerTicket =
                    deliveryGate.updatePhysicalButtonMask(0);
        }
        rejectPhysicalTriggerMove(rejectedPhysicalTriggerTicket);
        try {
            if (active != null) active.close();
        } finally {
            QnnHtpBridge.failClosedNativeMakcuOutput();
            notifyButtonStateChanged(0);
        }
    }

    private static long packMove(int x, int y) {
        return (((long) (x & 0xffff)) << 16) | (y & 0xffffL);
    }

    private static int unpackX(long packed) { return (short) (packed >>> 16); }
    private static int unpackY(long packed) { return (short) packed; }

    private void recordDeliveryFailureLocked(String reason) {
        boolean circuitWasOpen = deliveryCircuit.snapshot().circuitOpen;
        deliveryCircuit.recordFailure(reason);
        MakcuDeliveryState delivery = deliveryCircuit.snapshot();
        deliveryGate.failClosed();
        clearPendingMove();
        QnnHtpBridge.failClosedNativeMakcuOutput();
        events.write("makcu_usb_write_failed", "reason=" + reportToken(reason)
                + " consecutive_failures=" + delivery.consecutiveFailures
                + " circuit_open=" + delivery.circuitOpen
                + " output_disabled=true authorization_revoked=true");
        if (delivery.circuitOpen) {
            lastStatus = "MAKCU delivery circuit open; reconnect required: "
                    + delivery.lastFailure;
        } else {
            lastStatus = "MAKCU USB write failed; automatic output gate closed: "
                    + delivery.lastFailure;
        }
        if (!circuitWasOpen && delivery.circuitOpen) activeConnectionGeneration = 0L;
    }

    private void invalidateProtocolAfterDeliveryFailureLocked(String reason) {
        protocolIdentityVerified = false;
        activeConnectionGeneration = 0L;
        recordDeliveryFailureLocked(reason + " reconnect_required=true");
        notifyReconnectFailure();
    }

    private void notifyReconnectSuccess(long expectedGeneration) {
        mainHandler.post(() -> {
            ReconnectListener listener = reconnectListener;
            if (listener != null && activeConnectionGeneration == expectedGeneration && isReady()) {
                listener.onReconnectResult(true);
            }
        });
    }

    private void notifyReconnectFailure() {
        mainHandler.post(() -> {
            ReconnectListener listener = reconnectListener;
            if (listener != null) listener.onReconnectResult(false);
        });
    }

    /** Called by native recovery before its suspend operation returns. */
    private static boolean suspendNativeDeliveryForRecovery(long generation) {
        MakcuSerialController controller = instance;
        return controller != null && controller.suspendDeliveryForRecovery(generation);
    }

    /** Called only after native validates the matching recovery generation. */
    private static boolean resumeNativeDeliveryAfterRecovery(long generation) {
        MakcuSerialController controller = instance;
        return controller != null && controller.resumeDeliveryAfterRecovery(generation);
    }

    /** Native fail-close uses this boundary to synchronously drain old moves. */
    private static boolean failClosedNativeDelivery() {
        MakcuSerialController controller = instance;
        if (controller == null) return false;
        controller.failClosedDelivery();
        return true;
    }

    @Override
    public boolean suspendMoveDeliveryForNativeRecovery(long generation) {
        return suspendDeliveryForRecovery(generation);
    }

    @Override
    public boolean resumeMoveDeliveryAfterNativeRecovery(long generation) {
        return resumeDeliveryAfterRecovery(generation);
    }

    @Override
    public boolean failClosedNativeMoveDelivery() {
        failClosedDelivery();
        return true;
    }

    private boolean suspendDeliveryForRecovery(long generation) {
        deliveryGate.suspendForRecovery(generation);
        return true;
    }

    private boolean resumeDeliveryAfterRecovery(long generation) {
        synchronized (serialIoLock) {
            if (!isReady() || deliveryCircuit.snapshot().circuitOpen) {
                deliveryGate.failClosed();
                clearPendingMove();
                return false;
            }
            clearPendingMove();
            return deliveryGate.resumeAfterRecovery(generation);
        }
    }

    private void failClosedDelivery() {
        deliveryGate.failClosed();
        clearPendingMove();
    }

    private void rejectPhysicalTriggerMove(long rejectedTicket) {
        if (rejectedTicket > 0L) {
            droppedOutputDisabled.incrementAndGet();
            QnnHtpBridge.reportNativeMakcuMoveResult(
                    rejectedTicket, false, 0L);
        }
    }

    private void reportUndeliveredMoveUnlessRecoveryCancelled(long ticket) {
        // Decoder recovery deliberately cancels a move that has not entered
        // serial I/O. Native clears that ticket only after this transport is
        // idle; reporting it as a device failure would destroy resume
        // eligibility and turn every unlucky recovery race into a hard lock.
        if (ticket > 0L && !deliveryGate.isRecoverySuspended()) {
            QnnHtpBridge.reportNativeMakcuMoveResult(ticket, false, 0L);
        }
    }

    private void clearPendingMove() {
        pendingMoveSlot.clear();
    }

    private static String reportToken(String value) {
        return value == null || value.isEmpty() ? "none" : value.replace(' ', '_');
    }

    private static final class RawUsbTransport {
        private final Object bulkInTransferLock = new Object();
        private final Object bulkOutTransferLock = new Object();
        private UsbDeviceConnection connection;
        private UsbInterface dataInterface;
        private UsbEndpoint bulkIn;
        private UsbEndpoint bulkOut;
        private boolean dataInterfaceClaimed;

        private RawUsbTransport(UsbDeviceConnection connection, UsbInterface dataInterface,
                                UsbEndpoint bulkIn, UsbEndpoint bulkOut) {
            this.connection = connection;
            this.dataInterface = dataInterface;
            this.bulkIn = bulkIn;
            this.bulkOut = bulkOut;
        }

        private synchronized boolean claimDataInterface() {
            if (connection == null || dataInterface == null || dataInterfaceClaimed) return false;
            dataInterfaceClaimed = connection.claimInterface(dataInterface, true);
            return dataInterfaceClaimed;
        }

        private synchronized int controlTransfer(int requestType, int request, int value,
                                                 int interfaceId, byte[] buffer,
                                                 int length, int timeoutMillis) {
            if (!isOpen() || timeoutMillis <= 0) return -1;
            return connection.controlTransfer(requestType, request, value, interfaceId,
                    buffer, length, timeoutMillis);
        }

        private int write(byte[] bytes, int timeoutMillis) {
            if (bytes == null || timeoutMillis <= 0) return -1;
            synchronized (bulkOutTransferLock) {
                UsbDeviceConnection activeConnection;
                UsbEndpoint activeEndpoint;
                synchronized (this) {
                    if (!isOpen()) return -1;
                    activeConnection = connection;
                    activeEndpoint = bulkOut;
                }
                return activeConnection.bulkTransfer(
                        activeEndpoint, bytes, bytes.length, timeoutMillis);
            }
        }

        private int read(byte[] destination, int timeoutMillis) {
            if (destination == null || timeoutMillis <= 0) return -1;
            synchronized (bulkInTransferLock) {
                UsbDeviceConnection activeConnection;
                UsbEndpoint activeEndpoint;
                synchronized (this) {
                    if (!isOpen()) return -1;
                    activeConnection = connection;
                    activeEndpoint = bulkIn;
                }
                return activeConnection.bulkTransfer(
                        activeEndpoint, destination, destination.length,
                        timeoutMillis);
            }
        }

        private synchronized boolean isOpen() {
            return connection != null && dataInterface != null
                    && bulkIn != null && bulkOut != null && dataInterfaceClaimed;
        }

        private void close() {
            UsbDeviceConnection connectionToClose;
            UsbInterface interfaceToRelease;
            boolean releaseInterface;
            // IN and OUT transfers must remain full-duplex during operation.
            // Taking both endpoint locks only for teardown prevents closing a
            // native connection while either bounded bulkTransfer is active.
            synchronized (bulkInTransferLock) {
                synchronized (bulkOutTransferLock) {
                    synchronized (this) {
                        connectionToClose = connection;
                        interfaceToRelease = dataInterface;
                        releaseInterface = dataInterfaceClaimed;
                        connection = null;
                        dataInterface = null;
                        bulkIn = null;
                        bulkOut = null;
                        dataInterfaceClaimed = false;
                    }
                }
            }
            if (connectionToClose == null) return;
            try {
                if (releaseInterface && interfaceToRelease != null) {
                    connectionToClose.releaseInterface(interfaceToRelease);
                }
            } catch (Throwable releaseFailure) {
                safeLogCloseFailure("Cannot release MAKCU USB data interface", releaseFailure);
            } finally {
                try {
                    connectionToClose.close();
                } catch (Throwable closeFailure) {
                    safeLogCloseFailure("Cannot close MAKCU USB device connection", closeFailure);
                }
            }
        }

        private static void safeLogCloseFailure(String message, Throwable failure) {
            try {
                Log.e(LOG_TAG, message, failure);
            } catch (Throwable ignored) {
                // Closing this fail-closed transport must never throw.
            }
        }

        private static void closeUnownedConnection(UsbDeviceConnection unownedConnection) {
            if (unownedConnection == null) return;
            try {
                unownedConnection.close();
            } catch (Throwable closeFailure) {
                safeLogCloseFailure("Cannot close unowned MAKCU USB connection", closeFailure);
            }
        }
    }

    private final class AndroidSerialPort implements MakcuProtocolNegotiator.Port {
        private final MakcuConnectionAttemptTracker.Attempt attempt;
        private RawUsbTransport candidate;
        private String lastFailure = "none";

        private AndroidSerialPort(MakcuConnectionAttemptTracker.Attempt attempt) {
            this.attempt = attempt;
        }

        @Override
        public synchronized boolean open(int baudRate) {
            close();
            if (!isAttemptCurrent()) {
                lastFailure = "connection_attempt_cancelled";
                return false;
            }
            UsbDevice device = findExpectedAdapter(attempt.deviceName);
            if (device == null || !usbManager.hasPermission(device)) {
                lastFailure = "device_or_permission_unavailable";
                return false;
            }
            MakcuUsbInterfaceSelector.Result interfaceSelection =
                    selectUniqueBulkInterface(device);
            if (!interfaceSelection.succeeded) {
                lastFailure = interfaceSelection.failureToken;
                return false;
            }
            MakcuCdcLineCoding.InterfaceResult communicationInterface =
                    selectUniqueCommunicationInterface(device);
            if (!communicationInterface.succeeded) {
                lastFailure = communicationInterface.failureToken;
                return false;
            }
            UsbDeviceConnection openedConnection = null;
            try {
                openedConnection = usbManager.openDevice(device);
                if (openedConnection == null) {
                    lastFailure = "usb_open_failed";
                    return false;
                }
                UsbInterface dataInterface =
                        device.getInterface(interfaceSelection.interfaceIndex);
                candidate = new RawUsbTransport(
                        openedConnection,
                        dataInterface,
                        findBulkEndpoint(dataInterface, UsbConstants.USB_DIR_IN),
                        findBulkEndpoint(dataInterface, UsbConstants.USB_DIR_OUT));
                // The fail-safe transport owns the raw connection from here.
                openedConnection = null;
                if (!candidate.claimDataInterface()) {
                    lastFailure = "usb_data_interface_claim_failed_interface_"
                            + interfaceSelection.interfaceIndex;
                    close();
                    return false;
                }
                UsbInterface controlInterface =
                        device.getInterface(communicationInterface.interfaceIndex);
                if (!setAndVerifyLineCoding(baudRate, controlInterface.getId())) {
                    close();
                    return false;
                }
                lastFailure = "none";
                return true;
            } catch (RuntimeException exception) {
                lastFailure = "serial_open_exception_" + exception.getClass().getSimpleName();
                close();
                return false;
            } finally {
                RawUsbTransport.closeUnownedConnection(openedConnection);
            }
        }

        @Override
        public synchronized int write(byte[] bytes, int timeoutMillis) {
            if (!isAttemptCurrent()) return -1;
            try {
                return candidate == null ? -1 : candidate.write(bytes, timeoutMillis);
            } catch (RuntimeException exception) {
                lastFailure = "serial_write_exception_" + exception.getClass().getSimpleName();
                return -1;
            }
        }

        @Override
        public synchronized int read(byte[] destination, int timeoutMillis) {
            if (!isAttemptCurrent()) return -1;
            try {
                return candidate == null ? -1 : candidate.read(destination, timeoutMillis);
            } catch (RuntimeException exception) {
                lastFailure = "serial_read_exception_" + exception.getClass().getSimpleName();
                return -1;
            }
        }

        @Override
        public synchronized void close() {
            RawUsbTransport transportToClose = candidate;
            candidate = null;
            if (transportToClose != null) transportToClose.close();
        }

        private synchronized boolean isOpen() {
            return candidate != null && candidate.isOpen();
        }

        private synchronized RawUsbTransport releaseTransport() {
            RawUsbTransport released = candidate;
            candidate = null;
            return released;
        }

        private String failureToken() {
            return reportToken(lastFailure);
        }

        private MakcuUsbInterfaceSelector.Result selectUniqueBulkInterface(UsbDevice device) {
            int interfaceCount = device.getInterfaceCount();
            int[] interfaceClasses = new int[interfaceCount];
            int[] bulkInCounts = new int[interfaceCount];
            int[] bulkOutCounts = new int[interfaceCount];
            for (int interfaceIndex = 0; interfaceIndex < interfaceCount; interfaceIndex++) {
                UsbInterface usbInterface = device.getInterface(interfaceIndex);
                interfaceClasses[interfaceIndex] = usbInterface.getInterfaceClass();
                for (int endpointIndex = 0;
                     endpointIndex < usbInterface.getEndpointCount();
                     endpointIndex++) {
                    UsbEndpoint endpoint = usbInterface.getEndpoint(endpointIndex);
                    if (endpoint.getType() != UsbConstants.USB_ENDPOINT_XFER_BULK) continue;
                    if (endpoint.getDirection() == UsbConstants.USB_DIR_IN) {
                        bulkInCounts[interfaceIndex]++;
                    } else if (endpoint.getDirection() == UsbConstants.USB_DIR_OUT) {
                        bulkOutCounts[interfaceIndex]++;
                    }
                }
            }
            return MakcuUsbInterfaceSelector.selectUniqueDataInterface(
                    interfaceClasses, bulkInCounts, bulkOutCounts);
        }

        private MakcuCdcLineCoding.InterfaceResult selectUniqueCommunicationInterface(
                UsbDevice device) {
            int interfaceCount = device.getInterfaceCount();
            int[] interfaceClasses = new int[interfaceCount];
            int[] interfaceSubclasses = new int[interfaceCount];
            for (int interfaceIndex = 0; interfaceIndex < interfaceCount; interfaceIndex++) {
                UsbInterface usbInterface = device.getInterface(interfaceIndex);
                interfaceClasses[interfaceIndex] = usbInterface.getInterfaceClass();
                interfaceSubclasses[interfaceIndex] = usbInterface.getInterfaceSubclass();
            }
            return MakcuCdcLineCoding.selectUniqueAcmCommunicationInterface(
                    interfaceClasses, interfaceSubclasses);
        }

        private UsbEndpoint findBulkEndpoint(UsbInterface usbInterface, int direction) {
            for (int endpointIndex = 0;
                 endpointIndex < usbInterface.getEndpointCount();
                 endpointIndex++) {
                UsbEndpoint endpoint = usbInterface.getEndpoint(endpointIndex);
                if (endpoint.getType() == UsbConstants.USB_ENDPOINT_XFER_BULK
                        && endpoint.getDirection() == direction) return endpoint;
            }
            return null;
        }

        private boolean setAndVerifyLineCoding(int baudRate, int communicationInterfaceId) {
            byte[] expected = MakcuCdcLineCoding.encode8N1(baudRate);
            int written = candidate.controlTransfer(
                    MakcuCdcLineCoding.SET_LINE_CODING_REQUEST_TYPE,
                    MakcuCdcLineCoding.SET_LINE_CODING_REQUEST,
                    0,
                    communicationInterfaceId,
                    expected,
                    expected.length,
                    CDC_CONTROL_TRANSFER_TIMEOUT_MILLIS);
            if (written != MakcuCdcLineCoding.LINE_CODING_BYTES) {
                lastFailure = "cdc_set_line_coding_transfer_length_" + written;
                return false;
            }
            byte[] observed = new byte[MakcuCdcLineCoding.LINE_CODING_BYTES];
            int read = candidate.controlTransfer(
                    MakcuCdcLineCoding.GET_LINE_CODING_REQUEST_TYPE,
                    MakcuCdcLineCoding.GET_LINE_CODING_REQUEST,
                    0,
                    communicationInterfaceId,
                    observed,
                    observed.length,
                    CDC_CONTROL_TRANSFER_TIMEOUT_MILLIS);
            if (read != MakcuCdcLineCoding.LINE_CODING_BYTES) {
                lastFailure = "cdc_get_line_coding_transfer_length_" + read;
                return false;
            }
            if (!MakcuCdcLineCoding.matches(expected, observed, read)) {
                lastFailure = "cdc_get_line_coding_mismatch";
                return false;
            }
            int controlLineState = candidate.controlTransfer(
                    MakcuCdcLineCoding.SET_CONTROL_LINE_STATE_REQUEST_TYPE,
                    MakcuCdcLineCoding.SET_CONTROL_LINE_STATE_REQUEST,
                    MakcuCdcLineCoding.CONTROL_LINE_STATE_DTR_RTS,
                    communicationInterfaceId,
                    null,
                    0,
                    CDC_CONTROL_TRANSFER_TIMEOUT_MILLIS);
            if (controlLineState != 0) {
                lastFailure = "cdc_set_control_line_state_result_" + controlLineState;
                return false;
            }
            return true;
        }

        private boolean isAttemptCurrent() {
            return connectionAttempts.isCurrent(attempt.generation, attempt.deviceName);
        }
    }
}
