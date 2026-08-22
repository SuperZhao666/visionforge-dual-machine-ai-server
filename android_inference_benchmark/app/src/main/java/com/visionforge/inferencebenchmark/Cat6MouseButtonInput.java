package com.visionforge.inferencebenchmark;

import android.os.SystemClock;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

/** Production physical-button source received only on the selected transport network. */
final class Cat6MouseButtonInput implements ControlButtonInput, AutoCloseable {
    private static final int RECEIVE_TIMEOUT_MILLIS = 50;
    private static final long STREAM_LEASE_NANOS = 200_000_000L;
    private static final int THREAD_JOIN_TIMEOUT_MILLIS = 750;

    private static final class WorkerFailureClaim {
        final Cat6MouseButtonWorkerRecoveryPolicy.Failure retry;
        final Cat6MouseButtonLeaseState.Expiration expiration;

        WorkerFailureClaim(
                Cat6MouseButtonWorkerRecoveryPolicy.Failure retry,
                Cat6MouseButtonLeaseState.Expiration expiration) {
            this.retry = retry;
            this.expiration = expiration;
        }
    }

    private final MobileRuntimeEventSink events;
    private final Cat6MouseButtonProtocol protocol =
            new Cat6MouseButtonProtocol();
    private final Cat6MouseButtonEndpointPolicy endpointPolicy =
            new Cat6MouseButtonEndpointPolicy();
    private final Cat6MouseButtonLeaseState buttonState =
            new Cat6MouseButtonLeaseState();
    private final Cat6MouseButtonNotificationDispatcher buttonNotifications;
    private final Cat6MouseButtonWorkerRecoveryPolicy workerRecovery =
            new Cat6MouseButtonWorkerRecoveryPolicy();
    private final AtomicLong generation = new AtomicLong();
    private volatile Listener listener;
    private volatile DatagramSocket activeSocket;
    private volatile Thread worker;
    private volatile long networkHandle;
    private volatile String endpointIdentity = "";
    private volatile int requiredTriggerMask;
    private volatile long acceptedPackets;
    private volatile long rejectedPackets;

    Cat6MouseButtonInput(MobileRuntimeEventSink events) {
        this.events = events;
        buttonNotifications = new Cat6MouseButtonNotificationDispatcher(
                buttonState::matchesNotification,
                this::notifyListener);
    }

    synchronized void updateEndpoint(MobileTransportEndpoint endpoint) {
        boolean endpointReady = endpoint != null
                && endpoint.isReadyForDataPlane()
                && endpoint.network != null;
        long requestedHandle = endpoint == null ? 0L : endpoint.networkHandle;
        String requestedIdentity = !endpointReady
                ? "" : endpoint.localIpv4 + "|" + endpoint.hostIpv4;
        Thread currentWorker = worker;
        boolean sameEndpoint = endpointReady
                && requestedHandle == networkHandle
                && requestedIdentity.equals(endpointIdentity);
        Cat6MouseButtonLeaseState.Snapshot buttonSnapshot =
                buttonState.snapshot();
        if (sameEndpoint
                && currentWorker != null && currentWorker.isAlive()) {
            return;
        }
        long nowNanos = SystemClock.elapsedRealtimeNanos();
        if (sameEndpoint && !workerRecovery.canAttempt(nowNanos)) return;
        if (!endpointReady) {
            boolean inputAlreadyStopped = currentWorker == null
                    && activeSocket == null
                    && networkHandle == 0L
                    && endpointIdentity.isEmpty()
                    && !buttonSnapshot.streamReady
                    && buttonSnapshot.buttonMask == 0;
            if (!endpointPolicy.shouldHandleUnavailable(
                    inputAlreadyStopped)) return;
            clearConfirmedSession("endpoint_unavailable");
            stopWorker("endpoint_changed");
            workerRecovery.reset();
            writeEvent("cat6_mouse_button_input_stopped",
                    "reason=endpoint_unavailable fail_closed=true");
            return;
        }
        if (!sameEndpoint) {
            workerRecovery.reset();
            clearConfirmedSession("endpoint_changed");
        }
        stopWorker("endpoint_changed");
        endpointPolicy.recordEndpointStarting();
        long workerGeneration = generation.incrementAndGet();
        networkHandle = endpoint.networkHandle;
        endpointIdentity = requestedIdentity;
        Thread nextWorker = new Thread(
                () -> receiveLoop(endpoint, workerGeneration),
                "visionforge-cat6-mouse-buttons");
        nextWorker.setDaemon(false);
        worker = nextWorker;
        nextWorker.start();
        writeEvent("cat6_mouse_button_input_starting", endpoint.detail()
                + " previous_worker_failures="
                + workerRecovery.consecutiveFailures());
    }

    /**
     * Snapshots only the mouse traffic material from a fully confirmed CAT6
     * peer session. The session owner must call {@link #clearConfirmedSession}
     * when that peer session closes.
     */
    synchronized boolean installConfirmedSession(
            ConfirmedAndroidPeerSession session) {
        if (session == null) return rejectSessionInstall("session_missing");
        byte[] hostIpv4 = null;
        byte[] androidIpv4 = null;
        byte[] trafficMaterial = null;
        try {
            if (session.transportKind()
                    != AuthenticatedPeerHandshakeV1.TransportKind.CAT6) {
                return rejectSessionInstall("transport_not_cat6");
            }
            hostIpv4 = session.hostIpv4();
            androidIpv4 = session.androidIpv4();
            String sessionEndpointIdentity =
                    formatIpv4(androidIpv4) + "|" + formatIpv4(hostIpv4);
            if (networkHandle == 0L
                    || !sessionEndpointIdentity.equals(endpointIdentity)) {
                return rejectSessionInstall("endpoint_binding_mismatch");
            }
            long connectionId = session.connectionId();
            long sessionGeneration = session.sessionGeneration();
            trafficMaterial = session.mouseHostToAndroidMaterial();
            if (!protocol.installConfirmedMaterial(
                    trafficMaterial, connectionId)) {
                return rejectSessionInstall("crypto_install_failed");
            }
            expireStream("authenticated_session_replaced");
            writeEvent("cat6_mouse_button_session_installed",
                    "connection_id=" + Long.toUnsignedString(connectionId)
                            + " session_generation="
                            + Long.toUnsignedString(sessionGeneration)
                            + " endpoint=" + endpointIdentity
                            + " fail_closed=false");
            return true;
        } catch (GeneralSecurityException | RuntimeException failure) {
            return rejectSessionInstall(
                    "session_read_failed_" + safeToken(
                            failure.getClass().getSimpleName()));
        } finally {
            if (hostIpv4 != null) Arrays.fill(hostIpv4, (byte) 0);
            if (androidIpv4 != null) Arrays.fill(androidIpv4, (byte) 0);
            if (trafficMaterial != null) Arrays.fill(trafficMaterial, (byte) 0);
        }
    }

    synchronized void clearConfirmedSession(String reason) {
        if (!protocol.clearConfirmedSession()) return;
        expireStream("authenticated_session_cleared");
        writeEvent("cat6_mouse_button_session_cleared",
                "reason=" + safeToken(reason) + " fail_closed=true");
    }

    @Override
    public void setButtonStateListener(Listener listener) {
        this.listener = listener;
    }

    @Override
    public void setRequiredTriggerMask(int requiredButtonMask) {
        if ((requiredButtonMask & ~Cat6MouseButtonProtocol.VALID_BUTTON_MASK) != 0) {
            throw new IllegalArgumentException("requiredButtonMask");
        }
        requiredTriggerMask = requiredButtonMask;
    }

    @Override
    public int currentButtonMask() {
        expireLeaseIfNeeded(SystemClock.elapsedRealtimeNanos());
        return buttonState.snapshot().buttonMask;
    }

    @Override
    public boolean isButtonStreamReady() {
        expireLeaseIfNeeded(SystemClock.elapsedRealtimeNanos());
        return buttonState.snapshot().streamReady;
    }

    String report() {
        Cat6MouseButtonLeaseState.Snapshot snapshot = buttonState.snapshot();
        long ageMillis = !snapshot.streamReady ? -1L
                : Math.max(0L,
                (SystemClock.elapsedRealtimeNanos()
                        - snapshot.lastPacketNanos) / 1_000_000L);
        return String.format(Locale.US,
                "network_handle=%d worker_alive=%s worker_failures=%d "
                        + "authenticated_session_ready=%s "
                        + "stream_ready=%s button_mask=%d required_mask=%d "
                        + "last_packet_age_ms=%d accepted_packets=%d rejected_packets=%d",
                networkHandle, worker != null && worker.isAlive(),
                workerRecovery.consecutiveFailures(),
                protocol.sessionReady(),
                snapshot.streamReady, snapshot.buttonMask,
                requiredTriggerMask,
                ageMillis, acceptedPackets, rejectedPackets);
    }

    @Override
    public synchronized void close() {
        clearConfirmedSession("closed");
        stopWorker("closed");
        workerRecovery.reset();
        listener = null;
    }

    private void receiveLoop(MobileTransportEndpoint endpoint, long workerGeneration) {
        DatagramSocket socket = null;
        Throwable terminalFailure = null;
        try {
            socket = new DatagramSocket(null);
            socket.setReuseAddress(false);
            endpoint.network.bindSocket(socket);
            socket.bind(new InetSocketAddress(
                    InetAddress.getByName(endpoint.localIpv4),
                    Cat6MouseButtonProtocol.PORT));
            socket.setSoTimeout(RECEIVE_TIMEOUT_MILLIS);
            if (generation.get() != workerGeneration) return;
            activeSocket = socket;
            writeEvent("cat6_mouse_button_input_bound", endpoint.detail()
                    + " port=" + Cat6MouseButtonProtocol.PORT);
            receivePackets(socket, endpoint.hostIpv4, workerGeneration);
        } catch (IOException | RuntimeException failure) {
            terminalFailure = failure;
        } finally {
            if (socket != null) socket.close();
            if (activeSocket == socket) activeSocket = null;
            WorkerFailureClaim failureClaim = claimWorkerFailureIfCurrent(
                    workerGeneration,
                    SystemClock.elapsedRealtimeNanos());
            if (failureClaim != null) {
                if (failureClaim.expiration.stateChanged) {
                    reportExpiredStream(
                            "receiver_stopped",
                            failureClaim.expiration.revision);
                }
                writeEvent("cat6_mouse_button_input_failed",
                        "network_handle=" + endpoint.networkHandle
                                + " failure=" + safeToken(
                                terminalFailure == null
                                        ? "unexpected_stop"
                                        : terminalFailure.getClass().getSimpleName())
                                + " consecutive_failures="
                                + failureClaim.retry.consecutiveFailures
                                + " retry_delay_ms="
                                + failureClaim.retry.retryDelayNanos
                                / 1_000_000L
                                + " fail_closed=true automatic_retry=true");
            }
        }
    }

    private WorkerFailureClaim claimWorkerFailureIfCurrent(
            long workerGeneration,
            long nowNanos) {
        if (generation.get() != workerGeneration) return null;
        synchronized (this) {
            if (generation.get() != workerGeneration) return null;
            if (worker == Thread.currentThread()) worker = null;
            Cat6MouseButtonWorkerRecoveryPolicy.Failure retry =
                    workerRecovery.recordFailure(nowNanos);
            Cat6MouseButtonLeaseState.Expiration expiration =
                    buttonState.clear();
            return new WorkerFailureClaim(retry, expiration);
        }
    }

    private void receivePackets(
            DatagramSocket socket,
            String expectedHost,
            long workerGeneration) throws IOException {
        byte[] bytes = new byte[Cat6MouseButtonProtocol.RECEIVE_BUFFER_BYTES];
        DatagramPacket datagram = new DatagramPacket(bytes, bytes.length);
        long activeSessionRevision = 0L;
        boolean sessionKnown = false;
        while (generation.get() == workerGeneration && !socket.isClosed()) {
            datagram.setLength(bytes.length);
            try {
                socket.receive(datagram);
            } catch (SocketTimeoutException timeout) {
                expireLeaseIfNeeded(SystemClock.elapsedRealtimeNanos());
                continue;
            }
            String sourceHost = datagram.getAddress() == null
                    ? "" : datagram.getAddress().getHostAddress();
            if (!expectedHost.equals(sourceHost)
                    || datagram.getPort() != Cat6MouseButtonProtocol.PORT) {
                rejectedPackets++;
                continue;
            }
            Cat6MouseButtonProtocol.Packet packet =
                    protocol.decode(bytes, datagram.getLength());
            if (packet == null) {
                rejectedPackets++;
                continue;
            }
            boolean newSession = !sessionKnown
                    || packet.sessionRevision != activeSessionRevision;
            activeSessionRevision = packet.sessionRevision;
            sessionKnown = true;
            acceptPacket(
                    packet.buttonMask,
                    packet.sessionRevision,
                    newSession,
                    workerGeneration);
        }
    }

    private synchronized void acceptPacket(
            int buttonMask,
            long packetSessionRevision,
            boolean newSession,
            long workerGeneration) {
        if (generation.get() != workerGeneration
                || !protocol.isCurrentSessionRevision(packetSessionRevision)) {
            rejectedPackets++;
            return;
        }
        Cat6MouseButtonLeaseState.PacketUpdate update =
                buttonState.acceptPacket(
                        buttonMask,
                        SystemClock.elapsedRealtimeNanos(),
                        newSession);
        acceptedPackets++;
        workerRecovery.recordHealthyPacket();
        if (update.readyEventRequired) {
            writeEvent("cat6_mouse_button_stream_ready",
                    "network_handle=" + networkHandle
                            + " new_session=" + newSession
                            + " button_mask=" + buttonMask);
        }
        if (update.listenerNotificationRequired) {
            buttonNotifications.enqueue(
                    update.revision, true, update.buttonMask);
        }
    }

    private void expireLeaseIfNeeded(long nowNanos) {
        Cat6MouseButtonLeaseState.Expiration expiration =
                buttonState.expireIfStale(nowNanos, STREAM_LEASE_NANOS);
        if (expiration.stateChanged) {
            reportExpiredStream(
                    "packet_lease_expired", expiration.revision);
        }
    }

    private void expireStream(String reason) {
        Cat6MouseButtonLeaseState.Expiration expiration = buttonState.clear();
        if (expiration.stateChanged) {
            reportExpiredStream(reason, expiration.revision);
        }
    }

    private void reportExpiredStream(String reason, long revision) {
        writeEvent("cat6_mouse_button_stream_stale",
                "reason=" + reason + " fail_closed=true");
        buttonNotifications.enqueue(revision, false, 0);
    }

    private synchronized void stopWorker(String reason) {
        generation.incrementAndGet();
        DatagramSocket socket = activeSocket;
        if (socket != null) socket.close();
        Thread previousWorker = worker;
        worker = null;
        networkHandle = 0L;
        endpointIdentity = "";
        if (previousWorker != null && previousWorker != Thread.currentThread()) {
            previousWorker.interrupt();
            try {
                previousWorker.join(THREAD_JOIN_TIMEOUT_MILLIS);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
        }
        expireStream(reason);
    }

    private void notifyListener(int buttonMask) {
        Listener currentListener = listener;
        if (currentListener == null) return;
        try {
            currentListener.onButtonMaskChanged(buttonMask);
        } catch (RuntimeException failure) {
            writeEvent("cat6_mouse_button_listener_failed",
                    "failure=" + safeToken(failure.getClass().getSimpleName())
                            + " fail_closed=true");
        }
    }

    private void writeEvent(String event, String detail) {
        if (events != null) events.write(event, detail);
    }

    private boolean rejectSessionInstall(String reason) {
        clearConfirmedSession("session_install_rejected_" + safeToken(reason));
        writeEvent("cat6_mouse_button_session_rejected",
                "reason=" + safeToken(reason) + " fail_closed=true");
        return false;
    }

    private static String formatIpv4(byte[] address) {
        if (address == null || address.length != 4) return "";
        return (address[0] & 0xff) + "."
                + (address[1] & 0xff) + "."
                + (address[2] & 0xff) + "."
                + (address[3] & 0xff);
    }

    private static String safeToken(String value) {
        if (value == null || value.isBlank()) return "unspecified";
        return value.replace(' ', '_').replace('\r', '_').replace('\n', '_');
    }
}
