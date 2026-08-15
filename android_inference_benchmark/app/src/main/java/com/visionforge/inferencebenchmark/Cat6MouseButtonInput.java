package com.visionforge.inferencebenchmark;

import android.os.SystemClock;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
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
            stopWorker("endpoint_changed");
            workerRecovery.reset();
            writeEvent("cat6_mouse_button_input_stopped",
                    "reason=endpoint_unavailable fail_closed=true");
            return;
        }
        if (!sameEndpoint) workerRecovery.reset();
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
                        + "stream_ready=%s button_mask=%d required_mask=%d "
                        + "last_packet_age_ms=%d accepted_packets=%d rejected_packets=%d",
                networkHandle, worker != null && worker.isAlive(),
                workerRecovery.consecutiveFailures(),
                snapshot.streamReady, snapshot.buttonMask,
                requiredTriggerMask,
                ageMillis, acceptedPackets, rejectedPackets);
    }

    @Override
    public synchronized void close() {
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
        byte[] bytes = new byte[Cat6MouseButtonProtocol.PACKET_BYTES];
        DatagramPacket datagram = new DatagramPacket(bytes, bytes.length);
        int activeSessionId = 0;
        int lastSequence = 0;
        boolean sequenceKnown = false;
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
                    Cat6MouseButtonProtocol.decode(bytes, datagram.getLength());
            if (packet == null) {
                rejectedPackets++;
                continue;
            }
            boolean newSession = packet.sessionId != activeSessionId;
            if (!newSession && sequenceKnown
                    && !Cat6MouseButtonProtocol.isNewerSequence(
                    packet.sequence, lastSequence)) {
                rejectedPackets++;
                continue;
            }
            activeSessionId = packet.sessionId;
            lastSequence = packet.sequence;
            sequenceKnown = true;
            acceptPacket(
                    packet.buttonMask, newSession, workerGeneration);
        }
    }

    private synchronized void acceptPacket(
            int buttonMask,
            boolean newSession,
            long workerGeneration) {
        if (generation.get() != workerGeneration) {
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

    private static String safeToken(String value) {
        if (value == null || value.isBlank()) return "unspecified";
        return value.replace(' ', '_').replace('\r', '_').replace('\n', '_');
    }
}
