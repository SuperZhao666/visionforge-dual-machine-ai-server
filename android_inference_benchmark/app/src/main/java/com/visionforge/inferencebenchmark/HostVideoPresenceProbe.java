package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.net.BindException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

/**
 * Performs one bounded, non-inference UDP check before paid usage starts.
 *
 * <p>The probe does not authenticate or encrypt Host traffic. It only proves
 * that the configured Host is actively publishing a structurally valid
 * VisionForge video fragment on the selected transport. The socket is closed
 * before the server is asked to create the first billable lease.</p>
 */
final class HostVideoPresenceProbe {
    static final int VIDEO_HEADER_BYTES = 12;
    static final int VIDEO_PAYLOAD_BYTES = 1_400;
    static final int MAX_DATAGRAM_BYTES = VIDEO_HEADER_BYTES + VIDEO_PAYLOAD_BYTES;
    static final int VIDEO_PACKET_MAGIC = 0x56465247; // "VFRG"
    static final int VIDEO_REPEATED_PACKET_MAGIC = 0x56465252; // "VFRR"
    static final long LOGICAL_FRAME_ID_MASK = 0x7fff_ffffL;
    private static final int MAX_ACCESS_UNIT_BYTES = 2 * 1024 * 1024;
    private static final int MAX_FRAGMENT_COUNT =
            (MAX_ACCESS_UNIT_BYTES + VIDEO_PAYLOAD_BYTES - 1) / VIDEO_PAYLOAD_BYTES;

    private final MobileRuntimeEventSink events;
    private final HostVideoPreflightLogPolicy failureLogPolicy =
            new HostVideoPreflightLogPolicy();
    private final AtomicReference<DatagramSocket> activeSocket =
            new AtomicReference<>();
    private final AtomicLong cancellationGeneration = new AtomicLong();

    HostVideoPresenceProbe(MobileRuntimeEventSink events) {
        if (events == null) throw new IllegalArgumentException("events are required");
        this.events = events;
    }

    HostVideoObservation awaitValidHostVideo(
            MobileTransportEndpoint endpoint,
            int port,
            long timeoutMillis) throws IOException {
        return awaitValidHostVideo(
                endpoint, port, timeoutMillis, () -> false);
    }

    HostVideoObservation awaitValidHostVideo(
            MobileTransportEndpoint endpoint,
            int port,
            long timeoutMillis,
            BooleanSupplier cancellationRequested) throws IOException {
        // A single valid fragment can be a delayed tail of a stalled WLAN
        // burst. Billing readiness requires two distinct, forward-moving
        // frame starts so candidate3's one-packet late wake cannot debit.
        return receiveValidHostVideo(
                endpoint,
                port,
                timeoutMillis,
                true,
                2,
                cancellationRequested);
    }

    /**
     * Performs one quiet non-billing observation for the automatic re-arm
     * gate. A normal timeout means that no Host video is currently visible;
     * socket failures remain exceptional so diagnostics are not hidden.
     */
    HostVideoObservation pollValidHostVideo(
            MobileTransportEndpoint endpoint,
            int port,
            long timeoutMillis) throws IOException {
        try {
            // A re-arm observation must include two forward-moving frame
            // starts. One delayed fragment after an idle Wi-Fi interval is
            // never enough to unlock another paid generation.
            return receiveValidHostVideo(
                    endpoint,
                    port,
                    timeoutMillis,
                    false,
                    2,
                    () -> false);
        } catch (HostVideoNotObservedException notObserved) {
            return null;
        }
    }

    private HostVideoObservation receiveValidHostVideo(
            MobileTransportEndpoint endpoint,
            int port,
            long timeoutMillis,
            boolean logOutcome,
            int minimumForwardFrameStarts,
            BooleanSupplier cancellationRequested) throws IOException {
        if (cancellationRequested == null) {
            throw new IllegalArgumentException(
                    "Host video cancellation signal is required");
        }
        requireNotCancelled(cancellationRequested, -1L);
        if (endpoint == null || !endpoint.isReadyForDataPlane()) {
            throw new IOException("host_video_preflight_transport_unavailable");
        }
        if (port <= 0 || port > 65_535 || timeoutMillis <= 0L
                || minimumForwardFrameStarts <= 0) {
            throw new IllegalArgumentException("invalid Host video preflight parameters");
        }

        long startedNanos = System.nanoTime();
        long generation = cancellationGeneration.get();
        long deadlineNanos = startedNanos
                + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        int rejectedDatagrams = 0;
        int confirmedForwardFrameStarts = 0;
        long previousFrameStartSequence = -1L;
        DatagramSocket socket = null;
        try {
            InetAddress localAddress = InetAddress.getByName(endpoint.localIpv4);
            InetAddress expectedHost = InetAddress.getByName(endpoint.hostIpv4);
            socket = new DatagramSocket(null);
            if (!activeSocket.compareAndSet(null, socket)) {
                throw new IOException("host_video_preflight_already_running");
            }
            if (cancellationObserved(cancellationRequested, generation)) {
                activeSocket.compareAndSet(socket, null);
                socket.close();
                throw cancelled(null);
            }
            socket.setReuseAddress(false);
            endpoint.network.bindSocket(socket);
            try {
                socket.bind(new InetSocketAddress(localAddress, port));
            } catch (BindException failure) {
                if (!isLocalAddressUnavailable(failure)) throw failure;
                // CAT6 -> Wi-Fi fallback can revoke the fixed CAT6 address a
                // moment before Android publishes the replacement callback.
                // That exact route cannot carry a Host frame, so count it as
                // an absence observation instead of leaving the automatic
                // re-arm guard stuck behind a generic socket failure. Keep
                // the explicit address bind: wildcard fallback would let a
                // pre-billing probe validate a route the real data plane
                // cannot open.
                throw localAddressUnavailable(endpoint, failure);
            }

            // One extra byte lets DatagramSocket expose an oversized packet
            // instead of truncating it into an apparently valid 1412 bytes.
            byte[] bytes = new byte[MAX_DATAGRAM_BYTES + 1];
            DatagramPacket datagram = new DatagramPacket(bytes, bytes.length);
            while (true) {
                requireNotCancelled(cancellationRequested, generation);
                long remainingNanos = deadlineNanos - System.nanoTime();
                if (remainingNanos <= 0L) {
                    throw notObserved(timeoutMillis, rejectedDatagrams);
                }
                long remainingMillis = Math.max(
                        1L, TimeUnit.NANOSECONDS.toMillis(remainingNanos));
                socket.setSoTimeout((int) Math.min(
                        Integer.MAX_VALUE, remainingMillis));
                datagram.setLength(bytes.length);
                try {
                    socket.receive(datagram);
                } catch (SocketTimeoutException timeout) {
                    throw notObserved(timeoutMillis, rejectedDatagrams);
                }
                if (!expectedHost.equals(datagram.getAddress())
                        || !isValidVideoDatagram(bytes, datagram.getLength())) {
                    rejectedDatagrams++;
                    continue;
                }
                long logicalFrameSequence = logicalFrameSequence(
                        bytes, datagram.getLength());
                if (minimumForwardFrameStarts > 1) {
                    if (!isFrameStartDatagram(bytes, datagram.getLength())) {
                        continue;
                    }
                    if (previousFrameStartSequence < 0L) {
                        previousFrameStartSequence = logicalFrameSequence;
                        confirmedForwardFrameStarts = 1;
                        continue;
                    }
                    if (!isForwardFrameSequence(
                            previousFrameStartSequence,
                            logicalFrameSequence)) {
                        continue;
                    }
                    previousFrameStartSequence = logicalFrameSequence;
                    confirmedForwardFrameStarts++;
                    if (confirmedForwardFrameStarts
                            < minimumForwardFrameStarts) {
                        continue;
                    }
                } else {
                    confirmedForwardFrameStarts = 1;
                }
                long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(
                        Math.max(0L, System.nanoTime() - startedNanos));
                HostVideoObservation observation = new HostVideoObservation(
                        logicalFrameSequence,
                        datagram.getPort(),
                        datagram.getLength(),
                        confirmedForwardFrameStarts);
                failureLogPolicy.clearFailure();
                if (logOutcome) {
                    events.write(
                            "dual_machine_host_video_preflight_ready",
                            "network_handle=" + endpoint.networkHandle
                                    + " port=" + port
                                    + " accepted_bytes=" + datagram.getLength()
                                    + " logical_frame_id="
                                    + observation.logicalFrameSequence
                                    + " confirmed_forward_frame_starts="
                                    + observation.confirmedForwardFrameStarts
                                    + " rejected_datagrams=" + rejectedDatagrams
                                    + " elapsed_ms=" + elapsedMillis
                                    + " billing_started=false");
                }
                return observation;
            }
        } catch (HostVideoNotObservedException failure) {
            requireNotCancelled(cancellationRequested, generation, failure);
            if (logOutcome && failureLogPolicy.shouldWriteFailure(
                    endpoint.detail(),
                    "valid_host_video_not_observed",
                    monotonicMillis())) {
                events.write(
                        "dual_machine_host_video_preflight_failed",
                        "reason=valid_host_video_not_observed"
                                + " network_handle=" + endpoint.networkHandle
                                + " port=" + port
                                + " timeout_ms=" + timeoutMillis
                                + " rejected_datagrams=" + rejectedDatagrams
                                + " billing_started=false");
            }
            throw failure;
        } catch (IOException failure) {
            requireNotCancelled(cancellationRequested, generation, failure);
            String failureReason = "socket_failure:"
                    + failure.getClass().getSimpleName();
            if (logOutcome && failureLogPolicy.shouldWriteFailure(
                    endpoint.detail(), failureReason, monotonicMillis())) {
                events.write(
                        "dual_machine_host_video_preflight_failed",
                        "reason=socket_failure"
                                + " network_handle=" + endpoint.networkHandle
                                + " port=" + port
                                + " failure_type="
                                + failure.getClass().getSimpleName()
                                + " billing_started=false");
            }
            throw failure;
        } finally {
            if (socket != null) {
                activeSocket.compareAndSet(socket, null);
                socket.close();
            }
        }
    }

    void cancel() {
        cancellationGeneration.incrementAndGet();
        DatagramSocket socket = activeSocket.getAndSet(null);
        if (socket != null) socket.close();
    }

    static boolean isValidVideoDatagram(byte[] bytes, int length) {
        if (bytes == null || length <= VIDEO_HEADER_BYTES
                || length > MAX_DATAGRAM_BYTES || length > bytes.length) {
            return false;
        }
        int magic = readInt(bytes, 0);
        if (magic != VIDEO_PACKET_MAGIC
                && magic != VIDEO_REPEATED_PACKET_MAGIC) {
            return false;
        }
        int fragmentIndex = readUnsignedShort(bytes, 8);
        int fragmentCount = readUnsignedShort(bytes, 10);
        return fragmentCount > 0
                && fragmentCount <= MAX_FRAGMENT_COUNT
                && fragmentIndex < fragmentCount;
    }

    static long logicalFrameSequence(byte[] bytes, int length) {
        if (!isValidVideoDatagram(bytes, length)) return -1L;
        return Integer.toUnsignedLong(readInt(bytes, 4))
                & LOGICAL_FRAME_ID_MASK;
    }

    static boolean isFrameStartDatagram(byte[] bytes, int length) {
        return isValidVideoDatagram(bytes, length)
                && readUnsignedShort(bytes, 8) == 0;
    }

    static boolean isForwardFrameSequence(long previous, long current) {
        if (previous < 0L || previous > LOGICAL_FRAME_ID_MASK
                || current < 0L || current > LOGICAL_FRAME_ID_MASK
                || previous == current) {
            return false;
        }
        long forwardDistance = (current - previous)
                & LOGICAL_FRAME_ID_MASK;
        return forwardDistance > 0L
                && forwardDistance <= (LOGICAL_FRAME_ID_MASK + 1L) / 2L;
    }

    static boolean isLocalAddressUnavailable(Throwable failure) {
        for (Throwable current = failure;
             current != null;
             current = current.getCause()) {
            String message = current.getMessage();
            if (message == null || message.isBlank()) continue;
            String normalized = message.toUpperCase(Locale.ROOT);
            if (normalized.contains("EADDRNOTAVAIL")
                    || normalized.contains(
                    "CANNOT ASSIGN REQUESTED ADDRESS")) {
                return true;
            }
        }
        return false;
    }

    private static HostVideoNotObservedException localAddressUnavailable(
            MobileTransportEndpoint endpoint,
            BindException failure) {
        return new HostVideoNotObservedException(
                "host_video_not_observed reason=local_address_unavailable"
                        + " local_ipv4=" + endpoint.localIpv4,
                failure);
    }

    private static HostVideoNotObservedException notObserved(
            long timeoutMillis,
            int rejectedDatagrams) {
        return new HostVideoNotObservedException(
                "host_video_not_observed timeout_ms=" + timeoutMillis
                        + " rejected_datagrams=" + rejectedDatagrams);
    }

    private static long monotonicMillis() {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime());
    }

    private void requireNotCancelled(
            BooleanSupplier cancellationRequested,
            long generation) throws HostVideoProbeCancelledException {
        requireNotCancelled(cancellationRequested, generation, null);
    }

    private void requireNotCancelled(
            BooleanSupplier cancellationRequested,
            long generation,
            Throwable cause) throws HostVideoProbeCancelledException {
        if (cancellationObserved(cancellationRequested, generation)) {
            throw cancelled(cause);
        }
    }

    private boolean cancellationObserved(
            BooleanSupplier cancellationRequested,
            long generation) {
        return cancellationRequested.getAsBoolean()
                || generation >= 0L
                && generation != cancellationGeneration.get();
    }

    private static HostVideoProbeCancelledException cancelled(
            Throwable cause) {
        return new HostVideoProbeCancelledException(
                "host_video_preflight_cancelled", cause);
    }

    private static int readInt(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 24)
                | ((bytes[offset + 1] & 0xff) << 16)
                | ((bytes[offset + 2] & 0xff) << 8)
                | (bytes[offset + 3] & 0xff);
    }

    private static int readUnsignedShort(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8)
                | (bytes[offset + 1] & 0xff);
    }

    static final class HostVideoNotObservedException extends IOException {
        HostVideoNotObservedException(String message) {
            super(message);
        }

        HostVideoNotObservedException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static final class HostVideoProbeCancelledException extends IOException {
        HostVideoProbeCancelledException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static final class HostVideoObservation {
        final long logicalFrameSequence;
        final int sourcePort;
        final int datagramBytes;
        final int confirmedForwardFrameStarts;

        HostVideoObservation(
                long logicalFrameSequence,
                int sourcePort,
                int datagramBytes,
                int confirmedForwardFrameStarts) {
            this.logicalFrameSequence = logicalFrameSequence;
            this.sourcePort = sourcePort;
            this.datagramBytes = datagramBytes;
            this.confirmedForwardFrameStarts =
                    confirmedForwardFrameStarts;
        }
    }
}
