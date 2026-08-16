package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.video.VideoFrameIdentity;
import com.visionforge.inferencebenchmark.video.VideoWireProtocol;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.BindException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Development-only regression for the shared v6.0 VF2G/VF2R parser. */
final class HostVideoPresenceProbeSelfTest {
    static void run() {
        acceptsNormalAndRepeatedVideoFragments();
        extractsLogicalFrameSequenceWithoutRepeatFlag();
        identifiesFrameStartsAndForwardSequences();
        classifiesOnlyUnavailableLocalAddressBindFailures();
        rejectsMalformedOrNonVideoDatagrams();
        cancellationShortCircuitsBeforeEndpointValidation();
        activeSocketCancellationIsNotAProbeFailure();
    }

    private static void acceptsNormalAndRepeatedVideoFragments() {
        byte[] normal = packet(
                HostVideoPresenceProbe.VIDEO_PACKET_MAGIC, 0, 2, 64);
        byte[] repeated = packet(
                HostVideoPresenceProbe.VIDEO_REPEATED_PACKET_MAGIC, 1, 2, 12);
        byte[] maximumFragmentCount = packet(
                HostVideoPresenceProbe.VIDEO_PACKET_MAGIC, 1_497, 1_498, 1);
        require(HostVideoPresenceProbe.isValidVideoDatagram(
                normal, normal.length));
        require(HostVideoPresenceProbe.isValidVideoDatagram(
                repeated, repeated.length));
        require(HostVideoPresenceProbe.isValidVideoDatagram(
                maximumFragmentCount, maximumFragmentCount.length));
    }

    private static void rejectsMalformedOrNonVideoDatagrams() {
        byte[] valid = packet(
                HostVideoPresenceProbe.VIDEO_PACKET_MAGIC, 0, 1, 1);
        require(!HostVideoPresenceProbe.isValidVideoDatagram(null, 0));
        require(!HostVideoPresenceProbe.isValidVideoDatagram(
                valid, HostVideoPresenceProbe.VIDEO_HEADER_BYTES));
        require(!HostVideoPresenceProbe.isValidVideoDatagram(
                valid, valid.length + 1));

        byte[] oversized = new byte[
                HostVideoPresenceProbe.MAX_DATAGRAM_BYTES + 1];
        System.arraycopy(valid, 0, oversized, 0, valid.length);
        require(!HostVideoPresenceProbe.isValidVideoDatagram(
                oversized, oversized.length));

        byte[] wrongMagic = valid.clone();
        writeInt(wrongMagic, 0, 0x01020304);
        require(!HostVideoPresenceProbe.isValidVideoDatagram(
                wrongMagic, wrongMagic.length));

        byte[] zeroCount = valid.clone();
        writeUnsignedShort(zeroCount, 18, 0);
        require(!HostVideoPresenceProbe.isValidVideoDatagram(
                zeroCount, zeroCount.length));

        byte[] indexOutOfRange = valid.clone();
        writeUnsignedShort(indexOutOfRange, 16, 1);
        require(!HostVideoPresenceProbe.isValidVideoDatagram(
                indexOutOfRange, indexOutOfRange.length));

        byte[] excessiveCount = valid.clone();
        writeUnsignedShort(excessiveCount, 18, 1_499);
        require(!HostVideoPresenceProbe.isValidVideoDatagram(
                excessiveCount, excessiveCount.length));
        require(HostVideoPresenceProbe.logicalFrameSequence(
                excessiveCount, excessiveCount.length) == -1L);
    }

    private static void extractsLogicalFrameSequenceWithoutRepeatFlag() {
        byte[] normal = packet(
                HostVideoPresenceProbe.VIDEO_PACKET_MAGIC, 0, 1, 1);
        writeLong(normal, 4, 99L);
        writeInt(normal, 12, 0x8123_4567);
        require(HostVideoPresenceProbe.streamEpoch(normal, normal.length) == 99L);
        require(HostVideoPresenceProbe.logicalFrameSequence(
                normal, normal.length) == 0x8123_4567L);

        byte[] repeated = packet(
                HostVideoPresenceProbe.VIDEO_REPEATED_PACKET_MAGIC, 0, 1, 1);
        writeLong(repeated, 4, 99L);
        writeInt(repeated, 12, 37);
        require(HostVideoPresenceProbe.logicalFrameSequence(
                repeated, repeated.length) == 37L);
    }

    private static void identifiesFrameStartsAndForwardSequences() {
        byte[] first = packet(
                HostVideoPresenceProbe.VIDEO_PACKET_MAGIC, 0, 2, 4);
        byte[] second = packet(
                HostVideoPresenceProbe.VIDEO_PACKET_MAGIC, 1, 2, 4);
        require(HostVideoPresenceProbe.isFrameStartDatagram(
                first, first.length));
        require(!HostVideoPresenceProbe.isFrameStartDatagram(
                second, second.length));
        require(HostVideoPresenceProbe.isForwardFrameSequence(100L, 101L));
        require(!HostVideoPresenceProbe.isForwardFrameSequence(100L, 100L));
        require(!HostVideoPresenceProbe.isForwardFrameSequence(1_000L, 900L));
        require(!HostVideoPresenceProbe.isForwardFrameSequence(
                HostVideoPresenceProbe.LOGICAL_FRAME_ID_MASK, 0L));
        require(HostVideoPresenceProbe.isForwardFrameSequence(
                5L, HostVideoPresenceProbe.LOGICAL_FRAME_ID_MASK - 2L));
    }

    private static void classifiesOnlyUnavailableLocalAddressBindFailures() {
        require(HostVideoPresenceProbe.isLocalAddressUnavailable(
                new BindException(
                        "bind failed: EADDRNOTAVAIL (Cannot assign requested address)")));
        IOException wrapped = new IOException(
                "socket setup failed",
                new BindException("cannot assign requested address"));
        require(HostVideoPresenceProbe.isLocalAddressUnavailable(wrapped));
        require(!HostVideoPresenceProbe.isLocalAddressUnavailable(
                new BindException("bind failed: EADDRINUSE (Address already in use)")));
        require(!HostVideoPresenceProbe.isLocalAddressUnavailable(
                new IOException("network unreachable")));
        require(!HostVideoPresenceProbe.isLocalAddressUnavailable(null));
    }

    private static void cancellationShortCircuitsBeforeEndpointValidation() {
        AtomicInteger events = new AtomicInteger();
        HostVideoPresenceProbe probe = new HostVideoPresenceProbe(
                (event, detail) -> events.incrementAndGet());
        try {
            probe.awaitValidHostVideo(null, 42_000, 1_000L, () -> true);
            throw new AssertionError(
                    "cancelled Host-video probe unexpectedly continued");
        } catch (HostVideoPresenceProbe.HostVideoProbeCancelledException expected) {
            require("host_video_preflight_cancelled".equals(
                    expected.getMessage()));
        } catch (IOException wrongFailure) {
            throw new AssertionError(
                    "cancelled Host-video probe used the failure path",
                    wrongFailure);
        }
        require(events.get() == 0);
    }

    private static void activeSocketCancellationIsNotAProbeFailure() {
        AtomicInteger events = new AtomicInteger();
        HostVideoPresenceProbe probe = new HostVideoPresenceProbe(
                (event, detail) -> events.incrementAndGet());
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            int port;
            try (DatagramSocket reservation = new DatagramSocket(
                    0, InetAddress.getByName("127.0.0.1"))) {
                port = reservation.getLocalPort();
            }
            MobileTransportEndpoint endpoint =
                    MobileTransportEndpointTestFixtures.loopbackProbe(
                            17L, "127.0.0.1", "127.0.0.2");
            Future<HostVideoPresenceProbe.HostVideoObservation> future =
                    executor.submit(() -> probe.awaitValidHostVideo(
                            endpoint, port, 5_000L));
            waitForActiveSocket(probe);
            probe.cancel();
            try {
                future.get(2L, TimeUnit.SECONDS);
                throw new AssertionError(
                        "cancelled active Host-video probe unexpectedly completed");
            } catch (ExecutionException expected) {
                require(expected.getCause()
                        instanceof HostVideoPresenceProbe
                        .HostVideoProbeCancelledException);
            }
            require(events.get() == 0);
        } catch (Exception failure) {
            throw new AssertionError(
                    "active Host-video cancellation regression failed",
                    failure);
        } finally {
            executor.shutdownNow();
        }
    }

    @SuppressWarnings("unchecked")
    private static void waitForActiveSocket(HostVideoPresenceProbe probe)
            throws Exception {
        Field field = HostVideoPresenceProbe.class.getDeclaredField(
                "activeSocket");
        field.setAccessible(true);
        AtomicReference<DatagramSocket> active =
                (AtomicReference<DatagramSocket>) field.get(probe);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2L);
        while (active.get() == null && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        require(active.get() != null);
    }

    private static byte[] packet(
            int magic,
            int fragmentIndex,
            int fragmentCount,
            int payloadBytes) {
        byte[] payload = new byte[payloadBytes];
        payload[0] = 1;
        return VideoWireProtocol.encodeForTest(
                new VideoFrameIdentity(37L, 37L),
                magic == HostVideoPresenceProbe.VIDEO_REPEATED_PACKET_MAGIC,
                fragmentIndex, fragmentCount, payload);
    }

    private static void writeInt(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) (value >>> 24);
        bytes[offset + 1] = (byte) (value >>> 16);
        bytes[offset + 2] = (byte) (value >>> 8);
        bytes[offset + 3] = (byte) value;
    }

    private static void writeLong(byte[] bytes, int offset, long value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            bytes[offset++] = (byte) (value >>> shift);
        }
    }

    private static void writeUnsignedShort(
            byte[] bytes,
            int offset,
            int value) {
        bytes[offset] = (byte) (value >>> 8);
        bytes[offset + 1] = (byte) value;
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Host video preflight contract failed");
    }
}
