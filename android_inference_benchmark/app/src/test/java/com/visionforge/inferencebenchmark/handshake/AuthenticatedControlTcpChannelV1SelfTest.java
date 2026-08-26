package com.visionforge.inferencebenchmark.handshake;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.Direction;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.MessageType;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlTcpChannelV1.ChannelException;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlTcpChannelV1.Failure;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

/** Real loopback tests for bounded Android/JDK VFB1 TCP transport behavior. */
public final class AuthenticatedControlTcpChannelV1SelfTest {
    private AuthenticatedControlTcpChannelV1SelfTest() {}

    public static void main(String[] arguments) throws Exception {
        readsWritesAndPreservesCoalescedBoundaries();
        usageAuthorizationSigningTypesCrossTcpFraming();
        blockingSocketBackendReadsWritesAndTimesOut();
        transfersMaximumRecord();
        timeoutPeerMismatchAndInvalidWriteFailClosed();
        System.out.println("AuthenticatedControlTcpChannelV1SelfTest: PASS");
    }

    private static void usageAuthorizationSigningTypesCrossTcpFraming()
            throws Exception {
        byte[] request = authenticatedEnvelope(2, 8);
        byte[] response = authenticatedEnvelope(1, 9);
        try (ServerSocketChannel listener = loopbackListener()) {
            int port = localPort(listener);
            AtomicReference<Throwable> serverFailure = new AtomicReference<>();
            Thread server = new Thread(() -> {
                try (SocketChannel accepted = listener.accept();
                     AuthenticatedControlTcpChannelV1 channel =
                             AuthenticatedControlTcpChannelV1.adoptConnected(
                                     accepted,
                                     "127.0.0.1",
                                     port,
                                     "127.0.0.1",
                                     0)) {
                    byte[] received = channel.readAuthenticatedRecord(
                            com.visionforge.inferencebenchmark.dataplane
                                    .AuthenticatedControlRecordV1.Direction
                                    .ANDROID_TO_HOST,
                            2_000);
                    require(Arrays.equals(received, request),
                            "typed usage signing request framing");
                    channel.writeAuthenticatedRecord(
                            response,
                            com.visionforge.inferencebenchmark.dataplane
                                    .AuthenticatedControlRecordV1.Direction
                                    .HOST_TO_ANDROID,
                            2_000);
                    clear(received);
                } catch (Throwable failure) {
                    serverFailure.set(failure);
                }
            }, "vf-vfc1-usage-signing-server");
            server.start();
            try (AuthenticatedControlTcpChannelV1 client =
                    AuthenticatedControlTcpChannelV1.connectPrepared(
                            SocketChannel.open(),
                            "127.0.0.1",
                            "127.0.0.1",
                            port,
                            2_000)) {
                client.writeAuthenticatedRecord(
                        request,
                        com.visionforge.inferencebenchmark.dataplane
                                .AuthenticatedControlRecordV1.Direction
                                .ANDROID_TO_HOST,
                        2_000);
                byte[] received = client.readAuthenticatedRecord(
                        com.visionforge.inferencebenchmark.dataplane
                                .AuthenticatedControlRecordV1.Direction
                                .HOST_TO_ANDROID,
                        2_000);
                require(Arrays.equals(received, response),
                        "typed usage signing response framing");
                clear(received);
            }
            server.join(3_000L);
            require(!server.isAlive(), "typed usage signing server completed");
            rethrow(serverFailure.get());
        } finally {
            clear(request, response);
        }
    }

    private static byte[] authenticatedEnvelope(
            int directionCode, int messageTypeCode) {
        int headerBytes = com.visionforge.inferencebenchmark.dataplane
                .AuthenticatedControlRecordV1.AUTHENTICATED_HEADER_BYTES;
        int tagBytes = com.visionforge.inferencebenchmark.dataplane
                .AuthenticatedControlRecordV1.GCM_TAG_BYTES;
        ByteBuffer frame = ByteBuffer.allocate(headerBytes + tagBytes);
        frame.putInt(0x5646_4331);
        frame.put((byte) com.visionforge.inferencebenchmark.dataplane
                .AuthenticatedControlRecordV1.PROTOCOL_VERSION);
        frame.put((byte) headerBytes);
        frame.put((byte) directionCode);
        frame.put((byte) messageTypeCode);
        frame.position(36);
        frame.putInt(0);
        frame.position(headerBytes + tagBytes);
        return frame.array();
    }

    private static void blockingSocketBackendReadsWritesAndTimesOut()
            throws Exception {
        byte[] inbound = encode(
                Direction.ANDROID_TO_HOST,
                MessageType.ANDROID_FIRST_PAIR_OFFER,
                ascii("blocking-android-offer"));
        byte[] outbound = encode(
                Direction.HOST_TO_ANDROID,
                MessageType.HOST_FIRST_PAIR_OFFER,
                ascii("blocking-host-offer"));
        try (ServerSocketChannel listener = loopbackListener()) {
            int port = localPort(listener);
            AtomicReference<Throwable> serverFailure = new AtomicReference<>();
            Thread server = new Thread(() -> {
                try (SocketChannel accepted = listener.accept();
                     AuthenticatedControlTcpChannelV1 channel =
                             AuthenticatedControlTcpChannelV1.adoptConnected(
                                     accepted,
                                     "127.0.0.1",
                                     port,
                                     "127.0.0.1",
                                     0)) {
                    byte[] received = channel.readBootstrapRecord(
                            Direction.ANDROID_TO_HOST, 2_000);
                    require(Arrays.equals(received, inbound),
                            "blocking server inbound record");
                    channel.writeBootstrapRecord(
                            outbound,
                            Direction.HOST_TO_ANDROID,
                            2_000);
                    Thread.sleep(150L);
                    clear(received);
                } catch (Throwable failure) {
                    serverFailure.set(failure);
                }
            }, "vf-vfb1-blocking-server");
            server.start();
            try (AuthenticatedControlTcpChannelV1 client =
                    AuthenticatedControlTcpChannelV1.connectPreparedSocket(
                            new Socket(),
                            "127.0.0.1",
                            "127.0.0.1",
                            port,
                            2_000)) {
                require(client.localIpv4().equals("127.0.0.1"),
                        "blocking local IPv4");
                require(client.peerIpv4().equals("127.0.0.1"),
                        "blocking peer IPv4");
                client.writeBootstrapRecord(
                        inbound,
                        Direction.ANDROID_TO_HOST,
                        2_000);
                byte[] received = client.readBootstrapRecord(
                        Direction.HOST_TO_ANDROID, 2_000);
                require(Arrays.equals(received, outbound),
                        "blocking client outbound record");
                clear(received);
                expect(Failure.TIMED_OUT, () -> client.readBootstrapRecord(
                        Direction.HOST_TO_ANDROID, 20));
                require(!client.isOpen(), "blocking timeout closes channel");
            }
            server.join(3_000L);
            require(!server.isAlive(), "blocking server completed");
            rethrow(serverFailure.get());
        } finally {
            clear(inbound, outbound);
        }
    }

    private static void readsWritesAndPreservesCoalescedBoundaries()
            throws Exception {
        byte[] inbound = encode(
                Direction.ANDROID_TO_HOST,
                MessageType.ANDROID_CHALLENGE_REQUEST,
                ascii("android-challenge"));
        byte[] firstOutbound = encode(
                Direction.HOST_TO_ANDROID,
                MessageType.HOST_CHALLENGE_PROOF,
                ascii("host-proof-one"));
        byte[] secondOutbound = encode(
                Direction.HOST_TO_ANDROID,
                MessageType.HOST_FINAL_PROOF,
                ascii("host-proof-two"));
        try (ServerSocketChannel listener = loopbackListener()) {
            int port = localPort(listener);
            AtomicReference<Throwable> serverFailure = new AtomicReference<>();
            Thread server = new Thread(() -> {
                try (SocketChannel accepted = listener.accept();
                     AuthenticatedControlTcpChannelV1 channel =
                             AuthenticatedControlTcpChannelV1.adoptConnected(
                                     accepted,
                                     "127.0.0.1",
                                     port,
                                     "127.0.0.1",
                                     0)) {
                    require(channel.localIpv4().equals("127.0.0.1"),
                            "server local IPv4");
                    require(channel.peerIpv4().equals("127.0.0.1"),
                            "server peer IPv4");
                    byte[] received = channel.readBootstrapRecord(
                            Direction.ANDROID_TO_HOST, 2_000);
                    require(Arrays.equals(received, inbound),
                            "server inbound record");
                    channel.writeBootstrapRecord(
                            firstOutbound,
                            Direction.HOST_TO_ANDROID,
                            2_000);
                    channel.writeBootstrapRecord(
                            secondOutbound,
                            Direction.HOST_TO_ANDROID,
                            2_000);
                    clear(received);
                } catch (Throwable failure) {
                    serverFailure.set(failure);
                }
            }, "vf-vfb1-loopback-server");
            server.start();
            try (AuthenticatedControlTcpChannelV1 client =
                    AuthenticatedControlTcpChannelV1.connectPrepared(
                            SocketChannel.open(),
                            "127.0.0.1",
                            "127.0.0.1",
                            port,
                            2_000)) {
                client.writeBootstrapRecord(
                        inbound,
                        Direction.ANDROID_TO_HOST,
                        2_000);
                byte[] first = client.readBootstrapRecord(
                        Direction.HOST_TO_ANDROID, 2_000);
                byte[] second = client.readBootstrapRecord(
                        Direction.HOST_TO_ANDROID, 2_000);
                require(Arrays.equals(first, firstOutbound),
                        "first outbound record");
                require(Arrays.equals(second, secondOutbound),
                        "second outbound record");
                clear(first, second);
            }
            server.join(3_000L);
            require(!server.isAlive(), "server completed");
            rethrow(serverFailure.get());
        } finally {
            clear(inbound, firstOutbound, secondOutbound);
        }
    }

    private static void transfersMaximumRecord() throws Exception {
        byte[] payload = new byte[
                AuthenticatedControlBootstrapRecordV1.MAX_PAYLOAD_BYTES];
        Arrays.fill(payload, (byte) 0xa5);
        byte[] maximum = encode(
                Direction.HOST_TO_ANDROID,
                MessageType.HOST_HANDSHAKE_SIGNATURE,
                payload);
        try (ServerSocketChannel listener = loopbackListener()) {
            int port = localPort(listener);
            AtomicReference<Throwable> serverFailure = new AtomicReference<>();
            Thread server = new Thread(() -> {
                try (SocketChannel accepted = listener.accept();
                     AuthenticatedControlTcpChannelV1 channel =
                             AuthenticatedControlTcpChannelV1.adoptConnected(
                                     accepted,
                                     "127.0.0.1",
                                     port,
                                     "127.0.0.1",
                                     0)) {
                    channel.writeBootstrapRecord(
                            maximum,
                            Direction.HOST_TO_ANDROID,
                            2_000);
                } catch (Throwable failure) {
                    serverFailure.set(failure);
                }
            }, "vf-vfb1-maximum-server");
            server.start();
            try (AuthenticatedControlTcpChannelV1 client =
                    AuthenticatedControlTcpChannelV1.connectPrepared(
                            SocketChannel.open(),
                            "127.0.0.1",
                            "127.0.0.1",
                            port,
                            2_000)) {
                byte[] received = client.readBootstrapRecord(
                        Direction.HOST_TO_ANDROID, 2_000);
                require(Arrays.equals(received, maximum), "maximum record");
                clear(received);
            }
            server.join(3_000L);
            require(!server.isAlive(), "maximum server completed");
            rethrow(serverFailure.get());
        } finally {
            clear(payload, maximum);
        }
    }

    private static void timeoutPeerMismatchAndInvalidWriteFailClosed()
            throws Exception {
        try (ServerSocketChannel timeoutListener = loopbackListener()) {
            int port = localPort(timeoutListener);
            AtomicReference<Throwable> serverFailure = new AtomicReference<>();
            Thread server = new Thread(() -> {
                try (SocketChannel accepted = timeoutListener.accept()) {
                    require(accepted.isConnected(), "timeout peer connected");
                    Thread.sleep(250L);
                } catch (Throwable failure) {
                    serverFailure.set(failure);
                }
            }, "vf-vfb1-timeout-server");
            server.start();
            AuthenticatedControlTcpChannelV1 client =
                    AuthenticatedControlTcpChannelV1.connectPrepared(
                            SocketChannel.open(),
                            "127.0.0.1",
                            "127.0.0.1",
                            port,
                            2_000);
            expect(Failure.TIMED_OUT, () -> client.readBootstrapRecord(
                    Direction.HOST_TO_ANDROID, 20));
            require(!client.isOpen(), "timeout closes channel");
            client.close();
            server.join(3_000L);
            rethrow(serverFailure.get());
        }

        try (ServerSocketChannel mismatchListener = loopbackListener()) {
            int port = localPort(mismatchListener);
            SocketChannel clientSocket = SocketChannel.open();
            clientSocket.connect(new InetSocketAddress("127.0.0.1", port));
            SocketChannel accepted = mismatchListener.accept();
            expect(Failure.PEER_MISMATCH, () ->
                    AuthenticatedControlTcpChannelV1.adoptConnected(
                            accepted,
                            "127.0.0.1",
                            port,
                            "127.0.0.2",
                            0));
            require(!accepted.isOpen(), "mismatch closes accepted channel");
            clientSocket.close();
        }

        byte[] reflected = encode(
                Direction.HOST_TO_ANDROID,
                MessageType.HOST_HELLO,
                ascii("reflection"));
        try (ServerSocketChannel invalidListener = loopbackListener()) {
            int port = localPort(invalidListener);
            AtomicReference<Throwable> serverFailure = new AtomicReference<>();
            Thread server = new Thread(() -> {
                try (SocketChannel accepted = invalidListener.accept()) {
                    require(accepted.isConnected(), "invalid-write peer connected");
                    Thread.sleep(100L);
                } catch (Throwable failure) {
                    serverFailure.set(failure);
                }
            }, "vf-vfb1-invalid-write-server");
            server.start();
            AuthenticatedControlTcpChannelV1 client =
                    AuthenticatedControlTcpChannelV1.connectPrepared(
                            SocketChannel.open(),
                            "127.0.0.1",
                            "127.0.0.1",
                            port,
                            2_000);
            expect(Failure.INVALID_RECORD, () ->
                    client.writeBootstrapRecord(
                            reflected,
                            Direction.ANDROID_TO_HOST,
                            2_000));
            require(!client.isOpen(), "invalid write closes channel");
            client.close();
            server.join(3_000L);
            rethrow(serverFailure.get());
        } finally {
            clear(reflected);
        }
    }

    private static ServerSocketChannel loopbackListener() throws Exception {
        ServerSocketChannel listener = ServerSocketChannel.open();
        listener.bind(new InetSocketAddress("127.0.0.1", 0));
        return listener;
    }

    private static int localPort(ServerSocketChannel listener)
            throws Exception {
        return ((InetSocketAddress) listener.getLocalAddress()).getPort();
    }

    private static byte[] encode(
            Direction direction,
            MessageType type,
            byte[] payload) throws Exception {
        return AuthenticatedControlBootstrapRecordV1.encode(
                direction, type, payload);
    }

    private static byte[] ascii(String value) throws Exception {
        return value.getBytes("US-ASCII");
    }

    private interface CheckedOperation {
        void run() throws Exception;
    }

    private static void expect(
            Failure expected,
            CheckedOperation operation) throws Exception {
        try {
            operation.run();
            throw new AssertionError("expected " + expected);
        } catch (ChannelException rejected) {
            require(rejected.failure() == expected,
                    "failure reason " + expected);
        }
    }

    private static void rethrow(Throwable failure) throws Exception {
        if (failure == null) return;
        if (failure instanceof Exception) throw (Exception) failure;
        if (failure instanceof Error) throw (Error) failure;
        throw new AssertionError(failure);
    }

    private static void clear(byte[]... values) {
        for (byte[] value : values) {
            if (value != null) Arrays.fill(value, (byte) 0);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
