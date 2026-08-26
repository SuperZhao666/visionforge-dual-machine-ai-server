package com.visionforge.inferencebenchmark.handshake;

import com.visionforge.inferencebenchmark.dataplane.AuthenticatedControlRecordV1;

import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * One bounded TCP byte stream for VFB1 bootstrap records.
 *
 * <p>This class authenticates no peer. It validates only the locally selected
 * numeric route and strict VFB1 framing. The nine-record identity signatures
 * and Finished proofs remain the sole authority for an authenticated Host
 * attachment.</p>
 */
public final class AuthenticatedControlTcpChannelV1 implements AutoCloseable {
    public static final int FIRST_PAIRING_PORT = 5006;
    public static final int AUTHENTICATED_CONTROL_PORT = 5008;
    private static final int READ_BUFFER_BYTES = 4096;
    private static final int MAXIMUM_TIMEOUT_MILLIS = 60_000;

    public enum Failure {
        INVALID_CONFIGURATION,
        TIMED_OUT,
        PEER_CLOSED,
        PEER_MISMATCH,
        INVALID_RECORD,
        IO_FAILED,
        CANCELLED,
        CLOSED
    }

    /** Sanitized failure that never retains a socket exception or record. */
    public static final class ChannelException extends IOException {
        private static final long serialVersionUID = 1L;
        private final Failure failure;
        private final String stage;

        private ChannelException(Failure failure) {
            this(failure, "channel");
        }

        private ChannelException(Failure failure, String stage) {
            super("authenticated control TCP channel failed");
            this.failure = failure;
            this.stage = stage;
        }

        public Failure failure() {
            return failure;
        }

        /** Fixed diagnostic token; never contains an address or native error. */
        public String stage() {
            return stage;
        }
    }

    private final SocketChannel channel;
    private final Selector selector;
    private final Socket socket;
    private final InputStream socketInput;
    private final OutputStream socketOutput;
    private byte[] pendingInput;
    private int pendingOffset;
    private boolean closed;

    private AuthenticatedControlTcpChannelV1(
            SocketChannel channel,
            Selector selector) {
        this.channel = channel;
        this.selector = selector;
        this.socket = null;
        this.socketInput = null;
        this.socketOutput = null;
    }

    private AuthenticatedControlTcpChannelV1(
            Socket socket,
            InputStream socketInput,
            OutputStream socketOutput) {
        this.channel = null;
        this.selector = null;
        this.socket = socket;
        this.socketInput = socketInput;
        this.socketOutput = socketOutput;
    }

    /** Sanitized configuration rejection for the Android network adapter. */
    public static ChannelException invalidConfigurationFailure() {
        return failure(Failure.INVALID_CONFIGURATION);
    }

    /** Android adapter seam for a fixed, non-sensitive configuration stage. */
    public static ChannelException invalidConfigurationFailure(String stage) {
        if (!"socket_open".equals(stage)
                && !"socket_open_io".equals(stage)
                && !"socket_open_socket".equals(stage)
                && !"socket_open_security".equals(stage)
                && !"socket_open_unsupported".equals(stage)
                && !"socket_open_runtime".equals(stage)
                && !"network_bind".equals(stage)
                && !"channel_connect".equals(stage)) {
            return invalidConfigurationFailure();
        }
        return new ChannelException(Failure.INVALID_CONFIGURATION, stage);
    }

    /**
     * Completes a connection on a caller-created channel. Android production
     * must bind that channel's Socket to the selected {@code Network} first.
     */
    public static AuthenticatedControlTcpChannelV1 connectPrepared(
            SocketChannel preparedChannel,
            String localIpv4,
            String expectedPeerIpv4,
            int peerPort,
            int timeoutMillis) throws ChannelException {
        SocketChannel channel = preparedChannel;
        Selector selector = null;
        try {
            requireTimeout(timeoutMillis);
            Inet4Address local = numericIpv4(localIpv4);
            Inet4Address peer = numericIpv4(expectedPeerIpv4);
            if (channel == null || peerPort <= 0 || peerPort > 65_535) {
                throw failure(Failure.INVALID_CONFIGURATION);
            }
            channel.configureBlocking(false);
            channel.socket().setReuseAddress(false);
            channel.socket().setTcpNoDelay(true);
            channel.socket().setKeepAlive(false);
            channel.bind(new InetSocketAddress(local, 0));
            selector = Selector.open();
            channel.register(selector, SelectionKey.OP_CONNECT);
            boolean connected = channel.connect(
                    new InetSocketAddress(peer, peerPort));
            long deadline = deadline(timeoutMillis);
            while (!connected) {
                checkCancelled();
                waitReady(selector, SelectionKey.OP_CONNECT, deadline);
                connected = channel.finishConnect();
            }
            AuthenticatedControlTcpChannelV1 result = adoptConnected(
                    channel,
                    selector,
                    localIpv4,
                    0,
                    expectedPeerIpv4,
                    peerPort);
            channel = null;
            selector = null;
            return result;
        } catch (ChannelException rejected) {
            closeQuietly(channel, selector);
            throw rejected;
        } catch (IOException | RuntimeException rejected) {
            closeQuietly(channel, selector);
            throw failure(Failure.IO_FAILED);
        }
    }

    /**
     * Completes a connection on a caller-created blocking Socket.
     *
     * <p>Android production supplies a Socket created by the selected
     * {@code Network}'s SocketFactory. That is the public Android API for
     * retaining a per-socket network binding without changing the process-wide
     * default network.</p>
     */
    public static AuthenticatedControlTcpChannelV1 connectPreparedSocket(
            Socket preparedSocket,
            String localIpv4,
            String expectedPeerIpv4,
            int peerPort,
            int timeoutMillis) throws ChannelException {
        Socket socket = preparedSocket;
        try {
            requireTimeout(timeoutMillis);
            Inet4Address local = numericIpv4(localIpv4);
            Inet4Address peer = numericIpv4(expectedPeerIpv4);
            if (socket == null
                    || socket.isClosed()
                    || socket.isConnected()
                    || peerPort <= 0
                    || peerPort > 65_535) {
                throw failure(Failure.INVALID_CONFIGURATION);
            }
            socket.setReuseAddress(false);
            socket.setTcpNoDelay(true);
            socket.setKeepAlive(false);
            socket.bind(new InetSocketAddress(local, 0));
            try {
                socket.connect(
                        new InetSocketAddress(peer, peerPort),
                        timeoutMillis);
            } catch (SocketTimeoutException timedOut) {
                throw failure(Failure.TIMED_OUT);
            }
            AuthenticatedControlTcpChannelV1 result = adoptConnectedSocket(
                    socket,
                    localIpv4,
                    0,
                    expectedPeerIpv4,
                    peerPort);
            socket = null;
            return result;
        } catch (ChannelException rejected) {
            closeQuietly(socket);
            throw rejected;
        } catch (IOException | RuntimeException rejected) {
            closeQuietly(socket);
            throw failure(Failure.IO_FAILED);
        }
    }

    /** Test/server seam for a connected channel; it performs no network bind. */
    public static AuthenticatedControlTcpChannelV1 adoptConnected(
            SocketChannel connectedChannel,
            String expectedLocalIpv4,
            int expectedLocalPort,
            String expectedPeerIpv4,
            int expectedPeerPort) throws ChannelException {
        Selector selector = null;
        try {
            if (connectedChannel == null || !connectedChannel.isConnected()) {
                throw failure(Failure.INVALID_CONFIGURATION);
            }
            connectedChannel.configureBlocking(false);
            connectedChannel.socket().setTcpNoDelay(true);
            connectedChannel.socket().setKeepAlive(false);
            selector = Selector.open();
            connectedChannel.register(selector, 0);
            AuthenticatedControlTcpChannelV1 result = adoptConnected(
                    connectedChannel,
                    selector,
                    expectedLocalIpv4,
                    expectedLocalPort,
                    expectedPeerIpv4,
                    expectedPeerPort);
            selector = null;
            return result;
        } catch (ChannelException rejected) {
            closeQuietly(connectedChannel, selector);
            throw rejected;
        } catch (IOException | RuntimeException rejected) {
            closeQuietly(connectedChannel, selector);
            throw failure(Failure.IO_FAILED);
        }
    }

    public synchronized byte[] readBootstrapRecord(
            AuthenticatedControlBootstrapRecordV1.Direction expectedDirection,
            int timeoutMillis) throws ChannelException {
        requireOpen();
        requireTimeout(timeoutMillis);
        if (expectedDirection == null) {
            close();
            throw failure(Failure.INVALID_CONFIGURATION);
        }
        AuthenticatedControlBootstrapRecordV1.StreamDecoder decoder =
                new AuthenticatedControlBootstrapRecordV1.StreamDecoder(
                        expectedDirection);
        ByteBuffer input = ByteBuffer.allocate(READ_BUFFER_BYTES);
        long deadline = deadline(timeoutMillis);
        try {
            while (true) {
                checkCancelled();
                if (pendingInput != null && pendingOffset < pendingInput.length) {
                    AuthenticatedControlBootstrapRecordV1.FeedResult fed =
                            decoder.feed(
                                    pendingInput,
                                    pendingOffset,
                                    pendingInput.length - pendingOffset);
                    pendingOffset += fed.consumed();
                    if (pendingOffset == pendingInput.length) clearPending();
                    if (fed.status()
                            == AuthenticatedControlBootstrapRecordV1
                                    .StreamStatus.RECORD_READY) {
                        return decoder.takeEncodedRecord();
                    }
                    if (fed.status()
                                    == AuthenticatedControlBootstrapRecordV1
                                            .StreamStatus.REJECTED
                            || fed.status()
                                    == AuthenticatedControlBootstrapRecordV1
                                            .StreamStatus.ALLOCATION_FAILED) {
                        close();
                        throw failure(Failure.INVALID_RECORD);
                    }
                }

                input.clear();
                int received;
                if (socket != null) {
                    socket.setSoTimeout(remainingTimeoutMillis(deadline));
                    try {
                        received = socketInput.read(input.array());
                    } catch (SocketTimeoutException timedOut) {
                        throw failure(Failure.TIMED_OUT);
                    }
                } else {
                    waitReady(selector, SelectionKey.OP_READ, deadline);
                    received = channel.read(input);
                }
                if (received < 0) {
                    close();
                    throw failure(Failure.PEER_CLOSED);
                }
                if (received == 0) continue;
                if (socket != null) input.position(received);
                input.flip();
                pendingInput = new byte[received];
                input.get(pendingInput);
                pendingOffset = 0;
            }
        } catch (ChannelException rejected) {
            close();
            throw rejected;
        } catch (IOException | RuntimeException rejected) {
            close();
            throw failure(Failure.IO_FAILED);
        } finally {
            Arrays.fill(input.array(), (byte) 0);
            decoder.close();
        }
    }

    public synchronized void writeBootstrapRecord(
            byte[] encodedRecord,
            AuthenticatedControlBootstrapRecordV1.Direction expectedDirection,
            int timeoutMillis) throws ChannelException {
        requireOpen();
        requireTimeout(timeoutMillis);
        if (encodedRecord == null || expectedDirection == null) {
            close();
            throw failure(Failure.INVALID_CONFIGURATION);
        }
        try (AuthenticatedControlBootstrapRecordV1.Record validated =
                AuthenticatedControlBootstrapRecordV1.parse(
                        encodedRecord, expectedDirection)) {
            if (validated.direction() != expectedDirection) {
                close();
                throw failure(Failure.INVALID_RECORD);
            }
            long deadline = deadline(timeoutMillis);
            if (socket != null) {
                writeSocketWithDeadline(encodedRecord, deadline);
            } else {
                ByteBuffer output = ByteBuffer.wrap(encodedRecord);
                while (output.hasRemaining()) {
                    checkCancelled();
                    waitReady(selector, SelectionKey.OP_WRITE, deadline);
                    int written = channel.write(output);
                    if (written < 0) {
                        close();
                        throw failure(Failure.PEER_CLOSED);
                    }
                }
            }
        } catch (AuthenticatedControlBootstrapRecordV1.BootstrapException
                malformed) {
            close();
            throw failure(Failure.INVALID_RECORD);
        } catch (ChannelException rejected) {
            close();
            throw rejected;
        } catch (IOException | RuntimeException rejected) {
            close();
            throw failure(Failure.IO_FAILED);
        }
    }

    /** Reads one opaque VFC1 envelope; authentication is performed by its owner. */
    public synchronized byte[] readAuthenticatedRecord(
            AuthenticatedControlRecordV1.Direction expectedDirection,
            int timeoutMillis) throws ChannelException {
        requireOpen();
        requireTimeout(timeoutMillis);
        if (expectedDirection == null) {
            close();
            throw failure(Failure.INVALID_CONFIGURATION);
        }
        long deadline = deadline(timeoutMillis);
        byte[] header = null;
        byte[] body = null;
        try {
            header = readExactly(
                    AuthenticatedControlRecordV1.AUTHENTICATED_HEADER_BYTES,
                    deadline);
            ByteBuffer input = ByteBuffer.wrap(header);
            if (input.getInt() != 0x5646_4331
                    || Byte.toUnsignedInt(input.get())
                            != AuthenticatedControlRecordV1.PROTOCOL_VERSION
                    || Byte.toUnsignedInt(input.get())
                            != AuthenticatedControlRecordV1
                                    .AUTHENTICATED_HEADER_BYTES) {
                throw failure(Failure.INVALID_RECORD);
            }
            int expectedDirectionCode = expectedDirection
                    == AuthenticatedControlRecordV1.Direction.HOST_TO_ANDROID
                    ? 1 : 2;
            int directionCode = Byte.toUnsignedInt(input.get());
            int messageTypeCode = Byte.toUnsignedInt(input.get());
            if (directionCode != expectedDirectionCode
                    || !AuthenticatedControlRecordV1
                            .isKnownMessageTypeWireCode(messageTypeCode)) {
                throw failure(Failure.INVALID_RECORD);
            }
            input.position(36);
            int payloadBytes = input.getInt();
            if (payloadBytes < 0
                    || payloadBytes
                            > AuthenticatedControlRecordV1.MAX_PAYLOAD_BYTES) {
                throw failure(Failure.INVALID_RECORD);
            }
            body = readExactly(
                    payloadBytes + AuthenticatedControlRecordV1.GCM_TAG_BYTES,
                    deadline);
            byte[] result = new byte[header.length + body.length];
            System.arraycopy(header, 0, result, 0, header.length);
            System.arraycopy(body, 0, result, header.length, body.length);
            return result;
        } catch (ChannelException rejected) {
            close();
            throw rejected;
        } catch (IOException | RuntimeException rejected) {
            close();
            throw failure(Failure.IO_FAILED);
        } finally {
            if (header != null) Arrays.fill(header, (byte) 0);
            if (body != null) Arrays.fill(body, (byte) 0);
        }
    }

    /** Writes one already-sealed VFC1 envelope after strict local framing checks. */
    public synchronized void writeAuthenticatedRecord(
            byte[] encodedRecord,
            AuthenticatedControlRecordV1.Direction expectedDirection,
            int timeoutMillis) throws ChannelException {
        requireOpen();
        requireTimeout(timeoutMillis);
        if (encodedRecord == null || expectedDirection == null
                || encodedRecord.length
                        < AuthenticatedControlRecordV1
                                .AUTHENTICATED_HEADER_BYTES
                                + AuthenticatedControlRecordV1.GCM_TAG_BYTES) {
            close();
            throw failure(Failure.INVALID_CONFIGURATION);
        }
        ByteBuffer input = ByteBuffer.wrap(encodedRecord);
        int expectedDirectionCode = expectedDirection
                == AuthenticatedControlRecordV1.Direction.HOST_TO_ANDROID
                ? 1 : 2;
        if (input.getInt() != 0x5646_4331
                || Byte.toUnsignedInt(input.get())
                        != AuthenticatedControlRecordV1.PROTOCOL_VERSION
                || Byte.toUnsignedInt(input.get())
                        != AuthenticatedControlRecordV1
                                .AUTHENTICATED_HEADER_BYTES
                || Byte.toUnsignedInt(input.get()) != expectedDirectionCode) {
            close();
            throw failure(Failure.INVALID_RECORD);
        }
        int messageTypeCode = Byte.toUnsignedInt(input.get());
        input.position(36);
        int payloadBytes = input.getInt();
        if (!AuthenticatedControlRecordV1
                        .isKnownMessageTypeWireCode(messageTypeCode)
                || payloadBytes < 0
                || payloadBytes > AuthenticatedControlRecordV1.MAX_PAYLOAD_BYTES
                || encodedRecord.length
                        != AuthenticatedControlRecordV1
                                .AUTHENTICATED_HEADER_BYTES
                                + payloadBytes
                                + AuthenticatedControlRecordV1.GCM_TAG_BYTES) {
            close();
            throw failure(Failure.INVALID_RECORD);
        }
        try {
            long deadline = deadline(timeoutMillis);
            if (socket != null) {
                writeSocketWithDeadline(encodedRecord, deadline);
            } else {
                ByteBuffer output = ByteBuffer.wrap(encodedRecord);
                while (output.hasRemaining()) {
                    checkCancelled();
                    waitReady(selector, SelectionKey.OP_WRITE, deadline);
                    int written = channel.write(output);
                    if (written < 0) throw failure(Failure.PEER_CLOSED);
                }
            }
        } catch (ChannelException rejected) {
            close();
            throw rejected;
        } catch (IOException | RuntimeException rejected) {
            close();
            throw failure(Failure.IO_FAILED);
        }
    }

    public synchronized String localIpv4() throws ChannelException {
        requireOpen();
        return endpoint(transportSocket().getLocalSocketAddress()).ipv4;
    }

    public synchronized String peerIpv4() throws ChannelException {
        requireOpen();
        return endpoint(transportSocket().getRemoteSocketAddress()).ipv4;
    }

    public synchronized int localPort() throws ChannelException {
        requireOpen();
        return endpoint(transportSocket().getLocalSocketAddress()).port;
    }

    public synchronized int peerPort() throws ChannelException {
        requireOpen();
        return endpoint(transportSocket().getRemoteSocketAddress()).port;
    }

    public synchronized boolean isOpen() {
        if (closed) return false;
        return socket != null
                ? socket.isConnected() && !socket.isClosed()
                : channel.isOpen() && channel.isConnected();
    }

    @Override
    public synchronized void close() {
        if (closed) return;
        closed = true;
        clearPending();
        if (selector != null) {
            try {
                selector.close();
            } catch (IOException ignored) {
                // Best-effort cleanup after the capability is already closed.
            }
        }
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException ignored) {
                // Best-effort cleanup after the capability is already closed.
            }
        }
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // Best-effort cleanup after the capability is already closed.
            }
        }
    }

    private static AuthenticatedControlTcpChannelV1 adoptConnectedSocket(
            Socket socket,
            String expectedLocalIpv4,
            int expectedLocalPort,
            String expectedPeerIpv4,
            int expectedPeerPort) throws ChannelException, IOException {
        Endpoint local = endpoint(socket.getLocalSocketAddress());
        Endpoint peer = endpoint(socket.getRemoteSocketAddress());
        requireExpectedEndpoints(
                local,
                peer,
                expectedLocalIpv4,
                expectedLocalPort,
                expectedPeerIpv4,
                expectedPeerPort);
        socket.setSoTimeout(0);
        return new AuthenticatedControlTcpChannelV1(
                socket,
                socket.getInputStream(),
                socket.getOutputStream());
    }

    private static AuthenticatedControlTcpChannelV1 adoptConnected(
            SocketChannel channel,
            Selector selector,
            String expectedLocalIpv4,
            int expectedLocalPort,
            String expectedPeerIpv4,
            int expectedPeerPort) throws ChannelException {
        Endpoint local = endpoint(channel.socket().getLocalSocketAddress());
        Endpoint peer = endpoint(channel.socket().getRemoteSocketAddress());
        requireExpectedEndpoints(
                local,
                peer,
                expectedLocalIpv4,
                expectedLocalPort,
                expectedPeerIpv4,
                expectedPeerPort);
        return new AuthenticatedControlTcpChannelV1(channel, selector);
    }

    private static void requireExpectedEndpoints(
            Endpoint local,
            Endpoint peer,
            String expectedLocalIpv4,
            int expectedLocalPort,
            String expectedPeerIpv4,
            int expectedPeerPort) throws ChannelException {
        String checkedLocal = numericIpv4(expectedLocalIpv4).getHostAddress();
        String checkedPeer = numericIpv4(expectedPeerIpv4).getHostAddress();
        if (!checkedLocal.equals(local.ipv4)
                || !checkedPeer.equals(peer.ipv4)
                || (expectedLocalPort > 0 && expectedLocalPort != local.port)
                || (expectedPeerPort > 0 && expectedPeerPort != peer.port)) {
            throw failure(Failure.PEER_MISMATCH);
        }
    }

    private void writeSocketWithDeadline(
            byte[] encodedRecord,
            long deadlineNanos) throws ChannelException, IOException {
        AtomicReference<IOException> writeFailure = new AtomicReference<>();
        Thread writer = new Thread(() -> {
            try {
                socketOutput.write(encodedRecord);
                socketOutput.flush();
            } catch (IOException rejected) {
                writeFailure.set(rejected);
            }
        }, "vf-vfb1-socket-writer");
        writer.setDaemon(true);
        writer.start();
        while (writer.isAlive()) {
            checkCancelled();
            int remainingMillis = remainingTimeoutMillis(deadlineNanos);
            try {
                writer.join(Math.min(remainingMillis, 100));
            } catch (InterruptedException cancelled) {
                Thread.currentThread().interrupt();
                throw failure(Failure.CANCELLED);
            }
        }
        IOException rejected = writeFailure.get();
        if (rejected != null) throw rejected;
    }

    private byte[] readExactly(int byteCount, long deadlineNanos)
            throws ChannelException, IOException {
        if (byteCount < 0) throw failure(Failure.INVALID_CONFIGURATION);
        byte[] result = new byte[byteCount];
        int written = 0;
        ByteBuffer input = ByteBuffer.allocate(READ_BUFFER_BYTES);
        try {
            while (written < byteCount) {
                checkCancelled();
                if (pendingInput != null && pendingOffset < pendingInput.length) {
                    int copied = Math.min(
                            byteCount - written,
                            pendingInput.length - pendingOffset);
                    System.arraycopy(
                            pendingInput, pendingOffset, result, written, copied);
                    pendingOffset += copied;
                    written += copied;
                    if (pendingOffset == pendingInput.length) clearPending();
                    continue;
                }
                input.clear();
                int received;
                if (socket != null) {
                    socket.setSoTimeout(remainingTimeoutMillis(deadlineNanos));
                    try {
                        received = socketInput.read(input.array());
                    } catch (SocketTimeoutException timedOut) {
                        throw failure(Failure.TIMED_OUT);
                    }
                } else {
                    waitReady(selector, SelectionKey.OP_READ, deadlineNanos);
                    received = channel.read(input);
                }
                if (received < 0) throw failure(Failure.PEER_CLOSED);
                if (received == 0) continue;
                if (socket != null) input.position(received);
                input.flip();
                pendingInput = new byte[received];
                input.get(pendingInput);
                pendingOffset = 0;
            }
            return result;
        } catch (IOException | RuntimeException rejected) {
            Arrays.fill(result, (byte) 0);
            throw rejected;
        } finally {
            Arrays.fill(input.array(), (byte) 0);
        }
    }

    private Socket transportSocket() throws ChannelException {
        if (socket != null) return socket;
        if (channel != null) return channel.socket();
        throw failure(Failure.CLOSED);
    }

    private static void waitReady(
            Selector selector,
            int interest,
            long deadlineNanos) throws ChannelException, IOException {
        SelectionKey key = null;
        Iterator<SelectionKey> keys = selector.keys().iterator();
        if (keys.hasNext()) key = keys.next();
        if (key == null || !key.isValid()) {
            throw failure(Failure.CLOSED);
        }
        key.interestOps(interest);
        while (true) {
            checkCancelled();
            long remaining = deadlineNanos - System.nanoTime();
            if (remaining <= 0L) throw failure(Failure.TIMED_OUT);
            long millis = Math.max(
                    1L,
                    TimeUnit.NANOSECONDS.toMillis(remaining));
            int ready = selector.select(millis);
            if (ready == 0) continue;
            Set<SelectionKey> selected = selector.selectedKeys();
            boolean matched = false;
            for (SelectionKey candidate : selected) {
                if (candidate.isValid()
                        && (candidate.readyOps() & interest) != 0) {
                    matched = true;
                }
            }
            selected.clear();
            if (matched) return;
        }
    }

    private static Endpoint endpoint(SocketAddress address)
            throws ChannelException {
        if (!(address instanceof InetSocketAddress)) {
            throw failure(Failure.PEER_MISMATCH);
        }
        InetSocketAddress inet = (InetSocketAddress) address;
        InetAddress resolved = inet.getAddress();
        if (!(resolved instanceof Inet4Address)
                || inet.getPort() <= 0
                || inet.getPort() > 65_535) {
            throw failure(Failure.PEER_MISMATCH);
        }
        return new Endpoint(resolved.getHostAddress(), inet.getPort());
    }

    private static Inet4Address numericIpv4(String value)
            throws ChannelException {
        if (value == null
                || value.isEmpty()
                || !value.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) {
            throw failure(Failure.INVALID_CONFIGURATION);
        }
        try {
            InetAddress parsed = InetAddress.getByName(value);
            if (!(parsed instanceof Inet4Address)
                    || !parsed.getHostAddress().equals(value)) {
                throw failure(Failure.INVALID_CONFIGURATION);
            }
            return (Inet4Address) parsed;
        } catch (ChannelException rejected) {
            throw rejected;
        } catch (IOException | RuntimeException rejected) {
            throw failure(Failure.INVALID_CONFIGURATION);
        }
    }

    private static void requireTimeout(int timeoutMillis)
            throws ChannelException {
        if (timeoutMillis <= 0 || timeoutMillis > MAXIMUM_TIMEOUT_MILLIS) {
            throw failure(Failure.INVALID_CONFIGURATION);
        }
    }

    private static long deadline(int timeoutMillis) {
        return System.nanoTime()
                + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
    }

    private static int remainingTimeoutMillis(long deadlineNanos)
            throws ChannelException {
        long remaining = deadlineNanos - System.nanoTime();
        if (remaining <= 0L) throw failure(Failure.TIMED_OUT);
        long millis = TimeUnit.NANOSECONDS.toMillis(remaining);
        if (TimeUnit.MILLISECONDS.toNanos(millis) < remaining) millis++;
        return (int) Math.max(1L, Math.min(MAXIMUM_TIMEOUT_MILLIS, millis));
    }

    private static void checkCancelled() throws ChannelException {
        if (Thread.currentThread().isInterrupted()) {
            throw failure(Failure.CANCELLED);
        }
    }

    private synchronized void requireOpen() throws ChannelException {
        if (!isOpen()) {
            throw failure(Failure.CLOSED);
        }
    }

    private void clearPending() {
        if (pendingInput != null) Arrays.fill(pendingInput, (byte) 0);
        pendingInput = null;
        pendingOffset = 0;
    }

    private static ChannelException failure(Failure failure) {
        return new ChannelException(failure);
    }

    private static void closeQuietly(
            SocketChannel channel,
            Selector selector) {
        if (selector != null) {
            try {
                selector.close();
            } catch (IOException ignored) {
                // The candidate channel is already rejected.
            }
        }
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException ignored) {
                // The candidate channel is already rejected.
            }
        }
    }

    private static void closeQuietly(Socket socket) {
        if (socket == null) return;
        try {
            socket.close();
        } catch (IOException ignored) {
            // The candidate socket is already rejected.
        }
    }

    private static final class Endpoint {
        private final String ipv4;
        private final int port;

        private Endpoint(String ipv4, int port) {
            this.ipv4 = ipv4;
            this.port = port;
        }
    }
}
