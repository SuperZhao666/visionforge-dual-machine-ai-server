package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2;
import com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Exception;
import com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Receiver;
import com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Sender;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

/**
 * VFA2-only network boundary for mobile video, presence and IDR recovery.
 *
 * <p>Only authenticated VFA2 packets cross the selected CAT6/WLAN interface.
 * Decrypted VFP2 fragments are relayed over Android loopback to the existing
 * native decoder receiver.  Native {@code IDR1} recovery signals travel in the
 * opposite loopback direction and are sealed before any network send.</p>
 */
final class AuthenticatedMobileDataPlaneV2 implements AutoCloseable {
    static final int NETWORK_VIDEO_PORT = 5000;
    static final int HOST_IDR_PORT = 5001;
    static final int LOOPBACK_IDR_PORT = 5001;
    static final int NATIVE_VIDEO_PORT = 15000;
    static final int LOOPBACK_VIDEO_SOURCE_PORT = 15002;
    static final int AUTHENTICATED_PRESENCE_PORT = 5007;
    static final String LOOPBACK_IPV4 = "127.0.0.1";

    private static final int SOCKET_TIMEOUT_MILLIS = 250;
    private static final byte[] IDR_REQUEST = {'I', 'D', 'R', '1'};

    private final AtomicLong generation = new AtomicLong();
    private final AtomicLong videoAccepted = new AtomicLong();
    private final AtomicLong videoRejected = new AtomicLong();
    private final AtomicLong presenceAccepted = new AtomicLong();
    private final AtomicLong presenceRejected = new AtomicLong();
    private final AtomicLong idrSent = new AtomicLong();
    private final AtomicLong idrRejected = new AtomicLong();

    private AuthenticatedDataPlaneV2Receiver videoReceiver;
    private AuthenticatedDataPlaneV2Receiver presenceReceiver;
    private AuthenticatedDataPlaneV2Sender idrSender;
    private MobileTransportEndpoint sessionEndpoint;
    private long connectionId;
    private DatagramSocket networkVideoSocket;
    private DatagramSocket networkPresenceSocket;
    private DatagramSocket loopbackVideoSocket;
    private DatagramSocket loopbackIdrSocket;
    private DatagramSocket networkIdrSocket;
    private Thread videoThread;
    private Thread presenceThread;
    private Thread idrThread;

    synchronized boolean installConfirmedSession(
            ConfirmedMobileDataPlaneMaterialV2 material) {
        if (material == null) {
            return false;
        }
        byte[] hostAddress = null;
        byte[] androidAddress = null;
        byte[] videoMaterial = null;
        byte[] presenceMaterial = null;
        byte[] idrMaterial = null;
        AuthenticatedDataPlaneV2Receiver nextVideo = null;
        AuthenticatedDataPlaneV2Receiver nextPresence = null;
        AuthenticatedDataPlaneV2Sender nextIdr = null;
        try {
            MobileTransportEndpoint endpoint = material.endpoint();
            hostAddress = material.hostIpv4();
            androidAddress = material.androidIpv4();
            if (!endpoint.hostIpv4.equals(
                    InetAddress.getByAddress(hostAddress).getHostAddress())
                    || !endpoint.localIpv4.equals(
                    InetAddress.getByAddress(androidAddress).getHostAddress())) {
                return false;
            }
            long nextConnectionId = material.connectionId();
            if (nextConnectionId == connectionId && videoReceiver != null
                    && presenceReceiver != null && idrSender != null
                    && endpoint.hasSameDataPlaneRoute(sessionEndpoint)) {
                return true;
            }
            videoMaterial = material.videoHostToAndroidMaterial();
            presenceMaterial = material.presenceHostToAndroidMaterial();
            idrMaterial = material.idrAndroidToHostMaterial();
            nextVideo = newReceiver(
                    videoMaterial, nextConnectionId,
                    AuthenticatedDataPlaneV2.MessageType.VIDEO);
            nextPresence = newReceiver(
                    presenceMaterial, nextConnectionId,
                    AuthenticatedDataPlaneV2.MessageType.PRESENCE_PROBE);
            nextIdr = newSender(
                    idrMaterial, nextConnectionId,
                    AuthenticatedDataPlaneV2.MessageType.IDR_REQUEST);
            stopTransportLocked();
            clearCryptoLocked();
            videoReceiver = nextVideo;
            presenceReceiver = nextPresence;
            idrSender = nextIdr;
            nextVideo = null;
            nextPresence = null;
            nextIdr = null;
            connectionId = nextConnectionId;
            sessionEndpoint = endpoint;
            resetMetrics();
            return true;
        } catch (IOException | GeneralSecurityException | RuntimeException failure) {
            return false;
        } finally {
            clear(hostAddress);
            clear(androidAddress);
            clear(videoMaterial);
            clear(presenceMaterial);
            clear(idrMaterial);
            close(nextVideo);
            close(nextPresence);
            close(nextIdr);
        }
    }

    synchronized boolean startTransport(
            String localIpv4,
            String expectedHostIpv4,
            long networkHandle) {
        if (videoReceiver == null || presenceReceiver == null || idrSender == null
                || sessionEndpoint == null || connectionId == 0L
                || networkHandle != sessionEndpoint.networkHandle
                || !sessionEndpoint.localIpv4.equals(localIpv4)
                || !sessionEndpoint.hostIpv4.equals(expectedHostIpv4)) {
            return false;
        }
        if (videoThread != null && videoThread.isAlive()
                && presenceThread != null && presenceThread.isAlive()
                && idrThread != null && idrThread.isAlive()) {
            return true;
        }
        stopTransportLocked();
        try {
            networkVideoSocket = boundNetworkSocket(
                    sessionEndpoint, NETWORK_VIDEO_PORT);
            networkPresenceSocket = boundNetworkSocket(
                    sessionEndpoint, AUTHENTICATED_PRESENCE_PORT);

            loopbackVideoSocket = new DatagramSocket(null);
            loopbackVideoSocket.setReuseAddress(false);
            loopbackVideoSocket.bind(new InetSocketAddress(
                    InetAddress.getByName(LOOPBACK_IPV4),
                    LOOPBACK_VIDEO_SOURCE_PORT));
            loopbackVideoSocket.connect(
                    InetAddress.getByName(LOOPBACK_IPV4), NATIVE_VIDEO_PORT);

            loopbackIdrSocket = new DatagramSocket(null);
            loopbackIdrSocket.setReuseAddress(false);
            loopbackIdrSocket.bind(new InetSocketAddress(
                    InetAddress.getByName(LOOPBACK_IPV4), LOOPBACK_IDR_PORT));
            loopbackIdrSocket.setSoTimeout(SOCKET_TIMEOUT_MILLIS);

            networkIdrSocket = new DatagramSocket(null);
            networkIdrSocket.setReuseAddress(false);
            SelectedNetworkDatagramSocket.bind(
                    sessionEndpoint, networkIdrSocket, 0);
            networkIdrSocket.connect(
                    InetAddress.getByName(sessionEndpoint.hostIpv4), HOST_IDR_PORT);
        } catch (IOException | RuntimeException failure) {
            stopTransportLocked();
            return false;
        }
        long workerGeneration = generation.incrementAndGet();
        videoThread = worker(
                "visionforge-vfa2-video",
                () -> receiveVideo(workerGeneration));
        presenceThread = worker(
                "visionforge-vfa2-presence",
                () -> receivePresence(workerGeneration));
        idrThread = worker(
                "visionforge-vfa2-idr",
                () -> relayIdr(workerGeneration));
        videoThread.start();
        presenceThread.start();
        idrThread.start();
        return true;
    }

    synchronized void stopTransport() {
        stopTransportLocked();
    }

    synchronized String report() {
        return "vfa2_connection_id=" + Long.toUnsignedString(connectionId)
                + " vfa2_session_ready=" + (videoReceiver != null
                && presenceReceiver != null && idrSender != null)
                + " vfa2_transport_running=" + (videoThread != null
                && videoThread.isAlive())
                + " vfa2_video_accepted=" + videoAccepted.get()
                + " vfa2_video_rejected=" + videoRejected.get()
                + " vfa2_presence_accepted=" + presenceAccepted.get()
                + " vfa2_presence_rejected=" + presenceRejected.get()
                + " vfa2_idr_sent=" + idrSent.get()
                + " vfa2_idr_rejected=" + idrRejected.get();
    }

    @Override
    public synchronized void close() {
        stopTransportLocked();
        clearCryptoLocked();
        sessionEndpoint = null;
        connectionId = 0L;
    }

    private void receiveVideo(long workerGeneration) {
        byte[] envelope = new byte[AuthenticatedDataPlaneV2.MAX_DATAGRAM_BYTES];
        DatagramPacket packet = new DatagramPacket(envelope, envelope.length);
        while (generation.get() == workerGeneration) {
            DatagramSocket input = networkVideoSocket;
            DatagramSocket output = loopbackVideoSocket;
            if (input == null || output == null || input.isClosed() || output.isClosed()) {
                return;
            }
            try {
                packet.setLength(envelope.length);
                input.receive(packet);
                if (!isExpectedHost(packet)) {
                    videoRejected.incrementAndGet();
                    continue;
                }
                byte[] plaintext = openPacket(videoReceiver, envelope, packet.getLength());
                if (plaintext == null || plaintext.length == 0
                        || plaintext.length
                        > AuthenticatedDataPlaneV2.DEFAULT_MAX_PAYLOAD_BYTES) {
                    clear(plaintext);
                    videoRejected.incrementAndGet();
                    continue;
                }
                try {
                    output.send(new DatagramPacket(plaintext, plaintext.length));
                    videoAccepted.incrementAndGet();
                } finally {
                    clear(plaintext);
                }
            } catch (SocketTimeoutException timeout) {
                // Bounded wake-up lets stop/route replacement terminate promptly.
            } catch (IOException | RuntimeException failure) {
                if (generation.get() == workerGeneration) {
                    videoRejected.incrementAndGet();
                }
            }
        }
    }

    private void receivePresence(long workerGeneration) {
        byte[] envelope = new byte[AuthenticatedDataPlaneV2.MAX_DATAGRAM_BYTES];
        DatagramPacket packet = new DatagramPacket(envelope, envelope.length);
        while (generation.get() == workerGeneration) {
            DatagramSocket input = networkPresenceSocket;
            if (input == null || input.isClosed()) return;
            try {
                packet.setLength(envelope.length);
                input.receive(packet);
                if (!isExpectedHost(packet)) {
                    presenceRejected.incrementAndGet();
                    continue;
                }
                byte[] plaintext = openPacket(
                        presenceReceiver, envelope, packet.getLength());
                if (plaintext == null || plaintext.length != Long.BYTES) {
                    clear(plaintext);
                    presenceRejected.incrementAndGet();
                    continue;
                }
                clear(plaintext);
                presenceAccepted.incrementAndGet();
            } catch (SocketTimeoutException timeout) {
                // See video loop.
            } catch (IOException | RuntimeException failure) {
                if (generation.get() == workerGeneration) {
                    presenceRejected.incrementAndGet();
                }
            }
        }
    }

    private void relayIdr(long workerGeneration) {
        byte[] request = new byte[16];
        DatagramPacket packet = new DatagramPacket(request, request.length);
        while (generation.get() == workerGeneration) {
            DatagramSocket input = loopbackIdrSocket;
            DatagramSocket output = networkIdrSocket;
            if (input == null || output == null || input.isClosed() || output.isClosed()) {
                return;
            }
            try {
                packet.setLength(request.length);
                input.receive(packet);
                if (packet.getAddress() == null
                        || !LOOPBACK_IPV4.equals(packet.getAddress().getHostAddress())
                        || packet.getLength() != IDR_REQUEST.length
                        || !matches(request, IDR_REQUEST)) {
                    idrRejected.incrementAndGet();
                    continue;
                }
                byte[] envelope = idrSender.seal(IDR_REQUEST);
                try {
                    output.send(new DatagramPacket(envelope, envelope.length));
                    idrSent.incrementAndGet();
                } finally {
                    clear(envelope);
                }
            } catch (SocketTimeoutException timeout) {
                // See video loop.
            } catch (AuthenticatedDataPlaneV2Exception cryptoFailure) {
                idrRejected.incrementAndGet();
                return;
            } catch (IOException | RuntimeException failure) {
                if (generation.get() == workerGeneration) {
                    idrRejected.incrementAndGet();
                }
            }
        }
    }

    private boolean isExpectedHost(DatagramPacket packet) {
        return packet.getAddress() != null && sessionEndpoint != null
                && sessionEndpoint.hostIpv4.equals(
                packet.getAddress().getHostAddress());
    }

    private static DatagramSocket boundNetworkSocket(
            MobileTransportEndpoint endpoint,
            int port) throws IOException {
        DatagramSocket socket = new DatagramSocket(null);
        boolean success = false;
        try {
            socket.setReuseAddress(false);
            SelectedNetworkDatagramSocket.bind(endpoint, socket, port);
            socket.setSoTimeout(SOCKET_TIMEOUT_MILLIS);
            success = true;
            return socket;
        } finally {
            if (!success) socket.close();
        }
    }

    private static AuthenticatedDataPlaneV2Receiver newReceiver(
            byte[] material,
            long connectionId,
            AuthenticatedDataPlaneV2.MessageType type)
            throws AuthenticatedDataPlaneV2Exception {
        byte[] key = Arrays.copyOfRange(
                material, 0, AuthenticatedDataPlaneV2.AES_256_KEY_BYTES);
        byte[] prefix = Arrays.copyOfRange(
                material,
                AuthenticatedDataPlaneV2.AES_256_KEY_BYTES,
                AuthenticatedDataPlaneV2.AES_256_KEY_BYTES
                        + AuthenticatedDataPlaneV2.NONCE_PREFIX_BYTES);
        try {
            return AuthenticatedDataPlaneV2.newReceiver(
                    key,
                    prefix,
                    AuthenticatedDataPlaneV2.createDomain(
                            connectionId,
                            1,
                            AuthenticatedDataPlaneV2.Direction.HOST_TO_ANDROID,
                            type));
        } finally {
            clear(key);
            clear(prefix);
        }
    }

    private static AuthenticatedDataPlaneV2Sender newSender(
            byte[] material,
            long connectionId,
            AuthenticatedDataPlaneV2.MessageType type)
            throws AuthenticatedDataPlaneV2Exception {
        byte[] key = Arrays.copyOfRange(
                material, 0, AuthenticatedDataPlaneV2.AES_256_KEY_BYTES);
        byte[] prefix = Arrays.copyOfRange(
                material,
                AuthenticatedDataPlaneV2.AES_256_KEY_BYTES,
                AuthenticatedDataPlaneV2.AES_256_KEY_BYTES
                        + AuthenticatedDataPlaneV2.NONCE_PREFIX_BYTES);
        try {
            return AuthenticatedDataPlaneV2.newSender(
                    key,
                    prefix,
                    AuthenticatedDataPlaneV2.createDomain(
                            connectionId,
                            1,
                            AuthenticatedDataPlaneV2.Direction.ANDROID_TO_HOST,
                            type));
        } finally {
            clear(key);
            clear(prefix);
        }
    }

    private static byte[] openPacket(
            AuthenticatedDataPlaneV2Receiver receiver,
            byte[] buffer,
            int length) {
        if (receiver == null || length <= 0 || length > buffer.length) return null;
        byte[] envelope = Arrays.copyOf(buffer, length);
        try {
            return receiver.open(envelope);
        } catch (AuthenticatedDataPlaneV2Exception rejected) {
            return null;
        } finally {
            clear(envelope);
        }
    }

    private void stopTransportLocked() {
        generation.incrementAndGet();
        close(networkVideoSocket);
        close(networkPresenceSocket);
        close(loopbackVideoSocket);
        close(loopbackIdrSocket);
        close(networkIdrSocket);
        networkVideoSocket = null;
        networkPresenceSocket = null;
        loopbackVideoSocket = null;
        loopbackIdrSocket = null;
        networkIdrSocket = null;
        interrupt(videoThread);
        interrupt(presenceThread);
        interrupt(idrThread);
        videoThread = null;
        presenceThread = null;
        idrThread = null;
    }

    private void clearCryptoLocked() {
        close(videoReceiver);
        close(presenceReceiver);
        close(idrSender);
        videoReceiver = null;
        presenceReceiver = null;
        idrSender = null;
    }

    private void resetMetrics() {
        videoAccepted.set(0L);
        videoRejected.set(0L);
        presenceAccepted.set(0L);
        presenceRejected.set(0L);
        idrSent.set(0L);
        idrRejected.set(0L);
    }

    private static Thread worker(String name, Runnable action) {
        Thread result = new Thread(action, name);
        result.setDaemon(false);
        return result;
    }

    private static void interrupt(Thread thread) {
        if (thread != null && thread != Thread.currentThread()) thread.interrupt();
    }

    private static boolean matches(byte[] left, byte[] right) {
        if (left == null || right == null || left.length < right.length) return false;
        int difference = 0;
        for (int index = 0; index < right.length; index++) {
            difference |= left[index] ^ right[index];
        }
        return difference == 0;
    }

    private static void close(AutoCloseable value) {
        if (value == null) return;
        try {
            value.close();
        } catch (Exception ignored) {
            // Cleanup remains best-effort and fail-closed.
        }
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }
}
