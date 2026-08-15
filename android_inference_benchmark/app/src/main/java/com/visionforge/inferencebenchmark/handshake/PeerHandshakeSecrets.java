package com.visionforge.inferencebenchmark.handshake;

import java.util.Arrays;

/**
 * Confirmed, role-separated traffic material released only after both Finished proofs succeed.
 *
 * <p>Every accessor returns a defensive copy owned by the caller. Callers must clear those copies
 * after installing them into their final key owners. JVM/JCA provider internals can retain copies,
 * so this class cannot promise physical erasure from a fully controlled endpoint process.
 */
public final class PeerHandshakeSecrets implements AutoCloseable {
    private final byte[] controlHostToAndroid;
    private final byte[] controlAndroidToHost;
    private final byte[] presenceHostToAndroid;
    private final byte[] videoHostToAndroid;
    private final byte[] idrAndroidToHost;
    private final byte[] mouseHostToAndroid;
    private final byte[] channelBindingSha256;
    private boolean closed;

    PeerHandshakeSecrets(
            byte[] controlHostToAndroid,
            byte[] controlAndroidToHost,
            byte[] presenceHostToAndroid,
            byte[] videoHostToAndroid,
            byte[] idrAndroidToHost,
            byte[] mouseHostToAndroid,
            byte[] channelBindingSha256) {
        this.controlHostToAndroid = requireLength(
                controlHostToAndroid, AuthenticatedPeerHandshakeV1.CONTROL_MATERIAL_BYTES);
        this.controlAndroidToHost = requireLength(
                controlAndroidToHost, AuthenticatedPeerHandshakeV1.CONTROL_MATERIAL_BYTES);
        this.presenceHostToAndroid = requireLength(
                presenceHostToAndroid, AuthenticatedPeerHandshakeV1.DATA_PLANE_MATERIAL_BYTES);
        this.videoHostToAndroid = requireLength(
                videoHostToAndroid, AuthenticatedPeerHandshakeV1.DATA_PLANE_MATERIAL_BYTES);
        this.idrAndroidToHost = requireLength(
                idrAndroidToHost, AuthenticatedPeerHandshakeV1.DATA_PLANE_MATERIAL_BYTES);
        this.mouseHostToAndroid = requireLength(
                mouseHostToAndroid, AuthenticatedPeerHandshakeV1.DATA_PLANE_MATERIAL_BYTES);
        this.channelBindingSha256 = requireLength(
                channelBindingSha256, AuthenticatedPeerHandshakeV1.CHANNEL_BINDING_BYTES);
    }

    /** Returns AES-256 key[32] followed by nonce prefix[4]. */
    public synchronized byte[] controlHostToAndroidMaterial()
            throws AuthenticatedPeerHandshakeV1Exception {
        return copyOpen(controlHostToAndroid);
    }

    /** Returns AES-256 key[32] followed by nonce prefix[4]. */
    public synchronized byte[] controlAndroidToHostMaterial()
            throws AuthenticatedPeerHandshakeV1Exception {
        return copyOpen(controlAndroidToHost);
    }

    /** Returns AES-256 key[32] followed by nonce prefix[4]. */
    public synchronized byte[] presenceHostToAndroidMaterial()
            throws AuthenticatedPeerHandshakeV1Exception {
        return copyOpen(presenceHostToAndroid);
    }

    /** Returns AES-256 key[32] followed by nonce prefix[4]. */
    public synchronized byte[] videoHostToAndroidMaterial()
            throws AuthenticatedPeerHandshakeV1Exception {
        return copyOpen(videoHostToAndroid);
    }

    /** Returns AES-256 key[32] followed by nonce prefix[4]. */
    public synchronized byte[] idrAndroidToHostMaterial()
            throws AuthenticatedPeerHandshakeV1Exception {
        return copyOpen(idrAndroidToHost);
    }

    /** Returns AES-256 key[32] followed by nonce prefix[4]. */
    public synchronized byte[] mouseHostToAndroidMaterial()
            throws AuthenticatedPeerHandshakeV1Exception {
        return copyOpen(mouseHostToAndroid);
    }

    public synchronized byte[] channelBindingSha256()
            throws AuthenticatedPeerHandshakeV1Exception {
        return copyOpen(channelBindingSha256);
    }

    public synchronized String channelBindingLowercaseHex()
            throws AuthenticatedPeerHandshakeV1Exception {
        requireOpen();
        StringBuilder encoded =
                new StringBuilder(AuthenticatedPeerHandshakeV1.CHANNEL_BINDING_BYTES * 2);
        for (byte current : channelBindingSha256) {
            encoded.append(Character.forDigit((current >>> 4) & 0x0f, 16));
            encoded.append(Character.forDigit(current & 0x0f, 16));
        }
        return encoded.toString();
    }

    @Override
    public synchronized void close() {
        if (closed) return;
        closed = true;
        AuthenticatedPeerHandshakeV1Internals.clear(controlHostToAndroid);
        AuthenticatedPeerHandshakeV1Internals.clear(controlAndroidToHost);
        AuthenticatedPeerHandshakeV1Internals.clear(presenceHostToAndroid);
        AuthenticatedPeerHandshakeV1Internals.clear(videoHostToAndroid);
        AuthenticatedPeerHandshakeV1Internals.clear(idrAndroidToHost);
        AuthenticatedPeerHandshakeV1Internals.clear(mouseHostToAndroid);
        AuthenticatedPeerHandshakeV1Internals.clear(channelBindingSha256);
    }

    private byte[] copyOpen(byte[] value) throws AuthenticatedPeerHandshakeV1Exception {
        requireOpen();
        return value.clone();
    }

    private void requireOpen() throws AuthenticatedPeerHandshakeV1Exception {
        if (closed) throw AuthenticatedPeerHandshakeV1Internals.closedFailure();
    }

    private static byte[] requireLength(byte[] value, int expectedLength) {
        if (value == null || value.length != expectedLength) {
            throw new IllegalArgumentException("confirmed handshake material has invalid length");
        }
        return value.clone();
    }
}
