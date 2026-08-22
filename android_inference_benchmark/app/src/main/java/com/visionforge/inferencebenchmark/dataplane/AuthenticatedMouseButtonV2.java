package com.visionforge.inferencebenchmark.dataplane;

import java.util.Arrays;

/**
 * Mouse-button specialization of the authenticated {@code VFA2} envelope.
 *
 * <p>The 36-byte input must be the confirmed peer-handshake v1
 * {@code mouse_host_to_android} output: AES-256 key[32] followed by nonce
 * prefix[4]. This class defines the cross-language channel contract; callers
 * still have to install it from a confirmed live peer session and own its
 * transport lifecycle.</p>
 */
public final class AuthenticatedMouseButtonV2 {
    public static final int KEY_EPOCH_V1 = 1;
    public static final int PAYLOAD_BYTES = 1;
    public static final int TRAFFIC_MATERIAL_BYTES =
            AuthenticatedDataPlaneV2.AES_256_KEY_BYTES
                    + AuthenticatedDataPlaneV2.NONCE_PREFIX_BYTES;
    public static final int VALID_BUTTON_MASK = 0x1f;

    private AuthenticatedMouseButtonV2() {}

    public static AuthenticatedDataPlaneV2.Domain createHostToAndroidDomain(
            long connectionId) {
        return AuthenticatedDataPlaneV2.createDomain(
                connectionId,
                KEY_EPOCH_V1,
                AuthenticatedDataPlaneV2.Direction.HOST_TO_ANDROID,
                AuthenticatedDataPlaneV2.MessageType.MOUSE_BUTTON);
    }

    /**
     * Installs a defensive copy of confirmed handshake material into the
     * Android receive-side key owner. The caller remains responsible for
     * clearing its own material copy.
     */
    public static AuthenticatedDataPlaneV2Receiver newReceiver(
            byte[] trafficMaterial, long connectionId)
            throws AuthenticatedDataPlaneV2Exception {
        MaterialParts parts = splitMaterial(trafficMaterial);
        try {
            return AuthenticatedDataPlaneV2.newReceiver(
                    parts.key,
                    parts.noncePrefix,
                    createHostToAndroidDomain(connectionId),
                    PAYLOAD_BYTES,
                    AuthenticatedDataPlaneV2.DEFAULT_REPLAY_WINDOW_SIZE);
        } finally {
            parts.clear();
        }
    }

    /** Creates the single counter owner for one confirmed Host send session. */
    public static AuthenticatedDataPlaneV2Sender newSender(
            byte[] trafficMaterial, long connectionId)
            throws AuthenticatedDataPlaneV2Exception {
        MaterialParts parts = splitMaterial(trafficMaterial);
        try {
            return AuthenticatedDataPlaneV2.newSender(
                    parts.key,
                    parts.noncePrefix,
                    createHostToAndroidDomain(connectionId),
                    PAYLOAD_BYTES,
                    0L);
        } finally {
            parts.clear();
        }
    }

    public static byte[] encodeButtonMask(int buttonMask) {
        if ((buttonMask & ~VALID_BUTTON_MASK) != 0) {
            throw new IllegalArgumentException("buttonMask contains unsupported bits");
        }
        return new byte[] {(byte) buttonMask};
    }

    /** Returns {@code -1} when authenticated plaintext is not canonical. */
    public static int decodeButtonMask(byte[] plaintext) {
        if (plaintext == null || plaintext.length != PAYLOAD_BYTES) return -1;
        int buttonMask = plaintext[0] & 0xff;
        return (buttonMask & ~VALID_BUTTON_MASK) == 0 ? buttonMask : -1;
    }

    private static MaterialParts splitMaterial(byte[] trafficMaterial) {
        if (trafficMaterial == null
                || trafficMaterial.length != TRAFFIC_MATERIAL_BYTES) {
            throw new IllegalArgumentException(
                    "mouse traffic material must contain key[32] and nonce prefix[4]");
        }
        return new MaterialParts(
                Arrays.copyOfRange(
                        trafficMaterial,
                        0,
                        AuthenticatedDataPlaneV2.AES_256_KEY_BYTES),
                Arrays.copyOfRange(
                        trafficMaterial,
                        AuthenticatedDataPlaneV2.AES_256_KEY_BYTES,
                        TRAFFIC_MATERIAL_BYTES));
    }

    private static final class MaterialParts {
        final byte[] key;
        final byte[] noncePrefix;

        MaterialParts(byte[] key, byte[] noncePrefix) {
            this.key = key;
            this.noncePrefix = noncePrefix;
        }

        void clear() {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(noncePrefix, (byte) 0);
        }
    }
}
