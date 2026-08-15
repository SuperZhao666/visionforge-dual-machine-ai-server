package com.visionforge.inferencebenchmark.dataplane;

import java.util.Objects;

/**
 * Wire-level contract for the VisionForge authenticated data-plane v2 foundation.
 *
 * <p>This module authenticates packets after a caller has established a unique AES-256 session
 * key. It does not perform a handshake, establish peer identity, prove authorization, or turn a
 * static token into a cryptographic proof. It is intentionally not wired into a production data
 * path by itself and does not defend an endpoint whose key material or process is controlled by
 * an attacker.
 *
 * <p>The handshake/KDF layer must supply a fresh AES key and four-byte nonce prefix for every
 * (connection id, key epoch, direction, packet type) tuple. This class deliberately does not
 * invent a KDF. Callers must keep one sender counter owner per tuple and must never reset or fork
 * that counter under the same traffic key. This in-memory foundation does not persist counter
 * reservations: after a process-loss ambiguity, callers must discard the old traffic key unless
 * an external durable reservation proves the next counter cannot reuse a nonce.
 *
 * <p>The canonical datagram is a 32-byte big-endian {@code VFA2} header, ciphertext, and a
 * 16-byte GCM tag. The complete header is AAD. Its fields are magic[4], version u8, header-size
 * u8, packet-type u8, direction u8, connection-id u64, key-epoch u32, counter u64, and payload
 * length u32. The 12-byte nonce is the KDF-supplied four-byte tuple prefix followed by the same
 * counter in network byte order. Datagram length is capped at 1412 bytes.
 */
public final class AuthenticatedDataPlaneV2 {
    public static final int PROTOCOL_VERSION = 2;
    public static final int AES_256_KEY_BYTES = 32;
    public static final int CONNECTION_ID_BYTES = Long.BYTES;
    public static final int NONCE_BYTES = 12;
    public static final int NONCE_PREFIX_BYTES = 4;
    public static final int GCM_TAG_BYTES = 16;
    public static final int AUTHENTICATED_HEADER_BYTES = 32;
    public static final int MAX_DATAGRAM_BYTES = 1412;
    public static final int DEFAULT_MAX_PAYLOAD_BYTES =
            MAX_DATAGRAM_BYTES - AUTHENTICATED_HEADER_BYTES - GCM_TAG_BYTES;
    public static final int ABSOLUTE_MAX_PAYLOAD_BYTES = DEFAULT_MAX_PAYLOAD_BYTES;
    public static final int DEFAULT_REPLAY_WINDOW_SIZE = 1024;
    public static final int MAX_REPLAY_WINDOW_SIZE = 1024;
    public static final long MAX_PACKETS_PER_TRAFFIC_KEY = 1L << 23;
    public static final long MAX_COUNTER_PER_TRAFFIC_KEY = MAX_PACKETS_PER_TRAFFIC_KEY - 1L;

    private AuthenticatedDataPlaneV2() {}

    public static Domain createDomain(
            long connectionId, int keyEpoch, Direction direction, MessageType messageType) {
        return new Domain(connectionId, keyEpoch, direction, messageType);
    }

    public static AuthenticatedDataPlaneV2Sender newSender(
            byte[] key, byte[] noncePrefix, Domain domain)
            throws AuthenticatedDataPlaneV2Exception {
        return newSender(key, noncePrefix, domain, DEFAULT_MAX_PAYLOAD_BYTES, 0L);
    }

    static AuthenticatedDataPlaneV2Sender newSender(
            byte[] key,
            byte[] noncePrefix,
            Domain domain,
            int maxPayloadBytes,
            long initialCounter)
            throws AuthenticatedDataPlaneV2Exception {
        requirePayloadLimit(maxPayloadBytes);
        requireInitialCounter(initialCounter);
        return new AuthenticatedDataPlaneV2Sender(
                key,
                noncePrefix,
                Objects.requireNonNull(domain, "domain"),
                maxPayloadBytes,
                initialCounter);
    }

    public static AuthenticatedDataPlaneV2Receiver newReceiver(
            byte[] key, byte[] noncePrefix, Domain domain)
            throws AuthenticatedDataPlaneV2Exception {
        return newReceiver(
                key,
                noncePrefix,
                domain,
                DEFAULT_MAX_PAYLOAD_BYTES,
                DEFAULT_REPLAY_WINDOW_SIZE);
    }

    static AuthenticatedDataPlaneV2Receiver newReceiver(
            byte[] key,
            byte[] noncePrefix,
            Domain domain,
            int maxPayloadBytes,
            int replayWindowSize)
            throws AuthenticatedDataPlaneV2Exception {
        requirePayloadLimit(maxPayloadBytes);
        if (replayWindowSize < 1 || replayWindowSize > MAX_REPLAY_WINDOW_SIZE) {
            throw new IllegalArgumentException(
                    "replayWindowSize must be in [1, " + MAX_REPLAY_WINDOW_SIZE + "]");
        }
        return new AuthenticatedDataPlaneV2Receiver(
                key,
                noncePrefix,
                Objects.requireNonNull(domain, "domain"),
                maxPayloadBytes,
                replayWindowSize);
    }

    static void requirePayloadLimit(int maxPayloadBytes) {
        if (maxPayloadBytes < 0 || maxPayloadBytes > ABSOLUTE_MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException(
                    "maxPayloadBytes must be in [0, "
                            + ABSOLUTE_MAX_PAYLOAD_BYTES
                            + "]");
        }
    }

    static void requireInitialCounter(long initialCounter) {
        if (initialCounter < 0L || initialCounter > MAX_COUNTER_PER_TRAFFIC_KEY) {
            throw new IllegalArgumentException(
                    "initialCounter must be in [0, "
                            + MAX_COUNTER_PER_TRAFFIC_KEY
                            + "] for one traffic key");
        }
    }

    public enum Direction {
        HOST_TO_ANDROID(1),
        ANDROID_TO_HOST(2);

        private final int wireCode;

        Direction(int wireCode) {
            this.wireCode = wireCode;
        }

        int wireCode() {
            return wireCode;
        }

        static Direction fromWireCode(int wireCode) {
            for (Direction direction : values()) {
                if (direction.wireCode == wireCode) return direction;
            }
            return null;
        }
    }

    public enum MessageType {
        VIDEO(1),
        PRESENCE_PROBE(2),
        IDR_REQUEST(3),
        MOUSE_BUTTON(4);

        private final int wireCode;

        MessageType(int wireCode) {
            this.wireCode = wireCode;
        }

        int wireCode() {
            return wireCode;
        }

        static MessageType fromWireCode(int wireCode) {
            for (MessageType messageType : values()) {
                if (messageType.wireCode == wireCode) return messageType;
            }
            return null;
        }
    }

    /** Immutable nonce and AAD domain. */
    public static final class Domain {
        private final long connectionId;
        private final int keyEpoch;
        private final Direction direction;
        private final MessageType messageType;

        private Domain(
                long connectionId,
                int keyEpoch,
                Direction direction,
                MessageType messageType) {
            if (connectionId == 0L) {
                throw new IllegalArgumentException("connectionId must be non-zero");
            }
            if (keyEpoch == 0) {
                throw new IllegalArgumentException("keyEpoch must be non-zero");
            }
            this.connectionId = connectionId;
            this.keyEpoch = keyEpoch;
            this.direction = Objects.requireNonNull(direction, "direction");
            this.messageType = Objects.requireNonNull(messageType, "messageType");
        }

        /** Returns the unsigned 64-bit connection-id bit pattern. */
        public long connectionId() {
            return connectionId;
        }

        /** Returns the unsigned 32-bit key-epoch bit pattern. */
        public int keyEpoch() {
            return keyEpoch;
        }

        public Direction direction() {
            return direction;
        }

        public MessageType messageType() {
            return messageType;
        }

    }
}
