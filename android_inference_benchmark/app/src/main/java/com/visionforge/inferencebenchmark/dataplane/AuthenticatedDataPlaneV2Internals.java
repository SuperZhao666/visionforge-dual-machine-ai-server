package com.visionforge.inferencebenchmark.dataplane;

import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2.GCM_TAG_BYTES;
import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2.PROTOCOL_VERSION;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class AuthenticatedDataPlaneV2Internals {
    static final String TRANSFORMATION = "AES/GCM/NoPadding";
    static final int GCM_TAG_BITS = GCM_TAG_BYTES * Byte.SIZE;
    static final int MAGIC = 0x5646_4132; // "VFA2"

    static final int MAGIC_OFFSET = 0;
    static final int VERSION_OFFSET = MAGIC_OFFSET + Integer.BYTES;
    static final int HEADER_SIZE_OFFSET = VERSION_OFFSET + Byte.BYTES;
    static final int MESSAGE_TYPE_OFFSET = HEADER_SIZE_OFFSET + Byte.BYTES;
    static final int DIRECTION_OFFSET = MESSAGE_TYPE_OFFSET + Byte.BYTES;
    static final int CONNECTION_ID_OFFSET = DIRECTION_OFFSET + Byte.BYTES;
    static final int KEY_EPOCH_OFFSET = CONNECTION_ID_OFFSET + Long.BYTES;
    static final int COUNTER_OFFSET = KEY_EPOCH_OFFSET + Integer.BYTES;
    static final int PAYLOAD_LENGTH_OFFSET = COUNTER_OFFSET + Long.BYTES;
    static final int HEADER_BYTES = AuthenticatedDataPlaneV2.AUTHENTICATED_HEADER_BYTES;
    static final int MINIMUM_ENVELOPE_BYTES = HEADER_BYTES + GCM_TAG_BYTES;
    static final EncryptionAttemptHook NO_ENCRYPTION_FAILURE = () -> {};

    private AuthenticatedDataPlaneV2Internals() {}

    static byte[] buildHeader(
            AuthenticatedDataPlaneV2.Domain domain, long counter, int payloadLength) {
        byte[] header = new byte[HEADER_BYTES];
        ByteBuffer buffer = ByteBuffer.wrap(header);
        buffer.putInt(MAGIC);
        buffer.put((byte) PROTOCOL_VERSION);
        buffer.put((byte) HEADER_BYTES);
        buffer.put((byte) domain.messageType().wireCode());
        buffer.put((byte) domain.direction().wireCode());
        buffer.putLong(domain.connectionId());
        buffer.putInt(domain.keyEpoch());
        buffer.putLong(counter);
        buffer.putInt(payloadLength);
        return header;
    }

    static byte[] encryptWithJca(
            SecretKeySpec key, byte[] nonce, byte[] header, byte[] plaintext)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(
                Cipher.ENCRYPT_MODE,
                key,
                new GCMParameterSpec(GCM_TAG_BITS, nonce));
        cipher.updateAAD(header);
        return cipher.doFinal(plaintext);
    }

    static ParsedEnvelope parse(
            byte[] envelope,
            AuthenticatedDataPlaneV2.Domain expectedDomain,
            int maxPayloadBytes)
            throws AuthenticatedDataPlaneV2Exception {
        requireContainerLength(envelope, maxPayloadBytes);
        ByteBuffer buffer = ByteBuffer.wrap(envelope);
        requireMagic(buffer.getInt());
        requireVersion(Byte.toUnsignedInt(buffer.get()));
        requireHeaderSize(Byte.toUnsignedInt(buffer.get()));
        requireDomain(buffer, expectedDomain);
        long counter = buffer.getLong();
        long payloadLength = Integer.toUnsignedLong(buffer.getInt());
        int checkedPayloadLength =
                requirePayloadLength(envelope.length, payloadLength, maxPayloadBytes);
        return new ParsedEnvelope(counter, checkedPayloadLength);
    }

    static void requireContainerLength(byte[] envelope, int maxPayloadBytes)
            throws AuthenticatedDataPlaneV2Exception {
        if (envelope == null) {
            throw failure(
                    AuthenticatedDataPlaneV2Exception.Reason.MALFORMED_ENVELOPE,
                    "envelope is null");
        }
        if (envelope.length < MINIMUM_ENVELOPE_BYTES) {
            throw failure(
                    AuthenticatedDataPlaneV2Exception.Reason.MALFORMED_ENVELOPE,
                    "envelope is truncated");
        }
        long maximumLength = (long) HEADER_BYTES + maxPayloadBytes + GCM_TAG_BYTES;
        if (envelope.length > maximumLength) {
            throw failure(
                    AuthenticatedDataPlaneV2Exception.Reason.PAYLOAD_TOO_LARGE,
                    "envelope exceeds the configured payload limit");
        }
    }

    static AuthenticatedDataPlaneV2Exception failure(
            AuthenticatedDataPlaneV2Exception.Reason reason, String message) {
        return new AuthenticatedDataPlaneV2Exception(reason, message);
    }

    static AuthenticatedDataPlaneV2Exception failure(
            AuthenticatedDataPlaneV2Exception.Reason reason,
            String message,
            Throwable cause) {
        return new AuthenticatedDataPlaneV2Exception(reason, message, cause);
    }

    static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    static byte[] copyNoncePrefix(byte[] noncePrefix) {
        if (noncePrefix == null
                || noncePrefix.length != AuthenticatedDataPlaneV2.NONCE_PREFIX_BYTES) {
            throw new IllegalArgumentException(
                    "noncePrefix must be exactly "
                            + AuthenticatedDataPlaneV2.NONCE_PREFIX_BYTES
                            + " bytes");
        }
        return noncePrefix.clone();
    }

    static byte[] composeNonce(byte[] noncePrefix, long counter) {
        byte[] nonce = new byte[AuthenticatedDataPlaneV2.NONCE_BYTES];
        System.arraycopy(
                noncePrefix,
                0,
                nonce,
                0,
                AuthenticatedDataPlaneV2.NONCE_PREFIX_BYTES);
        ByteBuffer.wrap(
                        nonce,
                        AuthenticatedDataPlaneV2.NONCE_PREFIX_BYTES,
                        Long.BYTES)
                .putLong(counter);
        return nonce;
    }

    private static void requireMagic(int magic) throws AuthenticatedDataPlaneV2Exception {
        if (magic != MAGIC) {
            throw failure(
                    AuthenticatedDataPlaneV2Exception.Reason.MALFORMED_ENVELOPE,
                    "envelope magic is invalid");
        }
    }

    private static void requireVersion(int version) throws AuthenticatedDataPlaneV2Exception {
        if (version != PROTOCOL_VERSION) {
            throw failure(
                    AuthenticatedDataPlaneV2Exception.Reason.UNSUPPORTED_VERSION,
                    "envelope protocol version is unsupported");
        }
    }

    private static void requireHeaderSize(int headerSize)
            throws AuthenticatedDataPlaneV2Exception {
        if (headerSize != HEADER_BYTES) {
            throw failure(
                    AuthenticatedDataPlaneV2Exception.Reason.MALFORMED_ENVELOPE,
                    "envelope header size is invalid");
        }
    }

    private static void requireDomain(
            ByteBuffer buffer, AuthenticatedDataPlaneV2.Domain expectedDomain)
            throws AuthenticatedDataPlaneV2Exception {
        int messageTypeCode = Byte.toUnsignedInt(buffer.get());
        int directionCode = Byte.toUnsignedInt(buffer.get());
        long connectionId = buffer.getLong();
        int keyEpoch = buffer.getInt();
        AuthenticatedDataPlaneV2.Direction direction =
                AuthenticatedDataPlaneV2.Direction.fromWireCode(directionCode);
        AuthenticatedDataPlaneV2.MessageType messageType =
                AuthenticatedDataPlaneV2.MessageType.fromWireCode(messageTypeCode);
        if (direction == null || messageType == null) {
            throw failure(
                    AuthenticatedDataPlaneV2Exception.Reason.MALFORMED_ENVELOPE,
                    "envelope domain code is invalid");
        }
        if (connectionId != expectedDomain.connectionId()
                || keyEpoch != expectedDomain.keyEpoch()
                || direction != expectedDomain.direction()
                || messageType != expectedDomain.messageType()) {
            throw failure(
                    AuthenticatedDataPlaneV2Exception.Reason.DOMAIN_MISMATCH,
                    "envelope connection, epoch, direction, or packet type does not match");
        }
    }

    private static int requirePayloadLength(
            int envelopeLength, long payloadLength, int maxPayloadBytes)
            throws AuthenticatedDataPlaneV2Exception {
        if (payloadLength > maxPayloadBytes) {
            throw failure(
                    AuthenticatedDataPlaneV2Exception.Reason.PAYLOAD_TOO_LARGE,
                    "envelope payload exceeds the configured limit");
        }
        long expectedLength = (long) HEADER_BYTES + payloadLength + GCM_TAG_BYTES;
        if (expectedLength != envelopeLength) {
            throw failure(
                    AuthenticatedDataPlaneV2Exception.Reason.MALFORMED_ENVELOPE,
                    "envelope length is not canonical");
        }
        return (int) payloadLength;
    }

    static final class ParsedEnvelope {
        final long counter;
        final int payloadLength;

        ParsedEnvelope(long counter, int payloadLength) {
            this.counter = counter;
            this.payloadLength = payloadLength;
        }
    }

    @FunctionalInterface
    interface EncryptionAttemptHook {
        void beforeEncryption() throws GeneralSecurityException;
    }

    static final class KeyMaterial implements AutoCloseable {
        private final byte[] keyBytes;
        private boolean closed;

        KeyMaterial(byte[] key) {
            if (key == null || key.length != AuthenticatedDataPlaneV2.AES_256_KEY_BYTES) {
                throw new IllegalArgumentException(
                        "key must be exactly "
                                + AuthenticatedDataPlaneV2.AES_256_KEY_BYTES
                                + " bytes");
            }
            keyBytes = key.clone();
        }

        SecretKeySpec newKeySpec() throws AuthenticatedDataPlaneV2Exception {
            requireOpen();
            byte[] temporaryKey = keyBytes.clone();
            try {
                return new SecretKeySpec(temporaryKey, "AES");
            } finally {
                clear(temporaryKey);
            }
        }

        void requireOpen() throws AuthenticatedDataPlaneV2Exception {
            if (closed) {
                throw failure(
                        AuthenticatedDataPlaneV2Exception.Reason.CLOSED,
                        "authenticated data-plane endpoint is closed");
            }
        }

        @Override
        public void close() {
            if (closed) return;
            clear(keyBytes);
            closed = true;
        }
    }
}
