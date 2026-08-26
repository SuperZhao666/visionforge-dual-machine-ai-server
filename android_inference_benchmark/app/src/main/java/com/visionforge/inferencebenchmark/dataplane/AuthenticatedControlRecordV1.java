package com.visionforge.inferencebenchmark.dataplane;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Canonical authenticated control record used after the peer-handshake Finished exchange.
 *
 * <p>The wire envelope is a 40-byte big-endian {@code VFC1} AAD header, ciphertext, and a
 * 16-byte AES-GCM tag. Header fields are magic[4], version u8, header-size u8, direction u8,
 * message-type u8, connection-id u64, session-generation u64, key-epoch u32, counter u64, and
 * ciphertext-length u32. The nonce is the handshake-derived four-byte prefix followed by the
 * same counter in network byte order.
 *
 * <p>One Sender owns the only counter for every message type in one directional key domain. One
 * Receiver owns the corresponding 1024-bit replay window. Callers must never fork either owner
 * or reuse the same 36-byte key/prefix material after process-loss or counter ambiguity.
 */
public final class AuthenticatedControlRecordV1 {
    public static final int PROTOCOL_VERSION = 1;
    public static final int TRAFFIC_MATERIAL_BYTES = 36;
    public static final int AES_256_KEY_BYTES = 32;
    public static final int NONCE_PREFIX_BYTES = 4;
    public static final int NONCE_BYTES = 12;
    public static final int GCM_TAG_BYTES = 16;
    public static final int AUTHENTICATED_HEADER_BYTES = 40;
    public static final int MAX_PAYLOAD_BYTES = 65_536;
    public static final int REPLAY_WINDOW_BITS = 1024;
    public static final long MAX_RECORDS_PER_TRAFFIC_KEY = 1L << 23;
    public static final long MAX_COUNTER_PER_TRAFFIC_KEY =
            MAX_RECORDS_PER_TRAFFIC_KEY - 1L;

    private static final int MAGIC = 0x5646_4331; // "VFC1"
    private static final int GCM_TAG_BITS = GCM_TAG_BYTES * Byte.SIZE;
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final EncryptionAttemptHook NO_ENCRYPTION_FAILURE = () -> {};

    private AuthenticatedControlRecordV1() {}

    public static Domain createDomain(
            long connectionId,
            long sessionGeneration,
            int keyEpoch,
            Direction direction) {
        return new Domain(connectionId, sessionGeneration, keyEpoch, direction);
    }

    public static Sender newSender(byte[] trafficMaterial, Domain domain)
            throws ControlRecordException {
        return newSender(trafficMaterial, domain, 0L, NO_ENCRYPTION_FAILURE);
    }

    static Sender newSender(
            byte[] trafficMaterial,
            Domain domain,
            long initialCounter,
            EncryptionAttemptHook encryptionAttemptHook)
            throws ControlRecordException {
        requireInitialCounter(initialCounter);
        return new Sender(
                trafficMaterial,
                Objects.requireNonNull(domain, "domain"),
                initialCounter,
                Objects.requireNonNull(encryptionAttemptHook, "encryptionAttemptHook"));
    }

    public static Receiver newReceiver(byte[] trafficMaterial, Domain domain)
            throws ControlRecordException {
        return new Receiver(
                trafficMaterial,
                Objects.requireNonNull(domain, "domain"));
    }

    private static void requireInitialCounter(long initialCounter) {
        if (initialCounter < 0L || initialCounter > MAX_COUNTER_PER_TRAFFIC_KEY) {
            throw new IllegalArgumentException(
                    "initialCounter must be in [0, "
                            + MAX_COUNTER_PER_TRAFFIC_KEY
                            + "]");
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
        LEASE_OFFER(1),
        LEASE_ACCEPT(2),
        LEASE_COMMIT(3),
        SESSION_CLOSE(4),
        SESSION_CLOSE_ACK(5),
        ENTITLEMENT_STATUS_SIGN_REQUEST(6),
        ENTITLEMENT_STATUS_SIGN_RESPONSE(7),
        USAGE_AUTHORIZATION_SIGN_REQUEST(8),
        USAGE_AUTHORIZATION_SIGN_RESPONSE(9),
        HOST_START_INTENT_CLAIM_REQUEST(10),
        HOST_START_INTENT_CLAIM_RESPONSE(11);

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

    /** Shared framing predicate so TCP transport cannot lag new VFC1 types. */
    public static boolean isKnownMessageTypeWireCode(int wireCode) {
        return MessageType.fromWireCode(wireCode) != null;
    }

    /** Immutable key/counter/replay domain shared by every control message type. */
    public static final class Domain {
        private final long connectionId;
        private final long sessionGeneration;
        private final int keyEpoch;
        private final Direction direction;

        private Domain(
                long connectionId,
                long sessionGeneration,
                int keyEpoch,
                Direction direction) {
            if (connectionId == 0L) {
                throw new IllegalArgumentException("connectionId must be non-zero");
            }
            if (sessionGeneration == 0L) {
                throw new IllegalArgumentException("sessionGeneration must be non-zero");
            }
            if (keyEpoch == 0) {
                throw new IllegalArgumentException("keyEpoch must be non-zero");
            }
            this.connectionId = connectionId;
            this.sessionGeneration = sessionGeneration;
            this.keyEpoch = keyEpoch;
            this.direction = Objects.requireNonNull(direction, "direction");
        }

        public long connectionId() {
            return connectionId;
        }

        public long sessionGeneration() {
            return sessionGeneration;
        }

        public int keyEpoch() {
            return keyEpoch;
        }

        public Direction direction() {
            return direction;
        }

        private boolean matches(
                long candidateConnectionId,
                long candidateSessionGeneration,
                int candidateKeyEpoch,
                Direction candidateDirection) {
            return connectionId == candidateConnectionId
                    && sessionGeneration == candidateSessionGeneration
                    && keyEpoch == candidateKeyEpoch
                    && direction == candidateDirection;
        }
    }

    /** Successfully authenticated control payload. The returned bytes are defensive copies. */
    public static final class OpenedRecord implements AutoCloseable {
        private final MessageType messageType;
        private final long counter;
        private final byte[] plaintext;
        private boolean closed;

        private OpenedRecord(MessageType messageType, long counter, byte[] plaintext) {
            this.messageType = messageType;
            this.counter = counter;
            this.plaintext = plaintext.clone();
        }

        public MessageType messageType() {
            return messageType;
        }

        public long counter() {
            return counter;
        }

        public synchronized byte[] plaintext() throws ControlRecordException {
            if (closed) {
                throw failure(Reason.CLOSED, "opened control record is closed");
            }
            return plaintext.clone();
        }

        @Override
        public synchronized void close() {
            if (closed) return;
            clear(plaintext);
            closed = true;
        }
    }

    /** Stateful owner of the single send counter for one directional control key. */
    public static final class Sender implements AutoCloseable {
        private final KeyMaterial keyMaterial;
        private final byte[] noncePrefix;
        private final Domain domain;
        private final EncryptionAttemptHook encryptionAttemptHook;
        private long nextCounter;
        private boolean counterExhausted;

        private Sender(
                byte[] trafficMaterial,
                Domain domain,
                long initialCounter,
                EncryptionAttemptHook encryptionAttemptHook)
                throws ControlRecordException {
            SplitTrafficMaterial split = splitTrafficMaterial(trafficMaterial);
            try {
                keyMaterial = new KeyMaterial(split.key);
                noncePrefix = split.prefix.clone();
            } finally {
                split.close();
            }
            this.domain = domain;
            this.nextCounter = initialCounter;
            this.encryptionAttemptHook = encryptionAttemptHook;
        }

        /** Burns the counter before entering the provider, including failed attempts. */
        public synchronized byte[] seal(MessageType messageType, byte[] plaintext)
                throws ControlRecordException {
            Objects.requireNonNull(messageType, "messageType");
            if (plaintext == null) throw new IllegalArgumentException("plaintext is null");
            keyMaterial.requireOpen();
            if (plaintext.length > MAX_PAYLOAD_BYTES) {
                throw failure(Reason.PAYLOAD_TOO_LARGE, "control payload exceeds 65536 bytes");
            }
            if (counterExhausted) {
                throw failure(Reason.COUNTER_EXHAUSTED, "control traffic key requires rekey");
            }

            long counter = nextCounter;
            byte[] plaintextCopy = plaintext.clone();
            byte[] header = buildHeader(domain, messageType, counter, plaintextCopy.length);
            byte[] nonce = composeNonce(noncePrefix, counter);
            byte[] ciphertextAndTag = null;
            try {
                burnCounter(counter);
                ciphertextAndTag = encrypt(header, nonce, plaintextCopy);
                byte[] envelope =
                        new byte[AUTHENTICATED_HEADER_BYTES + ciphertextAndTag.length];
                System.arraycopy(header, 0, envelope, 0, AUTHENTICATED_HEADER_BYTES);
                System.arraycopy(
                        ciphertextAndTag,
                        0,
                        envelope,
                        AUTHENTICATED_HEADER_BYTES,
                        ciphertextAndTag.length);
                return envelope;
            } finally {
                clear(plaintextCopy);
                clear(header);
                clear(nonce);
                clear(ciphertextAndTag);
            }
        }

        private byte[] encrypt(byte[] header, byte[] nonce, byte[] plaintext)
                throws ControlRecordException {
            try {
                encryptionAttemptHook.beforeEncryption();
                Cipher cipher = Cipher.getInstance(TRANSFORMATION);
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        keyMaterial.newKeySpec(),
                        new GCMParameterSpec(GCM_TAG_BITS, nonce));
                cipher.updateAAD(header);
                byte[] output = cipher.doFinal(plaintext);
                if (output.length != plaintext.length + GCM_TAG_BYTES) {
                    clear(output);
                    throw new GeneralSecurityException(
                            "AES-GCM provider returned a non-canonical output length");
                }
                return output;
            } catch (GeneralSecurityException | RuntimeException providerFailure) {
                throw failure(
                        Reason.CRYPTO_UNAVAILABLE,
                        "AES-256-GCM control encryption failed closed",
                        providerFailure);
            }
        }

        private void burnCounter(long counter) {
            if (counter == MAX_COUNTER_PER_TRAFFIC_KEY) {
                counterExhausted = true;
            } else {
                nextCounter = counter + 1L;
            }
        }

        @Override
        public synchronized void close() {
            keyMaterial.close();
            clear(noncePrefix);
        }
    }

    /** Stateful owner of the single 1024-bit replay window for one direction. */
    public static final class Receiver implements AutoCloseable {
        private final KeyMaterial keyMaterial;
        private final byte[] noncePrefix;
        private final Domain expectedDomain;
        private final UnsignedReplayWindow replayWindow =
                new UnsignedReplayWindow(REPLAY_WINDOW_BITS);

        private Receiver(byte[] trafficMaterial, Domain expectedDomain)
                throws ControlRecordException {
            SplitTrafficMaterial split = splitTrafficMaterial(trafficMaterial);
            try {
                keyMaterial = new KeyMaterial(split.key);
                noncePrefix = split.prefix.clone();
            } finally {
                split.close();
            }
            this.expectedDomain = expectedDomain;
        }

        /**
         * Opens one record. Every packet-controlled parse, tuple, replay, and tag failure is
         * collapsed to {@link Reason#UNAUTHENTICATED_RECORD}; no replay state advances before a
         * valid tag.
         */
        public synchronized OpenedRecord open(byte[] envelope)
                throws ControlRecordException {
            try {
                return openUntrusted(envelope);
            } catch (ControlRecordException rejected) {
                if (rejected.reason() == Reason.CLOSED
                        || rejected.reason() == Reason.CRYPTO_UNAVAILABLE) {
                    throw rejected;
                }
                throw failure(
                        Reason.UNAUTHENTICATED_RECORD,
                        "authenticated control record was rejected");
            }
        }

        private OpenedRecord openUntrusted(byte[] envelope)
                throws ControlRecordException {
            keyMaterial.requireOpen();
            ParsedRecord parsed = parse(envelope, expectedDomain);
            if (replayWindow.inspect(parsed.counter)
                    != UnsignedReplayWindow.Decision.ACCEPT) {
                throw failure(Reason.REPLAY_REJECTED, "control counter is not fresh");
            }
            byte[] nonce = composeNonce(noncePrefix, parsed.counter);
            byte[] plaintext = null;
            try {
                plaintext = decrypt(parsed.envelope, nonce, parsed.payloadLength);
                if (!replayWindow.commitAuthenticated(parsed.counter)) {
                    throw failure(Reason.REPLAY_REJECTED, "control counter commit failed");
                }
                return new OpenedRecord(parsed.messageType, parsed.counter, plaintext);
            } finally {
                clear(nonce);
                clear(plaintext);
                parsed.close();
            }
        }

        private byte[] decrypt(byte[] envelope, byte[] nonce, int payloadLength)
                throws ControlRecordException {
            try {
                Cipher cipher = Cipher.getInstance(TRANSFORMATION);
                cipher.init(
                        Cipher.DECRYPT_MODE,
                        keyMaterial.newKeySpec(),
                        new GCMParameterSpec(GCM_TAG_BITS, nonce));
                cipher.updateAAD(envelope, 0, AUTHENTICATED_HEADER_BYTES);
                byte[] plaintext =
                        cipher.doFinal(
                                envelope,
                                AUTHENTICATED_HEADER_BYTES,
                                payloadLength + GCM_TAG_BYTES);
                if (plaintext.length != payloadLength) {
                    clear(plaintext);
                    throw new GeneralSecurityException(
                            "AES-GCM provider returned a non-canonical plaintext length");
                }
                return plaintext;
            } catch (BadPaddingException authenticationFailure) {
                throw failure(
                        Reason.AUTHENTICATION_FAILED,
                        "AES-GCM control authentication failed",
                        authenticationFailure);
            } catch (GeneralSecurityException | RuntimeException providerFailure) {
                throw failure(
                        Reason.CRYPTO_UNAVAILABLE,
                        "AES-256-GCM control decryption failed closed",
                        providerFailure);
            }
        }

        @Override
        public synchronized void close() {
            keyMaterial.close();
            clear(noncePrefix);
        }
    }

    public static final class ControlRecordException extends GeneralSecurityException {
        private static final long serialVersionUID = 1L;
        private final Reason reason;

        private ControlRecordException(Reason reason, String message) {
            super(message);
            this.reason = reason;
        }

        private ControlRecordException(Reason reason, String message, Throwable cause) {
            super(message, cause);
            this.reason = reason;
        }

        public Reason reason() {
            return reason;
        }
    }

    public enum Reason {
        AUTHENTICATION_FAILED,
        CLOSED,
        COUNTER_EXHAUSTED,
        CRYPTO_UNAVAILABLE,
        MALFORMED_RECORD,
        PAYLOAD_TOO_LARGE,
        REPLAY_REJECTED,
        UNAUTHENTICATED_RECORD
    }

    @FunctionalInterface
    interface EncryptionAttemptHook {
        void beforeEncryption() throws GeneralSecurityException;
    }

    private static byte[] buildHeader(
            Domain domain, MessageType messageType, long counter, int ciphertextLength) {
        byte[] header = new byte[AUTHENTICATED_HEADER_BYTES];
        ByteBuffer buffer = ByteBuffer.wrap(header);
        buffer.putInt(MAGIC);
        buffer.put((byte) PROTOCOL_VERSION);
        buffer.put((byte) AUTHENTICATED_HEADER_BYTES);
        buffer.put((byte) domain.direction().wireCode());
        buffer.put((byte) messageType.wireCode());
        buffer.putLong(domain.connectionId());
        buffer.putLong(domain.sessionGeneration());
        buffer.putInt(domain.keyEpoch());
        buffer.putLong(counter);
        buffer.putInt(ciphertextLength);
        return header;
    }

    private static ParsedRecord parse(byte[] envelope, Domain expectedDomain)
            throws ControlRecordException {
        if (envelope == null) {
            throw failure(Reason.MALFORMED_RECORD, "control record is null");
        }
        long maximumBytes =
                (long) AUTHENTICATED_HEADER_BYTES + MAX_PAYLOAD_BYTES + GCM_TAG_BYTES;
        if (envelope.length < AUTHENTICATED_HEADER_BYTES + GCM_TAG_BYTES
                || envelope.length > maximumBytes) {
            throw failure(Reason.MALFORMED_RECORD, "control record size is invalid");
        }
        byte[] copy = envelope.clone();
        try {
            ByteBuffer buffer = ByteBuffer.wrap(copy);
            if (buffer.getInt() != MAGIC
                    || Byte.toUnsignedInt(buffer.get()) != PROTOCOL_VERSION
                    || Byte.toUnsignedInt(buffer.get()) != AUTHENTICATED_HEADER_BYTES) {
                throw failure(Reason.MALFORMED_RECORD, "control record prefix is invalid");
            }
            Direction direction = Direction.fromWireCode(Byte.toUnsignedInt(buffer.get()));
            MessageType messageType =
                    MessageType.fromWireCode(Byte.toUnsignedInt(buffer.get()));
            long connectionId = buffer.getLong();
            long sessionGeneration = buffer.getLong();
            int keyEpoch = buffer.getInt();
            long counter = buffer.getLong();
            long payloadLength = Integer.toUnsignedLong(buffer.getInt());
            if (direction == null
                    || messageType == null
                    || connectionId == 0L
                    || sessionGeneration == 0L
                    || keyEpoch == 0
                    || !expectedDomain.matches(
                            connectionId, sessionGeneration, keyEpoch, direction)
                    || counter < 0L
                    || counter > MAX_COUNTER_PER_TRAFFIC_KEY
                    || payloadLength > MAX_PAYLOAD_BYTES
                    || (long) AUTHENTICATED_HEADER_BYTES
                                    + payloadLength
                                    + GCM_TAG_BYTES
                            != copy.length) {
                throw failure(Reason.MALFORMED_RECORD, "control record fields are invalid");
            }
            return new ParsedRecord(copy, messageType, counter, (int) payloadLength);
        } catch (ControlRecordException failure) {
            clear(copy);
            throw failure;
        } catch (RuntimeException malformed) {
            clear(copy);
            throw failure(Reason.MALFORMED_RECORD, "control record parsing failed", malformed);
        }
    }

    private static byte[] composeNonce(byte[] prefix, long counter) {
        byte[] nonce = new byte[NONCE_BYTES];
        System.arraycopy(prefix, 0, nonce, 0, NONCE_PREFIX_BYTES);
        ByteBuffer.wrap(nonce, NONCE_PREFIX_BYTES, Long.BYTES).putLong(counter);
        return nonce;
    }

    private static SplitTrafficMaterial splitTrafficMaterial(byte[] trafficMaterial) {
        if (trafficMaterial == null || trafficMaterial.length != TRAFFIC_MATERIAL_BYTES) {
            throw new IllegalArgumentException(
                    "trafficMaterial must be exactly " + TRAFFIC_MATERIAL_BYTES + " bytes");
        }
        return new SplitTrafficMaterial(
                Arrays.copyOfRange(trafficMaterial, 0, AES_256_KEY_BYTES),
                Arrays.copyOfRange(
                        trafficMaterial, AES_256_KEY_BYTES, TRAFFIC_MATERIAL_BYTES));
    }

    private static ControlRecordException failure(Reason reason, String message) {
        return new ControlRecordException(reason, message);
    }

    private static ControlRecordException failure(
            Reason reason, String message, Throwable cause) {
        return new ControlRecordException(reason, message, cause);
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    private static final class KeyMaterial implements AutoCloseable {
        private final byte[] key;
        private boolean closed;

        private KeyMaterial(byte[] key) {
            this.key = key.clone();
        }

        private void requireOpen() throws ControlRecordException {
            if (closed) {
                throw failure(Reason.CLOSED, "authenticated control endpoint is closed");
            }
        }

        private SecretKeySpec newKeySpec() throws ControlRecordException {
            requireOpen();
            byte[] temporary = key.clone();
            try {
                return new SecretKeySpec(temporary, "AES");
            } finally {
                clear(temporary);
            }
        }

        @Override
        public void close() {
            if (closed) return;
            clear(key);
            closed = true;
        }
    }

    private static final class SplitTrafficMaterial implements AutoCloseable {
        private final byte[] key;
        private final byte[] prefix;

        private SplitTrafficMaterial(byte[] key, byte[] prefix) {
            this.key = key;
            this.prefix = prefix;
        }

        @Override
        public void close() {
            clear(key);
            clear(prefix);
        }
    }

    private static final class ParsedRecord implements AutoCloseable {
        private final byte[] envelope;
        private final MessageType messageType;
        private final long counter;
        private final int payloadLength;

        private ParsedRecord(
                byte[] envelope, MessageType messageType, long counter, int payloadLength) {
            this.envelope = envelope;
            this.messageType = messageType;
            this.counter = counter;
            this.payloadLength = payloadLength;
        }

        @Override
        public void close() {
            clear(envelope);
        }
    }
}
