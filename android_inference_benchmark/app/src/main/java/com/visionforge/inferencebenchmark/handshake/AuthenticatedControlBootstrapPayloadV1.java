package com.visionforge.inferencebenchmark.handshake;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.MessageType;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Strict canonical TLV payloads for every pre-VFC1 bootstrap message. */
public final class AuthenticatedControlBootstrapPayloadV1 {
    public static final int TLV_HEADER_BYTES = 5;
    public static final int MAXIMUM_FIELDS = 12;
    public static final int MAXIMUM_CREDENTIAL_BYTES = 8192;

    private static final byte[] P256_SPKI_PREFIX = new byte[] {
            0x30, 0x59, 0x30, 0x13,
            0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x03, 0x42, 0x00, 0x04
    };

    private AuthenticatedControlBootstrapPayloadV1() {}

    public static final class HostHelloField {
        public static final int HOST_IDENTITY_SPKI_DER = 0;
        public static final int HOST_EPHEMERAL_PUBLIC_KEY = 1;
        public static final int HOST_NONCE = 2;
        public static final int TRANSPORT_KIND = 3;
        public static final int HOST_IPV4 = 4;
        public static final int ANDROID_IPV4 = 5;
        public static final int VIDEO_PORT = 6;
        public static final int CONTROL_PORT = 7;
        public static final int HOST_RUNTIME_VERSION = 8;

        private HostHelloField() {}
    }

    public static final class AndroidChallengeRequestField {
        public static final int REQUEST_ID = 0;
        public static final int ALLOCATION_REQUEST_ID = 1;
        public static final int ENTITLEMENT_ID = 2;
        public static final int PAIR_ID = 3;
        public static final int BINDING_ID = 4;
        public static final int BINDING_REVISION = 5;
        public static final int REVOCATION_VERSION = 6;
        public static final int ANDROID_IDENTITY_SPKI_DER = 7;
        public static final int ANDROID_EPHEMERAL_PUBLIC_KEY = 8;
        public static final int ANDROID_NONCE = 9;
        public static final int ANDROID_RUNTIME_VERSION = 10;
        public static final int ANDROID_CHALLENGE_SIGNATURE_DER = 11;

        private AndroidChallengeRequestField() {}
    }

    public static final class ServerChallengeField {
        public static final int CHALLENGE_ID = 0;
        public static final int EXPIRES_AT_EPOCH = 1;
        public static final int SERVER_NONCE = 2;

        private ServerChallengeField() {}
    }

    public static final class AndroidHandshakeConfirmationField {
        public static final int TRANSCRIPT_SIGNATURE_DER = 0;
        public static final int ANDROID_FINISHED = 1;

        private AndroidHandshakeConfirmationField() {}
    }

    public enum Reason {
        INVALID_MESSAGE_TYPE,
        INVALID_FIELD_COUNT,
        PAYLOAD_EMPTY,
        PAYLOAD_TOO_LARGE,
        TRUNCATED_TLV,
        UNEXPECTED_FIELD_TAG,
        INVALID_FIELD_LENGTH,
        INVALID_FIELD_VALUE,
        TRAILING_DATA,
        CLOSED
    }

    /** Sanitized failure: field tag is safe metadata; peer-controlled bytes are omitted. */
    public static final class PayloadException extends Exception {
        private static final long serialVersionUID = 1L;

        private final Reason reason;
        private final int fieldTag;

        private PayloadException(Reason reason, int fieldTag) {
            super("authenticated control bootstrap payload was rejected");
            this.reason = reason;
            this.fieldTag = fieldTag;
        }

        public Reason reason() {
            return reason;
        }

        public int fieldTag() {
            return fieldTag;
        }
    }

    /** Deep-copy owner; closing zeroes all credential, signature and Finished bytes. */
    public static final class ParsedPayload implements AutoCloseable {
        private final MessageType messageType;
        private byte[][] fields;
        private boolean closed;

        private ParsedPayload(MessageType messageType, byte[][] fields) {
            this.messageType = messageType;
            this.fields = fields;
        }

        public synchronized MessageType messageType() throws PayloadException {
            requireOpen();
            return messageType;
        }

        public synchronized int fieldCount() throws PayloadException {
            requireOpen();
            return fields.length;
        }

        public synchronized byte[] field(int tag) throws PayloadException {
            requireOpen();
            if (tag < 0 || tag >= fields.length) {
                throw failure(Reason.UNEXPECTED_FIELD_TAG, tag);
            }
            return fields[tag].clone();
        }

        @Override
        public synchronized void close() {
            if (closed) return;
            closed = true;
            if (fields != null) {
                for (byte[] field : fields) clear(field);
                fields = null;
            }
        }

        private void requireOpen() throws PayloadException {
            if (closed || fields == null) throw failure(Reason.CLOSED, -1);
        }
    }

    /**
     * Encodes fields in implicit canonical tag order 0..N-1.
     *
     * <p>This is representation validation only. Production coordination must
     * rebuild the existing typed cryptographic objects and verify signatures,
     * server credential claims and Finished before installing VFC1 keys.</p>
     */
    public static byte[] encode(MessageType messageType, byte[]... fields)
            throws PayloadException {
        FieldRule[] schema = schemaFor(messageType);
        if (schema == null) throw failure(Reason.INVALID_MESSAGE_TYPE, -1);
        if (fields == null || fields.length != schema.length) {
            throw failure(Reason.INVALID_FIELD_COUNT, -1);
        }
        int encodedBytes = 0;
        for (int index = 0; index < fields.length; index++) {
            validateField(schema[index], fields[index], index);
            int fieldBytes = TLV_HEADER_BYTES + fields[index].length;
            if (fieldBytes > AuthenticatedControlBootstrapRecordV1.MAX_PAYLOAD_BYTES
                    - encodedBytes) {
                throw failure(Reason.PAYLOAD_TOO_LARGE, index);
            }
            encodedBytes += fieldBytes;
        }
        validateCrossFields(messageType, fields);
        ByteBuffer encoded = ByteBuffer.allocate(encodedBytes);
        for (int index = 0; index < fields.length; index++) {
            encoded.put((byte) index);
            encoded.putInt(fields[index].length);
            encoded.put(fields[index]);
        }
        return encoded.array();
    }

    public static ParsedPayload parse(MessageType messageType, byte[] encoded)
            throws PayloadException {
        FieldRule[] schema = schemaFor(messageType);
        if (schema == null) throw failure(Reason.INVALID_MESSAGE_TYPE, -1);
        if (encoded == null || encoded.length == 0) {
            throw failure(Reason.PAYLOAD_EMPTY, -1);
        }
        if (encoded.length > AuthenticatedControlBootstrapRecordV1.MAX_PAYLOAD_BYTES) {
            throw failure(Reason.PAYLOAD_TOO_LARGE, -1);
        }
        byte[] source = encoded.clone();
        byte[][] fields = new byte[schema.length][];
        boolean succeeded = false;
        try {
            ByteBuffer input = ByteBuffer.wrap(source);
            for (int index = 0; index < schema.length; index++) {
                if (input.remaining() < TLV_HEADER_BYTES) {
                    throw failure(Reason.TRUNCATED_TLV, index);
                }
                int actualTag = Byte.toUnsignedInt(input.get());
                if (actualTag != index) {
                    throw failure(Reason.UNEXPECTED_FIELD_TAG, actualTag);
                }
                long fieldLength = Integer.toUnsignedLong(input.getInt());
                FieldRule rule = schema[index];
                if (fieldLength < rule.minimum || fieldLength > rule.maximum) {
                    throw failure(Reason.INVALID_FIELD_LENGTH, index);
                }
                if (fieldLength > input.remaining()) {
                    throw failure(Reason.TRUNCATED_TLV, index);
                }
                fields[index] = new byte[(int) fieldLength];
                input.get(fields[index]);
                validateField(rule, fields[index], index);
            }
            if (input.hasRemaining()) throw failure(Reason.TRAILING_DATA, -1);
            validateCrossFields(messageType, fields);
            ParsedPayload parsed = new ParsedPayload(messageType, fields);
            succeeded = true;
            return parsed;
        } finally {
            clear(source);
            if (!succeeded) {
                for (byte[] field : fields) clear(field);
            }
        }
    }

    public static int readUnsigned16(byte[] value) {
        if (value == null || value.length != 2) {
            throw new IllegalArgumentException("value must be an unsigned 16-bit integer");
        }
        return (Byte.toUnsignedInt(value[0]) << 8) | Byte.toUnsignedInt(value[1]);
    }

    public static long readPositiveSigned64(byte[] value) {
        if (value == null || value.length != Long.BYTES) {
            throw new IllegalArgumentException("value must be a signed 64-bit integer");
        }
        long decoded = ByteBuffer.wrap(value).getLong();
        if (decoded <= 0L) {
            throw new IllegalArgumentException("value must be positive");
        }
        return decoded;
    }

    private enum Semantic {
        OPAQUE,
        LOWER_HEX_IDENTIFIER,
        POSITIVE_U64,
        CANONICAL_P256_SPKI,
        SEC1_P256_PUBLIC_KEY,
        NONZERO_BYTES,
        TRANSPORT_KIND,
        NONZERO_PORT,
        STABLE_SEMVER,
        ECDSA_DER,
        COMPACT_JWT,
        POSITIVE_U16
    }

    private static final class FieldRule {
        private final int minimum;
        private final int maximum;
        private final Semantic semantic;

        private FieldRule(int minimum, int maximum, Semantic semantic) {
            this.minimum = minimum;
            this.maximum = maximum;
            this.semantic = semantic;
        }
    }

    private static FieldRule exact(int bytes, Semantic semantic) {
        return new FieldRule(bytes, bytes, semantic);
    }

    private static FieldRule exact(int bytes) {
        return exact(bytes, Semantic.OPAQUE);
    }

    private static FieldRule bounded(int minimum, int maximum, Semantic semantic) {
        return new FieldRule(minimum, maximum, semantic);
    }

    // Static schemas avoid attacker-controlled allocation before peer authentication.
    private static final FieldRule[] HOST_HELLO_SCHEMA = new FieldRule[] {
            exact(91, Semantic.CANONICAL_P256_SPKI),
            exact(65, Semantic.SEC1_P256_PUBLIC_KEY),
            exact(32, Semantic.NONZERO_BYTES),
            exact(1, Semantic.TRANSPORT_KIND),
            exact(4), exact(4),
            exact(2, Semantic.NONZERO_PORT),
            exact(2, Semantic.NONZERO_PORT),
            bounded(1, 32, Semantic.STABLE_SEMVER)
    };
    private static final FieldRule[] ANDROID_CHALLENGE_REQUEST_SCHEMA =
            new FieldRule[] {
                    exact(32, Semantic.LOWER_HEX_IDENTIFIER),
                    exact(32, Semantic.LOWER_HEX_IDENTIFIER),
                    exact(32, Semantic.LOWER_HEX_IDENTIFIER),
                    exact(32, Semantic.LOWER_HEX_IDENTIFIER),
                    exact(32, Semantic.LOWER_HEX_IDENTIFIER),
                    exact(8, Semantic.POSITIVE_U64),
                    exact(8, Semantic.POSITIVE_U64),
                    exact(91, Semantic.CANONICAL_P256_SPKI),
                    exact(65, Semantic.SEC1_P256_PUBLIC_KEY),
                    exact(32, Semantic.NONZERO_BYTES),
                    bounded(1, 32, Semantic.STABLE_SEMVER),
                    bounded(8, 72, Semantic.ECDSA_DER)
            };
    private static final FieldRule[] SIGNATURE_SCHEMA = new FieldRule[] {
            bounded(8, 72, Semantic.ECDSA_DER)
    };
    private static final FieldRule[] SERVER_CHALLENGE_SCHEMA = new FieldRule[] {
            exact(32, Semantic.LOWER_HEX_IDENTIFIER),
            exact(8, Semantic.POSITIVE_U64),
            exact(32, Semantic.NONZERO_BYTES)
    };
    private static final FieldRule[] CREDENTIAL_SCHEMA = new FieldRule[] {
            bounded(1, MAXIMUM_CREDENTIAL_BYTES, Semantic.COMPACT_JWT)
    };
    private static final FieldRule[] ANDROID_HANDSHAKE_CONFIRMATION_SCHEMA =
            new FieldRule[] {
                    bounded(8, 72, Semantic.ECDSA_DER),
                    exact(32, Semantic.NONZERO_BYTES)
            };
    private static final FieldRule[] HOST_FINISHED_SCHEMA = new FieldRule[] {
            exact(32, Semantic.NONZERO_BYTES)
    };
    private static final FieldRule[] ABORT_SCHEMA = new FieldRule[] {
            exact(2, Semantic.POSITIVE_U16)
    };

    private static FieldRule[] schemaFor(MessageType messageType) {
        if (messageType == null) return null;
        switch (messageType) {
            case HOST_HELLO:
                return HOST_HELLO_SCHEMA;
            case ANDROID_CHALLENGE_REQUEST:
                return ANDROID_CHALLENGE_REQUEST_SCHEMA;
            case HOST_CHALLENGE_PROOF:
            case HOST_FINAL_PROOF:
            case HOST_HANDSHAKE_SIGNATURE:
                return SIGNATURE_SCHEMA;
            case SERVER_CHALLENGE:
                return SERVER_CHALLENGE_SCHEMA;
            case PAIR_GENERATION_CREDENTIAL:
                return CREDENTIAL_SCHEMA;
            case ANDROID_HANDSHAKE_CONFIRMATION:
                return ANDROID_HANDSHAKE_CONFIRMATION_SCHEMA;
            case HOST_FINISHED:
                return HOST_FINISHED_SCHEMA;
            case ABORT:
                return ABORT_SCHEMA;
            default:
                return null;
        }
    }

    private static void validateField(FieldRule rule, byte[] value, int tag)
            throws PayloadException {
        if (value == null || value.length < rule.minimum || value.length > rule.maximum) {
            throw failure(Reason.INVALID_FIELD_LENGTH, tag);
        }
        boolean valid;
        switch (rule.semantic) {
            case OPAQUE:
                valid = true;
                break;
            case LOWER_HEX_IDENTIFIER:
                valid = lowerHexIdentifierValid(value);
                break;
            case POSITIVE_U64:
                valid = positiveSigned64Valid(value);
                break;
            case CANONICAL_P256_SPKI:
                valid = canonicalP256SpkiValid(value);
                break;
            case SEC1_P256_PUBLIC_KEY:
                valid = value.length == 65 && value[0] == 0x04
                        && containsNonzero(value, 1);
                break;
            case NONZERO_BYTES:
                valid = containsNonzero(value, 0);
                break;
            case TRANSPORT_KIND:
                valid = value.length == 1 && (value[0] == 1 || value[0] == 2);
                break;
            case NONZERO_PORT:
            case POSITIVE_U16:
                valid = readUnsigned16(value) != 0;
                break;
            case STABLE_SEMVER:
                valid = stableSemVerValid(value);
                break;
            case ECDSA_DER:
                valid = canonicalEcdsaDerValid(value);
                break;
            case COMPACT_JWT:
                valid = compactJwtValid(value);
                break;
            default:
                valid = false;
        }
        if (!valid) throw failure(Reason.INVALID_FIELD_VALUE, tag);
    }

    private static void validateCrossFields(MessageType messageType, byte[][] fields)
            throws PayloadException {
        if (messageType == MessageType.HOST_HELLO
                && readUnsigned16(fields[HostHelloField.VIDEO_PORT])
                == readUnsigned16(fields[HostHelloField.CONTROL_PORT])) {
            throw failure(Reason.INVALID_FIELD_VALUE, HostHelloField.CONTROL_PORT);
        }
    }

    private static boolean lowerHexIdentifierValid(byte[] value) {
        if (value.length != 32 || !containsNonzero(value, 0)) return false;
        for (byte current : value) {
            int character = Byte.toUnsignedInt(current);
            if (!((character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f'))) return false;
        }
        return true;
    }

    private static boolean positiveSigned64Valid(byte[] value) {
        if (value.length != Long.BYTES || (value[0] & 0x80) != 0) return false;
        long decoded = ByteBuffer.wrap(value).getLong();
        return decoded > 0L;
    }

    private static boolean canonicalP256SpkiValid(byte[] value) {
        if (value.length != 91) return false;
        for (int index = 0; index < P256_SPKI_PREFIX.length; index++) {
            if (value[index] != P256_SPKI_PREFIX[index]) return false;
        }
        return containsNonzero(value, P256_SPKI_PREFIX.length);
    }

    private static boolean stableSemVerValid(byte[] value) {
        if (value.length == 0 || value.length > 32) return false;
        int componentStart = 0;
        int components = 0;
        for (int index = 0; index <= value.length; index++) {
            if (index != value.length && value[index] != '.') {
                if (value[index] < '0' || value[index] > '9') return false;
                continue;
            }
            int componentLength = index - componentStart;
            if (componentLength == 0
                    || componentLength > 1 && value[componentStart] == '0') return false;
            components++;
            componentStart = index + 1;
        }
        return components == 3;
    }

    private static boolean canonicalEcdsaDerValid(byte[] value) {
        if (value.length < 8 || value.length > 72 || value[0] != 0x30
                || Byte.toUnsignedInt(value[1]) != value.length - 2) return false;
        int offset = 2;
        if (value[offset++] != 0x02) return false;
        int rLength = Byte.toUnsignedInt(value[offset++]);
        if (rLength == 0 || offset + rLength + 2 > value.length
                || !canonicalDerIntegerValid(value, offset, rLength)) return false;
        offset += rLength;
        if (value[offset++] != 0x02) return false;
        int sLength = Byte.toUnsignedInt(value[offset++]);
        return sLength != 0 && offset + sLength == value.length
                && canonicalDerIntegerValid(value, offset, sLength);
    }

    private static boolean canonicalDerIntegerValid(byte[] value, int offset, int length) {
        if (length == 0 || length > 33) return false;
        int first = Byte.toUnsignedInt(value[offset]);
        if ((first & 0x80) != 0) return false;
        if (length > 1 && first == 0
                && (Byte.toUnsignedInt(value[offset + 1]) & 0x80) == 0) return false;
        return containsNonzero(value, offset, length);
    }

    private static boolean compactJwtValid(byte[] value) {
        if (value.length == 0 || value.length > MAXIMUM_CREDENTIAL_BYTES) return false;
        int dots = 0;
        int segmentLength = 0;
        for (byte current : value) {
            int character = Byte.toUnsignedInt(current);
            if (character == '.') {
                if (segmentLength == 0 || dots == 2) return false;
                dots++;
                segmentLength = 0;
                continue;
            }
            boolean base64url = character >= 'A' && character <= 'Z'
                    || character >= 'a' && character <= 'z'
                    || character >= '0' && character <= '9'
                    || character == '-' || character == '_';
            if (!base64url) return false;
            segmentLength++;
        }
        return dots == 2 && segmentLength != 0;
    }

    private static boolean containsNonzero(byte[] value, int offset) {
        return containsNonzero(value, offset, value.length - offset);
    }

    private static boolean containsNonzero(byte[] value, int offset, int length) {
        for (int index = offset; index < offset + length; index++) {
            if (value[index] != 0) return true;
        }
        return false;
    }

    private static PayloadException failure(Reason reason, int fieldTag) {
        return new PayloadException(reason, fieldTag);
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }
}
