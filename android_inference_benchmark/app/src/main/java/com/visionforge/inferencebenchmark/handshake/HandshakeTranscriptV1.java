package com.visionforge.inferencebenchmark.handshake;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** Immutable canonical 18-field TLV transcript for authenticated peer-handshake v1. */
public final class HandshakeTranscriptV1 {
    private static final byte[] DOMAIN_BYTES =
            "visionforge-peer-handshake-v1".getBytes(StandardCharsets.US_ASCII);
    static final int FIELD_COUNT = 18;
    static final int TLV_HEADER_BYTES = 1 + Integer.BYTES;
    static final int MAX_PAIR_ID_BYTES = 64;
    static final int MAX_RUNTIME_VERSION_BYTES = 32;
    static final int MAX_CANONICAL_TRANSCRIPT_BYTES = 538;

    private final byte[] hostIdentitySpkiSha256;
    private final byte[] androidIdentitySpkiSha256;
    private final byte[] hostEphemeralPublicKey;
    private final byte[] androidEphemeralPublicKey;
    private final byte[] hostNonce;
    private final byte[] androidNonce;
    private final long connectionId;
    private final long sessionGeneration;
    private final AuthenticatedPeerHandshakeV1.TransportKind transportKind;
    private final byte[] hostIpv4;
    private final byte[] androidIpv4;
    private final int videoPort;
    private final int controlPort;
    private final String pairId;
    private final String hostRuntimeVersion;
    private final String androidRuntimeVersion;
    private final byte[] canonicalEncoding;

    private HandshakeTranscriptV1(Builder builder) {
        hostIdentitySpkiSha256 = requireLength(
                builder.hostIdentitySpkiSha256,
                AuthenticatedPeerHandshakeV1.SHA256_BYTES,
                "host identity hash");
        androidIdentitySpkiSha256 = requireLength(
                builder.androidIdentitySpkiSha256,
                AuthenticatedPeerHandshakeV1.SHA256_BYTES,
                "Android identity hash");
        if (AuthenticatedPeerHandshakeV1Internals.isAllZero(hostIdentitySpkiSha256)
                || AuthenticatedPeerHandshakeV1Internals.isAllZero(
                        androidIdentitySpkiSha256)) {
            throw new IllegalArgumentException("identity hashes must be non-zero");
        }
        if (Arrays.equals(hostIdentitySpkiSha256, androidIdentitySpkiSha256)) {
            throw new IllegalArgumentException("host and Android identity hashes must differ");
        }
        hostEphemeralPublicKey = requirePoint(
                builder.hostEphemeralPublicKey, "host ephemeral public key");
        androidEphemeralPublicKey = requirePoint(
                builder.androidEphemeralPublicKey, "Android ephemeral public key");
        if (Arrays.equals(hostEphemeralPublicKey, androidEphemeralPublicKey)) {
            throw new IllegalArgumentException("host and Android ephemeral keys must differ");
        }
        hostNonce = requireNonce(builder.hostNonce, "host nonce");
        androidNonce = requireNonce(builder.androidNonce, "Android nonce");
        if (Arrays.equals(hostNonce, androidNonce)) {
            throw new IllegalArgumentException("host and Android nonces must differ");
        }
        if (builder.connectionId == 0L) {
            throw new IllegalArgumentException("connection id must be non-zero u64");
        }
        if (builder.sessionGeneration == 0L) {
            throw new IllegalArgumentException("session generation must be non-zero u64");
        }
        connectionId = builder.connectionId;
        sessionGeneration = builder.sessionGeneration;
        if (builder.transportKind == null) {
            throw new IllegalArgumentException("transport kind is required");
        }
        transportKind = builder.transportKind;
        hostIpv4 = requireLength(builder.hostIpv4, 4, "host IPv4");
        androidIpv4 = requireLength(builder.androidIpv4, 4, "Android IPv4");
        videoPort = requirePort(builder.videoPort, "video port");
        controlPort = requirePort(builder.controlPort, "control port");
        if (videoPort == controlPort) {
            throw new IllegalArgumentException("video and control ports must be distinct");
        }
        pairId = requirePairId(builder.pairId);
        hostRuntimeVersion = requireStableSemVer(
                builder.hostRuntimeVersion, "host runtime version");
        androidRuntimeVersion = requireStableSemVer(
                builder.androidRuntimeVersion, "Android runtime version");
        canonicalEncoding = encodeCanonical();
    }

    static HandshakeTranscriptV1 parse(byte[] encoded)
            throws AuthenticatedPeerHandshakeV1Exception {
        try {
            return parseUntrusted(encoded);
        } catch (IllegalArgumentException | IndexOutOfBoundsException rejected) {
            throw AuthenticatedPeerHandshakeV1Internals.unauthenticatedFailure();
        }
    }

    /** Returns a defensive copy of the exact canonical TLV bytes signed by both identities. */
    public byte[] canonicalEncoding() {
        return canonicalEncoding.clone();
    }

    public byte[] transcriptHashSha256() throws AuthenticatedPeerHandshakeV1Exception {
        try {
            return AuthenticatedPeerHandshakeV1Internals.sha256(canonicalEncoding);
        } catch (GeneralSecurityException | RuntimeException failure) {
            throw AuthenticatedPeerHandshakeV1Internals.cryptoFailure();
        }
    }

    public byte[] hostIdentitySpkiSha256() {
        return hostIdentitySpkiSha256.clone();
    }

    public byte[] androidIdentitySpkiSha256() {
        return androidIdentitySpkiSha256.clone();
    }

    public byte[] hostEphemeralPublicKey() {
        return hostEphemeralPublicKey.clone();
    }

    public byte[] androidEphemeralPublicKey() {
        return androidEphemeralPublicKey.clone();
    }

    public byte[] hostNonce() {
        return hostNonce.clone();
    }

    public byte[] androidNonce() {
        return androidNonce.clone();
    }

    /** Returns the canonical unsigned-u64 connection-id bit pattern. */
    public long connectionId() {
        return connectionId;
    }

    /** Returns the canonical unsigned-u64 generation bit pattern. */
    public long sessionGeneration() {
        return sessionGeneration;
    }

    public AuthenticatedPeerHandshakeV1.TransportKind transportKind() {
        return transportKind;
    }

    public byte[] hostIpv4() {
        return hostIpv4.clone();
    }

    public byte[] androidIpv4() {
        return androidIpv4.clone();
    }

    public int videoPort() {
        return videoPort;
    }

    public int controlPort() {
        return controlPort;
    }

    public String pairId() {
        return pairId;
    }

    public String hostRuntimeVersion() {
        return hostRuntimeVersion;
    }

    public String androidRuntimeVersion() {
        return androidRuntimeVersion;
    }

    private static HandshakeTranscriptV1 parseUntrusted(byte[] encoded) {
        if (encoded == null || encoded.length > MAX_CANONICAL_TRANSCRIPT_BYTES) {
            throw new IllegalArgumentException("transcript container is invalid");
        }
        byte[] encodedCopy = encoded.clone();
        ByteBuffer input = ByteBuffer.wrap(encodedCopy);
        byte[][] values = new byte[FIELD_COUNT][];
        try {
            for (int expectedTag = 0; expectedTag < FIELD_COUNT; expectedTag++) {
                if (input.remaining() < TLV_HEADER_BYTES) {
                    throw new IllegalArgumentException("transcript is missing a field");
                }
                int actualTag = Byte.toUnsignedInt(input.get());
                if (actualTag != expectedTag) {
                    throw new IllegalArgumentException(
                            "transcript field is unknown, duplicated, or out of order");
                }
                long unsignedLength = Integer.toUnsignedLong(input.getInt());
                int maximumLength = maximumFieldLength(expectedTag);
                if (unsignedLength > maximumLength || unsignedLength > input.remaining()) {
                    throw new IllegalArgumentException("transcript field length is invalid");
                }
                int checkedLength = (int) unsignedLength;
                values[expectedTag] = new byte[checkedLength];
                input.get(values[expectedTag]);
            }
            if (input.hasRemaining()) {
                throw new IllegalArgumentException("transcript contains trailing fields or bytes");
            }
            requireExact(values[0], DOMAIN_BYTES, "domain");
            if (requireU32(values[1], "protocol version")
                    != AuthenticatedPeerHandshakeV1.PROTOCOL_VERSION) {
                throw new IllegalArgumentException("protocol version is unsupported");
            }
            AuthenticatedPeerHandshakeV1.TransportKind parsedTransport =
                    AuthenticatedPeerHandshakeV1.TransportKind.fromWireCode(
                            requireU8(values[10], "transport kind"));
            if (parsedTransport == null) {
                throw new IllegalArgumentException("transport kind is unsupported");
            }
            HandshakeTranscriptV1 parsed =
                    new Builder()
                            .hostIdentitySpkiSha256(values[2])
                            .androidIdentitySpkiSha256(values[3])
                            .hostEphemeralPublicKey(values[4])
                            .androidEphemeralPublicKey(values[5])
                            .hostNonce(values[6])
                            .androidNonce(values[7])
                            .connectionId(requireU64(values[8], "connection id"))
                            .sessionGeneration(requireU64(values[9], "session generation"))
                            .transportKind(parsedTransport)
                            .hostIpv4(values[11])
                            .androidIpv4(values[12])
                            .videoPort(requireU16(values[13], "video port"))
                            .controlPort(requireU16(values[14], "control port"))
                            .pairId(requireAsciiString(values[15], "pair id"))
                            .hostRuntimeVersion(
                                    requireAsciiString(values[16], "host runtime version"))
                            .androidRuntimeVersion(
                                    requireAsciiString(values[17], "Android runtime version"))
                            .build();
            if (!Arrays.equals(parsed.canonicalEncoding, encodedCopy)) {
                throw new IllegalArgumentException("transcript is not canonical");
            }
            return parsed;
        } finally {
            for (byte[] value : values) AuthenticatedPeerHandshakeV1Internals.clear(value);
            AuthenticatedPeerHandshakeV1Internals.clear(encodedCopy);
        }
    }

    private byte[] encodeCanonical() {
        byte[][] values = {
            DOMAIN_BYTES.clone(),
            ByteBuffer.allocate(Integer.BYTES)
                    .putInt(AuthenticatedPeerHandshakeV1.PROTOCOL_VERSION)
                    .array(),
            hostIdentitySpkiSha256.clone(),
            androidIdentitySpkiSha256.clone(),
            hostEphemeralPublicKey.clone(),
            androidEphemeralPublicKey.clone(),
            hostNonce.clone(),
            androidNonce.clone(),
            ByteBuffer.allocate(Long.BYTES).putLong(connectionId).array(),
            ByteBuffer.allocate(Long.BYTES).putLong(sessionGeneration).array(),
            new byte[] {(byte) transportKind.wireCode()},
            hostIpv4.clone(),
            androidIpv4.clone(),
            ByteBuffer.allocate(Short.BYTES).putShort((short) videoPort).array(),
            ByteBuffer.allocate(Short.BYTES).putShort((short) controlPort).array(),
            pairId.getBytes(StandardCharsets.US_ASCII),
            hostRuntimeVersion.getBytes(StandardCharsets.US_ASCII),
            androidRuntimeVersion.getBytes(StandardCharsets.US_ASCII)
        };
        ByteArrayOutputStream output = new ByteArrayOutputStream(MAX_CANONICAL_TRANSCRIPT_BYTES);
        try {
            for (int tag = 0; tag < values.length; tag++) {
                output.write(tag);
                byte[] length = ByteBuffer.allocate(Integer.BYTES).putInt(values[tag].length).array();
                output.write(length, 0, length.length);
                output.write(values[tag], 0, values[tag].length);
                AuthenticatedPeerHandshakeV1Internals.clear(length);
            }
            byte[] encoded = output.toByteArray();
            if (encoded.length > MAX_CANONICAL_TRANSCRIPT_BYTES) {
                AuthenticatedPeerHandshakeV1Internals.clear(encoded);
                throw new IllegalArgumentException("canonical transcript exceeds its byte limit");
            }
            return encoded;
        } finally {
            for (byte[] value : values) AuthenticatedPeerHandshakeV1Internals.clear(value);
        }
    }

    private static byte[] requireLength(byte[] value, int length, String fieldName) {
        if (value == null || value.length != length) {
            throw new IllegalArgumentException(fieldName + " has an invalid length");
        }
        return value.clone();
    }

    private static byte[] requirePoint(byte[] value, String fieldName) {
        byte[] copy = requireLength(
                value,
                AuthenticatedPeerHandshakeV1.P256_SEC1_UNCOMPRESSED_BYTES,
                fieldName);
        try {
            AuthenticatedPeerHandshakeV1Internals.requireP256Point(copy);
            return copy;
        } catch (IllegalArgumentException invalidPoint) {
            AuthenticatedPeerHandshakeV1Internals.clear(copy);
            throw new IllegalArgumentException(fieldName + " is not a valid P-256 point");
        }
    }

    private static byte[] requireNonce(byte[] value, String fieldName) {
        byte[] copy = requireLength(value, AuthenticatedPeerHandshakeV1.NONCE_BYTES, fieldName);
        if (AuthenticatedPeerHandshakeV1Internals.isAllZero(copy)) {
            AuthenticatedPeerHandshakeV1Internals.clear(copy);
            throw new IllegalArgumentException(fieldName + " must not be all zero");
        }
        return copy;
    }

    private static int requirePort(int value, String fieldName) {
        if (value < 1 || value > 0xffff) {
            throw new IllegalArgumentException(fieldName + " must be non-zero u16");
        }
        return value;
    }

    private static String requirePairId(String value) {
        byte[] encoded = AuthenticatedPeerHandshakeV1Internals.strictAscii(
                value, 0, MAX_PAIR_ID_BYTES, "pair id");
        try {
            for (byte current : encoded) {
                int character = current & 0xff;
                boolean allowed =
                        character >= 'A' && character <= 'Z'
                                || character >= 'a' && character <= 'z'
                                || character >= '0' && character <= '9'
                                || character == '.'
                                || character == '_'
                                || character == ':'
                                || character == '-';
                if (!allowed) {
                    throw new IllegalArgumentException("pair id contains a disallowed character");
                }
            }
            return value;
        } finally {
            AuthenticatedPeerHandshakeV1Internals.clear(encoded);
        }
    }

    private static String requireStableSemVer(String value, String fieldName) {
        byte[] encoded = AuthenticatedPeerHandshakeV1Internals.strictAscii(
                value, 1, MAX_RUNTIME_VERSION_BYTES, fieldName);
        try {
            if (value.indexOf('+') >= 0 || value.indexOf('-') >= 0) {
                throw new IllegalArgumentException(fieldName + " is not stable SemVer");
            }
            String[] numeric = value.split("\\.", -1);
            if (numeric.length != 3) {
                throw new IllegalArgumentException(fieldName + " is not stable SemVer");
            }
            for (String identifier : numeric) requireSemVerNumber(identifier, fieldName);
            return value;
        } finally {
            AuthenticatedPeerHandshakeV1Internals.clear(encoded);
        }
    }

    private static void requireSemVerNumber(String value, String fieldName) {
        if (value.isEmpty() || value.length() > 1 && value.charAt(0) == '0') {
            throw new IllegalArgumentException(fieldName + " is not stable SemVer");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character < '0' || character > '9') {
                throw new IllegalArgumentException(fieldName + " is not stable SemVer");
            }
        }
    }

    private static int maximumFieldLength(int tag) {
        switch (tag) {
            case 0:
                return DOMAIN_BYTES.length;
            case 1:
                return Integer.BYTES;
            case 2:
            case 3:
            case 6:
            case 7:
                return 32;
            case 4:
            case 5:
                return 65;
            case 8:
            case 9:
                return Long.BYTES;
            case 10:
                return 1;
            case 11:
            case 12:
                return 4;
            case 13:
            case 14:
                return Short.BYTES;
            case 15:
                return MAX_PAIR_ID_BYTES;
            case 16:
            case 17:
                return MAX_RUNTIME_VERSION_BYTES;
            default:
                throw new IllegalArgumentException("unknown transcript field");
        }
    }

    private static void requireExact(byte[] actual, byte[] expected, String fieldName) {
        if (!Arrays.equals(actual, expected)) {
            throw new IllegalArgumentException(fieldName + " is not canonical");
        }
    }

    private static int requireU8(byte[] value, String fieldName) {
        if (value.length != 1) throw new IllegalArgumentException(fieldName + " is not u8");
        return Byte.toUnsignedInt(value[0]);
    }

    private static int requireU16(byte[] value, String fieldName) {
        if (value.length != Short.BYTES) {
            throw new IllegalArgumentException(fieldName + " is not u16");
        }
        return Short.toUnsignedInt(ByteBuffer.wrap(value).getShort());
    }

    private static int requireU32(byte[] value, String fieldName) {
        if (value.length != Integer.BYTES) {
            throw new IllegalArgumentException(fieldName + " is not u32");
        }
        return ByteBuffer.wrap(value).getInt();
    }

    private static long requireU64(byte[] value, String fieldName) {
        if (value.length != Long.BYTES) {
            throw new IllegalArgumentException(fieldName + " is not u64");
        }
        return ByteBuffer.wrap(value).getLong();
    }

    private static String requireAsciiString(byte[] value, String fieldName) {
        for (byte current : value) {
            if ((current & 0x80) != 0 || current == 0) {
                throw new IllegalArgumentException(fieldName + " is not strict ASCII");
            }
        }
        return new String(value, StandardCharsets.US_ASCII);
    }

    /**
     * Builder for locally constructed transcripts. Every non-fixed field is mandatory.
     *
     * <p>Each nonce must be generated independently as a uniform 32-byte CSPRNG value. Runtime
     * validation can prove only its shape, so it rejects an all-zero value and role reuse but
     * cannot infer whether a caller used an adequate entropy source.
     */
    public static final class Builder {
        private byte[] hostIdentitySpkiSha256;
        private byte[] androidIdentitySpkiSha256;
        private byte[] hostEphemeralPublicKey;
        private byte[] androidEphemeralPublicKey;
        private byte[] hostNonce;
        private byte[] androidNonce;
        private long connectionId;
        private long sessionGeneration;
        private AuthenticatedPeerHandshakeV1.TransportKind transportKind;
        private byte[] hostIpv4;
        private byte[] androidIpv4;
        private int videoPort;
        private int controlPort;
        private String pairId;
        private String hostRuntimeVersion;
        private String androidRuntimeVersion;

        Builder() {}

        public Builder hostIdentitySpkiSha256(byte[] value) {
            hostIdentitySpkiSha256 = copy(value);
            return this;
        }

        public Builder androidIdentitySpkiSha256(byte[] value) {
            androidIdentitySpkiSha256 = copy(value);
            return this;
        }

        public Builder hostEphemeralPublicKey(byte[] value) {
            hostEphemeralPublicKey = copy(value);
            return this;
        }

        public Builder androidEphemeralPublicKey(byte[] value) {
            androidEphemeralPublicKey = copy(value);
            return this;
        }

        public Builder hostNonce(byte[] value) {
            hostNonce = copy(value);
            return this;
        }

        public Builder androidNonce(byte[] value) {
            androidNonce = copy(value);
            return this;
        }

        public Builder connectionId(long value) {
            connectionId = value;
            return this;
        }

        public Builder sessionGeneration(long value) {
            sessionGeneration = value;
            return this;
        }

        public Builder transportKind(AuthenticatedPeerHandshakeV1.TransportKind value) {
            transportKind = value;
            return this;
        }

        public Builder hostIpv4(byte[] value) {
            hostIpv4 = copy(value);
            return this;
        }

        public Builder androidIpv4(byte[] value) {
            androidIpv4 = copy(value);
            return this;
        }

        public Builder videoPort(int value) {
            videoPort = value;
            return this;
        }

        public Builder controlPort(int value) {
            controlPort = value;
            return this;
        }

        public Builder pairId(String value) {
            pairId = value;
            return this;
        }

        public Builder hostRuntimeVersion(String value) {
            hostRuntimeVersion = value;
            return this;
        }

        public Builder androidRuntimeVersion(String value) {
            androidRuntimeVersion = value;
            return this;
        }

        public HandshakeTranscriptV1 build() {
            return new HandshakeTranscriptV1(this);
        }

        private static byte[] copy(byte[] value) {
            return value == null ? null : value.clone();
        }
    }
}
