package com.visionforge.inferencebenchmark.handshake;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Immutable canonical pre-generation proposal v1.
 *
 * <p>This is a cryptographic foundation only. Production coordination must source {@code
 * connectionId} from a non-zero 63-bit CSPRNG or both fresh nonces plus a server challenge,
 * endpoints from the live socket/direct-link context, and {@code pairId} from the active server
 * binding. This type does not prove those authorities, allocate a generation, verify an
 * entitlement, sign a credential, or enable a production session.
 */
public final class PairGenerationProposalV1 {
    private static final byte[] DOMAIN_BYTES =
            "visionforge-peer-generation-proposal-v1"
                    .getBytes(StandardCharsets.US_ASCII);
    public static final int PROTOCOL_VERSION = 1;
    static final int FIELD_COUNT = 17;
    static final int TLV_HEADER_BYTES = 5;
    static final int MAX_CANONICAL_BYTES = 503;
    static final int PAIR_ID_BYTES = 32;
    static final int MAX_RUNTIME_VERSION_BYTES = 32;
    private static final int NO_FIELD_TAG = 0xff;

    private final byte[] hostIdentitySpkiSha256;
    private final byte[] androidIdentitySpkiSha256;
    private final byte[] hostEphemeralPublicKey;
    private final byte[] androidEphemeralPublicKey;
    private final byte[] hostNonce;
    private final byte[] androidNonce;
    private final long connectionId;
    private final AuthenticatedPeerHandshakeV1.TransportKind transportKind;
    private final byte[] hostIpv4;
    private final byte[] androidIpv4;
    private final int videoPort;
    private final int controlPort;
    private final String pairId;
    private final String hostRuntimeVersion;
    private final String androidRuntimeVersion;
    private final byte[] canonicalEncoding;
    private final byte[] proposalSha256;

    private PairGenerationProposalV1(
            byte[] hostIdentitySpkiSha256,
            byte[] androidIdentitySpkiSha256,
            byte[] hostEphemeralPublicKey,
            byte[] androidEphemeralPublicKey,
            byte[] hostNonce,
            byte[] androidNonce,
            long connectionId,
            AuthenticatedPeerHandshakeV1.TransportKind transportKind,
            byte[] hostIpv4,
            byte[] androidIpv4,
            int videoPort,
            int controlPort,
            String pairId,
            String hostRuntimeVersion,
            String androidRuntimeVersion,
            byte[] canonicalEncoding,
            byte[] proposalSha256) {
        this.hostIdentitySpkiSha256 = hostIdentitySpkiSha256;
        this.androidIdentitySpkiSha256 = androidIdentitySpkiSha256;
        this.hostEphemeralPublicKey = hostEphemeralPublicKey;
        this.androidEphemeralPublicKey = androidEphemeralPublicKey;
        this.hostNonce = hostNonce;
        this.androidNonce = androidNonce;
        this.connectionId = connectionId;
        this.transportKind = transportKind;
        this.hostIpv4 = hostIpv4;
        this.androidIpv4 = androidIpv4;
        this.videoPort = videoPort;
        this.controlPort = controlPort;
        this.pairId = pairId;
        this.hostRuntimeVersion = hostRuntimeVersion;
        this.androidRuntimeVersion = androidRuntimeVersion;
        this.canonicalEncoding = canonicalEncoding;
        this.proposalSha256 = proposalSha256;
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    /** Parses exactly one complete canonical 17-field proposal. */
    public static PairGenerationProposalV1 parse(byte[] encoded) throws ProposalException {
        if (encoded == null) throw failure(ErrorCode.OPERATION_FAILED);
        if (encoded.length > MAX_CANONICAL_BYTES) {
            throw failure(ErrorCode.PROPOSAL_TOO_LARGE);
        }
        byte[] canonical = encoded.clone();
        ByteBuffer input = ByteBuffer.wrap(canonical);
        byte[][] values = new byte[FIELD_COUNT][];
        boolean[] seen = new boolean[FIELD_COUNT];
        for (int expectedTag = 0; expectedTag < FIELD_COUNT; expectedTag++) {
            if (!input.hasRemaining()) {
                throw failure(ErrorCode.MISSING_FIELD, expectedTag);
            }
            if (input.remaining() < TLV_HEADER_BYTES) {
                throw failure(ErrorCode.TRUNCATED_TLV);
            }
            int actualTag = Byte.toUnsignedInt(input.get());
            if (actualTag >= FIELD_COUNT) {
                throw failure(ErrorCode.UNKNOWN_TAG, actualTag);
            }
            if (seen[actualTag]) {
                throw failure(ErrorCode.DUPLICATE_TAG, actualTag);
            }
            if (actualTag != expectedTag) {
                throw failure(ErrorCode.OUT_OF_ORDER_TAG, actualTag);
            }
            long encodedLength = Integer.toUnsignedLong(input.getInt());
            if (encodedLength > maximumFieldLength(actualTag)) {
                throw failure(ErrorCode.INVALID_FIELD_LENGTH, actualTag);
            }
            if (encodedLength > input.remaining()) {
                throw failure(ErrorCode.TRUNCATED_TLV, actualTag);
            }
            values[actualTag] = new byte[(int) encodedLength];
            input.get(values[actualTag]);
            seen[actualTag] = true;
        }
        if (input.hasRemaining()) throw failure(ErrorCode.TRAILING_DATA);
        requireExact(values[0], DOMAIN_BYTES, ErrorCode.INVALID_DOMAIN, 0);
        requireLength(values[1], Integer.BYTES, 1);
        if (ByteBuffer.wrap(values[1]).getInt() != PROTOCOL_VERSION) {
            throw failure(ErrorCode.UNSUPPORTED_VERSION, 1);
        }
        AuthenticatedPeerHandshakeV1.TransportKind parsedTransport =
                requireTransport(values[9]);
        PairGenerationProposalV1 parsed =
                new Builder()
                        .hostIdentitySpkiSha256(values[2])
                        .androidIdentitySpkiSha256(values[3])
                        .hostEphemeralPublicKey(values[4])
                        .androidEphemeralPublicKey(values[5])
                        .hostNonce(values[6])
                        .androidNonce(values[7])
                        .connectionId(requirePositiveSigned64(values[8], 8))
                        .transportKind(parsedTransport)
                        .hostIpv4(values[10])
                        .androidIpv4(values[11])
                        .videoPort(requireU16(values[12], 12))
                        .controlPort(requireU16(values[13], 13))
                        .pairId(requireAscii(values[14], 14))
                        .hostRuntimeVersion(requireAscii(values[15], 15))
                        .androidRuntimeVersion(requireAscii(values[16], 16))
                        .build();
        if (!Arrays.equals(parsed.canonicalEncoding, canonical)) {
            throw failure(ErrorCode.NONCANONICAL_ENCODING);
        }
        return parsed;
    }

    public byte[] canonicalEncoding() {
        return canonicalEncoding.clone();
    }

    public byte[] proposalSha256() {
        return proposalSha256.clone();
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

    public long connectionId() {
        return connectionId;
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

    /**
     * Inserts only the server-authoritative positive signed-64 generation into the existing final
     * 18-field transcript builder.
     */
    public HandshakeTranscriptV1 buildFinalHandshakeTranscript(long generation)
            throws ProposalException {
        if (generation <= 0L) throw failure(ErrorCode.INVALID_GENERATION, 9);
        try {
            return AuthenticatedPeerHandshakeV1.newTranscriptBuilder()
                    .hostIdentitySpkiSha256(hostIdentitySpkiSha256)
                    .androidIdentitySpkiSha256(androidIdentitySpkiSha256)
                    .hostEphemeralPublicKey(hostEphemeralPublicKey)
                    .androidEphemeralPublicKey(androidEphemeralPublicKey)
                    .hostNonce(hostNonce)
                    .androidNonce(androidNonce)
                    .connectionId(connectionId)
                    .sessionGeneration(generation)
                    .transportKind(transportKind)
                    .hostIpv4(hostIpv4)
                    .androidIpv4(androidIpv4)
                    .videoPort(videoPort)
                    .controlPort(controlPort)
                    .pairId(pairId)
                    .hostRuntimeVersion(hostRuntimeVersion)
                    .androidRuntimeVersion(androidRuntimeVersion)
                    .build();
        } catch (RuntimeException rejected) {
            throw failure(ErrorCode.OPERATION_FAILED);
        }
    }

    private static PairGenerationProposalV1 build(Builder builder) throws ProposalException {
        byte[] hostIdentity = requireIdentity(builder.hostIdentitySpkiSha256, 2);
        byte[] androidIdentity = requireIdentity(builder.androidIdentitySpkiSha256, 3);
        if (Arrays.equals(hostIdentity, androidIdentity)) {
            throw failure(ErrorCode.INVALID_IDENTITY_BINDING, 3);
        }
        byte[] hostPublic = requirePoint(builder.hostEphemeralPublicKey, 4);
        byte[] androidPublic = requirePoint(builder.androidEphemeralPublicKey, 5);
        if (Arrays.equals(hostPublic, androidPublic)) {
            throw failure(ErrorCode.INVALID_EPHEMERAL_PUBLIC_KEY, 5);
        }
        byte[] checkedHostNonce = requireNonce(builder.hostNonce, 6);
        byte[] checkedAndroidNonce = requireNonce(builder.androidNonce, 7);
        if (Arrays.equals(checkedHostNonce, checkedAndroidNonce)) {
            throw failure(ErrorCode.INVALID_NONCE, 7);
        }
        if (builder.connectionId <= 0L) {
            throw failure(ErrorCode.INVALID_CONNECTION_ID, 8);
        }
        if (builder.transportKind == null) {
            throw failure(ErrorCode.INVALID_TRANSPORT_KIND, 9);
        }
        byte[] checkedHostIpv4 = requireBytes(builder.hostIpv4, 4, 10);
        byte[] checkedAndroidIpv4 = requireBytes(builder.androidIpv4, 4, 11);
        int checkedVideoPort = requirePort(builder.videoPort, 12);
        int checkedControlPort = requirePort(builder.controlPort, 13);
        if (checkedVideoPort == checkedControlPort) {
            throw failure(ErrorCode.INVALID_ENDPOINT, 13);
        }
        String checkedPairId = requirePairId(builder.pairId);
        String checkedHostVersion = requireStableSemVer(builder.hostRuntimeVersion, 15);
        String checkedAndroidVersion = requireStableSemVer(builder.androidRuntimeVersion, 16);
        byte[] canonical =
                encode(
                        hostIdentity,
                        androidIdentity,
                        hostPublic,
                        androidPublic,
                        checkedHostNonce,
                        checkedAndroidNonce,
                        builder.connectionId,
                        builder.transportKind,
                        checkedHostIpv4,
                        checkedAndroidIpv4,
                        checkedVideoPort,
                        checkedControlPort,
                        checkedPairId,
                        checkedHostVersion,
                        checkedAndroidVersion);
        if (canonical.length > MAX_CANONICAL_BYTES) {
            throw failure(ErrorCode.PROPOSAL_TOO_LARGE);
        }
        byte[] digest;
        try {
            digest = AuthenticatedPeerHandshakeV1Internals.sha256(canonical);
        } catch (GeneralSecurityException | RuntimeException unavailable) {
            throw failure(ErrorCode.CRYPTO_UNAVAILABLE);
        }
        return new PairGenerationProposalV1(
                hostIdentity,
                androidIdentity,
                hostPublic,
                androidPublic,
                checkedHostNonce,
                checkedAndroidNonce,
                builder.connectionId,
                builder.transportKind,
                checkedHostIpv4,
                checkedAndroidIpv4,
                checkedVideoPort,
                checkedControlPort,
                checkedPairId,
                checkedHostVersion,
                checkedAndroidVersion,
                canonical,
                digest);
    }

    private static byte[] encode(
            byte[] hostIdentity,
            byte[] androidIdentity,
            byte[] hostPublic,
            byte[] androidPublic,
            byte[] checkedHostNonce,
            byte[] checkedAndroidNonce,
            long checkedConnectionId,
            AuthenticatedPeerHandshakeV1.TransportKind checkedTransport,
            byte[] checkedHostIpv4,
            byte[] checkedAndroidIpv4,
            int checkedVideoPort,
            int checkedControlPort,
            String checkedPairId,
            String checkedHostVersion,
            String checkedAndroidVersion) {
        byte[][] values = {
            DOMAIN_BYTES,
            ByteBuffer.allocate(Integer.BYTES).putInt(PROTOCOL_VERSION).array(),
            hostIdentity,
            androidIdentity,
            hostPublic,
            androidPublic,
            checkedHostNonce,
            checkedAndroidNonce,
            ByteBuffer.allocate(Long.BYTES).putLong(checkedConnectionId).array(),
            new byte[] {(byte) checkedTransport.wireCode()},
            checkedHostIpv4,
            checkedAndroidIpv4,
            ByteBuffer.allocate(Short.BYTES).putShort((short) checkedVideoPort).array(),
            ByteBuffer.allocate(Short.BYTES).putShort((short) checkedControlPort).array(),
            checkedPairId.getBytes(StandardCharsets.US_ASCII),
            checkedHostVersion.getBytes(StandardCharsets.US_ASCII),
            checkedAndroidVersion.getBytes(StandardCharsets.US_ASCII)
        };
        ByteArrayOutputStream output = new ByteArrayOutputStream(MAX_CANONICAL_BYTES);
        for (int tag = 0; tag < values.length; tag++) {
            byte[] value = values[tag];
            output.write(tag);
            byte[] length = ByteBuffer.allocate(Integer.BYTES).putInt(value.length).array();
            output.write(length, 0, length.length);
            output.write(value, 0, value.length);
        }
        return output.toByteArray();
    }

    private static byte[] requireIdentity(byte[] value, int tag) throws ProposalException {
        byte[] checked = requireBytes(value, AuthenticatedPeerHandshakeV1.SHA256_BYTES, tag);
        if (AuthenticatedPeerHandshakeV1Internals.isAllZero(checked)) {
            throw failure(ErrorCode.INVALID_IDENTITY_BINDING, tag);
        }
        return checked;
    }

    private static byte[] requirePoint(byte[] value, int tag) throws ProposalException {
        byte[] checked = requireBytes(
                value,
                AuthenticatedPeerHandshakeV1.P256_SEC1_UNCOMPRESSED_BYTES,
                tag);
        boolean invalid = false;
        boolean unavailable = false;
        try {
            AuthenticatedPeerHandshakeV1Internals.requireP256Point(checked);
        } catch (IllegalArgumentException rejected) {
            invalid = true;
        } catch (RuntimeException rejected) {
            unavailable = true;
        }
        if (invalid) throw failure(ErrorCode.INVALID_EPHEMERAL_PUBLIC_KEY, tag);
        if (unavailable) throw failure(ErrorCode.CRYPTO_UNAVAILABLE, tag);
        return checked;
    }

    private static byte[] requireNonce(byte[] value, int tag) throws ProposalException {
        byte[] checked = requireBytes(value, AuthenticatedPeerHandshakeV1.NONCE_BYTES, tag);
        if (AuthenticatedPeerHandshakeV1Internals.isAllZero(checked)) {
            throw failure(ErrorCode.INVALID_NONCE, tag);
        }
        return checked;
    }

    private static byte[] requireBytes(byte[] value, int length, int tag)
            throws ProposalException {
        if (value == null || value.length != length) {
            throw failure(ErrorCode.INVALID_FIELD_LENGTH, tag);
        }
        return value.clone();
    }

    private static int requirePort(int value, int tag) throws ProposalException {
        if (value < 1 || value > 0xffff) {
            throw failure(ErrorCode.INVALID_ENDPOINT, tag);
        }
        return value;
    }

    private static String requirePairId(String value) throws ProposalException {
        if (value == null || value.length() != PAIR_ID_BYTES) {
            throw failure(ErrorCode.INVALID_PAIR_ID, 14);
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f'))) {
                throw failure(ErrorCode.INVALID_PAIR_ID, 14);
            }
        }
        return value;
    }

    private static String requireStableSemVer(String value, int tag)
            throws ProposalException {
        if (value == null) throw failure(ErrorCode.INVALID_RUNTIME_VERSION, tag);
        byte[] encoded;
        try {
            encoded = AuthenticatedPeerHandshakeV1Internals.strictAscii(
                    value, 1, MAX_RUNTIME_VERSION_BYTES, "runtime version");
        } catch (IllegalArgumentException rejected) {
            throw failure(ErrorCode.INVALID_RUNTIME_VERSION, tag);
        }
        String[] components = value.split("\\.", -1);
        if (components.length != 3) throw failure(ErrorCode.INVALID_RUNTIME_VERSION, tag);
        for (String component : components) {
            if (component.isEmpty() || component.length() > 1 && component.charAt(0) == '0') {
                throw failure(ErrorCode.INVALID_RUNTIME_VERSION, tag);
            }
            for (int index = 0; index < component.length(); index++) {
                char character = component.charAt(index);
                if (character < '0' || character > '9') {
                    throw failure(ErrorCode.INVALID_RUNTIME_VERSION, tag);
                }
            }
        }
        Arrays.fill(encoded, (byte) 0);
        return value;
    }

    private static void requireLength(byte[] value, int expected, int tag)
            throws ProposalException {
        if (value.length != expected) throw failure(ErrorCode.INVALID_FIELD_LENGTH, tag);
    }

    private static void requireExact(
            byte[] value,
            byte[] expected,
            ErrorCode code,
            int tag)
            throws ProposalException {
        if (!Arrays.equals(value, expected)) throw failure(code, tag);
    }

    private static long requirePositiveSigned64(byte[] value, int tag)
            throws ProposalException {
        requireLength(value, Long.BYTES, tag);
        long parsed = ByteBuffer.wrap(value).getLong();
        if (parsed <= 0L) throw failure(ErrorCode.INVALID_CONNECTION_ID, tag);
        return parsed;
    }

    private static int requireU16(byte[] value, int tag) throws ProposalException {
        requireLength(value, Short.BYTES, tag);
        return Short.toUnsignedInt(ByteBuffer.wrap(value).getShort());
    }

    private static AuthenticatedPeerHandshakeV1.TransportKind requireTransport(byte[] value)
            throws ProposalException {
        requireLength(value, 1, 9);
        AuthenticatedPeerHandshakeV1.TransportKind parsed =
                AuthenticatedPeerHandshakeV1.TransportKind.fromWireCode(
                        Byte.toUnsignedInt(value[0]));
        if (parsed == null) throw failure(ErrorCode.INVALID_TRANSPORT_KIND, 9);
        return parsed;
    }

    private static String requireAscii(byte[] value, int tag) throws ProposalException {
        for (byte current : value) {
            if ((current & 0x80) != 0 || current == 0) {
                throw failure(ErrorCode.INVALID_FIELD_LENGTH, tag);
            }
        }
        return new String(value, StandardCharsets.US_ASCII);
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
            case 14:
            case 15:
            case 16:
                return 32;
            case 4:
            case 5:
                return 65;
            case 8:
                return Long.BYTES;
            case 9:
                return 1;
            case 10:
            case 11:
                return 4;
            case 12:
            case 13:
                return Short.BYTES;
            default:
                throw new AssertionError("unreachable proposal tag");
        }
    }

    private static ProposalException failure(ErrorCode code) {
        return new ProposalException(code, NO_FIELD_TAG);
    }

    private static ProposalException failure(ErrorCode code, int fieldTag) {
        return new ProposalException(code, fieldTag);
    }

    public enum ErrorCode {
        PROPOSAL_TOO_LARGE("proposal_too_large"),
        TRUNCATED_TLV("truncated_tlv"),
        UNKNOWN_TAG("unknown_tag"),
        DUPLICATE_TAG("duplicate_tag"),
        OUT_OF_ORDER_TAG("out_of_order_tag"),
        MISSING_FIELD("missing_field"),
        TRAILING_DATA("trailing_data"),
        NONCANONICAL_ENCODING("noncanonical_encoding"),
        INVALID_FIELD_LENGTH("invalid_field_length"),
        INVALID_DOMAIN("invalid_domain"),
        UNSUPPORTED_VERSION("unsupported_version"),
        INVALID_IDENTITY_BINDING("invalid_identity_binding"),
        INVALID_EPHEMERAL_PUBLIC_KEY("invalid_ephemeral_public_key"),
        INVALID_NONCE("invalid_nonce"),
        INVALID_CONNECTION_ID("invalid_connection_id"),
        INVALID_TRANSPORT_KIND("invalid_transport_kind"),
        INVALID_ENDPOINT("invalid_endpoint"),
        INVALID_PAIR_ID("invalid_pair_id"),
        INVALID_RUNTIME_VERSION("invalid_runtime_version"),
        INVALID_GENERATION("invalid_generation"),
        CRYPTO_UNAVAILABLE("crypto_unavailable"),
        OPERATION_FAILED("operation_failed");

        private final String wireName;

        ErrorCode(String wireName) {
            this.wireName = wireName;
        }
    }

    /** Sanitized checked failure containing neither raw values nor provider causes. */
    public static final class ProposalException extends Exception {
        private static final long serialVersionUID = 1L;

        private final ErrorCode code;
        private final int fieldTag;

        private ProposalException(ErrorCode code, int fieldTag) {
            super(code.wireName);
            this.code = code;
            this.fieldTag = fieldTag;
        }

        public ErrorCode code() {
            return code;
        }

        public int fieldTag() {
            return fieldTag;
        }
    }

    public static final class Builder {
        private byte[] hostIdentitySpkiSha256;
        private byte[] androidIdentitySpkiSha256;
        private byte[] hostEphemeralPublicKey;
        private byte[] androidEphemeralPublicKey;
        private byte[] hostNonce;
        private byte[] androidNonce;
        private long connectionId;
        private AuthenticatedPeerHandshakeV1.TransportKind transportKind;
        private byte[] hostIpv4;
        private byte[] androidIpv4;
        private int videoPort;
        private int controlPort;
        private String pairId;
        private String hostRuntimeVersion;
        private String androidRuntimeVersion;

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

        public PairGenerationProposalV1 build() throws ProposalException {
            return PairGenerationProposalV1.build(this);
        }

        private static byte[] copy(byte[] value) {
            return value == null ? null : value.clone();
        }
    }
}
