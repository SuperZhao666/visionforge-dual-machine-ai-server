package com.visionforge.inferencebenchmark.handshake;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/** Java 8 executable contract for the pre-generation proposal v1 foundation. */
public final class PairGenerationProposalV1SelfTest {
    private static final String HOST_PUBLIC_HEX =
            "046b17d1f2e12c4247f8bce6e563a440"
                    + "f277037d812deb33a0f4a13945d898c296"
                    + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e"
                    + "162bce33576b315ececbb6406837bf51f5";
    private static final String ANDROID_PUBLIC_HEX =
            "047cf27b188d034f7e8a52380304b51a"
                    + "c3c08969e277f21b35a60b48fc47669978"
                    + "07775510db8ed040293d9ac69f7430d"
                    + "bba7dade63ce982299e04b79d227873d1";
    private static final String PROPOSAL_CANONICAL_HEX =
            "0000000027766973696f6e666f7267652d706565722d67656e65726174696f6e2d"
                    + "70726f706f73616c2d763101000000040000000102000000200001020304050607"
                    + "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f030000002020212223"
                    + "2425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0400000041"
                    + "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                    + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f505"
                    + "00000041047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc"
                    + "4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227"
                    + "873d10600000020404142434445464748494a4b4c4d4e4f50515253545556575859"
                    + "5a5b5c5d5e5f0700000020606162636465666768696a6b6c6d6e6f707172737475"
                    + "767778797a7b7c7d7e7f080000000810203040506070800900000001010a000000"
                    + "04c0a837010b00000004c0a837020c00000002b26e0d00000002b26f0e00000020"
                    + "30313233343536373839616263646566303132333435363738396162636465660f00"
                    + "00000731372e382e3437100000000731372e382e3437";
    private static final String PROPOSAL_SHA256_HEX =
            "89669a6d4e73b4ae9e9e44e042c75426a520f611009077d5caa5a8fafad9732d";
    private static final String FINAL_TRANSCRIPT_SHA256_HEX =
            "ea8f01700d0921665958fcb8dc0f9abf657499cc7423ff37dd6efbd233025098";
    private static final long VECTOR_GENERATION = 0x0102_0304_0506_0708L;

    private PairGenerationProposalV1SelfTest() {}

    public static void main(String[] arguments) throws Exception {
        require(arguments.length == 0, "self-test accepts no arguments");
        verifiesFrozenCrossLanguageVectorAndFinalMapping();
        verifiesDefensiveOwnership();
        verifiesStrictCanonicalParser();
        verifiesBuilderBoundaries();
        verifiesSigned64GenerationAndRestrictedApi();
        System.out.println("PairGenerationProposalV1SelfTest: PASS");
    }

    private static void verifiesFrozenCrossLanguageVectorAndFinalMapping()
            throws Exception {
        PairGenerationProposalV1 proposal = vectorBuilder().build();
        byte[] canonical = proposal.canonicalEncoding();
        require(canonical.length == 453, "proposal canonical length");
        requireBytes(canonical, hex(PROPOSAL_CANONICAL_HEX), "proposal canonical bytes");
        requireHex(proposal.proposalSha256(), PROPOSAL_SHA256_HEX, "proposal SHA-256");

        PairGenerationProposalV1 parsed = PairGenerationProposalV1.parse(canonical);
        requireBytes(parsed.canonicalEncoding(), canonical, "proposal parse round trip");
        requireBytes(
                parsed.proposalSha256(),
                proposal.proposalSha256(),
                "parsed proposal SHA-256");

        HandshakeTranscriptV1 transcript =
                proposal.buildFinalHandshakeTranscript(VECTOR_GENERATION);
        require(transcript.canonicalEncoding().length == 456, "final transcript length");
        requireHex(
                transcript.transcriptHashSha256(),
                FINAL_TRANSCRIPT_SHA256_HEX,
                "final transcript SHA-256");
        requireBytes(
                transcript.hostIdentitySpkiSha256(),
                proposal.hostIdentitySpkiSha256(),
                "host identity mapping");
        requireBytes(
                transcript.androidIdentitySpkiSha256(),
                proposal.androidIdentitySpkiSha256(),
                "Android identity mapping");
        requireBytes(
                transcript.hostEphemeralPublicKey(),
                proposal.hostEphemeralPublicKey(),
                "host ephemeral mapping");
        requireBytes(
                transcript.androidEphemeralPublicKey(),
                proposal.androidEphemeralPublicKey(),
                "Android ephemeral mapping");
        requireBytes(transcript.hostNonce(), proposal.hostNonce(), "host nonce mapping");
        requireBytes(
                transcript.androidNonce(), proposal.androidNonce(), "Android nonce mapping");
        require(transcript.connectionId() == proposal.connectionId(), "connection mapping");
        require(transcript.sessionGeneration() == VECTOR_GENERATION, "generation insertion");
        require(transcript.transportKind() == proposal.transportKind(), "transport mapping");
        requireBytes(transcript.hostIpv4(), proposal.hostIpv4(), "host endpoint mapping");
        requireBytes(
                transcript.androidIpv4(), proposal.androidIpv4(), "Android endpoint mapping");
        require(transcript.videoPort() == proposal.videoPort(), "video port mapping");
        require(transcript.controlPort() == proposal.controlPort(), "control port mapping");
        require(transcript.pairId().equals(proposal.pairId()), "pair id mapping");
        require(
                transcript.hostRuntimeVersion().equals(proposal.hostRuntimeVersion()),
                "host version mapping");
        require(
                transcript.androidRuntimeVersion().equals(proposal.androidRuntimeVersion()),
                "Android version mapping");

        List<FieldSpan> proposalFields = fields(canonical);
        List<FieldSpan> finalFields = fields(transcript.canonicalEncoding());
        require(proposalFields.size() == 17, "proposal TLV count");
        require(finalFields.size() == 18, "final TLV count");
        for (int tag = 1; tag <= 8; tag++) {
            requireBytes(
                    value(canonical, proposalFields.get(tag)),
                    value(transcript.canonicalEncoding(), finalFields.get(tag)),
                    "pre-generation prefix field " + tag);
        }
        for (int proposalTag = 9; proposalTag < 17; proposalTag++) {
            requireBytes(
                    value(canonical, proposalFields.get(proposalTag)),
                    value(transcript.canonicalEncoding(), finalFields.get(proposalTag + 1)),
                    "post-generation field " + proposalTag);
        }
    }

    private static void verifiesDefensiveOwnership() throws Exception {
        byte[] hostNonce = sequence(0x40, 32);
        PairGenerationProposalV1.Builder builder = vectorBuilder().hostNonce(hostNonce);
        hostNonce[0] = 0;
        PairGenerationProposalV1 proposal = builder.build();
        require((proposal.hostNonce()[0] & 0xff) == 0x40, "builder defensive copy");

        byte[] returnedNonce = proposal.hostNonce();
        returnedNonce[0] = 0;
        require((proposal.hostNonce()[0] & 0xff) == 0x40, "getter defensive copy");
        byte[] returnedCanonical = proposal.canonicalEncoding();
        returnedCanonical[0] ^= 1;
        require(proposal.canonicalEncoding()[0] == 0, "canonical defensive copy");

        byte[] encoded = proposal.canonicalEncoding();
        PairGenerationProposalV1 parsed = PairGenerationProposalV1.parse(encoded);
        encoded[0] ^= 1;
        require(parsed.canonicalEncoding()[0] == 0, "parser defensive copy");
    }

    private static void verifiesStrictCanonicalParser() throws Exception {
        byte[] canonical = vectorBuilder().build().canonicalEncoding();
        List<FieldSpan> spans = fields(canonical);

        byte[] duplicate = canonical.clone();
        duplicate[spans.get(1).tagOffset] = 0;
        expectError(
                PairGenerationProposalV1.ErrorCode.DUPLICATE_TAG,
                () -> PairGenerationProposalV1.parse(duplicate));

        byte[] outOfOrder = canonical.clone();
        outOfOrder[spans.get(1).tagOffset] = 2;
        expectError(
                PairGenerationProposalV1.ErrorCode.OUT_OF_ORDER_TAG,
                () -> PairGenerationProposalV1.parse(outOfOrder));

        byte[] unknown = canonical.clone();
        unknown[spans.get(16).tagOffset] = 17;
        expectError(
                PairGenerationProposalV1.ErrorCode.UNKNOWN_TAG,
                () -> PairGenerationProposalV1.parse(unknown));

        FieldSpan removed = spans.get(7);
        byte[] missing = removeRange(canonical, removed.tagOffset, 5 + removed.length);
        expectError(
                PairGenerationProposalV1.ErrorCode.OUT_OF_ORDER_TAG,
                () -> PairGenerationProposalV1.parse(missing));

        byte[] trailing = Arrays.copyOf(canonical, canonical.length + 1);
        expectError(
                PairGenerationProposalV1.ErrorCode.TRAILING_DATA,
                () -> PairGenerationProposalV1.parse(trailing));

        byte[] truncated = Arrays.copyOf(canonical, 4);
        expectError(
                PairGenerationProposalV1.ErrorCode.TRUNCATED_TLV,
                () -> PairGenerationProposalV1.parse(truncated));

        byte[] invalidLength = canonical.clone();
        ByteBuffer.wrap(
                        invalidLength,
                        spans.get(2).lengthOffset,
                        Integer.BYTES)
                .putInt(-1);
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_FIELD_LENGTH,
                () -> PairGenerationProposalV1.parse(invalidLength));

        byte[] invalidDomain = canonical.clone();
        FieldSpan domain = spans.get(0);
        invalidDomain[domain.valueOffset + domain.length - 1] = '2';
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_DOMAIN,
                () -> PairGenerationProposalV1.parse(invalidDomain));

        byte[] unsupportedVersion = canonical.clone();
        FieldSpan version = spans.get(1);
        unsupportedVersion[version.valueOffset + 3] = 2;
        expectError(
                PairGenerationProposalV1.ErrorCode.UNSUPPORTED_VERSION,
                () -> PairGenerationProposalV1.parse(unsupportedVersion));

        expectError(
                PairGenerationProposalV1.ErrorCode.MISSING_FIELD,
                () -> PairGenerationProposalV1.parse(new byte[0]));
        expectError(
                PairGenerationProposalV1.ErrorCode.PROPOSAL_TOO_LARGE,
                () ->
                        PairGenerationProposalV1.parse(
                                new byte[PairGenerationProposalV1.MAX_CANONICAL_BYTES + 1]));
    }

    private static void verifiesBuilderBoundaries() throws Exception {
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_IDENTITY_BINDING,
                () -> vectorBuilder().hostIdentitySpkiSha256(new byte[32]).build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_IDENTITY_BINDING,
                () ->
                        vectorBuilder()
                                .androidIdentitySpkiSha256(sequence(0x00, 32))
                                .build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_EPHEMERAL_PUBLIC_KEY,
                () -> vectorBuilder().hostEphemeralPublicKey(invalidPoint()).build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_EPHEMERAL_PUBLIC_KEY,
                () ->
                        vectorBuilder()
                                .androidEphemeralPublicKey(hex(HOST_PUBLIC_HEX))
                                .build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_NONCE,
                () -> vectorBuilder().hostNonce(new byte[32]).build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_NONCE,
                () -> vectorBuilder().androidNonce(sequence(0x40, 32)).build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_CONNECTION_ID,
                () -> vectorBuilder().connectionId(0L).build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_CONNECTION_ID,
                () -> vectorBuilder().connectionId(-1L).build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_TRANSPORT_KIND,
                () -> vectorBuilder().transportKind(null).build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_FIELD_LENGTH,
                () -> vectorBuilder().hostIpv4(new byte[3]).build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_ENDPOINT,
                () -> vectorBuilder().videoPort(0).build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_ENDPOINT,
                () -> vectorBuilder().controlPort(45678).build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_PAIR_ID,
                () -> vectorBuilder().pairId("A123456789abcdef0123456789abcdef").build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_PAIR_ID,
                () -> vectorBuilder().pairId("a123").build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_RUNTIME_VERSION,
                () -> vectorBuilder().hostRuntimeVersion("01.2.3").build());
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_RUNTIME_VERSION,
                () -> vectorBuilder().androidRuntimeVersion("1.2.3+dev").build());

        PairGenerationProposalV1 maximumConnection =
                vectorBuilder().connectionId(Long.MAX_VALUE).build();
        require(maximumConnection.connectionId() == Long.MAX_VALUE, "signed64 maximum accepted");
    }

    private static void verifiesSigned64GenerationAndRestrictedApi() throws Exception {
        PairGenerationProposalV1 proposal = vectorBuilder().build();
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_GENERATION,
                () -> proposal.buildFinalHandshakeTranscript(0L));
        expectError(
                PairGenerationProposalV1.ErrorCode.INVALID_GENERATION,
                () -> proposal.buildFinalHandshakeTranscript(-1L));
        require(
                proposal.buildFinalHandshakeTranscript(Long.MAX_VALUE).sessionGeneration()
                        == Long.MAX_VALUE,
                "generation signed64 maximum accepted");

        for (Constructor<?> constructor : PairGenerationProposalV1.class.getDeclaredConstructors()) {
            require(!Modifier.isPublic(constructor.getModifiers()), "no public owner constructor");
        }
        for (Method method : PairGenerationProposalV1.Builder.class.getDeclaredMethods()) {
            String name = method.getName().toLowerCase();
            require(!name.contains("hash") && !name.contains("digest"), "no caller hash setter");
        }
    }

    private static PairGenerationProposalV1.Builder vectorBuilder() {
        return PairGenerationProposalV1.newBuilder()
                .hostIdentitySpkiSha256(sequence(0x00, 32))
                .androidIdentitySpkiSha256(sequence(0x20, 32))
                .hostEphemeralPublicKey(hex(HOST_PUBLIC_HEX))
                .androidEphemeralPublicKey(hex(ANDROID_PUBLIC_HEX))
                .hostNonce(sequence(0x40, 32))
                .androidNonce(sequence(0x60, 32))
                .connectionId(0x1020_3040_5060_7080L)
                .transportKind(AuthenticatedPeerHandshakeV1.TransportKind.CAT6)
                .hostIpv4(hex("c0a83701"))
                .androidIpv4(hex("c0a83702"))
                .videoPort(45678)
                .controlPort(45679)
                .pairId("0123456789abcdef0123456789abcdef")
                .hostRuntimeVersion("17.8.47")
                .androidRuntimeVersion("17.8.47");
    }

    private static byte[] invalidPoint() {
        byte[] value = new byte[65];
        value[0] = 4;
        return value;
    }

    private static byte[] sequence(int start, int length) {
        byte[] result = new byte[length];
        for (int index = 0; index < length; index++) {
            result[index] = (byte) (start + index);
        }
        return result;
    }

    private static List<FieldSpan> fields(byte[] canonical) {
        List<FieldSpan> result = new ArrayList<>();
        int offset = 0;
        while (offset < canonical.length) {
            require(canonical.length - offset >= 5, "complete TLV header");
            int length = ByteBuffer.wrap(canonical, offset + 1, Integer.BYTES).getInt();
            require(length >= 0 && canonical.length - offset >= 5 + length, "complete TLV");
            result.add(new FieldSpan(offset, offset + 1, offset + 5, length));
            offset += 5 + length;
        }
        return result;
    }

    private static byte[] value(byte[] canonical, FieldSpan span) {
        return Arrays.copyOfRange(
                canonical, span.valueOffset, span.valueOffset + span.length);
    }

    private static byte[] removeRange(byte[] value, int offset, int length) {
        byte[] result = new byte[value.length - length];
        System.arraycopy(value, 0, result, 0, offset);
        System.arraycopy(
                value,
                offset + length,
                result,
                offset,
                value.length - offset - length);
        return result;
    }

    private static byte[] hex(String value) {
        require(value.length() % 2 == 0, "hex length");
        byte[] result = new byte[value.length() / 2];
        for (int index = 0; index < result.length; index++) {
            int high = Character.digit(value.charAt(index * 2), 16);
            int low = Character.digit(value.charAt(index * 2 + 1), 16);
            require(high >= 0 && low >= 0, "valid hex");
            result[index] = (byte) ((high << 4) | low);
        }
        return result;
    }

    private static void expectError(
            PairGenerationProposalV1.ErrorCode expected,
            CheckedRunnable action)
            throws Exception {
        try {
            action.run();
            throw new AssertionError("expected proposal rejection: " + expected);
        } catch (PairGenerationProposalV1.ProposalException rejected) {
            require(rejected.code() == expected, "sanitized error code " + expected);
            require(rejected.getCause() == null, "provider cause is absent");
            require(
                    rejected.getMessage().equals(expected.name().toLowerCase(Locale.ROOT)),
                    "error message contains only the code");
            require(!rejected.getMessage().contains("17.8.47"), "runtime value is absent");
            require(
                    !rejected.getMessage().contains("0123456789abcdef"),
                    "pair value is absent");
        }
    }

    private static void requireHex(byte[] actual, String expected, String label) {
        requireBytes(actual, hex(expected), label);
    }

    private static void requireBytes(byte[] actual, byte[] expected, String label) {
        require(MessageDigest.isEqual(actual, expected), label);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private interface CheckedRunnable {
        void run() throws Exception;
    }

    private static final class FieldSpan {
        private final int tagOffset;
        private final int lengthOffset;
        private final int valueOffset;
        private final int length;

        private FieldSpan(int tagOffset, int lengthOffset, int valueOffset, int length) {
            this.tagOffset = tagOffset;
            this.lengthOffset = lengthOffset;
            this.valueOffset = valueOffset;
            this.length = length;
        }
    }
}
