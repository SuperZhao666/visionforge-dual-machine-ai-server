package com.visionforge.inferencebenchmark.handshake;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapPayloadV1.ParsedPayload;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapPayloadV1.PayloadException;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapPayloadV1.Reason;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.MessageType;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Dependency-free Java mirror of the C++ strict VFB1 payload schema. */
public final class AuthenticatedControlBootstrapPayloadV1SelfTest {
    private static final String SERVER_CHALLENGE_VECTOR =
            "0000000020"
            + "3131313131313131313131313131313131313131313131313131313131313131"
            + "01000000080000000068aa6f00"
            + "0200000020"
            + "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"
            + "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";

    private AuthenticatedControlBootstrapPayloadV1SelfTest() {}

    public static void main(String[] arguments) throws Exception {
        everyMessageRoundTripsWithExactSchema();
        serverChallengeMatchesCppVectorAndOwnsCopies();
        rejectsTagLengthValueAndTrailingConfusion();
        rejectsNoncanonicalAndCrossFieldValues();
        credentialBoundIsExactAndJwtShaped();
        System.out.println("AuthenticatedControlBootstrapPayloadV1SelfTest: PASS");
    }

    private static void everyMessageRoundTripsWithExactSchema() throws Exception {
        MessageType[] messages = new MessageType[] {
                MessageType.HOST_HELLO,
                MessageType.ANDROID_CHALLENGE_REQUEST,
                MessageType.HOST_CHALLENGE_PROOF,
                MessageType.SERVER_CHALLENGE,
                MessageType.HOST_FINAL_PROOF,
                MessageType.PAIR_GENERATION_CREDENTIAL,
                MessageType.HOST_HANDSHAKE_SIGNATURE,
                MessageType.ANDROID_HANDSHAKE_CONFIRMATION,
                MessageType.HOST_FINISHED,
                MessageType.ABORT
        };
        for (MessageType message : messages) {
            byte[][] fields = validFields(message);
            byte[] encoded = AuthenticatedControlBootstrapPayloadV1.encode(
                    message, fields);
            try (ParsedPayload parsed =
                    AuthenticatedControlBootstrapPayloadV1.parse(message, encoded)) {
                require(parsed.messageType() == message, "message type");
                require(parsed.fieldCount() == fields.length, "field count");
                for (int index = 0; index < fields.length; index++) {
                    require(Arrays.equals(parsed.field(index), fields[index]), "field " + index);
                }
            }
            clear(encoded);
            clearFields(fields);
        }
    }

    private static void serverChallengeMatchesCppVectorAndOwnsCopies()
            throws Exception {
        byte[][] fields = validFields(MessageType.SERVER_CHALLENGE);
        byte[] encoded = AuthenticatedControlBootstrapPayloadV1.encode(
                MessageType.SERVER_CHALLENGE, fields);
        require(Arrays.equals(encoded, hex(SERVER_CHALLENGE_VECTOR)), "C++ vector");
        ParsedPayload parsed = AuthenticatedControlBootstrapPayloadV1.parse(
                MessageType.SERVER_CHALLENGE, encoded);
        byte[] first = parsed.field(0);
        byte[] second = parsed.field(0);
        first[0] ^= 1;
        require(!Arrays.equals(first, second), "defensive field copy");
        parsed.close();
        expect(Reason.CLOSED, -1, () -> parsed.field(0));
        clearFields(fields);
        clear(encoded, first, second);
    }

    private static void rejectsTagLengthValueAndTrailingConfusion()
            throws Exception {
        byte[] encoded = AuthenticatedControlBootstrapPayloadV1.encode(
                MessageType.SERVER_CHALLENGE,
                validFields(MessageType.SERVER_CHALLENGE));
        byte[] badTag = encoded.clone();
        badTag[0] = 1;
        expect(Reason.UNEXPECTED_FIELD_TAG, 1, () -> parseServer(badTag));
        byte[] badLength = encoded.clone();
        badLength[4] = 31;
        expect(Reason.INVALID_FIELD_LENGTH, 0, () -> parseServer(badLength));
        byte[] badValue = encoded.clone();
        badValue[5] = 'g';
        expect(Reason.INVALID_FIELD_VALUE, 0, () -> parseServer(badValue));
        byte[] truncated = Arrays.copyOf(encoded, encoded.length - 1);
        expect(Reason.TRUNCATED_TLV, 2, () -> parseServer(truncated));
        byte[] trailing = Arrays.copyOf(encoded, encoded.length + 1);
        expect(Reason.TRAILING_DATA, -1, () -> parseServer(trailing));
        expect(Reason.INVALID_MESSAGE_TYPE, -1, () ->
                AuthenticatedControlBootstrapPayloadV1.parse(null, encoded));
        expect(Reason.PAYLOAD_EMPTY, -1, () ->
                AuthenticatedControlBootstrapPayloadV1.parse(
                        MessageType.SERVER_CHALLENGE, new byte[0]));
        clear(encoded, badTag, badLength, badValue, truncated, trailing);
    }

    private static void rejectsNoncanonicalAndCrossFieldValues()
            throws Exception {
        byte[][] equalPorts = validFields(MessageType.HOST_HELLO);
        equalPorts[7] = equalPorts[6].clone();
        expect(Reason.INVALID_FIELD_VALUE, 7, () ->
                AuthenticatedControlBootstrapPayloadV1.encode(
                        MessageType.HOST_HELLO, equalPorts));
        byte[][] badVersion = validFields(MessageType.HOST_HELLO);
        badVersion[8] = ascii("01.2.3");
        expect(Reason.INVALID_FIELD_VALUE, 8, () ->
                AuthenticatedControlBootstrapPayloadV1.encode(
                        MessageType.HOST_HELLO, badVersion));
        byte[][] proof = validFields(MessageType.HOST_FINAL_PROOF);
        proof[0][1] = 5;
        expect(Reason.INVALID_FIELD_VALUE, 0, () ->
                AuthenticatedControlBootstrapPayloadV1.encode(
                        MessageType.HOST_FINAL_PROOF, proof));
        byte[][] android = validFields(MessageType.ANDROID_CHALLENGE_REQUEST);
        android[0][0] = 'A';
        expect(Reason.INVALID_FIELD_VALUE, 0, () ->
                AuthenticatedControlBootstrapPayloadV1.encode(
                        MessageType.ANDROID_CHALLENGE_REQUEST, android));
        byte[][] shortServer = Arrays.copyOf(
                validFields(MessageType.SERVER_CHALLENGE), 2);
        expect(Reason.INVALID_FIELD_COUNT, -1, () ->
                AuthenticatedControlBootstrapPayloadV1.encode(
                        MessageType.SERVER_CHALLENGE, shortServer));
        clearFields(equalPorts);
        clearFields(badVersion);
        clearFields(proof);
        clearFields(android);
        clearFields(shortServer);
    }

    private static void credentialBoundIsExactAndJwtShaped() throws Exception {
        char[] middle = new char[
                AuthenticatedControlBootstrapPayloadV1.MAXIMUM_CREDENTIAL_BYTES - 4];
        Arrays.fill(middle, 'b');
        String maximum = "a." + new String(middle) + ".c";
        byte[] encoded = AuthenticatedControlBootstrapPayloadV1.encode(
                MessageType.PAIR_GENERATION_CREDENTIAL, ascii(maximum));
        try (ParsedPayload parsed = AuthenticatedControlBootstrapPayloadV1.parse(
                MessageType.PAIR_GENERATION_CREDENTIAL, encoded)) {
            require(parsed.field(0).length
                    == AuthenticatedControlBootstrapPayloadV1.MAXIMUM_CREDENTIAL_BYTES,
                    "exact credential maximum");
        }
        byte[] oversized = ascii("a" + maximum);
        expect(Reason.INVALID_FIELD_LENGTH, 0, () ->
                AuthenticatedControlBootstrapPayloadV1.encode(
                        MessageType.PAIR_GENERATION_CREDENTIAL, oversized));
        expect(Reason.INVALID_FIELD_VALUE, 0, () ->
                AuthenticatedControlBootstrapPayloadV1.encode(
                        MessageType.PAIR_GENERATION_CREDENTIAL,
                        ascii("header.payload.")));
        clear(encoded, oversized);
        Arrays.fill(middle, '\0');
    }

    private static byte[][] validFields(MessageType message) {
        switch (message) {
            case HOST_HELLO:
                return new byte[][] {
                        canonicalSpki(0x11), sec1(0x22), filled(32, 0x33),
                        new byte[] {1},
                        new byte[] {10, 57, 23, 1},
                        new byte[] {10, 57, 23, 2},
                        u16(5000), u16(5006), ascii("1.2.3")
                };
            case ANDROID_CHALLENGE_REQUEST:
                return new byte[][] {
                        ascii("11111111111111111111111111111111"),
                        ascii("22222222222222222222222222222222"),
                        ascii("33333333333333333333333333333333"),
                        ascii("44444444444444444444444444444444"),
                        ascii("55555555555555555555555555555555"),
                        u64(7), u64(9), canonicalSpki(0x44), sec1(0x55),
                        filled(32, 0x66), ascii("2.3.4"), signature()
                };
            case HOST_CHALLENGE_PROOF:
            case HOST_FINAL_PROOF:
            case HOST_HANDSHAKE_SIGNATURE:
                return new byte[][] {signature()};
            case SERVER_CHALLENGE:
                return new byte[][] {
                        ascii("11111111111111111111111111111111"),
                        u64(1_756_000_000L), filled(32, 0xa5)
                };
            case PAIR_GENERATION_CREDENTIAL:
                return new byte[][] {ascii("eyJhbGciOiJSUzI1NiJ9.e30.c2ln")};
            case ANDROID_HANDSHAKE_CONFIRMATION:
                return new byte[][] {signature(), filled(32, 0x77)};
            case HOST_FINISHED:
                return new byte[][] {filled(32, 0x88)};
            case ABORT:
                return new byte[][] {u16(1)};
            default:
                throw new IllegalArgumentException("unsupported message");
        }
    }

    private static byte[] canonicalSpki(int coordinate) {
        byte[] prefix = hex(
                "3059301306072a8648ce3d020106082a8648ce3d03010703420004");
        byte[] result = new byte[91];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        Arrays.fill(result, prefix.length, result.length, (byte) coordinate);
        clear(prefix);
        return result;
    }

    private static byte[] sec1(int coordinate) {
        byte[] result = filled(65, coordinate);
        result[0] = 0x04;
        return result;
    }

    private static byte[] signature() {
        return hex("3006020101020101");
    }

    private static byte[] filled(int length, int value) {
        byte[] result = new byte[length];
        Arrays.fill(result, (byte) value);
        return result;
    }

    private static byte[] u16(int value) {
        return ByteBuffer.allocate(2).putShort((short) value).array();
    }

    private static byte[] u64(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] hex(String encoded) {
        byte[] result = new byte[encoded.length() / 2];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) Integer.parseInt(
                    encoded.substring(index * 2, index * 2 + 2), 16);
        }
        return result;
    }

    private static void parseServer(byte[] encoded) throws Exception {
        try (ParsedPayload unexpectedlyParsed = AuthenticatedControlBootstrapPayloadV1.parse(
                MessageType.SERVER_CHALLENGE, encoded)) {
            throw new AssertionError(
                    "expected rejection, parsed " + unexpectedlyParsed.fieldCount() + " fields");
        }
    }

    private interface CheckedOperation {
        void run() throws Exception;
    }

    private static void expect(
            Reason expectedReason,
            int expectedTag,
            CheckedOperation operation) throws Exception {
        try {
            operation.run();
            throw new AssertionError("expected " + expectedReason);
        } catch (PayloadException rejected) {
            require(rejected.reason() == expectedReason, "reason " + expectedReason);
            require(rejected.fieldTag() == expectedTag, "field tag " + expectedTag);
        }
    }

    private static void clear(byte[]... values) {
        for (byte[] value : values) {
            if (value != null) Arrays.fill(value, (byte) 0);
        }
    }

    private static void clearFields(byte[][] values) {
        if (values == null) return;
        for (byte[] value : values) clear(value);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
