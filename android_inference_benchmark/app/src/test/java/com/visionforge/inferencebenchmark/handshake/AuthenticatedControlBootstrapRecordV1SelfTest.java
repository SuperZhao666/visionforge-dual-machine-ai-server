package com.visionforge.inferencebenchmark.handshake;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.BootstrapException;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.Direction;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.MessageType;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.Reason;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.Record;

import java.util.Arrays;

/** Dependency-free cross-language contract for the VFB1 startup record. */
public final class AuthenticatedControlBootstrapRecordV1SelfTest {
    private static final String FIXED_VECTOR =
            "56464231010c01010000000a686f73742d68656c6c6f";

    private AuthenticatedControlBootstrapRecordV1SelfTest() {}

    public static void main(String[] arguments) throws Exception {
        verifiesFixedCrossLanguageVectorAndDefensiveCopies();
        verifiesEveryMessageDirection();
        rejectsMutationsReflectionAndLengthConfusion();
        verifiesExactPayloadBound();
        System.out.println("AuthenticatedControlBootstrapRecordV1SelfTest: PASS");
    }

    private static void verifiesFixedCrossLanguageVectorAndDefensiveCopies()
            throws Exception {
        byte[] payload = ascii("host-hello");
        byte[] encoded = AuthenticatedControlBootstrapRecordV1.encode(
                Direction.HOST_TO_ANDROID, MessageType.HOST_HELLO, payload);
        require(Arrays.equals(encoded, hex(FIXED_VECTOR)), "fixed VFB1 vector");
        payload[0] ^= 0x40;
        Record record = AuthenticatedControlBootstrapRecordV1.parse(
                encoded, Direction.HOST_TO_ANDROID);
        try {
            require(record.direction() == Direction.HOST_TO_ANDROID, "direction");
            require(record.messageType() == MessageType.HOST_HELLO, "type");
            byte[] first = record.payload();
            byte[] second = record.payload();
            require(Arrays.equals(first, ascii("host-hello")), "payload");
            first[0] ^= 0x20;
            require(Arrays.equals(second, ascii("host-hello")), "defensive payload");
            clear(first, second);
        } finally {
            record.close();
        }
        expect(Reason.CLOSED, record::payload);
        clear(payload, encoded);
    }

    private static void verifiesEveryMessageDirection() throws Exception {
        MessageType[] hostTypes = new MessageType[] {
                MessageType.HOST_HELLO,
                MessageType.HOST_CHALLENGE_PROOF,
                MessageType.HOST_FINAL_PROOF,
                MessageType.HOST_HANDSHAKE_SIGNATURE,
                MessageType.HOST_FINISHED
        };
        MessageType[] androidTypes = new MessageType[] {
                MessageType.ANDROID_CHALLENGE_REQUEST,
                MessageType.SERVER_CHALLENGE,
                MessageType.PAIR_GENERATION_CREDENTIAL,
                MessageType.ANDROID_HANDSHAKE_CONFIRMATION
        };
        for (MessageType type : hostTypes) {
            require(AuthenticatedControlBootstrapRecordV1.isAllowed(
                    Direction.HOST_TO_ANDROID, type), "Host type allowed");
            require(!AuthenticatedControlBootstrapRecordV1.isAllowed(
                    Direction.ANDROID_TO_HOST, type), "Host type reflected");
        }
        for (MessageType type : androidTypes) {
            require(AuthenticatedControlBootstrapRecordV1.isAllowed(
                    Direction.ANDROID_TO_HOST, type), "Android type allowed");
            require(!AuthenticatedControlBootstrapRecordV1.isAllowed(
                    Direction.HOST_TO_ANDROID, type), "Android type reflected");
        }
        require(AuthenticatedControlBootstrapRecordV1.isAllowed(
                Direction.HOST_TO_ANDROID, MessageType.ABORT), "Host abort");
        require(AuthenticatedControlBootstrapRecordV1.isAllowed(
                Direction.ANDROID_TO_HOST, MessageType.ABORT), "Android abort");
        expect(Reason.DIRECTION_MISMATCH, () ->
                AuthenticatedControlBootstrapRecordV1.encode(
                        Direction.ANDROID_TO_HOST,
                        MessageType.HOST_HELLO,
                        new byte[] {1}));
        expect(Reason.PAYLOAD_EMPTY, () ->
                AuthenticatedControlBootstrapRecordV1.encode(
                        Direction.HOST_TO_ANDROID,
                        MessageType.HOST_HELLO,
                        new byte[0]));
    }

    private static void rejectsMutationsReflectionAndLengthConfusion()
            throws Exception {
        byte[] encoded = AuthenticatedControlBootstrapRecordV1.encode(
                Direction.ANDROID_TO_HOST,
                MessageType.SERVER_CHALLENGE,
                ascii("challenge"));
        byte[] badMagic = encoded.clone();
        badMagic[0] ^= 1;
        expect(Reason.INVALID_MAGIC, () -> parseAndroid(badMagic));
        byte[] badVersion = encoded.clone();
        badVersion[4] = 2;
        expect(Reason.UNSUPPORTED_VERSION, () -> parseAndroid(badVersion));
        byte[] badHeaderSize = encoded.clone();
        badHeaderSize[5] = 13;
        expect(Reason.INVALID_HEADER_SIZE, () -> parseAndroid(badHeaderSize));
        byte[] badDirection = encoded.clone();
        badDirection[6] = 0;
        expect(Reason.INVALID_DIRECTION, () -> parseAndroid(badDirection));
        expect(Reason.UNEXPECTED_DIRECTION, () ->
                AuthenticatedControlBootstrapRecordV1.parse(
                        encoded, Direction.HOST_TO_ANDROID));
        byte[] badType = encoded.clone();
        badType[7] = (byte) 0xff;
        expect(Reason.INVALID_MESSAGE_TYPE, () -> parseAndroid(badType));
        byte[] reflectedType = encoded.clone();
        reflectedType[7] = 1;
        expect(Reason.DIRECTION_MISMATCH, () -> parseAndroid(reflectedType));
        byte[] emptyLength = encoded.clone();
        emptyLength[11] = 0;
        expect(Reason.PAYLOAD_EMPTY, () -> parseAndroid(emptyLength));
        byte[] oversizedLength = encoded.clone();
        oversizedLength[8] = 0;
        oversizedLength[9] = 1;
        oversizedLength[10] = 0;
        oversizedLength[11] = 1;
        expect(Reason.PAYLOAD_TOO_LARGE, () -> parseAndroid(oversizedLength));
        byte[] truncated = Arrays.copyOf(encoded, encoded.length - 1);
        expect(Reason.LENGTH_MISMATCH, () -> parseAndroid(truncated));
        byte[] trailing = Arrays.copyOf(encoded, encoded.length + 1);
        expect(Reason.LENGTH_MISMATCH, () -> parseAndroid(trailing));
        clear(
                encoded,
                badMagic,
                badVersion,
                badHeaderSize,
                badDirection,
                badType,
                reflectedType,
                emptyLength,
                oversizedLength,
                truncated,
                trailing);
    }

    private static void verifiesExactPayloadBound() throws Exception {
        byte[] maximum = new byte[
                AuthenticatedControlBootstrapRecordV1.MAX_PAYLOAD_BYTES];
        Arrays.fill(maximum, (byte) 0xa5);
        byte[] encoded = AuthenticatedControlBootstrapRecordV1.encode(
                Direction.ANDROID_TO_HOST,
                MessageType.PAIR_GENERATION_CREDENTIAL,
                maximum);
        try (Record record = AuthenticatedControlBootstrapRecordV1.parse(
                encoded, Direction.ANDROID_TO_HOST)) {
            require(record.payload().length == maximum.length, "maximum payload");
        }
        byte[] oversized = new byte[maximum.length + 1];
        expect(Reason.PAYLOAD_TOO_LARGE, () ->
                AuthenticatedControlBootstrapRecordV1.encode(
                        Direction.ANDROID_TO_HOST,
                        MessageType.PAIR_GENERATION_CREDENTIAL,
                        oversized));
        clear(maximum, encoded, oversized);
    }

    private static void parseAndroid(byte[] encoded) throws Exception {
        try (Record unexpectedlyParsed =
                AuthenticatedControlBootstrapRecordV1.parse(
                encoded, Direction.ANDROID_TO_HOST)) {
            throw new AssertionError(
                    "expected rejection, parsed "
                            + unexpectedlyParsed.messageType());
        }
    }

    private interface CheckedOperation {
        void run() throws Exception;
    }

    private static void expect(Reason expected, CheckedOperation operation)
            throws Exception {
        try {
            operation.run();
            throw new AssertionError("expected " + expected);
        } catch (BootstrapException rejected) {
            require(rejected.reason() == expected, "rejection reason " + expected);
        }
    }

    private static byte[] ascii(String value) throws Exception {
        return value.getBytes("US-ASCII");
    }

    private static byte[] hex(String encoded) {
        byte[] result = new byte[encoded.length() / 2];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) Integer.parseInt(
                    encoded.substring(index * 2, index * 2 + 2), 16);
        }
        return result;
    }

    private static void clear(byte[]... values) {
        for (byte[] value : values) {
            if (value != null) Arrays.fill(value, (byte) 0);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
