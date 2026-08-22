package com.visionforge.inferencebenchmark.dataplane;

import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedControlRecordV1.Reason.CLOSED;
import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedControlRecordV1.Reason.COUNTER_EXHAUSTED;
import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedControlRecordV1.Reason.CRYPTO_UNAVAILABLE;
import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedControlRecordV1.Reason.PAYLOAD_TOO_LARGE;
import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedControlRecordV1.Reason.UNAUTHENTICATED_RECORD;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

/** Dependency-free executable contract for the Android VFC1 implementation. */
public final class AuthenticatedControlRecordV1SelfTest {
    private static final int DIRECTION_OFFSET = 6;
    private static final int MESSAGE_TYPE_OFFSET = 7;
    private static final int CONNECTION_ID_OFFSET = 8;
    private static final int COUNTER_OFFSET = 28;
    private static final int PAYLOAD_LENGTH_OFFSET = 36;

    private static final long CONNECTION_ID = 0x0102_0304_0506_0708L;
    private static final long SESSION_GENERATION = 0x1112_1314_1516_1718L;
    private static final int KEY_EPOCH = 1;
    private static final String VECTOR_WIRE_HEX =
            "56464331012801010102030405060708"
                    + "11121314151617180000000100000000000000000000000e"
                    + "70dc3d454649c1d3d25ed51e27eb"
                    + "90c38f65b29d2116262be102a306a49e";

    private AuthenticatedControlRecordV1SelfTest() {}

    public static void main(String[] arguments) throws Exception {
        verifiesFixedCrossLanguageVectorAndDefensiveCopies();
        verifiesAllMessageTypesShareOneCounterAndReplayDomain();
        verifiesMutationsDoNotCommitReplayState();
        verifiesReplayWindowAndStrictFraming();
        verifiesProviderFailureBurnsCounterAndLifetimeLimit();
        verifiesInvalidAndClosedInputsFailClosed();
        System.out.println("AuthenticatedControlRecordV1SelfTest: PASS");
    }

    private static void verifiesFixedCrossLanguageVectorAndDefensiveCopies()
            throws Exception {
        byte[] material = trafficMaterial();
        byte[] expectedMaterial = material.clone();
        byte[] plaintext = ascii("lease-token-v1");
        byte[] envelope;
        try (AuthenticatedControlRecordV1.Sender sender =
                AuthenticatedControlRecordV1.newSender(material, standardDomain())) {
            Arrays.fill(material, (byte) 0x7f);
            envelope = sender.seal(
                    AuthenticatedControlRecordV1.MessageType.LEASE_OFFER,
                    plaintext);
        }
        require(Arrays.equals(envelope, hex(VECTOR_WIRE_HEX)), "fixed VFC1 AES-GCM vector");
        require(headerCounter(envelope) == 0L, "fixed vector counter");
        require(Byte.toUnsignedInt(envelope[MESSAGE_TYPE_OFFSET]) == 1, "fixed message type");

        try (AuthenticatedControlRecordV1.Receiver receiver =
                        AuthenticatedControlRecordV1.newReceiver(
                                expectedMaterial, standardDomain());
                AuthenticatedControlRecordV1.OpenedRecord opened = receiver.open(envelope)) {
            byte[] first = opened.plaintext();
            byte[] second = opened.plaintext();
            require(Arrays.equals(first, plaintext), "fixed vector plaintext");
            first[0] ^= 0x40;
            require(Arrays.equals(second, plaintext), "opened plaintext is defensive");
            clear(first, second);
        }
        clear(material, expectedMaterial, plaintext, envelope);
    }

    private static void verifiesAllMessageTypesShareOneCounterAndReplayDomain()
            throws Exception {
        byte[] material = trafficMaterial();
        byte[][] records = new byte[AuthenticatedControlRecordV1.MessageType.values().length][];
        try (AuthenticatedControlRecordV1.Sender sender =
                        AuthenticatedControlRecordV1.newSender(material, standardDomain());
                AuthenticatedControlRecordV1.Receiver receiver =
                        AuthenticatedControlRecordV1.newReceiver(material, standardDomain())) {
            int index = 0;
            for (AuthenticatedControlRecordV1.MessageType type
                    : AuthenticatedControlRecordV1.MessageType.values()) {
                records[index] = sender.seal(type, new byte[] {(byte) index});
                require(headerCounter(records[index]) == index, "shared type counter");
                require(
                        Byte.toUnsignedInt(records[index][MESSAGE_TYPE_OFFSET]) == index + 1,
                        "canonical message-type code");
                index++;
            }
            for (int recordIndex = records.length - 1; recordIndex >= 0; recordIndex--) {
                try (AuthenticatedControlRecordV1.OpenedRecord opened =
                        receiver.open(records[recordIndex])) {
                    require(
                            opened.counter() == recordIndex,
                            "one replay window accepts bounded out-of-order types");
                    byte[] openedPlaintext = opened.plaintext();
                    require(
                            openedPlaintext.length == 1
                                    && Byte.toUnsignedInt(openedPlaintext[0]) == recordIndex,
                            "message payload");
                    clear(openedPlaintext);
                }
            }
            expectReason(UNAUTHENTICATED_RECORD, () -> receiver.open(records[2]));
        }
        clear(material);
        for (byte[] record : records) clear(record);
    }

    private static void verifiesMutationsDoNotCommitReplayState() throws Exception {
        byte[] material = trafficMaterial();
        try (AuthenticatedControlRecordV1.Sender sender =
                        AuthenticatedControlRecordV1.newSender(material, standardDomain());
                AuthenticatedControlRecordV1.Receiver receiver =
                        AuthenticatedControlRecordV1.newReceiver(material, standardDomain())) {
            byte[] first = sender.seal(
                    AuthenticatedControlRecordV1.MessageType.LEASE_OFFER,
                    ascii("first"));
            byte[] badTag = first.clone();
            badTag[badTag.length - 1] ^= 0x01;
            expectReason(UNAUTHENTICATED_RECORD, () -> receiver.open(badTag));
            requireOpenEquals(receiver, first, "first");

            byte[] second = sender.seal(
                    AuthenticatedControlRecordV1.MessageType.LEASE_COMMIT,
                    ascii("second"));
            byte[] wrongType = second.clone();
            wrongType[MESSAGE_TYPE_OFFSET] = 4;
            expectReason(UNAUTHENTICATED_RECORD, () -> receiver.open(wrongType));
            byte[] wrongDirection = second.clone();
            wrongDirection[DIRECTION_OFFSET] = 2;
            expectReason(UNAUTHENTICATED_RECORD, () -> receiver.open(wrongDirection));
            byte[] wrongConnection = second.clone();
            wrongConnection[CONNECTION_ID_OFFSET] ^= 0x40;
            expectReason(UNAUTHENTICATED_RECORD, () -> receiver.open(wrongConnection));
            requireOpenEquals(receiver, second, "second");
            clear(first, badTag, second, wrongType, wrongDirection, wrongConnection);
        }
        clear(material);
    }

    private static void verifiesReplayWindowAndStrictFraming() throws Exception {
        byte[] material = trafficMaterial();
        byte[][] records = new byte[AuthenticatedControlRecordV1.REPLAY_WINDOW_BITS + 1][];
        try (AuthenticatedControlRecordV1.Sender sender =
                        AuthenticatedControlRecordV1.newSender(material, standardDomain());
                AuthenticatedControlRecordV1.Receiver receiver =
                        AuthenticatedControlRecordV1.newReceiver(material, standardDomain())) {
            for (int index = 0; index < records.length; index++) {
                records[index] = sender.seal(
                        AuthenticatedControlRecordV1.MessageType.LEASE_ACCEPT,
                        new byte[] {(byte) index});
            }
            try (AuthenticatedControlRecordV1.OpenedRecord ignored =
                    receiver.open(records[records.length - 1])) {
                require(ignored.counter() == AuthenticatedControlRecordV1.REPLAY_WINDOW_BITS,
                        "new highest replay counter");
            }
            expectReason(UNAUTHENTICATED_RECORD, () -> receiver.open(records[0]));
            try (AuthenticatedControlRecordV1.OpenedRecord boundary =
                    receiver.open(records[1])) {
                require(boundary.counter() == 1L, "1023-distance replay boundary");
            }

            byte[] canonical = records[10];
            byte[] truncated = Arrays.copyOf(canonical, canonical.length - 1);
            byte[] trailing = Arrays.copyOf(canonical, canonical.length + 1);
            byte[] invalidType = canonical.clone();
            invalidType[MESSAGE_TYPE_OFFSET] = (byte) 0xff;
            byte[] invalidLength = canonical.clone();
            ByteBuffer.wrap(invalidLength, PAYLOAD_LENGTH_OFFSET, Integer.BYTES)
                    .putInt(AuthenticatedControlRecordV1.MAX_PAYLOAD_BYTES + 1);
            expectReason(UNAUTHENTICATED_RECORD, () -> receiver.open(truncated));
            expectReason(UNAUTHENTICATED_RECORD, () -> receiver.open(trailing));
            expectReason(UNAUTHENTICATED_RECORD, () -> receiver.open(invalidType));
            expectReason(UNAUTHENTICATED_RECORD, () -> receiver.open(invalidLength));
            clear(truncated, trailing, invalidType, invalidLength);
        }
        clear(material);
        for (byte[] record : records) clear(record);
    }

    private static void verifiesProviderFailureBurnsCounterAndLifetimeLimit()
            throws Exception {
        byte[] material = trafficMaterial();
        AtomicInteger attempts = new AtomicInteger();
        AuthenticatedControlRecordV1.EncryptionAttemptHook failOnce =
                () -> {
                    if (attempts.getAndIncrement() == 0) {
                        throw new GeneralSecurityException("injected failure");
                    }
                };
        try (AuthenticatedControlRecordV1.Sender sender =
                AuthenticatedControlRecordV1.newSender(
                        material, standardDomain(), 5L, failOnce)) {
            expectReason(
                    CRYPTO_UNAVAILABLE,
                    () -> sender.seal(
                            AuthenticatedControlRecordV1.MessageType.LEASE_OFFER,
                            ascii("failure")));
            byte[] afterFailure = sender.seal(
                    AuthenticatedControlRecordV1.MessageType.LEASE_OFFER,
                    ascii("retry"));
            require(headerCounter(afterFailure) == 6L, "failed provider attempt burns counter");
            clear(afterFailure);
        }

        try (AuthenticatedControlRecordV1.Sender sender =
                AuthenticatedControlRecordV1.newSender(
                        material,
                        standardDomain(),
                        AuthenticatedControlRecordV1.MAX_COUNTER_PER_TRAFFIC_KEY,
                        () -> {})) {
            byte[] last = sender.seal(
                    AuthenticatedControlRecordV1.MessageType.SESSION_CLOSE,
                    ascii("last"));
            require(
                    headerCounter(last)
                            == AuthenticatedControlRecordV1.MAX_COUNTER_PER_TRAFFIC_KEY,
                    "last permitted counter");
            expectReason(
                    COUNTER_EXHAUSTED,
                    () -> sender.seal(
                            AuthenticatedControlRecordV1.MessageType.SESSION_CLOSE,
                            ascii("late")));
            clear(last);
        }
        clear(material);
    }

    private static void verifiesInvalidAndClosedInputsFailClosed() throws Exception {
        byte[] material = trafficMaterial();
        expectIllegalArgument(() -> AuthenticatedControlRecordV1.newSender(
                new byte[35], standardDomain()));
        expectIllegalArgument(() -> AuthenticatedControlRecordV1.createDomain(
                0L,
                SESSION_GENERATION,
                KEY_EPOCH,
                AuthenticatedControlRecordV1.Direction.HOST_TO_ANDROID));
        expectIllegalArgument(() -> AuthenticatedControlRecordV1.createDomain(
                CONNECTION_ID,
                0L,
                KEY_EPOCH,
                AuthenticatedControlRecordV1.Direction.HOST_TO_ANDROID));

        AuthenticatedControlRecordV1.Sender sender =
                AuthenticatedControlRecordV1.newSender(material, standardDomain());
        expectReason(
                PAYLOAD_TOO_LARGE,
                () -> sender.seal(
                        AuthenticatedControlRecordV1.MessageType.LEASE_OFFER,
                        new byte[AuthenticatedControlRecordV1.MAX_PAYLOAD_BYTES + 1]));
        sender.close();
        expectReason(
                CLOSED,
                () -> sender.seal(
                        AuthenticatedControlRecordV1.MessageType.LEASE_OFFER,
                        new byte[0]));

        AuthenticatedControlRecordV1.Receiver receiver =
                AuthenticatedControlRecordV1.newReceiver(material, standardDomain());
        receiver.close();
        expectReason(CLOSED, () -> receiver.open(new byte[0]));
        clear(material);
    }

    private static AuthenticatedControlRecordV1.Domain standardDomain() {
        return AuthenticatedControlRecordV1.createDomain(
                CONNECTION_ID,
                SESSION_GENERATION,
                KEY_EPOCH,
                AuthenticatedControlRecordV1.Direction.HOST_TO_ANDROID);
    }

    private static byte[] trafficMaterial() {
        byte[] material = new byte[AuthenticatedControlRecordV1.TRAFFIC_MATERIAL_BYTES];
        for (int index = 0; index < AuthenticatedControlRecordV1.AES_256_KEY_BYTES; index++) {
            material[index] = (byte) index;
        }
        material[32] = (byte) 0xa0;
        material[33] = (byte) 0xa1;
        material[34] = (byte) 0xa2;
        material[35] = (byte) 0xa3;
        return material;
    }

    private static void requireOpenEquals(
            AuthenticatedControlRecordV1.Receiver receiver,
            byte[] envelope,
            String expected)
            throws Exception {
        try (AuthenticatedControlRecordV1.OpenedRecord opened = receiver.open(envelope)) {
            byte[] plaintext = opened.plaintext();
            require(Arrays.equals(plaintext, ascii(expected)), "opened plaintext " + expected);
            clear(plaintext);
        }
    }

    private static long headerCounter(byte[] envelope) {
        return ByteBuffer.wrap(envelope, COUNTER_OFFSET, Long.BYTES).getLong();
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] hex(String value) {
        if ((value.length() & 1) != 0) throw new IllegalArgumentException("odd hex length");
        byte[] output = new byte[value.length() / 2];
        for (int index = 0; index < output.length; index++) {
            int high = Character.digit(value.charAt(index * 2), 16);
            int low = Character.digit(value.charAt(index * 2 + 1), 16);
            if (high < 0 || low < 0) throw new IllegalArgumentException("invalid hex");
            output[index] = (byte) ((high << 4) | low);
        }
        return output;
    }

    private static void expectReason(
            AuthenticatedControlRecordV1.Reason expected, CheckedRunnable action)
            throws Exception {
        try {
            action.run();
            throw new AssertionError("expected control-record failure " + expected);
        } catch (AuthenticatedControlRecordV1.ControlRecordException actual) {
            require(actual.reason() == expected, "failure reason " + expected);
        }
    }

    private static void expectIllegalArgument(CheckedRunnable action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void clear(byte[]... values) {
        for (byte[] value : values) {
            if (value != null) Arrays.fill(value, (byte) 0);
        }
    }

    @FunctionalInterface
    private interface CheckedRunnable {
        void run() throws Exception;
    }
}
