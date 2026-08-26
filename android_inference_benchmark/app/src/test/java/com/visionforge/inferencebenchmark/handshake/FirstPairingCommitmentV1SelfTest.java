package com.visionforge.inferencebenchmark.handshake;

import java.security.GeneralSecurityException;
import java.util.Arrays;

/** Dependency-free cross-language VFP1 commitment contract. */
public final class FirstPairingCommitmentV1SelfTest {
    private FirstPairingCommitmentV1SelfTest() {}

    public static void main(String[] arguments) throws Exception {
        fixedCrossLanguageVector();
        fixedUserConfirmationVector();
        invalidFieldsFailClosed();
        System.out.println("FirstPairingCommitmentV1SelfTest: PASS");
    }

    private static void fixedUserConfirmationVector() throws Exception {
        byte[] attempt = new byte[16];
        for (int index = 0; index < attempt.length; index++) {
            attempt[index] = (byte) (index + 1);
        }
        try (FirstPairingUserConfirmationV1.Result result =
                FirstPairingUserConfirmationV1.build(
                        FirstPairingUserConfirmationV1.ROLE_HOST,
                        FirstPairingUserConfirmationV1.METHOD_DECIMAL_SAS,
                        attempt,
                        bytes(32, 0xaa),
                        2_000_000_000L)) {
            require(result.canonicalEncoding().length == 64, "VFU1 size");
            require(
                    "e54fa513da2102870b3e7f6439d5cbf7"
                            .concat(
                                    "2c6568f69c0d42de0e8fe3d0e6290308")
                            .equals(hex(result.payloadSha256())),
                    "cross-language user-confirmation digest");
        }
        try {
            FirstPairingUserConfirmationV1.build(
                    FirstPairingUserConfirmationV1.ROLE_ANDROID,
                    0,
                    attempt,
                    bytes(32, 0xaa),
                    2_000_000_000L);
            throw new AssertionError("invalid confirmation method was accepted");
        } catch (GeneralSecurityException expected) {
            // Expected.
        }
    }

    private static void fixedCrossLanguageVector() throws Exception {
        try (FirstPairingCommitmentV1.Result result =
                FirstPairingCommitmentV1.build(fields())) {
            require(result.canonicalEncoding().length == 368, "canonical size");
            require(result.canonicalEncoding()[0] == 0x56, "VFP1 magic");
            require(
                    "33f3dca1e5830d6588a192e46cb3490a"
                            .concat(
                                    "498988bef840cd63284dd98f5b5fa741")
                            .equals(hex(result.commitmentSha256())),
                    "cross-language commitment digest");
            require(
                    "102685".equals(result.decimalSas()),
                    "cross-language decimal SAS");
        }
    }

    private static void invalidFieldsFailClosed() throws Exception {
        FirstPairingCommitmentV1.Fields baseline = fields();
        expectRejected(new FirstPairingCommitmentV1.Fields(
                baseline.transportKind,
                baseline.requiredCapabilities,
                bytes(16, 0x01),
                bytes(32, 0x22),
                bytes(32, 0x22),
                p256(0x33), p256(0x44),
                bytes(32, 0x55), bytes(32, 0x66),
                new byte[] {(byte) 192, (byte) 168, 1, 22},
                new byte[] {(byte) 192, (byte) 168, 1, 42},
                5005, 5006,
                bytes(32, 0x77), bytes(32, 0x88),
                2_000_000_000L));
        expectRejected(new FirstPairingCommitmentV1.Fields(
                baseline.transportKind,
                baseline.requiredCapabilities,
                bytes(16, 0x01),
                bytes(32, 0x11), bytes(32, 0x22),
                p256(0x33), p256(0x44),
                bytes(32, 0x55), bytes(32, 0x66),
                new byte[] {(byte) 192, (byte) 168, 1, 22},
                new byte[] {(byte) 192, (byte) 168, 1, 42},
                5005, 5005,
                bytes(32, 0x77), bytes(32, 0x88),
                2_000_000_000L));
    }

    private static FirstPairingCommitmentV1.Fields fields() {
        byte[] attempt = new byte[16];
        for (int index = 0; index < attempt.length; index++) {
            attempt[index] = (byte) (index + 1);
        }
        return new FirstPairingCommitmentV1.Fields(
                FirstPairingCommitmentV1.TRANSPORT_ETHERNET,
                FirstPairingCommitmentV1
                        .CAPABILITY_TWO_SIDED_USER_CONFIRMATION,
                attempt,
                bytes(32, 0x11), bytes(32, 0x22),
                p256(0x33), p256(0x44),
                bytes(32, 0x55), bytes(32, 0x66),
                new byte[] {(byte) 192, (byte) 168, 1, 22},
                new byte[] {(byte) 192, (byte) 168, 1, 42},
                5005, 5006,
                bytes(32, 0x77), bytes(32, 0x88),
                2_000_000_000L);
    }

    private static byte[] p256(int value) {
        byte[] result = bytes(65, value);
        result[0] = 0x04;
        return result;
    }

    private static byte[] bytes(int length, int value) {
        byte[] result = new byte[length];
        Arrays.fill(result, (byte) value);
        return result;
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(String.format("%02x", item & 0xff));
        }
        return result.toString();
    }

    private static void expectRejected(FirstPairingCommitmentV1.Fields value)
            throws Exception {
        try {
            FirstPairingCommitmentV1.build(value);
            throw new AssertionError("invalid commitment was accepted");
        } catch (GeneralSecurityException expected) {
            // Expected.
        }
    }

    private static void require(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
    }
}
