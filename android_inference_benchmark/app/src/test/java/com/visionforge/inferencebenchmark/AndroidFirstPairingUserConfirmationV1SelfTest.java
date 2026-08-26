package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.handshake.FirstPairingUserConfirmationV1;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

/** JVM proof that VFU1 signs only the typed identity-bound confirmation. */
public final class AndroidFirstPairingUserConfirmationV1SelfTest {
    private AndroidFirstPairingUserConfirmationV1SelfTest() {}

    public static void main(String[] arguments) throws Exception {
        KeyPair android = keyPair();
        KeyPair host = keyPair();
        byte[] attempt = sequence(16);
        byte[] commitment = bytes(32, 0x5a);
        byte[] androidIdentity = sha256(android.getPublic().getEncoded());
        byte[] hostIdentity = sha256(host.getPublic().getEncoded());

        AndroidFirstPairingUserConfirmationV1.IdentityCapability capability =
                new AndroidFirstPairingUserConfirmationV1.IdentityCapability() {
                    @Override
                    public byte[] publicKeySpkiDer() {
                        return android.getPublic().getEncoded();
                    }

                    @Override
                    public byte[] sign(byte[] canonicalPayload)
                            throws GeneralSecurityException {
                        return DualMachinePairingIdentityCodec.sign(
                                android.getPrivate(), canonicalPayload);
                    }
                };
        try (AndroidFirstPairingUserConfirmationV1.SignedConfirmation signed =
                AndroidFirstPairingUserConfirmationV1.signWithIdentity(
                        capability,
                        FirstPairingUserConfirmationV1.METHOD_DECIMAL_SAS,
                        attempt,
                        commitment,
                        androidIdentity,
                        2_000_000_000L)) {
            require(DualMachinePairingIdentityCodec.verify(
                    android.getPublic().getEncoded(),
                    signed.canonicalPayload(),
                    signed.signatureDerLowS()), "Android self signature");
        }

        byte[] hostSignature;
        try (FirstPairingUserConfirmationV1.Result payload =
                FirstPairingUserConfirmationV1.build(
                        FirstPairingUserConfirmationV1.ROLE_HOST,
                        FirstPairingUserConfirmationV1.METHOD_QR,
                        attempt,
                        commitment,
                        2_000_000_000L)) {
            hostSignature = DualMachinePairingIdentityCodec.sign(
                    host.getPrivate(), payload.canonicalEncoding());
        }
        AndroidFirstPairingUserConfirmationV1.verifyHostConfirmation(
                host.getPublic().getEncoded(),
                hostIdentity,
                FirstPairingUserConfirmationV1.METHOD_QR,
                attempt,
                commitment,
                2_000_000_000L,
                hostSignature);

        byte[] wrongCommitment = commitment.clone();
        wrongCommitment[0] ^= 1;
        expectRejected(() ->
                AndroidFirstPairingUserConfirmationV1.verifyHostConfirmation(
                        host.getPublic().getEncoded(),
                        hostIdentity,
                        FirstPairingUserConfirmationV1.METHOD_QR,
                        attempt,
                        wrongCommitment,
                        2_000_000_000L,
                        hostSignature));
        expectRejected(() ->
                AndroidFirstPairingUserConfirmationV1.signWithIdentity(
                        capability,
                        FirstPairingUserConfirmationV1.METHOD_DECIMAL_SAS,
                        attempt,
                        commitment,
                        hostIdentity,
                        2_000_000_000L));

        Arrays.fill(hostSignature, (byte) 0);
        System.out.println("AndroidFirstPairingUserConfirmationV1SelfTest: PASS");
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }

    private static void expectRejected(ThrowingAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("invalid confirmation was accepted");
        } catch (GeneralSecurityException expected) {
            // Expected.
        }
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static byte[] sha256(byte[] value) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(value);
    }

    private static byte[] sequence(int length) {
        byte[] result = new byte[length];
        for (int index = 0; index < length; index++) {
            result[index] = (byte) (index + 1);
        }
        return result;
    }

    private static byte[] bytes(int length, int value) {
        byte[] result = new byte[length];
        Arrays.fill(result, (byte) value);
        return result;
    }

    private static void require(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
    }
}
