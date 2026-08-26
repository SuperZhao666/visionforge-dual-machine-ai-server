package com.visionforge.inferencebenchmark.handshake;

import com.visionforge.inferencebenchmark.DualMachinePairingIdentityCodec;
import com.visionforge.inferencebenchmark.DualMachineUsageAuthorizationContract;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

/** Cross-language first-pairing payload round-trip and mutation contracts. */
public final class FirstPairingBootstrapPayloadV1SelfTest {
    private FirstPairingBootstrapPayloadV1SelfTest() {}

    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(
                new ECGenParameterSpec("secp256r1"),
                SecureRandom.getInstance("SHA1PRNG"));
        KeyPair identity = generator.generateKeyPair();
        byte[] attempt = filled(16, 0x11);
        byte[] ephemeral = filled(65, 0x22);
        ephemeral[0] = 0x04;
        FirstPairingBootstrapPayloadV1.Offer offer =
                new FirstPairingBootstrapPayloadV1.Offer(
                        FirstPairingCommitmentV1
                                .CAPABILITY_TWO_SIDED_USER_CONFIRMATION,
                        FirstPairingUserConfirmationV1.METHOD_DECIMAL_SAS,
                        attempt,
                        identity.getPublic().getEncoded(),
                        ephemeral,
                        filled(32, 0x33),
                        filled(32, 0x44),
                        1_800_000_000L);
        byte[] encodedOffer = FirstPairingBootstrapPayloadV1.encodeOffer(
                AuthenticatedControlBootstrapRecordV1.MessageType
                        .HOST_FIRST_PAIR_OFFER,
                offer);
        require(encodedOffer.length == 256, "offer size");
        FirstPairingBootstrapPayloadV1.Offer parsedOffer =
                FirstPairingBootstrapPayloadV1.parseOffer(
                        AuthenticatedControlBootstrapRecordV1.MessageType
                                .HOST_FIRST_PAIR_OFFER,
                        encodedOffer);
        require(Arrays.equals(parsedOffer.attemptId(), attempt), "attempt");
        require(Arrays.equals(
                parsedOffer.identitySpkiDer(),
                identity.getPublic().getEncoded()), "SPKI");
        byte[] badOffer = encodedOffer.clone();
        badOffer[5] = 0;
        expectRejected(() -> FirstPairingBootstrapPayloadV1.parseOffer(
                AuthenticatedControlBootstrapRecordV1.MessageType
                        .HOST_FIRST_PAIR_OFFER,
                badOffer));

        byte[] commitment = filled(32, 0x55);
        byte[] signature = DualMachinePairingIdentityCodec.sign(
                identity.getPrivate(), new byte[] {1, 2, 3});
        FirstPairingBootstrapPayloadV1.Confirmation confirmation =
                new FirstPairingBootstrapPayloadV1.Confirmation(
                        FirstPairingUserConfirmationV1.ROLE_ANDROID,
                        FirstPairingUserConfirmationV1.METHOD_DECIMAL_SAS,
                        attempt,
                        commitment,
                        1_800_000_000L,
                        signature);
        byte[] encodedConfirmation =
                FirstPairingBootstrapPayloadV1.encodeConfirmation(
                        AuthenticatedControlBootstrapRecordV1.MessageType
                                .ANDROID_FIRST_PAIR_CONFIRMATION,
                        confirmation);
        FirstPairingBootstrapPayloadV1.Confirmation parsedConfirmation =
                FirstPairingBootstrapPayloadV1.parseConfirmation(
                        AuthenticatedControlBootstrapRecordV1.MessageType
                                .ANDROID_FIRST_PAIR_CONFIRMATION,
                        encodedConfirmation);
        require(Arrays.equals(
                parsedConfirmation.commitmentSha256(), commitment),
                "commitment");
        expectRejected(() ->
                FirstPairingBootstrapPayloadV1.encodeConfirmation(
                        AuthenticatedControlBootstrapRecordV1.MessageType
                                .HOST_FIRST_PAIR_CONFIRMATION,
                        confirmation));

        DualMachineUsageAuthorizationContract.ActivationConfirmation proof =
                new DualMachineUsageAuthorizationContract
                        .ActivationConfirmation();
        proof.activationMode = "activate";
        proof.androidClientVersion = "1.0.0";
        proof.androidDeviceCode = "ANDROID-ABC";
        proof.androidDeviceProfileSha256 = repeat('4', 64);
        proof.androidKeySha256 = repeat('5', 64);
        proof.challengeId = repeat('1', 32);
        proof.challengeTokenSha256 = repeat('6', 64);
        proof.hostClientVersion = "17.8.81";
        proof.hostDeviceCode = "HOST-XYZ";
        proof.hostKeySha256 = repeat('7', 64);
        proof.pairId = repeat('2', 32);
        proof.protocolVersion = 2;
        proof.requestId = repeat('3', 32);
        proof.targetEntitlementId = "";
        byte[] encodedProof =
                FirstPairingBootstrapPayloadV1
                        .encodeActivationProofRequest(proof);
        DualMachineUsageAuthorizationContract.ActivationConfirmation
                parsedProof = FirstPairingBootstrapPayloadV1
                        .parseActivationProofRequest(encodedProof);
        require(Arrays.equals(
                DualMachineUsageAuthorizationContract
                        .activationConfirmation(proof),
                DualMachineUsageAuthorizationContract
                        .activationConfirmation(parsedProof)),
                "activation proof");
        byte[] badProof = encodedProof.clone();
        badProof[badProof.length - 1] = 1;
        expectRejected(() -> FirstPairingBootstrapPayloadV1
                .parseActivationProofRequest(badProof));

        FirstPairingBootstrapPayloadV1.ActivationSignature activationSignature =
                new FirstPairingBootstrapPayloadV1.ActivationSignature(
                        filled(32, 0x66), signature);
        require(Arrays.equals(
                FirstPairingBootstrapPayloadV1.parseActivationSignature(
                        FirstPairingBootstrapPayloadV1
                                .encodeActivationSignature(activationSignature))
                        .canonicalPayloadSha256(),
                filled(32, 0x66)), "activation signature");

        FirstPairingBootstrapPayloadV1.ActivationResult activationResult =
                new FirstPairingBootstrapPayloadV1.ActivationResult(
                        repeat('1', 32), repeat('2', 32), repeat('3', 32),
                        4L, 5L);
        FirstPairingBootstrapPayloadV1.ActivationResult parsedResult =
                FirstPairingBootstrapPayloadV1.parseActivationResult(
                        FirstPairingBootstrapPayloadV1
                                .encodeActivationResult(activationResult));
        require(parsedResult.bindingRevision == 4L, "binding revision");
        require(parsedResult.pairId.equals(repeat('2', 32)), "pair id");

        require(Arrays.equals(
                FirstPairingBootstrapPayloadV1.parseComplete(
                        FirstPairingBootstrapPayloadV1
                                .encodeComplete(commitment)),
                commitment), "complete");
        require(AuthenticatedControlBootstrapRecordV1.isAllowed(
                AuthenticatedControlBootstrapRecordV1.Direction.HOST_TO_ANDROID,
                AuthenticatedControlBootstrapRecordV1.MessageType
                        .HOST_FIRST_PAIR_OFFER), "Host offer direction");
        require(!AuthenticatedControlBootstrapRecordV1.isAllowed(
                AuthenticatedControlBootstrapRecordV1.Direction.ANDROID_TO_HOST,
                AuthenticatedControlBootstrapRecordV1.MessageType
                        .HOST_FIRST_PAIR_OFFER), "Host offer reflection");
        require(AuthenticatedControlBootstrapRecordV1.isAllowed(
                AuthenticatedControlBootstrapRecordV1.Direction.ANDROID_TO_HOST,
                AuthenticatedControlBootstrapRecordV1.MessageType
                        .ACTIVATION_RESULT), "activation result direction");

        System.out.println("FirstPairingBootstrapPayloadV1SelfTest: PASS");
    }

    private static byte[] filled(int size, int value) {
        byte[] result = new byte[size];
        Arrays.fill(result, (byte) value);
        return result;
    }

    private static String repeat(char value, int count) {
        char[] result = new char[count];
        Arrays.fill(result, value);
        return new String(result);
    }

    private static void expectRejected(CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected rejection");
        } catch (java.security.GeneralSecurityException expected) {
            // Expected.
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface
    private interface CheckedAction {
        void run() throws Exception;
    }
}
