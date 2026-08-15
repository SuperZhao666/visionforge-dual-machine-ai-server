package com.visionforge.inferencebenchmark;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;

/** Dependency-free two-device proof and payload-isolation contract. */
public final class DualMachineDeviceProofsSelfTest {
    private DualMachineDeviceProofsSelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        verifiesBothSignaturesBeforeReturning();
        rejectsWrongPeerAndMutatedPayloadSignatures();
        rejectsSharedIdentityAndUnboundedOutputs();
        System.out.println("DUAL_MACHINE_DEVICE_PROOFS_OK");
    }

    private static void verifiesBothSignaturesBeforeReturning()
            throws Exception {
        KeyPair host = keyPair();
        KeyPair android = keyPair();
        byte[] payload = payload();
        AtomicBoolean hostSawOriginal = new AtomicBoolean();
        DualMachineDeviceProofs.SignedProof proof =
                DualMachineDeviceProofs.createVerified(
                        payload,
                        host.getPublic().getEncoded(),
                        android.getPublic().getEncoded(),
                        bytes -> {
                            hostSawOriginal.set(java.util.Arrays.equals(
                                    bytes, payload()));
                            bytes[0] ^= 1;
                            return DualMachinePairingIdentityCodec.sign(
                                    host.getPrivate(), payload());
                        },
                        bytes -> DualMachinePairingIdentityCodec.sign(
                                android.getPrivate(), bytes));
        check(hostSawOriginal.get());
        check(DualMachinePairingIdentityCodec.verify(
                host.getPublic().getEncoded(),
                payload,
                Base64.getDecoder().decode(proof.hostSignatureBase64)));
        check(DualMachinePairingIdentityCodec.verify(
                android.getPublic().getEncoded(),
                payload,
                Base64.getDecoder().decode(proof.androidSignatureBase64)));
    }

    private static void rejectsWrongPeerAndMutatedPayloadSignatures()
            throws Exception {
        KeyPair host = keyPair();
        KeyPair android = keyPair();
        KeyPair attacker = keyPair();
        expectSecurity(() -> DualMachineDeviceProofs.createVerified(
                payload(),
                host.getPublic().getEncoded(),
                android.getPublic().getEncoded(),
                bytes -> DualMachinePairingIdentityCodec.sign(
                        attacker.getPrivate(), bytes),
                bytes -> DualMachinePairingIdentityCodec.sign(
                        android.getPrivate(), bytes)));
        expectSecurity(() -> DualMachineDeviceProofs.createVerified(
                payload(),
                host.getPublic().getEncoded(),
                android.getPublic().getEncoded(),
                bytes -> DualMachinePairingIdentityCodec.sign(
                        host.getPrivate(), changed(bytes)),
                bytes -> DualMachinePairingIdentityCodec.sign(
                        android.getPrivate(), bytes)));
    }

    private static void rejectsSharedIdentityAndUnboundedOutputs()
            throws Exception {
        KeyPair host = keyPair();
        expectSecurity(() -> DualMachineDeviceProofs.createVerified(
                payload(),
                host.getPublic().getEncoded(),
                host.getPublic().getEncoded(),
                bytes -> DualMachinePairingIdentityCodec.sign(
                        host.getPrivate(), bytes),
                bytes -> DualMachinePairingIdentityCodec.sign(
                        host.getPrivate(), bytes)));
        KeyPair android = keyPair();
        expectIllegal(() -> DualMachineDeviceProofs.createVerified(
                payload(),
                host.getPublic().getEncoded(),
                android.getPublic().getEncoded(),
                bytes -> new byte[
                        DualMachinePairingIdentityCodec.MAX_SIGNATURE_DER_BYTES
                                + 1],
                bytes -> DualMachinePairingIdentityCodec.sign(
                        android.getPrivate(), bytes)));
    }

    private static byte[] payload() {
        DualMachineUsageAuthorizationContract.EntitlementStatus request =
                new DualMachineUsageAuthorizationContract.EntitlementStatus();
        request.entitlementId = "11".repeat(16);
        request.pairId = "22".repeat(16);
        request.requestNonce = "33".repeat(16);
        request.revocationVersion = 1L;
        return DualMachineUsageAuthorizationContract.entitlementStatus(
                request);
    }

    private static byte[] changed(byte[] value) {
        byte[] changed = value.clone();
        changed[changed.length - 1] ^= 1;
        return changed;
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(
                DualMachinePairingIdentityCodec.CURVE_NAME));
        return generator.generateKeyPair();
    }

    private static void expectSecurity(Action action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected security rejection");
        } catch (GeneralSecurityException expected) {
            // Expected.
        }
    }

    private static void expectIllegal(Action action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected input rejection");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("device proof check failed");
    }

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }
}
