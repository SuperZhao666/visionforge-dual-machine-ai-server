package com.visionforge.inferencebenchmark;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Base64;

/** SPKI pin validation and rotation checks using ephemeral test keys. */
public final class DualMachineTlsPinPolicySelfTest {
    private DualMachineTlsPinPolicySelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        KeyPair current = rsa();
        KeyPair backup = rsa();
        KeyPair attacker = rsa();
        String currentPin = DualMachineTlsPinPolicy.pinForEncodedPublicKey(
                current.getPublic().getEncoded());
        String backupPin = DualMachineTlsPinPolicy.pinForEncodedPublicKey(
                backup.getPublic().getEncoded());
        DualMachineTlsPinPolicy policy = new DualMachineTlsPinPolicy(
                Arrays.asList(currentPin, backupPin));
        policy.verify(new Certificate[]{certificate(current)});
        policy.verify(new Certificate[]{certificate(backup)});
        expectRejected(() -> policy.verify(
                new Certificate[]{certificate(attacker)}));
        expectInvalidPin(() -> new DualMachineTlsPinPolicy(Arrays.asList(
                "sha256/" + Base64.getEncoder().encodeToString(new byte[31]))));
        expectInvalidPin(() -> new DualMachineTlsPinPolicy(Arrays.asList(
                "md5/" + Base64.getEncoder().encodeToString(new byte[32]))));
        System.out.println("ANDROID_TLS_PIN_POLICY_OK");
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static Certificate certificate(KeyPair pair) {
        return new Certificate("TEST") {
            @Override
            public byte[] getEncoded() {
                return pair.getPublic().getEncoded();
            }

            @Override
            public void verify(java.security.PublicKey key) {
            }

            @Override
            public void verify(
                    java.security.PublicKey key,
                    String provider) {
            }

            @Override
            public String toString() {
                return "test-certificate";
            }

            @Override
            public java.security.PublicKey getPublicKey() {
                return pair.getPublic();
            }
        };
    }

    private static void expectRejected(CheckedRunnable action)
            throws Exception {
        try {
            action.run();
            throw new AssertionError("unpinned certificate was accepted");
        } catch (java.security.GeneralSecurityException expected) {
            // Expected.
        }
    }

    private static void expectInvalidPin(Runnable action) {
        try {
            action.run();
            throw new AssertionError("invalid pin was accepted");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private interface CheckedRunnable {
        void run() throws Exception;
    }
}
