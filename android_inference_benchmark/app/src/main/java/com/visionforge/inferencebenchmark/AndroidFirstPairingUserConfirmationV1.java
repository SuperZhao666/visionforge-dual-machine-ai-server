package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.handshake.FirstPairingUserConfirmationV1;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Typed Android identity adapter for one explicit first-pairing confirmation.
 *
 * <p>Production callers invoke {@link #signAfterUserConfirmation} only from an
 * actual local UI confirmation event. The adapter accepts no caller-built
 * payload or digest and verifies its own canonical low-S signature before it
 * leaves the AndroidKeyStore boundary.</p>
 */
public final class AndroidFirstPairingUserConfirmationV1 {
    interface IdentityCapability {
        byte[] publicKeySpkiDer() throws GeneralSecurityException;

        byte[] sign(byte[] canonicalPayload) throws GeneralSecurityException;
    }

    public static final class SignedConfirmation implements AutoCloseable {
        private byte[] canonicalPayload;
        private byte[] signatureDerLowS;
        private boolean closed;

        private SignedConfirmation(
                byte[] canonicalPayload,
                byte[] signatureDerLowS) {
            this.canonicalPayload = canonicalPayload;
            this.signatureDerLowS = signatureDerLowS;
        }

        public synchronized byte[] canonicalPayload()
                throws GeneralSecurityException {
            requireOpen();
            return canonicalPayload.clone();
        }

        public synchronized byte[] signatureDerLowS()
                throws GeneralSecurityException {
            requireOpen();
            return signatureDerLowS.clone();
        }

        @Override
        public synchronized void close() {
            if (closed) return;
            closed = true;
            clear(canonicalPayload);
            canonicalPayload = null;
            clear(signatureDerLowS);
            signatureDerLowS = null;
        }

        private void requireOpen() throws GeneralSecurityException {
            if (closed || canonicalPayload == null
                    || signatureDerLowS == null) {
                throw rejected();
            }
        }
    }

    private AndroidFirstPairingUserConfirmationV1() {}

    public static SignedConfirmation signAfterUserConfirmation(
            AndroidPairingIdentityStore identityStore,
            int method,
            byte[] attemptId,
            byte[] commitmentSha256,
            byte[] expectedAndroidIdentitySpkiSha256,
            long expiresAtEpoch) throws GeneralSecurityException {
        if (identityStore == null) throw rejected();
        return signWithIdentity(
                new IdentityCapability() {
                    @Override
                    public byte[] publicKeySpkiDer()
                            throws GeneralSecurityException {
                        return identityStore.publicKeySpkiDer();
                    }

                    @Override
                    public byte[] sign(byte[] canonicalPayload)
                            throws GeneralSecurityException {
                        return identityStore.sign(canonicalPayload);
                    }
                },
                method,
                attemptId,
                commitmentSha256,
                expectedAndroidIdentitySpkiSha256,
                expiresAtEpoch);
    }

    static SignedConfirmation signWithIdentity(
            IdentityCapability identity,
            int method,
            byte[] attemptId,
            byte[] commitmentSha256,
            byte[] expectedAndroidIdentitySpkiSha256,
            long expiresAtEpoch) throws GeneralSecurityException {
        byte[] publicKey = null;
        byte[] actualIdentitySha256 = null;
        byte[] canonical = null;
        byte[] signature = null;
        try {
            if (identity == null
                    || expectedAndroidIdentitySpkiSha256 == null
                    || expectedAndroidIdentitySpkiSha256.length != 32) {
                throw rejected();
            }
            publicKey = DualMachinePairingIdentityCodec
                    .requirePublicKey(identity.publicKeySpkiDer())
                    .getEncoded();
            actualIdentitySha256 = MessageDigest.getInstance("SHA-256")
                    .digest(publicKey);
            if (!MessageDigest.isEqual(
                    actualIdentitySha256,
                    expectedAndroidIdentitySpkiSha256)) {
                throw rejected();
            }
            try (FirstPairingUserConfirmationV1.Result payload =
                    FirstPairingUserConfirmationV1.build(
                            FirstPairingUserConfirmationV1.ROLE_ANDROID,
                            method,
                            attemptId,
                            commitmentSha256,
                            expiresAtEpoch)) {
                canonical = payload.canonicalEncoding();
            }
            signature = identity.sign(canonical.clone());
            if (!DualMachinePairingIdentityCodec.verify(
                    publicKey, canonical, signature)) {
                throw rejected();
            }
            SignedConfirmation result = new SignedConfirmation(
                    canonical.clone(), signature.clone());
            return result;
        } catch (GeneralSecurityException | RuntimeException failure) {
            throw rejected();
        } finally {
            clear(publicKey);
            clear(actualIdentitySha256);
            clear(canonical);
            clear(signature);
        }
    }

    public static void verifyHostConfirmation(
            byte[] hostIdentitySpkiDer,
            byte[] expectedHostIdentitySpkiSha256,
            int method,
            byte[] attemptId,
            byte[] commitmentSha256,
            long expiresAtEpoch,
            byte[] signatureDerLowS) throws GeneralSecurityException {
        byte[] publicKey = null;
        byte[] actualIdentitySha256 = null;
        byte[] canonical = null;
        try {
            if (expectedHostIdentitySpkiSha256 == null
                    || expectedHostIdentitySpkiSha256.length != 32
                    || signatureDerLowS == null) {
                throw rejected();
            }
            publicKey = DualMachinePairingIdentityCodec
                    .requirePublicKey(hostIdentitySpkiDer)
                    .getEncoded();
            actualIdentitySha256 = MessageDigest.getInstance("SHA-256")
                    .digest(publicKey);
            if (!MessageDigest.isEqual(
                    actualIdentitySha256,
                    expectedHostIdentitySpkiSha256)) {
                throw rejected();
            }
            try (FirstPairingUserConfirmationV1.Result payload =
                    FirstPairingUserConfirmationV1.build(
                            FirstPairingUserConfirmationV1.ROLE_HOST,
                            method,
                            attemptId,
                            commitmentSha256,
                            expiresAtEpoch)) {
                canonical = payload.canonicalEncoding();
            }
            if (!DualMachinePairingIdentityCodec.verify(
                    publicKey, canonical, signatureDerLowS)) {
                throw rejected();
            }
        } catch (GeneralSecurityException | RuntimeException failure) {
            throw rejected();
        } finally {
            clear(publicKey);
            clear(actualIdentitySha256);
            clear(canonical);
        }
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    private static GeneralSecurityException rejected() {
        return new GeneralSecurityException(
                "first pairing user confirmation signature was rejected");
    }
}
