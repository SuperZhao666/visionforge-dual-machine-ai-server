package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Produces and locally verifies the two independent P-256 proofs required by
 * every sensitive dual-machine sidecar operation.
 *
 * <p>The caller must first construct the payload with
 * {@link DualMachineUsageAuthorizationContract}. Each signer receives its own
 * copy, so a peer implementation cannot alter the bytes later signed by the
 * other device. No server-provided opaque payload is ever signed.</p>
 */
public final class DualMachineDeviceProofs {
    @FunctionalInterface
    public interface ProofSigner {
        byte[] sign(byte[] canonicalPayload)
                throws IOException, GeneralSecurityException;
    }

    public static final class SignedProof {
        public final String hostSignatureBase64;
        public final String androidSignatureBase64;

        private SignedProof(
                String hostSignatureBase64,
                String androidSignatureBase64) {
            this.hostSignatureBase64 = hostSignatureBase64;
            this.androidSignatureBase64 = androidSignatureBase64;
        }
    }

    private DualMachineDeviceProofs() {
    }

    public static SignedProof createVerified(
            byte[] canonicalPayload,
            byte[] hostIdentityPublicKeyDer,
            byte[] androidIdentityPublicKeyDer,
            ProofSigner hostSigner,
            ProofSigner androidSigner)
            throws IOException, GeneralSecurityException {
        requirePayload(canonicalPayload);
        if (hostSigner == null || androidSigner == null) {
            throw new IllegalArgumentException("both proof signers are required");
        }
        byte[] hostKey = requireIdentity(hostIdentityPublicKeyDer);
        byte[] androidKey = requireIdentity(androidIdentityPublicKeyDer);
        if (Arrays.equals(hostKey, androidKey)) {
            throw new GeneralSecurityException(
                    "host and Android proof identities must differ");
        }

        byte[] payload = canonicalPayload.clone();
        byte[] hostSignature = requireSignature(
                hostSigner.sign(payload.clone()), "host");
        byte[] androidSignature = requireSignature(
                androidSigner.sign(payload.clone()), "Android");
        if (!DualMachinePairingIdentityCodec.verify(
                hostKey, payload, hostSignature)) {
            throw new GeneralSecurityException(
                    "host proof signature verification failed");
        }
        if (!DualMachinePairingIdentityCodec.verify(
                androidKey, payload, androidSignature)) {
            throw new GeneralSecurityException(
                    "Android proof signature verification failed");
        }
        return new SignedProof(
                Base64.getEncoder().encodeToString(hostSignature),
                Base64.getEncoder().encodeToString(androidSignature));
    }

    private static void requirePayload(byte[] value) {
        if (value == null || value.length == 0
                || value.length > DualMachinePairingIdentityCodec.MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException(
                    "canonical proof payload is missing or oversized");
        }
    }

    private static byte[] requireIdentity(byte[] value)
            throws GeneralSecurityException {
        if (value == null) {
            throw new IllegalArgumentException("identity public key is required");
        }
        return DualMachinePairingIdentityCodec.requirePublicKey(
                value.clone()).getEncoded();
    }

    private static byte[] requireSignature(byte[] value, String peer) {
        if (value == null || value.length == 0
                || value.length
                > DualMachinePairingIdentityCodec.MAX_SIGNATURE_DER_BYTES) {
            throw new IllegalArgumentException(
                    peer + " proof signature is missing or oversized");
        }
        return value.clone();
    }
}
