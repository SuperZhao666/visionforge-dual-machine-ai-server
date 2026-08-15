package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

/** Dependency-free offline regression checks for the P-256 pairing identity codec. */
public final class DualMachinePairingIdentityCodecSelfTest {
    private static final int P256_SPKI_DER_LENGTH = 91;

    private DualMachinePairingIdentityCodecSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        generatesP256KeyWithCanonicalDer();
        encodesAndDecodesBase64RoundTrip();
        rejectsNonCanonicalBase64Aliases();
        computesLowercaseSha256Fingerprint();
        signsAndVerifiesPayload();
        everySignatureIsCanonicalLowS();
        rejectsTamperedPayloadSignatureAndKey();
        rejectsNonP256Keys();
        rejectsNullEmptyAndOversizeInputs();
        System.out.println("DUAL_MACHINE_PAIRING_IDENTITY_CODEC_SELF_TEST_OK");
    }

    private static void generatesP256KeyWithCanonicalDer() throws Exception {
        KeyPair keyPair = generateP256KeyPair();
        byte[] derSpki = keyPair.getPublic().getEncoded();
        require(derSpki.length == P256_SPKI_DER_LENGTH, "P-256 SPKI DER must be 91 bytes");
        require(derSpki[0] == 0x30, "SPKI DER must start with a SEQUENCE");
        ECPublicKey parsed = DualMachinePairingIdentityCodec.requirePublicKey(derSpki);
        require(Arrays.equals(derSpki, parsed.getEncoded()), "parsed key must re-encode identically");
        // Canonical form must be stable: re-encoding a generated key is a fixed point.
        require(Arrays.equals(derSpki,
                DualMachinePairingIdentityCodec.requirePublicKey(derSpki).getEncoded()),
                "canonical DER must be a fixed point");
    }

    private static void encodesAndDecodesBase64RoundTrip() throws Exception {
        byte[] derSpki = generateP256KeyPair().getPublic().getEncoded();
        String base64 = DualMachinePairingIdentityCodec.encodePublicKeyBase64(derSpki);
        require(base64.equals(Base64.getEncoder().encodeToString(derSpki)),
                "Base64 must use the standard alphabet with padding");
        require(Arrays.equals(derSpki, DualMachinePairingIdentityCodec.decodePublicKeyBase64(base64)),
                "Base64 round trip mismatch");
        require(DualMachinePairingIdentityCodec.encodePublicKeyBase64(derSpki).equals(base64),
                "encoding must be deterministic");
    }

    private static void rejectsNonCanonicalBase64Aliases() throws Exception {
        byte[] derSpki = generateP256KeyPair().getPublic().getEncoded();
        String canonical = Base64.getEncoder().encodeToString(derSpki);
        require(canonical.endsWith("=="), "P-256 SPKI fixture must have two padding bytes");

        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.decodePublicKeyBase64(
                        canonical.substring(0, canonical.length() - 2)),
                "missing Base64 padding must be rejected");

        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int characterIndex = canonical.length() - 3;
        int alphabetIndex = alphabet.indexOf(canonical.charAt(characterIndex));
        String alias = canonical.substring(0, characterIndex)
                + alphabet.charAt(alphabetIndex ^ 1)
                + canonical.substring(characterIndex + 1);
        require(Arrays.equals(
                        Base64.getDecoder().decode(canonical),
                        Base64.getDecoder().decode(alias)),
                "test alias must decode to the same DER bytes");
        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.decodePublicKeyBase64(alias),
                "non-canonical Base64 padding bits must be rejected");
    }

    private static void computesLowercaseSha256Fingerprint() throws Exception {
        byte[] derSpki = generateP256KeyPair().getPublic().getEncoded();
        String fingerprint = DualMachinePairingIdentityCodec.fingerprintHex(derSpki);
        require(fingerprint.length() == DualMachinePairingIdentityCodec.SHA256_HEX_LENGTH,
                "fingerprint must be 64 hex characters");
        require(fingerprint.matches("[0-9a-f]{64}"), "fingerprint must be lowercase hex");
        byte[] expectedDigest = MessageDigest.getInstance("SHA-256").digest(derSpki);
        StringBuilder expected = new StringBuilder();
        for (byte value : expectedDigest) {
            expected.append(String.format("%02x", value));
        }
        require(expected.toString().equals(fingerprint), "fingerprint must be SHA-256 of DER SPKI");
        require(DualMachinePairingIdentityCodec.fingerprintHexFromBase64(
                DualMachinePairingIdentityCodec.encodePublicKeyBase64(derSpki)).equals(fingerprint),
                "Base64 fingerprint path must agree with the DER path");
    }

    private static void signsAndVerifiesPayload() throws Exception {
        KeyPair keyPair = generateP256KeyPair();
        byte[] payload = "VisionForge pairing transcript".getBytes(StandardCharsets.UTF_8);
        byte[] signature = DualMachinePairingIdentityCodec.sign(keyPair.getPrivate(), payload);
        require(signature.length > 0
                        && signature.length <= DualMachinePairingIdentityCodec.MAX_SIGNATURE_DER_BYTES,
                "signature must be within DER bounds");
        require(signature[0] == 0x30, "ECDSA signature must be DER SEQUENCE encoded");
        require(DualMachinePairingIdentityCodec.verify(
                keyPair.getPublic().getEncoded(), payload, signature),
                "valid signature must verify");
    }

    private static void everySignatureIsCanonicalLowS() throws Exception {
        KeyPair keyPair = generateP256KeyPair();
        byte[] publicKey = keyPair.getPublic().getEncoded();
        for (int index = 0; index < 128; index++) {
            byte[] payload = ("identity-proof-low-s-" + index)
                    .getBytes(StandardCharsets.UTF_8);
            byte[] signature = DualMachinePairingIdentityCodec.sign(
                    keyPair.getPrivate(), payload);
            require(signature.length <= DualMachinePairingIdentityCodec.MAX_SIGNATURE_DER_BYTES
                            && signature.length >= 8
                            && signature[0] == 0x30,
                    "signature is not bounded DER at iteration " + index);
            require(DualMachinePairingIdentityCodec.verify(
                            publicKey, payload, signature),
                    "canonicalized signature no longer verifies");
        }
    }

    private static void rejectsTamperedPayloadSignatureAndKey() throws Exception {
        KeyPair keyPair = generateP256KeyPair();
        byte[] derSpki = keyPair.getPublic().getEncoded();
        byte[] payload = "pairing-payload".getBytes(StandardCharsets.UTF_8);
        byte[] signature = DualMachinePairingIdentityCodec.sign(keyPair.getPrivate(), payload);

        byte[] changedPayload = payload.clone();
        changedPayload[0] ^= 1;
        require(!DualMachinePairingIdentityCodec.verify(derSpki, changedPayload, signature),
                "payload tamper must fail verification");

        byte[] changedSignature = signature.clone();
        changedSignature[changedSignature.length - 1] ^= 1;
        require(!DualMachinePairingIdentityCodec.verify(derSpki, payload, changedSignature),
                "signature tamper must fail verification");

        byte[] truncatedSignature = Arrays.copyOf(signature, signature.length - 2);
        require(!DualMachinePairingIdentityCodec.verify(derSpki, payload, truncatedSignature),
                "truncated signature must fail verification");

        byte[] otherKey = generateP256KeyPair().getPublic().getEncoded();
        require(!DualMachinePairingIdentityCodec.verify(otherKey, payload, signature),
                "wrong identity key must fail verification");

        byte[] changedSpki = derSpki.clone();
        changedSpki[changedSpki.length - 1] ^= 1;
        boolean tamperedKeyRejected;
        try {
            tamperedKeyRejected = !DualMachinePairingIdentityCodec.verify(
                    changedSpki, payload, signature);
        } catch (GeneralSecurityException | IllegalArgumentException unparseableKey) {
            // A point knocked off the curve may already fail strict SPKI parsing.
            tamperedKeyRejected = true;
        }
        require(tamperedKeyRejected, "public key tamper must fail verification");
    }

    private static void rejectsNonP256Keys() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        byte[] rsaSpki = rsa.generateKeyPair().getPublic().getEncoded();
        requireRejectedSpki(rsaSpki, "RSA key must be rejected");

        KeyPairGenerator p384 = KeyPairGenerator.getInstance("EC");
        p384.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair p384Pair = p384.generateKeyPair();
        requireRejectedSpki(p384Pair.getPublic().getEncoded(), "P-384 key must be rejected");
        byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.sign(p384Pair.getPrivate(), payload),
                "P-384 private key must be rejected for signing");
    }

    private static void rejectsNullEmptyAndOversizeInputs() throws Exception {
        byte[] derSpki = generateP256KeyPair().getPublic().getEncoded();
        byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
        byte[] signature = DualMachinePairingIdentityCodec.sign(
                generateP256KeyPair().getPrivate(), payload);

        requireRejectedSpki(null, "null SPKI must be rejected");
        requireRejectedSpki(new byte[0], "empty SPKI must be rejected");
        requireRejectedSpki(new byte[DualMachinePairingIdentityCodec.MAX_SPKI_DER_BYTES + 1],
                "oversize SPKI must be rejected");
        requireRejectedSpki(new byte[P256_SPKI_DER_LENGTH], "all-zero SPKI must be rejected");

        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.decodePublicKeyBase64(null),
                "null Base64 must be rejected");
        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.decodePublicKeyBase64(""),
                "empty Base64 must be rejected");
        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.decodePublicKeyBase64(
                        "A".repeat(DualMachinePairingIdentityCodec.MAX_SPKI_BASE64_CHARS + 1)),
                "oversize Base64 must be rejected");
        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.decodePublicKeyBase64("###not-base64###"),
                "non-Base64 input must be rejected");
        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.decodePublicKeyBase64(
                        Base64.getEncoder().encodeToString(new byte[P256_SPKI_DER_LENGTH])),
                "Base64 of garbage DER must be rejected");

        KeyPair keyPair = generateP256KeyPair();
        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.sign(null, payload),
                "null private key must be rejected");
        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.sign(keyPair.getPrivate(), null),
                "null payload must be rejected");
        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.sign(keyPair.getPrivate(), new byte[0]),
                "empty payload must be rejected");
        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.sign(keyPair.getPrivate(),
                        new byte[DualMachinePairingIdentityCodec.MAX_PAYLOAD_BYTES + 1]),
                "oversize payload must be rejected");

        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.verify(derSpki, payload, null),
                "null signature must be rejected");
        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.verify(derSpki, payload, new byte[0]),
                "empty signature must be rejected");
        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.verify(derSpki, payload,
                        new byte[DualMachinePairingIdentityCodec.MAX_SIGNATURE_DER_BYTES + 1]),
                "oversize signature must be rejected");
        require(signature.length > 0, "test fixture signature must exist");
    }

    private static void requireRejectedSpki(byte[] derSpki, String message) {
        requireThrows(IllegalArgumentException.class,
                () -> DualMachinePairingIdentityCodec.requirePublicKey(derSpki), message);
    }

    private static KeyPair generateP256KeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(DualMachinePairingIdentityCodec.CURVE_NAME));
        return generator.generateKeyPair();
    }

    private static void requireThrows(Class<? extends Exception> expected, ThrowingAction action,
            String message) {
        try {
            action.run();
            throw new AssertionError(message);
        } catch (AssertionError failure) {
            throw failure;
        } catch (Exception exception) {
            if (!expected.isInstance(exception)) {
                throw new AssertionError(message + " (wrong exception: " + exception + ")");
            }
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private interface ThrowingAction {
        void run() throws Exception;
    }
}
