package com.visionforge.inferencebenchmark;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Pure-JCA codec for the dual-machine P-256 pairing identity key.
 * This class deliberately has no android.* dependency so the Windows host and
 * the Android device share one canonical wire contract: DER SPKI in standard
 * Base64, lowercase SHA-256 hex fingerprint, and DER SHA256withECDSA signatures.
 */
public final class DualMachinePairingIdentityCodec {
    public static final String CURVE_NAME = "secp256r1";
    public static final String KEY_ALGORITHM = "EC";
    public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    public static final int SHA256_HEX_LENGTH = 64;
    /** Canonical P-256 SPKI DER is exactly 91 bytes; bound rejects bloated encodings. */
    public static final int MAX_SPKI_DER_BYTES = 256;
    /** DER ECDSA over P-256 is at most 72 bytes; bound rejects bloated encodings. */
    public static final int MAX_SIGNATURE_DER_BYTES = 72;
    /** Pairing payloads are small handshake transcripts; bound rejects abuse. */
    public static final int MAX_PAYLOAD_BYTES = 64 * 1024;
    /** Base64 of a bounded SPKI cannot exceed this; bound rejects runaway input. */
    public static final int MAX_SPKI_BASE64_CHARS = 4 * (MAX_SPKI_DER_BYTES / 3 + 2);

    /**
     * Fixed DER prefix of every canonical secp256r1 SPKI: SEQUENCE(0x59) of
     * algorithm id ecPublicKey/prime256v1 followed by BIT STRING(0x42, 0 unused
     * bits) wrapping the 0x04 uncompressed point tag. The remaining 64 bytes are X||Y.
     */
    private static final byte[] P256_SPKI_DER_PREFIX = {
            0x30, 0x59, 0x30, 0x13,
            0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x03, 0x42, 0x00, 0x04
    };
    private static final int P256_SPKI_DER_LENGTH = 91;
    private static final BigInteger P256_ORDER = new BigInteger(
            "ffffffff00000000ffffffffffffffff"
                    + "bce6faada7179e84f3b9cac2fc632551",
            16);
    private static final BigInteger P256_HALF_ORDER =
            P256_ORDER.shiftRight(1);

    private static volatile ECParameterSpec p256Params;

    private DualMachinePairingIdentityCodec() {
    }

    /** Parses and strictly validates a canonical P-256 SPKI DER encoding. */
    public static ECPublicKey requirePublicKey(byte[] derSpki) throws GeneralSecurityException {
        requireBounded(derSpki, 1, MAX_SPKI_DER_BYTES, "derSpki");
        requireCanonicalP256SpkiDer(derSpki);
        PublicKey parsed;
        try {
            parsed = KeyFactory.getInstance(KEY_ALGORITHM)
                    .generatePublic(new X509EncodedKeySpec(derSpki));
        } catch (GeneralSecurityException exception) {
            throw new GeneralSecurityException("derSpki is not a parseable EC public key", exception);
        }
        requireP256Key(parsed, "derSpki");
        return (ECPublicKey) parsed;
    }

    /** Canonical wire form of a P-256 identity public key: DER SPKI, standard Base64. */
    public static String encodePublicKeyBase64(byte[] derSpki) throws GeneralSecurityException {
        requirePublicKey(derSpki);
        return Base64.getEncoder().encodeToString(derSpki);
    }

    /** Strict inverse of {@link #encodePublicKeyBase64(byte[])}. */
    public static byte[] decodePublicKeyBase64(String base64Spki) throws GeneralSecurityException {
        if (base64Spki == null || base64Spki.isEmpty()
                || base64Spki.length() > MAX_SPKI_BASE64_CHARS) {
            throw new IllegalArgumentException("base64Spki is missing or oversized");
        }
        byte[] derSpki;
        try {
            derSpki = Base64.getDecoder().decode(base64Spki);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("base64Spki is not strict Base64", exception);
        }
        if (!Base64.getEncoder().encodeToString(derSpki).equals(base64Spki)) {
            throw new IllegalArgumentException("base64Spki is not canonical Base64");
        }
        requirePublicKey(derSpki);
        return derSpki;
    }

    /** Lowercase hex SHA-256 over the canonical DER SPKI bytes. */
    public static String fingerprintHex(byte[] derSpki) throws GeneralSecurityException {
        requirePublicKey(derSpki);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(derSpki);
        StringBuilder hex = new StringBuilder(SHA256_HEX_LENGTH);
        for (byte value : digest) {
            hex.append(Character.forDigit((value >> 4) & 0x0f, 16));
            hex.append(Character.forDigit(value & 0x0f, 16));
        }
        return hex.toString();
    }

    /** Convenience fingerprint over the canonical Base64 wire form. */
    public static String fingerprintHexFromBase64(String base64Spki) throws GeneralSecurityException {
        return fingerprintHex(decodePublicKeyBase64(base64Spki));
    }

    /** Signs a bounded payload with a P-256 EC private key; returns the DER signature. */
    public static byte[] sign(PrivateKey privateKey, byte[] payload) throws GeneralSecurityException {
        if (privateKey == null) {
            throw new IllegalArgumentException("privateKey is required");
        }
        requireP256Key(privateKey, "privateKey");
        requireBounded(payload, 1, MAX_PAYLOAD_BYTES, "payload");
        Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
        signer.initSign(privateKey);
        signer.update(payload);
        byte[] providerSignature = signer.sign();
        try {
            return canonicalizeLowS(providerSignature);
        } finally {
            Arrays.fill(providerSignature, (byte) 0);
        }
    }

    /** Returns true only when a bounded DER signature verifies for the exact payload. */
    public static boolean verify(byte[] derSpki, byte[] payload, byte[] derSignature)
            throws GeneralSecurityException {
        requireBounded(derSignature, 1, MAX_SIGNATURE_DER_BYTES, "derSignature");
        requireBounded(payload, 1, MAX_PAYLOAD_BYTES, "payload");
        if (!isCanonicalLowS(derSignature)) return false;
        ECPublicKey publicKey = requirePublicKey(derSpki);
        Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
        verifier.initVerify(publicKey);
        verifier.update(payload);
        try {
            return verifier.verify(derSignature);
        } catch (GeneralSecurityException malformedSignature) {
            return false;
        }
    }

    private static void requireBounded(byte[] value, int minBytes, int maxBytes, String name) {
        if (value == null || value.length < minBytes || value.length > maxBytes) {
            throw new IllegalArgumentException(name + " is missing or outside byte bounds");
        }
    }

    private static void requireCanonicalP256SpkiDer(byte[] derSpki) {
        if (derSpki.length != P256_SPKI_DER_LENGTH) {
            throw new IllegalArgumentException("derSpki is not the canonical P-256 SPKI length");
        }
        for (int index = 0; index < P256_SPKI_DER_PREFIX.length; index++) {
            if (derSpki[index] != P256_SPKI_DER_PREFIX[index]) {
                throw new IllegalArgumentException("derSpki is not canonical secp256r1 SPKI DER");
            }
        }
    }

    private static byte[] canonicalizeLowS(byte[] signature)
            throws GeneralSecurityException {
        BigInteger[] scalars = parseDerScalars(signature);
        BigInteger canonicalS = scalars[1].compareTo(P256_HALF_ORDER) > 0
                ? P256_ORDER.subtract(scalars[1])
                : scalars[1];
        byte[] encodedR = scalars[0].toByteArray();
        byte[] encodedS = canonicalS.toByteArray();
        int payloadBytes = 2 + encodedR.length + 2 + encodedS.length;
        if (payloadBytes >= 128) {
            throw new GeneralSecurityException(
                    "P-256 ECDSA signature is oversized");
        }
        byte[] canonical = new byte[payloadBytes + 2];
        int offset = 0;
        canonical[offset++] = 0x30;
        canonical[offset++] = (byte) payloadBytes;
        canonical[offset++] = 0x02;
        canonical[offset++] = (byte) encodedR.length;
        System.arraycopy(
                encodedR, 0, canonical, offset, encodedR.length);
        offset += encodedR.length;
        canonical[offset++] = 0x02;
        canonical[offset++] = (byte) encodedS.length;
        System.arraycopy(
                encodedS, 0, canonical, offset, encodedS.length);
        if (!isCanonicalLowS(canonical)) {
            Arrays.fill(canonical, (byte) 0);
            throw new GeneralSecurityException(
                    "P-256 ECDSA canonicalization failed");
        }
        return canonical;
    }

    private static boolean isCanonicalLowS(byte[] signature) {
        try {
            BigInteger[] scalars = parseDerScalars(signature);
            return scalars[1].compareTo(P256_HALF_ORDER) <= 0;
        } catch (GeneralSecurityException | IllegalArgumentException rejected) {
            return false;
        }
    }

    private static BigInteger[] parseDerScalars(byte[] signature)
            throws GeneralSecurityException {
        requireBounded(
                signature, 8, MAX_SIGNATURE_DER_BYTES, "signature");
        if ((signature[0] & 0xff) != 0x30
                || (signature[1] & 0xff) != signature.length - 2
                || (signature[2] & 0xff) != 0x02) {
            throw new GeneralSecurityException(
                    "ECDSA signature DER sequence is invalid");
        }
        int rLength = signature[3] & 0xff;
        int sOffset = 4 + rLength;
        if (rLength == 0 || sOffset + 2 > signature.length
                || (signature[sOffset] & 0xff) != 0x02) {
            throw new GeneralSecurityException(
                    "ECDSA signature R is invalid");
        }
        int sLength = signature[sOffset + 1] & 0xff;
        if (sLength == 0 || sOffset + 2 + sLength != signature.length) {
            throw new GeneralSecurityException(
                    "ECDSA signature S is invalid");
        }
        BigInteger r = parsePositiveInteger(signature, 4, rLength);
        BigInteger s = parsePositiveInteger(
                signature, sOffset + 2, sLength);
        if (r.signum() <= 0 || s.signum() <= 0
                || r.compareTo(P256_ORDER) >= 0
                || s.compareTo(P256_ORDER) >= 0) {
            throw new GeneralSecurityException(
                    "ECDSA signature scalar is outside P-256");
        }
        return new BigInteger[]{r, s};
    }

    private static BigInteger parsePositiveInteger(
            byte[] encoded,
            int offset,
            int length) throws GeneralSecurityException {
        int first = encoded[offset] & 0xff;
        if ((first & 0x80) != 0
                || (length > 1 && first == 0
                && (encoded[offset + 1] & 0x80) == 0)) {
            throw new GeneralSecurityException(
                    "ECDSA signature integer is not minimal positive DER");
        }
        return new BigInteger(
                1, Arrays.copyOfRange(encoded, offset, offset + length));
    }

    private static void requireP256Key(java.security.Key key, String name) {
        if (!(key instanceof ECKey) || !KEY_ALGORITHM.equalsIgnoreCase(key.getAlgorithm())) {
            throw new IllegalArgumentException(name + " must be an EC key");
        }
        ECParameterSpec actual = ((ECKey) key).getParams();
        ECParameterSpec expected = p256Params();
        ECField actualField = actual.getCurve().getField();
        ECField expectedField = expected.getCurve().getField();
        boolean matches = actualField.getFieldSize() == expectedField.getFieldSize()
                && actual.getCurve().getA().equals(expected.getCurve().getA())
                && actual.getCurve().getB().equals(expected.getCurve().getB())
                && actual.getGenerator().equals(expected.getGenerator())
                && actual.getOrder().equals(expected.getOrder())
                && actual.getCofactor() == expected.getCofactor();
        if (!matches) {
            throw new IllegalArgumentException(name + " must be on curve " + CURVE_NAME);
        }
    }

    private static ECParameterSpec p256Params() {
        ECParameterSpec cached = p256Params;
        if (cached == null) {
            synchronized (DualMachinePairingIdentityCodec.class) {
                cached = p256Params;
                if (cached == null) {
                    try {
                        AlgorithmParameters parameters = AlgorithmParameters.getInstance(KEY_ALGORITHM);
                        parameters.init(new ECGenParameterSpec(CURVE_NAME));
                        cached = parameters.getParameterSpec(ECParameterSpec.class);
                    } catch (GeneralSecurityException exception) {
                        throw new IllegalStateException("JCA lacks the secp256r1 curve", exception);
                    }
                    p256Params = cached;
                }
            }
        }
        return cached;
    }
}
