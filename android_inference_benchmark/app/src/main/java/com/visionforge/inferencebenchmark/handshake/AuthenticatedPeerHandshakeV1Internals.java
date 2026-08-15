package com.visionforge.inferencebenchmark.handshake;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

final class AuthenticatedPeerHandshakeV1Internals {
    static final String CURVE_NAME = "secp256r1";
    static final String EC_ALGORITHM = "EC";
    static final String SHA256_ALGORITHM = "SHA-256";
    static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    static final int HKDF_SHA256_MAX_OUTPUT_BYTES = 255 * AuthenticatedPeerHandshakeV1.SHA256_BYTES;

    private static final BigInteger P256_PRIME =
            new BigInteger(
                    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                    16);
    private static final BigInteger P256_A = P256_PRIME.subtract(BigInteger.valueOf(3L));
    private static final BigInteger P256_B =
            new BigInteger(
                    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                    16);
    private static final BigInteger P256_ORDER =
            new BigInteger(
                    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                    16);
    private static final BigInteger P256_GENERATOR_X =
            new BigInteger(
                    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                    16);
    private static final BigInteger P256_GENERATOR_Y =
            new BigInteger(
                    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                    16);

    private static volatile ECParameterSpec p256Parameters;

    private AuthenticatedPeerHandshakeV1Internals() {}

    static AuthenticatedPeerHandshakeV1Exception unauthenticatedFailure() {
        return new AuthenticatedPeerHandshakeV1Exception(
                AuthenticatedPeerHandshakeV1Exception.Reason.UNAUTHENTICATED_HANDSHAKE,
                "authenticated peer handshake was rejected");
    }

    static AuthenticatedPeerHandshakeV1Exception cryptoFailure() {
        return new AuthenticatedPeerHandshakeV1Exception(
                AuthenticatedPeerHandshakeV1Exception.Reason.CRYPTO_UNAVAILABLE,
                "authenticated peer handshake cryptography failed closed");
    }

    static AuthenticatedPeerHandshakeV1Exception closedFailure() {
        return new AuthenticatedPeerHandshakeV1Exception(
                AuthenticatedPeerHandshakeV1Exception.Reason.CLOSED,
                "authenticated peer handshake secret owner is closed");
    }

    static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    static boolean isAllZero(byte[] value) {
        int aggregate = 0;
        for (byte current : value) aggregate |= current & 0xff;
        return aggregate == 0;
    }

    static byte[] sha256(byte[] value) throws GeneralSecurityException {
        return MessageDigest.getInstance(SHA256_ALGORITHM).digest(value);
    }

    static byte[] hmacSha256(byte[] key, byte[]... segments)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
        mac.init(new SecretKeySpec(key, HMAC_SHA256_ALGORITHM));
        for (byte[] segment : segments) mac.update(segment);
        return mac.doFinal();
    }

    static byte[] hkdfExtractSha256(byte[] salt, byte[] inputKeyMaterial)
            throws GeneralSecurityException {
        return hmacSha256(salt, inputKeyMaterial);
    }

    /** RFC 5869 expand primitive used by the fixed package-private key schedule. */
    static byte[] hkdfExpandSha256(byte[] pseudorandomKey, byte[] info, int outputBytes)
            throws GeneralSecurityException {
        if (pseudorandomKey == null
                || pseudorandomKey.length != AuthenticatedPeerHandshakeV1.SHA256_BYTES) {
            throw new IllegalArgumentException("HKDF pseudorandom key must be 32 bytes");
        }
        if (info == null) throw new IllegalArgumentException("HKDF info is required");
        if (outputBytes < 0 || outputBytes > HKDF_SHA256_MAX_OUTPUT_BYTES) {
            throw new IllegalArgumentException("HKDF output length exceeds the SHA-256 limit");
        }
        byte[] output = new byte[outputBytes];
        byte[] previous = new byte[0];
        int outputOffset = 0;
        int blockIndex = 1;
        try {
            while (outputOffset < outputBytes) {
                Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
                mac.init(new SecretKeySpec(pseudorandomKey, HMAC_SHA256_ALGORITHM));
                mac.update(previous);
                mac.update(info);
                mac.update((byte) blockIndex);
                byte[] next = mac.doFinal();
                clear(previous);
                previous = next;
                int copyBytes = Math.min(previous.length, outputBytes - outputOffset);
                System.arraycopy(previous, 0, output, outputOffset, copyBytes);
                outputOffset += copyBytes;
                blockIndex++;
            }
            return output;
        } catch (GeneralSecurityException | RuntimeException failure) {
            clear(output);
            throw failure;
        } finally {
            clear(previous);
        }
    }

    static byte[] strictAscii(String value, int minimumBytes, int maximumBytes, String fieldName) {
        if (value == null || value.length() < minimumBytes || value.length() > maximumBytes) {
            throw new IllegalArgumentException(fieldName + " is outside its length contract");
        }
        byte[] encoded = value.getBytes(StandardCharsets.US_ASCII);
        if (encoded.length != value.length()) {
            clear(encoded);
            throw new IllegalArgumentException(fieldName + " must contain only ASCII");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == 0 || character > 0x7f) {
                clear(encoded);
                throw new IllegalArgumentException(fieldName + " must contain only ASCII");
            }
        }
        return encoded;
    }

    static ECPoint requireP256Point(byte[] sec1) {
        if (sec1 == null
                || sec1.length != AuthenticatedPeerHandshakeV1.P256_SEC1_UNCOMPRESSED_BYTES
                || sec1[0] != 0x04) {
            throw new IllegalArgumentException("ephemeral public key is not uncompressed P-256");
        }
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(sec1, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(sec1, 33, 65));
        if (x.compareTo(P256_PRIME) >= 0 || y.compareTo(P256_PRIME) >= 0) {
            throw new IllegalArgumentException("ephemeral public key coordinate is outside P-256");
        }
        BigInteger left = y.multiply(y).mod(P256_PRIME);
        BigInteger right =
                x.multiply(x)
                        .mod(P256_PRIME)
                        .multiply(x)
                        .add(P256_A.multiply(x))
                        .add(P256_B)
                        .mod(P256_PRIME);
        if (!left.equals(right)) {
            throw new IllegalArgumentException("ephemeral public key is not on P-256");
        }
        return new ECPoint(x, y);
    }

    static ECPublicKey publicKeyFromSec1(byte[] sec1) throws GeneralSecurityException {
        ECPoint point = requireP256Point(sec1);
        PublicKey parsed =
                KeyFactory.getInstance(EC_ALGORITHM)
                        .generatePublic(new ECPublicKeySpec(point, p256Parameters()));
        if (!(parsed instanceof ECPublicKey)) {
            throw new GeneralSecurityException("JCA did not create an EC public key");
        }
        requireP256Parameters((ECPublicKey) parsed);
        return (ECPublicKey) parsed;
    }

    static byte[] encodeP256PublicKey(PublicKey publicKey) {
        if (!(publicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("ephemeral public key must be EC");
        }
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        requireP256Parameters(ecPublicKey);
        ECPoint point = ecPublicKey.getW();
        byte[] x = fixedUnsigned(point.getAffineX(), 32);
        byte[] y = fixedUnsigned(point.getAffineY(), 32);
        byte[] encoded = new byte[AuthenticatedPeerHandshakeV1.P256_SEC1_UNCOMPRESSED_BYTES];
        encoded[0] = 0x04;
        System.arraycopy(x, 0, encoded, 1, x.length);
        System.arraycopy(y, 0, encoded, 33, y.length);
        clear(x);
        clear(y);
        requireP256Point(encoded);
        return encoded;
    }

    static ECParameterSpec p256Parameters() {
        ECParameterSpec cached = p256Parameters;
        if (cached == null) {
            synchronized (AuthenticatedPeerHandshakeV1Internals.class) {
                cached = p256Parameters;
                if (cached == null) {
                    try {
                        AlgorithmParameters parameters =
                                AlgorithmParameters.getInstance(EC_ALGORITHM);
                        parameters.init(new ECGenParameterSpec(CURVE_NAME));
                        cached = parameters.getParameterSpec(ECParameterSpec.class);
                        requireExpectedP256Parameters(cached);
                    } catch (GeneralSecurityException failure) {
                        throw new IllegalStateException(
                                "JCA does not expose the required P-256 parameters", failure);
                    }
                    p256Parameters = cached;
                }
            }
        }
        return cached;
    }

    static byte[] normalizeP256SharedSecret(byte[] providerSecret)
            throws GeneralSecurityException {
        if (providerSecret == null
                || providerSecret.length == 0
                || providerSecret.length > 32) {
            throw new GeneralSecurityException("JCA returned a non-canonical P-256 secret length");
        }
        byte[] normalized = new byte[32];
        System.arraycopy(
                providerSecret,
                0,
                normalized,
                normalized.length - providerSecret.length,
                providerSecret.length);
        if (isAllZero(normalized)) {
            clear(normalized);
            throw new GeneralSecurityException("JCA returned the invalid zero P-256 secret");
        }
        return normalized;
    }

    private static void requireP256Parameters(ECKey key) {
        requireExpectedP256Parameters(key.getParams());
    }

    private static void requireExpectedP256Parameters(ECParameterSpec actual) {
        if (actual == null) throw new IllegalArgumentException("EC parameters are missing");
        ECField field = actual.getCurve().getField();
        boolean matches =
                field instanceof ECFieldFp
                        && ((ECFieldFp) field).getP().equals(P256_PRIME)
                        && field.getFieldSize() == 256
                        && actual.getCurve().getA().equals(P256_A)
                        && actual.getCurve().getB().equals(P256_B)
                        && actual.getGenerator().getAffineX().equals(P256_GENERATOR_X)
                        && actual.getGenerator().getAffineY().equals(P256_GENERATOR_Y)
                        && actual.getOrder().equals(P256_ORDER)
                        && actual.getCofactor() == 1;
        if (!matches) throw new IllegalArgumentException("EC key is not on P-256");
        ECPoint generator = actual.getGenerator();
        byte[] encodedGenerator = new byte[65];
        byte[] x = fixedUnsigned(generator.getAffineX(), 32);
        byte[] y = fixedUnsigned(generator.getAffineY(), 32);
        encodedGenerator[0] = 0x04;
        System.arraycopy(x, 0, encodedGenerator, 1, 32);
        System.arraycopy(y, 0, encodedGenerator, 33, 32);
        clear(x);
        clear(y);
        requireP256Point(encodedGenerator);
        clear(encodedGenerator);
    }

    private static byte[] fixedUnsigned(BigInteger value, int width) {
        if (value == null || value.signum() < 0) {
            throw new IllegalArgumentException("coordinate is negative or missing");
        }
        byte[] signed = value.toByteArray();
        int offset = signed.length > 1 && signed[0] == 0 ? 1 : 0;
        int significantBytes = signed.length - offset;
        if (significantBytes > width) {
            clear(signed);
            throw new IllegalArgumentException("coordinate is oversized");
        }
        byte[] fixed = new byte[width];
        System.arraycopy(signed, offset, fixed, width - significantBytes, significantBytes);
        clear(signed);
        return fixed;
    }

}
