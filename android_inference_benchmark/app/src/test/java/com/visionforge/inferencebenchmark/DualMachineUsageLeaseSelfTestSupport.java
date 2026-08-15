package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/** Test-only sidecar-compatible RS256 lease issuer. */
final class DualMachineUsageLeaseSelfTestSupport {
    static final String ENTITLEMENT = "1".repeat(32);
    static final String PAIR = "2".repeat(32);
    static final String SESSION = "3".repeat(32);
    static final String HOST_KEY = "4".repeat(64);
    static final String ANDROID_KEY = "5".repeat(64);
    static final String CHANNEL = "6".repeat(64);

    private DualMachineUsageLeaseSelfTestSupport() {
    }

    static KeyPair rsaKeyPair(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return generator.generateKeyPair();
    }

    static LeaseData initial(long issuedAt, long notBefore, long expiresAt) {
        LeaseData data = new LeaseData();
        data.issuedAt = issuedAt;
        data.notBefore = notBefore;
        data.expiresAt = expiresAt;
        return data;
    }

    static DualMachineUsageLeaseVerifier.ExpectedBinding expected(LeaseData data) {
        return new DualMachineUsageLeaseVerifier.ExpectedBinding(
                data.entitlementId,
                data.pairId,
                data.sessionId,
                data.protocolVersion,
                data.revocationVersion,
                data.hostKeySha256,
                data.androidKeySha256,
                data.channelBindingSha256,
                data.sequence,
                data.previousLeaseSha256,
                data.authorizationKind,
                data.permanent);
    }

    static String token(KeyPair keyPair, LeaseData data) throws Exception {
        return sign(keyPair.getPrivate(), header(keyPair), claims(data));
    }

    static String token(
            KeyPair keyPair,
            Map<String, Object> header,
            Map<String, Object> claims) throws Exception {
        return sign(keyPair.getPrivate(), header, claims);
    }

    static Map<String, Object> header(KeyPair keyPair) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "RS256");
        header.put("kid", sha256Hex(keyPair.getPublic().getEncoded()).substring(0, 16));
        header.put("typ", "JWT");
        return header;
    }

    static Map<String, Object> claims(LeaseData data) throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("typ", DualMachineUsageLeaseVerifier.LEASE_TYPE);
        claims.put("iss", DualMachineUsageLeaseVerifier.LEASE_ISSUER);
        claims.put("aud", DualMachineUsageLeaseVerifier.LEASE_AUDIENCE);
        claims.put("sub", data.entitlementId);
        claims.put("pid", data.pairId);
        claims.put("sid", data.sessionId);
        claims.put("pv", data.protocolVersion);
        claims.put("rv", data.revocationVersion);
        claims.put("hkh", data.hostKeySha256);
        claims.put("akh", data.androidKeySha256);
        claims.put("cbh", data.channelBindingSha256);
        claims.put("pth", data.previousLeaseSha256);
        claims.put("seq", data.sequence);
        claims.put("phase", data.phase);
        claims.put("authorization_kind", data.authorizationKind);
        claims.put("is_permanent", data.permanent);
        claims.put("remaining", data.remainingSeconds);
        claims.put("iat", data.issuedAt);
        claims.put("nbf", data.notBefore);
        claims.put("exp", data.expiresAt);
        refreshJti(claims);
        return claims;
    }

    static void refreshJti(Map<String, Object> claims) throws Exception {
        Map<String, Object> withoutJti = new LinkedHashMap<>(claims);
        withoutJti.remove("jti");
        claims.put("jti", sha256Hex(canonicalJson(withoutJti)).substring(0, 32));
    }

    static String sign(
            PrivateKey privateKey,
            Map<String, Object> header,
            Map<String, Object> claims) throws Exception {
        return signRaw(privateKey, canonicalJson(header), canonicalJson(claims));
    }

    static String signRaw(
            PrivateKey privateKey,
            byte[] headerJson,
            byte[] claimsJson) throws Exception {
        String header = base64Url(headerJson);
        String claims = base64Url(claimsJson);
        String signingInput = header + "." + claims;
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + base64Url(signer.sign());
    }

    static String corruptSignature(String token) {
        int separator = token.lastIndexOf('.');
        byte[] signature = Base64.getUrlDecoder().decode(token.substring(separator + 1));
        signature[signature.length - 1] ^= 1;
        return token.substring(0, separator + 1) + base64Url(signature);
    }

    static byte[] canonicalJson(Map<String, Object> source) {
        StringBuilder destination = new StringBuilder(512).append('{');
        boolean first = true;
        for (Map.Entry<String, Object> entry : new TreeMap<>(source).entrySet()) {
            if (!first) destination.append(',');
            appendString(destination, entry.getKey());
            destination.append(':');
            Object value = entry.getValue();
            if (value instanceof String) {
                appendString(destination, (String) value);
            } else if (value instanceof Number) {
                destination.append(value);
            } else if (value instanceof Boolean) {
                destination.append(value);
            } else {
                throw new IllegalArgumentException("unsupported test JSON value");
            }
            first = false;
        }
        destination.append('}');
        return destination.toString().getBytes(StandardCharsets.UTF_8);
    }

    static String sha256Hex(byte[] value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder hex = new StringBuilder(64);
        for (byte octet : digest) {
            hex.append(Character.forDigit((octet >>> 4) & 0x0f, 16));
            hex.append(Character.forDigit(octet & 0x0f, 16));
        }
        return hex.toString();
    }

    private static String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static void appendString(StringBuilder destination, String value) {
        destination.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '"' || character == '\\') destination.append('\\');
            destination.append(character);
        }
        destination.append('"');
    }

    static final class LeaseData {
        String entitlementId = ENTITLEMENT;
        String pairId = PAIR;
        String sessionId = SESSION;
        long protocolVersion = 2L;
        long revocationVersion = 1L;
        String hostKeySha256 = HOST_KEY;
        String androidKeySha256 = ANDROID_KEY;
        String channelBindingSha256 = CHANNEL;
        String previousLeaseSha256 =
                DualMachineUsageLeaseGate.EMPTY_PREVIOUS_LEASE_SHA256;
        long sequence;
        String phase = "active";
        String authorizationKind = "day";
        boolean permanent;
        long remainingSeconds = 600L;
        long issuedAt;
        long notBefore;
        long expiresAt;
    }
}
