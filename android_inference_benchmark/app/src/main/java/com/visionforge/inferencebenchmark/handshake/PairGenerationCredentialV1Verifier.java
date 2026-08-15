package com.visionforge.inferencebenchmark.handshake;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Strict JCA verifier for a server-authoritative peer-generation credential.
 *
 * <p>This class is deliberately only a cryptographic foundation. It does not
 * allocate generations, authenticate a route, persist a replay floor, or
 * enable the production data plane. Its caller must supply a build-pinned
 * one-to-three-key rotation ring, every other-purpose RSA key used by the
 * application, an independently authoritative expected allocation, and a
 * trusted epoch observation.</p>
 *
 * <p>Input {@link RSAPublicKey} implementations are never passed to a
 * signature provider and their encoded form is never trusted. The verifier
 * extracts the RSA numbers once, rebuilds a provider-owned key, and derives
 * the key id from that rebuilt key's canonical DER SubjectPublicKeyInfo.</p>
 */
public final class PairGenerationCredentialV1Verifier {
    public static final String CREDENTIAL_TYPE =
            "vf-dual-machine-pair-generation-credential-v1";
    public static final String CREDENTIAL_ISSUER =
            "visionforge-dual-machine-service";
    public static final String CREDENTIAL_AUDIENCE =
            "visionforge-dual-machine-peer-handshake-v1";
    public static final int MAXIMUM_CREDENTIAL_TTL_SECONDS = 30;
    public static final int MAXIMUM_ISSUED_AT_FUTURE_SECONDS = 2;
    public static final int MAXIMUM_TOKEN_ASCII_CHARACTERS = 8192;
    public static final int MINIMUM_RSA_BITS = 3072;

    private static final BigInteger REQUIRED_RSA_PUBLIC_EXPONENT =
            BigInteger.valueOf(65537L);
    private static final Pattern LOWER_HEX_16 =
            Pattern.compile("[0-9a-f]{16}");
    private static final Pattern LOWER_HEX_32 =
            Pattern.compile("[0-9a-f]{32}");
    private static final Pattern LOWER_HEX_64 =
            Pattern.compile("[0-9a-f]{64}");
    private static final Pattern ALLOCATION_REQUEST_ID =
            Pattern.compile("[A-Za-z0-9._:-]+");
    private static final Set<String> HEADER_KEYS = immutableSet(
            "alg", "kid", "typ");
    private static final Set<String> PAYLOAD_KEYS = immutableSet(
            "allocation_request_id",
            "android_identity_spki_sha256",
            "aud",
            "binding_id",
            "binding_revision",
            "connection_id",
            "credential_nonce",
            "entitlement_id",
            "exp",
            "generation",
            "host_identity_spki_sha256",
            "iat",
            "iss",
            "nbf",
            "pair_id",
            "revocation_version",
            "transcript_proposal_sha256",
            "typ");

    private final VerificationKey[] verificationKeys;

    /** Creates a verifier with no other-purpose RSA keys to compare. */
    public PairGenerationCredentialV1Verifier(PublicKey[] publicKeys)
            throws CredentialException {
        this(publicKeys, new PublicKey[0]);
    }

    /**
     * Creates a verifier from a bounded credential keyring.
     *
     * @param publicKeys one to three current/previous credential keys
     * @param otherPurposePublicKeys every RSA key pinned for another purpose;
     *                               none may share the same canonical SPKI
     * @throws CredentialException with only a stable sanitized error code
     */
    public PairGenerationCredentialV1Verifier(
            PublicKey[] publicKeys,
            PublicKey[] otherPurposePublicKeys) throws CredentialException {
        verificationKeys = validateCredentialKeyring(publicKeys);
        requireDisjointKeyPurposes(
                verificationKeys, otherPurposePublicKeys);
    }

    /** Returns the derived key ids in caller-supplied rotation order. */
    public String[] keyIds() {
        String[] result = new String[verificationKeys.length];
        for (int index = 0; index < verificationKeys.length; index++) {
            result[index] = verificationKeys[index].keyId;
        }
        return result;
    }

    /**
     * Verifies an exact canonical credential against the complete expected
     * allocation context.
     */
    public VerifiedPairGenerationCredentialV1 verify(
            String compactToken,
            ExpectedV1 expected,
            long nowEpochSeconds) throws CredentialException {
        requireValidExpected(expected);
        if (nowEpochSeconds <= 0L) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }

        TokenSegments token = decodeCompactToken(compactToken);
        Map<String, Object> header = parseCanonicalObject(
                token.headerBytes, HEADER_KEYS);
        requireHeader(header);
        VerificationKey verificationKey = selectKey(
                stringValue(header, "kid"));
        verifySignature(verificationKey.providerKey, token);

        Map<String, Object> payload = parseCanonicalObject(
                token.payloadBytes, PAYLOAD_KEYS);
        requirePayload(payload, expected, nowEpochSeconds);
        return verifiedOwner(compactToken, header, payload);
    }

    private VerificationKey selectKey(String keyId)
            throws CredentialException {
        VerificationKey selected = null;
        for (VerificationKey candidate : verificationKeys) {
            if (secureAsciiEquals(candidate.keyId, keyId)) {
                selected = candidate;
            }
        }
        if (selected == null) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
        return selected;
    }

    private static VerificationKey[] validateCredentialKeyring(
            PublicKey[] publicKeys) throws CredentialException {
        if (publicKeys == null
                || publicKeys.length < 1
                || publicKeys.length > 3) {
            throw failure(ErrorCode.KEY_INVALID);
        }
        VerificationKey[] normalized =
                new VerificationKey[publicKeys.length];
        for (int index = 0; index < publicKeys.length; index++) {
            normalized[index] = normalizeCredentialKey(publicKeys[index]);
            for (int prior = 0; prior < index; prior++) {
                if (secureAsciiEquals(
                        normalized[index].keyId,
                        normalized[prior].keyId)
                        || MessageDigest.isEqual(
                        normalized[index].canonicalSpkiDer,
                        normalized[prior].canonicalSpkiDer)) {
                    throw failure(ErrorCode.KEY_INVALID);
                }
            }
        }
        return normalized;
    }

    private static VerificationKey normalizeCredentialKey(PublicKey input)
            throws CredentialException {
        RebuiltRsaKey rebuilt = rebuildProviderRsaKey(input);
        if (rebuilt.providerKey.getModulus().bitLength()
                < MINIMUM_RSA_BITS
                || !REQUIRED_RSA_PUBLIC_EXPONENT.equals(
                rebuilt.providerKey.getPublicExponent())) {
            throw failure(ErrorCode.KEY_INVALID);
        }
        byte[] digest = sha256(
                rebuilt.canonicalSpkiDer, ErrorCode.KEY_INVALID);
        return new VerificationKey(
                lowerHex(digest).substring(0, 16),
                rebuilt.canonicalSpkiDer,
                rebuilt.providerKey);
    }

    private static void requireDisjointKeyPurposes(
            VerificationKey[] credentialKeys,
            PublicKey[] otherPurposePublicKeys) throws CredentialException {
        if (otherPurposePublicKeys == null) {
            throw failure(ErrorCode.KEY_INVALID);
        }
        for (PublicKey otherPurpose : otherPurposePublicKeys) {
            RebuiltRsaKey other = rebuildProviderRsaKey(otherPurpose);
            byte[] otherDigest = sha256(
                    other.canonicalSpkiDer, ErrorCode.KEY_INVALID);
            for (VerificationKey credentialKey : credentialKeys) {
                byte[] credentialDigest = sha256(
                        credentialKey.canonicalSpkiDer,
                        ErrorCode.KEY_INVALID);
                if (MessageDigest.isEqual(
                        credentialKey.canonicalSpkiDer,
                        other.canonicalSpkiDer)
                        || MessageDigest.isEqual(
                        credentialDigest, otherDigest)) {
                    throw failure(ErrorCode.KEY_INVALID);
                }
            }
        }
    }

    private static RebuiltRsaKey rebuildProviderRsaKey(PublicKey input)
            throws CredentialException {
        if (!(input instanceof RSAPublicKey)) {
            throw failure(ErrorCode.KEY_INVALID);
        }
        try {
            RSAPublicKey untrusted = (RSAPublicKey) input;
            BigInteger untrustedModulus = untrusted.getModulus();
            BigInteger untrustedExponent = untrusted.getPublicExponent();
            if (untrustedModulus == null || untrustedExponent == null) {
                throw failure(ErrorCode.KEY_INVALID);
            }

            // Reconstitute immutable values before constructing the provider
            // key. The untrusted key object itself is never used afterward.
            BigInteger modulus = new BigInteger(
                    untrustedModulus.toByteArray());
            BigInteger exponent = new BigInteger(
                    untrustedExponent.toByteArray());
            if (modulus.signum() <= 0 || exponent.signum() <= 0) {
                throw failure(ErrorCode.KEY_INVALID);
            }
            PublicKey generated = KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(modulus, exponent));
            if (!(generated instanceof RSAPublicKey)) {
                throw failure(ErrorCode.KEY_INVALID);
            }
            RSAPublicKey providerKey = (RSAPublicKey) generated;
            byte[] encoded = providerKey.getEncoded();
            if (encoded == null || encoded.length == 0) {
                throw failure(ErrorCode.KEY_INVALID);
            }
            return new RebuiltRsaKey(providerKey, encoded.clone());
        } catch (CredentialException rejected) {
            throw rejected;
        } catch (GeneralSecurityException | RuntimeException rejected) {
            throw failure(ErrorCode.KEY_INVALID);
        }
    }

    private static TokenSegments decodeCompactToken(String compactToken)
            throws CredentialException {
        if (compactToken == null
                || compactToken.isEmpty()
                || compactToken.length()
                > MAXIMUM_TOKEN_ASCII_CHARACTERS
                || !isAscii(compactToken)) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
        int firstSeparator = compactToken.indexOf('.');
        int secondSeparator = compactToken.indexOf(
                '.', firstSeparator + 1);
        if (firstSeparator <= 0
                || secondSeparator <= firstSeparator + 1
                || secondSeparator >= compactToken.length() - 1
                || compactToken.indexOf('.', secondSeparator + 1) >= 0) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
        String headerSegment = compactToken.substring(0, firstSeparator);
        String payloadSegment = compactToken.substring(
                firstSeparator + 1, secondSeparator);
        String signatureSegment = compactToken.substring(
                secondSeparator + 1);
        return new TokenSegments(
                decodeCanonicalBase64Url(headerSegment),
                decodeCanonicalBase64Url(payloadSegment),
                decodeCanonicalBase64Url(signatureSegment),
                (headerSegment + "." + payloadSegment)
                        .getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] decodeCanonicalBase64Url(String encoded)
            throws CredentialException {
        if (encoded.isEmpty()) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
        for (int index = 0; index < encoded.length(); index++) {
            char character = encoded.charAt(index);
            boolean valid = character >= 'A' && character <= 'Z'
                    || character >= 'a' && character <= 'z'
                    || character >= '0' && character <= '9'
                    || character == '-'
                    || character == '_';
            if (!valid) {
                throw failure(ErrorCode.TOKEN_INVALID);
            }
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(encoded);
            String canonical = Base64.getUrlEncoder()
                    .withoutPadding().encodeToString(decoded);
            if (!canonical.equals(encoded)) {
                throw failure(ErrorCode.TOKEN_INVALID);
            }
            return decoded;
        } catch (CredentialException rejected) {
            throw rejected;
        } catch (IllegalArgumentException rejected) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
    }

    private static Map<String, Object> parseCanonicalObject(
            byte[] encoded,
            Set<String> exactKeys) throws CredentialException {
        try {
            if (encoded == null || encoded.length < 2) {
                throw failure(ErrorCode.TOKEN_INVALID);
            }
            for (byte value : encoded) {
                if ((value & 0x80) != 0) {
                    throw failure(ErrorCode.TOKEN_INVALID);
                }
            }
            String text = new String(encoded, StandardCharsets.US_ASCII);
            Map<String, Object> parsed = new JsonObjectParser(text).parse();
            byte[] canonical = canonicalJson(parsed);
            if (!parsed.keySet().equals(exactKeys)
                    || !MessageDigest.isEqual(encoded, canonical)) {
                throw failure(ErrorCode.TOKEN_INVALID);
            }
            return parsed;
        } catch (CredentialException rejected) {
            throw rejected;
        } catch (RuntimeException rejected) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
    }

    private static void requireHeader(Map<String, Object> header)
            throws CredentialException {
        String keyId = stringValue(header, "kid");
        if (!"RS256".equals(stringValue(header, "alg"))
                || !"JWT".equals(stringValue(header, "typ"))
                || !matchesNonzero(LOWER_HEX_16, keyId)) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
    }

    private static void verifySignature(
            RSAPublicKey publicKey,
            TokenSegments token) throws CredentialException {
        int expectedSignatureBytes =
                (publicKey.getModulus().bitLength() + 7) / 8;
        if (token.signatureBytes.length != expectedSignatureBytes) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
        boolean verified = false;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(token.signingInput);
            verified = signature.verify(token.signatureBytes);
        } catch (GeneralSecurityException | RuntimeException rejected) {
            verified = false;
        }
        if (!verified) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
    }

    private static void requirePayload(
            Map<String, Object> payload,
            ExpectedV1 expected,
            long nowEpochSeconds) throws CredentialException {
        if (!CREDENTIAL_TYPE.equals(stringValue(payload, "typ"))
                || !CREDENTIAL_ISSUER.equals(
                stringValue(payload, "iss"))
                || !CREDENTIAL_AUDIENCE.equals(
                stringValue(payload, "aud"))) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
        requirePayloadIdentifiers(payload);
        requirePayloadNumbers(payload);
        requirePayloadTimes(payload, nowEpochSeconds);
        requireExpectedClaims(payload, expected);
    }

    private static void requirePayloadIdentifiers(Map<String, Object> payload)
            throws CredentialException {
        String allocationRequestId = stringValue(
                payload, "allocation_request_id");
        if (!isAllocationRequestId(allocationRequestId)
                || !matchesNonzero(
                LOWER_HEX_32, stringValue(payload, "pair_id"))
                || !matchesNonzero(
                LOWER_HEX_32,
                stringValue(payload, "entitlement_id"))
                || !matchesNonzero(
                LOWER_HEX_32, stringValue(payload, "binding_id"))) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
        String hostIdentity = stringValue(
                payload, "host_identity_spki_sha256");
        String androidIdentity = stringValue(
                payload, "android_identity_spki_sha256");
        if (!matchesNonzero(LOWER_HEX_64, hostIdentity)
                || !matchesNonzero(LOWER_HEX_64, androidIdentity)
                || !matchesNonzero(
                LOWER_HEX_64,
                stringValue(payload, "transcript_proposal_sha256"))
                || !matchesNonzero(
                LOWER_HEX_64,
                stringValue(payload, "credential_nonce"))
                || secureAsciiEquals(hostIdentity, androidIdentity)) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
    }

    private static void requirePayloadNumbers(Map<String, Object> payload)
            throws CredentialException {
        String[] names = {
            "binding_revision",
            "revocation_version",
            "generation",
            "connection_id",
            "iat",
            "nbf",
            "exp"
        };
        for (String name : names) {
            if (integerValue(payload, name) <= 0L) {
                throw failure(ErrorCode.TOKEN_INVALID);
            }
        }
    }

    private static void requirePayloadTimes(
            Map<String, Object> payload,
            long nowEpochSeconds) throws CredentialException {
        long issuedAt = integerValue(payload, "iat");
        long notBefore = integerValue(payload, "nbf");
        long expiresAt = integerValue(payload, "exp");
        boolean tooFarInFuture = issuedAt > nowEpochSeconds
                && issuedAt - nowEpochSeconds
                > MAXIMUM_ISSUED_AT_FUTURE_SECONDS;
        if (notBefore != issuedAt
                || expiresAt <= issuedAt
                || expiresAt - issuedAt
                > MAXIMUM_CREDENTIAL_TTL_SECONDS
                || tooFarInFuture
                || expiresAt <= nowEpochSeconds) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
    }

    private static void requireExpectedClaims(
            Map<String, Object> payload,
            ExpectedV1 expected) throws CredentialException {
        boolean stringsMatch = secureAsciiEquals(
                stringValue(payload, "allocation_request_id"),
                expected.allocationRequestId)
                && secureAsciiEquals(
                stringValue(payload, "pair_id"), expected.pairId)
                && secureAsciiEquals(
                stringValue(payload, "entitlement_id"),
                expected.entitlementId)
                && secureAsciiEquals(
                stringValue(payload, "binding_id"),
                expected.bindingId)
                && secureAsciiEquals(
                stringValue(payload, "host_identity_spki_sha256"),
                expected.hostIdentitySpkiSha256)
                && secureAsciiEquals(
                stringValue(payload, "android_identity_spki_sha256"),
                expected.androidIdentitySpkiSha256)
                && secureAsciiEquals(
                stringValue(payload, "transcript_proposal_sha256"),
                expected.transcriptProposalSha256);
        boolean numbersMatch = integerValue(payload, "binding_revision")
                == expected.bindingRevision
                && integerValue(payload, "revocation_version")
                == expected.revocationVersion
                && integerValue(payload, "generation")
                == expected.generation
                && integerValue(payload, "connection_id")
                == expected.connectionId;
        if (!stringsMatch || !numbersMatch) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
    }

    private static VerifiedPairGenerationCredentialV1 verifiedOwner(
            String compactToken,
            Map<String, Object> header,
            Map<String, Object> payload) throws CredentialException {
        return new VerifiedPairGenerationCredentialV1(
                lowerHex(sha256(
                        compactToken.getBytes(StandardCharsets.US_ASCII),
                        ErrorCode.TOKEN_INVALID)),
                stringValue(header, "kid"),
                stringValue(payload, "allocation_request_id"),
                stringValue(payload, "pair_id"),
                stringValue(payload, "entitlement_id"),
                stringValue(payload, "binding_id"),
                integerValue(payload, "binding_revision"),
                integerValue(payload, "revocation_version"),
                integerValue(payload, "generation"),
                integerValue(payload, "connection_id"),
                stringValue(payload, "host_identity_spki_sha256"),
                stringValue(payload, "android_identity_spki_sha256"),
                stringValue(payload, "transcript_proposal_sha256"),
                stringValue(payload, "credential_nonce"),
                stringValue(payload, "typ"),
                stringValue(payload, "iss"),
                stringValue(payload, "aud"),
                integerValue(payload, "iat"),
                integerValue(payload, "nbf"),
                integerValue(payload, "exp"));
    }

    private static void requireValidExpected(ExpectedV1 expected)
            throws CredentialException {
        if (expected == null
                || !isAllocationRequestId(expected.allocationRequestId)
                || !matchesNonzero(LOWER_HEX_32, expected.pairId)
                || !matchesNonzero(LOWER_HEX_32, expected.entitlementId)
                || !matchesNonzero(LOWER_HEX_32, expected.bindingId)
                || expected.bindingRevision <= 0L
                || expected.revocationVersion <= 0L
                || expected.generation <= 0L
                || expected.connectionId <= 0L
                || !matchesNonzero(
                LOWER_HEX_64, expected.hostIdentitySpkiSha256)
                || !matchesNonzero(
                LOWER_HEX_64, expected.androidIdentitySpkiSha256)
                || !matchesNonzero(
                LOWER_HEX_64, expected.transcriptProposalSha256)
                || secureAsciiEquals(
                expected.hostIdentitySpkiSha256,
                expected.androidIdentitySpkiSha256)) {
            throw failure(ErrorCode.SOURCE_INVALID);
        }
    }

    private static String stringValue(Map<String, Object> source, String name)
            throws CredentialException {
        Object value = source.get(name);
        if (!(value instanceof String)) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
        return (String) value;
    }

    private static long integerValue(Map<String, Object> source, String name)
            throws CredentialException {
        Object value = source.get(name);
        if (!(value instanceof Long)) {
            throw failure(ErrorCode.TOKEN_INVALID);
        }
        return (Long) value;
    }

    private static boolean isAllocationRequestId(String value) {
        return value != null
                && value.length() >= 1
                && value.length() <= 128
                && isAscii(value)
                && ALLOCATION_REQUEST_ID.matcher(value).matches();
    }

    private static boolean matchesNonzero(Pattern pattern, String value) {
        if (value == null || !pattern.matcher(value).matches()) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            if (value.charAt(index) != '0') {
                return true;
            }
        }
        return false;
    }

    private static boolean isAscii(String value) {
        for (int index = 0; index < value.length(); index++) {
            if (value.charAt(index) > 0x7f) {
                return false;
            }
        }
        return true;
    }

    private static boolean secureAsciiEquals(String first, String second) {
        return first != null
                && second != null
                && MessageDigest.isEqual(
                first.getBytes(StandardCharsets.US_ASCII),
                second.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] canonicalJson(Map<String, Object> source) {
        StringBuilder destination = new StringBuilder(768).append('{');
        boolean first = true;
        for (Map.Entry<String, Object> entry
                : new TreeMap<>(source).entrySet()) {
            if (!first) {
                destination.append(',');
            }
            appendCanonicalJsonString(destination, entry.getKey());
            destination.append(':');
            Object value = entry.getValue();
            if (value instanceof String) {
                appendCanonicalJsonString(destination, (String) value);
            } else if (value instanceof Long) {
                destination.append(value);
            } else {
                throw new IllegalArgumentException(
                        "canonical JSON scalar type is unsupported");
            }
            first = false;
        }
        destination.append('}');
        return destination.toString().getBytes(StandardCharsets.US_ASCII);
    }

    /** Mirrors Python json.dumps(..., ensure_ascii=True, separators=(',', ':')). */
    private static void appendCanonicalJsonString(
            StringBuilder destination,
            String value) {
        destination.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"':
                    destination.append("\\\"");
                    break;
                case '\\':
                    destination.append("\\\\");
                    break;
                case '\b':
                    destination.append("\\b");
                    break;
                case '\f':
                    destination.append("\\f");
                    break;
                case '\n':
                    destination.append("\\n");
                    break;
                case '\r':
                    destination.append("\\r");
                    break;
                case '\t':
                    destination.append("\\t");
                    break;
                default:
                    if (character < 0x20 || character >= 0x7f) {
                        appendUnicodeEscape(destination, character);
                    } else {
                        destination.append(character);
                    }
                    break;
            }
        }
        destination.append('"');
    }

    private static void appendUnicodeEscape(
            StringBuilder destination,
            char value) {
        destination.append("\\u");
        for (int shift = 12; shift >= 0; shift -= 4) {
            destination.append(Character.forDigit(
                    (value >>> shift) & 0x0f, 16));
        }
    }

    private static byte[] sha256(byte[] value, ErrorCode errorCode)
            throws CredentialException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (GeneralSecurityException | RuntimeException rejected) {
            throw failure(errorCode);
        }
    }

    private static String lowerHex(byte[] value) {
        StringBuilder destination = new StringBuilder(value.length * 2);
        for (byte octet : value) {
            destination.append(Character.forDigit(
                    (octet >>> 4) & 0x0f, 16));
            destination.append(Character.forDigit(octet & 0x0f, 16));
        }
        return destination.toString();
    }

    private static Set<String> immutableSet(String... values) {
        return Collections.unmodifiableSet(
                new HashSet<>(Arrays.asList(values)));
    }

    private static CredentialException failure(ErrorCode errorCode) {
        return new CredentialException(errorCode);
    }

    /** Stable failures that never include a token, claim, key, or provider. */
    public enum ErrorCode {
        KEY_INVALID("pair_generation_credential_key_invalid"),
        SOURCE_INVALID("pair_generation_credential_source_invalid"),
        TOKEN_INVALID("pair_generation_credential_invalid"),
        OWNER_INVALID("pair_generation_credential_owner_invalid");

        private final String stableCode;

        ErrorCode(String stableCode) {
            this.stableCode = stableCode;
        }

        public String stableCode() {
            return stableCode;
        }
    }

    /** Sanitized verification-boundary failure. */
    public static final class CredentialException
            extends GeneralSecurityException {
        private static final long serialVersionUID = 1L;
        private final ErrorCode errorCode;

        private CredentialException(ErrorCode errorCode) {
            super(errorCode.stableCode());
            this.errorCode = errorCode;
        }

        public ErrorCode errorCode() {
            return errorCode;
        }
    }

    /** Immutable authoritative context for one expected allocation. */
    public static final class ExpectedV1 {
        private final String allocationRequestId;
        private final String pairId;
        private final String entitlementId;
        private final String bindingId;
        private final long bindingRevision;
        private final long revocationVersion;
        private final long generation;
        private final long connectionId;
        private final String hostIdentitySpkiSha256;
        private final String androidIdentitySpkiSha256;
        private final String transcriptProposalSha256;

        public ExpectedV1(
                String allocationRequestId,
                String pairId,
                String entitlementId,
                String bindingId,
                long bindingRevision,
                long revocationVersion,
                long generation,
                long connectionId,
                String hostIdentitySpkiSha256,
                String androidIdentitySpkiSha256,
                String transcriptProposalSha256) throws CredentialException {
            this.allocationRequestId = allocationRequestId;
            this.pairId = pairId;
            this.entitlementId = entitlementId;
            this.bindingId = bindingId;
            this.bindingRevision = bindingRevision;
            this.revocationVersion = revocationVersion;
            this.generation = generation;
            this.connectionId = connectionId;
            this.hostIdentitySpkiSha256 = hostIdentitySpkiSha256;
            this.androidIdentitySpkiSha256 = androidIdentitySpkiSha256;
            this.transcriptProposalSha256 = transcriptProposalSha256;
            requireValidExpected(this);
        }

        public String allocationRequestId() {
            return allocationRequestId;
        }

        public String pairId() {
            return pairId;
        }

        public String entitlementId() {
            return entitlementId;
        }

        public String bindingId() {
            return bindingId;
        }

        public long bindingRevision() {
            return bindingRevision;
        }

        public long revocationVersion() {
            return revocationVersion;
        }

        public long generation() {
            return generation;
        }

        public long connectionId() {
            return connectionId;
        }

        public String hostIdentitySpkiSha256() {
            return hostIdentitySpkiSha256;
        }

        public String androidIdentitySpkiSha256() {
            return androidIdentitySpkiSha256;
        }

        public String transcriptProposalSha256() {
            return transcriptProposalSha256;
        }
    }

    /**
     * Immutable typed owner created only after signature, canonicality,
     * freshness, and complete expected-context verification succeed.
     */
    public static final class VerifiedPairGenerationCredentialV1 {
        private final String tokenSha256;
        private final String keyId;
        private final String allocationRequestId;
        private final String pairId;
        private final String entitlementId;
        private final String bindingId;
        private final long bindingRevision;
        private final long revocationVersion;
        private final long generation;
        private final long connectionId;
        private final String hostIdentitySpkiSha256;
        private final String androidIdentitySpkiSha256;
        private final String transcriptProposalSha256;
        private final String credentialNonce;
        private final String credentialType;
        private final String issuer;
        private final String audience;
        private final long issuedAtEpoch;
        private final long notBeforeEpoch;
        private final long expiresAtEpoch;

        private VerifiedPairGenerationCredentialV1(
                String tokenSha256,
                String keyId,
                String allocationRequestId,
                String pairId,
                String entitlementId,
                String bindingId,
                long bindingRevision,
                long revocationVersion,
                long generation,
                long connectionId,
                String hostIdentitySpkiSha256,
                String androidIdentitySpkiSha256,
                String transcriptProposalSha256,
                String credentialNonce,
                String credentialType,
                String issuer,
                String audience,
                long issuedAtEpoch,
                long notBeforeEpoch,
                long expiresAtEpoch) {
            this.tokenSha256 = tokenSha256;
            this.keyId = keyId;
            this.allocationRequestId = allocationRequestId;
            this.pairId = pairId;
            this.entitlementId = entitlementId;
            this.bindingId = bindingId;
            this.bindingRevision = bindingRevision;
            this.revocationVersion = revocationVersion;
            this.generation = generation;
            this.connectionId = connectionId;
            this.hostIdentitySpkiSha256 = hostIdentitySpkiSha256;
            this.androidIdentitySpkiSha256 = androidIdentitySpkiSha256;
            this.transcriptProposalSha256 = transcriptProposalSha256;
            this.credentialNonce = credentialNonce;
            this.credentialType = credentialType;
            this.issuer = issuer;
            this.audience = audience;
            this.issuedAtEpoch = issuedAtEpoch;
            this.notBeforeEpoch = notBeforeEpoch;
            this.expiresAtEpoch = expiresAtEpoch;
        }

        public String tokenSha256() {
            return tokenSha256;
        }

        public String keyId() {
            return keyId;
        }

        public String allocationRequestId() {
            return allocationRequestId;
        }

        public String pairId() {
            return pairId;
        }

        public String entitlementId() {
            return entitlementId;
        }

        public String bindingId() {
            return bindingId;
        }

        public long bindingRevision() {
            return bindingRevision;
        }

        public long revocationVersion() {
            return revocationVersion;
        }

        public long generation() {
            return generation;
        }

        public long connectionId() {
            return connectionId;
        }

        public String hostIdentitySpkiSha256() {
            return hostIdentitySpkiSha256;
        }

        public String androidIdentitySpkiSha256() {
            return androidIdentitySpkiSha256;
        }

        public String transcriptProposalSha256() {
            return transcriptProposalSha256;
        }

        public String credentialNonce() {
            return credentialNonce;
        }

        public String credentialType() {
            return credentialType;
        }

        public String issuer() {
            return issuer;
        }

        public String audience() {
            return audience;
        }

        public long issuedAtEpoch() {
            return issuedAtEpoch;
        }

        public long notBeforeEpoch() {
            return notBeforeEpoch;
        }

        public long expiresAtEpoch() {
            return expiresAtEpoch;
        }
    }

    private static final class VerificationKey {
        private final String keyId;
        private final byte[] canonicalSpkiDer;
        private final RSAPublicKey providerKey;

        private VerificationKey(
                String keyId,
                byte[] canonicalSpkiDer,
                RSAPublicKey providerKey) {
            this.keyId = keyId;
            this.canonicalSpkiDer = canonicalSpkiDer.clone();
            this.providerKey = providerKey;
        }
    }

    private static final class RebuiltRsaKey {
        private final RSAPublicKey providerKey;
        private final byte[] canonicalSpkiDer;

        private RebuiltRsaKey(
                RSAPublicKey providerKey,
                byte[] canonicalSpkiDer) {
            this.providerKey = providerKey;
            this.canonicalSpkiDer = canonicalSpkiDer.clone();
        }
    }

    private static final class TokenSegments {
        private final byte[] headerBytes;
        private final byte[] payloadBytes;
        private final byte[] signatureBytes;
        private final byte[] signingInput;

        private TokenSegments(
                byte[] headerBytes,
                byte[] payloadBytes,
                byte[] signatureBytes,
                byte[] signingInput) {
            this.headerBytes = headerBytes;
            this.payloadBytes = payloadBytes;
            this.signatureBytes = signatureBytes;
            this.signingInput = signingInput;
        }
    }

    /** Strict parser for canonical flat JSON objects with string/integer values. */
    private static final class JsonObjectParser {
        private final String source;
        private int offset;

        private JsonObjectParser(String source) {
            this.source = source;
        }

        private Map<String, Object> parse() {
            skipWhitespace();
            require('{');
            skipWhitespace();
            Map<String, Object> values = new LinkedHashMap<>();
            if (consume('}')) {
                requireEnd();
                return Collections.unmodifiableMap(values);
            }
            while (true) {
                String name = parseString();
                if (values.containsKey(name)) {
                    throw new IllegalArgumentException("duplicate JSON key");
                }
                skipWhitespace();
                require(':');
                skipWhitespace();
                Object value = peek() == '"'
                        ? parseString()
                        : parseInteger();
                values.put(name, value);
                skipWhitespace();
                if (consume('}')) {
                    requireEnd();
                    return Collections.unmodifiableMap(values);
                }
                require(',');
                skipWhitespace();
            }
        }

        private String parseString() {
            require('"');
            StringBuilder value = new StringBuilder();
            while (offset < source.length()) {
                char character = source.charAt(offset++);
                if (character == '"') {
                    return value.toString();
                }
                if (character < 0x20) {
                    throw new IllegalArgumentException(
                            "control character in JSON string");
                }
                if (character != '\\') {
                    value.append(character);
                    continue;
                }
                if (offset >= source.length()) {
                    throw new IllegalArgumentException(
                            "truncated JSON escape");
                }
                appendEscape(value, source.charAt(offset++));
            }
            throw new IllegalArgumentException("unterminated JSON string");
        }

        private void appendEscape(StringBuilder value, char escape) {
            switch (escape) {
                case '"':
                    value.append('"');
                    break;
                case '\\':
                    value.append('\\');
                    break;
                case '/':
                    value.append('/');
                    break;
                case 'b':
                    value.append('\b');
                    break;
                case 'f':
                    value.append('\f');
                    break;
                case 'n':
                    value.append('\n');
                    break;
                case 'r':
                    value.append('\r');
                    break;
                case 't':
                    value.append('\t');
                    break;
                case 'u':
                    value.append(parseUnicodeEscape());
                    break;
                default:
                    throw new IllegalArgumentException(
                            "invalid JSON escape");
            }
        }

        private char parseUnicodeEscape() {
            if (offset + 4 > source.length()) {
                throw new IllegalArgumentException(
                        "truncated Unicode escape");
            }
            int value = 0;
            for (int index = 0; index < 4; index++) {
                int digit = Character.digit(source.charAt(offset++), 16);
                if (digit < 0) {
                    throw new IllegalArgumentException(
                            "invalid Unicode escape");
                }
                value = (value << 4) | digit;
            }
            return (char) value;
        }

        private Long parseInteger() {
            int start = offset;
            consume('-');
            if (offset >= source.length()) {
                throw new IllegalArgumentException("truncated JSON integer");
            }
            if (consume('0')) {
                if (offset < source.length() && isDigit(source.charAt(offset))) {
                    throw new IllegalArgumentException(
                            "leading zero in JSON integer");
                }
            } else {
                if (source.charAt(offset) < '1'
                        || source.charAt(offset) > '9') {
                    throw new IllegalArgumentException("invalid JSON integer");
                }
                while (offset < source.length()
                        && isDigit(source.charAt(offset))) {
                    offset++;
                }
            }
            if (offset < source.length()) {
                char suffix = source.charAt(offset);
                if (suffix == '.'
                        || suffix == 'e'
                        || suffix == 'E'
                        || suffix == '+') {
                    throw new IllegalArgumentException(
                            "non-integer JSON number");
                }
            }
            return Long.valueOf(source.substring(start, offset));
        }

        private void skipWhitespace() {
            while (offset < source.length()) {
                char character = source.charAt(offset);
                if (character != ' '
                        && character != '\t'
                        && character != '\r'
                        && character != '\n') {
                    return;
                }
                offset++;
            }
        }

        private char peek() {
            if (offset >= source.length()) {
                throw new IllegalArgumentException("truncated JSON");
            }
            return source.charAt(offset);
        }

        private boolean consume(char expected) {
            if (offset < source.length()
                    && source.charAt(offset) == expected) {
                offset++;
                return true;
            }
            return false;
        }

        private void require(char expected) {
            if (!consume(expected)) {
                throw new IllegalArgumentException("unexpected JSON token");
            }
        }

        private void requireEnd() {
            skipWhitespace();
            if (offset != source.length()) {
                throw new IllegalArgumentException("trailing JSON data");
            }
        }

        private static boolean isDigit(char value) {
            return value >= '0' && value <= '9';
        }
    }
}
