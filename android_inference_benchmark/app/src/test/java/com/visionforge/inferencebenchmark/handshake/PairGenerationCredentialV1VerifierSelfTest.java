package com.visionforge.inferencebenchmark.handshake;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/** Dependency-free JVM attack-contract tests for the credential verifier. */
public final class PairGenerationCredentialV1VerifierSelfTest {
    private static final long NOW_EPOCH = 1_900_000_000L;
    private static final String ALLOCATION_REQUEST_ID =
            "allocation.req:android-1";
    private static final String PAIR_ID = repeat('1', 32);
    private static final String ENTITLEMENT_ID = repeat('2', 32);
    private static final String BINDING_ID = repeat('3', 32);
    private static final String HOST_IDENTITY_SHA256 = repeat('4', 64);
    private static final String ANDROID_IDENTITY_SHA256 = repeat('5', 64);
    private static final String PROPOSAL_SHA256 = repeat('6', 64);
    private static final String CREDENTIAL_NONCE = repeat('7', 64);
    private static final long BINDING_REVISION = 3L;
    private static final long REVOCATION_VERSION = 4L;
    private static final long GENERATION = 7L;
    private static final long CONNECTION_ID = 8L;

    private PairGenerationCredentialV1VerifierSelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        require(arguments.length == 0, "self-test accepts no arguments");
        KeyPair current = generateRsa3072();
        KeyPair previous = generateRsa3072();

        verifiesHappyPathAndRotation(current, previous);
        rejectsSignatureAndKeySelectionAttacks(current, previous);
        rejectsExpectedContextMismatchAndRollback(current);
        rejectsExpirationSkewTtlAndIntegerAttacks(current);
        rejectsNoncanonicalJwtEncodings(current);
        verifiesKeyringAndPurposeSeparation(current, previous);
        verifiesMaliciousRsaWrapperIsRebuilt(current);
        verifiesSanitizedErrorsAndImmutableOwner(current);
        System.out.println("PairGenerationCredentialV1VerifierSelfTest: PASS");
    }

    private static void verifiesHappyPathAndRotation(
            KeyPair current,
            KeyPair previous) throws Exception {
        PairGenerationCredentialV1Verifier verifier =
                new PairGenerationCredentialV1Verifier(
                        new PublicKey[] {
                            current.getPublic(), previous.getPublic()
                        },
                        new PublicKey[0]);
        String currentKid = keyId(current.getPublic());
        String token = signedToken(
                claims(), currentKid, current.getPrivate());
        PairGenerationCredentialV1Verifier.VerifiedPairGenerationCredentialV1
                verified = verifier.verify(token, expected(), NOW_EPOCH);

        require(verified.keyId().equals(currentKid), "current key id");
        require(
                verified.tokenSha256().equals(sha256Hex(
                token.getBytes(StandardCharsets.US_ASCII))),
                "token digest");
        require(
                verified.allocationRequestId().equals(ALLOCATION_REQUEST_ID),
                "allocation request");
        require(verified.pairId().equals(PAIR_ID), "pair id");
        require(
                verified.entitlementId().equals(ENTITLEMENT_ID),
                "entitlement id");
        require(verified.bindingId().equals(BINDING_ID), "binding id");
        require(
                verified.bindingRevision() == BINDING_REVISION,
                "binding revision");
        require(
                verified.revocationVersion() == REVOCATION_VERSION,
                "revocation version");
        require(verified.generation() == GENERATION, "generation");
        require(verified.connectionId() == CONNECTION_ID, "connection id");
        require(
                verified.hostIdentitySpkiSha256()
                        .equals(HOST_IDENTITY_SHA256),
                "host identity");
        require(
                verified.androidIdentitySpkiSha256()
                        .equals(ANDROID_IDENTITY_SHA256),
                "Android identity");
        require(
                verified.transcriptProposalSha256().equals(PROPOSAL_SHA256),
                "proposal digest");
        require(
                verified.credentialNonce().equals(CREDENTIAL_NONCE),
                "credential nonce");
        require(
                verified.credentialType().equals(
                PairGenerationCredentialV1Verifier.CREDENTIAL_TYPE),
                "credential type");
        require(
                verified.issuer().equals(
                PairGenerationCredentialV1Verifier.CREDENTIAL_ISSUER),
                "issuer");
        require(
                verified.audience().equals(
                PairGenerationCredentialV1Verifier.CREDENTIAL_AUDIENCE),
                "audience");
        require(verified.issuedAtEpoch() == NOW_EPOCH, "issued at");
        require(verified.notBeforeEpoch() == NOW_EPOCH, "not before");
        require(verified.expiresAtEpoch() == NOW_EPOCH + 15L, "expires");

        String previousToken = signedToken(
                claims(), keyId(previous.getPublic()), previous.getPrivate());
        require(
                verifier.verify(previousToken, expected(), NOW_EPOCH)
                        .keyId().equals(keyId(previous.getPublic())),
                "previous rotation key verifies");

        String[] returnedIds = verifier.keyIds();
        returnedIds[0] = repeat('f', 16);
        require(
                verifier.keyIds()[0].equals(currentKid),
                "key id ownership is defensive");
    }

    private static void rejectsSignatureAndKeySelectionAttacks(
            KeyPair current,
            KeyPair previous) throws Exception {
        PairGenerationCredentialV1Verifier verifier = verifier(current);
        String token = signedToken(
                claims(), keyId(current.getPublic()), current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(
                        corruptSignature(token), expected(), NOW_EPOCH));

        String wrongSignature = signedToken(
                claims(), keyId(current.getPublic()), previous.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(wrongSignature, expected(), NOW_EPOCH));

        String unknownKidToken = signedToken(
                claims(), repeat('a', 16), current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(
                        unknownKidToken, expected(), NOW_EPOCH));
    }

    private static void rejectsExpectedContextMismatchAndRollback(
            KeyPair current) throws Exception {
        PairGenerationCredentialV1Verifier verifier = verifier(current);
        String keyId = keyId(current.getPublic());
        String token = signedToken(claims(), keyId, current.getPrivate());

        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(
                        token,
                        expected(
                                HOST_IDENTITY_SHA256,
                                ANDROID_IDENTITY_SHA256,
                                repeat('8', 64),
                                GENERATION),
                        NOW_EPOCH));
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(
                        token,
                        expected(
                                repeat('9', 64),
                                ANDROID_IDENTITY_SHA256,
                                PROPOSAL_SHA256,
                                GENERATION),
                        NOW_EPOCH));

        Map<String, Object> rolledBackClaims = claims();
        rolledBackClaims.put("generation", GENERATION - 1L);
        String rolledBack = signedToken(
                rolledBackClaims, keyId, current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(rolledBack, expected(), NOW_EPOCH));

        Map<String, Object> staleRevisionClaims = claims();
        staleRevisionClaims.put(
                "binding_revision", BINDING_REVISION - 1L);
        String staleRevision = signedToken(
                staleRevisionClaims, keyId, current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(staleRevision, expected(), NOW_EPOCH));
    }

    private static void rejectsExpirationSkewTtlAndIntegerAttacks(
            KeyPair current) throws Exception {
        PairGenerationCredentialV1Verifier verifier = verifier(current);
        String keyId = keyId(current.getPublic());

        Map<String, Object> expiredClaims = claims();
        expiredClaims.put("iat", NOW_EPOCH - 15L);
        expiredClaims.put("nbf", NOW_EPOCH - 15L);
        expiredClaims.put("exp", NOW_EPOCH);
        String expired = signedToken(
                expiredClaims, keyId, current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(expired, expected(), NOW_EPOCH));

        Map<String, Object> excessiveTtlClaims = claims();
        excessiveTtlClaims.put("exp", NOW_EPOCH + 31L);
        String excessiveTtl = signedToken(
                excessiveTtlClaims, keyId, current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(
                        excessiveTtl, expected(), NOW_EPOCH));

        Map<String, Object> futureClaims = claims();
        futureClaims.put("iat", NOW_EPOCH + 3L);
        futureClaims.put("nbf", NOW_EPOCH + 3L);
        futureClaims.put("exp", NOW_EPOCH + 18L);
        String future = signedToken(
                futureClaims, keyId, current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(future, expected(), NOW_EPOCH));

        Map<String, Object> allowedSkewClaims = claims();
        allowedSkewClaims.put("iat", NOW_EPOCH + 2L);
        allowedSkewClaims.put("nbf", NOW_EPOCH + 2L);
        allowedSkewClaims.put("exp", NOW_EPOCH + 17L);
        String allowedSkew = signedToken(
                allowedSkewClaims, keyId, current.getPrivate());
        require(
                verifier.verify(allowedSkew, expected(), NOW_EPOCH)
                        .issuedAtEpoch() == NOW_EPOCH + 2L,
                "two-second issued-at skew accepted");

        String canonicalPayload = new String(
                canonicalJson(claims()), StandardCharsets.US_ASCII);
        String oversizedIntegerPayload = canonicalPayload.replace(
                "\"generation\":7",
                "\"generation\":9223372036854775808");
        require(
                !oversizedIntegerPayload.equals(canonicalPayload),
                "integer fixture mutation applied");
        String oversizedInteger = signedRawToken(
                canonicalHeader(keyId),
                oversizedIntegerPayload.getBytes(StandardCharsets.US_ASCII),
                current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(
                        oversizedInteger, expected(), NOW_EPOCH));

        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(
                        signedToken(claims(), keyId, current.getPrivate()),
                        expected(),
                        0L));
    }

    private static void rejectsNoncanonicalJwtEncodings(KeyPair current)
            throws Exception {
        PairGenerationCredentialV1Verifier verifier = verifier(current);
        String keyId = keyId(current.getPublic());
        byte[] payload = canonicalJson(claims());

        Map<String, Object> wrongAlgorithmHeader = header(keyId);
        wrongAlgorithmHeader.put("alg", "HS256");
        String wrongAlgorithm = signedRawToken(
                canonicalJson(wrongAlgorithmHeader),
                payload,
                current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(
                        wrongAlgorithm, expected(), NOW_EPOCH));

        String valid = signedToken(
                claims(), keyId, current.getPrivate());
        int firstSeparator = valid.indexOf('.');
        String paddedHeader = valid.substring(0, firstSeparator)
                + "=" + valid.substring(firstSeparator);
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(
                        paddedHeader, expected(), NOW_EPOCH));

        String reorderedHeader = "{\"typ\":\"JWT\",\"kid\":\""
                + keyId + "\",\"alg\":\"RS256\"}";
        String noncanonicalOrder = signedRawToken(
                reorderedHeader.getBytes(StandardCharsets.US_ASCII),
                payload,
                current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(
                        noncanonicalOrder, expected(), NOW_EPOCH));

        String escapedHeader = "{\"alg\":\"RS256\",\"kid\":\""
                + keyId + "\",\"typ\":\"\\u004aWT\"}";
        String noncanonicalEscape = signedRawToken(
                escapedHeader.getBytes(StandardCharsets.US_ASCII),
                payload,
                current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(
                        noncanonicalEscape, expected(), NOW_EPOCH));

        String canonicalPayload = new String(
                payload, StandardCharsets.US_ASCII);
        String duplicateAudience = "{\"aud\":\""
                + PairGenerationCredentialV1Verifier.CREDENTIAL_AUDIENCE
                + "\"," + canonicalPayload.substring(1);
        String duplicateKey = signedRawToken(
                canonicalHeader(keyId),
                duplicateAudience.getBytes(StandardCharsets.US_ASCII),
                current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(duplicateKey, expected(), NOW_EPOCH));

        Map<String, Object> missingClaim = claims();
        missingClaim.remove("credential_nonce");
        String missing = signedToken(
                missingClaim, keyId, current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(missing, expected(), NOW_EPOCH));

        Map<String, Object> extraClaim = claims();
        extraClaim.put("extra", "not-authorized");
        String extra = signedToken(
                extraClaim, keyId, current.getPrivate());
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(extra, expected(), NOW_EPOCH));
    }

    private static void verifiesKeyringAndPurposeSeparation(
            KeyPair current,
            KeyPair previous) throws Exception {
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.KEY_INVALID,
                () -> new PairGenerationCredentialV1Verifier(
                        new PublicKey[0]));
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.KEY_INVALID,
                () -> new PairGenerationCredentialV1Verifier(
                        new PublicKey[] {
                            current.getPublic(),
                            previous.getPublic(),
                            current.getPublic(),
                            previous.getPublic()
                        }));
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.KEY_INVALID,
                () -> new PairGenerationCredentialV1Verifier(
                        new PublicKey[] {
                            current.getPublic(), current.getPublic()
                        }));
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.KEY_INVALID,
                () -> new PairGenerationCredentialV1Verifier(
                        new PublicKey[] {current.getPublic()},
                        new PublicKey[] {current.getPublic()}));

        PairGenerationCredentialV1Verifier separated =
                new PairGenerationCredentialV1Verifier(
                        new PublicKey[] {current.getPublic()},
                        new PublicKey[] {previous.getPublic()});
        require(
                separated.keyIds()[0].equals(keyId(current.getPublic())),
                "different-purpose SPKI remains disjoint");

        RSAPublicKey currentPublic = (RSAPublicKey) current.getPublic();
        PublicKey wrongExponent = new NumbersOnlyRsaPublicKey(
                currentPublic.getModulus(), BigInteger.valueOf(3L));
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.KEY_INVALID,
                () -> new PairGenerationCredentialV1Verifier(
                        new PublicKey[] {wrongExponent}));
    }

    private static void verifiesMaliciousRsaWrapperIsRebuilt(KeyPair current)
            throws Exception {
        RSAPublicKey real = (RSAPublicKey) current.getPublic();
        PublicKey wrapper = new NumbersOnlyRsaPublicKey(
                real.getModulus(), real.getPublicExponent());
        PairGenerationCredentialV1Verifier verifier =
                new PairGenerationCredentialV1Verifier(
                        new PublicKey[] {wrapper});
        String token = signedToken(
                claims(), keyId(current.getPublic()), current.getPrivate());
        require(
                verifier.verify(token, expected(), NOW_EPOCH)
                        .keyId().equals(keyId(current.getPublic())),
                "provider-owned key verifies wrapper numbers");
    }

    private static void verifiesSanitizedErrorsAndImmutableOwner(
            KeyPair current) throws Exception {
        PairGenerationCredentialV1Verifier verifier = verifier(current);
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.TOKEN_INVALID,
                () -> verifier.verify(
                        "not-a-credential", expected(), NOW_EPOCH));
        expectError(
                PairGenerationCredentialV1Verifier.ErrorCode.SOURCE_INVALID,
                () -> new PairGenerationCredentialV1Verifier.ExpectedV1(
                        ALLOCATION_REQUEST_ID,
                        PAIR_ID,
                        ENTITLEMENT_ID,
                        BINDING_ID,
                        BINDING_REVISION,
                        REVOCATION_VERSION,
                        GENERATION,
                        CONNECTION_ID,
                        HOST_IDENTITY_SHA256,
                        HOST_IDENTITY_SHA256,
                        PROPOSAL_SHA256));

        Class<?> owner = PairGenerationCredentialV1Verifier
                .VerifiedPairGenerationCredentialV1.class;
        require(Modifier.isFinal(owner.getModifiers()), "owner class is final");
        for (Constructor<?> constructor : owner.getDeclaredConstructors()) {
            require(
                    !Modifier.isPublic(constructor.getModifiers()),
                    "owner has no public constructor");
            if (!constructor.isSynthetic()) {
                require(
                        Modifier.isPrivate(constructor.getModifiers()),
                        "declared owner constructor is private");
            }
        }
        for (Field field : owner.getDeclaredFields()) {
            int modifiers = field.getModifiers();
            require(
                    Modifier.isPrivate(modifiers)
                            && Modifier.isFinal(modifiers),
                    "owner fields are private final");
            require(!field.getType().isArray(), "owner has no mutable array");
        }
    }

    private static PairGenerationCredentialV1Verifier verifier(KeyPair keyPair)
            throws Exception {
        return new PairGenerationCredentialV1Verifier(
                new PublicKey[] {keyPair.getPublic()});
    }

    private static PairGenerationCredentialV1Verifier.ExpectedV1 expected()
            throws Exception {
        return expected(
                HOST_IDENTITY_SHA256,
                ANDROID_IDENTITY_SHA256,
                PROPOSAL_SHA256,
                GENERATION);
    }

    private static PairGenerationCredentialV1Verifier.ExpectedV1 expected(
            String hostIdentity,
            String androidIdentity,
            String proposalSha256,
            long generation) throws Exception {
        return new PairGenerationCredentialV1Verifier.ExpectedV1(
                ALLOCATION_REQUEST_ID,
                PAIR_ID,
                ENTITLEMENT_ID,
                BINDING_ID,
                BINDING_REVISION,
                REVOCATION_VERSION,
                generation,
                CONNECTION_ID,
                hostIdentity,
                androidIdentity,
                proposalSha256);
    }

    private static Map<String, Object> claims() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("allocation_request_id", ALLOCATION_REQUEST_ID);
        claims.put("android_identity_spki_sha256", ANDROID_IDENTITY_SHA256);
        claims.put(
                "aud",
                PairGenerationCredentialV1Verifier.CREDENTIAL_AUDIENCE);
        claims.put("binding_id", BINDING_ID);
        claims.put("binding_revision", BINDING_REVISION);
        claims.put("connection_id", CONNECTION_ID);
        claims.put("credential_nonce", CREDENTIAL_NONCE);
        claims.put("entitlement_id", ENTITLEMENT_ID);
        claims.put("exp", NOW_EPOCH + 15L);
        claims.put("generation", GENERATION);
        claims.put("host_identity_spki_sha256", HOST_IDENTITY_SHA256);
        claims.put("iat", NOW_EPOCH);
        claims.put(
                "iss",
                PairGenerationCredentialV1Verifier.CREDENTIAL_ISSUER);
        claims.put("nbf", NOW_EPOCH);
        claims.put("pair_id", PAIR_ID);
        claims.put("revocation_version", REVOCATION_VERSION);
        claims.put("transcript_proposal_sha256", PROPOSAL_SHA256);
        claims.put(
                "typ", PairGenerationCredentialV1Verifier.CREDENTIAL_TYPE);
        return claims;
    }

    private static Map<String, Object> header(String keyId) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "RS256");
        header.put("kid", keyId);
        header.put("typ", "JWT");
        return header;
    }

    private static byte[] canonicalHeader(String keyId) {
        return canonicalJson(header(keyId));
    }

    private static String signedToken(
            Map<String, Object> claims,
            String keyId,
            PrivateKey privateKey) throws Exception {
        return signedRawToken(
                canonicalHeader(keyId),
                canonicalJson(claims),
                privateKey);
    }

    private static String signedRawToken(
            byte[] header,
            byte[] payload,
            PrivateKey privateKey) throws Exception {
        String signingInput = base64Url(header) + "." + base64Url(payload);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + base64Url(signer.sign());
    }

    private static String corruptSignature(String token) {
        int separator = token.lastIndexOf('.');
        byte[] signature = Base64.getUrlDecoder().decode(
                token.substring(separator + 1));
        signature[signature.length - 1] ^= 1;
        return token.substring(0, separator + 1) + base64Url(signature);
    }

    private static byte[] canonicalJson(Map<String, Object> source) {
        StringBuilder destination = new StringBuilder(768).append('{');
        boolean first = true;
        for (Map.Entry<String, Object> entry
                : new TreeMap<>(source).entrySet()) {
            if (!first) {
                destination.append(',');
            }
            quoted(destination, entry.getKey());
            destination.append(':');
            Object value = entry.getValue();
            if (value instanceof String) {
                quoted(destination, (String) value);
            } else if (value instanceof Long) {
                destination.append(value);
            } else {
                throw new AssertionError("unsupported fixture value type");
            }
            first = false;
        }
        destination.append('}');
        return destination.toString().getBytes(StandardCharsets.US_ASCII);
    }

    private static void quoted(StringBuilder destination, String value) {
        destination.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '"' || character == '\\') {
                destination.append('\\');
            }
            destination.append(character);
        }
        destination.append('"');
    }

    private static String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static String keyId(PublicKey publicKey) throws Exception {
        return sha256Hex(publicKey.getEncoded()).substring(0, 16);
    }

    private static String sha256Hex(byte[] value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder result = new StringBuilder(digest.length * 2);
        for (byte octet : digest) {
            result.append(Character.forDigit((octet >>> 4) & 0x0f, 16));
            result.append(Character.forDigit(octet & 0x0f, 16));
        }
        return result.toString();
    }

    private static KeyPair generateRsa3072() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        return generator.generateKeyPair();
    }

    private static String repeat(char character, int count) {
        StringBuilder result = new StringBuilder(count);
        for (int index = 0; index < count; index++) {
            result.append(character);
        }
        return result.toString();
    }

    private static void expectError(
            PairGenerationCredentialV1Verifier.ErrorCode expectedCode,
            CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError(
                    "expected credential rejection: " + expectedCode);
        } catch (PairGenerationCredentialV1Verifier.CredentialException
                rejected) {
            require(
                    rejected.errorCode() == expectedCode,
                    "stable error enum");
            require(
                    rejected.getMessage().equals(expectedCode.stableCode()),
                    "error contains only stable code");
            require(rejected.getCause() == null, "provider cause is absent");
            require(
                    !rejected.getMessage().contains(PAIR_ID.substring(0, 8))
                            && !rejected.getMessage().contains("RSA")
                            && !rejected.getMessage().contains("eyJ"),
                    "credential, key, and token data are absent");
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private interface CheckedAction {
        void run() throws Exception;
    }

    /**
     * Hostile wrapper: only RSA numbers are usable. Any encoded/provider
     * interaction with this object aborts the test immediately.
     */
    private static final class NumbersOnlyRsaPublicKey
            implements RSAPublicKey {
        private static final long serialVersionUID = 1L;
        private final BigInteger modulus;
        private final BigInteger publicExponent;

        private NumbersOnlyRsaPublicKey(
                BigInteger modulus,
                BigInteger publicExponent) {
            this.modulus = modulus;
            this.publicExponent = publicExponent;
        }

        @Override
        public BigInteger getModulus() {
            return modulus;
        }

        @Override
        public BigInteger getPublicExponent() {
            return publicExponent;
        }

        @Override
        public String getAlgorithm() {
            throw new AssertionError("untrusted algorithm accessor used");
        }

        @Override
        public String getFormat() {
            throw new AssertionError("untrusted format accessor used");
        }

        @Override
        public byte[] getEncoded() {
            throw new AssertionError("untrusted encoding accessor used");
        }
    }
}
