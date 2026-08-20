package com.visionforge.inferencebenchmark;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
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
 * Strict JCA-only verifier for the independent dual-machine sidecar's short
 * RS256 data-plane lease.
 *
 * <p>The verifier owns no key storage. Its caller supplies the pinned public
 * key, an exact expected binding and trusted wall/monotonic time observations.
 * A verified wall-clock interval is converted once into monotonic deadlines;
 * later wall-clock changes cannot extend the lease.</p>
 */
public final class DualMachineUsageLeaseVerifier {
    public static final int DEFAULT_MAXIMUM_TTL_SECONDS = 5;
    public static final int ABSOLUTE_MAXIMUM_TTL_SECONDS = 10;
    public static final int SERVER_CLOCK_AHEAD_GRACE_SECONDS = 2;
    public static final int MAXIMUM_TOKEN_CHARACTERS = 8192;
    public static final int MINIMUM_RSA_BITS = 3072;
    public static final int PROTOCOL_VERSION = 2;
    public static final String LEASE_TYPE = "vf-dual-machine-usage-lease-v1";
    public static final String LEASE_ISSUER = "visionforge-dual-machine-service";
    public static final String LEASE_AUDIENCE = "visionforge-dual-machine-data-plane";
    /** Initial-chain sentinel; intentionally not SHA-256(empty). */
    public static final String EMPTY_PREVIOUS_LEASE_SHA256 =
            "0000000000000000000000000000000000000000000000000000000000000000";

    private static final long NANOS_PER_SECOND = 1_000_000_000L;
    private static final Pattern HEX_128 = Pattern.compile("[0-9a-f]{32}");
    private static final Pattern SHA256_HEX = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern JTI_HEX = Pattern.compile("[0-9a-f]{32}");
    private static final Pattern KID_HEX = Pattern.compile("[0-9a-f]{16}");
    private static final Set<String> HEADER_KEYS = immutableSet("alg", "kid", "typ");
    private static final Set<String> CLAIM_KEYS = immutableSet(
            "akh", "aud", "authorization_kind", "cbh", "exp", "hkh",
            "iat", "is_permanent", "iss", "jti",
            "nbf", "phase", "pid", "pth", "pv", "remaining", "rv",
            "seq", "sid", "sub", "typ");

    private final RSAPublicKey publicKey;
    private final String expectedKeyId;
    private final int maximumTtlSeconds;

    public DualMachineUsageLeaseVerifier(PublicKey publicKey)
            throws GeneralSecurityException {
        this(publicKey, DEFAULT_MAXIMUM_TTL_SECONDS);
    }

    public DualMachineUsageLeaseVerifier(PublicKey publicKey, int maximumTtlSeconds)
            throws GeneralSecurityException {
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new GeneralSecurityException("usage_lease_key_must_be_rsa");
        }
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        if (rsaPublicKey.getModulus().bitLength() < MINIMUM_RSA_BITS
                || rsaPublicKey.getEncoded() == null) {
            throw new GeneralSecurityException("usage_lease_key_too_small_or_unavailable");
        }
        if (maximumTtlSeconds < 1
                || maximumTtlSeconds > ABSOLUTE_MAXIMUM_TTL_SECONDS) {
            throw new IllegalArgumentException("maximumTtlSeconds must be between 1 and 10");
        }
        this.publicKey = rsaPublicKey;
        this.expectedKeyId = sha256Hex(rsaPublicKey.getEncoded()).substring(0, 16);
        this.maximumTtlSeconds = maximumTtlSeconds;
    }

    public String expectedKeyId() {
        return expectedKeyId;
    }

    public int maximumTtlSeconds() {
        return maximumTtlSeconds;
    }

    /**
     * Verifies a ticket and maps its trusted epoch interval to caller-supplied
     * monotonic time. Future tickets are valid results but remain closed until
     * their returned not-before deadline.
     */
    public VerifiedLease verify(
            String token,
            ExpectedBinding expected,
            long trustedWallTimeEpochSeconds,
            long monotonicNowNanos) throws LeaseVerificationException {
        if (expected == null || trustedWallTimeEpochSeconds <= 0L) {
            throw invalid("usage_lease_verification_context_invalid");
        }
        TokenSegments segments = decodeToken(token);
        Map<String, Object> header = parseCanonicalObject(
                segments.headerBytes, HEADER_KEYS, "usage_lease_header_invalid");
        requireHeader(header);
        verifySignature(segments);
        Map<String, Object> claims = parseCanonicalObject(
                segments.payloadBytes, CLAIM_KEYS, "usage_lease_claims_invalid");
        requireClaims(claims, expected, trustedWallTimeEpochSeconds);
        requireJti(claims);

        long issuedAtEpoch = integerClaim(claims, "iat");
        long notBeforeEpoch = integerClaim(claims, "nbf");
        long expiresEpoch = integerClaim(claims, "exp");
        long mappingEpoch = Math.max(trustedWallTimeEpochSeconds, issuedAtEpoch);
        long notBeforeDelay = Math.max(0L, notBeforeEpoch - mappingEpoch);
        long expiresDelay = expiresEpoch - mappingEpoch;
        long notBeforeDeadline = addSeconds(monotonicNowNanos, notBeforeDelay);
        long expiresDeadline = addSeconds(monotonicNowNanos, expiresDelay);
        return new VerifiedLease(
                sha256Hex(token.getBytes(StandardCharsets.US_ASCII)),
                stringClaim(claims, "sub"),
                stringClaim(claims, "pid"),
                stringClaim(claims, "sid"),
                integerClaim(claims, "pv"),
                integerClaim(claims, "rv"),
                stringClaim(claims, "hkh"),
                stringClaim(claims, "akh"),
                stringClaim(claims, "cbh"),
                stringClaim(claims, "pth"),
                integerClaim(claims, "seq"),
                stringClaim(claims, "authorization_kind"),
                booleanClaim(claims, "is_permanent"),
                integerClaim(claims, "remaining"),
                issuedAtEpoch,
                notBeforeEpoch,
                expiresEpoch,
                notBeforeDeadline,
                expiresDeadline);
    }

    private TokenSegments decodeToken(String token) throws LeaseVerificationException {
        if (token == null || token.isEmpty() || token.length() > MAXIMUM_TOKEN_CHARACTERS) {
            throw invalid("usage_lease_token_size_invalid");
        }
        int firstSeparator = token.indexOf('.');
        int secondSeparator = token.indexOf('.', firstSeparator + 1);
        if (firstSeparator <= 0 || secondSeparator <= firstSeparator + 1
                || secondSeparator >= token.length() - 1
                || token.indexOf('.', secondSeparator + 1) >= 0) {
            throw invalid("usage_lease_token_segments_invalid");
        }
        String header = token.substring(0, firstSeparator);
        String payload = token.substring(firstSeparator + 1, secondSeparator);
        String signature = token.substring(secondSeparator + 1);
        return new TokenSegments(
                decodeCanonicalBase64Url(header),
                decodeCanonicalBase64Url(payload),
                decodeCanonicalBase64Url(signature),
                (header + "." + payload).getBytes(StandardCharsets.US_ASCII));
    }

    private byte[] decodeCanonicalBase64Url(String value)
            throws LeaseVerificationException {
        if (value.isEmpty() || value.indexOf('=') >= 0) {
            throw invalid("usage_lease_base64url_invalid");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            boolean valid = character >= 'A' && character <= 'Z'
                    || character >= 'a' && character <= 'z'
                    || character >= '0' && character <= '9'
                    || character == '-' || character == '_';
            if (!valid) throw invalid("usage_lease_base64url_invalid");
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(value);
            String canonical = Base64.getUrlEncoder().withoutPadding().encodeToString(decoded);
            if (!canonical.equals(value)) throw invalid("usage_lease_base64url_not_canonical");
            return decoded;
        } catch (IllegalArgumentException exception) {
            throw invalid("usage_lease_base64url_invalid", exception);
        }
    }

    private Map<String, Object> parseCanonicalObject(
            byte[] encoded,
            Set<String> exactKeys,
            String errorCode) throws LeaseVerificationException {
        try {
            String text = decodeUtf8(encoded);
            Map<String, Object> parsed = new JsonObjectParser(text).parse();
            if (!parsed.keySet().equals(exactKeys)
                    || !Arrays.equals(encoded, canonicalJson(parsed))) {
                throw invalid(errorCode);
            }
            return parsed;
        } catch (LeaseVerificationException exception) {
            throw exception;
        } catch (RuntimeException | CharacterCodingException exception) {
            throw invalid(errorCode, exception);
        }
    }

    private void requireHeader(Map<String, Object> header)
            throws LeaseVerificationException {
        if (!"RS256".equals(stringClaim(header, "alg"))
                || !"JWT".equals(stringClaim(header, "typ"))
                || !KID_HEX.matcher(stringClaim(header, "kid")).matches()
                || !expectedKeyId.equals(stringClaim(header, "kid"))) {
            throw invalid("usage_lease_header_binding_invalid");
        }
    }

    private void verifySignature(TokenSegments segments)
            throws LeaseVerificationException {
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(segments.signingInput);
            if (!verifier.verify(segments.signatureBytes)) {
                throw invalid("usage_lease_signature_invalid");
            }
        } catch (LeaseVerificationException exception) {
            throw exception;
        } catch (GeneralSecurityException exception) {
            throw invalid("usage_lease_signature_invalid", exception);
        }
    }

    private void requireClaims(
            Map<String, Object> claims,
            ExpectedBinding expected,
            long trustedWallTimeEpochSeconds) throws LeaseVerificationException {
        requireStringFormats(claims);
        long protocolVersion = integerClaim(claims, "pv");
        long revocationVersion = integerClaim(claims, "rv");
        long sequence = integerClaim(claims, "seq");
        long remaining = integerClaim(claims, "remaining");
        long issuedAt = integerClaim(claims, "iat");
        long notBefore = integerClaim(claims, "nbf");
        long expiresAt = integerClaim(claims, "exp");
        String authorizationKind = stringClaim(
                claims, "authorization_kind");
        boolean permanent = booleanClaim(claims, "is_permanent");
        long maximumObservedIssuedAt = trustedWallTimeEpochSeconds
                + SERVER_CLOCK_AHEAD_GRACE_SECONDS;
        if (protocolVersion != PROTOCOL_VERSION || revocationVersion <= 0L
                || sequence < 0L || remaining < 0L || issuedAt <= 0L
                || issuedAt > maximumObservedIssuedAt || notBefore < issuedAt
                || expiresAt <= notBefore || expiresAt <= trustedWallTimeEpochSeconds
                || expiresAt - notBefore > maximumTtlSeconds
                || permanent != "permanent".equals(authorizationKind)
                || (permanent && remaining != 0L)) {
            throw invalid("usage_lease_time_or_numeric_claim_invalid");
        }
        if (!expected.matches(claims)) {
            throw invalid("usage_lease_expected_binding_mismatch");
        }
    }

    private void requireStringFormats(Map<String, Object> claims)
            throws LeaseVerificationException {
        long sequence = integerClaim(claims, "seq");
        if (!LEASE_TYPE.equals(stringClaim(claims, "typ"))
                || !LEASE_ISSUER.equals(stringClaim(claims, "iss"))
                || !LEASE_AUDIENCE.equals(stringClaim(claims, "aud"))
                || !"active".equals(stringClaim(claims, "phase"))
                || !isAuthorizationKind(
                stringClaim(claims, "authorization_kind"))
                || !matchesNonzero(HEX_128, stringClaim(claims, "sub"))
                || !matchesNonzero(HEX_128, stringClaim(claims, "pid"))
                || !matchesNonzero(HEX_128, stringClaim(claims, "sid"))
                || !matchesNonzero(SHA256_HEX, stringClaim(claims, "hkh"))
                || !matchesNonzero(SHA256_HEX, stringClaim(claims, "akh"))
                || !matchesNonzero(SHA256_HEX, stringClaim(claims, "cbh"))
                || !previousLeaseSha256Valid(
                stringClaim(claims, "pth"), sequence)
                || !matchesNonzero(JTI_HEX, stringClaim(claims, "jti"))) {
            throw invalid("usage_lease_string_claim_invalid");
        }
    }

    private void requireJti(Map<String, Object> claims)
            throws LeaseVerificationException {
        Map<String, Object> withoutJti = new LinkedHashMap<>(claims);
        String providedJti = stringClaim(withoutJti.remove("jti"), "jti");
        String expectedJti = sha256Hex(canonicalJson(withoutJti)).substring(0, 32);
        if (!MessageDigest.isEqual(
                providedJti.getBytes(StandardCharsets.US_ASCII),
                expectedJti.getBytes(StandardCharsets.US_ASCII))) {
            throw invalid("usage_lease_jti_invalid");
        }
    }

    private static String stringClaim(Map<String, Object> source, String key)
            throws LeaseVerificationException {
        return stringClaim(source.get(key), key);
    }

    private static String stringClaim(Object value, String key)
            throws LeaseVerificationException {
        if (!(value instanceof String)) {
            throw invalid("usage_lease_claim_type_invalid_" + key);
        }
        return (String) value;
    }

    private static long integerClaim(Map<String, Object> source, String key)
            throws LeaseVerificationException {
        Object value = source.get(key);
        if (!(value instanceof Long)) {
            throw invalid("usage_lease_claim_type_invalid_" + key);
        }
        return (Long) value;
    }

    private static boolean booleanClaim(
            Map<String, Object> source,
            String key) throws LeaseVerificationException {
        Object value = source.get(key);
        if (!(value instanceof Boolean)) {
            throw invalid("usage_lease_claim_type_invalid_" + key);
        }
        return (Boolean) value;
    }

    private static boolean isAuthorizationKind(String value) {
        return "legacy_balance".equals(value)
                || "day".equals(value)
                || "week".equals(value)
                || "month".equals(value)
                || "permanent".equals(value);
    }

    private static long addSeconds(long monotonicNowNanos, long seconds)
            throws LeaseVerificationException {
        try {
            return Math.addExact(monotonicNowNanos, Math.multiplyExact(seconds, NANOS_PER_SECOND));
        } catch (ArithmeticException exception) {
            throw invalid("usage_lease_monotonic_deadline_overflow", exception);
        }
    }

    private static String decodeUtf8(byte[] value) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value)).toString();
    }

    private static byte[] canonicalJson(Map<String, Object> source) {
        StringBuilder destination = new StringBuilder(512).append('{');
        boolean first = true;
        for (Map.Entry<String, Object> entry : new TreeMap<>(source).entrySet()) {
            if (!first) destination.append(',');
            appendJsonString(destination, entry.getKey());
            destination.append(':');
            Object value = entry.getValue();
            if (value instanceof String) {
                appendJsonString(destination, (String) value);
            } else if (value instanceof Long) {
                destination.append(value);
            } else if (value instanceof Boolean) {
                destination.append(value);
            } else {
                throw new IllegalArgumentException("canonical JSON value type is unsupported");
            }
            first = false;
        }
        destination.append('}');
        return destination.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void appendJsonString(StringBuilder destination, String value) {
        destination.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"': destination.append("\\\""); break;
                case '\\': destination.append("\\\\"); break;
                case '\b': destination.append("\\b"); break;
                case '\f': destination.append("\\f"); break;
                case '\n': destination.append("\\n"); break;
                case '\r': destination.append("\\r"); break;
                case '\t': destination.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        destination.append("\\u00");
                        destination.append(Character.forDigit((character >> 4) & 0x0f, 16));
                        destination.append(Character.forDigit(character & 0x0f, 16));
                    } else {
                        destination.append(character);
                    }
                    break;
            }
        }
        destination.append('"');
    }

    private static String sha256Hex(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            StringBuilder hex = new StringBuilder(64);
            for (byte octet : digest) {
                hex.append(Character.forDigit((octet >>> 4) & 0x0f, 16));
                hex.append(Character.forDigit(octet & 0x0f, 16));
            }
            return hex.toString();
        } catch (GeneralSecurityException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static LeaseVerificationException invalid(String errorCode) {
        return new LeaseVerificationException(errorCode);
    }

    private static LeaseVerificationException invalid(String errorCode, Throwable cause) {
        return new LeaseVerificationException(errorCode, cause);
    }

    private static Set<String> immutableSet(String... values) {
        return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(values)));
    }

    public static final class ExpectedBinding {
        private final String entitlementId;
        private final String pairId;
        private final String sessionId;
        private final long protocolVersion;
        private final long revocationVersion;
        private final String hostKeySha256;
        private final String androidKeySha256;
        private final String channelTranscriptSha256;
        private final long sequence;
        private final String previousLeaseSha256;
        private final String authorizationKind;
        private final boolean permanent;

        public ExpectedBinding(
                String entitlementId,
                String pairId,
                String sessionId,
                long protocolVersion,
                long revocationVersion,
                String hostKeySha256,
                String androidKeySha256,
                String channelTranscriptSha256,
                long sequence,
                String previousLeaseSha256,
                String authorizationKind,
                boolean permanent) {
            requireNonzeroPattern(HEX_128, entitlementId, "entitlementId");
            requireNonzeroPattern(HEX_128, pairId, "pairId");
            requireNonzeroPattern(HEX_128, sessionId, "sessionId");
            requireNonzeroPattern(
                    SHA256_HEX, hostKeySha256, "hostKeySha256");
            requireNonzeroPattern(
                    SHA256_HEX, androidKeySha256, "androidKeySha256");
            requireNonzeroPattern(
                    SHA256_HEX,
                    channelTranscriptSha256,
                    "channelTranscriptSha256");
            if (!previousLeaseSha256Valid(
                    previousLeaseSha256, sequence)) {
                throw new IllegalArgumentException(
                        "previousLeaseSha256 is invalid");
            }
            if (protocolVersion != PROTOCOL_VERSION
                    || revocationVersion <= 0L || sequence < 0L
                    || !isAuthorizationKind(authorizationKind)
                    || permanent != "permanent".equals(
                    authorizationKind)) {
                throw new IllegalArgumentException("expected numeric binding is invalid");
            }
            this.entitlementId = entitlementId;
            this.pairId = pairId;
            this.sessionId = sessionId;
            this.protocolVersion = protocolVersion;
            this.revocationVersion = revocationVersion;
            this.hostKeySha256 = hostKeySha256;
            this.androidKeySha256 = androidKeySha256;
            this.channelTranscriptSha256 = channelTranscriptSha256;
            this.sequence = sequence;
            this.previousLeaseSha256 = previousLeaseSha256;
            this.authorizationKind = authorizationKind;
            this.permanent = permanent;
        }

        private boolean matches(Map<String, Object> claims)
                throws LeaseVerificationException {
            return entitlementId.equals(stringClaim(claims, "sub"))
                    && pairId.equals(stringClaim(claims, "pid"))
                    && sessionId.equals(stringClaim(claims, "sid"))
                    && protocolVersion == integerClaim(claims, "pv")
                    && revocationVersion == integerClaim(claims, "rv")
                    && hostKeySha256.equals(stringClaim(claims, "hkh"))
                    && androidKeySha256.equals(stringClaim(claims, "akh"))
                    && channelTranscriptSha256.equals(stringClaim(claims, "cbh"))
                    && sequence == integerClaim(claims, "seq")
                    && previousLeaseSha256.equals(stringClaim(claims, "pth"))
                    && authorizationKind.equals(
                    stringClaim(claims, "authorization_kind"))
                    && permanent == booleanClaim(
                    claims, "is_permanent");
        }
    }

    public static final class VerifiedLease {
        private final String tokenSha256;
        private final String entitlementId;
        private final String pairId;
        private final String sessionId;
        private final long protocolVersion;
        private final long revocationVersion;
        private final String hostKeySha256;
        private final String androidKeySha256;
        private final String channelTranscriptSha256;
        private final String previousLeaseSha256;
        private final long sequence;
        private final String authorizationKind;
        private final boolean permanent;
        private final long remainingSeconds;
        private final long issuedAtEpochSeconds;
        private final long notBeforeEpochSeconds;
        private final long expiresAtEpochSeconds;
        private final long notBeforeMonotonicNanos;
        private final long expiresAtMonotonicNanos;

        private VerifiedLease(
                String tokenSha256,
                String entitlementId,
                String pairId,
                String sessionId,
                long protocolVersion,
                long revocationVersion,
                String hostKeySha256,
                String androidKeySha256,
                String channelTranscriptSha256,
                String previousLeaseSha256,
                long sequence,
                String authorizationKind,
                boolean permanent,
                long remainingSeconds,
                long issuedAtEpochSeconds,
                long notBeforeEpochSeconds,
                long expiresAtEpochSeconds,
                long notBeforeMonotonicNanos,
                long expiresAtMonotonicNanos) {
            this.tokenSha256 = tokenSha256;
            this.entitlementId = entitlementId;
            this.pairId = pairId;
            this.sessionId = sessionId;
            this.protocolVersion = protocolVersion;
            this.revocationVersion = revocationVersion;
            this.hostKeySha256 = hostKeySha256;
            this.androidKeySha256 = androidKeySha256;
            this.channelTranscriptSha256 = channelTranscriptSha256;
            this.previousLeaseSha256 = previousLeaseSha256;
            this.sequence = sequence;
            this.authorizationKind = authorizationKind;
            this.permanent = permanent;
            this.remainingSeconds = remainingSeconds;
            this.issuedAtEpochSeconds = issuedAtEpochSeconds;
            this.notBeforeEpochSeconds = notBeforeEpochSeconds;
            this.expiresAtEpochSeconds = expiresAtEpochSeconds;
            this.notBeforeMonotonicNanos = notBeforeMonotonicNanos;
            this.expiresAtMonotonicNanos = expiresAtMonotonicNanos;
        }

        public String tokenSha256() { return tokenSha256; }
        public String entitlementId() { return entitlementId; }
        public String pairId() { return pairId; }
        public String sessionId() { return sessionId; }
        public long protocolVersion() { return protocolVersion; }
        public long revocationVersion() { return revocationVersion; }
        public String hostKeySha256() { return hostKeySha256; }
        public String androidKeySha256() { return androidKeySha256; }
        public String channelTranscriptSha256() { return channelTranscriptSha256; }
        public String previousLeaseSha256() { return previousLeaseSha256; }
        public long sequence() { return sequence; }
        public String authorizationKind() { return authorizationKind; }
        public boolean permanent() { return permanent; }
        public long remainingSeconds() { return remainingSeconds; }
        public long issuedAtEpochSeconds() { return issuedAtEpochSeconds; }
        public long notBeforeEpochSeconds() { return notBeforeEpochSeconds; }
        public long expiresAtEpochSeconds() { return expiresAtEpochSeconds; }
        public long notBeforeMonotonicNanos() { return notBeforeMonotonicNanos; }
        public long expiresAtMonotonicNanos() { return expiresAtMonotonicNanos; }

        /**
         * Anchors an exactly contiguous signed renewal to the already
         * verified monotonic end of its predecessor.
         *
         * <p>Each server timestamp is expressed in whole epoch seconds. If
         * every response is independently mapped at its receipt time, the
         * sub-second receipt phase can manufacture a short local gap or
         * overlap even when the signed chain states
         * {@code next.nbf == previous.exp}. This method normalizes only that
         * mapping skew. It never changes a signed claim and never moves the
         * independently verified expiry later.</p>
         */
        VerifiedLease alignContiguousRenewalAfter(VerifiedLease previous)
                throws LeaseVerificationException {
            if (previous == null
                    || notBeforeEpochSeconds
                    != previous.expiresAtEpochSeconds) {
                return this;
            }
            if (!isImmediateSuccessorOf(previous)) {
                throw invalid(
                        "usage_lease_contiguous_renewal_chain_invalid");
            }
            try {
                long signedDurationSeconds = Math.subtractExact(
                        expiresAtEpochSeconds,
                        notBeforeEpochSeconds);
                long signedDurationNanos = Math.multiplyExact(
                        signedDurationSeconds, NANOS_PER_SECOND);
                long anchoredExpiresAt = Math.addExact(
                        previous.expiresAtMonotonicNanos,
                        signedDurationNanos);
                long boundedExpiresAt = earlierDeadline(
                        anchoredExpiresAt,
                        expiresAtMonotonicNanos);
                if (!isStrictlyAfter(
                        boundedExpiresAt,
                        previous.expiresAtMonotonicNanos)) {
                    throw invalid(
                            "usage_lease_contiguous_renewal_window_invalid");
                }
                return new VerifiedLease(
                        tokenSha256,
                        entitlementId,
                        pairId,
                        sessionId,
                        protocolVersion,
                        revocationVersion,
                        hostKeySha256,
                        androidKeySha256,
                        channelTranscriptSha256,
                        previousLeaseSha256,
                        sequence,
                        authorizationKind,
                        permanent,
                        remainingSeconds,
                        issuedAtEpochSeconds,
                        notBeforeEpochSeconds,
                        expiresAtEpochSeconds,
                        previous.expiresAtMonotonicNanos,
                        boundedExpiresAt);
            } catch (ArithmeticException overflow) {
                throw invalid(
                        "usage_lease_contiguous_renewal_deadline_overflow",
                        overflow);
            }
        }

        private boolean isImmediateSuccessorOf(VerifiedLease previous) {
            return previous.sequence != Long.MAX_VALUE
                    && sequence == previous.sequence + 1L
                    && previous.tokenSha256.equals(previousLeaseSha256)
                    && entitlementId.equals(previous.entitlementId)
                    && pairId.equals(previous.pairId)
                    && sessionId.equals(previous.sessionId)
                    && protocolVersion == previous.protocolVersion
                    && revocationVersion == previous.revocationVersion
                    && hostKeySha256.equals(previous.hostKeySha256)
                    && androidKeySha256.equals(previous.androidKeySha256)
                    && channelTranscriptSha256.equals(
                    previous.channelTranscriptSha256)
                    && authorizationKind.equals(previous.authorizationKind)
                    && permanent == previous.permanent;
        }

        private static long earlierDeadline(long first, long second) {
            return isStrictlyAfter(first, second) ? second : first;
        }

        private static boolean isStrictlyAfter(long value, long reference) {
            return value - reference > 0L;
        }
    }

    public static final class LeaseVerificationException extends GeneralSecurityException {
        LeaseVerificationException(String message) {
            super(message);
        }

        LeaseVerificationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static final class TokenSegments {
        final byte[] headerBytes;
        final byte[] payloadBytes;
        final byte[] signatureBytes;
        final byte[] signingInput;

        TokenSegments(
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

    private static void requireNonzeroPattern(
            Pattern pattern, String value, String name) {
        if (!matchesNonzero(pattern, value)) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }

    private static boolean matchesNonzero(Pattern pattern, String value) {
        return value != null
                && pattern.matcher(value).matches()
                && containsNonzero(value);
    }

    private static boolean previousLeaseSha256Valid(
            String value, long sequence) {
        if (value == null || !SHA256_HEX.matcher(value).matches()) {
            return false;
        }
        return sequence == 0L
                ? EMPTY_PREVIOUS_LEASE_SHA256.equals(value)
                : containsNonzero(value);
    }

    private static boolean containsNonzero(String value) {
        for (int index = 0; index < value.length(); index++) {
            if (value.charAt(index) != '0') return true;
        }
        return false;
    }

    /** Minimal parser for canonical flat JSON objects containing scalar values. */
    private static final class JsonObjectParser {
        private final String source;
        private int offset;

        JsonObjectParser(String source) {
            this.source = source;
        }

        Map<String, Object> parse() {
            skipWhitespace();
            require('{');
            Map<String, Object> values = new LinkedHashMap<>();
            skipWhitespace();
            if (consume('}')) {
                requireEnd();
                return Collections.unmodifiableMap(values);
            }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                require(':');
                skipWhitespace();
                char token = peek();
                Object value = token == '"'
                        ? parseString()
                        : (token == 't' || token == 'f')
                        ? parseBoolean()
                        : parseInteger();
                if (values.put(key, value) != null) {
                    throw new IllegalArgumentException("duplicate JSON key");
                }
                skipWhitespace();
                if (consume('}')) break;
                require(',');
            }
            requireEnd();
            return Collections.unmodifiableMap(values);
        }

        private String parseString() {
            require('"');
            StringBuilder value = new StringBuilder();
            while (offset < source.length()) {
                char character = source.charAt(offset++);
                if (character == '"') return value.toString();
                if (character < 0x20) throw new IllegalArgumentException("control in JSON string");
                if (character != '\\') {
                    value.append(character);
                    continue;
                }
                if (offset >= source.length()) throw new IllegalArgumentException("truncated escape");
                appendEscape(value, source.charAt(offset++));
            }
            throw new IllegalArgumentException("unterminated JSON string");
        }

        private void appendEscape(StringBuilder value, char escape) {
            switch (escape) {
                case '"': value.append('"'); break;
                case '\\': value.append('\\'); break;
                case '/': value.append('/'); break;
                case 'b': value.append('\b'); break;
                case 'f': value.append('\f'); break;
                case 'n': value.append('\n'); break;
                case 'r': value.append('\r'); break;
                case 't': value.append('\t'); break;
                case 'u': value.append(parseUnicodeEscape()); break;
                default: throw new IllegalArgumentException("invalid JSON escape");
            }
        }

        private char parseUnicodeEscape() {
            if (offset + 4 > source.length()) {
                throw new IllegalArgumentException("truncated unicode escape");
            }
            int value = 0;
            for (int index = 0; index < 4; index++) {
                int digit = Character.digit(source.charAt(offset++), 16);
                if (digit < 0) throw new IllegalArgumentException("invalid unicode escape");
                value = (value << 4) | digit;
            }
            return (char) value;
        }

        private Long parseInteger() {
            int start = offset;
            if (consume('-') && offset >= source.length()) {
                throw new IllegalArgumentException("truncated JSON number");
            }
            if (consume('0')) {
                if (offset < source.length() && Character.isDigit(source.charAt(offset))) {
                    throw new IllegalArgumentException("leading zero in JSON number");
                }
            } else {
                if (offset >= source.length()
                        || source.charAt(offset) < '1' || source.charAt(offset) > '9') {
                    throw new IllegalArgumentException("invalid JSON number");
                }
                while (offset < source.length()
                        && source.charAt(offset) >= '0' && source.charAt(offset) <= '9') {
                    offset++;
                }
            }
            if (offset < source.length()) {
                char suffix = source.charAt(offset);
                if (suffix == '.' || suffix == 'e' || suffix == 'E' || suffix == '+') {
                    throw new IllegalArgumentException("non-integer JSON number");
                }
            }
            return Long.parseLong(source.substring(start, offset));
        }

        private Boolean parseBoolean() {
            if (source.startsWith("true", offset)) {
                offset += 4;
                return Boolean.TRUE;
            }
            if (source.startsWith("false", offset)) {
                offset += 5;
                return Boolean.FALSE;
            }
            throw new IllegalArgumentException("invalid JSON boolean");
        }

        private void skipWhitespace() {
            while (offset < source.length()
                    && Character.isWhitespace(source.charAt(offset))) {
                offset++;
            }
        }

        private char peek() {
            if (offset >= source.length()) throw new IllegalArgumentException("truncated JSON");
            return source.charAt(offset);
        }

        private boolean consume(char expected) {
            if (offset < source.length() && source.charAt(offset) == expected) {
                offset++;
                return true;
            }
            return false;
        }

        private void require(char expected) {
            if (!consume(expected)) throw new IllegalArgumentException("unexpected JSON token");
        }

        private void requireEnd() {
            skipWhitespace();
            if (offset != source.length()) throw new IllegalArgumentException("trailing JSON data");
        }
    }
}
