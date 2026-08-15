package com.visionforge.inferencebenchmark;

/** Dependency-free privacy contract for the mobile log's single write boundary. */
public final class MobileLogSanitizerSelfTest {
    private MobileLogSanitizerSelfTest() {
    }

    public static void main(String[] arguments) {
        run();
        System.out.println("MOBILE_LOG_SANITIZER_OK");
    }

    static void run() {
        redactsEverySensitiveCredentialFamily();
        preservesOperationalDiagnostics();
        remainsNullSafeAndIdempotent();
    }

    private static void redactsEverySensitiveCredentialFamily() {
        String[] secrets = {
                "CARD-7A9B-2C4D",
                "CARDSECRET-9911",
                "ZH-CARD-5511",
                "access-token-value-77",
                "authorization-bearer-88",
                "authorization-basic-99",
                "standalone-bearer-101",
                "cookie-session-202",
                "cookie-csrf-303",
                "ticket-value-404",
                "lease-digest-505",
                "signature-value-606",
                "proof-value-707",
                "nonce-value-808",
                "session-value-909",
                "fingerprint-value-1001",
                "channel-binding-1102",
                "pair-id-1203",
                "entitlement-id-1304",
                "path-session-1405",
                "challenge-token-1506",
                "usage-session-1607",
                "key-fingerprint-1708",
                "signature-base64-1809",
                "VFD2-23456-789AB-CDEFG-HJKLM-NPQRS-TUVWX",
                "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzZXNzaW9uLTEyMyJ9."
                        + "c2lnbmF0dXJlLWJ5dGVzLTEyMzQ1Ng"
        };
        String input = String.join("\n",
                "card_code=" + secrets[0],
                "card secret " + secrets[1],
                "\u5361\u5bc6=" + secrets[2],
                "{\"accessToken\":\"" + secrets[3] + "\"}",
                "Authorization: Bearer " + secrets[4],
                "authorization=Basic " + secrets[5],
                "credential=Bearer " + secrets[6],
                "Cookie: session=" + secrets[7] + "; csrf=" + secrets[8],
                "usage_ticket=" + secrets[9],
                "leaseSha256=" + secrets[10],
                "hostSignature=" + secrets[11],
                "deviceProof=" + secrets[12],
                "requestNonce=" + secrets[13],
                "sessionId=" + secrets[14],
                "deviceFingerprint=" + secrets[15],
                "channelBinding=" + secrets[16],
                "pairId=" + secrets[17],
                "entitlement_id=" + secrets[18],
                "request=https://example.invalid/usage-sessions/"
                        + secrets[19] + "/heartbeat",
                "challengeToken=" + secrets[20],
                "usageSessionId=" + secrets[21],
                "hostKeyFingerprintSha256=" + secrets[22],
                "androidSignatureBase64=" + secrets[23],
                "issued_value=" + secrets[24],
                "opaque_value=" + secrets[25]);

        String sanitized = MobileLogSanitizer.sanitize(input);
        for (String secret : secrets) {
            require(!sanitized.contains(secret), "secret leaked: " + secret);
        }
        require(sanitized.contains(MobileLogSanitizer.REDACTED),
                "redaction marker missing");
    }

    private static void preservesOperationalDiagnostics() {
        String ordinary = "status=ready backend=QNN failure_count=0 "
                + "card_secret_persisted=false host_session_persisted=false "
                + "formal_lease_restored=false token_count=4 "
                + "proof verification failed";
        require(ordinary.equals(MobileLogSanitizer.sanitize(ordinary)),
                "non-secret diagnostics changed");
    }

    private static void remainsNullSafeAndIdempotent() {
        require("".equals(MobileLogSanitizer.sanitize(null)),
                "null must become an empty field");
        require("".equals(MobileLogSanitizer.sanitize("")),
                "empty value changed");
        String once = MobileLogSanitizer.sanitize(
                "token=token-value-1506 Cookie: session=cookie-value-1607");
        require(once.equals(MobileLogSanitizer.sanitize(once)),
                "sanitization must be idempotent");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
