package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/** Dependency-free regression contract for strict RS256 lease verification. */
public final class DualMachineUsageLeaseVerifierSelfTest {
    private static final long SECOND = 1_000_000_000L;

    private DualMachineUsageLeaseVerifierSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        KeyPair signingKey = DualMachineUsageLeaseSelfTestSupport.rsaKeyPair(3072);
        verifiesValidLeaseAndMonotonicMapping(signingKey);
        verifiesFutureLeaseRemainsFuture(signingKey);
        alignsOnlyAContiguousVerifiedRenewal(signingKey);
        acceptsSmallServerClockAheadWithoutExtendingTtl(signingKey);
        verifiesLegacyBalanceAuthorizationClaims(signingKey);
        verifiesPermanentAuthorizationClaims(signingKey);
        rejectsSignatureHeaderKeyAndEncodingTampering(signingKey);
        rejectsClaimTypeBindingAndJtiTampering(signingKey);
        rejectsZeroIdentityAndDigestBindings(signingKey);
        rejectsZeroExpectedBindings();
        rejectsExpiredAndOversizedTtl(signingKey);
        rejectsNonCanonicalJsonAndWeakKey(signingKey);
        System.out.println("DUAL_MACHINE_USAGE_LEASE_VERIFIER_SELF_TEST_OK");
    }

    private static void verifiesValidLeaseAndMonotonicMapping(KeyPair keyPair)
            throws Exception {
        DualMachineUsageLeaseSelfTestSupport.LeaseData data =
                DualMachineUsageLeaseSelfTestSupport.initial(100L, 100L, 105L);
        String token = DualMachineUsageLeaseSelfTestSupport.token(keyPair, data);
        DualMachineUsageLeaseVerifier verifier =
                new DualMachineUsageLeaseVerifier(keyPair.getPublic());
        DualMachineUsageLeaseVerifier.VerifiedLease lease = verifier.verify(
                token,
                DualMachineUsageLeaseSelfTestSupport.expected(data),
                100L,
                7L * SECOND);

        require(lease.sequence() == 0L);
        require(lease.authorizationKind().equals("day"));
        require(!lease.permanent());
        require(lease.notBeforeMonotonicNanos() == 7L * SECOND);
        require(lease.expiresAtMonotonicNanos() == 12L * SECOND);
        require(lease.tokenSha256().equals(
                DualMachineUsageLeaseSelfTestSupport.sha256Hex(
                        token.getBytes(StandardCharsets.US_ASCII))));
        require(verifier.expectedKeyId().length() == 16);
        require(verifier.maximumTtlSeconds() == 5);
    }

    private static void verifiesPermanentAuthorizationClaims(KeyPair keyPair)
            throws Exception {
        DualMachineUsageLeaseSelfTestSupport.LeaseData data =
                DualMachineUsageLeaseSelfTestSupport.initial(
                        100L, 100L, 105L);
        data.authorizationKind = "permanent";
        data.permanent = true;
        data.remainingSeconds = 0L;
        DualMachineUsageLeaseVerifier.VerifiedLease lease =
                new DualMachineUsageLeaseVerifier(keyPair.getPublic()).verify(
                        DualMachineUsageLeaseSelfTestSupport.token(keyPair, data),
                        DualMachineUsageLeaseSelfTestSupport.expected(data),
                        100L,
                        0L);
        require(lease.authorizationKind().equals("permanent"));
        require(lease.permanent());
        require(lease.remainingSeconds() == 0L);

        Map<String, Object> mismatched =
                DualMachineUsageLeaseSelfTestSupport.claims(data);
        mismatched.put("is_permanent", false);
        DualMachineUsageLeaseSelfTestSupport.refreshJti(mismatched);
        expectRejected(() -> new DualMachineUsageLeaseVerifier(
                keyPair.getPublic()).verify(
                DualMachineUsageLeaseSelfTestSupport.token(
                        keyPair,
                        DualMachineUsageLeaseSelfTestSupport.header(keyPair),
                        mismatched),
                DualMachineUsageLeaseSelfTestSupport.expected(data),
                100L,
                0L));
    }

    private static void verifiesLegacyBalanceAuthorizationClaims(KeyPair keyPair)
            throws Exception {
        DualMachineUsageLeaseSelfTestSupport.LeaseData data =
                DualMachineUsageLeaseSelfTestSupport.initial(
                        100L, 100L, 105L);
        data.authorizationKind = "legacy_balance";
        data.permanent = false;
        data.remainingSeconds = 900L;
        DualMachineUsageLeaseVerifier.VerifiedLease lease =
                new DualMachineUsageLeaseVerifier(keyPair.getPublic()).verify(
                        DualMachineUsageLeaseSelfTestSupport.token(keyPair, data),
                        DualMachineUsageLeaseSelfTestSupport.expected(data),
                        100L,
                        0L);
        require(lease.authorizationKind().equals("legacy_balance"));
        require(!lease.permanent());
        require(lease.remainingSeconds() == 900L);
    }

    private static void verifiesFutureLeaseRemainsFuture(KeyPair keyPair)
            throws Exception {
        DualMachineUsageLeaseSelfTestSupport.LeaseData data =
                DualMachineUsageLeaseSelfTestSupport.initial(100L, 103L, 108L);
        DualMachineUsageLeaseVerifier.VerifiedLease lease =
                new DualMachineUsageLeaseVerifier(keyPair.getPublic()).verify(
                        DualMachineUsageLeaseSelfTestSupport.token(keyPair, data),
                        DualMachineUsageLeaseSelfTestSupport.expected(data),
                        100L,
                        SECOND);
        require(lease.notBeforeMonotonicNanos() == 4L * SECOND);
        require(lease.expiresAtMonotonicNanos() == 9L * SECOND);
    }

    private static void alignsOnlyAContiguousVerifiedRenewal(
            KeyPair keyPair) throws Exception {
        DualMachineUsageLeaseVerifier verifier =
                new DualMachineUsageLeaseVerifier(keyPair.getPublic());
        DualMachineUsageLeaseSelfTestSupport.LeaseData initial =
                DualMachineUsageLeaseSelfTestSupport.initial(
                        100L, 100L, 105L);
        DualMachineUsageLeaseVerifier.VerifiedLease previous =
                verifier.verify(
                        DualMachineUsageLeaseSelfTestSupport.token(
                                keyPair, initial),
                        DualMachineUsageLeaseSelfTestSupport.expected(
                                initial),
                        100L,
                        0L);

        DualMachineUsageLeaseSelfTestSupport.LeaseData contiguous =
                DualMachineUsageLeaseSelfTestSupport.initial(
                        101L, 105L, 110L);
        contiguous.sequence = 1L;
        contiguous.previousLeaseSha256 = previous.tokenSha256();
        DualMachineUsageLeaseVerifier.VerifiedLease independentlyMapped =
                verifier.verify(
                        DualMachineUsageLeaseSelfTestSupport.token(
                                keyPair, contiguous),
                        DualMachineUsageLeaseSelfTestSupport.expected(
                                contiguous),
                        101L,
                        3L * SECOND);
        require(independentlyMapped.notBeforeMonotonicNanos()
                == 7L * SECOND);
        require(independentlyMapped.expiresAtMonotonicNanos()
                == 12L * SECOND);

        DualMachineUsageLeaseVerifier.VerifiedLease aligned =
                independentlyMapped.alignContiguousRenewalAfter(previous);
        require(aligned.notBeforeMonotonicNanos() == 5L * SECOND);
        require(aligned.expiresAtMonotonicNanos() == 10L * SECOND);
        require(aligned.expiresAtMonotonicNanos()
                <= independentlyMapped.expiresAtMonotonicNanos());
        require(aligned.notBeforeEpochSeconds() == 105L);
        require(aligned.expiresAtEpochSeconds() == 110L);
        require(aligned.tokenSha256().equals(
                independentlyMapped.tokenSha256()));
        DualMachineUsageLeaseVerifier.VerifiedLease repeatedAlignment =
                independentlyMapped.alignContiguousRenewalAfter(previous);
        require(repeatedAlignment.notBeforeMonotonicNanos()
                == aligned.notBeforeMonotonicNanos());
        require(repeatedAlignment.expiresAtMonotonicNanos()
                == aligned.expiresAtMonotonicNanos());

        DualMachineUsageLeaseVerifier.VerifiedLease earlierMapped =
                verifier.verify(
                        DualMachineUsageLeaseSelfTestSupport.token(
                                keyPair, contiguous),
                        DualMachineUsageLeaseSelfTestSupport.expected(
                                contiguous),
                        104L,
                        2L * SECOND);
        require(earlierMapped.notBeforeMonotonicNanos()
                == 3L * SECOND);
        require(earlierMapped.expiresAtMonotonicNanos()
                == 8L * SECOND);
        DualMachineUsageLeaseVerifier.VerifiedLease earlierAligned =
                earlierMapped.alignContiguousRenewalAfter(previous);
        require(earlierAligned.notBeforeMonotonicNanos()
                == previous.expiresAtMonotonicNanos());
        require(earlierAligned.expiresAtMonotonicNanos()
                == earlierMapped.expiresAtMonotonicNanos());
        require(earlierAligned.expiresAtMonotonicNanos()
                <= earlierMapped.expiresAtMonotonicNanos());

        DualMachineUsageLeaseVerifier.VerifiedLease collapsedMapped =
                verifier.verify(
                        DualMachineUsageLeaseSelfTestSupport.token(
                                keyPair, contiguous),
                        DualMachineUsageLeaseSelfTestSupport.expected(
                                contiguous),
                        109L,
                        SECOND);
        require(collapsedMapped.expiresAtMonotonicNanos()
                < previous.expiresAtMonotonicNanos());
        expectRejected(() ->
                collapsedMapped.alignContiguousRenewalAfter(previous));

        DualMachineUsageLeaseVerifier.VerifiedLease lateButUsable =
                verifier.verify(
                        DualMachineUsageLeaseSelfTestSupport.token(
                                keyPair, contiguous),
                        DualMachineUsageLeaseSelfTestSupport.expected(
                                contiguous),
                        108L,
                        8L * SECOND)
                        .alignContiguousRenewalAfter(previous);
        require(lateButUsable.notBeforeMonotonicNanos()
                == 5L * SECOND);
        require(lateButUsable.expiresAtMonotonicNanos()
                == 10L * SECOND);
        AtomicLong lateClock = new AtomicLong();
        DualMachineUsageLeaseGate lateGate =
                new DualMachineUsageLeaseGate(lateClock::get);
        lateGate.beginSession();
        require(lateGate.install(previous)
                == DualMachineUsageLeaseGate.InstallResult
                .CURRENT_INSTALLED);
        lateClock.set(8L * SECOND);
        require(lateGate.install(lateButUsable)
                == DualMachineUsageLeaseGate.InstallResult
                .CURRENT_INSTALLED);
        require(lateGate.isOpen());

        DualMachineUsageLeaseVerifier.VerifiedLease alreadyExpired =
                verifier.verify(
                        DualMachineUsageLeaseSelfTestSupport.token(
                                keyPair, contiguous),
                        DualMachineUsageLeaseSelfTestSupport.expected(
                                contiguous),
                        109L,
                        10L * SECOND)
                        .alignContiguousRenewalAfter(previous);
        require(alreadyExpired.expiresAtMonotonicNanos()
                == 10L * SECOND);
        AtomicLong expiredClock = new AtomicLong();
        DualMachineUsageLeaseGate expiredGate =
                new DualMachineUsageLeaseGate(expiredClock::get);
        expiredGate.beginSession();
        expiredGate.install(previous);
        expiredClock.set(10L * SECOND);
        expectGateRejected(() -> expiredGate.install(alreadyExpired));

        DualMachineUsageLeaseSelfTestSupport.LeaseData genuineGap =
                DualMachineUsageLeaseSelfTestSupport.initial(
                        106L, 107L, 112L);
        genuineGap.sequence = 1L;
        genuineGap.previousLeaseSha256 = previous.tokenSha256();
        DualMachineUsageLeaseVerifier.VerifiedLease gapLease =
                verifier.verify(
                        DualMachineUsageLeaseSelfTestSupport.token(
                                keyPair, genuineGap),
                        DualMachineUsageLeaseSelfTestSupport.expected(
                                genuineGap),
                        106L,
                        6L * SECOND);
        require(gapLease.alignContiguousRenewalAfter(previous) == gapLease);
        require(gapLease.notBeforeMonotonicNanos() == 7L * SECOND);

        DualMachineUsageLeaseSelfTestSupport.LeaseData wrongBinding =
                DualMachineUsageLeaseSelfTestSupport.initial(
                        101L, 105L, 110L);
        wrongBinding.sequence = 1L;
        wrongBinding.previousLeaseSha256 = previous.tokenSha256();
        wrongBinding.channelBindingSha256 = "a".repeat(64);
        DualMachineUsageLeaseVerifier.VerifiedLease mismatched =
                verifier.verify(
                        DualMachineUsageLeaseSelfTestSupport.token(
                                keyPair, wrongBinding),
                        DualMachineUsageLeaseSelfTestSupport.expected(
                                wrongBinding),
                        101L,
                        3L * SECOND);
        expectRejected(() ->
                mismatched.alignContiguousRenewalAfter(previous));
    }

    private static void acceptsSmallServerClockAheadWithoutExtendingTtl(
            KeyPair keyPair) throws Exception {
        DualMachineUsageLeaseSelfTestSupport.LeaseData data =
                DualMachineUsageLeaseSelfTestSupport.initial(101L, 101L, 106L);
        DualMachineUsageLeaseVerifier.VerifiedLease lease =
                new DualMachineUsageLeaseVerifier(keyPair.getPublic()).verify(
                        DualMachineUsageLeaseSelfTestSupport.token(keyPair, data),
                        DualMachineUsageLeaseSelfTestSupport.expected(data),
                        100L,
                        SECOND);
        require(lease.notBeforeMonotonicNanos() == SECOND);
        require(lease.expiresAtMonotonicNanos() == 6L * SECOND);
    }

    private static void rejectsSignatureHeaderKeyAndEncodingTampering(KeyPair keyPair)
            throws Exception {
        DualMachineUsageLeaseSelfTestSupport.LeaseData data =
                DualMachineUsageLeaseSelfTestSupport.initial(100L, 100L, 105L);
        DualMachineUsageLeaseVerifier verifier =
                new DualMachineUsageLeaseVerifier(keyPair.getPublic());
        String valid = DualMachineUsageLeaseSelfTestSupport.token(keyPair, data);
        expectRejected(() -> verifier.verify(
                DualMachineUsageLeaseSelfTestSupport.corruptSignature(valid),
                DualMachineUsageLeaseSelfTestSupport.expected(data), 100L, 0L));

        Map<String, Object> wrongAlgorithm =
                DualMachineUsageLeaseSelfTestSupport.header(keyPair);
        wrongAlgorithm.put("alg", "HS256");
        expectRejected(() -> verifier.verify(
                DualMachineUsageLeaseSelfTestSupport.token(
                        keyPair, wrongAlgorithm,
                        DualMachineUsageLeaseSelfTestSupport.claims(data)),
                DualMachineUsageLeaseSelfTestSupport.expected(data), 100L, 0L));

        Map<String, Object> wrongKid =
                DualMachineUsageLeaseSelfTestSupport.header(keyPair);
        wrongKid.put("kid", "0".repeat(16));
        expectRejected(() -> verifier.verify(
                DualMachineUsageLeaseSelfTestSupport.token(
                        keyPair, wrongKid,
                        DualMachineUsageLeaseSelfTestSupport.claims(data)),
                DualMachineUsageLeaseSelfTestSupport.expected(data), 100L, 0L));

        KeyPair otherKey = DualMachineUsageLeaseSelfTestSupport.rsaKeyPair(3072);
        DualMachineUsageLeaseVerifier otherVerifier =
                new DualMachineUsageLeaseVerifier(otherKey.getPublic());
        expectRejected(() -> otherVerifier.verify(
                valid, DualMachineUsageLeaseSelfTestSupport.expected(data), 100L, 0L));

        int firstSeparator = valid.indexOf('.');
        String padded = valid.substring(0, firstSeparator) + "="
                + valid.substring(firstSeparator);
        expectRejected(() -> verifier.verify(
                padded, DualMachineUsageLeaseSelfTestSupport.expected(data), 100L, 0L));
        expectRejected(() -> verifier.verify(
                valid + ".extra",
                DualMachineUsageLeaseSelfTestSupport.expected(data), 100L, 0L));
        expectRejected(() -> verifier.verify(
                "A".repeat(DualMachineUsageLeaseVerifier.MAXIMUM_TOKEN_CHARACTERS + 1),
                DualMachineUsageLeaseSelfTestSupport.expected(data), 100L, 0L));

        Map<String, Object> extraHeader =
                DualMachineUsageLeaseSelfTestSupport.header(keyPair);
        extraHeader.put("extra", "forbidden");
        expectRejected(() -> verifier.verify(
                DualMachineUsageLeaseSelfTestSupport.token(
                        keyPair, extraHeader,
                        DualMachineUsageLeaseSelfTestSupport.claims(data)),
                DualMachineUsageLeaseSelfTestSupport.expected(data), 100L, 0L));
    }

    private static void rejectsClaimTypeBindingAndJtiTampering(KeyPair keyPair)
            throws Exception {
        DualMachineUsageLeaseSelfTestSupport.LeaseData data =
                DualMachineUsageLeaseSelfTestSupport.initial(100L, 100L, 105L);
        DualMachineUsageLeaseVerifier verifier =
                new DualMachineUsageLeaseVerifier(keyPair.getPublic());

        Map<String, Object> wrongType =
                DualMachineUsageLeaseSelfTestSupport.claims(data);
        wrongType.put("seq", "0");
        DualMachineUsageLeaseSelfTestSupport.refreshJti(wrongType);
        expectRejected(() -> verifier.verify(
                DualMachineUsageLeaseSelfTestSupport.token(
                        keyPair,
                        DualMachineUsageLeaseSelfTestSupport.header(keyPair),
                        wrongType),
                DualMachineUsageLeaseSelfTestSupport.expected(data), 100L, 0L));

        DualMachineUsageLeaseSelfTestSupport.LeaseData wrongBinding =
                DualMachineUsageLeaseSelfTestSupport.initial(100L, 100L, 105L);
        wrongBinding.entitlementId = "a".repeat(32);
        expectRejected(() -> verifier.verify(
                DualMachineUsageLeaseSelfTestSupport.token(keyPair, wrongBinding),
                DualMachineUsageLeaseSelfTestSupport.expected(data), 100L, 0L));

        Map<String, Object> wrongJti =
                DualMachineUsageLeaseSelfTestSupport.claims(data);
        wrongJti.put("jti", "0".repeat(32));
        expectRejectedCode("usage_lease_string_claim_invalid", () -> verifier.verify(
                DualMachineUsageLeaseSelfTestSupport.token(
                        keyPair,
                        DualMachineUsageLeaseSelfTestSupport.header(keyPair),
                        wrongJti),
                DualMachineUsageLeaseSelfTestSupport.expected(data), 100L, 0L));

        Map<String, Object> extraClaim =
                DualMachineUsageLeaseSelfTestSupport.claims(data);
        extraClaim.put("unexpected", "value");
        expectRejected(() -> verifier.verify(
                DualMachineUsageLeaseSelfTestSupport.token(
                        keyPair,
                        DualMachineUsageLeaseSelfTestSupport.header(keyPair),
                        extraClaim),
                DualMachineUsageLeaseSelfTestSupport.expected(data), 100L, 0L));
    }

    private static void rejectsZeroIdentityAndDigestBindings(KeyPair keyPair)
            throws Exception {
        DualMachineUsageLeaseSelfTestSupport.LeaseData initial =
                DualMachineUsageLeaseSelfTestSupport.initial(
                        100L, 100L, 105L);
        DualMachineUsageLeaseVerifier verifier =
                new DualMachineUsageLeaseVerifier(keyPair.getPublic());

        expectZeroClaimRejected(keyPair, verifier, initial, "sub", 32);
        expectZeroClaimRejected(keyPair, verifier, initial, "pid", 32);
        expectZeroClaimRejected(keyPair, verifier, initial, "sid", 32);
        expectZeroClaimRejected(keyPair, verifier, initial, "hkh", 64);
        expectZeroClaimRejected(keyPair, verifier, initial, "akh", 64);
        expectZeroClaimRejected(keyPair, verifier, initial, "cbh", 64);

        DualMachineUsageLeaseSelfTestSupport.LeaseData renewal =
                DualMachineUsageLeaseSelfTestSupport.initial(
                        100L, 100L, 105L);
        renewal.sequence = 1L;
        renewal.previousLeaseSha256 = "f".repeat(64);
        expectZeroClaimRejected(keyPair, verifier, renewal, "pth", 64);

        DualMachineUsageLeaseVerifier.VerifiedLease acceptedInitial =
                verifier.verify(
                        DualMachineUsageLeaseSelfTestSupport.token(
                                keyPair, initial),
                        DualMachineUsageLeaseSelfTestSupport.expected(initial),
                        100L,
                        0L);
        require(acceptedInitial.sequence() == 0L);
        require(acceptedInitial.previousLeaseSha256().equals(
                DualMachineUsageLeaseVerifier
                        .EMPTY_PREVIOUS_LEASE_SHA256));
    }

    private static void rejectsZeroExpectedBindings() throws Exception {
        DualMachineUsageLeaseSelfTestSupport.LeaseData entitlement =
                validInitialBinding();
        entitlement.entitlementId = "0".repeat(32);
        expectIllegalArgument(() ->
                DualMachineUsageLeaseSelfTestSupport.expected(entitlement));

        DualMachineUsageLeaseSelfTestSupport.LeaseData pair =
                validInitialBinding();
        pair.pairId = "0".repeat(32);
        expectIllegalArgument(() ->
                DualMachineUsageLeaseSelfTestSupport.expected(pair));

        DualMachineUsageLeaseSelfTestSupport.LeaseData session =
                validInitialBinding();
        session.sessionId = "0".repeat(32);
        expectIllegalArgument(() ->
                DualMachineUsageLeaseSelfTestSupport.expected(session));

        DualMachineUsageLeaseSelfTestSupport.LeaseData hostKey =
                validInitialBinding();
        hostKey.hostKeySha256 = "0".repeat(64);
        expectIllegalArgument(() ->
                DualMachineUsageLeaseSelfTestSupport.expected(hostKey));

        DualMachineUsageLeaseSelfTestSupport.LeaseData androidKey =
                validInitialBinding();
        androidKey.androidKeySha256 = "0".repeat(64);
        expectIllegalArgument(() ->
                DualMachineUsageLeaseSelfTestSupport.expected(androidKey));

        DualMachineUsageLeaseSelfTestSupport.LeaseData channel =
                validInitialBinding();
        channel.channelBindingSha256 = "0".repeat(64);
        expectIllegalArgument(() ->
                DualMachineUsageLeaseSelfTestSupport.expected(channel));

        DualMachineUsageLeaseSelfTestSupport.LeaseData renewal =
                validInitialBinding();
        renewal.sequence = 1L;
        expectIllegalArgument(() ->
                DualMachineUsageLeaseSelfTestSupport.expected(renewal));
    }

    private static DualMachineUsageLeaseSelfTestSupport.LeaseData
            validInitialBinding() {
        return DualMachineUsageLeaseSelfTestSupport.initial(
                100L, 100L, 105L);
    }

    private static void expectZeroClaimRejected(
            KeyPair keyPair,
            DualMachineUsageLeaseVerifier verifier,
            DualMachineUsageLeaseSelfTestSupport.LeaseData expectedBinding,
            String claimName,
            int length) throws Exception {
        Map<String, Object> claims =
                DualMachineUsageLeaseSelfTestSupport.claims(expectedBinding);
        claims.put(claimName, "0".repeat(length));
        DualMachineUsageLeaseSelfTestSupport.refreshJti(claims);
        expectRejectedCode("usage_lease_string_claim_invalid", () ->
                verifier.verify(
                        DualMachineUsageLeaseSelfTestSupport.token(
                                keyPair,
                                DualMachineUsageLeaseSelfTestSupport.header(
                                        keyPair),
                                claims),
                        DualMachineUsageLeaseSelfTestSupport.expected(
                                expectedBinding),
                        100L,
                        0L));
    }

    private static void rejectsExpiredAndOversizedTtl(KeyPair keyPair)
            throws Exception {
        DualMachineUsageLeaseVerifier verifier =
                new DualMachineUsageLeaseVerifier(keyPair.getPublic());
        DualMachineUsageLeaseSelfTestSupport.LeaseData expired =
                DualMachineUsageLeaseSelfTestSupport.initial(95L, 95L, 100L);
        expectRejected(() -> verifier.verify(
                DualMachineUsageLeaseSelfTestSupport.token(keyPair, expired),
                DualMachineUsageLeaseSelfTestSupport.expected(expired), 100L, 0L));

        DualMachineUsageLeaseSelfTestSupport.LeaseData sixSeconds =
                DualMachineUsageLeaseSelfTestSupport.initial(100L, 100L, 106L);
        String token = DualMachineUsageLeaseSelfTestSupport.token(keyPair, sixSeconds);
        expectRejected(() -> verifier.verify(
                token, DualMachineUsageLeaseSelfTestSupport.expected(sixSeconds), 100L, 0L));
        DualMachineUsageLeaseVerifier configured =
                new DualMachineUsageLeaseVerifier(keyPair.getPublic(), 10);
        require(configured.verify(
                token,
                DualMachineUsageLeaseSelfTestSupport.expected(sixSeconds),
                100L,
                0L).expiresAtMonotonicNanos() == 6L * SECOND);

        DualMachineUsageLeaseSelfTestSupport.LeaseData futureIssued =
                DualMachineUsageLeaseSelfTestSupport.initial(
                        100L + DualMachineUsageLeaseVerifier
                                .SERVER_CLOCK_AHEAD_GRACE_SECONDS + 1L,
                        100L + DualMachineUsageLeaseVerifier
                                .SERVER_CLOCK_AHEAD_GRACE_SECONDS + 1L,
                        105L + DualMachineUsageLeaseVerifier
                                .SERVER_CLOCK_AHEAD_GRACE_SECONDS + 1L);
        expectRejected(() -> verifier.verify(
                DualMachineUsageLeaseSelfTestSupport.token(keyPair, futureIssued),
                DualMachineUsageLeaseSelfTestSupport.expected(futureIssued), 100L, 0L));
    }

    private static void rejectsNonCanonicalJsonAndWeakKey(KeyPair keyPair)
            throws Exception {
        DualMachineUsageLeaseSelfTestSupport.LeaseData data =
                DualMachineUsageLeaseSelfTestSupport.initial(100L, 100L, 105L);
        byte[] canonicalClaims = DualMachineUsageLeaseSelfTestSupport.canonicalJson(
                DualMachineUsageLeaseSelfTestSupport.claims(data));
        byte[] nonCanonicalClaims = (" " + new String(
                canonicalClaims, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
        String token = DualMachineUsageLeaseSelfTestSupport.signRaw(
                keyPair.getPrivate(),
                DualMachineUsageLeaseSelfTestSupport.canonicalJson(
                        DualMachineUsageLeaseSelfTestSupport.header(keyPair)),
                nonCanonicalClaims);
        DualMachineUsageLeaseVerifier verifier =
                new DualMachineUsageLeaseVerifier(keyPair.getPublic());
        expectRejected(() -> verifier.verify(
                token, DualMachineUsageLeaseSelfTestSupport.expected(data), 100L, 0L));

        KeyPair weakKey = DualMachineUsageLeaseSelfTestSupport.rsaKeyPair(2048);
        expectGeneralSecurity(() -> new DualMachineUsageLeaseVerifier(weakKey.getPublic()));
    }

    private static void expectRejected(CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected lease verification rejection");
        } catch (DualMachineUsageLeaseVerifier.LeaseVerificationException expected) {
            // Expected.
        }
    }

    private static void expectRejectedCode(
            String expectedCode,
            CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected lease verification rejection");
        } catch (DualMachineUsageLeaseVerifier.LeaseVerificationException expected) {
            if (!expectedCode.equals(expected.getMessage())) {
                throw new AssertionError(
                        "unexpected lease rejection code: "
                                + expected.getMessage());
            }
        }
    }

    private static void expectIllegalArgument(CheckedAction action)
            throws Exception {
        try {
            action.run();
            throw new AssertionError("expected binding rejection");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static void expectGeneralSecurity(CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected key rejection");
        } catch (java.security.GeneralSecurityException expected) {
            // Expected.
        }
    }

    private static void expectGateRejected(CheckedAction action)
            throws Exception {
        try {
            action.run();
            throw new AssertionError("expected lease gate rejection");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("usage lease verifier contract failed");
    }

    @FunctionalInterface
    private interface CheckedAction {
        void run() throws Exception;
    }
}
