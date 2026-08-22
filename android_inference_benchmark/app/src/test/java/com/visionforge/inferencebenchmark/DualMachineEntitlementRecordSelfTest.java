package com.visionforge.inferencebenchmark;

/** Dependency-free contract checks for the persisted non-secret binding. */
public final class DualMachineEntitlementRecordSelfTest {
    private static final String IDENTITY_ALIAS =
            "visionforge-dual-machine-pairing-identity";
    private static final String HOST_PUBLIC_KEY_BASE64 =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt"
                    + "6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==";
    private static final String HOST_KEY_SHA256 =
            "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3";

    private DualMachineEntitlementRecordSelfTest() {
    }

    public static void main(String[] arguments) {
        DualMachineEntitlementRecord record = new DualMachineEntitlementRecord(
                repeated('a', 32),
                repeated('b', 32),
                repeated('c', 32),
                3L,
                "active",
                2,
                7L,
                HOST_KEY_SHA256,
                HOST_PUBLIC_KEY_BASE64,
                repeated('d', 64),
                IDENTITY_ALIAS);
        check(record.hostIdentityPublicKeyDer().length == 91);
        check(record.matchesAndroidIdentity(
                IDENTITY_ALIAS,
                repeated('d', 64)));
        check(!record.matchesAndroidIdentity(
                IDENTITY_ALIAS,
                repeated('e', 64)));
        check(!record.matchesAndroidIdentity(
                "replacement-alias",
                repeated('d', 64)));
        check(!record.revoked);
        check(record.hasActivePairSecurityBinding());
        check(record.bindingRevision == 3L);
        DualMachineEntitlementRecord legacyBalance =
                new DualMachineEntitlementRecord(
                        repeated('c', 32), repeated('d', 32), 2, 7L,
                        HOST_KEY_SHA256, HOST_PUBLIC_KEY_BASE64,
                        repeated('e', 64), IDENTITY_ALIAS,
                        "legacy_balance", "legacy_balance", false, false);
        check(legacyBalance.authorizationKind.equals("legacy_balance"));
        check(!legacyBalance.permanent);
        check(!legacyBalance.hasActivePairSecurityBinding());
        DualMachineEntitlementRecord revoked =
                record.withRevocationVersion(8L);
        check(revoked.revoked);
        check(revoked.revocationVersion == 8L);
        expectRejected(() -> record.withRevocationVersion(6L));
        expectRejected(() -> new DualMachineEntitlementRecord(
                repeated('a', 32), repeated('b', 32), "", 1L, "active",
                2, 7L, HOST_KEY_SHA256, HOST_PUBLIC_KEY_BASE64,
                repeated('d', 64), "valid-alias",
                "day", "day", false, false));
        expectRejected(() -> new DualMachineEntitlementRecord(
                repeated('a', 32), repeated('b', 32),
                repeated('c', 32), 0L, "active",
                2, 7L, HOST_KEY_SHA256, HOST_PUBLIC_KEY_BASE64,
                repeated('d', 64), "valid-alias",
                "day", "day", false, false));
        expectRejected(() -> new DualMachineEntitlementRecord(
                repeated('a', 32), repeated('b', 32), 1, 7L,
                HOST_KEY_SHA256, HOST_PUBLIC_KEY_BASE64,
                repeated('d', 64), "valid-alias"));
        expectRejected(() -> new DualMachineEntitlementRecord(
                repeated('a', 32), repeated('b', 32), 2, 0L,
                HOST_KEY_SHA256, HOST_PUBLIC_KEY_BASE64,
                repeated('d', 64), "valid-alias"));
        expectRejected(() -> new DualMachineEntitlementRecord(
                repeated('A', 32), repeated('b', 32), 2, 7L,
                HOST_KEY_SHA256, HOST_PUBLIC_KEY_BASE64,
                repeated('d', 64), "valid-alias"));
        expectRejected(() -> new DualMachineEntitlementRecord(
                repeated('0', 32), repeated('b', 32), 2, 7L,
                HOST_KEY_SHA256, HOST_PUBLIC_KEY_BASE64,
                repeated('d', 64), "valid-alias"));
        expectRejected(() -> new DualMachineEntitlementRecord(
                repeated('a', 32), repeated('0', 32), 2, 7L,
                HOST_KEY_SHA256, HOST_PUBLIC_KEY_BASE64,
                repeated('d', 64), "valid-alias"));
        expectRejected(() -> new DualMachineEntitlementRecord(
                repeated('a', 32), repeated('b', 32), 2, 7L,
                HOST_KEY_SHA256, HOST_PUBLIC_KEY_BASE64,
                repeated('0', 64), "valid-alias"));
        expectRejected(() -> new DualMachineEntitlementRecord(
                repeated('a', 32), repeated('b', 32), 2, 7L,
                HOST_KEY_SHA256, HOST_PUBLIC_KEY_BASE64,
                repeated('d', 64), "invalid alias"));
        expectRejected(() -> new DualMachineEntitlementRecord(
                repeated('a', 32), repeated('b', 32), 2, 7L,
                repeated('c', 64), HOST_PUBLIC_KEY_BASE64,
                repeated('d', 64), "valid-alias"));
        expectRejected(() -> new DualMachineEntitlementRecord(
                repeated('a', 32), repeated('b', 32), 2, 7L,
                HOST_KEY_SHA256, "not-base64",
                repeated('d', 64), "valid-alias"));
        System.out.println("ANDROID_ENTITLEMENT_RECORD_OK");
    }

    private static void expectRejected(Runnable action) {
        try {
            action.run();
            throw new AssertionError("invalid record was accepted");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("check failed");
    }

    private static String repeated(char character, int count) {
        StringBuilder value = new StringBuilder(count);
        for (int index = 0; index < count; index++) value.append(character);
        return value.toString();
    }
}
