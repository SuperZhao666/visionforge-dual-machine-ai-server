package com.visionforge.inferencebenchmark;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collections;

/** Current/previous public-key rotation contract. */
public final class DualMachineUsageLeaseKeyringSelfTest {
    private DualMachineUsageLeaseKeyringSelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        KeyPair current = DualMachineUsageLeaseSelfTestSupport.rsaKeyPair(3072);
        KeyPair previous = DualMachineUsageLeaseSelfTestSupport.rsaKeyPair(3072);
        KeyPair unknown = DualMachineUsageLeaseSelfTestSupport.rsaKeyPair(3072);
        DualMachineUsageLeaseSelfTestSupport.LeaseData data =
                DualMachineUsageLeaseSelfTestSupport.initial(100L, 100L, 105L);
        DualMachineUsageLeaseKeyring keyring =
                new DualMachineUsageLeaseKeyring(
                        Arrays.asList(current.getPublic(), previous.getPublic()),
                        5);
        require(keyring.size() == 2);
        verify(keyring, current, data);
        verify(keyring, previous, data);
        expectRejected(() -> verify(keyring, unknown, data));
        expectInvalid(() -> new DualMachineUsageLeaseKeyring(
                Collections.emptyList(), 5));
        expectInvalid(() -> new DualMachineUsageLeaseKeyring(
                Arrays.asList(current.getPublic(), current.getPublic()), 5));
        System.out.println("DUAL_MACHINE_USAGE_LEASE_KEYRING_SELF_TEST_OK");
    }

    private static void verify(
            DualMachineUsageLeaseKeyring keyring,
            KeyPair signer,
            DualMachineUsageLeaseSelfTestSupport.LeaseData data)
            throws Exception {
        DualMachineUsageLeaseVerifier.VerifiedLease lease = keyring.verify(
                DualMachineUsageLeaseSelfTestSupport.token(signer, data),
                DualMachineUsageLeaseSelfTestSupport.expected(data),
                100L,
                0L);
        require(lease.sequence() == 0L);
    }

    private static void expectRejected(CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("unknown signing key was accepted");
        } catch (DualMachineUsageLeaseVerifier.LeaseVerificationException
                 expected) {
            // Expected.
        }
    }

    private static void expectInvalid(CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("invalid keyring was accepted");
        } catch (GeneralSecurityException expected) {
            // Expected.
        }
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("keyring contract failed");
    }

    @FunctionalInterface
    private interface CheckedAction {
        void run() throws Exception;
    }
}
