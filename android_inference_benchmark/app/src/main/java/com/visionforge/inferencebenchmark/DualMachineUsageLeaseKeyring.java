package com.visionforge.inferencebenchmark;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Bounded public-key rotation wrapper for usage leases.
 *
 * <p>Keeping the current and immediately previous RSA public keys permits a
 * controlled server rotation without accepting an unbounded attacker-chosen
 * key set. No private key or dynamic network key is accepted.</p>
 */
public final class DualMachineUsageLeaseKeyring {
    private static final int MAXIMUM_KEYS = 3;
    private final List<DualMachineUsageLeaseVerifier> verifiers;

    public DualMachineUsageLeaseKeyring(
            Collection<? extends PublicKey> publicKeys,
            int maximumTtlSeconds) throws GeneralSecurityException {
        if (publicKeys == null || publicKeys.isEmpty()
                || publicKeys.size() > MAXIMUM_KEYS) {
            throw new GeneralSecurityException(
                    "usage_lease_keyring_size_invalid");
        }
        List<DualMachineUsageLeaseVerifier> built =
                new ArrayList<>(publicKeys.size());
        Set<String> keyIds = new HashSet<>();
        for (PublicKey publicKey : publicKeys) {
            DualMachineUsageLeaseVerifier verifier =
                    new DualMachineUsageLeaseVerifier(
                            publicKey, maximumTtlSeconds);
            if (!keyIds.add(verifier.expectedKeyId())) {
                throw new GeneralSecurityException(
                        "usage_lease_keyring_duplicate_kid");
            }
            built.add(verifier);
        }
        verifiers = Collections.unmodifiableList(new ArrayList<>(built));
    }

    public DualMachineUsageLeaseVerifier.VerifiedLease verify(
            String token,
            DualMachineUsageLeaseVerifier.ExpectedBinding expected,
            long trustedWallTimeEpochSeconds,
            long monotonicNowNanos)
            throws DualMachineUsageLeaseVerifier.LeaseVerificationException {
        DualMachineUsageLeaseVerifier.LeaseVerificationException last = null;
        for (DualMachineUsageLeaseVerifier verifier : verifiers) {
            try {
                return verifier.verify(
                        token,
                        expected,
                        trustedWallTimeEpochSeconds,
                        monotonicNowNanos);
            } catch (DualMachineUsageLeaseVerifier.LeaseVerificationException
                     exception) {
                last = exception;
            }
        }
        throw new DualMachineUsageLeaseVerifier.LeaseVerificationException(
                "usage_lease_keyring_verification_failed", last);
    }

    public int size() {
        return verifiers.size();
    }
}
