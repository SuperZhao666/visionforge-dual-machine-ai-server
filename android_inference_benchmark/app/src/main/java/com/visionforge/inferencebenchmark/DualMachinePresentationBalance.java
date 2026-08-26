package com.visionforge.inferencebenchmark;

import java.util.Objects;

/**
 * Last server-confirmed balance retained strictly for offline presentation.
 *
 * <p>This value is non-secret and never restores {@code balanceKnown} in the
 * formal-use state machine. A process restart must still obtain a fresh,
 * dual-device-signed status response before it can start billable use.</p>
 */
public final class DualMachinePresentationBalance {
    public final String entitlementId;
    public final String pairId;
    public final String bindingId;
    public final long bindingRevision;
    public final long revocationVersion;
    public final String hostKeySha256;
    public final String androidKeySha256;
    public final String authorizationKind;
    public final boolean permanent;
    public final long remainingSeconds;
    public final long totalConsumedSeconds;
    public final long synchronizedAtEpochSeconds;

    DualMachinePresentationBalance(
            String entitlementId,
            String pairId,
            String bindingId,
            long bindingRevision,
            long revocationVersion,
            String hostKeySha256,
            String androidKeySha256,
            String authorizationKind,
            boolean permanent,
            long remainingSeconds,
            long totalConsumedSeconds,
            long synchronizedAtEpochSeconds) {
        if (entitlementId == null || pairId == null || bindingId == null
                || hostKeySha256 == null || androidKeySha256 == null
                || authorizationKind == null || bindingRevision <= 0L
                || revocationVersion <= 0L || remainingSeconds < 0L
                || totalConsumedSeconds < 0L
                || synchronizedAtEpochSeconds <= 0L) {
            throw new IllegalArgumentException(
                    "presentation balance is invalid");
        }
        this.entitlementId = entitlementId;
        this.pairId = pairId;
        this.bindingId = bindingId;
        this.bindingRevision = bindingRevision;
        this.revocationVersion = revocationVersion;
        this.hostKeySha256 = hostKeySha256;
        this.androidKeySha256 = androidKeySha256;
        this.authorizationKind = authorizationKind;
        this.permanent = permanent;
        this.remainingSeconds = remainingSeconds;
        this.totalConsumedSeconds = totalConsumedSeconds;
        this.synchronizedAtEpochSeconds = synchronizedAtEpochSeconds;
    }

    public static DualMachinePresentationBalance fromAuthoritativeSnapshot(
            DualMachineEntitlementRecord entitlement,
            long remainingSeconds,
            long totalConsumedSeconds,
            long synchronizedAtEpochSeconds) {
        if (entitlement == null) {
            throw new IllegalArgumentException("entitlement is required");
        }
        return new DualMachinePresentationBalance(
                entitlement.entitlementId,
                entitlement.pairId,
                entitlement.bindingId,
                entitlement.bindingRevision,
                entitlement.revocationVersion,
                entitlement.hostKeySha256,
                entitlement.androidKeySha256,
                entitlement.authorizationKind,
                entitlement.permanent,
                remainingSeconds,
                totalConsumedSeconds,
                synchronizedAtEpochSeconds);
    }

    public boolean matches(DualMachineEntitlementRecord entitlement) {
        return entitlement != null
                && entitlementId.equals(entitlement.entitlementId)
                && pairId.equals(entitlement.pairId)
                && bindingId.equals(entitlement.bindingId)
                && bindingRevision == entitlement.bindingRevision
                && revocationVersion == entitlement.revocationVersion
                && hostKeySha256.equals(entitlement.hostKeySha256)
                && androidKeySha256.equals(entitlement.androidKeySha256)
                && authorizationKind.equals(entitlement.authorizationKind)
                && permanent == entitlement.permanent;
    }

    boolean sameBalance(DualMachinePresentationBalance other) {
        return other != null
                && entitlementId.equals(other.entitlementId)
                && pairId.equals(other.pairId)
                && bindingId.equals(other.bindingId)
                && bindingRevision == other.bindingRevision
                && revocationVersion == other.revocationVersion
                && hostKeySha256.equals(other.hostKeySha256)
                && androidKeySha256.equals(other.androidKeySha256)
                && authorizationKind.equals(other.authorizationKind)
                && permanent == other.permanent
                && remainingSeconds == other.remainingSeconds
                && totalConsumedSeconds == other.totalConsumedSeconds;
    }

    @Override
    public boolean equals(Object candidate) {
        if (this == candidate) return true;
        if (!(candidate instanceof DualMachinePresentationBalance)) {
            return false;
        }
        DualMachinePresentationBalance other =
                (DualMachinePresentationBalance) candidate;
        return sameBalance(other)
                && synchronizedAtEpochSeconds
                == other.synchronizedAtEpochSeconds;
    }

    @Override
    public int hashCode() {
        return Objects.hash(entitlementId, pairId, bindingId,
                bindingRevision, revocationVersion, hostKeySha256,
                androidKeySha256, authorizationKind, permanent,
                remainingSeconds, totalConsumedSeconds,
                synchronizedAtEpochSeconds);
    }
}
