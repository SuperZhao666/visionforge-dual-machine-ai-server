package com.visionforge.inferencebenchmark;

import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;

/**
 * Non-secret local binding for one activated dual-machine card entitlement.
 *
 * <p>Card codes, challenge tokens, usage leases, signatures and session keys
 * are intentionally absent. The Host public identity is non-secret and is
 * retained so peer proofs can be verified against the server-bound
 * fingerprint after restart. A process restart therefore cannot restore an
 * active paid session or reopen the data plane.</p>
 */
public final class DualMachineEntitlementRecord {
    public static final int PROTOCOL_VERSION = 2;

    public final String entitlementId;
    public final String pairId;
    public final String bindingId;
    public final long bindingRevision;
    public final String pairAssuranceState;
    public final int protocolVersion;
    public final long revocationVersion;
    public final String hostKeySha256;
    public final String hostIdentityPublicKeyBase64;
    public final String androidKeySha256;
    public final String androidIdentityAlias;
    public final String authorizationKind;
    public final String productKey;
    public final boolean permanent;
    public final boolean revoked;

    public DualMachineEntitlementRecord(
            String entitlementId,
            String pairId,
            String bindingId,
            long bindingRevision,
            String pairAssuranceState,
            int protocolVersion,
            long revocationVersion,
            String hostKeySha256,
            String hostIdentityPublicKeyBase64,
            String androidKeySha256,
            String androidIdentityAlias) {
        this(
                entitlementId,
                pairId,
                bindingId,
                bindingRevision,
                pairAssuranceState,
                protocolVersion,
                revocationVersion,
                hostKeySha256,
                hostIdentityPublicKeyBase64,
                androidKeySha256,
                androidIdentityAlias,
                "day",
                "day",
                false,
                false);
    }

    public DualMachineEntitlementRecord(
            String entitlementId,
            String pairId,
            int protocolVersion,
            long revocationVersion,
            String hostKeySha256,
            String hostIdentityPublicKeyBase64,
            String androidKeySha256,
            String androidIdentityAlias) {
        this(
                entitlementId,
                pairId,
                "",
                0L,
                "legacy_blocked",
                protocolVersion,
                revocationVersion,
                hostKeySha256,
                hostIdentityPublicKeyBase64,
                androidKeySha256,
                androidIdentityAlias,
                "day",
                "day",
                false,
                false);
    }

    public DualMachineEntitlementRecord(
            String entitlementId,
            String pairId,
            int protocolVersion,
            long revocationVersion,
            String hostKeySha256,
            String hostIdentityPublicKeyBase64,
            String androidKeySha256,
            String androidIdentityAlias,
            boolean revoked) {
        this(
                entitlementId,
                pairId,
                "",
                0L,
                "legacy_blocked",
                protocolVersion,
                revocationVersion,
                hostKeySha256,
                hostIdentityPublicKeyBase64,
                androidKeySha256,
                androidIdentityAlias,
                "day",
                "day",
                false,
                revoked);
    }

    public DualMachineEntitlementRecord(
            String entitlementId,
            String pairId,
            int protocolVersion,
            long revocationVersion,
            String hostKeySha256,
            String hostIdentityPublicKeyBase64,
            String androidKeySha256,
            String androidIdentityAlias,
            String authorizationKind,
            String productKey,
            boolean permanent,
            boolean revoked) {
        this(
                entitlementId,
                pairId,
                "",
                0L,
                "legacy_blocked",
                protocolVersion,
                revocationVersion,
                hostKeySha256,
                hostIdentityPublicKeyBase64,
                androidKeySha256,
                androidIdentityAlias,
                authorizationKind,
                productKey,
                permanent,
                revoked);
    }

    public DualMachineEntitlementRecord(
            String entitlementId,
            String pairId,
            String bindingId,
            long bindingRevision,
            String pairAssuranceState,
            int protocolVersion,
            long revocationVersion,
            String hostKeySha256,
            String hostIdentityPublicKeyBase64,
            String androidKeySha256,
            String androidIdentityAlias,
            String authorizationKind,
            String productKey,
            boolean permanent,
            boolean revoked) {
        this.entitlementId = requireLowerHex(entitlementId, 32, "entitlementId");
        this.pairId = requireLowerHex(pairId, 32, "pairId");
        this.pairAssuranceState = requirePairAssuranceState(
                pairAssuranceState);
        if ("active".equals(this.pairAssuranceState)) {
            this.bindingId = requireLowerHex(bindingId, 32, "bindingId");
            if (bindingRevision <= 0L) {
                throw new IllegalArgumentException(
                        "bindingRevision must be positive");
            }
            this.bindingRevision = bindingRevision;
        } else {
            if ((bindingId != null && !bindingId.isEmpty())
                    || bindingRevision != 0L) {
                throw new IllegalArgumentException(
                        "legacy-blocked binding authority must be absent");
            }
            this.bindingId = "";
            this.bindingRevision = 0L;
        }
        if (protocolVersion != PROTOCOL_VERSION) {
            throw new IllegalArgumentException("unsupported protocolVersion");
        }
        if (revocationVersion <= 0L) {
            throw new IllegalArgumentException("revocationVersion must be positive");
        }
        this.protocolVersion = protocolVersion;
        this.revocationVersion = revocationVersion;
        this.hostKeySha256 = requireLowerHex(
                hostKeySha256, 64, "hostKeySha256");
        this.hostIdentityPublicKeyBase64 = requireHostIdentity(
                hostIdentityPublicKeyBase64, this.hostKeySha256);
        this.androidKeySha256 = requireLowerHex(
                androidKeySha256, 64, "androidKeySha256");
        this.androidIdentityAlias = requireIdentityAlias(androidIdentityAlias);
        this.authorizationKind = requireAuthorizationKind(
                authorizationKind);
        this.productKey = requireProductKey(productKey);
        if (!this.authorizationKind.equals(this.productKey)) {
            throw new IllegalArgumentException(
                    "productKey does not match authorizationKind");
        }
        if (permanent != "permanent".equals(this.authorizationKind)) {
            throw new IllegalArgumentException(
                    "permanent marker does not match authorizationKind");
        }
        this.permanent = permanent;
        this.revoked = revoked;
    }

    public boolean matchesAndroidIdentity(String alias, String fingerprintSha256) {
        return androidIdentityAlias.equals(alias)
                && androidKeySha256.equals(fingerprintSha256);
    }

    public boolean hasActivePairSecurityBinding() {
        return "active".equals(pairAssuranceState)
                && !bindingId.isEmpty()
                && bindingRevision > 0L;
    }

    public byte[] hostIdentityPublicKeyDer() {
        return Base64.getDecoder().decode(hostIdentityPublicKeyBase64);
    }

    public DualMachineEntitlementRecord withRevocationVersion(
            long confirmedRevocationVersion) {
        if (confirmedRevocationVersion < revocationVersion) {
            throw new IllegalArgumentException(
                    "revocationVersion must not decrease");
        }
        return new DualMachineEntitlementRecord(
                entitlementId,
                pairId,
                bindingId,
                bindingRevision,
                pairAssuranceState,
                protocolVersion,
                confirmedRevocationVersion,
                hostKeySha256,
                hostIdentityPublicKeyBase64,
                androidKeySha256,
                androidIdentityAlias,
                authorizationKind,
                productKey,
                permanent,
                true);
    }

    @Override
    public boolean equals(Object candidate) {
        if (this == candidate) return true;
        if (!(candidate instanceof DualMachineEntitlementRecord)) return false;
        DualMachineEntitlementRecord other =
                (DualMachineEntitlementRecord) candidate;
        return protocolVersion == other.protocolVersion
                && revocationVersion == other.revocationVersion
                && permanent == other.permanent
                && revoked == other.revoked
                && bindingRevision == other.bindingRevision
                && entitlementId.equals(other.entitlementId)
                && pairId.equals(other.pairId)
                && bindingId.equals(other.bindingId)
                && pairAssuranceState.equals(other.pairAssuranceState)
                && hostKeySha256.equals(other.hostKeySha256)
                && hostIdentityPublicKeyBase64.equals(
                        other.hostIdentityPublicKeyBase64)
                && androidKeySha256.equals(other.androidKeySha256)
                && androidIdentityAlias.equals(other.androidIdentityAlias)
                && authorizationKind.equals(other.authorizationKind)
                && productKey.equals(other.productKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                entitlementId,
                pairId,
                bindingId,
                bindingRevision,
                pairAssuranceState,
                protocolVersion,
                revocationVersion,
                hostKeySha256,
                hostIdentityPublicKeyBase64,
                androidKeySha256,
                androidIdentityAlias,
                authorizationKind,
                productKey,
                permanent,
                revoked);
    }

    private static String requireAuthorizationKind(String value) {
        if (!isSupportedAuthorizationKind(value)) {
            throw new IllegalArgumentException(
                    "authorizationKind is invalid");
        }
        return value;
    }

    private static String requirePairAssuranceState(String value) {
        if (!"active".equals(value) && !"legacy_blocked".equals(value)) {
            throw new IllegalArgumentException(
                    "pairAssuranceState is invalid");
        }
        return value;
    }

    static boolean isSupportedAuthorizationKind(String value) {
        return "legacy_balance".equals(value)
                || "day".equals(value)
                || "week".equals(value)
                || "month".equals(value)
                || "permanent".equals(value);
    }

    private static String requireProductKey(String value) {
        String normalized = value == null ? "" : value;
        if (normalized.length() > 32) {
            throw new IllegalArgumentException("productKey is invalid");
        }
        for (int index = 0; index < normalized.length(); index++) {
            char character = normalized.charAt(index);
            if (!((character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9')
                    || character == '_' || character == '-')) {
                throw new IllegalArgumentException("productKey is invalid");
            }
        }
        return normalized;
    }

    private static String requireLowerHex(String value, int length, String name) {
        if (value == null || value.length() != length) {
            throw new IllegalArgumentException(name + " has invalid length");
        }
        boolean containsNonzero = false;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f'))) {
                throw new IllegalArgumentException(name + " is not lowercase hex");
            }
            containsNonzero |= character != '0';
        }
        if (!containsNonzero) {
            throw new IllegalArgumentException(name + " must not be all zero");
        }
        return value;
    }

    private static String requireIdentityAlias(String value) {
        if (value == null || value.isEmpty() || value.length() > 128) {
            throw new IllegalArgumentException(
                    "androidIdentityAlias has invalid length");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= 'A' && character <= 'Z')
                    || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9')
                    || character == '.' || character == '_'
                    || character == ':' || character == '-')) {
                throw new IllegalArgumentException(
                        "androidIdentityAlias has invalid characters");
            }
        }
        return value;
    }

    private static String requireHostIdentity(
            String publicKeyBase64,
            String expectedFingerprintSha256) {
        try {
            byte[] publicKeyDer =
                    DualMachinePairingIdentityCodec.decodePublicKeyBase64(
                            publicKeyBase64);
            String actualFingerprint =
                    DualMachinePairingIdentityCodec.fingerprintHex(
                            publicKeyDer);
            if (!expectedFingerprintSha256.equals(actualFingerprint)) {
                throw new IllegalArgumentException(
                        "host identity fingerprint mismatch");
            }
            return DualMachinePairingIdentityCodec.encodePublicKeyBase64(
                    publicKeyDer);
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException(
                    "host identity public key is invalid", exception);
        }
    }
}
