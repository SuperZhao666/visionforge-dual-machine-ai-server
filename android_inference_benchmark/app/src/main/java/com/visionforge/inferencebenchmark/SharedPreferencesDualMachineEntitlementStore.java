package com.visionforge.inferencebenchmark;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Android persistence for the non-secret entitlement binding only.
 *
 * <p>Malformed or partially written state is rejected instead of being
 * silently repaired. This prevents a stale identity from being substituted
 * after an AndroidKeyStore reset.</p>
 */
public final class SharedPreferencesDualMachineEntitlementStore
        implements DualMachineEntitlementStore {
    private static final String STORE =
            "visionforge_dual_machine_entitlement_v2";
    private static final int SCHEMA_VERSION = 4;
    private static final int LEGACY_SCHEMA_VERSION = 2;
    private static final int REVOKED_SCHEMA_VERSION = 3;
    private static final String LEGACY_AUTHORIZATION_KIND = "legacy_balance";
    private static final String KEY_SCHEMA_VERSION = "schema_version";
    private static final String KEY_ENTITLEMENT_ID = "entitlement_id";
    private static final String KEY_PAIR_ID = "pair_id";
    private static final String KEY_PROTOCOL_VERSION = "protocol_version";
    private static final String KEY_REVOCATION_VERSION = "revocation_version";
    private static final String KEY_HOST_KEY_SHA256 = "host_key_sha256";
    private static final String KEY_HOST_IDENTITY_PUBLIC_KEY_BASE64 =
            "host_identity_public_key_base64";
    private static final String KEY_ANDROID_KEY_SHA256 = "android_key_sha256";
    private static final String KEY_ANDROID_IDENTITY_ALIAS =
            "android_identity_alias";
    private static final String KEY_AUTHORIZATION_KIND =
            "authorization_kind";
    private static final String KEY_PRODUCT_KEY = "product_key";
    private static final String KEY_PERMANENT = "permanent";
    private static final String KEY_REVOKED = "revoked";

    private final SharedPreferences preferences;

    public SharedPreferencesDualMachineEntitlementStore(Context context) {
        this(resolvePreferences(context));
    }

    SharedPreferencesDualMachineEntitlementStore(
            SharedPreferences preferences) {
        if (preferences == null) {
            throw new IllegalArgumentException("preferences are required");
        }
        this.preferences = preferences;
    }

    private static SharedPreferences resolvePreferences(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        return context.getApplicationContext().getSharedPreferences(
                STORE, Context.MODE_PRIVATE);
    }

    @Override
    public DualMachineEntitlementRecord load() {
        if (!preferences.contains(KEY_SCHEMA_VERSION)) return null;
        try {
            int schemaVersion = preferences.getInt(KEY_SCHEMA_VERSION, -1);
            if (schemaVersion != SCHEMA_VERSION
                    && schemaVersion != LEGACY_SCHEMA_VERSION
                    && schemaVersion != REVOKED_SCHEMA_VERSION) {
                throw new SecurityException(
                        "dual-machine entitlement schema is unsupported");
            }
            if (schemaVersion >= REVOKED_SCHEMA_VERSION
                    && !preferences.contains(KEY_REVOKED)) {
                throw new SecurityException(
                        "dual-machine entitlement revocation marker is missing");
            }
            StoredAuthorization authorization = readAuthorization(schemaVersion);
            DualMachineEntitlementRecord record = new DualMachineEntitlementRecord(
                    preferences.getString(KEY_ENTITLEMENT_ID, ""),
                    preferences.getString(KEY_PAIR_ID, ""),
                    preferences.getInt(KEY_PROTOCOL_VERSION, -1),
                    preferences.getLong(KEY_REVOCATION_VERSION, -1L),
                    preferences.getString(KEY_HOST_KEY_SHA256, ""),
                    preferences.getString(
                            KEY_HOST_IDENTITY_PUBLIC_KEY_BASE64, ""),
                    preferences.getString(KEY_ANDROID_KEY_SHA256, ""),
                    preferences.getString(KEY_ANDROID_IDENTITY_ALIAS, ""),
                    authorization.kind,
                    authorization.productKey,
                    authorization.permanent,
                    schemaVersion >= REVOKED_SCHEMA_VERSION
                            && preferences.getBoolean(KEY_REVOKED, false));
            if (schemaVersion != SCHEMA_VERSION) save(record);
            return record;
        } catch (IllegalArgumentException | ClassCastException exception) {
            throw new SecurityException(
                    "dual-machine entitlement binding is corrupt", exception);
        }
    }

    @Override
    public void save(DualMachineEntitlementRecord record) {
        if (record == null) {
            throw new IllegalArgumentException("record is required");
        }
        boolean committed = preferences.edit()
                .clear()
                .putInt(KEY_SCHEMA_VERSION, SCHEMA_VERSION)
                .putString(KEY_ENTITLEMENT_ID, record.entitlementId)
                .putString(KEY_PAIR_ID, record.pairId)
                .putInt(KEY_PROTOCOL_VERSION, record.protocolVersion)
                .putLong(KEY_REVOCATION_VERSION, record.revocationVersion)
                .putString(KEY_HOST_KEY_SHA256, record.hostKeySha256)
                .putString(
                        KEY_HOST_IDENTITY_PUBLIC_KEY_BASE64,
                        record.hostIdentityPublicKeyBase64)
                .putString(KEY_ANDROID_KEY_SHA256, record.androidKeySha256)
                .putString(
                        KEY_ANDROID_IDENTITY_ALIAS,
                        record.androidIdentityAlias)
                .putString(KEY_AUTHORIZATION_KIND, record.authorizationKind)
                .putString(KEY_PRODUCT_KEY, record.productKey)
                .putBoolean(KEY_PERMANENT, record.permanent)
                .putBoolean(KEY_REVOKED, record.revoked)
                .commit();
        if (!committed) {
            throw new IllegalStateException(
                    "dual-machine entitlement persistence failed");
        }
    }

    @Override
    public void clear() {
        if (!preferences.edit().clear().commit()) {
            throw new IllegalStateException(
                    "dual-machine entitlement clear failed");
        }
    }

    private StoredAuthorization readAuthorization(int schemaVersion) {
        boolean hasAuthorizationKind = preferences.contains(
                KEY_AUTHORIZATION_KIND);
        boolean hasProductKey = preferences.contains(KEY_PRODUCT_KEY);
        boolean hasPermanent = preferences.contains(KEY_PERMANENT);
        if (schemaVersion != SCHEMA_VERSION
                && !hasAuthorizationKind
                && !hasProductKey
                && !hasPermanent) {
            return new StoredAuthorization(
                    LEGACY_AUTHORIZATION_KIND,
                    LEGACY_AUTHORIZATION_KIND,
                    false);
        }
        if (!hasAuthorizationKind || !hasProductKey || !hasPermanent) {
            throw new SecurityException(
                    "dual-machine entitlement authorization is incomplete");
        }
        String authorizationKind = preferences.getString(
                KEY_AUTHORIZATION_KIND, "");
        String productKey = preferences.getString(KEY_PRODUCT_KEY, "");
        boolean permanent = preferences.getBoolean(KEY_PERMANENT, false);
        if (!DualMachineEntitlementRecord.isSupportedAuthorizationKind(
                authorizationKind)
                || !authorizationKind.equals(productKey)
                || permanent != "permanent".equals(authorizationKind)) {
            throw new SecurityException(
                    "dual-machine entitlement authorization is invalid");
        }
        return new StoredAuthorization(
                authorizationKind, productKey, permanent);
    }

    private static final class StoredAuthorization {
        final String kind;
        final String productKey;
        final boolean permanent;

        StoredAuthorization(String kind, String productKey, boolean permanent) {
            this.kind = kind;
            this.productKey = productKey;
            this.permanent = permanent;
        }
    }
}
