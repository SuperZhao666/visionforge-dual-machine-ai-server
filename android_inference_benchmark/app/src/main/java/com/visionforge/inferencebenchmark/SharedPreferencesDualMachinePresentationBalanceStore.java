package com.visionforge.inferencebenchmark;

import android.content.Context;
import android.content.SharedPreferences;

/** Android storage for a non-authorizing, last-confirmed balance display. */
final class SharedPreferencesDualMachinePresentationBalanceStore {
    private static final String STORE =
            "visionforge_dual_machine_presentation_balance_v1";
    private static final int SCHEMA_VERSION = 1;
    private static final String KEY_SCHEMA_VERSION = "schema_version";
    private static final String KEY_ENTITLEMENT_ID = "entitlement_id";
    private static final String KEY_PAIR_ID = "pair_id";
    private static final String KEY_BINDING_ID = "binding_id";
    private static final String KEY_BINDING_REVISION = "binding_revision";
    private static final String KEY_REVOCATION_VERSION = "revocation_version";
    private static final String KEY_HOST_KEY_SHA256 = "host_key_sha256";
    private static final String KEY_ANDROID_KEY_SHA256 = "android_key_sha256";
    private static final String KEY_AUTHORIZATION_KIND = "authorization_kind";
    private static final String KEY_PERMANENT = "permanent";
    private static final String KEY_REMAINING_SECONDS = "remaining_seconds";
    private static final String KEY_TOTAL_CONSUMED_SECONDS =
            "total_consumed_seconds";
    private static final String KEY_SYNCHRONIZED_AT_EPOCH_SECONDS =
            "synchronized_at_epoch_seconds";

    private final SharedPreferences preferences;

    SharedPreferencesDualMachinePresentationBalanceStore(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        preferences = context.getApplicationContext().getSharedPreferences(
                STORE, Context.MODE_PRIVATE);
    }

    DualMachinePresentationBalance load() {
        if (!preferences.contains(KEY_SCHEMA_VERSION)) return null;
        try {
            if (preferences.getInt(KEY_SCHEMA_VERSION, -1)
                    != SCHEMA_VERSION) {
                throw new SecurityException(
                        "presentation balance schema is unsupported");
            }
            return new DualMachinePresentationBalance(
                    preferences.getString(KEY_ENTITLEMENT_ID, null),
                    preferences.getString(KEY_PAIR_ID, null),
                    preferences.getString(KEY_BINDING_ID, null),
                    preferences.getLong(KEY_BINDING_REVISION, -1L),
                    preferences.getLong(KEY_REVOCATION_VERSION, -1L),
                    preferences.getString(KEY_HOST_KEY_SHA256, null),
                    preferences.getString(KEY_ANDROID_KEY_SHA256, null),
                    preferences.getString(KEY_AUTHORIZATION_KIND, null),
                    preferences.getBoolean(KEY_PERMANENT, false),
                    preferences.getLong(KEY_REMAINING_SECONDS, -1L),
                    preferences.getLong(KEY_TOTAL_CONSUMED_SECONDS, -1L),
                    preferences.getLong(
                            KEY_SYNCHRONIZED_AT_EPOCH_SECONDS, -1L));
        } catch (IllegalArgumentException | ClassCastException failure) {
            throw new SecurityException(
                    "presentation balance is corrupt", failure);
        }
    }

    void save(DualMachinePresentationBalance balance) {
        if (balance == null) {
            throw new IllegalArgumentException("balance is required");
        }
        boolean committed = preferences.edit()
                .clear()
                .putInt(KEY_SCHEMA_VERSION, SCHEMA_VERSION)
                .putString(KEY_ENTITLEMENT_ID, balance.entitlementId)
                .putString(KEY_PAIR_ID, balance.pairId)
                .putString(KEY_BINDING_ID, balance.bindingId)
                .putLong(KEY_BINDING_REVISION, balance.bindingRevision)
                .putLong(KEY_REVOCATION_VERSION, balance.revocationVersion)
                .putString(KEY_HOST_KEY_SHA256, balance.hostKeySha256)
                .putString(KEY_ANDROID_KEY_SHA256, balance.androidKeySha256)
                .putString(KEY_AUTHORIZATION_KIND, balance.authorizationKind)
                .putBoolean(KEY_PERMANENT, balance.permanent)
                .putLong(KEY_REMAINING_SECONDS, balance.remainingSeconds)
                .putLong(
                        KEY_TOTAL_CONSUMED_SECONDS,
                        balance.totalConsumedSeconds)
                .putLong(
                        KEY_SYNCHRONIZED_AT_EPOCH_SECONDS,
                        balance.synchronizedAtEpochSeconds)
                .commit();
        if (!committed) {
            throw new IllegalStateException(
                    "presentation balance persistence failed");
        }
    }

    void clear() {
        if (!preferences.edit().clear().commit()) {
            throw new IllegalStateException(
                    "presentation balance clear failed");
        }
    }
}
