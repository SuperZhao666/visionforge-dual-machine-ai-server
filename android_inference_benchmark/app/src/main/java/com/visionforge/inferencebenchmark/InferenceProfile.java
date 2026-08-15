package com.visionforge.inferencebenchmark;

import android.content.Context;
import android.content.SharedPreferences;

/** Persistent, validated QNN post-process policy; independent from MAKCU output. */
final class InferenceProfile {
    private final SharedPreferences store;
    private MobileModelCatalog.Profile model;
    private MobileAimTarget aimTarget;
    private InferencePolicy policy;
    private boolean nativeConfigurationApplied;

    InferenceProfile(Context context) {
        store = context.getSharedPreferences(
                MobileProfileStorageKeys.INFERENCE_STORE, Context.MODE_PRIVATE);
        model = MobileModelCatalog.forProductionToken(store.getString(
                MobileProfileStorageKeys.ACTIVE_MODEL, MobileModelCatalog.DEFAULT.token));
        aimTarget = restoredAimTarget(model);
        policy = policyFor(model);
        apply();
    }

    void selectModel(MobileModelCatalog.Profile selected) {
        if (!MobileModelCatalog.isProductionSelectable(selected)) return;
        model = selected;
        aimTarget = restoredAimTarget(model);
        policy = policyFor(model);
        store.edit().putString(MobileProfileStorageKeys.ACTIVE_MODEL, model.token).apply();
        apply();
    }

    void setAimTarget(MobileAimTarget selected) {
        if (!model.supports(selected)) return;
        aimTarget = selected;
        store.edit().putString(aimTargetKey(model), aimTarget.storageToken).apply();
    }

    void setConfidence(float value) {
        policy = policy.withConfidence(value);
        store.edit().putFloat(confidenceKey(model), policy.confidence()).apply();
        apply();
    }

    float confidence() {
        return policy.confidence();
    }

    float nmsIou() {
        return policy.nmsIou();
    }

    MobileModelCatalog.Profile model() {
        return model;
    }

    MobileAimTarget aimTarget() {
        return aimTarget;
    }

    boolean isNativeConfigurationApplied() {
        return nativeConfigurationApplied;
    }

    String auditDetail() {
        return "model=" + model.token
                + " aim_target=" + aimTarget.storageToken
                + " confidence=" + String.format(java.util.Locale.US, "%.2f", policy.confidence())
                + " iou=" + String.format(java.util.Locale.US, "%.2f", policy.nmsIou())
                + " native_applied=" + nativeConfigurationApplied;
    }

    private void apply() {
        nativeConfigurationApplied = QnnHtpBridge.configureNativeQnnPostprocess(
                policy.confidence(), policy.nmsIou());
    }

    private InferencePolicy policyFor(MobileModelCatalog.Profile profile) {
        return InferencePolicy.forProfile(profile,
                store.getFloat(confidenceKey(profile), profile.defaultConfidence));
    }

    private MobileAimTarget restoredAimTarget(MobileModelCatalog.Profile profile) {
        MobileAimTarget restored = MobileAimTarget.fromStorage(
                store.getString(aimTargetKey(profile), null), profile.defaultAimTarget);
        return profile.supports(restored) ? restored : profile.defaultAimTarget;
    }

    private static String confidenceKey(MobileModelCatalog.Profile profile) {
        return MobileProfileStorageKeys.inferenceConfidence(profile);
    }

    private static String aimTargetKey(MobileModelCatalog.Profile profile) {
        return MobileProfileStorageKeys.inferenceAimTarget(profile);
    }
}
