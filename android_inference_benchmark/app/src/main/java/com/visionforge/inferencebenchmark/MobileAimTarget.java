package com.visionforge.inferencebenchmark;

/** User-visible target class or geometric aim point within the selected game model. */
public enum MobileAimTarget {
    BODY("body"),
    HEAD("head"),
    TEAMMATE("teammate"),
    AI("ai"),
    CROSSHAIR("crosshair"),
    CT_BODY("ct_body"),
    CT_HEAD("ct_head"),
    T_BODY("t_body"),
    T_HEAD("t_head");

    public final String storageToken;

    MobileAimTarget(String storageToken) {
        this.storageToken = storageToken;
    }

    public static MobileAimTarget fromStorage(String value, MobileAimTarget fallback) {
        if (value != null) {
            for (MobileAimTarget target : values()) {
                if (target.storageToken.equals(value)) return target;
            }
        }
        return fallback;
    }
}
