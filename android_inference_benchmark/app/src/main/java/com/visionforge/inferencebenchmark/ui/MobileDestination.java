package com.visionforge.inferencebenchmark.ui;

import com.visionforge.inferencebenchmark.R;

/** Stable top-level destinations owned by the application shell. */
public enum MobileDestination {
    AUTHORIZATION(R.string.nav_authorization, MaterialIcons.KEY,
            UiAutomationIds.NAV_AUTHORIZATION),
    INFERENCE(R.string.nav_inference, MaterialIcons.MEMORY, UiAutomationIds.NAV_INFERENCE),
    CONTROL(R.string.nav_control, MaterialIcons.TUNE, UiAutomationIds.NAV_CONTROL);

    public final int labelResource;
    public final String icon;
    public final String contentDescription;

    MobileDestination(int labelResource, String icon, String contentDescription) {
        this.labelResource = labelResource;
        this.icon = icon;
        this.contentDescription = contentDescription;
    }
}
