package com.visionforge.inferencebenchmark.ui;

/** Stable accessibility identifiers used by device acceptance tests. */
final class UiAutomationIds {
    static final String NAV_AUTHORIZATION = "vf.nav.authorization";
    static final String NAV_INFERENCE = "vf.nav.inference";
    static final String NAV_CONTROL = "vf.nav.control";
    static final String SCROLL_AUTHORIZATION = "vf.page_scroll.authorization";
    static final String SCROLL_INFERENCE = "vf.page_scroll.inference";
    static final String SCROLL_CONTROL = "vf.page_scroll.control";
    static final String INFERENCE_LINK_STATUS = "vf.inference.link_status";
    static final String CARD_CODE_INPUT = "vf.authorization.card_code";
    static final String CARD_ACTIVATE = "vf.authorization.activate";
    static final String OUTPUT_ROUTE_MAKCU = "vf.output_route.makcu_usb";
    static final String OUTPUT_ROUTE_BLUETOOTH_HID =
            "vf.output_route.bluetooth_hid";
    static final String MODEL_PREFIX = "vf.game_model.";
    static final String AIM_TARGET_PREFIX = "vf.aim_target.";

    static String gameModel(String token) {
        return MODEL_PREFIX + token;
    }

    static String aimTarget(String storageToken) {
        return AIM_TARGET_PREFIX + storageToken;
    }

    private UiAutomationIds() {
    }
}
