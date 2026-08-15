package com.visionforge.inferencebenchmark;

/** Operator-visible production output routes. MAKCU remains the default. */
enum ControlOutputRoute {
    NONE("none"),
    MAKCU_USB("makcu_usb"),
    BLUETOOTH_HID("bluetooth_hid");

    final String storageToken;

    ControlOutputRoute(String storageToken) {
        this.storageToken = storageToken;
    }

    static ControlOutputRoute fromStorageToken(String token) {
        if (token == null || token.trim().isEmpty()) return MAKCU_USB;
        String normalized = token.trim();
        for (ControlOutputRoute route : values()) {
            if (route.storageToken.equals(normalized)) return route;
        }
        return NONE;
    }
}
