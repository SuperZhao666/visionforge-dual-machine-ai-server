package com.visionforge.inferencebenchmark;

import java.util.Locale;

/**
 * Fail-closed identity contract for the MAKCU USB transport.
 *
 * <p>The CH343 VID/PID only identifies the expected serial adapter. A device
 * becomes eligible for output only after it also answers a non-moving
 * {@code km.version()} query with the exact documented MAKCU identity frame.</p>
 */
final class MakcuDeviceIdentityPolicy {
    static final int WCH_VENDOR_ID = 0x1A86;
    static final int CH343_PRODUCT_ID = 0x55D3;

    private MakcuDeviceIdentityPolicy() { }

    static boolean isExpectedAdapter(int vendorId, int productId) {
        return vendorId == WCH_VENDOR_ID && productId == CH343_PRODUCT_ID;
    }

    static boolean isVerifiedProtocolResponse(String response) {
        return "km.MAKCU\r\n>>> ".equals(response);
    }

    static String adapterToken(int vendorId, int productId) {
        return String.format(Locale.US, "vid=%04x pid=%04x", vendorId, productId);
    }

    static boolean isSameDevice(String activeDeviceName, String detachedDeviceName) {
        return activeDeviceName != null && activeDeviceName.equals(detachedDeviceName);
    }
}
