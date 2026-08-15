package com.visionforge.inferencebenchmark;

/** Dependency-free contract for fail-closed MAKCU adapter and protocol identity. */
final class MakcuDeviceIdentityPolicySelfTest {
    static void run() {
        verifiesOnlyExpectedCh343AdapterIsAccepted();
        verifiesMakcuPromptIsRequired();
    }

    private static void verifiesOnlyExpectedCh343AdapterIsAccepted() {
        require(MakcuDeviceIdentityPolicy.isExpectedAdapter(0x1A86, 0x55D3));
        require(!MakcuDeviceIdentityPolicy.isExpectedAdapter(0x0BDA, 0x8153));
        require(!MakcuDeviceIdentityPolicy.isExpectedAdapter(0x1A86, 0x7523));
        require(!MakcuDeviceIdentityPolicy.isExpectedAdapter(0x10C4, 0xEA60));
        require("vid=1a86 pid=55d3".equals(
                MakcuDeviceIdentityPolicy.adapterToken(0x1A86, 0x55D3)));
        require(MakcuDeviceIdentityPolicy.isSameDevice("/dev/bus/usb/001/004",
                "/dev/bus/usb/001/004"));
        require(!MakcuDeviceIdentityPolicy.isSameDevice("/dev/bus/usb/001/004",
                "/dev/bus/usb/001/003"));
        require(!MakcuDeviceIdentityPolicy.isSameDevice(null,
                "/dev/bus/usb/001/004"));
    }

    private static void verifiesMakcuPromptIsRequired() {
        require(MakcuDeviceIdentityPolicy.isVerifiedProtocolResponse(
                "km.MAKCU\r\n>>> "));
        require(!MakcuDeviceIdentityPolicy.isVerifiedProtocolResponse(
                "km.version()\r\n>>> "));
        require(!MakcuDeviceIdentityPolicy.isVerifiedProtocolResponse(
                "km.move(1,2)\r\n>>> "));
        require(!MakcuDeviceIdentityPolicy.isVerifiedProtocolResponse(
                "boot\r\nkm.MAKCU\r\n>>> "));
        require(!MakcuDeviceIdentityPolicy.isVerifiedProtocolResponse(
                "km.MAKCU\r\n>>>"));
        require(!MakcuDeviceIdentityPolicy.isVerifiedProtocolResponse("km.version()"));
        require(!MakcuDeviceIdentityPolicy.isVerifiedProtocolResponse(">>>"));
        require(!MakcuDeviceIdentityPolicy.isVerifiedProtocolResponse(
                "USB-Enhanced-SERIAL CH343\r\n>>> "));
        require(!MakcuDeviceIdentityPolicy.isVerifiedProtocolResponse(null));
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("MAKCU device identity contract failed");
    }
}
