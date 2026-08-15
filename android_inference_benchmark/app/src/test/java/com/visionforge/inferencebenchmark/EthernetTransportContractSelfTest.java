package com.visionforge.inferencebenchmark;

public final class EthernetTransportContractSelfTest {
    public static void main(String[] arguments) {
        require(EthernetTransportContract.accepts(true, "eth0", "10.57.23.2", 24),
                "accept fixed CAT6 link");
        require(!EthernetTransportContract.accepts(false, "eth0", "10.57.23.2", 24),
                "reject non-Ethernet transport");
        require(!EthernetTransportContract.accepts(true, "wlan0", "10.57.23.2", 24),
                "reject wireless interface");
        require(!EthernetTransportContract.accepts(true, "eth1", "10.57.23.2", 24),
                "reject alternate Ethernet interface");
        require(!EthernetTransportContract.accepts(true, "eth0", "10.57.23.3", 24),
                "reject alternate mobile address");
        require(!EthernetTransportContract.accepts(true, "eth0", "10.57.23.2", 16),
                "reject alternate prefix");
        require("eth0 10.57.23.2/24".equals(EthernetTransportContract.requiredLink()),
                "fixed link diagnostic");
        requireReason(false, "eth0", "10.57.23.2", 24, "transport_not_ethernet");
        requireReason(true, null, "10.57.23.2", 24, "interface_name_missing");
        requireReason(true, "eth1", "10.57.23.2", 24, "interface_name_mismatch");
        requireReason(true, "eth0", null, 24, "ip_address_missing");
        requireReason(true, "eth0", "10.57.23.3", 24, "ip_address_mismatch");
        requireReason(true, "eth0", "10.57.23.2", 16, "prefix_length_mismatch");
        EthernetTransportContract.Validation accepted =
                EthernetTransportContract.evaluate(true, "eth0", "10.57.23.2", 24);
        require(accepted.accepted && "accepted".equals(accepted.reason),
                "accepted validation reason");
    }

    private static void requireReason(
            boolean ethernet, String interfaceName, String ipv4, int prefixLength,
            String expectedReason) {
        EthernetTransportContract.Validation validation =
                EthernetTransportContract.evaluate(
                        ethernet, interfaceName, ipv4, prefixLength);
        require(!validation.accepted && validation.reason.startsWith(expectedReason),
                "rejection reason " + expectedReason);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
