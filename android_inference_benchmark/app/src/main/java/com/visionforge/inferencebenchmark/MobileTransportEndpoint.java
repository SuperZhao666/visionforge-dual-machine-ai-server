package com.visionforge.inferencebenchmark;

import android.net.Network;

/** Immutable network endpoint selected for the mobile UDP data/control path. */
final class MobileTransportEndpoint {
    static final String WIRELESS_DISCOVERY_IPV4 = "239.57.23.57";
    static final String WIRELESS_DISCOVERY_BROADCAST_IPV4 = "255.255.255.255";

    enum Kind {
        CAT6("cat6"),
        WIRELESS_LAN_UDP("wireless_lan_udp");

        final String token;

        Kind(String token) {
            this.token = token;
        }
    }

    final Network network;
    final long networkHandle;
    final Kind kind;
    final String localIpv4;
    final String hostIpv4;
    final boolean hostDiscovered;

    private MobileTransportEndpoint(
            Network network,
            long networkHandle,
            Kind kind,
            String localIpv4,
            String hostIpv4,
            boolean hostDiscovered) {
        this.network = network;
        this.networkHandle = networkHandle;
        this.kind = kind;
        this.localIpv4 = localIpv4;
        this.hostIpv4 = hostIpv4;
        this.hostDiscovered = hostDiscovered;
    }

    static MobileTransportEndpoint cat6(Network network) {
        if (network == null) throw new IllegalArgumentException("CAT6 network is required");
        return new MobileTransportEndpoint(
                network,
                network.getNetworkHandle(),
                Kind.CAT6,
                EthernetTransportContract.MOBILE_IPV4,
                EthernetTransportContract.HOST_IPV4,
                true);
    }

    static MobileTransportEndpoint wirelessLan(Network network, String localIpv4) {
        if (network == null || !isUsableUnicastIpv4(localIpv4)) {
            throw new IllegalArgumentException("usable Wi-Fi network and IPv4 address are required");
        }
        return new MobileTransportEndpoint(
                network,
                network.getNetworkHandle(),
                Kind.WIRELESS_LAN_UDP,
                localIpv4,
                WIRELESS_DISCOVERY_IPV4,
                false);
    }

    MobileTransportEndpoint withDiscoveredHost(String discoveredHostIpv4) {
        if (isCat6()) return this;
        if (!isUsableUnicastIpv4(discoveredHostIpv4)
                || discoveredHostIpv4.equals(localIpv4)) {
            throw new IllegalArgumentException("discovered Host IPv4 is invalid");
        }
        return new MobileTransportEndpoint(
                network,
                networkHandle,
                kind,
                localIpv4,
                discoveredHostIpv4,
                true);
    }

    MobileTransportEndpoint forWirelessHostDiscovery() {
        if (isCat6() || !hostDiscovered) return this;
        return new MobileTransportEndpoint(
                network,
                networkHandle,
                kind,
                localIpv4,
                WIRELESS_DISCOVERY_IPV4,
                false);
    }

    String readyAnnouncementIpv4() {
        return isCat6() ? hostIpv4 : WIRELESS_DISCOVERY_IPV4;
    }

    String readyAnnouncementBroadcastIpv4() {
        return isCat6() ? "" : WIRELESS_DISCOVERY_BROADCAST_IPV4;
    }

    boolean isCat6() {
        return kind == Kind.CAT6;
    }

    boolean isReadyForDataPlane() {
        return networkHandle > 0L && hostDiscovered;
    }

    boolean hasSameDataPlaneRoute(MobileTransportEndpoint other) {
        return other != null
                && networkHandle == other.networkHandle
                && kind == other.kind
                && hostDiscovered == other.hostDiscovered
                && localIpv4.equals(other.localIpv4)
                && hostIpv4.equals(other.hostIpv4);
    }

    String detail() {
        return "transport=" + kind.token
                + " network_handle=" + networkHandle
                + " local_ipv4=" + localIpv4
                + " host_ipv4=" + hostIpv4
                + " host_discovered=" + hostDiscovered;
    }

    static boolean isUsableUnicastIpv4(String value) {
        if (value == null || value.isBlank()) return false;
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) return false;
        int[] octets = new int[4];
        for (int index = 0; index < parts.length; index++) {
            if (parts[index].isEmpty() || parts[index].length() > 3) return false;
            int octet = 0;
            for (int character = 0; character < parts[index].length(); character++) {
                char digit = parts[index].charAt(character);
                if (digit < '0' || digit > '9') return false;
                octet = octet * 10 + digit - '0';
            }
            if (octet > 255) return false;
            octets[index] = octet;
        }
        if (octets[0] == 0 || octets[0] == 127 || octets[0] >= 224) return false;
        return !(octets[0] == 169 && octets[1] == 254)
                && !(octets[0] == 255 && octets[1] == 255
                && octets[2] == 255 && octets[3] == 255);
    }
}
