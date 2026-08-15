package com.visionforge.inferencebenchmark;

import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.StringJoiner;

/** Captures and validates CAT6 and wireless-LAN candidates for the mobile transport. */
final class EthernetNetworkDiagnostics {
    private EthernetNetworkDiagnostics() {
    }

    static Evaluation evaluate(
            ConnectivityManager manager, Network network, LinkProperties properties) {
        if (manager == null) {
            return Evaluation.rejected(
                    "connectivity_manager_unavailable",
                    snapshot(network, properties, null));
        }
        if (network == null) {
            return Evaluation.rejected(
                    "network_unavailable",
                    snapshot(null, properties, null));
        }
        NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
        if (capabilities == null) {
            return Evaluation.rejected(
                    "network_capabilities_unavailable",
                    snapshot(network, properties, null));
        }
        if (properties == null) {
            return Evaluation.rejected(
                    "link_properties_unavailable",
                    snapshot(network, null, capabilities));
        }

        boolean ethernet =
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET);
        boolean wifi = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
        if (!ethernet && !wifi) {
            return Evaluation.rejected(
                    "transport_not_ethernet_or_wifi",
                    snapshot(network, properties, capabilities));
        }
        List<LinkAddress> addresses = properties.getLinkAddresses();
        if (addresses.isEmpty()) {
            return Evaluation.rejected(
                    "link_addresses_empty", snapshot(network, properties, capabilities));
        }
        StringJoiner rejectedAddresses = new StringJoiner(",", "[", "]");
        for (LinkAddress address : addresses) {
            InetAddress inetAddress = address.getAddress();
            String ipv4 = inetAddress.getHostAddress();
            if (ethernet) {
                EthernetTransportContract.Validation validation =
                        EthernetTransportContract.evaluate(
                                true,
                                properties.getInterfaceName(),
                                ipv4,
                                address.getPrefixLength());
                if (validation.accepted) {
                    return Evaluation.accepted(
                            "cat6_matched=" + address,
                            snapshot(network, properties, capabilities),
                            MobileTransportEndpoint.cat6(network));
                }
                rejectedAddresses.add(address + "{" + validation.reason + "}");
                continue;
            }
            if (inetAddress instanceof Inet4Address
                    && MobileTransportEndpoint.isUsableUnicastIpv4(ipv4)) {
                return Evaluation.accepted(
                        "wireless_lan_matched=" + address,
                        snapshot(network, properties, capabilities),
                        MobileTransportEndpoint.wirelessLan(network, ipv4));
            }
            rejectedAddresses.add(address + "{wifi_ipv4_not_usable}");
        }
        return Evaluation.rejected(
                "no_link_address_matches_transport_contract evaluations="
                        + rejectedAddresses,
                snapshot(network, properties, capabilities));
    }

    static String kernelInterfaceSnapshot(String interfaceName) {
        StringBuilder detail = new StringBuilder();
        appendKernelInterface(detail, interfaceName);
        return detail.toString();
    }

    private static String snapshot(
            Network network, LinkProperties properties, NetworkCapabilities capabilities) {
        StringBuilder detail = new StringBuilder();
        detail.append("network_handle=")
                .append(network == null ? 0L : network.getNetworkHandle());
        appendCapabilities(detail, capabilities);
        appendLinkProperties(detail, properties);
        appendKernelInterface(detail, EthernetTransportContract.INTERFACE_NAME);
        return detail.toString();
    }

    private static void appendCapabilities(
            StringBuilder detail, NetworkCapabilities capabilities) {
        if (capabilities == null) {
            detail.append(" capabilities=unavailable");
            return;
        }
        detail.append(" transports={ethernet=")
                .append(capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))
                .append(",wifi=")
                .append(capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
                .append(",cellular=")
                .append(capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))
                .append(",vpn=")
                .append(capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
                .append(",bluetooth=")
                .append(capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH))
                .append("} capabilities={validated=")
                .append(capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
                .append(",internet=")
                .append(capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
                .append(",not_vpn=")
                .append(capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))
                .append("} capabilities_raw={")
                .append(capabilities)
                .append('}');
    }

    private static void appendLinkProperties(
            StringBuilder detail, LinkProperties properties) {
        if (properties == null) {
            detail.append(" link_properties=unavailable");
            return;
        }
        detail.append(" interface=")
                .append(valueOrMissing(properties.getInterfaceName()))
                .append(" mtu=")
                .append(properties.getMtu())
                .append(" addresses=")
                .append(joinLinkAddresses(properties.getLinkAddresses()))
                .append(" routes=")
                .append(joinRoutes(properties.getRoutes()))
                .append(" dns=")
                .append(joinAddresses(properties.getDnsServers()))
                .append(" domains=")
                .append(valueOrMissing(properties.getDomains()))
                .append(" private_dns_active=")
                .append(properties.isPrivateDnsActive())
                .append(" private_dns_server=")
                .append(valueOrMissing(properties.getPrivateDnsServerName()))
                .append(" link_properties_raw={")
                .append(properties)
                .append('}');
    }

    private static String joinLinkAddresses(List<LinkAddress> addresses) {
        StringJoiner joined = new StringJoiner(",", "[", "]");
        for (LinkAddress address : addresses) joined.add(address.toString());
        return joined.toString();
    }

    private static String joinRoutes(List<RouteInfo> routes) {
        StringJoiner joined = new StringJoiner(",", "[", "]");
        for (RouteInfo route : routes) joined.add(route.toString());
        return joined.toString();
    }

    private static String joinAddresses(List<InetAddress> addresses) {
        StringJoiner joined = new StringJoiner(",", "[", "]");
        for (InetAddress address : addresses) joined.add(address.getHostAddress());
        return joined.toString();
    }

    private static void appendKernelInterface(StringBuilder detail, String interfaceName) {
        detail.append(" kernel_interface={name=")
                .append(valueOrMissing(interfaceName));
        try {
            NetworkInterface networkInterface = NetworkInterface.getByName(interfaceName);
            if (networkInterface == null) {
                detail.append(" present=false}");
                return;
            }
            boolean hasIpv4 = false;
            boolean hasIpv6LinkLocal = false;
            StringJoiner addresses = new StringJoiner(",", "[", "]");
            Enumeration<InetAddress> addressEnumeration = networkInterface.getInetAddresses();
            for (InetAddress address : Collections.list(addressEnumeration)) {
                addresses.add(address.getHostAddress());
                hasIpv4 |= address instanceof Inet4Address;
                hasIpv6LinkLocal |= address instanceof Inet6Address && address.isLinkLocalAddress();
            }
            detail.append(" present=true")
                    .append(" index=").append(networkInterface.getIndex())
                    .append(" up=").append(networkInterface.isUp())
                    .append(" virtual=").append(networkInterface.isVirtual())
                    .append(" loopback=").append(networkInterface.isLoopback())
                    .append(" mtu=").append(networkInterface.getMTU())
                    .append(" has_ipv4=").append(hasIpv4)
                    .append(" has_ipv6_link_local=").append(hasIpv6LinkLocal)
                    .append(" addresses=").append(addresses)
                    .append('}');
        } catch (SocketException | RuntimeException failure) {
            detail.append(" present=unknown read_failed=")
                    .append(failure.getClass().getSimpleName())
                    .append('}');
        }
    }

    private static String valueOrMissing(String value) {
        return value == null || value.isBlank() ? "missing" : value;
    }

    static final class Evaluation {
        final boolean accepted;
        final String reason;
        final String snapshot;
        final MobileTransportEndpoint endpoint;

        private Evaluation(
                boolean accepted,
                String reason,
                String snapshot,
                MobileTransportEndpoint endpoint) {
            this.accepted = accepted;
            this.reason = reason;
            this.snapshot = snapshot;
            this.endpoint = endpoint;
        }

        static Evaluation accepted(
                String reason,
                String snapshot,
                MobileTransportEndpoint endpoint) {
            return new Evaluation(true, reason, snapshot, endpoint);
        }

        static Evaluation rejected(String reason, String snapshot) {
            return new Evaluation(false, reason, snapshot, null);
        }

        String detail() {
            return "accepted=" + accepted + " rejection_reason="
                    + (accepted ? "none" : reason) + " decision=" + reason
                    + " endpoint={"
                    + (endpoint == null ? "none" : endpoint.detail()) + "}"
                    + " snapshot={" + snapshot + "}";
        }
    }
}
