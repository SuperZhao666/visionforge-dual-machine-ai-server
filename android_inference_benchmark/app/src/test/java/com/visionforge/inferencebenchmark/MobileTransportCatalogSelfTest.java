package com.visionforge.inferencebenchmark;

/** Dependency-free contract for automatic CAT6 preference and Wi-Fi fallback. */
public final class MobileTransportCatalogSelfTest {
    public static void main(String[] arguments) {
        MobileTransportCatalog catalog = new MobileTransportCatalog();
        MobileTransportEndpoint wifi = MobileTransportEndpointTestFixtures.wirelessLan(
                41L, "192.168.1.42");
        require(catalog.upsert(wifi) == wifi, "Wi-Fi is selected when CAT6 is absent");
        require(!wifi.hostDiscovered, "Wi-Fi starts in multicast discovery mode");

        MobileTransportEndpoint discovered = wifi.withDiscoveredHost("192.168.1.18");
        require(wifi.hasSameDataPlaneRoute(wifi),
                "an unchanged endpoint keeps the same data-plane route");
        require(!wifi.hasSameDataPlaneRoute(discovered),
                "Host discovery changes the data-plane route binding");
        require(catalog.upsert(discovered).hostDiscovered, "discovered Host is retained");
        require(catalog.upsert(MobileTransportEndpointTestFixtures.wirelessLan(
                41L, "192.168.1.42")).hostDiscovered,
                "routine Wi-Fi callbacks do not erase Host discovery");
        MobileTransportEndpoint differentDiscoveredHost =
                wifi.withDiscoveredHost("192.168.1.19");
        require(catalog.resetWirelessHostDiscoveryIfSelectedRoute(
                        differentDiscoveredHost).hostDiscovered,
                "a stale observation cannot reset a newer selected Host route");
        MobileTransportEndpoint rediscovery =
                catalog.resetWirelessHostDiscoveryIfSelectedRoute(discovered);
        require(!rediscovery.hostDiscovered,
                "a failed observation can clear its selected Wi-Fi Host binding");
        require(MobileTransportEndpoint.WIRELESS_DISCOVERY_IPV4.equals(
                        rediscovery.hostIpv4),
                "explicit reset returns to multicast discovery");
        require(MobileTransportEndpoint.WIRELESS_DISCOVERY_IPV4.equals(
                        discovered.readyAnnouncementIpv4()),
                "a discovered Wi-Fi Host never replaces the multicast ready destination");
        require(MobileTransportEndpoint.WIRELESS_DISCOVERY_BROADCAST_IPV4.equals(
                        discovered.readyAnnouncementBroadcastIpv4()),
                "Wi-Fi readiness also announces over limited LAN broadcast");
        require(EthernetTransportContract.HOST_IPV4.equals(
                        MobileTransportEndpointTestFixtures.cat6(56L)
                                .readyAnnouncementIpv4()),
                "CAT6 readiness remains fixed unicast");
        require(MobileTransportEndpointTestFixtures.cat6(56L)
                        .readyAnnouncementBroadcastIpv4().isEmpty(),
                "CAT6 readiness never emits a broadcast announcement");

        MobileTransportEndpoint cat6 = MobileTransportEndpointTestFixtures.cat6(57L);
        require(!cat6.hasSameDataPlaneRoute(
                        MobileTransportEndpointTestFixtures.cat6(58L)),
                "a network-handle change invalidates preflight evidence");
        require(catalog.upsert(cat6) == cat6, "CAT6 replaces Wi-Fi automatically");
        require(catalog.upsert(MobileTransportEndpointTestFixtures.wirelessLan(
                42L, "192.168.1.43")) == cat6,
                "Wi-Fi callbacks cannot displace live CAT6");
        require(catalog.resetSelectedWirelessHostDiscovery() == cat6,
                "explicit Wi-Fi reset cannot displace live CAT6");
        require(catalog.remove(57L).networkHandle == 41L,
                "Wi-Fi resumes automatically after CAT6 loss");
        require(catalog.remove(41L).networkHandle == 42L,
                "remaining Wi-Fi candidate is selected");
        require(catalog.remove(42L) == null, "catalog empties after all links are lost");

        MobileTransportCatalog pinnedCatalog = new MobileTransportCatalog();
        MobileTransportEndpoint pinnedWifi =
                MobileTransportEndpointTestFixtures.wirelessLan(
                        61L, "192.168.1.61")
                        .withDiscoveredHost("192.168.1.18");
        pinnedCatalog.upsert(pinnedWifi);
        require(pinnedCatalog.pinForFormalSession(61L) == pinnedWifi,
                "formal session pins its verified data-plane route");
        MobileTransportEndpoint laterCat6 =
                MobileTransportEndpointTestFixtures.cat6(62L);
        require(pinnedCatalog.upsert(laterCat6) == pinnedWifi,
                "a healthier preferred link cannot replace an active formal route");
        require(pinnedCatalog.releaseFormalSessionPin() == laterCat6,
                "the next formal session re-evaluates CAT6 preference");
        require(pinnedCatalog.pinForFormalSession(62L) == laterCat6,
                "the next formal session can pin the new preferred route");
        require(pinnedCatalog.remove(62L) == null,
                "loss of the pinned route fails closed during the formal session");
        require(pinnedCatalog.releaseFormalSessionPin() == pinnedWifi,
                "fallback selection is deferred until the next formal session");

        MobileTransportCatalog immutableRouteCatalog =
                new MobileTransportCatalog();
        MobileTransportEndpoint firstRoute =
                MobileTransportEndpointTestFixtures.wirelessLan(
                        71L, "192.168.1.42")
                        .withDiscoveredHost("192.168.1.18");
        immutableRouteCatalog.upsert(firstRoute);
        immutableRouteCatalog.pinForFormalSession(71L);
        MobileTransportEndpoint changedHost =
                MobileTransportEndpointTestFixtures.wirelessLan(
                        71L, "192.168.1.42")
                        .withDiscoveredHost("192.168.1.19");
        require(immutableRouteCatalog.upsert(changedHost) == null,
                "a same-handle Host route change fails closed");
        require(immutableRouteCatalog.selected() == null,
                "a changed candidate cannot replace the pinned route");
        require(immutableRouteCatalog.releaseFormalSessionPin() == changedHost,
                "the changed Host route becomes eligible between sessions");

        MobileTransportCatalog changedKindCatalog =
                new MobileTransportCatalog();
        MobileTransportEndpoint pinnedCat6 =
                MobileTransportEndpointTestFixtures.cat6(81L);
        changedKindCatalog.upsert(pinnedCat6);
        changedKindCatalog.pinForFormalSession(81L);
        MobileTransportEndpoint sameHandleWifi =
                MobileTransportEndpointTestFixtures.wirelessLan(
                        81L, "192.168.1.52")
                        .withDiscoveredHost("192.168.1.28");
        require(changedKindCatalog.upsert(sameHandleWifi) == null,
                "a same-handle transport kind and address change fails closed");
        require(changedKindCatalog.releaseFormalSessionPin() == sameHandleWifi,
                "the new same-handle route is selectable only after pin release");

        MobileTransportCatalog restoredRouteCatalog =
                new MobileTransportCatalog();
        restoredRouteCatalog.upsert(firstRoute);
        restoredRouteCatalog.pinForFormalSession(71L);
        require(restoredRouteCatalog.upsert(changedHost) == null,
                "route mutation starts fail-closed selection");
        MobileTransportEndpoint restoredRoute =
                MobileTransportEndpointTestFixtures.wirelessLan(
                        71L, "192.168.1.42")
                        .withDiscoveredHost("192.168.1.18");
        require(restoredRouteCatalog.upsert(restoredRoute) == restoredRoute,
                "the exact pinned route may recover on the same handle");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
