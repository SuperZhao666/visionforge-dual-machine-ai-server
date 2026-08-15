package com.visionforge.inferencebenchmark;

import java.util.Arrays;
import java.util.Collections;

/** Route isolation regressions for public authentication versus CAT6. */
public final class DualMachineInternetRoutePolicySelfTest {
    private DualMachineInternetRoutePolicySelfTest() {
    }

    public static void main(String[] arguments) {
        rejectsIsolatedEthernetEvenWhenMarkedValidated();
        rejectsUnvalidatedInternet();
        prefersActiveValidatedVpnOverUnderlyingWifi();
        acceptsActiveValidatedVpnWithUnderlyingEthernetCapabilities();
        rejectsUnderlyingWifiWhenActiveVpnIsUnvalidated();
        rejectsInactiveVpnWithoutSafeFallback();
        prefersValidatedWifiOverCellular();
        acceptsValidatedCellularFallback();
        revalidationUsesNewlyActiveValidatedVpn();
        revalidationRejectsUnvalidatedOrDisappearedVpn();
        revalidationRejectsActiveNetworkRace();
        System.out.println("ANDROID_INTERNET_ROUTE_POLICY_OK");
    }

    private static void prefersActiveValidatedVpnOverUnderlyingWifi() {
        int selected = DualMachineInternetRoutePolicy.select(Arrays.asList(
                candidate(true, true, false, true, false,
                        false, false, "wlan0"),
                candidate(true, true, false, true, false,
                        true, true, "tun0")));
        check(selected == 1);
    }

    private static void acceptsActiveValidatedVpnWithUnderlyingEthernetCapabilities() {
        DualMachineInternetRoutePolicy.Candidate vpn = candidate(
                true, true, true, true, false,
                true, true, "eth0");
        int selected = DualMachineInternetRoutePolicy.select(Arrays.asList(
                candidate(true, true, false, true, false,
                        false, false, "wlan0"),
                vpn));
        check(selected == 1);
        check(DualMachineInternetRoutePolicy.eligible(vpn));
    }

    private static void rejectsUnderlyingWifiWhenActiveVpnIsUnvalidated() {
        int selected = DualMachineInternetRoutePolicy.select(Arrays.asList(
                candidate(true, true, false, true, false,
                        false, false, "wlan0"),
                candidate(true, false, false, true, false,
                        true, true, "tun0")));
        check(selected == -1);
    }

    private static void rejectsInactiveVpnWithoutSafeFallback() {
        int selected = DualMachineInternetRoutePolicy.select(
                Collections.singletonList(candidate(
                        true, true, false, true, false,
                        true, false, "tun0")));
        check(selected == -1);
    }

    private static void rejectsIsolatedEthernetEvenWhenMarkedValidated() {
        check(DualMachineInternetRoutePolicy.select(Collections.singletonList(
                candidate(true, true, true, false, false, "eth0"))) == -1);
        check(!DualMachineInternetRoutePolicy.eligible(
                candidate(true, true, false, true, false, "eth0")));
    }

    private static void rejectsUnvalidatedInternet() {
        check(DualMachineInternetRoutePolicy.select(Collections.singletonList(
                candidate(true, false, false, true, false, "wlan0"))) == -1);
        check(DualMachineInternetRoutePolicy.select(Collections.singletonList(
                candidate(false, true, false, false, true, "rmnet0"))) == -1);
    }

    private static void prefersValidatedWifiOverCellular() {
        int selected = DualMachineInternetRoutePolicy.select(Arrays.asList(
                candidate(true, true, false, false, true, "rmnet0"),
                candidate(true, true, false, true, false, "wlan0")));
        check(selected == 1);
    }

    private static void acceptsValidatedCellularFallback() {
        int selected = DualMachineInternetRoutePolicy.select(Arrays.asList(
                candidate(true, false, false, true, false, "wlan0"),
                candidate(true, true, false, false, true, "rmnet0")));
        check(selected == 1);
    }

    private static void revalidationUsesNewlyActiveValidatedVpn() {
        DualMachineInternetRoutePolicy.Candidate wifi = candidate(
                true, true, false, true, false,
                false, false, "wlan0");
        DualMachineInternetRoutePolicy.Candidate activeVpn = candidate(
                true, true, true, true, false,
                true, true, "eth0");
        check(DualMachineInternetRoutePolicy.revalidate(
                wifi, wifi, activeVpn, true)
                == DualMachineInternetRoutePolicy
                .RevalidationDecision.USE_ACTIVE_VPN);
    }

    private static void revalidationRejectsUnvalidatedOrDisappearedVpn() {
        DualMachineInternetRoutePolicy.Candidate wifi = candidate(
                true, true, false, true, false,
                false, false, "wlan0");
        DualMachineInternetRoutePolicy.Candidate activeVpn = candidate(
                true, false, false, true, false,
                true, true, "tun0");
        check(DualMachineInternetRoutePolicy.revalidate(
                wifi, wifi, activeVpn, true)
                == DualMachineInternetRoutePolicy.RevalidationDecision.REJECT);
        DualMachineInternetRoutePolicy.Candidate selectedVpn = candidate(
                true, true, false, true, false,
                true, true, "tun0");
        check(DualMachineInternetRoutePolicy.revalidate(
                selectedVpn, selectedVpn, wifi, true)
                == DualMachineInternetRoutePolicy.RevalidationDecision.REJECT);
    }

    private static void revalidationRejectsActiveNetworkRace() {
        DualMachineInternetRoutePolicy.Candidate wifi = candidate(
                true, true, false, true, false,
                false, false, "wlan0");
        check(DualMachineInternetRoutePolicy.revalidate(
                wifi, wifi, null, false)
                == DualMachineInternetRoutePolicy.RevalidationDecision.REJECT);
    }

    private static DualMachineInternetRoutePolicy.Candidate candidate(
            boolean internet,
            boolean validated,
            boolean ethernet,
            boolean wifi,
            boolean cellular,
            String interfaceName) {
        return new DualMachineInternetRoutePolicy.Candidate(
                internet, validated, ethernet, wifi, cellular, interfaceName);
    }

    private static DualMachineInternetRoutePolicy.Candidate candidate(
            boolean internet,
            boolean validated,
            boolean ethernet,
            boolean wifi,
            boolean cellular,
            boolean vpn,
            boolean active,
            String interfaceName) {
        return new DualMachineInternetRoutePolicy.Candidate(
                internet, validated, ethernet, wifi, cellular,
                vpn, active, interfaceName);
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("check failed");
    }
}
