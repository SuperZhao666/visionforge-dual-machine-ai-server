package com.visionforge.inferencebenchmark;

import java.util.List;

/**
 * Pure selection policy for the public card-authentication route.
 *
 * <p>The isolated CAT6 Ethernet link has no gateway or DNS and must never be
 * used for Internet authentication. Only Android-validated Wi-Fi or cellular
 * networks are eligible. A validated active VPN is eligible because Android
 * forbids binding sockets around a non-bypassable VPN to its underlying
 * Wi-Fi network.</p>
 */
public final class DualMachineInternetRoutePolicy {
    public static final String ISOLATED_CAT6_INTERFACE = "eth0";

    enum RevalidationDecision {
        USE_SELECTED,
        USE_ACTIVE_VPN,
        REJECT
    }

    public static final class Candidate {
        public final boolean internet;
        public final boolean validated;
        public final boolean ethernet;
        public final boolean wifi;
        public final boolean cellular;
        public final boolean vpn;
        public final boolean active;
        public final String interfaceName;

        public Candidate(
                boolean internet,
                boolean validated,
                boolean ethernet,
                boolean wifi,
                boolean cellular,
                String interfaceName) {
            this(internet, validated, ethernet, wifi, cellular,
                    false, false, interfaceName);
        }

        public Candidate(
                boolean internet,
                boolean validated,
                boolean ethernet,
                boolean wifi,
                boolean cellular,
                boolean vpn,
                boolean active,
                String interfaceName) {
            this.internet = internet;
            this.validated = validated;
            this.ethernet = ethernet;
            this.wifi = wifi;
            this.cellular = cellular;
            this.vpn = vpn;
            this.active = active;
            this.interfaceName = interfaceName == null ? "" : interfaceName;
        }
    }

    private DualMachineInternetRoutePolicy() {
    }

    /**
     * Returns the preferred candidate index, or -1 when no safe route exists.
     * The active validated VPN is preferred when present. Otherwise validated
     * Wi-Fi is preferred over cellular without accepting Ethernet.
     */
    public static int select(List<Candidate> candidates) {
        if (candidates == null) return -1;
        int activeVpn = -1;
        for (int index = 0; index < candidates.size(); index++) {
            Candidate candidate = candidates.get(index);
            if (candidate == null || !candidate.active || !candidate.vpn) {
                continue;
            }
            if (!eligible(candidate)) return -1;
            if (activeVpn < 0) activeVpn = index;
        }
        if (activeVpn >= 0) return activeVpn;
        int cellular = -1;
        for (int index = 0; index < candidates.size(); index++) {
            Candidate candidate = candidates.get(index);
            if (!eligible(candidate)) continue;
            if (!candidate.vpn && candidate.wifi) return index;
            if (!candidate.vpn && cellular < 0 && candidate.cellular) {
                cellular = index;
            }
        }
        return cellular;
    }

    public static boolean eligible(Candidate candidate) {
        if (candidate == null || !candidate.internet || !candidate.validated) {
            return false;
        }
        if (candidate.vpn) return candidate.active;
        if (candidate.ethernet
                || ISOLATED_CAT6_INTERFACE.equals(candidate.interfaceName)) {
            return false;
        }
        return candidate.wifi || candidate.cellular;
    }

    /**
     * Revalidates a snapshot selection against the latest active network.
     * A newly active VPN must take ownership, while a disappeared VPN or an
     * unstable active-network read fails closed instead of exposing its
     * underlying transport.
     */
    static RevalidationDecision revalidate(
            Candidate selectedSnapshot,
            Candidate selectedCurrent,
            Candidate activeCurrent,
            boolean activeNetworkStable) {
        if (!activeNetworkStable) return RevalidationDecision.REJECT;
        if (activeCurrent != null && activeCurrent.vpn) {
            return eligible(activeCurrent)
                    ? RevalidationDecision.USE_ACTIVE_VPN
                    : RevalidationDecision.REJECT;
        }
        if (selectedSnapshot == null || selectedSnapshot.vpn
                || selectedCurrent == null || selectedCurrent.vpn
                || !eligible(selectedCurrent)) {
            return RevalidationDecision.REJECT;
        }
        return RevalidationDecision.USE_SELECTED;
    }
}
