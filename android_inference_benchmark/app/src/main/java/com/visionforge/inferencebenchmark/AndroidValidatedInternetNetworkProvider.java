package com.visionforge.inferencebenchmark;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.List;

/**
 * Opens public-sidecar connections on the selected validated active VPN,
 * Wi-Fi, or cellular network without changing Android's process-wide binding.
 */
public final class AndroidValidatedInternetNetworkProvider {
    private final ConnectivityManager connectivityManager;

    public AndroidValidatedInternetNetworkProvider(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        connectivityManager = (ConnectivityManager)
                context.getApplicationContext().getSystemService(
                        Context.CONNECTIVITY_SERVICE);
        if (connectivityManager == null) {
            throw new IllegalStateException(
                    "ConnectivityManager is unavailable");
        }
    }

    public Network requireValidatedInternetNetwork() throws IOException {
        Network[] networks = connectivityManager.getAllNetworks();
        Network activeNetwork = connectivityManager.getActiveNetwork();
        List<Network> available = new ArrayList<>(networks.length);
        List<DualMachineInternetRoutePolicy.Candidate> candidates =
                new ArrayList<>(networks.length);
        for (Network network : networks) {
            DualMachineInternetRoutePolicy.Candidate candidate =
                    readCandidate(network, network.equals(activeNetwork));
            if (candidate == null) continue;
            available.add(network);
            candidates.add(candidate);
        }
        int selected = DualMachineInternetRoutePolicy.select(candidates);
        if (selected < 0) {
            throw routeUnavailable();
        }
        return revalidateSelectedNetwork(
                available.get(selected), candidates.get(selected));
    }

    public URLConnection openConnection(URL url) throws IOException {
        if (url == null || !"https".equalsIgnoreCase(url.getProtocol())) {
            throw new IOException("dual-machine sidecar requires HTTPS");
        }
        return requireValidatedInternetNetwork().openConnection(url);
    }

    private Network revalidateSelectedNetwork(
            Network selected,
            DualMachineInternetRoutePolicy.Candidate selectedSnapshot)
            throws IOException {
        DualMachineInternetRoutePolicy.Candidate selectedCurrent =
                readCandidate(selected, false);
        Network activeNetwork = connectivityManager.getActiveNetwork();
        DualMachineInternetRoutePolicy.Candidate activeCurrent =
                readCandidate(activeNetwork, true);
        if (activeNetwork != null && activeCurrent == null) {
            throw routeUnavailable();
        }
        Network confirmedActiveNetwork =
                connectivityManager.getActiveNetwork();
        boolean activeNetworkStable = activeNetwork == null
                ? confirmedActiveNetwork == null
                : activeNetwork.equals(confirmedActiveNetwork);
        DualMachineInternetRoutePolicy.RevalidationDecision decision =
                DualMachineInternetRoutePolicy.revalidate(
                        selectedSnapshot,
                        selectedCurrent,
                        activeCurrent,
                        activeNetworkStable);
        if (decision == DualMachineInternetRoutePolicy
                .RevalidationDecision.USE_ACTIVE_VPN) {
            return activeNetwork;
        }
        if (decision == DualMachineInternetRoutePolicy
                .RevalidationDecision.USE_SELECTED) {
            return selected;
        }
        throw routeUnavailable();
    }

    private DualMachineInternetRoutePolicy.Candidate readCandidate(
            Network network,
            boolean active) {
        if (network == null) return null;
        NetworkCapabilities capabilities =
                connectivityManager.getNetworkCapabilities(network);
        if (capabilities == null) return null;
        LinkProperties linkProperties =
                connectivityManager.getLinkProperties(network);
        return new DualMachineInternetRoutePolicy.Candidate(
                capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_INTERNET),
                capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                capabilities.hasTransport(
                        NetworkCapabilities.TRANSPORT_ETHERNET),
                capabilities.hasTransport(
                        NetworkCapabilities.TRANSPORT_WIFI),
                capabilities.hasTransport(
                        NetworkCapabilities.TRANSPORT_CELLULAR),
                capabilities.hasTransport(
                        NetworkCapabilities.TRANSPORT_VPN),
                active,
                linkProperties == null
                        ? "" : linkProperties.getInterfaceName());
    }

    private static IOException routeUnavailable() {
        return new IOException(
                "no validated VPN, Wi-Fi or cellular authentication route");
    }
}
