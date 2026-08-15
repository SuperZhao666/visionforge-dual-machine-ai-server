package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

/** Android adapter that keeps public authentication off the CAT6 network. */
public final class AndroidDualMachineHttpsConnectionFactory
        implements DualMachineHttpsJsonTransport.ConnectionFactory {
    private final AndroidValidatedInternetNetworkProvider networkProvider;

    public AndroidDualMachineHttpsConnectionFactory(
            AndroidValidatedInternetNetworkProvider networkProvider) {
        if (networkProvider == null) {
            throw new IllegalArgumentException("networkProvider is required");
        }
        this.networkProvider = networkProvider;
    }

    @Override
    public URLConnection open(URL url) throws IOException {
        return networkProvider.openConnection(url);
    }
}
