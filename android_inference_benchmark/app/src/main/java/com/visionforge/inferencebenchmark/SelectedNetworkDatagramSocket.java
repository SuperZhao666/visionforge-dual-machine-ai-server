package com.visionforge.inferencebenchmark;

import android.net.Network;
import android.system.ErrnoException;
import android.system.OsConstants;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;

/**
 * Binds UDP sockets to one selected Android route without ever using a wildcard address.
 *
 * <p>Some vendor Android builds return {@code EPERM}/{@code EACCES} from
 * {@link Network#bindSocket(DatagramSocket)} while a non-bypassable VPN owns the default
 * route. The selected route can still be pinned safely by binding the socket to the exact
 * local IPv4 published by that same {@link Network}. Only those two permission failures may
 * use this fallback; stale handles, unavailable addresses and every other error remain
 * fail-closed.</p>
 */
final class SelectedNetworkDatagramSocket {
    enum BindingMode {
        NETWORK_HANDLE,
        EXACT_LOCAL_IPV4_FALLBACK
    }

    private SelectedNetworkDatagramSocket() {}

    static BindingMode bind(
            MobileTransportEndpoint endpoint,
            DatagramSocket socket,
            int port) throws IOException {
        if (endpoint == null || !endpoint.isReadyForDataPlane()) {
            throw new IOException("selected UDP endpoint is unavailable");
        }
        return bindExactLocalIpv4(
                endpoint.network,
                InetAddress.getByName(endpoint.localIpv4),
                socket,
                port);
    }

    static BindingMode bindExactLocalIpv4(
            Network network,
            InetAddress localAddress,
            DatagramSocket socket,
            int port) throws IOException {
        if (network == null || localAddress == null || socket == null
                || localAddress.isAnyLocalAddress()
                || port < 0 || port > 65_535
                || socket.isBound()) {
            throw new IllegalArgumentException("invalid selected UDP socket binding");
        }
        if (socket.isClosed()) {
            throw new SocketException("selected UDP socket is closed");
        }

        IOException networkBindFailure = null;
        BindingMode mode = BindingMode.NETWORK_HANDLE;
        try {
            network.bindSocket(socket);
        } catch (IOException failure) {
            if (!isPermissionDeniedNetworkBind(failure)) throw failure;
            networkBindFailure = failure;
            mode = BindingMode.EXACT_LOCAL_IPV4_FALLBACK;
        }

        try {
            socket.bind(new InetSocketAddress(localAddress, port));
        } catch (IOException failure) {
            if (networkBindFailure != null) failure.addSuppressed(networkBindFailure);
            throw failure;
        }
        return mode;
    }

    static boolean isPermissionDeniedNetworkBind(IOException failure) {
        Throwable current = failure;
        while (current != null) {
            if (current instanceof ErrnoException) {
                int errno = ((ErrnoException) current).errno;
                return errno == OsConstants.EPERM || errno == OsConstants.EACCES;
            }
            current = current.getCause();
        }
        return false;
    }
}
