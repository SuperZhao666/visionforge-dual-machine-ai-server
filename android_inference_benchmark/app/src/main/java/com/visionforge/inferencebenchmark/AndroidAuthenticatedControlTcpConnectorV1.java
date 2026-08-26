package com.visionforge.inferencebenchmark;

import android.net.Network;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlTcpChannelV1;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;

/** Android per-Network adapter for the pure VFB1 TCP channel. */
final class AndroidAuthenticatedControlTcpConnectorV1 {
    private AndroidAuthenticatedControlTcpConnectorV1() {}

    static AuthenticatedControlTcpChannelV1 connect(
            Network selectedLocalNetwork,
            String localIpv4,
            String expectedHostIpv4,
            int hostPort,
            int timeoutMillis)
            throws AuthenticatedControlTcpChannelV1.ChannelException {
        if (selectedLocalNetwork == null) {
            throw invalidConfiguration();
        }
        Socket prepared = null;
        String stage = "socket_open";
        try {
            try {
                prepared = selectedLocalNetwork.getSocketFactory().createSocket();
            } catch (SocketException networkBindingRejected) {
                // Some vendor network stacks reject per-Network fd binding for
                // ordinary apps. The channel still binds the exact IPv4 owned
                // by the selected Network before connect and verifies both
                // connected endpoints, so this never becomes an unbound
                // default-network fallback.
                prepared = new Socket();
            }
            stage = "channel_connect";
            AuthenticatedControlTcpChannelV1 connected =
                    AuthenticatedControlTcpChannelV1.connectPreparedSocket(
                            prepared,
                            localIpv4,
                            expectedHostIpv4,
                            hostPort,
                            timeoutMillis);
            prepared = null;
            return connected;
        } catch (AuthenticatedControlTcpChannelV1.ChannelException rejected) {
            throw rejected;
        } catch (IOException rejected) {
            throw invalidConfiguration("socket_open_io");
        } catch (SecurityException rejected) {
            throw invalidConfiguration("socket_open_security");
        } catch (UnsupportedOperationException rejected) {
            throw invalidConfiguration("socket_open_unsupported");
        } catch (RuntimeException rejected) {
            throw invalidConfiguration(
                    "socket_open".equals(stage)
                            ? "socket_open_runtime"
                            : stage);
        } finally {
            if (prepared != null) {
                try {
                    prepared.close();
                } catch (IOException ignored) {
                    // The candidate socket never became a capability.
                }
            }
        }
    }

    private static AuthenticatedControlTcpChannelV1.ChannelException
            invalidConfiguration() {
        return AuthenticatedControlTcpChannelV1
                .invalidConfigurationFailure();
    }

    private static AuthenticatedControlTcpChannelV1.ChannelException
            invalidConfiguration(String stage) {
        return AuthenticatedControlTcpChannelV1
                .invalidConfigurationFailure(stage);
    }
}
