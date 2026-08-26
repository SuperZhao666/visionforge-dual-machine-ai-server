package com.visionforge.inferencebenchmark;

import android.net.Network;
import android.system.ErrnoException;
import android.system.OsConstants;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

/** Executable contract for the selected-network UDP permission fallback. */
final class SelectedNetworkDatagramSocketSelfTest {
    static void run() throws Exception {
        bindsNormallyThroughTheSelectedNetwork();
        fallsBackOnlyForPermissionDeniedErrnos();
        rejectsWildcardAndInvalidSocketBindings();
    }

    private static void bindsNormallyThroughTheSelectedNetwork() throws Exception {
        try (DatagramSocket socket = new DatagramSocket(null)) {
            SelectedNetworkDatagramSocket.BindingMode mode =
                    SelectedNetworkDatagramSocket.bindExactLocalIpv4(
                            new Network(7L),
                            InetAddress.getLoopbackAddress(),
                            socket,
                            0);
            require(mode == SelectedNetworkDatagramSocket.BindingMode.NETWORK_HANDLE);
            require(socket.isBound());
            require(socket.getLocalAddress().isLoopbackAddress());
        }
    }

    private static void fallsBackOnlyForPermissionDeniedErrnos() throws Exception {
        for (int errno : new int[]{OsConstants.EPERM, OsConstants.EACCES}) {
            try (DatagramSocket socket = new DatagramSocket(null)) {
                SelectedNetworkDatagramSocket.BindingMode mode =
                        SelectedNetworkDatagramSocket.bindExactLocalIpv4(
                                failingNetwork(errno),
                                InetAddress.getLoopbackAddress(),
                                socket,
                                0);
                require(mode == SelectedNetworkDatagramSocket.BindingMode
                        .EXACT_LOCAL_IPV4_FALLBACK);
                require(socket.isBound());
                require(socket.getLocalAddress().isLoopbackAddress());
            }
        }

        IOException staleHandle = networkBindFailure(OsConstants.EPERM + 1);
        try (DatagramSocket socket = new DatagramSocket(null)) {
            expectThrows(IOException.class, () ->
                    SelectedNetworkDatagramSocket.bindExactLocalIpv4(
                            failingNetwork(OsConstants.EPERM + 1),
                            InetAddress.getLoopbackAddress(),
                            socket,
                            0));
            require(!socket.isBound());
        }
        require(!SelectedNetworkDatagramSocket
                .isPermissionDeniedNetworkBind(staleHandle));
    }

    private static void rejectsWildcardAndInvalidSocketBindings() throws Exception {
        try (DatagramSocket socket = new DatagramSocket(null)) {
            expectThrows(IllegalArgumentException.class, () ->
                    SelectedNetworkDatagramSocket.bindExactLocalIpv4(
                            new Network(7L),
                            InetAddress.getByName("0.0.0.0"),
                            socket,
                            0));
        }
        try (DatagramSocket socket = new DatagramSocket(null)) {
            socket.bind(null);
            expectThrows(IllegalArgumentException.class, () ->
                    SelectedNetworkDatagramSocket.bindExactLocalIpv4(
                            new Network(7L),
                            InetAddress.getLoopbackAddress(),
                            socket,
                            0));
        }
    }

    private static Network failingNetwork(int errno) {
        return new Network(7L) {
            @Override
            public void bindSocket(DatagramSocket socket) throws IOException {
                throw networkBindFailure(errno);
            }
        };
    }

    private static IOException networkBindFailure(int errno) {
        SocketException failure = new SocketException("selected network bind failed");
        failure.initCause(new ErrnoException("android_setsocknetwork", errno));
        return failure;
    }

    private static void expectThrows(
            Class<? extends Throwable> type,
            ThrowingAction action) throws Exception {
        try {
            action.run();
        } catch (Throwable failure) {
            if (type.isInstance(failure)) return;
            throw new AssertionError("unexpected failure type", failure);
        }
        throw new AssertionError("expected " + type.getSimpleName());
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("selected UDP binding contract failed");
    }

    private interface ThrowingAction {
        void run() throws Exception;
    }
}
