package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2;
import com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Exception;
import com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Receiver;
import com.visionforge.inferencebenchmark.dataplane.AuthenticatedMouseButtonV2;

import java.security.GeneralSecurityException;
import java.util.Arrays;

/** Confirmed-session-only decoder for the Host-to-Android CAT6 button snapshot. */
final class Cat6MouseButtonProtocol implements AutoCloseable {
    static final int PORT = EthernetTransportContract.MOUSE_BUTTON_PORT;
    static final int VALID_BUTTON_MASK = AuthenticatedMouseButtonV2.VALID_BUTTON_MASK;
    static final int MAX_ENVELOPE_BYTES =
            AuthenticatedDataPlaneV2.AUTHENTICATED_HEADER_BYTES
                    + AuthenticatedMouseButtonV2.PAYLOAD_BYTES
                    + AuthenticatedDataPlaneV2.GCM_TAG_BYTES;
    /** One extra byte lets DatagramPacket expose, and reject, oversized input. */
    static final int RECEIVE_BUFFER_BYTES = MAX_ENVELOPE_BYTES + 1;

    private AuthenticatedDataPlaneV2Receiver receiver;
    private long activeConnectionId;
    private long sessionRevision;

    Cat6MouseButtonProtocol() {}

    /**
     * Installs a defensive key copy obtained from a confirmed peer session.
     * Reinstalling the same connection is idempotent so its replay window is
     * never reset. Any invalid replacement closes the current session.
     */
    synchronized boolean installConfirmedMaterial(
            byte[] trafficMaterial, long connectionId) {
        if (trafficMaterial == null
                || trafficMaterial.length
                != AuthenticatedMouseButtonV2.TRAFFIC_MATERIAL_BYTES
                || connectionId == 0L) {
            clearConfirmedSession();
            return false;
        }
        if (receiver != null && activeConnectionId == connectionId) {
            return true;
        }
        AuthenticatedDataPlaneV2Receiver next;
        try {
            next = AuthenticatedMouseButtonV2.newReceiver(
                    trafficMaterial, connectionId);
        } catch (GeneralSecurityException | RuntimeException invalidCandidate) {
            clearConfirmedSession();
            return false;
        }

        AuthenticatedDataPlaneV2Receiver previous = receiver;
        receiver = next;
        activeConnectionId = connectionId;
        sessionRevision++;
        if (sessionRevision == 0L) sessionRevision = 1L;
        if (previous != null) previous.close();
        return true;
    }

    synchronized boolean sessionReady() {
        return receiver != null;
    }

    synchronized Packet decode(byte[] datagram, int length) {
        if (receiver == null
                || datagram == null
                || length != MAX_ENVELOPE_BYTES
                || datagram.length < length) {
            return null;
        }

        byte[] envelope = Arrays.copyOf(datagram, length);
        byte[] plaintext = null;
        try {
            plaintext = receiver.open(envelope);
            int buttonMask = AuthenticatedMouseButtonV2.decodeButtonMask(plaintext);
            return buttonMask < 0
                    ? null : new Packet(buttonMask, sessionRevision);
        } catch (AuthenticatedDataPlaneV2Exception rejected) {
            if (rejected.reason() == AuthenticatedDataPlaneV2Exception.Reason.CLOSED
                    || rejected.reason()
                    == AuthenticatedDataPlaneV2Exception.Reason.CRYPTO_UNAVAILABLE) {
                clearConfirmedSession();
            }
            return null;
        } finally {
            Arrays.fill(envelope, (byte) 0);
            if (plaintext != null) Arrays.fill(plaintext, (byte) 0);
        }
    }

    synchronized boolean clearConfirmedSession() {
        AuthenticatedDataPlaneV2Receiver previous = receiver;
        receiver = null;
        activeConnectionId = 0L;
        if (previous == null) return false;
        previous.close();
        return true;
    }

    @Override
    public void close() {
        clearConfirmedSession();
    }

    static final class Packet {
        final int buttonMask;
        final long sessionRevision;

        Packet(int buttonMask, long sessionRevision) {
            this.buttonMask = buttonMask;
            this.sessionRevision = sessionRevision;
        }
    }
}
