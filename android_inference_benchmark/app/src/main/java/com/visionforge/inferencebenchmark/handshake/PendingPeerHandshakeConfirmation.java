package com.visionforge.inferencebenchmark.handshake;

/**
 * Unconfirmed handshake state. No traffic material is exposed until both Finished proofs exist.
 */
public final class PendingPeerHandshakeConfirmation implements AutoCloseable {
    private final AuthenticatedPeerHandshakeV1.Role localRole;
    private PeerHandshakeKeySchedule keySchedule;
    private boolean localFinishedCreated;
    private boolean closed;

    private PendingPeerHandshakeConfirmation(
            AuthenticatedPeerHandshakeV1.Role localRole,
            PeerHandshakeKeySchedule keySchedule) {
        this.localRole = localRole;
        this.keySchedule = keySchedule;
    }

    static PendingPeerHandshakeConfirmation derive(
            byte[] sharedSecret,
            byte[] transcriptHash,
            AuthenticatedPeerHandshakeV1.Role localRole)
            throws AuthenticatedPeerHandshakeV1Exception {
        if (localRole == null) throw new IllegalArgumentException("local role is required");
        PeerHandshakeKeySchedule schedule =
                PeerHandshakeKeySchedule.derive(sharedSecret, transcriptHash);
        return new PendingPeerHandshakeConfirmation(localRole, schedule);
    }

    /** Creates the Finished proof for the immutable local role. */
    public synchronized byte[] createLocalFinishedMac()
            throws AuthenticatedPeerHandshakeV1Exception {
        requireOpen();
        try {
            byte[] finished = keySchedule.createFinishedMac(localRole);
            localFinishedCreated = true;
            return finished;
        } catch (AuthenticatedPeerHandshakeV1Exception failure) {
            close();
            throw failure;
        } catch (RuntimeException failure) {
            close();
            throw AuthenticatedPeerHandshakeV1Internals.cryptoFailure();
        }
    }

    /**
     * Confirms the opposite role's Finished proof and consumes this pending state exactly once.
     */
    public synchronized PeerHandshakeSecrets confirmPeerFinishedMac(byte[] untrustedPeerMac)
            throws AuthenticatedPeerHandshakeV1Exception {
        requireOpen();
        if (!localFinishedCreated) {
            close();
            throw AuthenticatedPeerHandshakeV1Internals.unauthenticatedFailure();
        }
        AuthenticatedPeerHandshakeV1.Role peerRole =
                localRole == AuthenticatedPeerHandshakeV1.Role.HOST
                        ? AuthenticatedPeerHandshakeV1.Role.ANDROID
                        : AuthenticatedPeerHandshakeV1.Role.HOST;
        try {
            if (!keySchedule.verifiesFinishedMac(peerRole, untrustedPeerMac)) {
                close();
                throw AuthenticatedPeerHandshakeV1Internals.unauthenticatedFailure();
            }
            PeerHandshakeSecrets confirmed = keySchedule.confirmedSecrets();
            close();
            return confirmed;
        } catch (AuthenticatedPeerHandshakeV1Exception failure) {
            close();
            throw failure;
        } catch (RuntimeException failure) {
            close();
            throw AuthenticatedPeerHandshakeV1Internals.cryptoFailure();
        }
    }

    @Override
    public synchronized void close() {
        if (closed) return;
        closed = true;
        localFinishedCreated = false;
        PeerHandshakeKeySchedule schedule = keySchedule;
        keySchedule = null;
        if (schedule != null) schedule.close();
    }

    private void requireOpen() throws AuthenticatedPeerHandshakeV1Exception {
        if (closed || keySchedule == null) {
            throw AuthenticatedPeerHandshakeV1Internals.closedFailure();
        }
    }
}
