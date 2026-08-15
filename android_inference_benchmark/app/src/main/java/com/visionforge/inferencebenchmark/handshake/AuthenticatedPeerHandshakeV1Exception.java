package com.visionforge.inferencebenchmark.handshake;

import java.security.GeneralSecurityException;

/** Checked fail-closed result from the authenticated peer-handshake v1 foundation. */
public final class AuthenticatedPeerHandshakeV1Exception extends GeneralSecurityException {
    private static final long serialVersionUID = 1L;

    private final Reason reason;

    AuthenticatedPeerHandshakeV1Exception(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }

    /** Public failures deliberately do not disclose attacker-controlled parsing details. */
    public enum Reason {
        UNAUTHENTICATED_HANDSHAKE,
        CRYPTO_UNAVAILABLE,
        CLOSED
    }
}
