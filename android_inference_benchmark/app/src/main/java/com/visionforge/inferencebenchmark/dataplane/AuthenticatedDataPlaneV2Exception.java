package com.visionforge.inferencebenchmark.dataplane;

import java.security.GeneralSecurityException;

/** Checked failure from authenticated data-plane packet processing. */
public final class AuthenticatedDataPlaneV2Exception extends GeneralSecurityException {
    private static final long serialVersionUID = 1L;

    private final Reason reason;

    AuthenticatedDataPlaneV2Exception(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    AuthenticatedDataPlaneV2Exception(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }

    public enum Reason {
        AUTHENTICATION_FAILED,
        CLOSED,
        COUNTER_EXHAUSTED,
        COUNTER_LIMIT_EXCEEDED,
        CRYPTO_UNAVAILABLE,
        DOMAIN_MISMATCH,
        MALFORMED_ENVELOPE,
        PAYLOAD_TOO_LARGE,
        REPLAY_DUPLICATE,
        REPLAY_TOO_OLD,
        UNAUTHENTICATED_PACKET,
        UNSUPPORTED_VERSION
    }
}
