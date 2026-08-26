package com.visionforge.inferencebenchmark;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/** Strict request/response codec for one authenticated Host start claim. */
final class AuthenticatedHostStartIntentClaimV1 {
    static final int REQUEST_NONCE_BYTES = 16;
    static final int RESPONSE_BYTES = 32;

    static final class Claim {
        final long connectionId;
        final long intentToken;

        Claim(long connectionId, long intentToken) {
            this.connectionId = connectionId;
            this.intentToken = intentToken;
        }

        boolean present() {
            return connectionId != 0L && intentToken > 0L;
        }
    }

    private AuthenticatedHostStartIntentClaimV1() {}

    static byte[] encodeRequest(byte[] requestNonce)
            throws GeneralSecurityException {
        if (requestNonce == null
                || requestNonce.length != REQUEST_NONCE_BYTES) {
            throw new GeneralSecurityException(
                    "Host start-intent request nonce is invalid");
        }
        return requestNonce.clone();
    }

    static Claim decodeResponse(
            byte[] expectedRequestNonce,
            long expectedConnectionId,
            byte[] response) throws GeneralSecurityException {
        if (expectedRequestNonce == null
                || expectedRequestNonce.length != REQUEST_NONCE_BYTES
                || expectedConnectionId == 0L
                || response == null
                || response.length != RESPONSE_BYTES) {
            throw new GeneralSecurityException(
                    "Host start-intent response shape is invalid");
        }
        byte[] echoedNonce = Arrays.copyOfRange(
                response, 0, REQUEST_NONCE_BYTES);
        try {
            if (!MessageDigest.isEqual(
                    expectedRequestNonce, echoedNonce)) {
                throw new GeneralSecurityException(
                        "Host start-intent response is not request-bound");
            }
        } finally {
            Arrays.fill(echoedNonce, (byte) 0);
        }
        ByteBuffer input = ByteBuffer.wrap(response)
                .order(ByteOrder.BIG_ENDIAN);
        input.position(REQUEST_NONCE_BYTES);
        long connectionId = input.getLong();
        long intentToken = input.getLong();
        if (connectionId != expectedConnectionId || intentToken < 0L) {
            throw new GeneralSecurityException(
                    "Host start-intent response binding is invalid");
        }
        return new Claim(connectionId, intentToken);
    }
}
