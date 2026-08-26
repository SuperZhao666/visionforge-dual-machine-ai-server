package com.visionforge.inferencebenchmark;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.util.Arrays;

final class AuthenticatedHostStartIntentClaimV1SelfTest {
    private static final long CONNECTION_ID = 0x1020_3040_5060_7080L;

    static void run() throws Exception {
        acceptsRequestBoundPresentAndEmptyClaims();
        rejectsWrongNonceConnectionAndShape();
    }

    private static void acceptsRequestBoundPresentAndEmptyClaims()
            throws Exception {
        byte[] nonce = nonce();
        byte[] request = AuthenticatedHostStartIntentClaimV1
                .encodeRequest(nonce);
        require(Arrays.equals(nonce, request));
        request[0] ^= 0x7f;
        require(request[0] != nonce[0]);

        byte[] presentResponse = response(nonce, CONNECTION_ID, 7L);
        AuthenticatedHostStartIntentClaimV1.Claim present =
                AuthenticatedHostStartIntentClaimV1.decodeResponse(
                        nonce, CONNECTION_ID, presentResponse);
        require(present.present());
        require(present.connectionId == CONNECTION_ID);
        require(present.intentToken == 7L);

        byte[] emptyResponse = response(nonce, CONNECTION_ID, 0L);
        AuthenticatedHostStartIntentClaimV1.Claim empty =
                AuthenticatedHostStartIntentClaimV1.decodeResponse(
                        nonce, CONNECTION_ID, emptyResponse);
        require(!empty.present());
        clear(nonce, request, presentResponse, emptyResponse);
    }

    private static void rejectsWrongNonceConnectionAndShape()
            throws Exception {
        byte[] nonce = nonce();
        byte[] wrongNonce = nonce.clone();
        wrongNonce[0] ^= 1;
        byte[] valid = response(nonce, CONNECTION_ID, 9L);
        expectRejected(() -> AuthenticatedHostStartIntentClaimV1
                .decodeResponse(wrongNonce, CONNECTION_ID, valid));
        expectRejected(() -> AuthenticatedHostStartIntentClaimV1
                .decodeResponse(nonce, CONNECTION_ID + 1L, valid));
        expectRejected(() -> AuthenticatedHostStartIntentClaimV1
                .decodeResponse(nonce, CONNECTION_ID, new byte[31]));
        byte[] negativeToken = response(nonce, CONNECTION_ID, -1L);
        expectRejected(() -> AuthenticatedHostStartIntentClaimV1
                .decodeResponse(nonce, CONNECTION_ID, negativeToken));
        expectRejected(() -> AuthenticatedHostStartIntentClaimV1
                .encodeRequest(new byte[15]));
        clear(nonce, wrongNonce, valid, negativeToken);
    }

    private static byte[] response(
            byte[] nonce, long connectionId, long token) {
        return ByteBuffer.allocate(
                        AuthenticatedHostStartIntentClaimV1.RESPONSE_BYTES)
                .order(ByteOrder.BIG_ENDIAN)
                .put(nonce)
                .putLong(connectionId)
                .putLong(token)
                .array();
    }

    private static byte[] nonce() {
        byte[] nonce = new byte[
                AuthenticatedHostStartIntentClaimV1.REQUEST_NONCE_BYTES];
        for (int index = 0; index < nonce.length; index++) {
            nonce[index] = (byte) (0xa0 + index);
        }
        return nonce;
    }

    private static void expectRejected(ThrowingAction action)
            throws Exception {
        boolean rejected = false;
        try {
            action.run();
        } catch (GeneralSecurityException expected) {
            rejected = true;
        }
        require(rejected);
    }

    private static void clear(byte[]... values) {
        for (byte[] value : values) {
            if (value != null) Arrays.fill(value, (byte) 0);
        }
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError(
                    "authenticated Host start-intent claim contract failed");
        }
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }
}
