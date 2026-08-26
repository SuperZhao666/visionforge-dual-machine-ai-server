package com.visionforge.inferencebenchmark.handshake;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/** Frozen VFU1 payload signed only after a local first-pairing UI confirmation. */
public final class FirstPairingUserConfirmationV1 {
    public static final int ROLE_HOST = 1;
    public static final int ROLE_ANDROID = 2;
    public static final int METHOD_DECIMAL_SAS = 1;
    public static final int METHOD_QR = 2;
    public static final int CANONICAL_BYTES = 64;
    private static final byte[] MAGIC = {'V', 'F', 'U', '1'};
    private static final byte VERSION = 1;

    public static final class Result implements AutoCloseable {
        private byte[] canonicalEncoding;
        private byte[] payloadSha256;
        private boolean closed;

        private Result(byte[] canonicalEncoding, byte[] payloadSha256) {
            this.canonicalEncoding = canonicalEncoding;
            this.payloadSha256 = payloadSha256;
        }

        public synchronized byte[] canonicalEncoding()
                throws GeneralSecurityException {
            requireOpen();
            return canonicalEncoding.clone();
        }

        public synchronized byte[] payloadSha256()
                throws GeneralSecurityException {
            requireOpen();
            return payloadSha256.clone();
        }

        @Override
        public synchronized void close() {
            if (closed) return;
            closed = true;
            clear(canonicalEncoding);
            canonicalEncoding = null;
            clear(payloadSha256);
            payloadSha256 = null;
        }

        private void requireOpen() throws GeneralSecurityException {
            if (closed || canonicalEncoding == null || payloadSha256 == null) {
                throw rejected();
            }
        }
    }

    private FirstPairingUserConfirmationV1() {}

    public static Result build(
            int role,
            int method,
            byte[] attemptId,
            byte[] commitmentSha256,
            long expiresAtEpoch) throws GeneralSecurityException {
        if ((role != ROLE_HOST && role != ROLE_ANDROID)
                || (method != METHOD_DECIMAL_SAS && method != METHOD_QR)
                || !valid(attemptId, 16)
                || !valid(commitmentSha256, 32)
                || expiresAtEpoch <= 0L) {
            throw rejected();
        }
        byte[] canonical = ByteBuffer.allocate(CANONICAL_BYTES)
                .order(ByteOrder.BIG_ENDIAN)
                .put(MAGIC)
                .put(VERSION)
                .put((byte) role)
                .put((byte) method)
                .put((byte) 0)
                .put(attemptId)
                .put(commitmentSha256)
                .putLong(expiresAtEpoch)
                .array();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical);
        return new Result(canonical, digest);
    }

    private static boolean valid(byte[] value, int expectedLength) {
        if (value == null || value.length != expectedLength) return false;
        int aggregate = 0;
        for (byte item : value) aggregate |= item & 0xff;
        return aggregate != 0;
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    private static GeneralSecurityException rejected() {
        return new GeneralSecurityException(
                "first pairing user confirmation was rejected");
    }
}
