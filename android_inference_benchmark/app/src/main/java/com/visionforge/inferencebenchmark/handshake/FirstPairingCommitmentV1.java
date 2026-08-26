package com.visionforge.inferencebenchmark.handshake;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

/** Frozen cross-language commitment for a user-confirmed first pairing. */
public final class FirstPairingCommitmentV1 {
    public static final int ATTEMPT_ID_BYTES = 16;
    public static final int CANONICAL_BYTES = 368;
    public static final int CAPABILITY_TWO_SIDED_USER_CONFIRMATION = 1;
    public static final int TRANSPORT_ETHERNET = 1;
    private static final byte[] MAGIC = {'V', 'F', 'P', '1'};
    private static final byte VERSION = 1;
    private static final byte[] SAS_DOMAIN =
            "visionforge-dual-machine-first-pairing-sas-v1"
                    .getBytes(StandardCharsets.US_ASCII);
    private static final long SAS_ACCEPT_LIMIT =
            (1L << 32) / 1_000_000L * 1_000_000L;

    public static final class Fields {
        public final int transportKind;
        public final int requiredCapabilities;
        private final byte[] attemptId;
        private final byte[] hostIdentitySpkiSha256;
        private final byte[] androidIdentitySpkiSha256;
        private final byte[] hostEphemeralPublicKey;
        private final byte[] androidEphemeralPublicKey;
        private final byte[] hostNonce;
        private final byte[] androidNonce;
        private final byte[] hostIpv4;
        private final byte[] androidIpv4;
        public final int videoPort;
        public final int controlPort;
        private final byte[] hostRuntimeVersionSha256;
        private final byte[] androidRuntimeVersionSha256;
        public final long expiresAtEpoch;

        public Fields(
                int transportKind,
                int requiredCapabilities,
                byte[] attemptId,
                byte[] hostIdentitySpkiSha256,
                byte[] androidIdentitySpkiSha256,
                byte[] hostEphemeralPublicKey,
                byte[] androidEphemeralPublicKey,
                byte[] hostNonce,
                byte[] androidNonce,
                byte[] hostIpv4,
                byte[] androidIpv4,
                int videoPort,
                int controlPort,
                byte[] hostRuntimeVersionSha256,
                byte[] androidRuntimeVersionSha256,
                long expiresAtEpoch) {
            this.transportKind = transportKind;
            this.requiredCapabilities = requiredCapabilities;
            this.attemptId = copy(attemptId);
            this.hostIdentitySpkiSha256 = copy(hostIdentitySpkiSha256);
            this.androidIdentitySpkiSha256 = copy(androidIdentitySpkiSha256);
            this.hostEphemeralPublicKey = copy(hostEphemeralPublicKey);
            this.androidEphemeralPublicKey = copy(androidEphemeralPublicKey);
            this.hostNonce = copy(hostNonce);
            this.androidNonce = copy(androidNonce);
            this.hostIpv4 = copy(hostIpv4);
            this.androidIpv4 = copy(androidIpv4);
            this.videoPort = videoPort;
            this.controlPort = controlPort;
            this.hostRuntimeVersionSha256 = copy(hostRuntimeVersionSha256);
            this.androidRuntimeVersionSha256 = copy(androidRuntimeVersionSha256);
            this.expiresAtEpoch = expiresAtEpoch;
        }
    }

    public static final class Result implements AutoCloseable {
        private byte[] canonicalEncoding;
        private byte[] commitmentSha256;
        private String decimalSas;
        private boolean closed;

        private Result(
                byte[] canonicalEncoding,
                byte[] commitmentSha256,
                String decimalSas) {
            this.canonicalEncoding = canonicalEncoding;
            this.commitmentSha256 = commitmentSha256;
            this.decimalSas = decimalSas;
        }

        public synchronized byte[] canonicalEncoding()
                throws GeneralSecurityException {
            requireOpen();
            return canonicalEncoding.clone();
        }

        public synchronized byte[] commitmentSha256()
                throws GeneralSecurityException {
            requireOpen();
            return commitmentSha256.clone();
        }

        public synchronized String decimalSas()
                throws GeneralSecurityException {
            requireOpen();
            return decimalSas;
        }

        @Override
        public synchronized void close() {
            if (closed) return;
            closed = true;
            clear(canonicalEncoding);
            canonicalEncoding = null;
            clear(commitmentSha256);
            commitmentSha256 = null;
            decimalSas = null;
        }

        private void requireOpen() throws GeneralSecurityException {
            if (closed || canonicalEncoding == null
                    || commitmentSha256 == null || decimalSas == null) {
                throw rejected();
            }
        }
    }

    private FirstPairingCommitmentV1() {}

    public static Result build(Fields fields) throws GeneralSecurityException {
        requireFields(fields);
        ByteBuffer encoded = ByteBuffer.allocate(CANONICAL_BYTES)
                .order(ByteOrder.BIG_ENDIAN);
        encoded.put(MAGIC);
        encoded.put(VERSION);
        encoded.put((byte) fields.transportKind);
        encoded.putInt(fields.requiredCapabilities);
        encoded.put(fields.attemptId);
        encoded.put(fields.hostIdentitySpkiSha256);
        encoded.put(fields.androidIdentitySpkiSha256);
        encoded.put(fields.hostEphemeralPublicKey);
        encoded.put(fields.androidEphemeralPublicKey);
        encoded.put(fields.hostNonce);
        encoded.put(fields.androidNonce);
        encoded.put(fields.hostIpv4);
        encoded.put(fields.androidIpv4);
        encoded.putShort((short) fields.videoPort);
        encoded.putShort((short) fields.controlPort);
        encoded.put(fields.hostRuntimeVersionSha256);
        encoded.put(fields.androidRuntimeVersionSha256);
        encoded.putLong(fields.expiresAtEpoch);
        if (encoded.position() != CANONICAL_BYTES) throw rejected();
        byte[] canonical = encoded.array();
        byte[] commitment = sha256(canonical);
        try {
            return new Result(canonical, commitment, deriveSas(commitment));
        } catch (GeneralSecurityException failure) {
            clear(canonical);
            clear(commitment);
            throw failure;
        }
    }

    private static String deriveSas(byte[] commitment)
            throws GeneralSecurityException {
        byte[] message = new byte[SAS_DOMAIN.length + 1 + 32 + 1];
        System.arraycopy(SAS_DOMAIN, 0, message, 0, SAS_DOMAIN.length);
        System.arraycopy(
                commitment, 0, message, SAS_DOMAIN.length + 1, 32);
        try {
            for (int counter = 0; counter <= 0xff; counter++) {
                message[message.length - 1] = (byte) counter;
                byte[] digest = sha256(message);
                long candidate = ByteBuffer.wrap(digest)
                        .order(ByteOrder.BIG_ENDIAN).getInt() & 0xffff_ffffL;
                clear(digest);
                if (candidate >= SAS_ACCEPT_LIMIT) continue;
                return String.format(Locale.ROOT, "%06d", candidate % 1_000_000L);
            }
            throw rejected();
        } finally {
            clear(message);
        }
    }

    private static void requireFields(Fields fields)
            throws GeneralSecurityException {
        if (fields == null
                || fields.transportKind != TRANSPORT_ETHERNET
                || fields.requiredCapabilities
                        != CAPABILITY_TWO_SIDED_USER_CONFIRMATION
                || !valid(fields.attemptId, ATTEMPT_ID_BYTES)
                || !valid(fields.hostIdentitySpkiSha256, 32)
                || !valid(fields.androidIdentitySpkiSha256, 32)
                || MessageDigest.isEqual(
                        fields.hostIdentitySpkiSha256,
                        fields.androidIdentitySpkiSha256)
                || !validP256(fields.hostEphemeralPublicKey)
                || !validP256(fields.androidEphemeralPublicKey)
                || MessageDigest.isEqual(
                        fields.hostEphemeralPublicKey,
                        fields.androidEphemeralPublicKey)
                || !valid(fields.hostNonce, 32)
                || !valid(fields.androidNonce, 32)
                || MessageDigest.isEqual(fields.hostNonce, fields.androidNonce)
                || !valid(fields.hostIpv4, 4)
                || !valid(fields.androidIpv4, 4)
                || MessageDigest.isEqual(fields.hostIpv4, fields.androidIpv4)
                || fields.videoPort <= 0 || fields.videoPort > 65_535
                || fields.controlPort <= 0 || fields.controlPort > 65_535
                || fields.videoPort == fields.controlPort
                || !valid(fields.hostRuntimeVersionSha256, 32)
                || !valid(fields.androidRuntimeVersionSha256, 32)
                || fields.expiresAtEpoch <= 0L) {
            throw rejected();
        }
    }

    private static boolean validP256(byte[] value) {
        return valid(value, 65) && value[0] == 0x04;
    }

    private static boolean valid(byte[] value, int length) {
        if (value == null || value.length != length) return false;
        int aggregate = 0;
        for (byte item : value) aggregate |= item & 0xff;
        return aggregate != 0;
    }

    private static byte[] sha256(byte[] value)
            throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(value);
    }

    private static byte[] copy(byte[] value) {
        return value == null ? null : value.clone();
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    private static GeneralSecurityException rejected() {
        return new GeneralSecurityException(
                "first pairing commitment was rejected");
    }
}
