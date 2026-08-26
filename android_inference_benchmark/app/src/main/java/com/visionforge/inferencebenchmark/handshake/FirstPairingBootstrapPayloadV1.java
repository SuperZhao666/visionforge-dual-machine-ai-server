package com.visionforge.inferencebenchmark.handshake;

import com.visionforge.inferencebenchmark.DualMachinePairingIdentityCodec;
import com.visionforge.inferencebenchmark.DualMachineUsageAuthorizationContract;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** Strict cross-language payloads for the first-pairing VFB1 records. */
public final class FirstPairingBootstrapPayloadV1 {
    private static final int VERSION = 1;
    private static final int OFFER_BYTES = 256;
    private static final int MAX_ACTIVATION_PROOF_BYTES = 2_048;
    private static final byte[] HOST_OFFER_MAGIC = {'V', 'F', 'H', 'O'};
    private static final byte[] ANDROID_OFFER_MAGIC = {'V', 'F', 'A', 'O'};
    private static final byte[] CONFIRMATION_MAGIC = {'V', 'F', 'C', 'F'};
    private static final byte[] ACTIVATION_REQUEST_MAGIC = {'V', 'F', 'A', 'R'};
    private static final byte[] ACTIVATION_SIGNATURE_MAGIC = {'V', 'F', 'A', 'S'};
    private static final byte[] ACTIVATION_RESULT_MAGIC = {'V', 'F', 'R', 'S'};
    private static final byte[] COMPLETE_MAGIC = {'V', 'F', 'P', 'C'};

    private FirstPairingBootstrapPayloadV1() {}

    public static final class Offer {
        public final int requiredCapabilities;
        public final int confirmationMethod;
        private final byte[] attemptId;
        private final byte[] identitySpkiDer;
        private final byte[] ephemeralPublicKey;
        private final byte[] nonce;
        private final byte[] runtimeVersionSha256;
        public final long expiresAtEpoch;

        public Offer(
                int requiredCapabilities,
                int confirmationMethod,
                byte[] attemptId,
                byte[] identitySpkiDer,
                byte[] ephemeralPublicKey,
                byte[] nonce,
                byte[] runtimeVersionSha256,
                long expiresAtEpoch) throws GeneralSecurityException {
            this.requiredCapabilities = requiredCapabilities;
            this.confirmationMethod = confirmationMethod;
            this.attemptId = copy(attemptId);
            this.identitySpkiDer = copy(identitySpkiDer);
            this.ephemeralPublicKey = copy(ephemeralPublicKey);
            this.nonce = copy(nonce);
            this.runtimeVersionSha256 = copy(runtimeVersionSha256);
            this.expiresAtEpoch = expiresAtEpoch;
            requireValidOffer(this);
        }

        public byte[] attemptId() { return attemptId.clone(); }
        public byte[] identitySpkiDer() { return identitySpkiDer.clone(); }
        public byte[] ephemeralPublicKey() {
            return ephemeralPublicKey.clone();
        }
        public byte[] nonce() { return nonce.clone(); }
        public byte[] runtimeVersionSha256() {
            return runtimeVersionSha256.clone();
        }
    }

    public static final class Confirmation {
        public final int role;
        public final int method;
        private final byte[] attemptId;
        private final byte[] commitmentSha256;
        public final long expiresAtEpoch;
        private final byte[] signatureDerLowS;

        public Confirmation(
                int role,
                int method,
                byte[] attemptId,
                byte[] commitmentSha256,
                long expiresAtEpoch,
                byte[] signatureDerLowS) throws GeneralSecurityException {
            this.role = role;
            this.method = method;
            this.attemptId = copy(attemptId);
            this.commitmentSha256 = copy(commitmentSha256);
            this.expiresAtEpoch = expiresAtEpoch;
            this.signatureDerLowS = copy(signatureDerLowS);
            validateConfirmation(this);
        }

        public byte[] attemptId() { return attemptId.clone(); }
        public byte[] commitmentSha256() {
            return commitmentSha256.clone();
        }
        public byte[] signatureDerLowS() {
            return signatureDerLowS.clone();
        }
    }

    public static final class ActivationSignature {
        private final byte[] canonicalPayloadSha256;
        private final byte[] signatureDerLowS;

        public ActivationSignature(
                byte[] canonicalPayloadSha256,
                byte[] signatureDerLowS) throws GeneralSecurityException {
            this.canonicalPayloadSha256 = copy(canonicalPayloadSha256);
            this.signatureDerLowS = copy(signatureDerLowS);
            if (!validNonzero(this.canonicalPayloadSha256, 32)
                    || !validSignature(this.signatureDerLowS)) {
                throw rejected();
            }
        }

        public byte[] canonicalPayloadSha256() {
            return canonicalPayloadSha256.clone();
        }
        public byte[] signatureDerLowS() {
            return signatureDerLowS.clone();
        }
    }

    public static final class ActivationResult {
        public final String entitlementId;
        public final String pairId;
        public final String bindingId;
        public final long bindingRevision;
        public final long revocationVersion;

        public ActivationResult(
                String entitlementId,
                String pairId,
                String bindingId,
                long bindingRevision,
                long revocationVersion) throws GeneralSecurityException {
            this.entitlementId = lowerHex32(entitlementId);
            this.pairId = lowerHex32(pairId);
            this.bindingId = lowerHex32(bindingId);
            if (bindingRevision <= 0L || revocationVersion < 0L) {
                throw rejected();
            }
            this.bindingRevision = bindingRevision;
            this.revocationVersion = revocationVersion;
        }
    }

    public static byte[] encodeOffer(
            AuthenticatedControlBootstrapRecordV1.MessageType type,
            Offer offer) throws GeneralSecurityException {
        requireOfferType(type);
        requireValidOffer(offer);
        ByteBuffer output = ByteBuffer.allocate(OFFER_BYTES)
                .order(ByteOrder.BIG_ENDIAN);
        output.put(type == AuthenticatedControlBootstrapRecordV1.MessageType
                .HOST_FIRST_PAIR_OFFER ? HOST_OFFER_MAGIC : ANDROID_OFFER_MAGIC);
        output.put((byte) VERSION);
        output.put((byte) offer.confirmationMethod);
        output.putShort((short) 0);
        output.putInt(offer.requiredCapabilities);
        output.put(offer.attemptId);
        output.put(offer.identitySpkiDer);
        output.put(offer.ephemeralPublicKey);
        output.put(offer.nonce);
        output.put(offer.runtimeVersionSha256);
        output.putLong(offer.expiresAtEpoch);
        if (output.hasRemaining()) throw rejected();
        return output.array();
    }

    public static Offer parseOffer(
            AuthenticatedControlBootstrapRecordV1.MessageType type,
            byte[] encoded) throws GeneralSecurityException {
        requireOfferType(type);
        if (encoded == null || encoded.length != OFFER_BYTES) throw rejected();
        Reader reader = new Reader(encoded);
        reader.magic(type == AuthenticatedControlBootstrapRecordV1.MessageType
                .HOST_FIRST_PAIR_OFFER ? HOST_OFFER_MAGIC : ANDROID_OFFER_MAGIC);
        int version = reader.u8();
        int method = reader.u8();
        int reserved = reader.u16();
        int capabilities = reader.i32();
        byte[] attempt = reader.bytes(16);
        byte[] spki = reader.bytes(91);
        byte[] ephemeral = reader.bytes(65);
        byte[] nonce = reader.bytes(32);
        byte[] runtimeHash = reader.bytes(32);
        long expiry = reader.i64();
        reader.finish();
        if (version != VERSION || reserved != 0) throw rejected();
        return new Offer(
                capabilities, method, attempt, spki, ephemeral, nonce,
                runtimeHash, expiry);
    }

    public static byte[] encodeConfirmation(
            AuthenticatedControlBootstrapRecordV1.MessageType type,
            Confirmation confirmation) throws GeneralSecurityException {
        requireConfirmationType(type, confirmation.role);
        validateConfirmation(confirmation);
        ByteBuffer output = ByteBuffer.allocate(
                66 + confirmation.signatureDerLowS.length)
                .order(ByteOrder.BIG_ENDIAN);
        output.put(CONFIRMATION_MAGIC);
        output.put((byte) VERSION);
        output.put((byte) confirmation.role);
        output.put((byte) confirmation.method);
        output.put((byte) 0);
        output.put(confirmation.attemptId);
        output.put(confirmation.commitmentSha256);
        output.putLong(confirmation.expiresAtEpoch);
        output.putShort((short) confirmation.signatureDerLowS.length);
        output.put(confirmation.signatureDerLowS);
        return output.array();
    }

    public static Confirmation parseConfirmation(
            AuthenticatedControlBootstrapRecordV1.MessageType type,
            byte[] encoded) throws GeneralSecurityException {
        if (encoded == null || encoded.length < 74 || encoded.length > 138) {
            throw rejected();
        }
        Reader reader = new Reader(encoded);
        reader.magic(CONFIRMATION_MAGIC);
        int version = reader.u8();
        int role = reader.u8();
        int method = reader.u8();
        int reserved = reader.u8();
        byte[] attempt = reader.bytes(16);
        byte[] commitment = reader.bytes(32);
        long expiry = reader.i64();
        int signatureBytes = reader.u16();
        byte[] signature = reader.bytes(signatureBytes);
        reader.finish();
        if (version != VERSION || reserved != 0) throw rejected();
        requireConfirmationType(type, role);
        return new Confirmation(
                role, method, attempt, commitment, expiry, signature);
    }

    public static byte[] encodeActivationProofRequest(
            DualMachineUsageAuthorizationContract.ActivationConfirmation proof)
            throws GeneralSecurityException {
        validateActivationProof(proof);
        try {
            Writer output = new Writer();
            output.header(ACTIVATION_REQUEST_MAGIC);
            output.string(proof.activationMode);
            output.string(proof.androidClientVersion);
            output.string(proof.androidDeviceCode);
            output.string(proof.androidDeviceProfileSha256);
            output.string(proof.androidKeySha256);
            output.string(proof.challengeId);
            output.string(proof.challengeTokenSha256);
            output.string(proof.hostClientVersion);
            output.string(proof.hostDeviceCode);
            output.string(proof.hostKeySha256);
            output.string(proof.pairId);
            output.i32(proof.protocolVersion);
            output.string(proof.requestId);
            output.string(proof.targetEntitlementId);
            byte[] encoded = output.toByteArray();
            if (encoded.length > MAX_ACTIVATION_PROOF_BYTES) throw rejected();
            return encoded;
        } catch (RuntimeException failure) {
            throw rejected(failure);
        }
    }

    public static DualMachineUsageAuthorizationContract.ActivationConfirmation
            parseActivationProofRequest(byte[] encoded)
            throws GeneralSecurityException {
        if (encoded == null || encoded.length < 8
                || encoded.length > MAX_ACTIVATION_PROOF_BYTES) {
            throw rejected();
        }
        Reader reader = new Reader(encoded);
        reader.header(ACTIVATION_REQUEST_MAGIC);
        DualMachineUsageAuthorizationContract.ActivationConfirmation proof =
                new DualMachineUsageAuthorizationContract.ActivationConfirmation();
        proof.activationMode = reader.string(16, false);
        proof.androidClientVersion = reader.string(80, false);
        proof.androidDeviceCode = reader.string(128, false);
        proof.androidDeviceProfileSha256 = reader.string(64, false);
        proof.androidKeySha256 = reader.string(64, false);
        proof.challengeId = reader.string(32, false);
        proof.challengeTokenSha256 = reader.string(64, false);
        proof.hostClientVersion = reader.string(80, false);
        proof.hostDeviceCode = reader.string(128, false);
        proof.hostKeySha256 = reader.string(64, false);
        proof.pairId = reader.string(32, false);
        proof.protocolVersion = reader.i32();
        proof.requestId = reader.string(32, false);
        proof.targetEntitlementId = reader.string(32, true);
        reader.finish();
        validateActivationProof(proof);
        return proof;
    }

    public static byte[] encodeActivationSignature(ActivationSignature value)
            throws GeneralSecurityException {
        if (value == null) throw rejected();
        ByteBuffer output = ByteBuffer.allocate(
                42 + value.signatureDerLowS.length)
                .order(ByteOrder.BIG_ENDIAN);
        putHeader(output, ACTIVATION_SIGNATURE_MAGIC);
        output.put(value.canonicalPayloadSha256);
        output.putShort((short) value.signatureDerLowS.length);
        output.put(value.signatureDerLowS);
        return output.array();
    }

    public static ActivationSignature parseActivationSignature(byte[] encoded)
            throws GeneralSecurityException {
        if (encoded == null || encoded.length < 50 || encoded.length > 114) {
            throw rejected();
        }
        Reader reader = new Reader(encoded);
        reader.header(ACTIVATION_SIGNATURE_MAGIC);
        byte[] digest = reader.bytes(32);
        byte[] signature = reader.bytes(reader.u16());
        reader.finish();
        return new ActivationSignature(digest, signature);
    }

    public static byte[] encodeActivationResult(ActivationResult value)
            throws GeneralSecurityException {
        if (value == null) throw rejected();
        ByteBuffer output = ByteBuffer.allocate(120)
                .order(ByteOrder.BIG_ENDIAN);
        putHeader(output, ACTIVATION_RESULT_MAGIC);
        output.put(value.entitlementId.getBytes(StandardCharsets.US_ASCII));
        output.put(value.pairId.getBytes(StandardCharsets.US_ASCII));
        output.put(value.bindingId.getBytes(StandardCharsets.US_ASCII));
        output.putLong(value.bindingRevision);
        output.putLong(value.revocationVersion);
        return output.array();
    }

    public static ActivationResult parseActivationResult(byte[] encoded)
            throws GeneralSecurityException {
        if (encoded == null || encoded.length != 120) throw rejected();
        Reader reader = new Reader(encoded);
        reader.header(ACTIVATION_RESULT_MAGIC);
        String entitlement = reader.fixedAscii(32);
        String pair = reader.fixedAscii(32);
        String binding = reader.fixedAscii(32);
        long revision = reader.i64();
        long revocation = reader.i64();
        reader.finish();
        return new ActivationResult(
                entitlement, pair, binding, revision, revocation);
    }

    public static byte[] encodeComplete(byte[] commitmentSha256)
            throws GeneralSecurityException {
        if (!validNonzero(commitmentSha256, 32)) throw rejected();
        ByteBuffer output = ByteBuffer.allocate(40)
                .order(ByteOrder.BIG_ENDIAN);
        putHeader(output, COMPLETE_MAGIC);
        output.put(commitmentSha256);
        return output.array();
    }

    public static byte[] parseComplete(byte[] encoded)
            throws GeneralSecurityException {
        if (encoded == null || encoded.length != 40) throw rejected();
        Reader reader = new Reader(encoded);
        reader.header(COMPLETE_MAGIC);
        byte[] commitment = reader.bytes(32);
        reader.finish();
        if (!validNonzero(commitment, 32)) throw rejected();
        return commitment;
    }

    private static void requireValidOffer(Offer offer)
            throws GeneralSecurityException {
        if (offer == null
                || offer.requiredCapabilities != FirstPairingCommitmentV1
                        .CAPABILITY_TWO_SIDED_USER_CONFIRMATION
                || (offer.confirmationMethod
                        != FirstPairingUserConfirmationV1.METHOD_DECIMAL_SAS
                    && offer.confirmationMethod
                        != FirstPairingUserConfirmationV1.METHOD_QR)
                || !validNonzero(offer.attemptId, 16)
                || !validNonzero(offer.ephemeralPublicKey, 65)
                || offer.ephemeralPublicKey[0] != 0x04
                || !validNonzero(offer.nonce, 32)
                || !validNonzero(offer.runtimeVersionSha256, 32)
                || offer.expiresAtEpoch <= 0L) {
            throw rejected();
        }
        byte[] canonical = DualMachinePairingIdentityCodec
                .requirePublicKey(offer.identitySpkiDer).getEncoded();
        if (!Arrays.equals(canonical, offer.identitySpkiDer)) throw rejected();
    }

    private static void validateConfirmation(Confirmation value)
            throws GeneralSecurityException {
        if (value == null || !validSignature(value.signatureDerLowS)) {
            throw rejected();
        }
        try (FirstPairingUserConfirmationV1.Result built =
                FirstPairingUserConfirmationV1.build(
                        value.role,
                        value.method,
                        value.attemptId,
                        value.commitmentSha256,
                        value.expiresAtEpoch)) {
            byte[] digest = built.payloadSha256();
            Arrays.fill(digest, (byte) 0);
        }
    }

    private static void validateActivationProof(
            DualMachineUsageAuthorizationContract.ActivationConfirmation proof)
            throws GeneralSecurityException {
        if (proof == null) throw rejected();
        try {
            byte[] canonical = DualMachineUsageAuthorizationContract
                    .activationConfirmation(proof);
            Arrays.fill(canonical, (byte) 0);
        } catch (IllegalArgumentException failure) {
            throw rejected(failure);
        }
    }

    private static void requireOfferType(
            AuthenticatedControlBootstrapRecordV1.MessageType type)
            throws GeneralSecurityException {
        if (type != AuthenticatedControlBootstrapRecordV1.MessageType
                    .HOST_FIRST_PAIR_OFFER
                && type != AuthenticatedControlBootstrapRecordV1.MessageType
                    .ANDROID_FIRST_PAIR_OFFER) {
            throw rejected();
        }
    }

    private static void requireConfirmationType(
            AuthenticatedControlBootstrapRecordV1.MessageType type,
            int role) throws GeneralSecurityException {
        boolean host = type == AuthenticatedControlBootstrapRecordV1.MessageType
                .HOST_FIRST_PAIR_CONFIRMATION
                && role == FirstPairingUserConfirmationV1.ROLE_HOST;
        boolean android = type == AuthenticatedControlBootstrapRecordV1
                .MessageType.ANDROID_FIRST_PAIR_CONFIRMATION
                && role == FirstPairingUserConfirmationV1.ROLE_ANDROID;
        if (!host && !android) throw rejected();
    }

    private static boolean validSignature(byte[] value) {
        return value != null && value.length >= 8 && value.length <= 72
                && value[0] == 0x30
                && (value[1] & 0xff) == value.length - 2;
    }

    private static boolean validNonzero(byte[] value, int size) {
        if (value == null || value.length != size) return false;
        int aggregate = 0;
        for (byte item : value) aggregate |= item & 0xff;
        return aggregate != 0;
    }

    private static String lowerHex32(String value)
            throws GeneralSecurityException {
        if (value == null || value.length() != 32) throw rejected();
        boolean nonzero = false;
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (!((item >= '0' && item <= '9')
                    || (item >= 'a' && item <= 'f'))) throw rejected();
            nonzero |= item != '0';
        }
        if (!nonzero) throw rejected();
        return value;
    }

    private static byte[] copy(byte[] value) {
        return value == null ? null : value.clone();
    }

    private static void putHeader(ByteBuffer output, byte[] magic) {
        output.put(magic);
        output.put((byte) VERSION);
        output.put((byte) 0);
        output.put((byte) 0);
        output.put((byte) 0);
    }

    private static GeneralSecurityException rejected() {
        return new GeneralSecurityException(
                "first pairing bootstrap payload was rejected");
    }

    private static GeneralSecurityException rejected(Throwable cause) {
        return new GeneralSecurityException(
                "first pairing bootstrap payload was rejected", cause);
    }

    private static final class Writer {
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();

        void header(byte[] magic) {
            bytes(magic);
            u8(VERSION);
            u8(0);
            u8(0);
            u8(0);
        }

        void string(String value) {
            if (value == null) throw new IllegalArgumentException();
            byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
            if (bytes.length > 0xffff) throw new IllegalArgumentException();
            u16(bytes.length);
            bytes(bytes);
        }

        void i32(int value) {
            u8(value >>> 24);
            u8(value >>> 16);
            u8(value >>> 8);
            u8(value);
        }

        void u16(int value) {
            u8(value >>> 8);
            u8(value);
        }

        void u8(int value) { output.write(value & 0xff); }

        void bytes(byte[] value) { output.write(value, 0, value.length); }

        byte[] toByteArray() { return output.toByteArray(); }
    }

    private static final class Reader {
        private final ByteBuffer input;

        Reader(byte[] encoded) {
            input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
        }

        void magic(byte[] expected) throws GeneralSecurityException {
            if (!Arrays.equals(bytes(expected.length), expected)) {
                throw rejected();
            }
        }

        void header(byte[] expected) throws GeneralSecurityException {
            magic(expected);
            if (u8() != VERSION || u8() != 0 || u8() != 0 || u8() != 0) {
                throw rejected();
            }
        }

        int u8() throws GeneralSecurityException {
            if (input.remaining() < 1) throw rejected();
            return input.get() & 0xff;
        }

        int u16() throws GeneralSecurityException {
            if (input.remaining() < 2) throw rejected();
            return input.getShort() & 0xffff;
        }

        int i32() throws GeneralSecurityException {
            if (input.remaining() < 4) throw rejected();
            return input.getInt();
        }

        long i64() throws GeneralSecurityException {
            if (input.remaining() < 8) throw rejected();
            long value = input.getLong();
            if (value < 0L) throw rejected();
            return value;
        }

        byte[] bytes(int size) throws GeneralSecurityException {
            if (size < 0 || input.remaining() < size) throw rejected();
            byte[] value = new byte[size];
            input.get(value);
            return value;
        }

        String fixedAscii(int size) throws GeneralSecurityException {
            return ascii(bytes(size), false);
        }

        String string(int maximum, boolean allowEmpty)
                throws GeneralSecurityException {
            int size = u16();
            if (size > maximum || (!allowEmpty && size == 0)) throw rejected();
            return ascii(bytes(size), allowEmpty);
        }

        void finish() throws GeneralSecurityException {
            if (input.hasRemaining()) throw rejected();
        }

        private String ascii(byte[] bytes, boolean allowEmpty)
                throws GeneralSecurityException {
            if (!allowEmpty && bytes.length == 0) throw rejected();
            for (byte item : bytes) {
                int character = item & 0xff;
                if (character < 0x20 || character > 0x7e) throw rejected();
            }
            return new String(bytes, StandardCharsets.US_ASCII);
        }
    }
}
