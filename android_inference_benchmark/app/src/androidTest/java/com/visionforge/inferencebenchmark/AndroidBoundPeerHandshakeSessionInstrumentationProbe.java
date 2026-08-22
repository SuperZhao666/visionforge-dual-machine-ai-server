package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1Exception;
import com.visionforge.inferencebenchmark.handshake.FreshP256KeyAgreement;
import com.visionforge.inferencebenchmark.handshake.HandshakeTranscriptV1;
import com.visionforge.inferencebenchmark.handshake.PeerHandshakeSecrets;
import com.visionforge.inferencebenchmark.handshake.PendingPeerHandshakeConfirmation;

import android.os.Build;
import android.security.keystore.KeyInfo;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

/** API-29+ device evidence for the public entitlement-bound Android handshake path. */
final class AndroidBoundPeerHandshakeSessionInstrumentationProbe {
    private static final String PAIR_ID =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static final String ENTITLEMENT_ID =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final byte[] HOST_IPV4 = {
        (byte) 192, (byte) 168, 55, 1
    };
    private static final byte[] ANDROID_IPV4 = {
        (byte) 192, (byte) 168, 55, 2
    };
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private AndroidBoundPeerHandshakeSessionInstrumentationProbe() {}

    static Result verify() throws Exception {
        require(
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
                "bound peer-session probe requires API 29 or newer");
        String alias = "vf-bound-peer-" + Long.toHexString(System.nanoTime());
        try (IdentityFixture identity = new IdentityFixture(alias)) {
            identity.store.getOrCreateIdentity();
            boolean hardwareBacked = isInsideSecureHardware(alias);
            verifySuccessfulPublicBinding(identity);
            verifyAliasMismatchBurnsFresh(identity);
            verifyRecordHashMismatchBurnsFresh(identity);
            return new Result(Build.VERSION.SDK_INT, hardwareBacked);
        }
    }

    private static void verifySuccessfulPublicBinding(IdentityFixture identity)
            throws Exception {
        KeyPair hostIdentity = generateP256Identity();
        try (FreshP256KeyAgreement hostEphemeral =
                        AuthenticatedPeerHandshakeV1
                                .generateFreshEphemeralKeyAgreement();
                FreshP256KeyAgreement androidEphemeral =
                        AuthenticatedPeerHandshakeV1
                                .generateFreshEphemeralKeyAgreement()) {
            SessionContract contract = SessionContract.create(
                    identity, hostIdentity, hostEphemeral, androidEphemeral);
            AndroidBoundPeerHandshakeSession androidBound = null;
            try {
                androidBound = AndroidBoundPeerHandshakeSession.bindExpectedPair(
                        contract.entitlement,
                        identity.store,
                        androidEphemeral,
                        contract.transcript,
                        contract.hostTranscriptSignature);
                verifyAndroidTranscriptSignature(
                        identity.store, contract.transcript, androidBound);
                confirmBothFinished(
                        hostEphemeral,
                        contract.transcript,
                        androidBound,
                        contract);
            } finally {
                if (androidBound != null) androidBound.close();
                contract.close();
            }
        }
    }

    private static void verifyAndroidTranscriptSignature(
            AndroidPairingIdentityStore identity,
            HandshakeTranscriptV1 transcript,
            AndroidBoundPeerHandshakeSession androidBound) throws Exception {
        byte[] canonical = transcript.canonicalEncoding();
        byte[] signature = androidBound.androidTranscriptSignature();
        byte[] androidSpki = identity.publicKeySpkiDer();
        try {
            require(
                    DualMachinePairingIdentityCodec.verify(
                            androidSpki, canonical, signature),
                    "Android must sign the exact checked canonical transcript");
        } finally {
            clear(canonical);
            clear(signature);
            clear(androidSpki);
        }
    }

    private static void confirmBothFinished(
            FreshP256KeyAgreement hostEphemeral,
            HandshakeTranscriptV1 transcript,
            AndroidBoundPeerHandshakeSession androidBound,
            SessionContract contract) throws Exception {
        try (PendingPeerHandshakeConfirmation hostPending =
                        hostEphemeral.deriveAfterPeerIdentityVerified(
                                transcript,
                                AuthenticatedPeerHandshakeV1.Role.HOST)) {
            byte[] androidFinished = null;
            byte[] hostFinished = null;
            ConfirmedAndroidPeerSession androidConfirmed = null;
            try {
                androidFinished = androidBound.createAndroidFinished();
                hostFinished = hostPending.createLocalFinishedMac();
                try (PeerHandshakeSecrets hostConfirmed =
                        hostPending.confirmPeerFinishedMac(androidFinished)) {
                    androidConfirmed = androidBound.confirmHostFinished(hostFinished);
                    requireConfirmedMetadata(contract, androidConfirmed);
                    requireMatchingSecrets(hostConfirmed, androidConfirmed);
                }
            } finally {
                if (androidConfirmed != null) androidConfirmed.close();
                clear(androidFinished);
                clear(hostFinished);
            }
        }
    }

    private static void verifyAliasMismatchBurnsFresh(IdentityFixture identity)
            throws Exception {
        verifyRejectedRecordBurnsFresh(
                identity,
                "vf-unbound-alias",
                identity.store.fingerprintHex(),
                "alias mismatch");
    }

    private static void verifyRecordHashMismatchBurnsFresh(
            IdentityFixture identity) throws Exception {
        verifyRejectedRecordBurnsFresh(
                identity,
                identity.alias,
                repeated('f', 64),
                "record fingerprint mismatch");
    }

    private static void verifyRejectedRecordBurnsFresh(
            IdentityFixture identity,
            String recordAlias,
            String recordAndroidFingerprint,
            String label) throws Exception {
        KeyPair hostIdentity = generateP256Identity();
        try (FreshP256KeyAgreement hostEphemeral =
                        AuthenticatedPeerHandshakeV1
                                .generateFreshEphemeralKeyAgreement();
                FreshP256KeyAgreement androidEphemeral =
                        AuthenticatedPeerHandshakeV1
                                .generateFreshEphemeralKeyAgreement()) {
            SessionContract contract = SessionContract.create(
                    identity, hostIdentity, hostEphemeral, androidEphemeral);
            try {
                DualMachineEntitlementRecord rejectedRecord =
                        contract.entitlement(
                                recordAlias, recordAndroidFingerprint);
                try {
                    AndroidBoundPeerHandshakeSession unexpectedlyBound =
                            AndroidBoundPeerHandshakeSession.bindExpectedPair(
                                    rejectedRecord,
                                    identity.store,
                                    androidEphemeral,
                                    contract.transcript,
                                    contract.hostTranscriptSignature);
                    unexpectedlyBound.close();
                    throw new AssertionError(label + " must fail closed");
                } catch (GeneralSecurityException expected) {
                    require(expected.getCause() == null,
                            label + " must not expose a provider cause");
                }
                requireFreshBurned(androidEphemeral, label);
            } finally {
                contract.close();
            }
        }
    }

    private static void requireConfirmedMetadata(
            SessionContract contract,
            ConfirmedAndroidPeerSession confirmed) throws Exception {
        require(PAIR_ID.equals(confirmed.pairId()), "confirmed pair mismatch");
        require(confirmed.connectionId() == contract.transcript.connectionId(),
                "confirmed connection mismatch");
        require(
                confirmed.sessionGeneration()
                        == contract.transcript.sessionGeneration(),
                "confirmed generation mismatch");
        require(
                confirmed.transportKind()
                        == AuthenticatedPeerHandshakeV1.TransportKind.CAT6,
                "confirmed transport mismatch");
        require(Arrays.equals(HOST_IPV4, confirmed.hostIpv4()),
                "confirmed Host route mismatch");
        require(Arrays.equals(ANDROID_IPV4, confirmed.androidIpv4()),
                "confirmed Android route mismatch");
        require(confirmed.videoPort() == 45678, "confirmed video port mismatch");
        require(confirmed.controlPort() == 45679,
                "confirmed control port mismatch");
        requireEqualAndClear(
                contract.transcript.transcriptHashSha256(),
                confirmed.transcriptHashSha256(),
                "confirmed transcript hash");
    }

    private static void requireMatchingSecrets(
            PeerHandshakeSecrets host,
            ConfirmedAndroidPeerSession android) throws Exception {
        requireEqualAndClear(
                host.controlHostToAndroidMaterial(),
                android.controlHostToAndroidMaterial(), "Host control material");
        requireEqualAndClear(
                host.controlAndroidToHostMaterial(),
                android.controlAndroidToHostMaterial(), "Android control material");
        requireEqualAndClear(
                host.presenceHostToAndroidMaterial(),
                android.presenceHostToAndroidMaterial(), "presence material");
        requireEqualAndClear(
                host.videoHostToAndroidMaterial(),
                android.videoHostToAndroidMaterial(), "video material");
        requireEqualAndClear(
                host.idrAndroidToHostMaterial(),
                android.idrAndroidToHostMaterial(), "IDR material");
        requireEqualAndClear(
                host.mouseHostToAndroidMaterial(),
                android.mouseHostToAndroidMaterial(), "mouse material");
        requireEqualAndClear(
                host.channelBindingSha256(),
                android.channelBindingSha256(), "channel binding");
    }

    private static boolean isInsideSecureHardware(String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        Key key = keyStore.getKey(alias, null);
        require(key instanceof PrivateKey,
                "bound peer identity private key must exist");
        PrivateKey privateKey = (PrivateKey) key;
        KeyFactory keyFactory = KeyFactory.getInstance(
                privateKey.getAlgorithm(), "AndroidKeyStore");
        return keyFactory.getKeySpec(privateKey, KeyInfo.class)
                .isInsideSecureHardware();
    }

    private static KeyPair generateP256Identity() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(
                DualMachinePairingIdentityCodec.CURVE_NAME));
        return generator.generateKeyPair();
    }

    private static byte[] freshNonce() {
        byte[] nonce = new byte[AuthenticatedPeerHandshakeV1.NONCE_BYTES];
        do {
            SECURE_RANDOM.nextBytes(nonce);
        } while (isAllZero(nonce));
        return nonce;
    }

    private static long freshNonZeroLong() {
        long value;
        do {
            value = SECURE_RANDOM.nextLong();
        } while (value == 0L);
        return value;
    }

    private static byte[] sha256(byte[] value) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(value);
    }

    private static boolean isAllZero(byte[] value) {
        int aggregate = 0;
        for (byte current : value) aggregate |= current;
        return aggregate == 0;
    }

    private static void requireFreshBurned(
            FreshP256KeyAgreement fresh, String label) throws Exception {
        try {
            fresh.publicKeySec1();
            throw new AssertionError(label + " must burn fresh ephemeral");
        } catch (AuthenticatedPeerHandshakeV1Exception expected) {
            require(
                    expected.reason()
                            == AuthenticatedPeerHandshakeV1Exception.Reason.CLOSED,
                    label + " must close fresh ephemeral");
            require(expected.getCause() == null,
                    label + " must not leak a provider cause");
        }
    }

    private static void requireEqualAndClear(
            byte[] left, byte[] right, String label) {
        try {
            require(MessageDigest.isEqual(left, right), label + " mismatch");
        } finally {
            clear(left);
            clear(right);
        }
    }

    private static String repeated(char character, int count) {
        StringBuilder value = new StringBuilder(count);
        for (int index = 0; index < count; index++) value.append(character);
        return value.toString();
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    static final class Result {
        final int apiLevel;
        final boolean hardwareBacked;

        private Result(int apiLevel, boolean hardwareBacked) {
            this.apiLevel = apiLevel;
            this.hardwareBacked = hardwareBacked;
        }
    }

    private static final class IdentityFixture implements AutoCloseable {
        private final String alias;
        private final AndroidPairingIdentityStore store;

        private IdentityFixture(String alias) throws Exception {
            this.alias = alias;
            store = new AndroidPairingIdentityStore(alias);
            store.deleteIdentity();
        }

        @Override
        public void close() throws Exception {
            store.deleteIdentity();
        }
    }

    private static final class SessionContract implements AutoCloseable {
        private final KeyPair hostIdentity;
        private final byte[] androidIdentitySpki;
        private final DualMachineEntitlementRecord entitlement;
        private final HandshakeTranscriptV1 transcript;
        private final byte[] hostTranscriptSignature;

        private SessionContract(
                KeyPair hostIdentity,
                byte[] androidIdentitySpki,
                DualMachineEntitlementRecord entitlement,
                HandshakeTranscriptV1 transcript,
                byte[] hostTranscriptSignature) {
            this.hostIdentity = hostIdentity;
            this.androidIdentitySpki = androidIdentitySpki;
            this.entitlement = entitlement;
            this.transcript = transcript;
            this.hostTranscriptSignature = hostTranscriptSignature;
        }

        private static SessionContract create(
                IdentityFixture identity,
                KeyPair hostIdentity,
                FreshP256KeyAgreement hostEphemeral,
                FreshP256KeyAgreement androidEphemeral) throws Exception {
            byte[] hostIdentitySpki = hostIdentity.getPublic().getEncoded();
            byte[] androidIdentitySpki = identity.store.publicKeySpkiDer();
            byte[] hostIdentityHash = sha256(hostIdentitySpki);
            byte[] androidIdentityHash = sha256(androidIdentitySpki);
            byte[] hostEphemeralPublic = hostEphemeral.publicKeySec1();
            byte[] androidEphemeralPublic = androidEphemeral.publicKeySec1();
            byte[] hostNonce = freshNonce();
            byte[] androidNonce = freshNonce();
            byte[] canonical = null;
            try {
                HandshakeTranscriptV1 transcript =
                        AuthenticatedPeerHandshakeV1.newTranscriptBuilder()
                                .hostIdentitySpkiSha256(hostIdentityHash)
                                .androidIdentitySpkiSha256(androidIdentityHash)
                                .hostEphemeralPublicKey(hostEphemeralPublic)
                                .androidEphemeralPublicKey(androidEphemeralPublic)
                                .hostNonce(hostNonce)
                                .androidNonce(androidNonce)
                                .connectionId(freshNonZeroLong())
                                .sessionGeneration(1L)
                                .transportKind(
                                        AuthenticatedPeerHandshakeV1
                                                .TransportKind.CAT6)
                                .hostIpv4(HOST_IPV4)
                                .androidIpv4(ANDROID_IPV4)
                                .videoPort(45678)
                                .controlPort(45679)
                                .pairId(PAIR_ID)
                                .hostRuntimeVersion("17.8.47")
                                .androidRuntimeVersion("17.8.47")
                                .build();
                DualMachineEntitlementRecord entitlement =
                        entitlement(
                                hostIdentitySpki,
                                identity.alias,
                                DualMachinePairingIdentityCodec.fingerprintHex(
                                        androidIdentitySpki));
                canonical = transcript.canonicalEncoding();
                byte[] hostSignature = DualMachinePairingIdentityCodec.sign(
                        hostIdentity.getPrivate(), canonical);
                return new SessionContract(
                        hostIdentity,
                        androidIdentitySpki.clone(),
                        entitlement,
                        transcript,
                        hostSignature);
            } finally {
                clear(hostIdentitySpki);
                clear(androidIdentitySpki);
                clear(hostIdentityHash);
                clear(androidIdentityHash);
                clear(hostEphemeralPublic);
                clear(androidEphemeralPublic);
                clear(hostNonce);
                clear(androidNonce);
                clear(canonical);
            }
        }

        private DualMachineEntitlementRecord entitlement(
                String androidAlias, String androidFingerprint) throws Exception {
            return entitlement(
                    hostIdentity.getPublic().getEncoded(),
                    androidAlias,
                    androidFingerprint);
        }

        private static DualMachineEntitlementRecord entitlement(
                byte[] hostIdentitySpki,
                String androidAlias,
                String androidFingerprint) throws Exception {
            return new DualMachineEntitlementRecord(
                    ENTITLEMENT_ID,
                    PAIR_ID,
                    "89aabbccddeeff001122334455667788",
                    3L,
                    "active",
                    DualMachineEntitlementRecord.PROTOCOL_VERSION,
                    1L,
                    DualMachinePairingIdentityCodec.fingerprintHex(
                            hostIdentitySpki),
                    DualMachinePairingIdentityCodec.encodePublicKeyBase64(
                            hostIdentitySpki),
                    androidFingerprint,
                    androidAlias);
        }

        @Override
        public void close() {
            clear(androidIdentitySpki);
            clear(hostTranscriptSignature);
        }
    }
}
