package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1;
import com.visionforge.inferencebenchmark.handshake.FreshP256KeyAgreement;
import com.visionforge.inferencebenchmark.handshake.HandshakeTranscriptV1;
import com.visionforge.inferencebenchmark.handshake.PeerHandshakeSecrets;
import com.visionforge.inferencebenchmark.handshake.PendingPeerHandshakeConfirmation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import android.os.Build;

/** API-29+ provider smoke for the public peer-handshake foundation. */
final class AuthenticatedPeerHandshakeV1InstrumentationProbe {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final byte[] HOST_IPV4 = {(byte) 192, (byte) 168, 55, 1};
    private static final byte[] ANDROID_IPV4 = {(byte) 192, (byte) 168, 55, 2};

    private AuthenticatedPeerHandshakeV1InstrumentationProbe() {}

    static int verify() throws Exception {
        require(
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q,
                "peer-handshake provider probe requires API 29 or newer");
        try (SessionSnapshot first = runFreshSession(1L);
                SessionSnapshot second = runFreshSession(2L)) {
            requireDifferent(
                    first.hostPublicKey, second.hostPublicKey,
                    "fresh Host ephemeral keys must differ");
            requireDifferent(
                    first.androidPublicKey, second.androidPublicKey,
                    "fresh Android ephemeral keys must differ");
            requireDifferent(
                    first.channelBinding, second.channelBinding,
                    "fresh channel bindings must differ");
            requireDifferent(
                    first.controlHostToAndroid, second.controlHostToAndroid,
                    "fresh traffic material must differ");
        }
        return Build.VERSION.SDK_INT;
    }

    private static SessionSnapshot runFreshSession(long generation) throws Exception {
        byte[] hostPublicKey = null;
        byte[] androidPublicKey = null;
        byte[] hostNonce = freshNonce();
        byte[] androidNonce = freshNonce();
        try (FreshP256KeyAgreement host =
                        AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement();
                FreshP256KeyAgreement android =
                        AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement()) {
            hostPublicKey = host.publicKeySec1();
            androidPublicKey = android.publicKeySec1();
            requirePublicKey(hostPublicKey, "Host");
            requirePublicKey(androidPublicKey, "Android");
            requireDifferent(
                    hostPublicKey, androidPublicKey,
                    "Host and Android ephemeral keys must differ");
            requireDifferent(hostNonce, androidNonce, "fresh role nonces must differ");

            HandshakeTranscriptV1 transcript = buildTranscript(
                    hostPublicKey, androidPublicKey, hostNonce, androidNonce, generation);
            try (PendingPeerHandshakeConfirmation hostPending =
                            host.deriveAfterPeerIdentityVerified(
                                    transcript, AuthenticatedPeerHandshakeV1.Role.HOST);
                    PendingPeerHandshakeConfirmation androidPending =
                            android.deriveAfterPeerIdentityVerified(
                                    transcript, AuthenticatedPeerHandshakeV1.Role.ANDROID)) {
                SessionSnapshot snapshot = confirmSession(
                        hostPending, androidPending, hostPublicKey, androidPublicKey);
                return snapshot;
            }
        } finally {
            clear(hostPublicKey);
            clear(androidPublicKey);
            clear(hostNonce);
            clear(androidNonce);
        }
    }

    private static SessionSnapshot confirmSession(
            PendingPeerHandshakeConfirmation hostPending,
            PendingPeerHandshakeConfirmation androidPending,
            byte[] hostPublicKey,
            byte[] androidPublicKey) throws Exception {
        byte[] hostFinished = null;
        byte[] androidFinished = null;
        try {
            hostFinished = hostPending.createLocalFinishedMac();
            androidFinished = androidPending.createLocalFinishedMac();
            try (PeerHandshakeSecrets hostSecrets =
                            hostPending.confirmPeerFinishedMac(androidFinished);
                    PeerHandshakeSecrets androidSecrets =
                            androidPending.confirmPeerFinishedMac(hostFinished)) {
                requireMatchingSecrets(hostSecrets, androidSecrets);
                return new SessionSnapshot(
                        hostPublicKey,
                        androidPublicKey,
                        hostSecrets.channelBindingSha256(),
                        hostSecrets.controlHostToAndroidMaterial());
            }
        } finally {
            clear(hostFinished);
            clear(androidFinished);
        }
    }

    private static HandshakeTranscriptV1 buildTranscript(
            byte[] hostPublicKey,
            byte[] androidPublicKey,
            byte[] hostNonce,
            byte[] androidNonce,
            long generation) throws Exception {
        return AuthenticatedPeerHandshakeV1.newTranscriptBuilder()
                .hostIdentitySpkiSha256(sha256("instrumentation-host-identity"))
                .androidIdentitySpkiSha256(sha256("instrumentation-android-identity"))
                .hostEphemeralPublicKey(hostPublicKey)
                .androidEphemeralPublicKey(androidPublicKey)
                .hostNonce(hostNonce)
                .androidNonce(androidNonce)
                .connectionId(freshNonZeroLong())
                .sessionGeneration(generation)
                .transportKind(AuthenticatedPeerHandshakeV1.TransportKind.CAT6)
                .hostIpv4(HOST_IPV4)
                .androidIpv4(ANDROID_IPV4)
                .videoPort(45678)
                .controlPort(45679)
                .pairId("PAIR-API29-PROVIDER")
                .hostRuntimeVersion("17.8.47")
                .androidRuntimeVersion("17.8.47")
                .build();
    }

    private static void requireMatchingSecrets(
            PeerHandshakeSecrets host, PeerHandshakeSecrets android) throws Exception {
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

    private static void requireEqualAndClear(byte[] left, byte[] right, String label) {
        try {
            require(MessageDigest.isEqual(left, right), label + " must match");
        } finally {
            clear(left);
            clear(right);
        }
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

    private static byte[] sha256(String value) throws Exception {
        return MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.US_ASCII));
    }

    private static void requirePublicKey(byte[] value, String role) {
        require(
                value.length == AuthenticatedPeerHandshakeV1.P256_SEC1_UNCOMPRESSED_BYTES
                        && value[0] == 0x04,
                role + " public key must be canonical uncompressed SEC1");
    }

    private static void requireDifferent(byte[] left, byte[] right, String message) {
        require(!MessageDigest.isEqual(left, right), message);
    }

    private static boolean isAllZero(byte[] value) {
        int aggregate = 0;
        for (byte current : value) aggregate |= current;
        return aggregate == 0;
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    private static final class SessionSnapshot implements AutoCloseable {
        private final byte[] hostPublicKey;
        private final byte[] androidPublicKey;
        private final byte[] channelBinding;
        private final byte[] controlHostToAndroid;

        private SessionSnapshot(
                byte[] hostPublicKey,
                byte[] androidPublicKey,
                byte[] channelBinding,
                byte[] controlHostToAndroid) {
            this.hostPublicKey = hostPublicKey.clone();
            this.androidPublicKey = androidPublicKey.clone();
            this.channelBinding = channelBinding.clone();
            this.controlHostToAndroid = controlHostToAndroid.clone();
            clear(channelBinding);
            clear(controlHostToAndroid);
        }

        @Override
        public void close() {
            clear(hostPublicKey);
            clear(androidPublicKey);
            clear(channelBinding);
            clear(controlHostToAndroid);
        }
    }
}
