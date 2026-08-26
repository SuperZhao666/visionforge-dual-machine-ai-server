package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlTcpChannelV1;
import com.visionforge.inferencebenchmark.handshake.FirstPairingBootstrapPayloadV1;
import com.visionforge.inferencebenchmark.handshake.FirstPairingCommitmentV1;
import com.visionforge.inferencebenchmark.handshake.FirstPairingUserConfirmationV1;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Android owner for one user-confirmed fresh pairing and one card activation.
 *
 * <p>The socket and Host signing capability stay process-local. SAS approval
 * alone never calls {@code attachAuthenticatedHost}; only the later
 * server-credential-bound nine-record handshake may create that capability.</p>
 */
final class AndroidFirstPairingCoordinatorV1 implements AutoCloseable {
    private static final int IO_TIMEOUT_MILLIS = 60_000;
    private static final long MAXIMUM_OFFER_LIFETIME_SECONDS = 300L;
    private static final long MAXIMUM_CLOCK_SKEW_SECONDS = 30L;

    @FunctionalInterface
    interface UserConfirmation {
        boolean awaitMatchingSas(
                String decimalSas,
                String hostIpv4,
                long expiresAtEpoch)
                throws InterruptedException;
    }

    private final MobileTransportEndpoint endpoint;
    private final DualMachineAuthorizationRuntime authorizationRuntime;
    private final AndroidPairingIdentityStore androidIdentityStore;
    private final DualMachineCardAuthorizationCoordinator.IdentityBinding
            androidIdentity;
    private final UserConfirmation userConfirmation;
    private final AtomicBoolean activationSignatureUsed = new AtomicBoolean();
    private final Object channelLock = new Object();

    private AuthenticatedControlTcpChannelV1 channel;
    private FirstPairingBootstrapPayloadV1.Offer hostOffer;
    private byte[] hostIdentitySpkiDer;
    private byte[] hostIdentitySha256;
    private byte[] androidIdentitySha256;
    private byte[] commitmentSha256;
    private boolean installed;
    private boolean closed;
    private volatile String diagnosticStage = "not_started";

    AndroidFirstPairingCoordinatorV1(
            MobileTransportEndpoint endpoint,
            DualMachineAuthorizationRuntime authorizationRuntime,
            AndroidPairingIdentityStore androidIdentityStore,
            DualMachineCardAuthorizationCoordinator.IdentityBinding
                    androidIdentity,
            UserConfirmation userConfirmation) {
        if (endpoint == null || !endpoint.isReadyForDataPlane()
                || authorizationRuntime == null
                || androidIdentityStore == null || androidIdentity == null
                || userConfirmation == null) {
            throw new IllegalArgumentException(
                    "fresh-pair Android dependencies are required");
        }
        this.endpoint = endpoint;
        this.authorizationRuntime = authorizationRuntime;
        this.androidIdentityStore = androidIdentityStore;
        this.androidIdentity = androidIdentity;
        this.userConfirmation = userConfirmation;
    }

    void connectConfirmAndInstall()
            throws IOException, GeneralSecurityException,
            InterruptedException {
        diagnosticStage = "channel_connect";
        synchronized (channelLock) {
            requireOpen();
            if (installed) throw rejected();
            channel = AndroidAuthenticatedControlTcpConnectorV1.connect(
                    endpoint.network,
                    endpoint.localIpv4,
                    endpoint.hostIpv4,
                    AuthenticatedControlTcpChannelV1.FIRST_PAIRING_PORT,
                    IO_TIMEOUT_MILLIS);
        }

        diagnosticStage = "host_offer_read";
        byte[] hostOfferPayload = readExpected(
                AuthenticatedControlBootstrapRecordV1.MessageType
                        .HOST_FIRST_PAIR_OFFER);
        diagnosticStage = "host_offer_parse";
        FirstPairingBootstrapPayloadV1.Offer received;
        try {
            received = parseHostOffer(hostOfferPayload);
        } finally {
            Arrays.fill(hostOfferPayload, (byte) 0);
        }
        diagnosticStage = "host_offer_validate";
        validateHostOffer(received);
        diagnosticStage = "identity_prepare";
        hostOffer = received;
        hostIdentitySpkiDer = received.identitySpkiDer();
        hostIdentitySha256 = sha256(hostIdentitySpkiDer);
        byte[] androidSpki = androidIdentityStore.publicKeySpkiDer();
        androidIdentitySha256 = sha256(androidSpki);
        if (MessageDigest.isEqual(
                hostIdentitySha256, androidIdentitySha256)) {
            throw rejected();
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ephemeral = generator.generateKeyPair();
        byte[] ephemeralSpki = ephemeral.getPublic().getEncoded();
        if (ephemeralSpki == null || ephemeralSpki.length != 91) {
            throw rejected();
        }
        byte[] ephemeralSec1 = Arrays.copyOfRange(
                ephemeralSpki, ephemeralSpki.length - 65, ephemeralSpki.length);
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        byte[] runtimeHash = sha256(
                BuildConfig.VERSION_NAME.getBytes(StandardCharsets.UTF_8));
        FirstPairingBootstrapPayloadV1.Offer androidOffer =
                new FirstPairingBootstrapPayloadV1.Offer(
                        received.requiredCapabilities,
                        received.confirmationMethod,
                        received.attemptId(),
                        androidSpki,
                        ephemeralSec1,
                        nonce,
                        runtimeHash,
                        received.expiresAtEpoch);
        diagnosticStage = "android_offer_write";
        write(
                AuthenticatedControlBootstrapRecordV1.MessageType
                        .ANDROID_FIRST_PAIR_OFFER,
                FirstPairingBootstrapPayloadV1.encodeOffer(
                        AuthenticatedControlBootstrapRecordV1.MessageType
                                .ANDROID_FIRST_PAIR_OFFER,
                        androidOffer));

        String localIpv4;
        String peerIpv4;
        synchronized (channelLock) {
            requireOpen();
            localIpv4 = channel.localIpv4();
            peerIpv4 = channel.peerIpv4();
        }
        diagnosticStage = "commitment_build";
        try (FirstPairingCommitmentV1.Result commitment =
                FirstPairingCommitmentV1.build(
                        new FirstPairingCommitmentV1.Fields(
                                FirstPairingCommitmentV1.TRANSPORT_ETHERNET,
                                received.requiredCapabilities,
                                received.attemptId(),
                                hostIdentitySha256,
                                androidIdentitySha256,
                                received.ephemeralPublicKey(),
                                androidOffer.ephemeralPublicKey(),
                                received.nonce(),
                                androidOffer.nonce(),
                                ipv4(peerIpv4),
                                ipv4(localIpv4),
                                MobilePipelineCoordinator.VIDEO_PORT,
                                AuthenticatedControlTcpChannelV1.AUTHENTICATED_CONTROL_PORT,
                                received.runtimeVersionSha256(),
                                androidOffer.runtimeVersionSha256(),
                                received.expiresAtEpoch))) {
            commitmentSha256 = commitment.commitmentSha256();
            diagnosticStage = "user_confirmation";
            if (!userConfirmation.awaitMatchingSas(
                    commitment.decimalSas(),
                    peerIpv4,
                    received.expiresAtEpoch)) {
                throw rejected();
            }
        }

        diagnosticStage = "host_confirmation_read";
        FirstPairingBootstrapPayloadV1.Confirmation hostConfirmation =
                FirstPairingBootstrapPayloadV1.parseConfirmation(
                        AuthenticatedControlBootstrapRecordV1.MessageType
                                .HOST_FIRST_PAIR_CONFIRMATION,
                        readExpected(
                                AuthenticatedControlBootstrapRecordV1.MessageType
                                        .HOST_FIRST_PAIR_CONFIRMATION));
        diagnosticStage = "host_confirmation_validate";
        requireMatchingConfirmation(hostConfirmation);
        diagnosticStage = "host_confirmation_verify";
        AndroidFirstPairingUserConfirmationV1.verifyHostConfirmation(
                hostIdentitySpkiDer,
                hostIdentitySha256,
                received.confirmationMethod,
                received.attemptId(),
                commitmentSha256,
                received.expiresAtEpoch,
                hostConfirmation.signatureDerLowS());

        diagnosticStage = "android_confirmation_sign";
        try (AndroidFirstPairingUserConfirmationV1.SignedConfirmation signed =
                AndroidFirstPairingUserConfirmationV1
                        .signAfterUserConfirmation(
                                androidIdentityStore,
                                received.confirmationMethod,
                                received.attemptId(),
                                commitmentSha256,
                                androidIdentitySha256,
                                received.expiresAtEpoch)) {
            FirstPairingBootstrapPayloadV1.Confirmation confirmation =
                    new FirstPairingBootstrapPayloadV1.Confirmation(
                            FirstPairingUserConfirmationV1.ROLE_ANDROID,
                            received.confirmationMethod,
                            received.attemptId(),
                            commitmentSha256,
                            received.expiresAtEpoch,
                            signed.signatureDerLowS());
            write(
                    AuthenticatedControlBootstrapRecordV1.MessageType
                            .ANDROID_FIRST_PAIR_CONFIRMATION,
                    FirstPairingBootstrapPayloadV1.encodeConfirmation(
                            AuthenticatedControlBootstrapRecordV1.MessageType
                                    .ANDROID_FIRST_PAIR_CONFIRMATION,
                            confirmation));
        }

        String hostFingerprint = hex(hostIdentitySha256);
        String hostDeviceCode = "HOST-" + hostFingerprint.substring(0, 32)
                .toUpperCase(Locale.ROOT);
        DualMachineCardAuthorizationCoordinator.IdentityBinding hostIdentity =
                DualMachineCardAuthorizationCoordinator.IdentityBinding
                        .forFirstPairingActivation(
                                hostDeviceCode,
                                BuildConfig.DUAL_MACHINE_PROTOCOL_CLIENT_VERSION,
                                Base64.getEncoder().encodeToString(
                                        hostIdentitySpkiDer),
                                this::signActivationConfirmation);
        diagnosticStage = "activation_host_attach";
        authorizationRuntime.attachFirstPairingActivationHost(
                hostIdentity,
                () -> System.currentTimeMillis() / 1_000L,
                this::completeActivation);
        installed = true;
        diagnosticStage = "ready_for_activation";
    }

    boolean isInstalled() {
        synchronized (channelLock) {
            return installed && !closed && channel != null && channel.isOpen();
        }
    }

    String diagnosticStage() {
        return diagnosticStage;
    }

    private byte[] signActivationConfirmation(
            DualMachineUsageAuthorizationContract.ActivationConfirmation proof,
            byte[] canonicalPayload)
            throws IOException, GeneralSecurityException {
        if (!activationSignatureUsed.compareAndSet(false, true)) {
            throw rejected();
        }
        byte[] expected = DualMachineUsageAuthorizationContract
                .activationConfirmation(proof);
        if (!MessageDigest.isEqual(expected, canonicalPayload)
                || !hex(hostIdentitySha256).equals(proof.hostKeySha256)
                || !hex(androidIdentitySha256).equals(proof.androidKeySha256)
                || !BuildConfig.DUAL_MACHINE_PROTOCOL_CLIENT_VERSION.equals(
                        proof.hostClientVersion)
                || !androidIdentity.peerIdentity.deviceCode.equals(
                        proof.androidDeviceCode)
                || !androidIdentity.peerIdentity.clientVersion.equals(
                        proof.androidClientVersion)) {
            throw rejected();
        }
        write(
                AuthenticatedControlBootstrapRecordV1.MessageType
                        .ACTIVATION_PROOF_REQUEST,
                FirstPairingBootstrapPayloadV1
                        .encodeActivationProofRequest(proof));
        FirstPairingBootstrapPayloadV1.ActivationSignature signature =
                FirstPairingBootstrapPayloadV1.parseActivationSignature(
                        readExpected(
                                AuthenticatedControlBootstrapRecordV1.MessageType
                                        .HOST_ACTIVATION_SIGNATURE));
        byte[] digest = sha256(canonicalPayload);
        if (!MessageDigest.isEqual(
                digest, signature.canonicalPayloadSha256())
                || !DualMachinePairingIdentityCodec.verify(
                        hostIdentitySpkiDer,
                        canonicalPayload,
                        signature.signatureDerLowS())) {
            throw rejected();
        }
        return signature.signatureDerLowS();
    }

    private void completeActivation(DualMachineEntitlementRecord entitlement)
            throws IOException, GeneralSecurityException {
        if (entitlement == null
                || !entitlement.hasActivePairSecurityBinding()
                || !entitlement.hostKeySha256.equals(hex(hostIdentitySha256))
                || !entitlement.androidKeySha256.equals(
                        hex(androidIdentitySha256))) {
            throw rejected();
        }
        FirstPairingBootstrapPayloadV1.ActivationResult result =
                new FirstPairingBootstrapPayloadV1.ActivationResult(
                        entitlement.entitlementId,
                        entitlement.pairId,
                        entitlement.bindingId,
                        entitlement.bindingRevision,
                        entitlement.revocationVersion);
        write(
                AuthenticatedControlBootstrapRecordV1.MessageType
                        .ACTIVATION_RESULT,
                FirstPairingBootstrapPayloadV1.encodeActivationResult(result));
        byte[] completed = FirstPairingBootstrapPayloadV1.parseComplete(
                readExpected(
                        AuthenticatedControlBootstrapRecordV1.MessageType
                                .FIRST_PAIR_COMPLETE));
        if (!MessageDigest.isEqual(completed, commitmentSha256)) {
            throw rejected();
        }
        close();
    }

    private FirstPairingBootstrapPayloadV1.Offer parseHostOffer(byte[] payload)
            throws GeneralSecurityException {
        return FirstPairingBootstrapPayloadV1.parseOffer(
                AuthenticatedControlBootstrapRecordV1.MessageType
                        .HOST_FIRST_PAIR_OFFER,
                payload);
    }

    private void validateHostOffer(
            FirstPairingBootstrapPayloadV1.Offer offer)
            throws GeneralSecurityException {
        long now = System.currentTimeMillis() / 1_000L;
        if (offer == null
                || offer.requiredCapabilities
                        != FirstPairingCommitmentV1
                                .CAPABILITY_TWO_SIDED_USER_CONFIRMATION
                || offer.confirmationMethod
                        != FirstPairingUserConfirmationV1.METHOD_DECIMAL_SAS
                || offer.expiresAtEpoch <= now
                || offer.expiresAtEpoch > now
                        + MAXIMUM_OFFER_LIFETIME_SECONDS
                        + MAXIMUM_CLOCK_SKEW_SECONDS) {
            throw rejected();
        }
    }

    private void requireMatchingConfirmation(
            FirstPairingBootstrapPayloadV1.Confirmation confirmation)
            throws GeneralSecurityException {
        if (confirmation.role != FirstPairingUserConfirmationV1.ROLE_HOST
                || confirmation.method != hostOffer.confirmationMethod
                || confirmation.expiresAtEpoch != hostOffer.expiresAtEpoch
                || !MessageDigest.isEqual(
                        confirmation.attemptId(), hostOffer.attemptId())
                || !MessageDigest.isEqual(
                        confirmation.commitmentSha256(), commitmentSha256)) {
            throw rejected();
        }
    }

    private byte[] readExpected(
            AuthenticatedControlBootstrapRecordV1.MessageType expected)
            throws IOException, GeneralSecurityException {
        byte[] encoded;
        synchronized (channelLock) {
            requireOpen();
            encoded = channel.readBootstrapRecord(
                    AuthenticatedControlBootstrapRecordV1.Direction
                            .HOST_TO_ANDROID,
                    IO_TIMEOUT_MILLIS);
        }
        try (AuthenticatedControlBootstrapRecordV1.Record record =
                AuthenticatedControlBootstrapRecordV1.parse(
                        encoded,
                        AuthenticatedControlBootstrapRecordV1.Direction
                                .HOST_TO_ANDROID)) {
            if (record.messageType() != expected) throw rejected();
            return record.payload();
        } catch (AuthenticatedControlBootstrapRecordV1.BootstrapException
                malformed) {
            throw rejected();
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private void write(
            AuthenticatedControlBootstrapRecordV1.MessageType type,
            byte[] payload)
            throws IOException, GeneralSecurityException {
        byte[] record;
        try {
            record = AuthenticatedControlBootstrapRecordV1.encode(
                    AuthenticatedControlBootstrapRecordV1.Direction
                            .ANDROID_TO_HOST,
                    type,
                    payload);
        } catch (AuthenticatedControlBootstrapRecordV1.BootstrapException
                malformed) {
            throw rejected();
        } finally {
            if (payload != null) Arrays.fill(payload, (byte) 0);
        }
        try {
            synchronized (channelLock) {
                requireOpen();
                channel.writeBootstrapRecord(
                        record,
                        AuthenticatedControlBootstrapRecordV1.Direction
                                .ANDROID_TO_HOST,
                        IO_TIMEOUT_MILLIS);
            }
        } finally {
            Arrays.fill(record, (byte) 0);
        }
    }

    @Override
    public void close() {
        synchronized (channelLock) {
            if (closed) return;
            closed = true;
            installed = false;
            if (channel != null) channel.close();
            channel = null;
            clear(hostIdentitySpkiDer);
            hostIdentitySpkiDer = null;
            clear(hostIdentitySha256);
            hostIdentitySha256 = null;
            clear(androidIdentitySha256);
            androidIdentitySha256 = null;
            clear(commitmentSha256);
            commitmentSha256 = null;
        }
    }

    private void requireOpen() throws GeneralSecurityException {
        if (closed) throw rejected();
    }

    private static byte[] ipv4(String value)
            throws GeneralSecurityException {
        try {
            InetAddress parsed = InetAddress.getByName(value);
            if (!(parsed instanceof Inet4Address)
                    || !parsed.getHostAddress().equals(value)) {
                throw rejected();
            }
            return parsed.getAddress();
        } catch (IOException | RuntimeException failure) {
            throw rejected();
        }
    }

    private static byte[] sha256(byte[] value)
            throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(value);
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(Character.forDigit((item >>> 4) & 0x0f, 16));
            result.append(Character.forDigit(item & 0x0f, 16));
        }
        return result.toString();
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    private static GeneralSecurityException rejected() {
        return new GeneralSecurityException(
                "fresh-pair Android protocol was rejected");
    }
}
