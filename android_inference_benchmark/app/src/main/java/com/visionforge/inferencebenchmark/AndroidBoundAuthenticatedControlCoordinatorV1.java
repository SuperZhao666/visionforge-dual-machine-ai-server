package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlTcpChannelV1;
import com.visionforge.inferencebenchmark.handshake.PairGenerationCredentialV1Verifier;
import com.visionforge.inferencebenchmark.dataplane.AuthenticatedControlRecordV1;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;

/** Owns one production VFB1 TCP channel and its confirmed Android session. */
final class AndroidBoundAuthenticatedControlCoordinatorV1
        implements AutoCloseable {
    private static final int IO_TIMEOUT_MILLIS = 60_000;
    private static final int START_INTENT_TIMEOUT_MILLIS = 3_000;

    private final MobileTransportEndpoint endpoint;
    private final DualMachineEntitlementRecord entitlement;
    private final AndroidPairingIdentityStore identityStore;
    private final DualMachineSidecarPort sidecar;
    private final PairGenerationCredentialV1Verifier credentialVerifier;
    private final AuthenticatedPairingHandshake.HexIdSource idSource;
    private final SecureRandom controlNonceRandom = new SecureRandom();
    private final Object channelLock = new Object();

    private AuthenticatedControlTcpChannelV1 channel;
    private AuthenticatedPairingHandshake handshake;
    private ConfirmedAndroidPeerSession session;
    private AuthenticatedControlRecordV1.Sender controlSender;
    private AuthenticatedControlRecordV1.Receiver controlReceiver;
    private boolean closed;
    private volatile String diagnosticStage = "not_started";
    private volatile long pairGenerationChallengeExpiresAtEpoch;

    AndroidBoundAuthenticatedControlCoordinatorV1(
            MobileTransportEndpoint endpoint,
            DualMachineEntitlementRecord entitlement,
            AndroidPairingIdentityStore identityStore,
            DualMachineSidecarPort sidecar,
            PairGenerationCredentialV1Verifier credentialVerifier,
            AuthenticatedPairingHandshake.HexIdSource idSource) {
        if (endpoint == null || !endpoint.isReadyForDataPlane()
                || entitlement == null || entitlement.revoked
                || !entitlement.hasActivePairSecurityBinding()
                || identityStore == null || sidecar == null
                || credentialVerifier == null || idSource == null) {
            throw new IllegalArgumentException(
                    "bound authenticated-control dependencies are required");
        }
        this.endpoint = endpoint;
        this.entitlement = entitlement;
        this.identityStore = identityStore;
        this.sidecar = sidecar;
        this.credentialVerifier = credentialVerifier;
        this.idSource = idSource;
    }

    void connectAndAuthenticate()
            throws IOException, GeneralSecurityException {
        synchronized (channelLock) {
            requireOpen();
            if (session != null) {
                throw new GeneralSecurityException(
                        "bound authenticated-control session already exists");
            }
            diagnosticStage = "channel_connect";
            channel = AndroidAuthenticatedControlTcpConnectorV1.connect(
                    endpoint.network,
                    endpoint.localIpv4,
                    endpoint.hostIpv4,
                    AuthenticatedControlTcpChannelV1.AUTHENTICATED_CONTROL_PORT,
                    IO_TIMEOUT_MILLIS);
            handshake = AuthenticatedPairingHandshake.create(
                    entitlement,
                    identityStore,
                    sidecar,
                    credentialVerifier,
                    stableRuntimeVersion(),
                    idSource);

            diagnosticStage = "host_hello";
            writeAndroid(handshake.acceptHostHello(readHost()));
            diagnosticStage = "host_challenge_proof";
            byte[] serverChallengeRecord =
                    handshake.acceptHostChallengeProof(readHost());
            pairGenerationChallengeExpiresAtEpoch =
                    handshake.serverChallengeExpiresAtEpoch();
            writeAndroid(serverChallengeRecord);
            diagnosticStage = "host_final_proof";
            writeAndroid(handshake.acceptHostFinalProof(readHost()));
            diagnosticStage = "host_handshake_signature";
            writeAndroid(handshake.acceptHostHandshakeSignature(readHost()));
            diagnosticStage = "host_finished";
            session = handshake.acceptHostFinished(readHost());
            handshake = null;
            installAuthenticatedControlRecords();
            diagnosticStage = "confirmed";
        }
    }

    DualMachineCardAuthorizationCoordinator.IdentityBinding
            hostIdentityBinding() throws GeneralSecurityException {
        synchronized (channelLock) {
            requireAuthenticated();
            return new DualMachineCardAuthorizationCoordinator.IdentityBinding(
                    "HOST-"
                            + entitlement.hostKeySha256.substring(0, 32)
                                    .toUpperCase(Locale.ROOT),
                    stableRuntimeVersion(),
                    entitlement.hostIdentityPublicKeyBase64,
                    this::signCanonicalUsageAuthorization);
        }
    }

    boolean installMouseSession(MobileControlRuntime controlRuntime) {
        synchronized (channelLock) {
            return !closed && session != null && channel != null
                    && channel.isOpen() && controlRuntime != null
                    && controlRuntime.installConfirmedPeerSession(session);
        }
    }

    boolean installDataPlaneSession(MobilePipelineCoordinator pipeline) {
        synchronized (channelLock) {
            if (closed || session == null || channel == null
                    || !channel.isOpen() || pipeline == null) {
                return false;
            }
            ConfirmedMobileDataPlaneMaterialV2 material = null;
            try {
                material = new ConfirmedMobileDataPlaneMaterialV2(
                        session.connectionId(),
                        endpoint,
                        session.hostIpv4(),
                        session.androidIpv4(),
                        session.videoHostToAndroidMaterial(),
                        session.presenceHostToAndroidMaterial(),
                        session.idrAndroidToHostMaterial());
                return pipeline.installConfirmedPeerSession(material);
            } catch (GeneralSecurityException | RuntimeException failure) {
                return false;
            } finally {
                if (material != null) material.close();
            }
        }
    }

    boolean isAuthenticated() {
        synchronized (channelLock) {
            return !closed && session != null && channel != null
                    && channel.isOpen();
        }
    }

    String channelBindingLowercaseHex()
            throws GeneralSecurityException {
        synchronized (channelLock) {
            requireAuthenticated();
            return session.channelBindingLowercaseHex();
        }
    }

    String diagnosticStage() {
        return diagnosticStage;
    }

    long pairGenerationChallengeExpiresAtEpoch() {
        return pairGenerationChallengeExpiresAtEpoch;
    }

    AuthenticatedHostStartIntentClaimV1.Claim claimHostStartIntent()
            throws IOException, GeneralSecurityException {
        synchronized (channelLock) {
            requireAuthenticated();
            if (controlSender == null || controlReceiver == null) {
                throw new GeneralSecurityException(
                        "authenticated Host start-intent channel is unavailable");
            }
            byte[] requestNonce = new byte[
                    AuthenticatedHostStartIntentClaimV1.REQUEST_NONCE_BYTES];
            byte[] request = null;
            byte[] requestEnvelope = null;
            byte[] responseEnvelope = null;
            byte[] responsePlaintext = null;
            try {
                controlNonceRandom.nextBytes(requestNonce);
                request = AuthenticatedHostStartIntentClaimV1.encodeRequest(
                        requestNonce);
                diagnosticStage = "host_start_intent_claim_request";
                requestEnvelope = controlSender.seal(
                        AuthenticatedControlRecordV1.MessageType
                                .HOST_START_INTENT_CLAIM_REQUEST,
                        request);
                channel.writeAuthenticatedRecord(
                        requestEnvelope,
                        AuthenticatedControlRecordV1.Direction.ANDROID_TO_HOST,
                        START_INTENT_TIMEOUT_MILLIS);
                responseEnvelope = channel.readAuthenticatedRecord(
                        AuthenticatedControlRecordV1.Direction.HOST_TO_ANDROID,
                        START_INTENT_TIMEOUT_MILLIS);
                try (AuthenticatedControlRecordV1.OpenedRecord opened =
                        controlReceiver.open(responseEnvelope)) {
                    if (opened.messageType()
                            != AuthenticatedControlRecordV1.MessageType
                                    .HOST_START_INTENT_CLAIM_RESPONSE) {
                        throw new GeneralSecurityException(
                                "Host returned an unexpected start-intent response");
                    }
                    responsePlaintext = opened.plaintext();
                }
                AuthenticatedHostStartIntentClaimV1.Claim claim =
                        AuthenticatedHostStartIntentClaimV1.decodeResponse(
                                requestNonce,
                                session.connectionId(),
                                responsePlaintext);
                diagnosticStage = "confirmed";
                return claim;
            } catch (IOException | GeneralSecurityException
                     | RuntimeException failure) {
                diagnosticStage = "host_start_intent_claim_failed";
                close();
                throw failure;
            } finally {
                clear(requestNonce);
                clear(request);
                clear(requestEnvelope);
                clear(responseEnvelope);
                clear(responsePlaintext);
            }
        }
    }

    private byte[] signCanonicalUsageAuthorization(byte[] canonicalPayload)
            throws IOException, GeneralSecurityException {
        if (canonicalPayload == null) {
            throw new GeneralSecurityException(
                    "Host usage authorization payload is unavailable");
        }
        String payload = new String(
                canonicalPayload, StandardCharsets.UTF_8);
        String statusDomain = "\"domain\":\""
                + DualMachineUsageAuthorizationContract
                        .ENTITLEMENT_STATUS_DOMAIN
                + "\"";
        if (payload.contains(statusDomain)) {
            return signCanonicalEntitlementStatus(canonicalPayload);
        }
        return signCanonicalTypedUsageAuthorization(canonicalPayload);
    }

    private byte[] signCanonicalTypedUsageAuthorization(
            byte[] canonicalPayload)
            throws IOException, GeneralSecurityException {
        synchronized (channelLock) {
            requireAuthenticated();
            if (controlSender == null || controlReceiver == null) {
                throw new GeneralSecurityException(
                        "authenticated Host usage signer is unavailable");
            }
            byte[] typedRequest = null;
            byte[] expectedDigest = null;
            byte[] requestEnvelope = null;
            byte[] responseEnvelope = null;
            byte[] responsePlaintext = null;
            try {
                typedRequest = TypedUsageAuthorizationRequestV1.encode(
                        canonicalPayload,
                        entitlement,
                        session.channelBindingLowercaseHex());
                expectedDigest = MessageDigest.getInstance("SHA-256")
                        .digest(canonicalPayload);
                diagnosticStage = "usage_authorization_sign_request";
                requestEnvelope = controlSender.seal(
                        AuthenticatedControlRecordV1.MessageType
                                .USAGE_AUTHORIZATION_SIGN_REQUEST,
                        typedRequest);
                channel.writeAuthenticatedRecord(
                        requestEnvelope,
                        AuthenticatedControlRecordV1.Direction
                                .ANDROID_TO_HOST,
                        IO_TIMEOUT_MILLIS);
                responseEnvelope = channel.readAuthenticatedRecord(
                        AuthenticatedControlRecordV1.Direction
                                .HOST_TO_ANDROID,
                        IO_TIMEOUT_MILLIS);
                try (AuthenticatedControlRecordV1.OpenedRecord opened =
                        controlReceiver.open(responseEnvelope)) {
                    if (opened.messageType()
                                    != AuthenticatedControlRecordV1.MessageType
                                            .USAGE_AUTHORIZATION_SIGN_RESPONSE) {
                        throw new GeneralSecurityException(
                                "Host returned an unexpected usage proof");
                    }
                    responsePlaintext = opened.plaintext();
                }
                if (responsePlaintext.length <= expectedDigest.length
                        || !constantTimePrefix(
                                responsePlaintext, expectedDigest)) {
                    throw new GeneralSecurityException(
                            "Host usage proof is not request-bound");
                }
                byte[] signature = Arrays.copyOfRange(
                        responsePlaintext,
                        expectedDigest.length,
                        responsePlaintext.length);
                if (signature.length < 64 || signature.length > 80) {
                    Arrays.fill(signature, (byte) 0);
                    throw new GeneralSecurityException(
                            "Host usage proof signature is malformed");
                }
                diagnosticStage = "confirmed";
                return signature;
            } finally {
                clear(typedRequest);
                clear(expectedDigest);
                clear(requestEnvelope);
                clear(responseEnvelope);
                clear(responsePlaintext);
            }
        }
    }

    /**
     * Installs the exact server-signed lease through VFC1 Offer/Accept/Commit.
     * The Host independently verifies the raw bytes and cannot open its data
     * plane until the final authenticated commit has been received.
     */
    void installVerifiedUsageLease(
            DualMachineFormalUsageCoordinator.DataPlanePermit permit)
            throws IOException, GeneralSecurityException {
        synchronized (channelLock) {
            requireAuthenticated();
            if (permit == null || permit.sequence < 0L
                    || controlSender == null || controlReceiver == null
                    || !session.channelBindingLowercaseHex().equals(
                            permit.channelBindingSha256)) {
                throw new GeneralSecurityException(
                        "verified usage lease binding is unavailable");
            }
            byte[] rawLease = permit.copySignedUsageLeaseUtf8();
            byte[] expectedDigest = null;
            byte[] calculatedDigest = null;
            byte[] commitment = null;
            byte[] offerEnvelope = null;
            byte[] acceptEnvelope = null;
            byte[] acceptPlaintext = null;
            byte[] commitEnvelope = null;
            try {
                if (rawLease.length == 0 || rawLease.length > 8_192) {
                    throw new GeneralSecurityException(
                            "verified usage lease length is invalid");
                }
                expectedDigest = decodeLowerHexSha256(permit.leaseSha256);
                calculatedDigest = MessageDigest.getInstance("SHA-256")
                        .digest(rawLease);
                if (!MessageDigest.isEqual(
                        expectedDigest, calculatedDigest)) {
                    throw new GeneralSecurityException(
                            "verified usage lease digest changed");
                }
                commitment = ByteBuffer.allocate(40)
                        .order(ByteOrder.BIG_ENDIAN)
                        .put(expectedDigest)
                        .putLong(permit.sequence)
                        .array();
                diagnosticStage = "lease_offer";
                offerEnvelope = controlSender.seal(
                        AuthenticatedControlRecordV1.MessageType.LEASE_OFFER,
                        rawLease);
                channel.writeAuthenticatedRecord(
                        offerEnvelope,
                        AuthenticatedControlRecordV1.Direction
                                .ANDROID_TO_HOST,
                        IO_TIMEOUT_MILLIS);

                diagnosticStage = "lease_accept";
                acceptEnvelope = channel.readAuthenticatedRecord(
                        AuthenticatedControlRecordV1.Direction
                                .HOST_TO_ANDROID,
                        IO_TIMEOUT_MILLIS);
                try (AuthenticatedControlRecordV1.OpenedRecord opened =
                        controlReceiver.open(acceptEnvelope)) {
                    if (opened.messageType()
                                    != AuthenticatedControlRecordV1.MessageType
                                            .LEASE_ACCEPT) {
                        throw new GeneralSecurityException(
                                "Host returned an unexpected lease response");
                    }
                    acceptPlaintext = opened.plaintext();
                }
                if (!MessageDigest.isEqual(
                        commitment, acceptPlaintext)) {
                    throw new GeneralSecurityException(
                            "Host lease acceptance is not request-bound");
                }

                diagnosticStage = "lease_commit";
                commitEnvelope = controlSender.seal(
                        AuthenticatedControlRecordV1.MessageType.LEASE_COMMIT,
                        commitment);
                channel.writeAuthenticatedRecord(
                        commitEnvelope,
                        AuthenticatedControlRecordV1.Direction
                                .ANDROID_TO_HOST,
                        IO_TIMEOUT_MILLIS);
                diagnosticStage = "lease_committed";
            } catch (IOException | GeneralSecurityException
                     | RuntimeException failure) {
                close();
                diagnosticStage = "lease_install_failed";
                throw failure;
            } finally {
                clear(rawLease);
                clear(expectedDigest);
                clear(calculatedDigest);
                clear(commitment);
                clear(offerEnvelope);
                clear(acceptEnvelope);
                clear(acceptPlaintext);
                clear(commitEnvelope);
            }
        }
    }

    private byte[] signCanonicalEntitlementStatus(byte[] canonicalPayload)
            throws IOException, GeneralSecurityException {
        synchronized (channelLock) {
            requireAuthenticated();
            if (canonicalPayload == null || controlSender == null
                    || controlReceiver == null) {
                throw new GeneralSecurityException(
                        "authenticated Host status signer is unavailable");
            }
            byte[] requestNonce = extractStatusRequestNonce(canonicalPayload);
            byte[] requestEnvelope = null;
            byte[] responseEnvelope = null;
            byte[] responsePlaintext = null;
            try {
                requestEnvelope = controlSender.seal(
                        AuthenticatedControlRecordV1.MessageType
                                .ENTITLEMENT_STATUS_SIGN_REQUEST,
                        requestNonce);
                channel.writeAuthenticatedRecord(
                        requestEnvelope,
                        AuthenticatedControlRecordV1.Direction.ANDROID_TO_HOST,
                        IO_TIMEOUT_MILLIS);
                responseEnvelope = channel.readAuthenticatedRecord(
                        AuthenticatedControlRecordV1.Direction.HOST_TO_ANDROID,
                        IO_TIMEOUT_MILLIS);
                try (AuthenticatedControlRecordV1.OpenedRecord opened =
                        controlReceiver.open(responseEnvelope)) {
                    if (opened.messageType()
                                    != AuthenticatedControlRecordV1.MessageType
                                            .ENTITLEMENT_STATUS_SIGN_RESPONSE) {
                        throw new GeneralSecurityException(
                                "Host returned an unexpected control proof");
                    }
                    responsePlaintext = opened.plaintext();
                }
                if (responsePlaintext.length <= requestNonce.length
                        || !constantTimePrefix(
                                responsePlaintext, requestNonce)) {
                    throw new GeneralSecurityException(
                            "Host status proof response is not request-bound");
                }
                byte[] signature = Arrays.copyOfRange(
                        responsePlaintext,
                        requestNonce.length,
                        responsePlaintext.length);
                if (signature.length < 64 || signature.length > 80) {
                    Arrays.fill(signature, (byte) 0);
                    throw new GeneralSecurityException(
                            "Host status proof signature is malformed");
                }
                return signature;
            } finally {
                Arrays.fill(requestNonce, (byte) 0);
                clear(requestEnvelope);
                clear(responseEnvelope);
                clear(responsePlaintext);
            }
        }
    }

    private byte[] extractStatusRequestNonce(byte[] canonicalPayload)
            throws GeneralSecurityException {
        String payload = new String(canonicalPayload, StandardCharsets.UTF_8);
        String marker = "\"request_nonce\":\"";
        int start = payload.indexOf(marker);
        if (start < 0) {
            throw new GeneralSecurityException(
                    "Host status proof payload is not typed");
        }
        start += marker.length();
        int end = start + 32;
        if (end >= payload.length() || payload.charAt(end) != '"') {
            throw new GeneralSecurityException(
                    "Host status proof nonce is malformed");
        }
        String nonceHex = payload.substring(start, end);
        DualMachineUsageAuthorizationContract.EntitlementStatus proof =
                new DualMachineUsageAuthorizationContract.EntitlementStatus();
        proof.entitlementId = entitlement.entitlementId;
        proof.pairId = entitlement.pairId;
        proof.protocolVersion = entitlement.protocolVersion;
        proof.requestNonce = nonceHex;
        proof.revocationVersion = entitlement.revocationVersion;
        byte[] rebuilt = DualMachineUsageAuthorizationContract
                .entitlementStatus(proof);
        try {
            if (!java.security.MessageDigest.isEqual(
                    canonicalPayload, rebuilt)) {
                throw new GeneralSecurityException(
                        "Host status proof payload does not match the pair");
            }
        } finally {
            Arrays.fill(rebuilt, (byte) 0);
        }
        return decodeLowerHex(nonceHex);
    }

    private void installAuthenticatedControlRecords()
            throws GeneralSecurityException {
        byte[] androidToHost = null;
        byte[] hostToAndroid = null;
        try {
            androidToHost = session.controlAndroidToHostMaterial();
            hostToAndroid = session.controlHostToAndroidMaterial();
            controlSender = AuthenticatedControlRecordV1.newSender(
                    androidToHost,
                    AuthenticatedControlRecordV1.createDomain(
                            session.connectionId(),
                            session.sessionGeneration(),
                            1,
                            AuthenticatedControlRecordV1.Direction
                                    .ANDROID_TO_HOST));
            controlReceiver = AuthenticatedControlRecordV1.newReceiver(
                    hostToAndroid,
                    AuthenticatedControlRecordV1.createDomain(
                            session.connectionId(),
                            session.sessionGeneration(),
                            1,
                            AuthenticatedControlRecordV1.Direction
                                    .HOST_TO_ANDROID));
        } finally {
            clear(androidToHost);
            clear(hostToAndroid);
        }
    }

    private byte[] readHost()
            throws AuthenticatedControlTcpChannelV1.ChannelException {
        return channel.readBootstrapRecord(
                AuthenticatedControlBootstrapRecordV1.Direction
                        .HOST_TO_ANDROID,
                IO_TIMEOUT_MILLIS);
    }

    private void writeAndroid(byte[] record)
            throws AuthenticatedControlTcpChannelV1.ChannelException {
        channel.writeBootstrapRecord(
                record,
                AuthenticatedControlBootstrapRecordV1.Direction
                        .ANDROID_TO_HOST,
                IO_TIMEOUT_MILLIS);
    }

    private static String stableRuntimeVersion() {
        String version = BuildConfig.VERSION_NAME;
        int suffix = version.indexOf('-');
        return suffix < 0 ? version : version.substring(0, suffix);
    }

    private void requireOpen() throws GeneralSecurityException {
        if (closed) {
            throw new GeneralSecurityException(
                    "bound authenticated-control owner is closed");
        }
    }

    private void requireAuthenticated() throws GeneralSecurityException {
        requireOpen();
        if (session == null || channel == null || !channel.isOpen()) {
            throw new GeneralSecurityException(
                    "bound authenticated-control session is unavailable");
        }
    }

    @Override
    public void close() {
        synchronized (channelLock) {
            if (closed) return;
            closed = true;
            if (handshake != null) handshake.close();
            handshake = null;
            if (session != null) session.close();
            session = null;
            if (controlSender != null) controlSender.close();
            controlSender = null;
            if (controlReceiver != null) controlReceiver.close();
            controlReceiver = null;
            if (channel != null) channel.close();
            channel = null;
            diagnosticStage = "closed";
        }
    }

    private static boolean constantTimePrefix(byte[] value, byte[] prefix) {
        if (value == null || prefix == null || value.length < prefix.length) {
            return false;
        }
        int difference = 0;
        for (int index = 0; index < prefix.length; index++) {
            difference |= value[index] ^ prefix[index];
        }
        return difference == 0;
    }

    private static byte[] decodeLowerHex(String value)
            throws GeneralSecurityException {
        if (value == null || value.length() != 32) {
            throw new GeneralSecurityException("status nonce is malformed");
        }
        byte[] output = new byte[16];
        for (int index = 0; index < output.length; index++) {
            int high = Character.digit(value.charAt(index * 2), 16);
            int low = Character.digit(value.charAt(index * 2 + 1), 16);
            if (high < 0 || low < 0
                    || Character.isUpperCase(value.charAt(index * 2))
                    || Character.isUpperCase(value.charAt(index * 2 + 1))) {
                Arrays.fill(output, (byte) 0);
                throw new GeneralSecurityException(
                        "status nonce is not lowercase hexadecimal");
            }
            output[index] = (byte) ((high << 4) | low);
        }
        return output;
    }

    private static byte[] decodeLowerHexSha256(String value)
            throws GeneralSecurityException {
        if (value == null || value.length() != 64) {
            throw new GeneralSecurityException(
                    "usage lease digest is malformed");
        }
        byte[] output = new byte[32];
        for (int index = 0; index < output.length; index++) {
            char highCharacter = value.charAt(index * 2);
            char lowCharacter = value.charAt(index * 2 + 1);
            int high = Character.digit(highCharacter, 16);
            int low = Character.digit(lowCharacter, 16);
            if (high < 0 || low < 0
                    || Character.isUpperCase(highCharacter)
                    || Character.isUpperCase(lowCharacter)) {
                Arrays.fill(output, (byte) 0);
                throw new GeneralSecurityException(
                        "usage lease digest is malformed");
            }
            output[index] = (byte) ((high << 4) | low);
        }
        return output;
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }
}
