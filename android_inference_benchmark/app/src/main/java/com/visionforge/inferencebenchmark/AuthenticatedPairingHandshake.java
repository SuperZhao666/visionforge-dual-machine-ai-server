package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapPayloadV1;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapPayloadV1.ParsedPayload;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.Direction;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.MessageType;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.Record;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1;
import com.visionforge.inferencebenchmark.handshake.ControlBootstrapSequenceV1;
import com.visionforge.inferencebenchmark.handshake.FreshP256KeyAgreement;
import com.visionforge.inferencebenchmark.handshake.HandshakeTranscriptV1;
import com.visionforge.inferencebenchmark.handshake.PairGenerationCredentialV1Verifier;
import com.visionforge.inferencebenchmark.handshake.PairGenerationPopV1;
import com.visionforge.inferencebenchmark.handshake.PairGenerationProposalV1;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Android owner for the exact nine-record authenticated control bootstrap.
 *
 * <p>The coordinator accepts complete VFB1 records, rebuilds every typed
 * pair-generation and peer-handshake object locally, and releases a confirmed
 * session only after the Host transcript signature and Host Finished proof
 * both verify. A failure burns this owner and its fresh ephemeral key; callers
 * must open a new TCP connection and create a new coordinator.</p>
 */
public final class AuthenticatedPairingHandshake implements AutoCloseable {
    @FunctionalInterface
    public interface HexIdSource {
        String nextHex128();
    }

    @FunctionalInterface
    interface NonceSource {
        byte[] nextNonce();
    }

    @FunctionalInterface
    interface EpochSecondsSource {
        long now();
    }

    interface AndroidIdentityCapability
            extends AndroidBoundPeerHandshakeSession.TranscriptIdentity {
        byte[] signPairGenerationChallenge(
                PairGenerationPopV1.ChallengeRequest request,
                DualMachineEntitlementRecord expectedPair)
                throws GeneralSecurityException;

        byte[] signPairGenerationFinalProof(
                PairGenerationPopV1.FinalCredentialProof proof,
                DualMachineEntitlementRecord expectedPair)
                throws GeneralSecurityException;
    }

    interface PairGenerationAuthority {
        DualMachineSidecarPort.PairGenerationChallengeResponse createChallenge(
                PairGenerationPopV1.ChallengeRequest request,
                byte[] hostSignature,
                byte[] androidSignature) throws Exception;

        AuthorizedGeneration issueCredential(
                PairGenerationPopV1.FinalCredentialProof proof,
                DualMachineSidecarPort.PairGenerationChallengeResponse challenge,
                PairGenerationProposalV1 proposal,
                byte[] hostSignature,
                byte[] androidSignature,
                DualMachineEntitlementRecord expectedPair,
                long nowEpochSeconds) throws Exception;
    }

    static final class AuthorizedGeneration {
        final long generation;
        final long connectionId;
        final String credentialToken;

        AuthorizedGeneration(
                long generation,
                long connectionId,
                String credentialToken) {
            if (generation <= 0L || connectionId <= 0L
                    || credentialToken == null || credentialToken.isEmpty()) {
                throw new IllegalArgumentException(
                        "authorized pair generation is invalid");
            }
            this.generation = generation;
            this.connectionId = connectionId;
            this.credentialToken = credentialToken;
        }
    }

    public enum Reason {
        INVALID_CONFIGURATION,
        UNEXPECTED_RECORD,
        PAIR_BINDING_MISMATCH,
        SERVER_AUTHORIZATION_REJECTED,
        CRYPTOGRAPHIC_VERIFICATION_FAILED,
        CLOSED
    }

    /** Sanitized failure; no peer bytes, credentials, signatures or keys. */
    public static final class PairingException
            extends GeneralSecurityException {
        private static final long serialVersionUID = 1L;
        private final Reason reason;

        private PairingException(Reason reason) {
            super("authenticated pairing handshake was rejected");
            this.reason = reason;
        }

        public Reason reason() {
            return reason;
        }
    }

    private final DualMachineEntitlementRecord expectedPair;
    private final AndroidIdentityCapability androidIdentity;
    private final PairGenerationAuthority authority;
    private final String androidRuntimeVersion;
    private final HexIdSource idSource;
    private final NonceSource nonceSource;
    private final EpochSecondsSource epochSecondsSource;
    private final ControlBootstrapSequenceV1 sequence =
            new ControlBootstrapSequenceV1(
                    ControlBootstrapSequenceV1.Role.ANDROID);

    private FreshP256KeyAgreement androidEphemeral;
    private AndroidBoundPeerHandshakeSession boundSession;
    private byte[] hostIdentitySpki;
    private byte[] hostIdentitySha256;
    private byte[] androidIdentitySha256;
    private byte[] hostEphemeralPublicKey;
    private byte[] androidEphemeralPublicKey;
    private byte[] hostNonce;
    private byte[] androidNonce;
    private byte[] hostIpv4;
    private byte[] androidIpv4;
    private byte[] androidChallengeSignature;
    private PairGenerationPopV1.ChallengeRequest challengeRequest;
    private DualMachineSidecarPort.PairGenerationChallengeResponse
            serverChallenge;
    private PairGenerationProposalV1 proposal;
    private AuthorizedGeneration authorizedGeneration;
    private AuthenticatedPeerHandshakeV1.TransportKind transportKind;
    private int videoPort;
    private int controlPort;
    private String hostRuntimeVersion;
    private boolean completed;
    private boolean closed;

    /** Production factory: concrete AndroidKeyStore identity and pinned verifier only. */
    public static AuthenticatedPairingHandshake create(
            DualMachineEntitlementRecord expectedPair,
            AndroidPairingIdentityStore androidIdentityStore,
            DualMachineSidecarPort sidecar,
            PairGenerationCredentialV1Verifier credentialVerifier,
            String androidRuntimeVersion,
            HexIdSource idSource) throws PairingException {
        if (androidIdentityStore == null || sidecar == null
                || credentialVerifier == null) {
            throw failure(Reason.INVALID_CONFIGURATION);
        }
        SecureRandom random = new SecureRandom();
        return createWithTypedCapabilities(
                expectedPair,
                new StoreBackedAndroidIdentity(androidIdentityStore),
                new VerifiedSidecarAuthority(sidecar, credentialVerifier),
                androidRuntimeVersion,
                idSource,
                () -> {
                    byte[] nonce = new byte[32];
                    random.nextBytes(nonce);
                    return nonce;
                },
                () -> System.currentTimeMillis() / 1000L);
    }

    static AuthenticatedPairingHandshake createWithTypedCapabilities(
            DualMachineEntitlementRecord expectedPair,
            AndroidIdentityCapability androidIdentity,
            PairGenerationAuthority authority,
            String androidRuntimeVersion,
            HexIdSource idSource,
            NonceSource nonceSource,
            EpochSecondsSource epochSecondsSource) throws PairingException {
        try {
            return new AuthenticatedPairingHandshake(
                    expectedPair,
                    androidIdentity,
                    authority,
                    androidRuntimeVersion,
                    idSource,
                    nonceSource,
                    epochSecondsSource,
                    AuthenticatedPeerHandshakeV1
                            .generateFreshEphemeralKeyAgreement());
        } catch (Exception failure) {
            throw failure(Reason.INVALID_CONFIGURATION);
        }
    }

    private AuthenticatedPairingHandshake(
            DualMachineEntitlementRecord expectedPair,
            AndroidIdentityCapability androidIdentity,
            PairGenerationAuthority authority,
            String androidRuntimeVersion,
            HexIdSource idSource,
            NonceSource nonceSource,
            EpochSecondsSource epochSecondsSource,
            FreshP256KeyAgreement androidEphemeral) throws Exception {
        byte[] androidDigest = null;
        byte[] ephemeralPublicKey = null;
        byte[] nonce = null;
        try {
            if (expectedPair == null || expectedPair.revoked
                    || !expectedPair.hasActivePairSecurityBinding()
                    || androidIdentity == null || authority == null
                    || idSource == null || nonceSource == null
                    || epochSecondsSource == null || androidEphemeral == null
                    || !stableSemVer(androidRuntimeVersion)) {
                throw failure(Reason.INVALID_CONFIGURATION);
            }
            if (!expectedPair.androidIdentityAlias.equals(
                    androidIdentity.alias())) {
                throw failure(Reason.PAIR_BINDING_MISMATCH);
            }
            byte[] androidSpki = androidIdentity.publicKeySpkiDer();
            try {
                DualMachinePairingIdentityCodec.requirePublicKey(androidSpki);
                String actualFingerprint =
                        DualMachinePairingIdentityCodec.fingerprintHex(
                                androidSpki);
                if (!expectedPair.androidKeySha256.equals(
                        actualFingerprint)) {
                    throw failure(Reason.PAIR_BINDING_MISMATCH);
                }
                androidDigest = sha256(androidSpki);
            } finally {
                clear(androidSpki);
            }
            ephemeralPublicKey = androidEphemeral.publicKeySec1();
            nonce = requireNonce(nonceSource.nextNonce());
        } catch (Exception rejected) {
            closeFresh(androidEphemeral);
            clear(androidDigest);
            clear(ephemeralPublicKey);
            clear(nonce);
            throw rejected;
        }
        this.expectedPair = expectedPair;
        this.androidIdentity = androidIdentity;
        this.authority = authority;
        this.androidRuntimeVersion = androidRuntimeVersion;
        this.idSource = idSource;
        this.nonceSource = nonceSource;
        this.epochSecondsSource = epochSecondsSource;
        this.androidIdentitySha256 = androidDigest;
        this.androidEphemeral = androidEphemeral;
        this.androidEphemeralPublicKey = ephemeralPublicKey;
        this.androidNonce = nonce;
    }

    public synchronized byte[] acceptHostHello(byte[] encodedRecord)
            throws PairingException {
        try {
            ParsedPayload payload = parseInbound(
                    encodedRecord, MessageType.HOST_HELLO);
            try {
                hostIdentitySpki = payload.field(
                        AuthenticatedControlBootstrapPayloadV1.HostHelloField
                                .HOST_IDENTITY_SPKI_DER);
                byte[] expectedHostSpki = expectedPair.hostIdentityPublicKeyDer();
                try {
                    if (!MessageDigest.isEqual(
                            expectedHostSpki, hostIdentitySpki)
                            || !expectedPair.hostKeySha256.equals(
                            DualMachinePairingIdentityCodec.fingerprintHex(
                                    hostIdentitySpki))) {
                        throw failure(Reason.PAIR_BINDING_MISMATCH);
                    }
                } finally {
                    clear(expectedHostSpki);
                }
                hostIdentitySha256 = sha256(hostIdentitySpki);
                if (MessageDigest.isEqual(
                        hostIdentitySha256, androidIdentitySha256)) {
                    throw failure(Reason.PAIR_BINDING_MISMATCH);
                }
                hostEphemeralPublicKey = payload.field(
                        AuthenticatedControlBootstrapPayloadV1.HostHelloField
                                .HOST_EPHEMERAL_PUBLIC_KEY);
                hostNonce = payload.field(
                        AuthenticatedControlBootstrapPayloadV1.HostHelloField
                                .HOST_NONCE);
                transportKind = transportKind(payload.field(
                        AuthenticatedControlBootstrapPayloadV1.HostHelloField
                                .TRANSPORT_KIND));
                hostIpv4 = payload.field(
                        AuthenticatedControlBootstrapPayloadV1.HostHelloField
                                .HOST_IPV4);
                androidIpv4 = payload.field(
                        AuthenticatedControlBootstrapPayloadV1.HostHelloField
                                .ANDROID_IPV4);
                videoPort = AuthenticatedControlBootstrapPayloadV1
                        .readUnsigned16(payload.field(
                        AuthenticatedControlBootstrapPayloadV1.HostHelloField
                                .VIDEO_PORT));
                controlPort = AuthenticatedControlBootstrapPayloadV1
                        .readUnsigned16(payload.field(
                        AuthenticatedControlBootstrapPayloadV1.HostHelloField
                                .CONTROL_PORT));
                hostRuntimeVersion = ascii(payload.field(
                        AuthenticatedControlBootstrapPayloadV1.HostHelloField
                                .HOST_RUNTIME_VERSION));
            } finally {
                payload.close();
            }

            PairGenerationPopV1.ChallengeFields fields =
                    new PairGenerationPopV1.ChallengeFields(
                            requireId(idSource.nextHex128()),
                            requireId(idSource.nextHex128()),
                            expectedPair.entitlementId,
                            expectedPair.pairId,
                            expectedPair.bindingId,
                            expectedPair.bindingRevision,
                            expectedPair.revocationVersion,
                            expectedPair.hostKeySha256,
                            expectedPair.androidKeySha256);
            challengeRequest =
                    PairGenerationPopV1.buildChallengeRequest(fields);
            androidChallengeSignature =
                    androidIdentity.signPairGenerationChallenge(
                            challengeRequest, expectedPair);
            byte[] androidSpki = androidIdentity.publicKeySpkiDer();
            try {
                byte[] payloadBytes =
                        AuthenticatedControlBootstrapPayloadV1.encode(
                                MessageType.ANDROID_CHALLENGE_REQUEST,
                                ascii(fields.requestId),
                                ascii(fields.allocationRequestId),
                                ascii(fields.entitlementId),
                                ascii(fields.pairId),
                                ascii(fields.bindingId),
                                u64(fields.bindingRevision),
                                u64(fields.revocationVersion),
                                androidSpki,
                                androidEphemeralPublicKey,
                                androidNonce,
                                ascii(androidRuntimeVersion),
                                androidChallengeSignature);
                return finishExchange(
                        MessageType.HOST_HELLO,
                        MessageType.ANDROID_CHALLENGE_REQUEST,
                        payloadBytes);
            } finally {
                clear(androidSpki);
            }
        } catch (Exception rejected) {
            throw burn(rejected);
        }
    }

    public synchronized byte[] acceptHostChallengeProof(byte[] encodedRecord)
            throws PairingException {
        byte[] hostSignature = null;
        try {
            ParsedPayload payload = parseInbound(
                    encodedRecord, MessageType.HOST_CHALLENGE_PROOF);
            try {
                hostSignature = payload.field(0);
            } finally {
                payload.close();
            }
            serverChallenge = authority.createChallenge(
                    challengeRequest,
                    hostSignature,
                    androidChallengeSignature);
            requireChallengeResponse(serverChallenge);
            byte[] payloadBytes = AuthenticatedControlBootstrapPayloadV1.encode(
                    MessageType.SERVER_CHALLENGE,
                    ascii(serverChallenge.challengeId),
                    u64(serverChallenge.expiresAtEpoch),
                    serverChallenge.serverNonce());
            return finishExchange(
                    MessageType.HOST_CHALLENGE_PROOF,
                    MessageType.SERVER_CHALLENGE,
                    payloadBytes);
        } catch (Exception rejected) {
            throw burn(rejected);
        } finally {
            clear(hostSignature);
        }
    }

    public synchronized byte[] acceptHostFinalProof(byte[] encodedRecord)
            throws PairingException {
        byte[] hostSignature = null;
        byte[] androidSignature = null;
        try {
            ParsedPayload payload = parseInbound(
                    encodedRecord, MessageType.HOST_FINAL_PROOF);
            try {
                hostSignature = payload.field(0);
            } finally {
                payload.close();
            }
            long connectionId = PairGenerationPopV1.deriveConnectionId(
                    serverChallenge.serverNonce(),
                    serverChallenge.challengeId,
                    hostNonce,
                    androidNonce,
                    expectedPair.pairId,
                    expectedPair.hostKeySha256,
                    expectedPair.androidKeySha256);
            proposal = PairGenerationProposalV1.newBuilder()
                    .hostIdentitySpkiSha256(hostIdentitySha256)
                    .androidIdentitySpkiSha256(androidIdentitySha256)
                    .hostEphemeralPublicKey(hostEphemeralPublicKey)
                    .androidEphemeralPublicKey(androidEphemeralPublicKey)
                    .hostNonce(hostNonce)
                    .androidNonce(androidNonce)
                    .connectionId(connectionId)
                    .transportKind(transportKind)
                    .hostIpv4(hostIpv4)
                    .androidIpv4(androidIpv4)
                    .videoPort(videoPort)
                    .controlPort(controlPort)
                    .pairId(expectedPair.pairId)
                    .hostRuntimeVersion(hostRuntimeVersion)
                    .androidRuntimeVersion(androidRuntimeVersion)
                    .build();
            PairGenerationPopV1.FinalCredentialProof proof =
                    PairGenerationPopV1.buildFinalCredentialProof(
                            challengeRequest,
                            serverChallenge.challengeId,
                            serverChallenge.expiresAtEpoch,
                            serverChallenge.serverNonce(),
                            proposal);
            androidSignature = androidIdentity.signPairGenerationFinalProof(
                    proof, expectedPair);
            authorizedGeneration = authority.issueCredential(
                    proof,
                    serverChallenge,
                    proposal,
                    hostSignature,
                    androidSignature,
                    expectedPair,
                    requireEpoch(epochSecondsSource.now()));
            if (authorizedGeneration.connectionId != connectionId) {
                throw failure(Reason.SERVER_AUTHORIZATION_REJECTED);
            }
            byte[] payloadBytes = AuthenticatedControlBootstrapPayloadV1.encode(
                    MessageType.PAIR_GENERATION_CREDENTIAL,
                    ascii(authorizedGeneration.credentialToken));
            return finishExchange(
                    MessageType.HOST_FINAL_PROOF,
                    MessageType.PAIR_GENERATION_CREDENTIAL,
                    payloadBytes);
        } catch (Exception rejected) {
            throw burn(rejected);
        } finally {
            clear(hostSignature);
            clear(androidSignature);
        }
    }

    public synchronized byte[] acceptHostHandshakeSignature(
            byte[] encodedRecord) throws PairingException {
        byte[] hostSignature = null;
        byte[] androidTranscriptSignature = null;
        byte[] androidFinished = null;
        try {
            ParsedPayload payload = parseInbound(
                    encodedRecord, MessageType.HOST_HANDSHAKE_SIGNATURE);
            try {
                hostSignature = payload.field(0);
            } finally {
                payload.close();
            }
            HandshakeTranscriptV1 transcript = proposal
                    .buildFinalHandshakeTranscript(
                            authorizedGeneration.generation);
            FreshP256KeyAgreement fresh = androidEphemeral;
            androidEphemeral = null;
            boundSession = AndroidBoundPeerHandshakeSession
                    .bindWithTypedIdentityForCoordinator(
                            expectedPair,
                            androidIdentity,
                            fresh,
                            transcript,
                            hostSignature);
            androidTranscriptSignature =
                    boundSession.androidTranscriptSignature();
            androidFinished = boundSession.createAndroidFinished();
            byte[] payloadBytes = AuthenticatedControlBootstrapPayloadV1.encode(
                    MessageType.ANDROID_HANDSHAKE_CONFIRMATION,
                    androidTranscriptSignature,
                    androidFinished);
            authorizedGeneration = null;
            return finishExchange(
                    MessageType.HOST_HANDSHAKE_SIGNATURE,
                    MessageType.ANDROID_HANDSHAKE_CONFIRMATION,
                    payloadBytes);
        } catch (Exception rejected) {
            throw burn(rejected);
        } finally {
            clear(hostSignature);
            clear(androidTranscriptSignature);
            clear(androidFinished);
        }
    }

    public synchronized ConfirmedAndroidPeerSession acceptHostFinished(
            byte[] encodedRecord) throws PairingException {
        byte[] hostFinished = null;
        try {
            ParsedPayload payload = parseInbound(
                    encodedRecord, MessageType.HOST_FINISHED);
            try {
                hostFinished = payload.field(0);
            } finally {
                payload.close();
            }
            ConfirmedAndroidPeerSession confirmed =
                    boundSession.confirmHostFinished(hostFinished);
            boundSession = null;
            ControlBootstrapSequenceV1.AdvanceStatus status =
                    sequence.advanceInbound(MessageType.HOST_FINISHED);
            if (status != ControlBootstrapSequenceV1.AdvanceStatus.COMPLETED) {
                confirmed.close();
                throw failure(Reason.UNEXPECTED_RECORD);
            }
            completed = true;
            closed = true;
            clearOwnedPublicState();
            return confirmed;
        } catch (Exception rejected) {
            throw burn(rejected);
        } finally {
            clear(hostFinished);
        }
    }

    public synchronized boolean isCompleted() {
        return completed;
    }

    @Override
    public synchronized void close() {
        if (closed && completed) return;
        closed = true;
        completed = false;
        closeFresh(androidEphemeral);
        androidEphemeral = null;
        if (boundSession != null) boundSession.close();
        boundSession = null;
        clearOwnedPublicState();
    }

    private ParsedPayload parseInbound(
            byte[] encodedRecord,
            MessageType expectedType) throws Exception {
        requireOpen();
        ControlBootstrapSequenceV1.ExpectedEvent expected =
                sequence.expectedNext();
        if (expected == null
                || expected.flow() != ControlBootstrapSequenceV1.Flow.INBOUND
                || expected.messageType() != expectedType) {
            throw failure(Reason.UNEXPECTED_RECORD);
        }
        try (Record record = AuthenticatedControlBootstrapRecordV1.parse(
                encodedRecord, Direction.HOST_TO_ANDROID)) {
            if (record.messageType() != expectedType) {
                throw failure(Reason.UNEXPECTED_RECORD);
            }
            return AuthenticatedControlBootstrapPayloadV1.parse(
                    expectedType, record.payload());
        }
    }

    private byte[] finishExchange(
            MessageType inbound,
            MessageType outbound,
            byte[] payload) throws Exception {
        byte[] record = null;
        try {
            record = AuthenticatedControlBootstrapRecordV1.encode(
                    Direction.ANDROID_TO_HOST, outbound, payload);
            if (sequence.advanceInbound(inbound)
                    != ControlBootstrapSequenceV1.AdvanceStatus.ADVANCED
                    || sequence.advanceOutbound(outbound)
                    != ControlBootstrapSequenceV1.AdvanceStatus.ADVANCED) {
                clear(record);
                throw failure(Reason.UNEXPECTED_RECORD);
            }
            return record;
        } finally {
            clear(payload);
        }
    }

    private void requireChallengeResponse(
            DualMachineSidecarPort.PairGenerationChallengeResponse response)
            throws PairingException {
        PairGenerationPopV1.ChallengeFields fields = challengeRequest.fields();
        if (response == null
                || !fields.requestId.equals(response.requestId)
                || !fields.allocationRequestId.equals(
                response.allocationRequestId)
                || !fields.pairId.equals(response.pairId)
                || fields.bindingRevision != response.bindingRevision
                || response.expiresAtEpoch <= requireEpoch(
                epochSecondsSource.now())) {
            throw failure(Reason.SERVER_AUTHORIZATION_REJECTED);
        }
    }

    private void clearOwnedPublicState() {
        clear(hostIdentitySpki);
        hostIdentitySpki = null;
        clear(hostIdentitySha256);
        hostIdentitySha256 = null;
        clear(androidIdentitySha256);
        androidIdentitySha256 = null;
        clear(hostEphemeralPublicKey);
        hostEphemeralPublicKey = null;
        clear(androidEphemeralPublicKey);
        androidEphemeralPublicKey = null;
        clear(hostNonce);
        hostNonce = null;
        clear(androidNonce);
        androidNonce = null;
        clear(hostIpv4);
        hostIpv4 = null;
        clear(androidIpv4);
        androidIpv4 = null;
        clear(androidChallengeSignature);
        androidChallengeSignature = null;
        challengeRequest = null;
        serverChallenge = null;
        proposal = null;
        authorizedGeneration = null;
        hostRuntimeVersion = null;
    }

    private void requireOpen() throws PairingException {
        if (closed || completed) throw failure(Reason.CLOSED);
    }

    private PairingException burn(Exception rejected) {
        Reason reason = rejected instanceof PairingException
                ? ((PairingException) rejected).reason()
                : rejected instanceof java.io.IOException
                ? Reason.SERVER_AUTHORIZATION_REJECTED
                : Reason.CRYPTOGRAPHIC_VERIFICATION_FAILED;
        close();
        return failure(reason);
    }

    private static final class StoreBackedAndroidIdentity
            implements AndroidIdentityCapability {
        private final AndroidPairingIdentityStore store;

        private StoreBackedAndroidIdentity(AndroidPairingIdentityStore store) {
            this.store = store;
        }

        @Override
        public String alias() {
            return store.alias();
        }

        @Override
        public byte[] publicKeySpkiDer() throws GeneralSecurityException {
            return store.publicKeySpkiDer();
        }

        @Override
        public byte[] signTranscript(
                HandshakeTranscriptV1 transcript,
                DualMachineEntitlementRecord expectedPair)
                throws GeneralSecurityException {
            return store.signHandshakeTranscript(transcript, expectedPair);
        }

        @Override
        public byte[] signPairGenerationChallenge(
                PairGenerationPopV1.ChallengeRequest request,
                DualMachineEntitlementRecord expectedPair)
                throws GeneralSecurityException {
            return store.signPairGenerationChallenge(request, expectedPair);
        }

        @Override
        public byte[] signPairGenerationFinalProof(
                PairGenerationPopV1.FinalCredentialProof proof,
                DualMachineEntitlementRecord expectedPair)
                throws GeneralSecurityException {
            return store.signPairGenerationFinalProof(proof, expectedPair);
        }
    }

    private static final class VerifiedSidecarAuthority
            implements PairGenerationAuthority {
        private final DualMachineSidecarPort sidecar;
        private final PairGenerationCredentialV1Verifier verifier;

        private VerifiedSidecarAuthority(
                DualMachineSidecarPort sidecar,
                PairGenerationCredentialV1Verifier verifier) {
            this.sidecar = sidecar;
            this.verifier = verifier;
        }

        @Override
        public DualMachineSidecarPort.PairGenerationChallengeResponse
                createChallenge(
                PairGenerationPopV1.ChallengeRequest request,
                byte[] hostSignature,
                byte[] androidSignature) throws Exception {
            return sidecar.createPairGenerationChallenge(
                    new DualMachineSidecarPort.PairGenerationChallengeRequest(
                            request,
                            Base64.getEncoder().encodeToString(hostSignature),
                            Base64.getEncoder().encodeToString(
                                    androidSignature)));
        }

        @Override
        public AuthorizedGeneration issueCredential(
                PairGenerationPopV1.FinalCredentialProof proof,
                DualMachineSidecarPort.PairGenerationChallengeResponse challenge,
                PairGenerationProposalV1 proposal,
                byte[] hostSignature,
                byte[] androidSignature,
                DualMachineEntitlementRecord expectedPair,
                long nowEpochSeconds) throws Exception {
            DualMachineSidecarPort.PairGenerationCredentialResponse response =
                    sidecar.issuePairGenerationCredential(
                            new DualMachineSidecarPort
                                    .PairGenerationCredentialRequest(
                                    proof,
                                    challenge,
                                    proposal,
                                    Base64.getEncoder().encodeToString(
                                            hostSignature),
                                    Base64.getEncoder().encodeToString(
                                            androidSignature)));
            String proposalSha256 = hex(proposal.proposalSha256());
            PairGenerationCredentialV1Verifier.ExpectedV1 expected =
                    new PairGenerationCredentialV1Verifier.ExpectedV1(
                            challenge.allocationRequestId,
                            expectedPair.pairId,
                            expectedPair.entitlementId,
                            expectedPair.bindingId,
                            expectedPair.bindingRevision,
                            expectedPair.revocationVersion,
                            response.generation,
                            proposal.connectionId(),
                            expectedPair.hostKeySha256,
                            expectedPair.androidKeySha256,
                            proposalSha256);
            PairGenerationCredentialV1Verifier
                    .VerifiedPairGenerationCredentialV1 verified =
                    verifier.verify(
                            response.credentialToken,
                            expected,
                            nowEpochSeconds);
            if (verified.generation() != response.generation
                    || verified.connectionId() != response.connectionId
                    || !verified.transcriptProposalSha256().equals(
                    response.transcriptProposalSha256)) {
                throw failure(Reason.SERVER_AUTHORIZATION_REJECTED);
            }
            return new AuthorizedGeneration(
                    verified.generation(),
                    verified.connectionId(),
                    response.credentialToken);
        }
    }

    private static AuthenticatedPeerHandshakeV1.TransportKind transportKind(
            byte[] encoded) throws PairingException {
        if (encoded == null || encoded.length != 1) {
            throw failure(Reason.UNEXPECTED_RECORD);
        }
        if (encoded[0] == 1) return AuthenticatedPeerHandshakeV1.TransportKind.CAT6;
        if (encoded[0] == 2) return AuthenticatedPeerHandshakeV1.TransportKind.WLAN;
        throw failure(Reason.UNEXPECTED_RECORD);
    }

    private static byte[] requireNonce(byte[] value) throws PairingException {
        if (value == null || value.length != 32 || allZero(value)) {
            clear(value);
            throw failure(Reason.INVALID_CONFIGURATION);
        }
        return value.clone();
    }

    private static String requireId(String value) throws PairingException {
        if (value == null || value.length() != 32
                || value.equals("0".repeat(32))) {
            throw failure(Reason.INVALID_CONFIGURATION);
        }
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (!((current >= '0' && current <= '9')
                    || (current >= 'a' && current <= 'f'))) {
                throw failure(Reason.INVALID_CONFIGURATION);
            }
        }
        return value;
    }

    private static long requireEpoch(long value) throws PairingException {
        if (value <= 0L) throw failure(Reason.INVALID_CONFIGURATION);
        return value;
    }

    private static byte[] sha256(byte[] value)
            throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(value);
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static String ascii(byte[] value) {
        return new String(value, StandardCharsets.US_ASCII);
    }

    private static byte[] u64(long value) {
        return ByteBuffer.allocate(Long.BYTES).putLong(value).array();
    }

    private static String hex(byte[] value) {
        char[] alphabet = "0123456789abcdef".toCharArray();
        char[] encoded = new char[value.length * 2];
        for (int index = 0; index < value.length; index++) {
            int current = value[index] & 0xff;
            encoded[index * 2] = alphabet[current >>> 4];
            encoded[index * 2 + 1] = alphabet[current & 0x0f];
        }
        return new String(encoded);
    }

    private static boolean stableSemVer(String value) {
        if (value == null || value.isEmpty() || value.length() > 32) return false;
        return value.matches("(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)");
    }

    private static boolean allZero(byte[] value) {
        int aggregate = 0;
        for (byte current : value) aggregate |= current;
        return aggregate == 0;
    }

    private static PairingException failure(Reason reason) {
        return new PairingException(reason);
    }

    private static void closeFresh(FreshP256KeyAgreement value) {
        if (value != null) value.close();
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }
}
