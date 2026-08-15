package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1;
import com.visionforge.inferencebenchmark.handshake.FreshP256KeyAgreement;
import com.visionforge.inferencebenchmark.handshake.HandshakeTranscriptV1;
import com.visionforge.inferencebenchmark.handshake.PeerHandshakeSecrets;
import com.visionforge.inferencebenchmark.handshake.PendingPeerHandshakeConfirmation;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Android owner for one entitlement-bound, identity-authenticated peer handshake.
 *
 * <p>The caller must locally rebuild the typed transcript; this class never
 * parses a peer-provided transcript blob. It binds that transcript to the
 * activated entitlement, the actual AndroidKeyStore identity, the fresh
 * Android ephemeral key and the Host identity stored in the entitlement. Only
 * after the Host signature and the Android signature have both verified does
 * it derive an unconfirmed ECDH schedule.</p>
 *
 * <p>This foundation deliberately has no socket, runtime-service, lease or
 * data-plane integration. Traffic material remains unavailable until the Host
 * Finished proof is accepted.</p>
 */
public final class AndroidBoundPeerHandshakeSession implements AutoCloseable {
    private static final String REJECTED_MESSAGE =
            "authenticated peer handshake was rejected";

    private PendingPeerHandshakeConfirmation pendingConfirmation;
    private byte[] androidTranscriptSignature;
    private byte[] transcriptHashSha256;
    private byte[] hostIpv4;
    private byte[] androidIpv4;
    private final String pairId;
    private final long connectionId;
    private final long sessionGeneration;
    private final AuthenticatedPeerHandshakeV1.TransportKind transportKind;
    private final int videoPort;
    private final int controlPort;
    private boolean androidFinishedCreated;
    private boolean closed;

    private AndroidBoundPeerHandshakeSession(
            PendingPeerHandshakeConfirmation pendingConfirmation,
            byte[] androidTranscriptSignature,
            HandshakeTranscriptV1 transcript,
            byte[] transcriptHashSha256) {
        this.pendingConfirmation = requirePending(pendingConfirmation);
        this.androidTranscriptSignature = requireSignature(
                androidTranscriptSignature, "Android transcript signature");
        this.transcriptHashSha256 = requireLength(
                transcriptHashSha256,
                AuthenticatedPeerHandshakeV1.SHA256_BYTES,
                "transcript hash");
        pairId = transcript.pairId();
        connectionId = transcript.connectionId();
        sessionGeneration = transcript.sessionGeneration();
        transportKind = transcript.transportKind();
        hostIpv4 = requireLength(transcript.hostIpv4(), 4, "Host IPv4");
        androidIpv4 = requireLength(transcript.androidIpv4(), 4, "Android IPv4");
        videoPort = transcript.videoPort();
        controlPort = transcript.controlPort();
    }

    /**
     * Binds a fresh Android ephemeral key to one expected activated pair.
     *
     * <p>The only production identity input is the concrete
     * {@link AndroidPairingIdentityStore}. A caller cannot supply an arbitrary
     * signer, public key, digest, shared secret or verification result.</p>
     */
    public static AndroidBoundPeerHandshakeSession bindExpectedPair(
            DualMachineEntitlementRecord expectedPair,
            AndroidPairingIdentityStore androidIdentityStore,
            FreshP256KeyAgreement freshAndroidEphemeral,
            HandshakeTranscriptV1 locallyRebuiltTranscript,
            byte[] untrustedHostTranscriptSignature)
            throws GeneralSecurityException {
        if (androidIdentityStore == null) {
            closeFresh(freshAndroidEphemeral);
            throw rejected();
        }
        return bindWithTypedIdentity(
                expectedPair,
                new StoreBackedTranscriptIdentity(androidIdentityStore),
                freshAndroidEphemeral,
                locallyRebuiltTranscript,
                untrustedHostTranscriptSignature);
    }

    /** Returns a defensive copy of Android's signature over the checked transcript. */
    public synchronized byte[] androidTranscriptSignature()
            throws GeneralSecurityException {
        requireOpen();
        return androidTranscriptSignature.clone();
    }

    /** Creates Android's Finished proof exactly once. */
    public synchronized byte[] createAndroidFinished()
            throws GeneralSecurityException {
        try {
            requireOpen();
            if (androidFinishedCreated) {
                throw rejected();
            }
            byte[] finished = pendingConfirmation.createLocalFinishedMac();
            androidFinishedCreated = true;
            return finished;
        } catch (GeneralSecurityException | RuntimeException failure) {
            close();
            throw rejected();
        }
    }

    /**
     * Accepts the Host Finished proof and transfers ownership to the confirmed
     * wrapper. Calling this before {@link #createAndroidFinished()} fails closed.
     */
    public synchronized ConfirmedAndroidPeerSession confirmHostFinished(
            byte[] untrustedHostFinished) throws GeneralSecurityException {
        PeerHandshakeSecrets confirmedSecrets = null;
        byte[] hostFinishedCopy = null;
        try {
            requireOpen();
            if (!androidFinishedCreated) {
                throw rejected();
            }
            hostFinishedCopy = requireLength(
                    untrustedHostFinished,
                    AuthenticatedPeerHandshakeV1.FINISHED_MAC_BYTES,
                    "Host Finished");
            confirmedSecrets = pendingConfirmation.confirmPeerFinishedMac(
                    hostFinishedCopy);
            ConfirmedAndroidPeerSession confirmed =
                    new ConfirmedAndroidPeerSession(
                            pairId,
                            connectionId,
                            sessionGeneration,
                            transportKind,
                            hostIpv4,
                            androidIpv4,
                            videoPort,
                            controlPort,
                            transcriptHashSha256,
                            confirmedSecrets);
            confirmedSecrets = null;
            close();
            return confirmed;
        } catch (GeneralSecurityException | RuntimeException failure) {
            if (confirmedSecrets != null) confirmedSecrets.close();
            close();
            throw rejected();
        } finally {
            clear(hostFinishedCopy);
        }
    }

    @Override
    public synchronized void close() {
        if (closed) return;
        closed = true;
        androidFinishedCreated = false;
        PendingPeerHandshakeConfirmation pending = pendingConfirmation;
        pendingConfirmation = null;
        if (pending != null) pending.close();
        clear(androidTranscriptSignature);
        androidTranscriptSignature = null;
        clear(transcriptHashSha256);
        transcriptHashSha256 = null;
        clear(hostIpv4);
        hostIpv4 = null;
        clear(androidIpv4);
        androidIpv4 = null;
    }

    /**
     * Private typed identity boundary shared by the concrete AndroidKeyStore
     * adapter and reflection-based JVM contract tests. It cannot sign raw
     * bytes, accept a digest or inject a verification result.
     */
    private interface TranscriptIdentity {
        String alias();

        byte[] publicKeySpkiDer() throws GeneralSecurityException;

        byte[] signTranscript(
                HandshakeTranscriptV1 transcript,
                DualMachineEntitlementRecord expectedPair)
                throws GeneralSecurityException;
    }

    private static AndroidBoundPeerHandshakeSession bindWithTypedIdentity(
            DualMachineEntitlementRecord expectedPair,
            TranscriptIdentity androidIdentity,
            FreshP256KeyAgreement freshAndroidEphemeral,
            HandshakeTranscriptV1 locallyRebuiltTranscript,
            byte[] untrustedHostTranscriptSignature)
            throws GeneralSecurityException {
        PendingPeerHandshakeConfirmation pending = null;
        byte[] hostSpki = null;
        byte[] androidSpki = null;
        byte[] canonicalTranscript = null;
        byte[] androidSignature = null;
        byte[] transcriptHash = null;
        boolean transferred = false;
        try {
            requireInputs(
                    expectedPair,
                    androidIdentity,
                    freshAndroidEphemeral,
                    locallyRebuiltTranscript);

            requireExpectedPair(expectedPair, locallyRebuiltTranscript);
            hostSpki = requireHostIdentityBinding(
                    expectedPair, locallyRebuiltTranscript);
            androidSpki = requireAndroidIdentityBinding(
                    expectedPair,
                    androidIdentity,
                    locallyRebuiltTranscript,
                    hostSpki);
            requireAndroidEphemeralBinding(
                    freshAndroidEphemeral, locallyRebuiltTranscript);
            canonicalTranscript = locallyRebuiltTranscript.canonicalEncoding();
            requireHostTranscriptSignature(
                    hostSpki,
                    canonicalTranscript,
                    untrustedHostTranscriptSignature,
                    "Host transcript signature");
            androidSignature = createVerifiedAndroidTranscriptSignature(
                    androidIdentity,
                    expectedPair,
                    locallyRebuiltTranscript,
                    androidSpki,
                    canonicalTranscript);
            transcriptHash = locallyRebuiltTranscript.transcriptHashSha256();
            pending = freshAndroidEphemeral.deriveAfterPeerIdentityVerified(
                    locallyRebuiltTranscript,
                    AuthenticatedPeerHandshakeV1.Role.ANDROID);
            AndroidBoundPeerHandshakeSession bound =
                    new AndroidBoundPeerHandshakeSession(
                            pending,
                            androidSignature,
                            locallyRebuiltTranscript,
                            transcriptHash);
            pending = null;
            transferred = true;
            return bound;
        } catch (GeneralSecurityException | RuntimeException failure) {
            throw rejected();
        } finally {
            if (!transferred && pending != null) pending.close();
            closeFresh(freshAndroidEphemeral);
            clear(hostSpki);
            clear(androidSpki);
            clear(canonicalTranscript);
            clear(androidSignature);
            clear(transcriptHash);
        }
    }

    private static byte[] requireHostIdentityBinding(
            DualMachineEntitlementRecord expectedPair,
            HandshakeTranscriptV1 transcript) throws GeneralSecurityException {
        byte[] hostSpki = expectedPair.hostIdentityPublicKeyDer();
        byte[] actualHash = null;
        byte[] declaredHash = null;
        boolean accepted = false;
        try {
            DualMachinePairingIdentityCodec.requirePublicKey(hostSpki);
            requireFingerprint(
                    hostSpki, expectedPair.hostKeySha256, "Host identity");
            actualHash = sha256(hostSpki);
            declaredHash = transcript.hostIdentitySpkiSha256();
            requireEqual(actualHash, declaredHash, "Host identity transcript binding");
            accepted = true;
            return hostSpki;
        } finally {
            if (!accepted) clear(hostSpki);
            clear(actualHash);
            clear(declaredHash);
        }
    }

    private static byte[] requireAndroidIdentityBinding(
            DualMachineEntitlementRecord expectedPair,
            TranscriptIdentity androidIdentity,
            HandshakeTranscriptV1 transcript,
            byte[] hostSpki) throws GeneralSecurityException {
        if (!expectedPair.androidIdentityAlias.equals(androidIdentity.alias())) {
            throw rejected();
        }
        byte[] androidSpki = androidIdentity.publicKeySpkiDer();
        byte[] hostHash = null;
        byte[] androidHash = null;
        byte[] declaredHash = null;
        boolean accepted = false;
        try {
            DualMachinePairingIdentityCodec.requirePublicKey(androidSpki);
            requireFingerprint(
                    androidSpki, expectedPair.androidKeySha256, "Android identity");
            hostHash = sha256(hostSpki);
            androidHash = sha256(androidSpki);
            declaredHash = transcript.androidIdentitySpkiSha256();
            requireEqual(
                    androidHash, declaredHash, "Android identity transcript binding");
            if (MessageDigest.isEqual(hostHash, androidHash)) throw rejected();
            accepted = true;
            return androidSpki;
        } finally {
            if (!accepted) clear(androidSpki);
            clear(hostHash);
            clear(androidHash);
            clear(declaredHash);
        }
    }

    private static void requireAndroidEphemeralBinding(
            FreshP256KeyAgreement freshAndroidEphemeral,
            HandshakeTranscriptV1 transcript) throws GeneralSecurityException {
        byte[] actual = null;
        byte[] declared = null;
        try {
            actual = freshAndroidEphemeral.publicKeySec1();
            declared = transcript.androidEphemeralPublicKey();
            requireEqual(actual, declared, "Android ephemeral transcript binding");
        } finally {
            clear(actual);
            clear(declared);
        }
    }

    private static void requireHostTranscriptSignature(
            byte[] hostSpki,
            byte[] canonicalTranscript,
            byte[] untrustedSignature,
            String label) throws GeneralSecurityException {
        byte[] signature = requireSignature(untrustedSignature, label);
        try {
            if (!DualMachinePairingIdentityCodec.verify(
                    hostSpki, canonicalTranscript, signature)) {
                throw rejected();
            }
        } finally {
            clear(signature);
        }
    }

    private static byte[] createVerifiedAndroidTranscriptSignature(
            TranscriptIdentity androidIdentity,
            DualMachineEntitlementRecord expectedPair,
            HandshakeTranscriptV1 transcript,
            byte[] androidSpki,
            byte[] canonicalTranscript) throws GeneralSecurityException {
        byte[] providerSignature =
                androidIdentity.signTranscript(transcript, expectedPair);
        byte[] signature = null;
        boolean accepted = false;
        try {
            signature = requireSignature(
                    providerSignature, "Android transcript signature");
            if (!DualMachinePairingIdentityCodec.verify(
                    androidSpki, canonicalTranscript, signature)) {
                throw rejected();
            }
            accepted = true;
            return signature;
        } finally {
            clear(providerSignature);
            if (!accepted) clear(signature);
        }
    }

    private static void requireInputs(
            DualMachineEntitlementRecord expectedPair,
            TranscriptIdentity androidIdentity,
            FreshP256KeyAgreement freshAndroidEphemeral,
            HandshakeTranscriptV1 transcript) throws GeneralSecurityException {
        if (expectedPair == null
                || androidIdentity == null
                || freshAndroidEphemeral == null
                || transcript == null) {
            throw rejected();
        }
    }

    private static void requireExpectedPair(
            DualMachineEntitlementRecord expectedPair,
            HandshakeTranscriptV1 transcript) throws GeneralSecurityException {
        if (expectedPair.revoked
                || expectedPair.pairId == null
                || expectedPair.pairId.isEmpty()
                || transcript.pairId().isEmpty()
                || !expectedPair.pairId.equals(transcript.pairId())) {
            throw rejected();
        }
    }

    private static void requireFingerprint(
            byte[] spki, String expectedFingerprint, String label)
            throws GeneralSecurityException {
        String actualFingerprint =
                DualMachinePairingIdentityCodec.fingerprintHex(spki);
        if (!actualFingerprint.equals(expectedFingerprint)) {
            throw new GeneralSecurityException(label + " is not pair-bound");
        }
    }

    private static byte[] sha256(byte[] value) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(value);
    }

    private static void requireEqual(byte[] left, byte[] right, String label)
            throws GeneralSecurityException {
        if (!MessageDigest.isEqual(left, right)) {
            throw new GeneralSecurityException(label + " mismatch");
        }
    }

    private static PendingPeerHandshakeConfirmation requirePending(
            PendingPeerHandshakeConfirmation value) {
        if (value == null) {
            throw new IllegalArgumentException("pending confirmation is required");
        }
        return value;
    }

    private static byte[] requireSignature(byte[] value, String label) {
        if (value == null
                || value.length == 0
                || value.length
                        > DualMachinePairingIdentityCodec.MAX_SIGNATURE_DER_BYTES) {
            throw new IllegalArgumentException(label + " has invalid length");
        }
        return value.clone();
    }

    private static byte[] requireLength(byte[] value, int length, String label) {
        if (value == null || value.length != length) {
            throw new IllegalArgumentException(label + " has invalid length");
        }
        return value.clone();
    }

    private synchronized void requireOpen() throws GeneralSecurityException {
        if (closed || pendingConfirmation == null) throw rejected();
    }

    private static void closeFresh(FreshP256KeyAgreement fresh) {
        if (fresh != null) fresh.close();
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    private static GeneralSecurityException rejected() {
        return new GeneralSecurityException(REJECTED_MESSAGE);
    }

    private static final class StoreBackedTranscriptIdentity
            implements TranscriptIdentity {
        private final AndroidPairingIdentityStore store;

        private StoreBackedTranscriptIdentity(AndroidPairingIdentityStore store) {
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
    }
}
