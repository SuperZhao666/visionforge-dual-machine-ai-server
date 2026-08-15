package com.visionforge.inferencebenchmark.handshake;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.KeyAgreement;
import javax.security.auth.DestroyFailedException;

/** One-shot owner of a fresh P-256 ephemeral private key. */
public final class FreshP256KeyAgreement implements AutoCloseable {
    private PrivateKey privateKey;
    private final byte[] publicKeySec1;
    private boolean consumed;
    private boolean closed;

    private FreshP256KeyAgreement(PrivateKey privateKey, byte[] publicKeySec1) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        AuthenticatedPeerHandshakeV1Internals.requireP256Point(publicKeySec1);
        this.publicKeySec1 = publicKeySec1.clone();
    }

    static FreshP256KeyAgreement generate() throws AuthenticatedPeerHandshakeV1Exception {
        KeyPair generatedPair = null;
        byte[] encoded = null;
        boolean transferred = false;
        try {
            KeyPairGenerator generator =
                    KeyPairGenerator.getInstance(
                            AuthenticatedPeerHandshakeV1Internals.EC_ALGORITHM);
            generator.initialize(
                    new ECGenParameterSpec(AuthenticatedPeerHandshakeV1Internals.CURVE_NAME));
            generatedPair = generator.generateKeyPair();
            encoded =
                    AuthenticatedPeerHandshakeV1Internals.encodeP256PublicKey(
                            generatedPair.getPublic());
            FreshP256KeyAgreement result =
                    new FreshP256KeyAgreement(generatedPair.getPrivate(), encoded);
            transferred = true;
            return result;
        } catch (GeneralSecurityException | RuntimeException failure) {
            throw AuthenticatedPeerHandshakeV1Internals.cryptoFailure();
        } finally {
            AuthenticatedPeerHandshakeV1Internals.clear(encoded);
            if (!transferred && generatedPair != null) {
                destroyPrivateKey(generatedPair.getPrivate());
            }
        }
    }

    public synchronized byte[] publicKeySec1() throws AuthenticatedPeerHandshakeV1Exception {
        requireOpen();
        return publicKeySec1.clone();
    }

    /**
     * Runs one fresh ECDH after the caller has verified both long-term identity signatures.
     *
     * <p>The local public key must exactly match the role-specific transcript field. The private
     * key is irreversibly consumed before provider invocation and is destroyed best-effort even
     * when derivation fails, so retry requires a new ephemeral key and transcript.
     */
    public synchronized PendingPeerHandshakeConfirmation deriveAfterPeerIdentityVerified(
            HandshakeTranscriptV1 transcript, AuthenticatedPeerHandshakeV1.Role localRole)
            throws AuthenticatedPeerHandshakeV1Exception {
        if (transcript == null) throw new IllegalArgumentException("transcript is required");
        if (localRole == null) throw new IllegalArgumentException("local role is required");
        requireOpen();
        if (consumed || privateKey == null) {
            throw AuthenticatedPeerHandshakeV1Internals.closedFailure();
        }
        if (transcript.pairId().isEmpty()) {
            close();
            throw AuthenticatedPeerHandshakeV1Internals.unauthenticatedFailure();
        }

        byte[] declaredLocal =
                localRole == AuthenticatedPeerHandshakeV1.Role.HOST
                        ? transcript.hostEphemeralPublicKey()
                        : transcript.androidEphemeralPublicKey();
        byte[] peerSec1 =
                localRole == AuthenticatedPeerHandshakeV1.Role.HOST
                        ? transcript.androidEphemeralPublicKey()
                        : transcript.hostEphemeralPublicKey();
        if (!MessageDigest.isEqual(publicKeySec1, declaredLocal)) {
            AuthenticatedPeerHandshakeV1Internals.clear(declaredLocal);
            AuthenticatedPeerHandshakeV1Internals.clear(peerSec1);
            close();
            throw AuthenticatedPeerHandshakeV1Internals.unauthenticatedFailure();
        }

        PrivateKey consumedPrivateKey = privateKey;
        privateKey = null;
        consumed = true;
        byte[] providerSecret = null;
        byte[] normalizedSecret = null;
        byte[] transcriptHash = null;
        try {
            ECPublicKey peerPublicKey =
                    AuthenticatedPeerHandshakeV1Internals.publicKeyFromSec1(peerSec1);
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(consumedPrivateKey);
            agreement.doPhase(peerPublicKey, true);
            providerSecret = agreement.generateSecret();
            normalizedSecret =
                    AuthenticatedPeerHandshakeV1Internals.normalizeP256SharedSecret(
                            providerSecret);
            transcriptHash = transcript.transcriptHashSha256();
            return PendingPeerHandshakeConfirmation.derive(
                    normalizedSecret, transcriptHash, localRole);
        } catch (AuthenticatedPeerHandshakeV1Exception failure) {
            close();
            throw failure;
        } catch (IllegalArgumentException invalidPeer) {
            close();
            throw AuthenticatedPeerHandshakeV1Internals.unauthenticatedFailure();
        } catch (GeneralSecurityException | RuntimeException failure) {
            close();
            throw AuthenticatedPeerHandshakeV1Internals.cryptoFailure();
        } finally {
            AuthenticatedPeerHandshakeV1Internals.clear(declaredLocal);
            AuthenticatedPeerHandshakeV1Internals.clear(peerSec1);
            AuthenticatedPeerHandshakeV1Internals.clear(providerSecret);
            AuthenticatedPeerHandshakeV1Internals.clear(normalizedSecret);
            AuthenticatedPeerHandshakeV1Internals.clear(transcriptHash);
            destroyPrivateKey(consumedPrivateKey);
        }
    }

    @Override
    public synchronized void close() {
        if (closed) return;
        closed = true;
        consumed = true;
        PrivateKey key = privateKey;
        privateKey = null;
        destroyPrivateKey(key);
        Arrays.fill(publicKeySec1, (byte) 0);
    }

    private void requireOpen() throws AuthenticatedPeerHandshakeV1Exception {
        if (closed) throw AuthenticatedPeerHandshakeV1Internals.closedFailure();
    }

    private static void destroyPrivateKey(PrivateKey key) {
        if (key == null) return;
        try {
            key.destroy();
        } catch (DestroyFailedException | RuntimeException ignored) {
            // JCA provider objects are not guaranteed to be destroyable. Dropping the final
            // reference is the only portable fallback; all owned byte arrays are still cleared.
        }
    }
}
