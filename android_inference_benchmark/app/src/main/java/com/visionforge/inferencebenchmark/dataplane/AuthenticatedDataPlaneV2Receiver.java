package com.visionforge.inferencebenchmark.dataplane;

import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2.GCM_TAG_BYTES;
import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Internals.GCM_TAG_BITS;
import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Internals.HEADER_BYTES;
import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Internals.TRANSFORMATION;

import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Authenticated packet opener with a bounded unsigned-counter replay window. */
public final class AuthenticatedDataPlaneV2Receiver implements AutoCloseable {
    private final AuthenticatedDataPlaneV2Internals.KeyMaterial keyMaterial;
    private final byte[] noncePrefix;
    private final AuthenticatedDataPlaneV2.Domain expectedDomain;
    private final int maxPayloadBytes;
    private final UnsignedReplayWindow replayWindow;

    AuthenticatedDataPlaneV2Receiver(
            byte[] key,
            byte[] noncePrefix,
            AuthenticatedDataPlaneV2.Domain expectedDomain,
            int maxPayloadBytes,
            int replayWindowSize) {
        AuthenticatedDataPlaneV2.requirePayloadLimit(maxPayloadBytes);
        if (replayWindowSize < 1
                || replayWindowSize > AuthenticatedDataPlaneV2.MAX_REPLAY_WINDOW_SIZE) {
            throw new IllegalArgumentException("replayWindowSize is outside the supported range");
        }
        this.expectedDomain = Objects.requireNonNull(expectedDomain, "expectedDomain");
        this.noncePrefix = AuthenticatedDataPlaneV2Internals.copyNoncePrefix(noncePrefix);
        try {
            this.keyMaterial = new AuthenticatedDataPlaneV2Internals.KeyMaterial(key);
        } catch (RuntimeException invalidKey) {
            AuthenticatedDataPlaneV2Internals.clear(this.noncePrefix);
            throw invalidKey;
        }
        this.maxPayloadBytes = maxPayloadBytes;
        this.replayWindow = new UnsignedReplayWindow(replayWindowSize);
    }

    /**
     * Opens one canonical envelope. No plaintext is returned, and the replay window is not
     * advanced, unless the GCM tag verifies successfully.
     */
    public synchronized byte[] open(byte[] envelope)
            throws AuthenticatedDataPlaneV2Exception {
        try {
            return openUntrustedEnvelope(envelope);
        } catch (AuthenticatedDataPlaneV2Exception failure) {
            if (failure.reason() == AuthenticatedDataPlaneV2Exception.Reason.CLOSED
                    || failure.reason()
                            == AuthenticatedDataPlaneV2Exception.Reason.CRYPTO_UNAVAILABLE) {
                throw failure;
            }
            // No packet-controlled pre-authentication detail crosses the
            // public boundary. Network adapters must silently drop this one
            // generic result and must never drive rekey/session side effects.
            throw AuthenticatedDataPlaneV2Internals.failure(
                    AuthenticatedDataPlaneV2Exception.Reason.UNAUTHENTICATED_PACKET,
                    "authenticated data-plane packet was rejected");
        }
    }

    private byte[] openUntrustedEnvelope(byte[] envelope)
            throws AuthenticatedDataPlaneV2Exception {
        keyMaterial.requireOpen();
        AuthenticatedDataPlaneV2Internals.requireContainerLength(
                envelope, maxPayloadBytes);
        byte[] envelopeCopy = envelope.clone();
        byte[] nonce = null;
        try {
            AuthenticatedDataPlaneV2Internals.ParsedEnvelope parsed =
                    AuthenticatedDataPlaneV2Internals.parse(
                            envelopeCopy, expectedDomain, maxPayloadBytes);
            requireCounterWithinTrafficKeyLifetime(parsed.counter);
            requireReplayAcceptable(parsed.counter);
            nonce =
                    AuthenticatedDataPlaneV2Internals.composeNonce(
                            noncePrefix, parsed.counter);
            byte[] plaintext = decrypt(envelopeCopy, nonce, parsed.payloadLength);
            if (!replayWindow.commitAuthenticated(parsed.counter)) {
                AuthenticatedDataPlaneV2Internals.clear(plaintext);
                throw AuthenticatedDataPlaneV2Internals.failure(
                        AuthenticatedDataPlaneV2Exception.Reason.CRYPTO_UNAVAILABLE,
                        "authenticated counter could not be committed");
            }
            return plaintext;
        } finally {
            AuthenticatedDataPlaneV2Internals.clear(nonce);
            AuthenticatedDataPlaneV2Internals.clear(envelopeCopy);
        }
    }

    @Override
    public synchronized void close() {
        keyMaterial.close();
        AuthenticatedDataPlaneV2Internals.clear(noncePrefix);
    }

    private byte[] decrypt(byte[] envelope, byte[] nonce, int payloadLength)
            throws AuthenticatedDataPlaneV2Exception {
        SecretKeySpec keySpec = keyMaterial.newKeySpec();
        byte[] plaintext;
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    keySpec,
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(envelope, 0, HEADER_BYTES);
            plaintext =
                    cipher.doFinal(
                            envelope,
                            HEADER_BYTES,
                            payloadLength + GCM_TAG_BYTES);
        } catch (BadPaddingException authenticationFailure) {
            throw AuthenticatedDataPlaneV2Internals.failure(
                    AuthenticatedDataPlaneV2Exception.Reason.AUTHENTICATION_FAILED,
                    "AES-GCM authentication failed",
                    authenticationFailure);
        } catch (GeneralSecurityException cryptoFailure) {
            throw AuthenticatedDataPlaneV2Internals.failure(
                    AuthenticatedDataPlaneV2Exception.Reason.CRYPTO_UNAVAILABLE,
                    "AES-256-GCM decryption failed closed",
                    cryptoFailure);
        } catch (RuntimeException providerFailure) {
            throw AuthenticatedDataPlaneV2Internals.failure(
                    AuthenticatedDataPlaneV2Exception.Reason.CRYPTO_UNAVAILABLE,
                    "AES-256-GCM provider failed closed",
                    providerFailure);
        }
        if (plaintext.length != payloadLength) {
            AuthenticatedDataPlaneV2Internals.clear(plaintext);
            throw AuthenticatedDataPlaneV2Internals.failure(
                    AuthenticatedDataPlaneV2Exception.Reason.CRYPTO_UNAVAILABLE,
                    "AES-GCM provider returned a non-canonical plaintext length");
        }
        return plaintext;
    }

    private void requireReplayAcceptable(long counter)
            throws AuthenticatedDataPlaneV2Exception {
        UnsignedReplayWindow.Decision decision = replayWindow.inspect(counter);
        if (decision == UnsignedReplayWindow.Decision.DUPLICATE) {
            throw AuthenticatedDataPlaneV2Internals.failure(
                    AuthenticatedDataPlaneV2Exception.Reason.REPLAY_DUPLICATE,
                    "envelope counter was already authenticated");
        }
        if (decision == UnsignedReplayWindow.Decision.TOO_OLD) {
            throw AuthenticatedDataPlaneV2Internals.failure(
                    AuthenticatedDataPlaneV2Exception.Reason.REPLAY_TOO_OLD,
                    "envelope counter is outside the replay window");
        }
    }

    private void requireCounterWithinTrafficKeyLifetime(long counter)
            throws AuthenticatedDataPlaneV2Exception {
        if (Long.compareUnsigned(
                        counter, AuthenticatedDataPlaneV2.MAX_COUNTER_PER_TRAFFIC_KEY)
                > 0) {
            throw AuthenticatedDataPlaneV2Internals.failure(
                    AuthenticatedDataPlaneV2Exception.Reason.COUNTER_LIMIT_EXCEEDED,
                    "envelope counter exceeds the traffic-key lifetime");
        }
    }
}
