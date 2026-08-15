package com.visionforge.inferencebenchmark.dataplane;

import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Internals.HEADER_BYTES;

import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.spec.SecretKeySpec;

/**
 * Stateful single-owner packet sealer with a monotonic wire counter and a 2^23-packet key limit.
 */
public final class AuthenticatedDataPlaneV2Sender implements AutoCloseable {
    private final AuthenticatedDataPlaneV2Internals.KeyMaterial keyMaterial;
    private final byte[] noncePrefix;
    private final AuthenticatedDataPlaneV2.Domain domain;
    private final int maxPayloadBytes;
    private final AuthenticatedDataPlaneV2Internals.EncryptionAttemptHook
            encryptionAttemptHook;
    private long nextCounter;
    private boolean counterExhausted;

    AuthenticatedDataPlaneV2Sender(
            byte[] key,
            byte[] noncePrefix,
            AuthenticatedDataPlaneV2.Domain domain,
            int maxPayloadBytes,
            long initialCounter) {
        this(
                key,
                noncePrefix,
                domain,
                maxPayloadBytes,
                initialCounter,
                AuthenticatedDataPlaneV2Internals.NO_ENCRYPTION_FAILURE);
    }

    AuthenticatedDataPlaneV2Sender(
            byte[] key,
            byte[] noncePrefix,
            AuthenticatedDataPlaneV2.Domain domain,
            int maxPayloadBytes,
            long initialCounter,
            AuthenticatedDataPlaneV2Internals.EncryptionAttemptHook
                    encryptionAttemptHook) {
        AuthenticatedDataPlaneV2.requirePayloadLimit(maxPayloadBytes);
        AuthenticatedDataPlaneV2.requireInitialCounter(initialCounter);
        this.domain = Objects.requireNonNull(domain, "domain");
        this.encryptionAttemptHook = Objects.requireNonNull(
                encryptionAttemptHook, "encryptionAttemptHook");
        this.noncePrefix = AuthenticatedDataPlaneV2Internals.copyNoncePrefix(noncePrefix);
        try {
            this.keyMaterial = new AuthenticatedDataPlaneV2Internals.KeyMaterial(key);
        } catch (RuntimeException invalidKey) {
            AuthenticatedDataPlaneV2Internals.clear(this.noncePrefix);
            throw invalidKey;
        }
        this.maxPayloadBytes = maxPayloadBytes;
        this.nextCounter = initialCounter;
    }

    /**
     * Seals one payload. The counter is irreversibly burned before invoking the AEAD operation, so
     * a provider failure cannot cause nonce reuse on a retry.
     */
    public synchronized byte[] seal(byte[] plaintext)
            throws AuthenticatedDataPlaneV2Exception {
        if (plaintext == null) throw new IllegalArgumentException("plaintext is null");
        keyMaterial.requireOpen();
        requireCounterAvailable();
        requirePayloadLength(plaintext.length);

        long counter = nextCounter;
        byte[] plaintextCopy = plaintext.clone();
        byte[] nonce = AuthenticatedDataPlaneV2Internals.composeNonce(noncePrefix, counter);
        byte[] header =
                AuthenticatedDataPlaneV2Internals.buildHeader(
                        domain, counter, plaintextCopy.length);
        byte[] ciphertextAndTag = null;
        try {
            burnCounter(counter);
            ciphertextAndTag = encrypt(plaintextCopy, nonce, header);
            byte[] envelope = new byte[HEADER_BYTES + ciphertextAndTag.length];
            System.arraycopy(header, 0, envelope, 0, HEADER_BYTES);
            System.arraycopy(
                    ciphertextAndTag,
                    0,
                    envelope,
                    HEADER_BYTES,
                    ciphertextAndTag.length);
            return envelope;
        } finally {
            AuthenticatedDataPlaneV2Internals.clear(plaintextCopy);
            AuthenticatedDataPlaneV2Internals.clear(nonce);
            AuthenticatedDataPlaneV2Internals.clear(header);
            AuthenticatedDataPlaneV2Internals.clear(ciphertextAndTag);
        }
    }

    @Override
    public synchronized void close() {
        keyMaterial.close();
        AuthenticatedDataPlaneV2Internals.clear(noncePrefix);
    }

    private byte[] encrypt(byte[] plaintext, byte[] nonce, byte[] header)
            throws AuthenticatedDataPlaneV2Exception {
        SecretKeySpec keySpec = keyMaterial.newKeySpec();
        try {
            encryptionAttemptHook.beforeEncryption();
            byte[] ciphertextAndTag =
                    AuthenticatedDataPlaneV2Internals.encryptWithJca(
                            keySpec, nonce, header, plaintext);
            if (ciphertextAndTag == null
                    || ciphertextAndTag.length
                            != plaintext.length + AuthenticatedDataPlaneV2.GCM_TAG_BYTES) {
                AuthenticatedDataPlaneV2Internals.clear(ciphertextAndTag);
                throw new GeneralSecurityException(
                        "AES-GCM provider returned a non-canonical output length");
            }
            return ciphertextAndTag;
        } catch (GeneralSecurityException failure) {
            throw AuthenticatedDataPlaneV2Internals.failure(
                    AuthenticatedDataPlaneV2Exception.Reason.CRYPTO_UNAVAILABLE,
                    "AES-256-GCM encryption failed closed",
                    failure);
        } catch (RuntimeException providerFailure) {
            throw AuthenticatedDataPlaneV2Internals.failure(
                    AuthenticatedDataPlaneV2Exception.Reason.CRYPTO_UNAVAILABLE,
                    "AES-256-GCM provider failed closed",
                    providerFailure);
        }
    }

    private void requirePayloadLength(int payloadLength)
            throws AuthenticatedDataPlaneV2Exception {
        if (payloadLength > maxPayloadBytes) {
            throw AuthenticatedDataPlaneV2Internals.failure(
                    AuthenticatedDataPlaneV2Exception.Reason.PAYLOAD_TOO_LARGE,
                    "plaintext exceeds the configured payload limit");
        }
    }

    private void requireCounterAvailable() throws AuthenticatedDataPlaneV2Exception {
        if (counterExhausted) {
            throw AuthenticatedDataPlaneV2Internals.failure(
                    AuthenticatedDataPlaneV2Exception.Reason.COUNTER_EXHAUSTED,
                    "traffic-key packet limit is exhausted; rekey is required");
        }
    }

    private void burnCounter(long counter) {
        if (counter == AuthenticatedDataPlaneV2.MAX_COUNTER_PER_TRAFFIC_KEY) {
            counterExhausted = true;
        } else {
            nextCounter = counter + 1L;
        }
    }
}
