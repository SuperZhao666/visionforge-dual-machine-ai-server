package com.visionforge.inferencebenchmark;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import com.visionforge.inferencebenchmark.handshake.HandshakeTranscriptV1;

/**
 * AndroidKeyStore-backed P-256 ECDSA pairing identity for the dual-machine
 * secure-v2 protocol. The private key is generated inside AndroidKeyStore and
 * is non-exportable by construction; only DER SPKI bytes, fingerprints and
 * signatures ever leave this class. Wire encoding and validation are delegated
 * to {@link DualMachinePairingIdentityCodec} so host and device share one contract.
 */
public final class AndroidPairingIdentityStore {
    public static final String DEFAULT_ALIAS = "visionforge-dual-machine-pairing-identity";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final int MAX_ALIAS_LENGTH = 64;
    private static final Object KEY_STORE_LOCK = new Object();

    private final String alias;
    private final boolean requireHardwareBacked;

    public AndroidPairingIdentityStore() {
        this(DEFAULT_ALIAS, BuildConfig.APP_SIGNING_INTEGRITY_REQUIRED);
    }

    public AndroidPairingIdentityStore(String alias) {
        this(alias, BuildConfig.APP_SIGNING_INTEGRITY_REQUIRED);
    }

    AndroidPairingIdentityStore(String alias, boolean requireHardwareBacked) {
        if (!isValidAlias(alias)) {
            throw new IllegalArgumentException("alias is invalid");
        }
        this.alias = alias;
        this.requireHardwareBacked = requireHardwareBacked;
    }

    public String alias() {
        return alias;
    }

    public boolean hasIdentity() throws GeneralSecurityException {
        synchronized (KEY_STORE_LOCK) {
            KeyStore keyStore = loadKeyStore();
            if (!keyStore.containsAlias(alias)) {
                return false;
            }
            requireStoredPublicKey(keyStore);
            requireStoredPrivateKey(keyStore);
            return true;
        }
    }

    /** Returns the stored identity public key, generating it on first use. */
    public ECPublicKey getOrCreateIdentity() throws GeneralSecurityException {
        synchronized (KEY_STORE_LOCK) {
            KeyStore keyStore = loadKeyStore();
            if (keyStore.containsAlias(alias)) {
                ECPublicKey publicKey = requireStoredPublicKey(keyStore);
                requireStoredPrivateKey(keyStore);
                return publicKey;
            }
            KeyPairGenerator generator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
            // Non-exportable is inherent to AndroidKeyStore: only signing
            // operations are permitted and raw private material never leaves it.
            generator.initialize(new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(
                            new ECGenParameterSpec(DualMachinePairingIdentityCodec.CURVE_NAME))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUnlockedDeviceRequired(true)
                    .build());
            generator.generateKeyPair();
            keyStore = loadKeyStore();
            ECPublicKey publicKey = requireStoredPublicKey(keyStore);
            requireStoredPrivateKey(keyStore);
            return publicKey;
        }
    }

    /** Canonical DER SPKI bytes of the identity public key. */
    public byte[] publicKeySpkiDer() throws GeneralSecurityException {
        byte[] derSpki = getOrCreateIdentity().getEncoded();
        DualMachinePairingIdentityCodec.requirePublicKey(derSpki);
        return derSpki;
    }

    /** Canonical wire form: DER SPKI in standard Base64. */
    public String publicKeyBase64() throws GeneralSecurityException {
        return DualMachinePairingIdentityCodec.encodePublicKeyBase64(publicKeySpkiDer());
    }

    /** Lowercase SHA-256 hex fingerprint of the canonical DER SPKI. */
    public String fingerprintHex() throws GeneralSecurityException {
        return DualMachinePairingIdentityCodec.fingerprintHex(publicKeySpkiDer());
    }

    /**
     * Signs the canonical encoding of one already-built typed handshake transcript.
     *
     * <p>This is the only signing entry point used by the bound peer-handshake
     * session. Keeping the typed object in the contract prevents the future
     * network layer from turning the Android identity into a generic
     * {@code sign(bytes)} oracle.</p>
     */
    byte[] signHandshakeTranscript(
            HandshakeTranscriptV1 transcript,
            DualMachineEntitlementRecord expectedPair)
            throws GeneralSecurityException {
        synchronized (KEY_STORE_LOCK) {
            if (transcript == null || expectedPair == null) {
                throw new IllegalArgumentException(
                        "transcript and expected pair are required");
            }
            if (expectedPair.revoked
                    || expectedPair.pairId.isEmpty()
                    || transcript.pairId().isEmpty()
                    || !expectedPair.pairId.equals(transcript.pairId())
                    || !alias.equals(expectedPair.androidIdentityAlias)) {
                throw new GeneralSecurityException(
                        "handshake transcript is not bound to this identity");
            }

            byte[] publicKeySpki = null;
            byte[] actualIdentityHash = null;
            byte[] expectedIdentityHash = null;
            byte[] transcriptAndroidHash = null;
            byte[] transcriptHostHash = null;
            byte[] canonicalTranscript = null;
            byte[] signature = null;
            boolean transferred = false;
            try {
                publicKeySpki = publicKeySpkiDer();
                actualIdentityHash = MessageDigest.getInstance("SHA-256")
                        .digest(publicKeySpki);
                expectedIdentityHash = decodeLowercaseHexSha256(
                        expectedPair.androidKeySha256);
                transcriptAndroidHash =
                        transcript.androidIdentitySpkiSha256();
                transcriptHostHash = transcript.hostIdentitySpkiSha256();
                if (!MessageDigest.isEqual(
                                actualIdentityHash, expectedIdentityHash)
                        || !MessageDigest.isEqual(
                                actualIdentityHash, transcriptAndroidHash)
                        || MessageDigest.isEqual(
                                transcriptHostHash, transcriptAndroidHash)) {
                    throw new GeneralSecurityException(
                            "handshake identity role binding is invalid");
                }

                canonicalTranscript = transcript.canonicalEncoding();
                signature = sign(canonicalTranscript);
                if (!DualMachinePairingIdentityCodec.verify(
                        publicKeySpki, canonicalTranscript, signature)) {
                    throw new GeneralSecurityException(
                            "handshake transcript signature self-check failed");
                }
                transferred = true;
                return signature;
            } finally {
                if (!transferred && signature != null) {
                    Arrays.fill(signature, (byte) 0);
                }
                clear(publicKeySpki);
                clear(actualIdentityHash);
                clear(expectedIdentityHash);
                clear(transcriptAndroidHash);
                clear(transcriptHostHash);
                clear(canonicalTranscript);
            }
        }
    }

    /**
     * Package-private compatibility primitive for existing local pairing and
     * authorization proof code. New peer-network code must use the typed
     * transcript method above and must never receive this raw signer.
     */
    byte[] sign(byte[] payload) throws GeneralSecurityException {
        synchronized (KEY_STORE_LOCK) {
            KeyStore keyStore = loadKeyStore();
            if (!keyStore.containsAlias(alias)) {
                throw new GeneralSecurityException("pairing identity does not exist");
            }
            PrivateKey privateKey = requireStoredPrivateKey(keyStore);
            return DualMachinePairingIdentityCodec.sign(privateKey, payload);
        }
    }

    /**
     * Deletes only this device's local identity from AndroidKeyStore.
     * The caller must separately complete server-side pairing revocation.
     */
    public void deleteIdentity() throws GeneralSecurityException {
        synchronized (KEY_STORE_LOCK) {
            KeyStore keyStore = loadKeyStore();
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
            }
        }
    }

    /** Alias retained for callers that also perform the required server revoke. */
    public void revokeIdentity() throws GeneralSecurityException {
        deleteIdentity();
    }

    private ECPublicKey requireStoredPublicKey(KeyStore keyStore) throws GeneralSecurityException {
        KeyStore.Entry entry = keyStore.getEntry(alias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new GeneralSecurityException("alias does not hold a private key entry");
        }
        Certificate certificate = ((KeyStore.PrivateKeyEntry) entry).getCertificate();
        if (certificate == null) {
            throw new GeneralSecurityException("pairing identity certificate is unavailable");
        }
        return DualMachinePairingIdentityCodec.requirePublicKey(
                certificate.getPublicKey().getEncoded());
    }

    private PrivateKey requireStoredPrivateKey(KeyStore keyStore)
            throws GeneralSecurityException {
        Key storedKey = keyStore.getKey(alias, null);
        if (!(storedKey instanceof PrivateKey)) {
            throw new GeneralSecurityException(
                    "pairing identity private key is unavailable");
        }
        PrivateKey privateKey = (PrivateKey) storedKey;
        if (privateKey.getEncoded() != null || privateKey.getFormat() != null) {
            throw new GeneralSecurityException(
                    "pairing identity private key is exportable");
        }
        KeyFactory keyFactory = KeyFactory.getInstance(
                privateKey.getAlgorithm(), ANDROID_KEYSTORE);
        KeyInfo keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo.class);
        if (keyInfo.getPurposes() != KeyProperties.PURPOSE_SIGN
                || !Arrays.asList(keyInfo.getDigests()).contains(
                        KeyProperties.DIGEST_SHA256)
                || keyInfo.getOrigin() != KeyProperties.ORIGIN_GENERATED) {
            throw new GeneralSecurityException(
                    "pairing identity key policy is invalid");
        }
        if (requireHardwareBacked && !keyInfo.isInsideSecureHardware()) {
            throw new GeneralSecurityException(
                    "production pairing identity is not hardware-backed");
        }
        return privateKey;
    }

    private static boolean isValidAlias(String value) {
        if (value == null || value.isEmpty() || value.length() > MAX_ALIAS_LENGTH) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            boolean valid = (character >= 'a' && character <= 'z')
                    || (character >= 'A' && character <= 'Z')
                    || (character >= '0' && character <= '9')
                    || character == '.'
                    || character == '_'
                    || character == '-';
            if (!valid) {
                return false;
            }
        }
        return true;
    }

    private static byte[] decodeLowercaseHexSha256(String value)
            throws GeneralSecurityException {
        if (value == null || value.length() != 64) {
            throw new GeneralSecurityException(
                    "identity fingerprint is invalid");
        }
        byte[] decoded = new byte[32];
        for (int index = 0; index < decoded.length; index++) {
            int high = Character.digit(value.charAt(index * 2), 16);
            int low = Character.digit(value.charAt(index * 2 + 1), 16);
            if (high < 0 || low < 0
                    || Character.toLowerCase(value.charAt(index * 2))
                            != value.charAt(index * 2)
                    || Character.toLowerCase(value.charAt(index * 2 + 1))
                            != value.charAt(index * 2 + 1)) {
                Arrays.fill(decoded, (byte) 0);
                throw new GeneralSecurityException(
                        "identity fingerprint is invalid");
            }
            decoded[index] = (byte) ((high << 4) | low);
        }
        return decoded;
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    private static KeyStore loadKeyStore() throws GeneralSecurityException {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            return keyStore;
        } catch (java.io.IOException ioException) {
            throw new GeneralSecurityException("AndroidKeyStore load failed", ioException);
        }
    }
}
