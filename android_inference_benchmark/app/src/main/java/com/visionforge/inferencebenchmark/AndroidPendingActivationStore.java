package com.visionforge.inferencebenchmark;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * AndroidKeyStore-sealed recovery store for one pending card confirmation.
 *
 * <p>Private keys are never exported or persisted by this store. A card that
 * the user has explicitly submitted may be retained only in a separate,
 * domain-separated AndroidKeyStore AES-256-GCM envelope until Host pairing
 * makes activation possible. The short-lived challenge token and
 * already-created signatures use their own sealed envelope so the exact
 * idempotent confirmation can survive a lost response or process restart
 * without creating a second challenge.</p>
 */
public final class AndroidPendingActivationStore
        implements DualMachineCardAuthorizationCoordinator
        .PendingActivationStore {
    static final String STORE =
            "visionforge_dual_machine_pending_activation_v1";
    static final String VALUE_KEY = "sealed_pending_activation";
    static final String QUEUED_CARD_VALUE_KEY = "sealed_queued_card";
    static final String DEFAULT_KEY_ALIAS =
            "visionforge-dual-machine-pending-activation-v1";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int MAGIC = 0x56465041; // "VFPA"
    private static final int QUEUED_CARD_MAGIC = 0x56465143; // "VFQC"
    private static final int SCHEMA_VERSION = 4;
    private static final int QUEUED_CARD_SCHEMA_VERSION = 1;
    private static final int LEGACY_SCHEMA_VERSION = 3;
    private static final int IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int MAX_SEALED_BYTES = 4096;
    private static final int MAX_PLAINTEXT_BYTES = 2048;
    private static final byte[] AAD =
            "visionforge-dual-machine-pending-activation-v1"
                    .getBytes(StandardCharsets.US_ASCII);
    static final byte[] QUEUED_CARD_AAD =
            "visionforge-dual-machine-queued-card-v1"
                    .getBytes(StandardCharsets.US_ASCII);
    private static final Object KEY_LOCK = new Object();

    private final SharedPreferences preferences;
    private final String keyAlias;

    public AndroidPendingActivationStore(Context context) {
        this(context, DEFAULT_KEY_ALIAS);
    }

    AndroidPendingActivationStore(Context context, String keyAlias) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        if (!validAlias(keyAlias)) {
            throw new IllegalArgumentException("key alias is invalid");
        }
        preferences = context.getApplicationContext()
                .getSharedPreferences(STORE, Context.MODE_PRIVATE);
        this.keyAlias = keyAlias;
    }

    @Override
    public synchronized DualMachineCardAuthorizationCoordinator
            .PendingActivation load()
            throws IOException, GeneralSecurityException {
        final String encoded;
        try {
            encoded = preferences.getString(VALUE_KEY, null);
        } catch (ClassCastException corruptType) {
            throw new GeneralSecurityException(
                    "pending activation storage type is corrupt",
                    corruptType);
        }
        if (encoded == null) return null;
        byte[] sealed = decodeCanonicalBase64(encoded);
        if (sealed.length <= 1 + IV_BYTES + 16
                || sealed.length > MAX_SEALED_BYTES) {
            throw new GeneralSecurityException(
                    "pending activation envelope is invalid");
        }
        if (sealed[0] == (byte) LEGACY_SCHEMA_VERSION) {
            // V3 did not bind activate/bind_device or its target. It cannot
            // be replayed safely; clearing lets the same card create a fresh,
            // proof-bound challenge (including a server-directed rebind).
            clear();
            return null;
        }
        if (sealed[0] != (byte) SCHEMA_VERSION) {
            throw new GeneralSecurityException(
                    "pending activation envelope schema is invalid");
        }
        byte[] iv = Arrays.copyOfRange(sealed, 1, 1 + IV_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(
                sealed, 1 + IV_BYTES, sealed.length);
        byte[] plaintext = decrypt(
                requireExistingKey(), iv, ciphertext, AAD);
        try {
            return parse(plaintext);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    @Override
    public synchronized void save(
            DualMachineCardAuthorizationCoordinator
                    .PendingActivation pending)
            throws IOException, GeneralSecurityException {
        if (pending == null) {
            throw new IllegalArgumentException(
                    "pending activation is required");
        }
        byte[] plaintext = serialize(pending);
        byte[] sealed;
        try {
            sealed = encrypt(
                    getOrCreateKey(), plaintext, AAD,
                    (byte) SCHEMA_VERSION);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
        String encoded = Base64.getEncoder().encodeToString(sealed);
        if (!preferences.edit().putString(VALUE_KEY, encoded).commit()) {
            throw new IOException(
                    "pending activation persistence failed");
        }
    }

    @Override
    public synchronized void clear() throws IOException {
        if (!preferences.edit().remove(VALUE_KEY).commit()) {
            throw new IOException("pending activation clear failed");
        }
    }

    /**
     * Returns the one card awaiting Host pairing, or {@code null}.  The card is
     * never logged and exists at rest only in an AndroidKeyStore-sealed GCM
     * envelope with a domain-separated AAD value.
     */
    public synchronized String loadQueuedCard()
            throws IOException, GeneralSecurityException {
        final String encoded;
        try {
            encoded = preferences.getString(QUEUED_CARD_VALUE_KEY, null);
        } catch (ClassCastException corruptType) {
            throw new GeneralSecurityException(
                    "queued card storage type is corrupt", corruptType);
        }
        if (encoded == null) return null;
        byte[] sealed = decodeCanonicalBase64(encoded);
        if (sealed.length <= 1 + IV_BYTES + 16
                || sealed.length > MAX_SEALED_BYTES
                || sealed[0] != (byte) QUEUED_CARD_SCHEMA_VERSION) {
            throw new GeneralSecurityException(
                    "queued card envelope is invalid");
        }
        byte[] iv = Arrays.copyOfRange(sealed, 1, 1 + IV_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(
                sealed, 1 + IV_BYTES, sealed.length);
        byte[] plaintext = decrypt(
                requireExistingKey(), iv, ciphertext, QUEUED_CARD_AAD);
        try (DataInputStream input = new DataInputStream(
                new ByteArrayInputStream(plaintext))) {
            if (input.readInt() != QUEUED_CARD_MAGIC
                    || input.readUnsignedShort()
                    != QUEUED_CARD_SCHEMA_VERSION) {
                throw new GeneralSecurityException(
                        "queued card payload schema is invalid");
            }
            String cardCode = readAscii(input, 64);
            if (input.read() != -1) {
                throw new GeneralSecurityException(
                        "queued card payload has trailing data");
            }
            final String canonical;
            try {
                canonical = DualMachineCardCode.normalizeAndValidate(cardCode);
            } catch (IllegalArgumentException malformed) {
                throw new GeneralSecurityException(
                        "queued card payload is invalid", malformed);
            }
            if (!canonical.equals(cardCode)) {
                throw new GeneralSecurityException(
                        "queued card payload is not canonical");
            }
            return canonical;
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    public synchronized void saveQueuedCard(String cardCode)
            throws IOException, GeneralSecurityException {
        final String canonical;
        try {
            canonical = DualMachineCardCode.normalizeAndValidate(cardCode);
        } catch (IllegalArgumentException malformed) {
            throw new GeneralSecurityException(
                    "queued card is invalid", malformed);
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(96);
        try (DataOutputStream output = new DataOutputStream(buffer)) {
            output.writeInt(QUEUED_CARD_MAGIC);
            output.writeShort(QUEUED_CARD_SCHEMA_VERSION);
            writeAscii(output, canonical, 64);
        }
        byte[] plaintext = buffer.toByteArray();
        byte[] sealed;
        try {
            sealed = encrypt(
                    getOrCreateKey(), plaintext, QUEUED_CARD_AAD,
                    (byte) QUEUED_CARD_SCHEMA_VERSION);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
        String encoded = Base64.getEncoder().encodeToString(sealed);
        if (!preferences.edit().putString(
                QUEUED_CARD_VALUE_KEY, encoded).commit()) {
            throw new IOException("queued card persistence failed");
        }
    }

    public synchronized void clearQueuedCard() throws IOException {
        if (!preferences.edit().remove(QUEUED_CARD_VALUE_KEY).commit()) {
            throw new IOException("queued card clear failed");
        }
    }

    private byte[] serialize(
            DualMachineCardAuthorizationCoordinator
                    .PendingActivation pending) throws IOException {
        ByteArrayOutputStream buffer =
                new ByteArrayOutputStream(1024);
        try (DataOutputStream output = new DataOutputStream(buffer)) {
            output.writeInt(MAGIC);
            output.writeShort(SCHEMA_VERSION);
            writeAscii(output, pending.requestId, 32);
            writeAscii(output, pending.pairId, 32);
            writeAscii(output, pending.challengeId, 32);
            writeAscii(output, pending.challengeToken, 43);
            output.writeLong(pending.challengeExpiresAtEpoch);
            writeAscii(output, pending.hostSignatureBase64, 256);
            writeAscii(output, pending.androidSignatureBase64, 256);
            writeAscii(output, pending.hostKeyFingerprintSha256, 64);
            writeAscii(output, pending.androidKeyFingerprintSha256, 64);
            writeAscii(output, pending.androidIdentityAlias, 128);
            writeAscii(output, pending.activationMode, 11);
            writeAscii(output, pending.targetEntitlementId, 32);
        }
        byte[] result = buffer.toByteArray();
        if (result.length > MAX_PLAINTEXT_BYTES) {
            Arrays.fill(result, (byte) 0);
            throw new IOException(
                    "pending activation payload is oversized");
        }
        return result;
    }

    private DualMachineCardAuthorizationCoordinator.PendingActivation parse(
            byte[] plaintext)
            throws IOException, GeneralSecurityException {
        if (plaintext.length == 0
                || plaintext.length > MAX_PLAINTEXT_BYTES) {
            throw new GeneralSecurityException(
                    "pending activation payload size is invalid");
        }
        try (DataInputStream input = new DataInputStream(
                new ByteArrayInputStream(plaintext))) {
            if (input.readInt() != MAGIC
                    || input.readUnsignedShort() != SCHEMA_VERSION) {
                throw new GeneralSecurityException(
                        "pending activation payload schema is invalid");
            }
            String requestId = readAscii(input, 32);
            String pairId = readAscii(input, 32);
            String challengeId = readAscii(input, 32);
            String challengeToken = readAscii(input, 43);
            long expiresAt = input.readLong();
            String hostSignature = readAscii(input, 256);
            String androidSignature = readAscii(input, 256);
            String hostFingerprint = readAscii(input, 64);
            String androidFingerprint = readAscii(input, 64);
            String androidIdentityAlias = readAscii(input, 128);
            String activationMode = readAscii(input, 11);
            String targetEntitlementId = readAscii(input, 32);
            if (input.read() != -1) {
                throw new GeneralSecurityException(
                        "pending activation payload has trailing data");
            }
            return new DualMachineCardAuthorizationCoordinator
                    .PendingActivation(
                    requestId,
                    pairId,
                    challengeId,
                    challengeToken,
                    expiresAt,
                    hostSignature,
                    androidSignature,
                    hostFingerprint,
                    androidFingerprint,
                    androidIdentityAlias,
                    activationMode,
                    targetEntitlementId);
        } catch (IllegalArgumentException malformed) {
            throw new GeneralSecurityException(
                    "pending activation payload is corrupt", malformed);
        }
    }

    private byte[] encrypt(
            SecretKey key,
            byte[] plaintext,
            byte[] associatedData,
            byte envelopeVersion)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        if (iv == null || iv.length != IV_BYTES) {
            throw new GeneralSecurityException(
                    "pending activation GCM IV is invalid");
        }
        cipher.updateAAD(associatedData);
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] envelope = new byte[1 + IV_BYTES + ciphertext.length];
        envelope[0] = envelopeVersion;
        System.arraycopy(iv, 0, envelope, 1, IV_BYTES);
        System.arraycopy(
                ciphertext, 0, envelope, 1 + IV_BYTES,
                ciphertext.length);
        if (envelope.length > MAX_SEALED_BYTES) {
            Arrays.fill(envelope, (byte) 0);
            throw new GeneralSecurityException(
                    "pending activation envelope is oversized");
        }
        return envelope;
    }

    private byte[] decrypt(
            SecretKey key,
            byte[] iv,
            byte[] ciphertext,
            byte[] associatedData) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(associatedData);
        return cipher.doFinal(ciphertext);
    }

    private SecretKey getOrCreateKey()
            throws GeneralSecurityException, IOException {
        synchronized (KEY_LOCK) {
            KeyStore keyStore = loadKeyStore();
            if (!keyStore.containsAlias(keyAlias)) {
                KeyGenerator generator = KeyGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_AES,
                        ANDROID_KEYSTORE);
                generator.init(new KeyGenParameterSpec.Builder(
                        keyAlias,
                        KeyProperties.PURPOSE_ENCRYPT
                                | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(
                                KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .setRandomizedEncryptionRequired(true)
                        .setUserAuthenticationRequired(false)
                        .build());
                generator.generateKey();
                keyStore = loadKeyStore();
            }
            return requireKey(keyStore);
        }
    }

    private SecretKey requireExistingKey()
            throws GeneralSecurityException, IOException {
        synchronized (KEY_LOCK) {
            KeyStore keyStore = loadKeyStore();
            if (!keyStore.containsAlias(keyAlias)) {
                throw new GeneralSecurityException(
                        "pending activation sealing key is missing");
            }
            return requireKey(keyStore);
        }
    }

    private SecretKey requireKey(KeyStore keyStore)
            throws GeneralSecurityException {
        java.security.Key value = keyStore.getKey(keyAlias, null);
        if (!(value instanceof SecretKey)
                || value.getEncoded() != null
                || value.getFormat() != null) {
            throw new GeneralSecurityException(
                    "pending activation sealing key is invalid");
        }
        SecretKey key = (SecretKey) value;
        SecretKeyFactory factory = SecretKeyFactory.getInstance(
                key.getAlgorithm(), ANDROID_KEYSTORE);
        KeyInfo keyInfo = (KeyInfo) factory.getKeySpec(
                key, KeyInfo.class);
        int expectedPurposes = KeyProperties.PURPOSE_ENCRYPT
                | KeyProperties.PURPOSE_DECRYPT;
        if (keyInfo.getPurposes() != expectedPurposes
                || !Arrays.asList(keyInfo.getBlockModes()).contains(
                KeyProperties.BLOCK_MODE_GCM)
                || !Arrays.asList(
                keyInfo.getEncryptionPaddings()).contains(
                KeyProperties.ENCRYPTION_PADDING_NONE)) {
            throw new GeneralSecurityException(
                    "pending activation sealing key policy is invalid");
        }
        return key;
    }

    private static KeyStore loadKeyStore()
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        return keyStore;
    }

    private static void writeAscii(
            DataOutputStream output,
            String value,
            int maximumBytes) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        if (bytes.length > maximumBytes
                || !value.equals(new String(
                bytes, StandardCharsets.US_ASCII))) {
            throw new IOException(
                    "pending activation field is not bounded ASCII");
        }
        output.writeShort(bytes.length);
        output.write(bytes);
    }

    private static String readAscii(
            DataInputStream input,
            int maximumBytes) throws IOException {
        int length = input.readUnsignedShort();
        if (length > maximumBytes) {
            throw new IOException(
                    "pending activation field is oversized");
        }
        byte[] bytes = new byte[length];
        input.readFully(bytes);
        for (byte value : bytes) {
            if ((value & 0x80) != 0) {
                throw new IOException(
                        "pending activation field is not ASCII");
            }
        }
        return new String(bytes, StandardCharsets.US_ASCII);
    }

    private static byte[] decodeCanonicalBase64(String encoded)
            throws GeneralSecurityException {
        if (encoded.isEmpty() || encoded.length() > 8192) {
            throw new GeneralSecurityException(
                    "pending activation envelope encoding is invalid");
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(encoded);
            if (!Base64.getEncoder().encodeToString(decoded)
                    .equals(encoded)) {
                throw new GeneralSecurityException(
                        "pending activation envelope is not canonical");
            }
            return decoded;
        } catch (IllegalArgumentException malformed) {
            throw new GeneralSecurityException(
                    "pending activation envelope is not Base64",
                    malformed);
        }
    }

    private static boolean validAlias(String value) {
        if (value == null || value.isEmpty() || value.length() > 96) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= 'A' && character <= 'Z')
                    || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9')
                    || character == '.' || character == '_'
                    || character == '-')) {
                return false;
            }
        }
        return true;
    }
}
