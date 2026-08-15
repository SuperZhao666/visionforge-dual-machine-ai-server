package com.visionforge.inferencebenchmark;

import android.content.Context;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Loads only build-pinned public security material for the dual-machine
 * sidecar. No URL, TLS pin or lease key is accepted from app preferences,
 * intents, QR payloads or a network response.
 */
public final class DualMachineReleaseSecurityConfig {
    private static final int MAXIMUM_TLS_PINS = 4;
    private static final int MAXIMUM_TICKET_KEYS = 3;
    private static final String PUBLIC_KEY_BEGIN =
            "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_END =
            "-----END PUBLIC KEY-----";

    public static final class Material {
        public final DualMachineSidecarPort sidecar;
        public final DualMachineUsageLeaseKeyring leaseKeyring;

        private Material(
                DualMachineSidecarPort sidecar,
                DualMachineUsageLeaseKeyring leaseKeyring) {
            this.sidecar = sidecar;
            this.leaseKeyring = leaseKeyring;
        }
    }

    private DualMachineReleaseSecurityConfig() {
    }

    public static Material load(Context context)
            throws GeneralSecurityException {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        AndroidAppIntegrityVerifier.requireTrustedProductionInstall(context);
        List<String> pins = parsePins(
                BuildConfig.DUAL_MACHINE_TLS_SPKI_PINS,
                BuildConfig.DEBUG);
        List<PublicKey> ticketKeys = parseTicketKeys(
                BuildConfig.DUAL_MACHINE_TICKET_PUBLIC_KEYS_BASE64);
        DualMachineTlsPinPolicy pinPolicy =
                new DualMachineTlsPinPolicy(pins);
        DualMachineHttpsJsonTransport transport =
                new DualMachineHttpsJsonTransport(
                        BuildConfig.DUAL_MACHINE_API_ORIGIN,
                        new AndroidDualMachineHttpsConnectionFactory(
                                new AndroidValidatedInternetNetworkProvider(
                                        context)),
                        pinPolicy,
                        BuildConfig.VERSION_NAME);
        return new Material(
                new DualMachineSidecarHttpClient(transport),
                new DualMachineUsageLeaseKeyring(ticketKeys, 5));
    }

    static List<String> parsePins(String configured, boolean developmentBuild)
            throws GeneralSecurityException {
        if (configured == null || configured.isBlank()) {
            throw new GeneralSecurityException(
                    "dual_machine_tls_pins_missing");
        }
        String[] values = configured.split("[,;]", -1);
        List<String> result = new ArrayList<>(values.length);
        Set<String> uniquePins = new LinkedHashSet<>();
        for (String value : values) {
            String pin = value.trim();
            if (!pin.isEmpty()) {
                result.add(pin);
                uniquePins.add(pin);
            }
        }
        int minimumPins = developmentBuild ? 1 : 2;
        if (result.size() < minimumPins
                || result.size() > MAXIMUM_TLS_PINS
                || uniquePins.size() != result.size()) {
            throw new GeneralSecurityException(
                    "dual_machine_tls_pin_rotation_set_invalid");
        }
        try {
            // Constructor performs strict canonical SHA-256/Base64 checks.
            new DualMachineTlsPinPolicy(result);
        } catch (IllegalArgumentException invalid) {
            throw new GeneralSecurityException(
                    "dual_machine_tls_pin_invalid", invalid);
        }
        return Collections.unmodifiableList(result);
    }

    static List<PublicKey> parseTicketKeys(String encodedFiles)
            throws GeneralSecurityException {
        if (encodedFiles == null || encodedFiles.isBlank()) {
            throw new GeneralSecurityException(
                    "dual_machine_ticket_keys_missing");
        }
        String[] values = encodedFiles.split(";", -1);
        if (values.length < 1 || values.length > MAXIMUM_TICKET_KEYS) {
            throw new GeneralSecurityException(
                    "dual_machine_ticket_keyring_size_invalid");
        }
        List<PublicKey> result = new ArrayList<>(values.length);
        Set<String> keyFingerprints = new LinkedHashSet<>();
        for (String encodedFile : values) {
            if (encodedFile.isBlank()) {
                throw new GeneralSecurityException(
                        "dual_machine_ticket_key_empty");
            }
            final byte[] pemBytes;
            try {
                pemBytes = Base64.getDecoder().decode(encodedFile);
            } catch (IllegalArgumentException invalid) {
                throw new GeneralSecurityException(
                        "dual_machine_ticket_key_wrapper_invalid",
                        invalid);
            }
            PublicKey publicKey = parsePublicPem(pemBytes);
            String fingerprint = sha256Hex(publicKey.getEncoded());
            if (!keyFingerprints.add(fingerprint)) {
                throw new GeneralSecurityException(
                        "dual_machine_ticket_key_duplicated");
            }
            result.add(publicKey);
        }
        return Collections.unmodifiableList(result);
    }

    private static PublicKey parsePublicPem(byte[] pemBytes)
            throws GeneralSecurityException {
        if (pemBytes.length < 256 || pemBytes.length > 16 * 1024) {
            throw new GeneralSecurityException(
                    "dual_machine_ticket_public_pem_size_invalid");
        }
        String pem = new String(
                pemBytes, StandardCharsets.US_ASCII).trim();
        if (!pem.startsWith(PUBLIC_KEY_BEGIN)
                || !pem.endsWith(PUBLIC_KEY_END)
                || pem.contains("PRIVATE KEY")
                || pem.indexOf(PUBLIC_KEY_BEGIN, 1) >= 0) {
            throw new GeneralSecurityException(
                    "dual_machine_ticket_public_pem_invalid");
        }
        String body = pem.substring(
                PUBLIC_KEY_BEGIN.length(),
                pem.length() - PUBLIC_KEY_END.length())
                .replaceAll("\\s", "");
        final byte[] der;
        try {
            der = Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException invalid) {
            throw new GeneralSecurityException(
                    "dual_machine_ticket_public_pem_base64_invalid",
                    invalid);
        }
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(der));
        if (!(key instanceof RSAPublicKey)) {
            throw new GeneralSecurityException(
                    "dual_machine_ticket_public_key_not_rsa");
        }
        RSAPublicKey rsaPublicKey = (RSAPublicKey) key;
        if (rsaPublicKey.getModulus().bitLength() < 3072) {
            throw new GeneralSecurityException(
                    "dual_machine_ticket_public_key_too_weak");
        }
        if (!MessageDigest.isEqual(key.getEncoded(), der)) {
            throw new GeneralSecurityException(
                    "dual_machine_ticket_public_key_not_canonical");
        }
        return key;
    }

    private static String sha256Hex(byte[] value)
            throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder builder = new StringBuilder(digest.length * 2);
        for (byte item : digest) {
            builder.append(String.format("%02x", item & 0xff));
        }
        return builder.toString();
    }
}
