package com.visionforge.inferencebenchmark;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * SHA-256 SPKI pin policy with rotation support.
 *
 * <p>Only public-key pins are accepted. A production build can carry both the
 * current and offline backup certificate key without embedding any private
 * material.</p>
 */
public final class DualMachineTlsPinPolicy {
    private static final String PIN_PREFIX = "sha256/";
    private final Set<String> pins;

    public DualMachineTlsPinPolicy(Collection<String> configuredPins) {
        if (configuredPins == null || configuredPins.isEmpty()) {
            throw new IllegalArgumentException(
                    "at least one TLS SPKI pin is required");
        }
        Set<String> validated = new HashSet<>();
        for (String pin : configuredPins) {
            validated.add(requirePin(pin));
        }
        pins = Collections.unmodifiableSet(validated);
    }

    public void verify(Certificate[] peerChain)
            throws GeneralSecurityException {
        if (peerChain == null || peerChain.length == 0) {
            throw new GeneralSecurityException("TLS peer chain is missing");
        }
        for (Certificate certificate : peerChain) {
            if (certificate == null || certificate.getPublicKey() == null) {
                continue;
            }
            String candidate = pinForEncodedPublicKey(
                    certificate.getPublicKey().getEncoded());
            if (pins.contains(candidate)) return;
        }
        throw new GeneralSecurityException("TLS SPKI pin mismatch");
    }

    public static String pinForEncodedPublicKey(byte[] encodedPublicKey)
            throws GeneralSecurityException {
        if (encodedPublicKey == null || encodedPublicKey.length < 32
                || encodedPublicKey.length > 16 * 1024) {
            throw new GeneralSecurityException(
                    "TLS public key encoding is invalid");
        }
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(encodedPublicKey);
        return PIN_PREFIX + Base64.getEncoder().encodeToString(digest);
    }

    private static String requirePin(String value) {
        if (value == null || !value.startsWith(PIN_PREFIX)) {
            throw new IllegalArgumentException("TLS pin has invalid prefix");
        }
        String encoded = value.substring(PIN_PREFIX.length());
        try {
            byte[] decoded = Base64.getDecoder().decode(encoded);
            if (decoded.length != 32
                    || !Base64.getEncoder().encodeToString(decoded)
                    .equals(encoded)) {
                throw new IllegalArgumentException(
                        "TLS pin is not canonical SHA-256 Base64");
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("TLS pin is invalid", exception);
        }
        return value;
    }
}
