package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * Canonical traditional card-key input contract shared by UI and transport.
 *
 * <p>Only spaces and hyphens are treated as presentation separators. Other
 * punctuation is rejected instead of silently changing what the user typed.
 * The public checksum is validated locally before any network request.</p>
 */
public final class DualMachineCardCode {
    private static final String PREFIX = "VFD2";
    private static final String ALPHABET =
            "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    private static final int PAYLOAD_CHARACTERS = 28;
    private static final int CHECKSUM_CHARACTERS = 2;
    private static final int BODY_CHARACTERS =
            PAYLOAD_CHARACTERS + CHECKSUM_CHARACTERS;

    private DualMachineCardCode() {
    }

    public static String normalizeAndValidate(String rawValue) {
        if (rawValue == null) {
            throw new IllegalArgumentException("card code is required");
        }
        StringBuilder compact = new StringBuilder(
                PREFIX.length() + BODY_CHARACTERS);
        for (int index = 0; index < rawValue.length(); index++) {
            char value = rawValue.charAt(index);
            if (value == '-' || Character.isWhitespace(value)) {
                continue;
            }
            if (value > 0x7f || !Character.isLetterOrDigit(value)) {
                throw new IllegalArgumentException(
                        "card code contains invalid punctuation");
            }
            compact.append(Character.toUpperCase(value));
        }
        if (compact.length() != PREFIX.length() + BODY_CHARACTERS
                || !compact.toString().startsWith(PREFIX)) {
            throw new IllegalArgumentException(
                    "card code must use the issued VFD2 format");
        }
        String body = compact.substring(PREFIX.length());
        for (int index = 0; index < body.length(); index++) {
            if (ALPHABET.indexOf(body.charAt(index)) < 0) {
                throw new IllegalArgumentException(
                        "card code contains an invalid character");
            }
        }
        String payload = body.substring(0, PAYLOAD_CHARACTERS);
        String suppliedChecksum = body.substring(PAYLOAD_CHARACTERS);
        if (!constantTimeEquals(suppliedChecksum, checksum(payload))) {
            throw new IllegalArgumentException("card code checksum is invalid");
        }
        StringBuilder formatted = new StringBuilder(40);
        formatted.append(PREFIX).append('-');
        for (int offset = 0; offset < body.length(); offset += 5) {
            if (offset > 0) formatted.append('-');
            formatted.append(body, offset, offset + 5);
        }
        return formatted.toString();
    }

    private static String checksum(String payload) {
        final byte[] digest;
        try {
            digest = MessageDigest.getInstance("SHA-256").digest(
                    payload.getBytes(StandardCharsets.US_ASCII));
        } catch (GeneralSecurityException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
        int first = (digest[0] & 0xff) >>> 3;
        int second = ((digest[0] & 0x07) << 2)
                | ((digest[1] & 0xff) >>> 6);
        return new String(new char[]{
                ALPHABET.charAt(first),
                ALPHABET.charAt(second)}).toUpperCase(Locale.ROOT);
    }

    private static boolean constantTimeEquals(String first, String second) {
        return MessageDigest.isEqual(
                first.getBytes(StandardCharsets.US_ASCII),
                second.getBytes(StandardCharsets.US_ASCII));
    }
}
