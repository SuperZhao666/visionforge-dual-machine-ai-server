package com.visionforge.inferencebenchmark;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.provider.Settings;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;

/** Collects bounded hardware metadata without privileged identifiers. */
final class AndroidDeviceProfileCollector {
    private static final String FINGERPRINT_DOMAIN =
            "visionforge-android-device-profile-v1";

    private AndroidDeviceProfileCollector() {
    }

    /** Public Android SoC identity; never substitutes for the QNN graph probe. */
    static String collectSocModel() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                ? safe(Build.SOC_MODEL)
                : safe(Build.HARDWARE);
    }

    static String collectSocManufacturer() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                ? safe(Build.SOC_MANUFACTURER)
                : safe(Build.MANUFACTURER);
    }

    static String collectSocHardwareEvidence() {
        String hardware = safe(Build.HARDWARE);
        String board = safe(Build.BOARD);
        return hardware.equals(board) ? hardware : hardware + " " + board;
    }

    @SuppressLint("HardwareIds")
    static DualMachineAndroidDeviceProfile collect(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        String androidId = Settings.Secure.getString(
                context.getApplicationContext().getContentResolver(),
                Settings.Secure.ANDROID_ID);
        String fingerprint = sha256Hex(String.join("\n",
                FINGERPRINT_DOMAIN,
                safe(androidId),
                safe(Build.MANUFACTURER),
                safe(Build.BRAND),
                safe(Build.MODEL),
                safe(Build.DEVICE),
                safe(Build.PRODUCT),
                safe(Build.HARDWARE),
                safe(Build.FINGERPRINT))
                .getBytes(StandardCharsets.UTF_8));
        return new DualMachineAndroidDeviceProfile(
                safe(Build.MANUFACTURER),
                safe(Build.BRAND),
                safe(Build.MODEL),
                safe(Build.DEVICE),
                safe(Build.PRODUCT),
                safe(Build.HARDWARE),
                safe(Build.VERSION.RELEASE),
                Build.VERSION.SDK_INT,
                Arrays.asList(Build.SUPPORTED_ABIS.clone()),
                fingerprint);
    }

    private static String safe(String value) {
        String normalized = value == null ? "" : value.trim();
        return normalized.isEmpty() ? "unknown" : normalized;
    }

    private static String sha256Hex(byte[] input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(input);
            StringBuilder result = new StringBuilder(64);
            for (byte value : digest) {
                result.append(String.format(
                        Locale.ROOT, "%02x", value & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException(
                    "SHA-256 is unavailable", unavailable);
        }
    }
}
