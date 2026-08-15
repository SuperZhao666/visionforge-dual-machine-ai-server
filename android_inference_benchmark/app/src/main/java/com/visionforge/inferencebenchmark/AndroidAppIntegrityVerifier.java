package com.visionforge.inferencebenchmark;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Debug;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Locale;

/** Fail-closed production signer and debuggability gate for paid mobile features. */
final class AndroidAppIntegrityVerifier {
    private static final int SHA256_HEX_LENGTH = 64;

    private AndroidAppIntegrityVerifier() {
    }

    static void requireTrustedProductionInstall(Context context)
            throws GeneralSecurityException {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        // QA and explicitly permitted development-signing releases remain
        // installable. The production builder always supplies the certificate.
        if (!BuildConfig.APP_SIGNING_INTEGRITY_REQUIRED) return;

        requireReleaseProcess(context);
        String expected = requireSha256(
                BuildConfig.EXPECTED_APP_SIGNING_CERTIFICATE_SHA256);
        String actual = currentSignerSha256(context);
        if (!MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII),
                actual.getBytes(StandardCharsets.US_ASCII))) {
            throw new GeneralSecurityException(
                    "android_app_signing_certificate_mismatch");
        }
    }

    private static void requireReleaseProcess(Context context)
            throws GeneralSecurityException {
        ApplicationInfo application = context.getApplicationInfo();
        boolean debuggable = (application.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        boolean testOnly = (application.flags & ApplicationInfo.FLAG_TEST_ONLY) != 0;
        if (BuildConfig.DEBUG || debuggable || testOnly) {
            throw new GeneralSecurityException(
                    "android_production_process_flags_invalid");
        }
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            throw new GeneralSecurityException(
                    "android_production_debugger_attached");
        }
        if (!BuildConfig.APPLICATION_ID.equals(context.getPackageName())) {
            throw new GeneralSecurityException(
                    "android_application_id_mismatch");
        }
    }

    private static String currentSignerSha256(Context context)
            throws GeneralSecurityException {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
                    context.getPackageName(),
                    PackageManager.GET_SIGNING_CERTIFICATES);
            SigningInfo signingInfo = packageInfo.signingInfo;
            Signature[] signers = signingInfo == null
                    ? null : signingInfo.getApkContentsSigners();
            if (signers == null || signers.length != 1) {
                throw new GeneralSecurityException(
                        "android_current_signer_set_invalid");
            }
            return sha256Hex(signers[0].toByteArray());
        } catch (PackageManager.NameNotFoundException failure) {
            throw new GeneralSecurityException(
                    "android_package_signer_unavailable", failure);
        }
    }

    private static String requireSha256(String value)
            throws GeneralSecurityException {
        String normalized = value == null
                ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (normalized.length() != SHA256_HEX_LENGTH) {
            throw new GeneralSecurityException(
                    "android_expected_signer_invalid");
        }
        for (int index = 0; index < normalized.length(); index++) {
            char character = normalized.charAt(index);
            if ((character < '0' || character > '9')
                    && (character < 'a' || character > 'f')) {
                throw new GeneralSecurityException(
                        "android_expected_signer_invalid");
            }
        }
        return normalized;
    }

    private static String sha256Hex(byte[] value)
            throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        char[] encoded = new char[digest.length * 2];
        char[] alphabet = "0123456789abcdef".toCharArray();
        for (int index = 0; index < digest.length; index++) {
            int current = digest[index] & 0xff;
            encoded[index * 2] = alphabet[current >>> 4];
            encoded[index * 2 + 1] = alphabet[current & 0x0f];
        }
        return new String(encoded);
    }
}
