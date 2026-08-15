package com.visionforge.inferencebenchmark;

import android.app.ActivityManager;
import android.app.ApplicationExitInfo;
import android.content.Context;
import android.os.Build;

import java.util.List;
import java.util.Locale;

/** Reads the newest public Android process-exit record without privileged APIs. */
final class MobilePreviousExitInspector {
    private static final int MAXIMUM_RECORDS = 8;

    private MobilePreviousExitInspector() {}

    static Result inspect(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return Result.none();
        }
        ActivityManager manager = context.getSystemService(ActivityManager.class);
        if (manager == null) return Result.none();
        try {
            List<ApplicationExitInfo> history =
                    manager.getHistoricalProcessExitReasons(
                            context.getPackageName(), 0, MAXIMUM_RECORDS);
            if (history == null || history.isEmpty()) return Result.none();
            ApplicationExitInfo latest = history.get(0);
            String description = latest.getDescription();
            return new Result(
                    MobilePreviousExitPolicy.classify(
                            latest.getReason(), description),
                    latest.getTimestamp(),
                    latest.getReason(),
                    boundedToken(description));
        } catch (RuntimeException unavailable) {
            return Result.none();
        }
    }

    private static String boundedToken(String value) {
        if (value == null || value.isBlank()) return "none";
        String normalized = value.replace('\r', ' ')
                .replace('\n', ' ').trim();
        if (normalized.length() > 200) {
            normalized = normalized.substring(0, 200);
        }
        return normalized.replace(' ', '_');
    }

    static final class Result {
        final MobilePreviousExitPolicy.Kind kind;
        final long timestampMillis;
        final int reason;
        final String descriptionToken;

        Result(
                MobilePreviousExitPolicy.Kind kind,
                long timestampMillis,
                int reason,
                String descriptionToken) {
            this.kind = kind;
            this.timestampMillis = Math.max(0L, timestampMillis);
            this.reason = reason;
            this.descriptionToken = descriptionToken;
        }

        static Result none() {
            return new Result(
                    MobilePreviousExitPolicy.Kind.NONE,
                    0L, 0, "none");
        }

        String detail() {
            return "kind=" + kind.name().toLowerCase(Locale.ROOT)
                    + " timestamp_ms=" + timestampMillis
                    + " android_reason=" + reason
                    + " description=" + descriptionToken;
        }
    }
}
