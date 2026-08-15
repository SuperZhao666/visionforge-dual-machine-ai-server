package com.visionforge.inferencebenchmark;

import android.Manifest;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;

/** Runtime notification permission boundary for a visible foreground service. */
final class NotificationExecutionPolicy {
    private static final String PREFERENCES = "visionforge_notification_policy";
    private static final String PREF_REQUESTED = "notification_permission_requested";

    private final Activity activity;

    NotificationExecutionPolicy(Activity activity) {
        this.activity = activity;
    }

    boolean isGranted() {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU
                || activity.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED;
    }

    boolean requestIfRequired(int requestCode) {
        if (isGranted() || wasRequested()) return false;
        if (!preferences().edit().putBoolean(PREF_REQUESTED, true).commit()) return false;
        activity.requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, requestCode);
        return true;
    }

    boolean openSettings() {
        Intent settings = new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, activity.getPackageName());
        try {
            activity.startActivity(settings);
            return true;
        } catch (ActivityNotFoundException unavailable) {
            return false;
        }
    }

    String auditDetail() {
        return "notification_permission_granted=" + isGranted()
                + " notification_permission_requested=" + wasRequested();
    }

    private boolean wasRequested() {
        return preferences().getBoolean(PREF_REQUESTED, false);
    }

    private SharedPreferences preferences() {
        return activity.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
    }
}
