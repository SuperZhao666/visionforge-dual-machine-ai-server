package com.visionforge.inferencebenchmark;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.PowerManager;
import android.provider.Settings;

/** Public-API battery policy boundary for uninterrupted foreground inference. */
final class BackgroundExecutionPolicy {
    private final Activity activity;

    BackgroundExecutionPolicy(Activity activity) {
        this.activity = activity;
    }

    boolean isExempt() {
        PowerManager power = activity.getSystemService(PowerManager.class);
        return power != null && power.isIgnoringBatteryOptimizations(activity.getPackageName());
    }

    boolean requestExemption() {
        Intent request = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                .setData(Uri.parse("package:" + activity.getPackageName()));
        try {
            activity.startActivity(request);
            return true;
        } catch (ActivityNotFoundException unavailable) {
            try {
                activity.startActivity(new Intent(
                        Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
                return true;
            } catch (ActivityNotFoundException ignored) {
                return false;
            }
        }
    }

    String auditDetail() {
        return "battery_optimization_exempt=" + isExempt();
    }
}
