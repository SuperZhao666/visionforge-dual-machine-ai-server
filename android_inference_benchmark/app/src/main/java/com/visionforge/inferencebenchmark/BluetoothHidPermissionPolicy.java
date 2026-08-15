package com.visionforge.inferencebenchmark;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Build;

/** Runtime Nearby devices permission boundary for the Bluetooth HID route. */
final class BluetoothHidPermissionPolicy {
    private final Activity activity;

    BluetoothHidPermissionPolicy(Activity activity) {
        this.activity = activity;
    }

    boolean isGranted() {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.S
                || activity.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                == PackageManager.PERMISSION_GRANTED
                && activity.checkSelfPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
                == PackageManager.PERMISSION_GRANTED;
    }

    void request(int requestCode) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return;
        activity.requestPermissions(
                new String[] {
                        Manifest.permission.BLUETOOTH_CONNECT,
                        Manifest.permission.BLUETOOTH_ADVERTISE
                },
                requestCode);
    }

    String auditDetail() {
        return "bluetooth_hid_nearby_devices_permission_granted=" + isGranted();
    }
}
