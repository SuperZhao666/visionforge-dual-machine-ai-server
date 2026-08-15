package com.visionforge.inferencebenchmark;

import android.bluetooth.BluetoothManager;
import android.content.Context;
import android.content.pm.PackageManager;

/** Android-framework factory kept outside MobileControlRuntime's policy boundary. */
final class AndroidHidMouseSessionFactory {
    private AndroidHidMouseSessionFactory() {
    }

    static BluetoothHidSessionPort create(Context context) {
        return create(context, null);
    }

    static BluetoothHidSessionPort create(Context context, MobileRuntimeEventSink events) {
        return new AndroidBluetoothHidDeviceAdapter(
                context,
                context == null ? null : context.getMainExecutor(),
                events);
    }

    static boolean isSupported(Context context) {
        if (context == null) return false;
        PackageManager packageManager = context.getPackageManager();
        BluetoothManager manager = context.getSystemService(BluetoothManager.class);
        return packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH)
                && manager != null
                && manager.getAdapter() != null;
    }
}
