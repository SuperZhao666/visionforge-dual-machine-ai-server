package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Source-level contract for the narrow Android Bluetooth HID API adapter. */
final class BluetoothHidDeviceAdapterSourceContractSelfTest {
    static void run() throws IOException {
        String projectDirectory = System.getProperty("visionforge.android.project.dir", ".");
        Path projectPath = Paths.get(projectDirectory);
        String adapter = read(projectPath,
                "src/main/java/com/visionforge/inferencebenchmark/"
                        + "AndroidBluetoothHidDeviceAdapter.java");
        String manifest = read(projectPath, "src/main/AndroidManifest.xml");
        String runtime = read(projectPath,
                "src/main/java/com/visionforge/inferencebenchmark/MobileControlRuntime.java");
        String cat6ButtonInput = read(projectPath,
                "src/main/java/com/visionforge/inferencebenchmark/"
                        + "Cat6MouseButtonInput.java");
        String factory = read(projectPath,
                "src/main/java/com/visionforge/inferencebenchmark/"
                        + "AndroidHidMouseSessionFactory.java");
        String sessionPort = read(projectPath,
                "src/main/java/com/visionforge/inferencebenchmark/BluetoothHidSessionPort.java");
        String buildGradle = read(projectPath, "build.gradle");
        String compactAdapter = adapter.replaceAll("\\s+", "");
        String compactSessionPort = sessionPort.replaceAll("\\s+", "");

        require(adapter.contains(
                "implements BluetoothHidMouseTransportCore.SessionPort, AutoCloseable"));
        require(adapter.contains("import android.bluetooth.BluetoothHidDevice;"));
        require(adapter.contains("BluetoothProfile.HID_DEVICE"));
        require(adapter.contains("BluetoothHidDeviceAppSdpSettings"));
        require(adapter.contains("BluetoothHidDevice.SUBCLASS1_MOUSE"));
        require(adapter.contains("VF \\u65e0\\u7ebf\\u9f20\\u6807"));
        require(adapter.contains("\"VF\","));
        require(!adapter.contains("VisionForge"));
        require(compactAdapter.contains("targetHidDevice.sendReport(target,0,report.clone())"));
        require(adapter.contains("logging=rate_limited"));
        require(adapter.contains("SEND_REPORT_SUCCESS_LOG_INTERVAL_NANOS"));
        require(adapter.contains("cachedSessionState"));
        require(compactAdapter.contains("cached!=null&&cached.matches("));
        require(compactAdapter.contains(
                "if(state==BluetoothProfile.STATE_CONNECTED){connectedHost=target;"
                        + "lastSendReportAccepted=true;rememberHostLocked(target);returntrue;}"));
        require(compactAdapter.contains("newbyte[]{0x05,0x01"));
        require(adapter.contains("BluetoothHidSessionPort"));
        require(adapter.contains("void setForegroundSessionActive(boolean active)"));
        require(adapter.contains("unregisterMouseApp();"));
        require(adapter.contains("MobileRuntimeEventSink"));
        require(adapter.contains("bluetooth_hid_register_app"));
        require(adapter.contains("already_registered_or_pending"));
        require(adapter.contains("reason=request_pending"));
        require(adapter.contains("BluetoothHidPendingOperationPolicy.hasTimedOut("));
        require(adapter.contains("bluetooth_hid_profile_request_timeout"));
        require(adapter.contains("bluetooth_hid_register_app_timeout"));
        require(adapter.contains("recoverTimedOutAppRegistrationLocked()"));
        require(adapter.contains("automatic_retry=true"));
        require(adapter.contains("reason=not_registered"));
        require(adapter.contains("hidDevice.connect(target)"));
        require(adapter.contains("adapter.getBondedDevices()"));
        require(adapter.contains("KEY_PREFERRED_HOST"));
        require(adapter.contains("BluetoothDevice.ACTION_BOND_STATE_CHANGED"));
        require(adapter.contains("Manifest.permission.BLUETOOTH_CONNECT"));
        require(adapter.contains("Manifest.permission.BLUETOOTH_ADVERTISE"));
        require(compactSessionPort.contains(
                "extendsBluetoothHidMouseTransportCore.SessionPort,AutoCloseable"));
        require(sessionPort.contains("void setForegroundSessionActive(boolean active);"));
        require(sessionPort.contains("BluetoothHidOutputFailClosedPolicy.SessionState sessionState();"));

        require(manifest.contains("android.permission.BLUETOOTH_CONNECT"));
        require(manifest.contains("android.permission.BLUETOOTH_ADVERTISE"));
        require(manifest.contains("android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE"));

        require(runtime.contains("AndroidHidMouseSessionFactory.create(appContext, events)"));
        require(runtime.contains("selectOutputRoute("));
        require(runtime.contains("Cat6MouseButtonInput"));
        require(runtime.contains("ControlOutputRoute.BLUETOOTH_HID"));
        require(cat6ButtonInput.contains("Cat6MouseButtonEndpointPolicy"));
        require(cat6ButtonInput.contains(
                "endpointPolicy.shouldHandleUnavailable("));
        require(cat6ButtonInput.contains("if (!endpointReady)"));
        require(cat6ButtonInput.contains("inputAlreadyStopped"));
        int makcuSwitchStart = runtime.indexOf(
                "private void switchToMakcuOutputRoute");
        int bluetoothSwitchStart = runtime.indexOf(
                "private String switchToBluetoothHidOutputRoute",
                makcuSwitchStart);
        require(makcuSwitchStart >= 0 && bluetoothSwitchStart > makcuSwitchStart);
        String makcuSwitch = runtime.substring(makcuSwitchStart, bluetoothSwitchStart);
        require(makcuSwitch.indexOf("installOutputRoute(")
                < makcuSwitch.indexOf("closeBluetoothHidRoute()"));
        require(!runtime.contains("BluetoothHidVerifiedDeviceCatalog"));
        require(!runtime.contains("AndroidBluetoothHidDeviceAdapter"));
        require(!runtime.contains("BluetoothHidDevice"));
        require(!runtime.contains("BluetoothProfile.HID_DEVICE"));
        require(factory.contains("MobileRuntimeEventSink events"));
        require(factory.contains("new AndroidBluetoothHidDeviceAdapter("));
        require(!buildGradle.contains(
                "'src/main/java/com/visionforge/inferencebenchmark/"
                        + "AndroidBluetoothHidDeviceAdapter.java'"));
    }

    private static String read(Path projectPath, String relativePath) throws IOException {
        return new String(
                Files.readAllBytes(projectPath.resolve(relativePath)),
                StandardCharsets.UTF_8);
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("Bluetooth HID adapter source contract failed");
        }
    }
}
