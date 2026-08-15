package com.visionforge.inferencebenchmark;

import android.Manifest;
import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothClass;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHidDevice;
import android.bluetooth.BluetoothHidDeviceAppSdpSettings;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;

import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;

/** Android Bluetooth HID device adapter for the production move-only route. */
final class AndroidBluetoothHidDeviceAdapter
        implements BluetoothHidMouseTransportCore.SessionPort, AutoCloseable,
        BluetoothHidSessionPort {
    private static final byte[] MOUSE_REPORT_DESCRIPTOR = new byte[] {
            0x05, 0x01,
            0x09, 0x02,
            (byte) 0xA1, 0x01,
            0x09, 0x01,
            (byte) 0xA1, 0x00,
            0x05, 0x09,
            0x19, 0x01,
            0x29, 0x03,
            0x15, 0x00,
            0x25, 0x01,
            (byte) 0x95, 0x03,
            0x75, 0x01,
            (byte) 0x81, 0x02,
            (byte) 0x95, 0x01,
            0x75, 0x05,
            (byte) 0x81, 0x03,
            0x05, 0x01,
            0x09, 0x30,
            0x09, 0x31,
            0x09, 0x38,
            0x15, (byte) 0x81,
            0x25, 0x7F,
            0x75, 0x08,
            (byte) 0x95, 0x03,
            (byte) 0x81, 0x06,
            (byte) 0xC0,
            (byte) 0xC0
    };
    private static final String PREFERENCES = "visionforge_bluetooth_hid";
    private static final String KEY_PREFERRED_HOST = "preferred_host_address_v1";
    private static final long CONNECT_RETRY_NANOS = 1_000_000_000L;
    private static final long SEND_REPORT_SUCCESS_LOG_INTERVAL_NANOS = 5_000_000_000L;

    private final Context appContext;
    private final Executor callbackExecutor;
    private final MobileRuntimeEventSink events;
    private final SharedPreferences preferences;
    private BluetoothHidDevice hidDevice;
    private BluetoothDevice connectedHost;
    private boolean profileProxyRequested;
    private boolean profileProxyConnected;
    private boolean foregroundSessionActive;
    private boolean registerAppAccepted;
    private boolean appRegistered;
    private boolean lastSendReportAccepted = true;
    private long acceptedSendReportCount;
    private long nextAcceptedSendReportLogNanos;
    private boolean receiverRegistered;
    private long nextConnectAttemptNanos;
    private long profileProxyRequestStartedNanos;
    private long registerAppRequestStartedNanos;
    private BluetoothHidOutputFailClosedPolicy.SessionState cachedSessionState;

    private final BroadcastReceiver bluetoothReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent == null) return;
            synchronized (AndroidBluetoothHidDeviceAdapter.this) {
                String action = intent.getAction();
                if (BluetoothDevice.ACTION_BOND_STATE_CHANGED.equals(action)) {
                    BluetoothDevice device = intent.getParcelableExtra(
                            BluetoothDevice.EXTRA_DEVICE);
                    int state = intent.getIntExtra(
                            BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.BOND_NONE);
                    writeEvent("bluetooth_hid_bond_state",
                            "state=" + state + " device_present=" + (device != null));
                    if (state == BluetoothDevice.BOND_BONDED && device != null
                            && foregroundSessionActive) {
                        connectHostLocked(device);
                    }
                } else if (BluetoothAdapter.ACTION_STATE_CHANGED.equals(action)) {
                    int state = intent.getIntExtra(
                            BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR);
                    writeEvent("bluetooth_hid_adapter_state", "state=" + state);
                    if (state == BluetoothAdapter.STATE_ON && foregroundSessionActive) {
                        requestHidProfile();
                        registerMouseAppIfProfileReady();
                        connectPreferredHostLocked();
                    }
                }
            }
        }
    };

    private final BluetoothProfile.ServiceListener profileListener =
            new BluetoothProfile.ServiceListener() {
                @Override
                public void onServiceConnected(int profile, BluetoothProfile proxy) {
                    synchronized (AndroidBluetoothHidDeviceAdapter.this) {
                        profileProxyRequested = false;
                        profileProxyRequestStartedNanos = 0L;
                        writeEvent("bluetooth_hid_profile_connected",
                                "profile=" + profile
                                        + " expected_profile=" + BluetoothProfile.HID_DEVICE
                                        + " proxy_class=" + safeToken(proxy == null
                                        ? "null" : proxy.getClass().getName())
                                        + " foreground_session=" + foregroundSessionActive);
                        if (profile != BluetoothProfile.HID_DEVICE
                                || !(proxy instanceof BluetoothHidDevice)) {
                            profileProxyConnected = false;
                            hidDevice = null;
                            writeEvent("bluetooth_hid_profile_rejected",
                                    "reason=unexpected_profile profile=" + profile);
                            return;
                        }
                        hidDevice = (BluetoothHidDevice) proxy;
                        profileProxyConnected = true;
                        if (foregroundSessionActive) {
                            registerMouseAppIfProfileReady();
                            connectPreferredHostLocked();
                        }
                    }
                }

                @Override
                public void onServiceDisconnected(int profile) {
                    synchronized (AndroidBluetoothHidDeviceAdapter.this) {
                        if (profile != BluetoothProfile.HID_DEVICE) return;
                        writeEvent("bluetooth_hid_profile_disconnected",
                                "profile=" + profile
                                        + " app_registered=" + appRegistered
                                        + " host_connected=" + (connectedHost != null));
                        profileProxyConnected = false;
                        profileProxyRequested = false;
                        profileProxyRequestStartedNanos = 0L;
                        hidDevice = null;
                        connectedHost = null;
                        appRegistered = false;
                        registerAppAccepted = false;
                    }
                }
            };

    private final BluetoothHidDevice.Callback hidCallback =
            new BluetoothHidDevice.Callback() {
                @Override
                public void onAppStatusChanged(BluetoothDevice pluggedDevice, boolean registered) {
                    synchronized (AndroidBluetoothHidDeviceAdapter.this) {
                        registerAppRequestStartedNanos = 0L;
                        writeEvent("bluetooth_hid_app_status",
                                "registered=" + registered
                                        + " plugged_device_present=" + (pluggedDevice != null));
                        appRegistered = registered;
                        if (registered && pluggedDevice != null) {
                            connectedHost = pluggedDevice;
                            rememberHostLocked(pluggedDevice);
                            lastSendReportAccepted = true;
                        } else if (registered) {
                            connectPreferredHostLocked();
                        } else if (!registered) {
                            connectedHost = null;
                            registerAppAccepted = false;
                        }
                    }
                }

                @Override
                public void onConnectionStateChanged(BluetoothDevice device, int state) {
                    synchronized (AndroidBluetoothHidDeviceAdapter.this) {
                        writeEvent("bluetooth_hid_connection_state",
                                "state=" + stateName(state)
                                        + " device_present=" + (device != null));
                        if (state == BluetoothProfile.STATE_CONNECTED) {
                            connectedHost = device;
                            rememberHostLocked(device);
                            lastSendReportAccepted = true;
                        } else if (sameDevice(connectedHost, device)) {
                            connectedHost = null;
                            if (foregroundSessionActive && appRegistered) {
                                connectPreferredHostLocked();
                            }
                        }
                    }
                }
            };

    AndroidBluetoothHidDeviceAdapter(Context context) {
        this(context, context == null ? null : context.getMainExecutor(), null);
    }

    AndroidBluetoothHidDeviceAdapter(Context context, Executor callbackExecutor) {
        this(context, callbackExecutor, null);
    }

    AndroidBluetoothHidDeviceAdapter(
            Context context,
            Executor callbackExecutor,
            MobileRuntimeEventSink events) {
        if (context == null) throw new IllegalArgumentException("context");
        if (callbackExecutor == null) throw new IllegalArgumentException("callbackExecutor");
        this.appContext = context.getApplicationContext();
        this.callbackExecutor = callbackExecutor;
        this.events = events;
        preferences = appContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
    }

    public synchronized void setForegroundSessionActive(boolean active) {
        boolean sessionStateChanged = foregroundSessionActive != active;
        foregroundSessionActive = active;
        if (sessionStateChanged) {
            writeEvent("bluetooth_hid_foreground_session",
                    "active=" + active
                            + " profile_connected=" + profileProxyConnected
                            + " app_registered=" + appRegistered);
        }
        if (active) {
            registerBluetoothReceiverLocked();
            requestHidProfile();
            registerMouseAppIfProfileReady();
            connectPreferredHostLocked();
        } else if (sessionStateChanged) {
            unregisterMouseApp();
        }
    }

    @Override
    public synchronized BluetoothHidOutputFailClosedPolicy.SessionState sessionState() {
        boolean permissionGranted = hasBluetoothRuntimePermissions();
        boolean bluetoothEnabled = permissionGranted && isBluetoothEnabled();
        BluetoothDevice target = permissionGranted ? connectedHostLocked() : null;
        boolean hostConnected = target != null;
        BluetoothHidOutputFailClosedPolicy.SessionState cached = cachedSessionState;
        if (cached != null && cached.matches(
                hidDevice != null,
                permissionGranted,
                bluetoothEnabled,
                foregroundSessionActive,
                appRegistered,
                hostConnected,
                profileProxyConnected,
                lastSendReportAccepted)) {
            return cached;
        }
        cachedSessionState = new BluetoothHidOutputFailClosedPolicy.SessionState(
                hidDevice != null,
                permissionGranted,
                bluetoothEnabled,
                foregroundSessionActive,
                appRegistered,
                hostConnected,
                profileProxyConnected,
                lastSendReportAccepted);
        return cachedSessionState;
    }

    @Override
    public synchronized void connectFirstSupportedHost() {
        requestHidProfile();
        registerMouseAppIfProfileReady();
        connectPreferredHostLocked();
    }

    @Override
    @SuppressLint("MissingPermission")
    public synchronized boolean sendMouseReport(byte[] report) {
        if (report == null || report.length != 4 || !hasBluetoothRuntimePermissions()) {
            lastSendReportAccepted = false;
            writeEvent("bluetooth_hid_send_report",
                    "accepted=false reason=precondition report_length="
                            + (report == null ? -1 : report.length));
            return false;
        }
        BluetoothHidDevice targetHidDevice = hidDevice;
        BluetoothDevice target = connectedHostLocked();
        if (!foregroundSessionActive || !appRegistered || targetHidDevice == null
                || target == null) {
            lastSendReportAccepted = false;
            writeEvent("bluetooth_hid_send_report",
                    "accepted=false reason=session_not_ready foreground_session="
                            + foregroundSessionActive
                            + " app_registered=" + appRegistered
                            + " hid_device_present=" + (targetHidDevice != null)
                            + " host_connected=" + (target != null));
            return false;
        }
        try {
            lastSendReportAccepted = targetHidDevice.sendReport(target, 0, report.clone());
            if (lastSendReportAccepted) {
                recordAcceptedSendReportLocked();
            } else {
                writeEvent("bluetooth_hid_send_report",
                        "accepted=false reason=api_return");
            }
            return lastSendReportAccepted;
        } catch (SecurityException exception) {
            lastSendReportAccepted = false;
            writeEvent("bluetooth_hid_send_report",
                    "accepted=false reason=security_exception");
            return false;
        } catch (RuntimeException exception) {
            lastSendReportAccepted = false;
            writeEvent("bluetooth_hid_send_report",
                    "accepted=false reason=runtime_exception type="
                            + safeToken(exception.getClass().getSimpleName()));
            return false;
        }
    }

    @SuppressLint("MissingPermission")
    synchronized boolean requestHidProfile() {
        if (!hasBluetoothRuntimePermissions()) {
            writeEvent("bluetooth_hid_profile_request",
                    "requested=false reason=permission_missing");
            return false;
        }
        BluetoothAdapter adapter = bluetoothAdapter();
        if (adapter == null) {
            writeEvent("bluetooth_hid_profile_request",
                    "requested=false reason=adapter_missing");
            return false;
        }
        if (!adapter.isEnabled()) {
            writeEvent("bluetooth_hid_profile_request",
                    "requested=false reason=bluetooth_disabled");
            return false;
        }
        if (hidDevice != null) {
            writeEvent("bluetooth_hid_profile_request",
                    "requested=true reason=already_connected");
            return true;
        }
        if (profileProxyRequested) {
            long nowNanos = System.nanoTime();
            if (BluetoothHidPendingOperationPolicy.hasTimedOut(
                    true, profileProxyRequestStartedNanos, nowNanos)) {
                profileProxyRequested = false;
                profileProxyRequestStartedNanos = 0L;
                profileProxyConnected = false;
                writeEvent("bluetooth_hid_profile_request_timeout",
                        "recovered=true fail_closed=true automatic_retry=true");
            } else {
                writeEvent("bluetooth_hid_profile_request",
                        "requested=true reason=request_pending");
                return true;
            }
        }
        try {
            profileProxyRequested = adapter.getProfileProxy(
                    appContext, profileListener, BluetoothProfile.HID_DEVICE);
            profileProxyRequestStartedNanos = profileProxyRequested
                    ? System.nanoTime() : 0L;
            writeEvent("bluetooth_hid_profile_request",
                    "requested=" + profileProxyRequested + " reason=api_return");
            return profileProxyRequested;
        } catch (SecurityException exception) {
            profileProxyRequested = false;
            profileProxyRequestStartedNanos = 0L;
            writeEvent("bluetooth_hid_profile_request",
                    "requested=false reason=security_exception");
            return false;
        } catch (RuntimeException exception) {
            profileProxyRequested = false;
            profileProxyRequestStartedNanos = 0L;
            writeEvent("bluetooth_hid_profile_request",
                    "requested=false reason=runtime_exception type="
                            + safeToken(exception.getClass().getSimpleName()));
            return false;
        }
    }

    @SuppressLint("MissingPermission")
    synchronized boolean registerMouseAppIfProfileReady() {
        if (!foregroundSessionActive) {
            registerAppAccepted = false;
            writeEvent("bluetooth_hid_register_app",
                    "accepted=false reason=foreground_session_inactive");
            return false;
        }
        if (!hasBluetoothRuntimePermissions()) {
            registerAppAccepted = false;
            writeEvent("bluetooth_hid_register_app",
                    "accepted=false reason=permission_missing");
            return false;
        }
        if (hidDevice == null) {
            registerAppAccepted = false;
            writeEvent("bluetooth_hid_register_app",
                    "accepted=false reason=profile_proxy_missing");
            return false;
        }
        if (appRegistered) {
            registerAppRequestStartedNanos = 0L;
            writeEvent("bluetooth_hid_register_app",
                    "accepted=true reason=already_registered_or_pending"
                            + " app_registered=" + appRegistered
                            + " register_app_accepted=" + registerAppAccepted);
            return true;
        }
        if (registerAppAccepted) {
            long nowNanos = System.nanoTime();
            if (!BluetoothHidPendingOperationPolicy.hasTimedOut(
                    true, registerAppRequestStartedNanos, nowNanos)) {
                writeEvent("bluetooth_hid_register_app",
                        "accepted=true reason=already_registered_or_pending"
                                + " app_registered=false register_app_accepted=true");
                return true;
            }
            recoverTimedOutAppRegistrationLocked();
            return false;
        }
        BluetoothHidDeviceAppSdpSettings sdpSettings =
                new BluetoothHidDeviceAppSdpSettings(
                        "VF \u65e0\u7ebf\u9f20\u6807",
                        "\u65e0\u7ebf\u9f20\u6807\u8f93\u51fa",
                        "VF",
                        BluetoothHidDevice.SUBCLASS1_MOUSE,
                        MOUSE_REPORT_DESCRIPTOR);
        try {
            registerAppAccepted = hidDevice.registerApp(
                    sdpSettings,
                    null,
                    null,
                    callbackExecutor,
                    hidCallback);
            registerAppRequestStartedNanos = registerAppAccepted
                    ? System.nanoTime() : 0L;
            writeEvent("bluetooth_hid_register_app",
                    "accepted=" + registerAppAccepted + " reason=api_return");
            if (!registerAppAccepted) {
                appRegistered = false;
            }
            return registerAppAccepted;
        } catch (SecurityException exception) {
            registerAppAccepted = false;
            registerAppRequestStartedNanos = 0L;
            appRegistered = false;
            writeEvent("bluetooth_hid_register_app",
                    "accepted=false reason=security_exception");
            return false;
        } catch (RuntimeException exception) {
            registerAppAccepted = false;
            registerAppRequestStartedNanos = 0L;
            appRegistered = false;
            writeEvent("bluetooth_hid_register_app",
                    "accepted=false reason=runtime_exception type="
                            + safeToken(exception.getClass().getSimpleName()));
            return false;
        }
    }

    @SuppressLint("MissingPermission")
    synchronized void unregisterMouseApp() {
        boolean registrationMayBeActive = appRegistered || registerAppAccepted;
        appRegistered = false;
        registerAppAccepted = false;
        registerAppRequestStartedNanos = 0L;
        connectedHost = null;
        if (!registrationMayBeActive) {
            writeEvent("bluetooth_hid_unregister_app",
                    "requested=false reason=not_registered");
            return;
        }
        if (hidDevice == null || !hasBluetoothRuntimePermissions()) {
            writeEvent("bluetooth_hid_unregister_app",
                    "requested=false reason=profile_or_permission_missing");
            return;
        }
        try {
            boolean accepted = hidDevice.unregisterApp();
            writeEvent("bluetooth_hid_unregister_app",
                    "requested=true accepted=" + accepted);
        } catch (SecurityException ignored) {
            writeEvent("bluetooth_hid_unregister_app",
                    "requested=true accepted=false reason=security_exception");
        } catch (RuntimeException exception) {
            writeEvent("bluetooth_hid_unregister_app",
                    "requested=true accepted=false reason=runtime_exception type="
                            + safeToken(exception.getClass().getSimpleName()));
            // State is already fail-closed locally.
        }
    }

    synchronized boolean wasProfileProxyRequested() {
        return profileProxyRequested;
    }

    synchronized boolean wasRegisterAppAccepted() {
        return registerAppAccepted;
    }

    @Override
    @SuppressLint("MissingPermission")
    public synchronized void close() {
        unregisterMouseApp();
        unregisterBluetoothReceiverLocked();
        BluetoothAdapter adapter = bluetoothAdapter();
        if (adapter != null && hidDevice != null) {
            try {
                adapter.closeProfileProxy(BluetoothProfile.HID_DEVICE, hidDevice);
            } catch (SecurityException ignored) {
                // Local state is cleared below.
            }
        }
        hidDevice = null;
        connectedHost = null;
        profileProxyConnected = false;
        profileProxyRequested = false;
        profileProxyRequestStartedNanos = 0L;
        registerAppRequestStartedNanos = 0L;
        writeEvent("bluetooth_hid_adapter_closed", "closed=true");
    }

    @SuppressLint("MissingPermission")
    private void recoverTimedOutAppRegistrationLocked() {
        BluetoothHidDevice targetHidDevice = hidDevice;
        registerAppAccepted = false;
        registerAppRequestStartedNanos = 0L;
        appRegistered = false;
        connectedHost = null;
        lastSendReportAccepted = false;
        boolean unregisterAccepted = false;
        String failureDetail = "none";
        if (targetHidDevice != null && hasBluetoothRuntimePermissions()) {
            try {
                unregisterAccepted = targetHidDevice.unregisterApp();
            } catch (RuntimeException failure) {
                failureDetail = MobileThrowableDiagnostics.format(failure);
            }
        }
        writeEvent("bluetooth_hid_register_app_timeout",
                "recovered=true fail_closed=true automatic_retry=true"
                        + " unregister_accepted=" + unregisterAccepted
                        + " failure={" + failureDetail + "}");
    }

    @SuppressLint("MissingPermission")
    private BluetoothDevice connectedHostLocked() {
        if (connectedHost != null) return connectedHost;
        if (hidDevice == null || !hasBluetoothRuntimePermissions()) return null;
        try {
            List<BluetoothDevice> connectedDevices = hidDevice.getConnectedDevices();
            if (!connectedDevices.isEmpty()) {
                connectedHost = connectedDevices.get(0);
                rememberHostLocked(connectedHost);
            }
            return connectedHost;
        } catch (SecurityException exception) {
            return null;
        }
    }

    private boolean hasBluetoothRuntimePermissions() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return true;
        return appContext.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                == PackageManager.PERMISSION_GRANTED
                && appContext.checkSelfPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
                == PackageManager.PERMISSION_GRANTED;
    }

    @SuppressLint("MissingPermission")
    private boolean isBluetoothEnabled() {
        BluetoothAdapter adapter = bluetoothAdapter();
        if (adapter == null) return false;
        try {
            return adapter.isEnabled();
        } catch (SecurityException exception) {
            return false;
        }
    }

    private BluetoothAdapter bluetoothAdapter() {
        BluetoothManager manager = appContext.getSystemService(BluetoothManager.class);
        return manager == null ? null : manager.getAdapter();
    }

    @SuppressLint("MissingPermission")
    private boolean connectPreferredHostLocked() {
        if (!foregroundSessionActive || !appRegistered || hidDevice == null
                || !hasBluetoothRuntimePermissions()) {
            return false;
        }
        BluetoothDevice target = findPreferredHostLocked();
        return target != null && connectHostLocked(target);
    }

    @SuppressLint("MissingPermission")
    private BluetoothDevice findPreferredHostLocked() {
        BluetoothAdapter adapter = bluetoothAdapter();
        if (adapter == null) return null;
        Set<BluetoothDevice> bondedDevices;
        try {
            bondedDevices = adapter.getBondedDevices();
        } catch (SecurityException exception) {
            return null;
        }
        String preferredAddress = preferences.getString(KEY_PREFERRED_HOST, "");
        for (BluetoothDevice device : bondedDevices) {
            if (device != null && preferredAddress.equals(device.getAddress())) return device;
        }
        BluetoothDevice onlyComputer = null;
        for (BluetoothDevice device : bondedDevices) {
            if (device == null || !isComputer(device)) continue;
            if (onlyComputer != null) return null;
            onlyComputer = device;
        }
        return onlyComputer;
    }

    @SuppressLint("MissingPermission")
    private boolean connectHostLocked(BluetoothDevice target) {
        if (target == null || hidDevice == null || !appRegistered
                || !hasBluetoothRuntimePermissions()) {
            return false;
        }
        long nowNanos = System.nanoTime();
        if (nowNanos < nextConnectAttemptNanos) return false;
        nextConnectAttemptNanos = nowNanos + CONNECT_RETRY_NANOS;
        try {
            int state = hidDevice.getConnectionState(target);
            if (state == BluetoothProfile.STATE_CONNECTED) {
                connectedHost = target;
                lastSendReportAccepted = true;
                rememberHostLocked(target);
                return true;
            }
            if (state == BluetoothProfile.STATE_CONNECTING) return true;
            boolean accepted = hidDevice.connect(target);
            writeEvent("bluetooth_hid_host_connect",
                    "accepted=" + accepted + " bonded="
                            + (target.getBondState() == BluetoothDevice.BOND_BONDED));
            return accepted;
        } catch (SecurityException exception) {
            writeEvent("bluetooth_hid_host_connect",
                    "accepted=false reason=security_exception");
            return false;
        } catch (RuntimeException exception) {
            writeEvent("bluetooth_hid_host_connect",
                    "accepted=false reason=runtime_exception type="
                            + safeToken(exception.getClass().getSimpleName()));
            return false;
        }
    }

    @SuppressLint("MissingPermission")
    private static boolean isComputer(BluetoothDevice device) {
        try {
            BluetoothClass bluetoothClass = device.getBluetoothClass();
            return bluetoothClass != null
                    && bluetoothClass.getMajorDeviceClass()
                    == BluetoothClass.Device.Major.COMPUTER;
        } catch (SecurityException exception) {
            return false;
        }
    }

    @SuppressLint("MissingPermission")
    private void rememberHostLocked(BluetoothDevice device) {
        if (device == null || !hasBluetoothRuntimePermissions()) return;
        try {
            String address = device.getAddress();
            if (BluetoothAdapter.checkBluetoothAddress(address)) {
                preferences.edit().putString(KEY_PREFERRED_HOST, address).apply();
            }
        } catch (SecurityException ignored) {
            // The current session remains connected; persistence is best effort.
        }
    }

    private void recordAcceptedSendReportLocked() {
        acceptedSendReportCount++;
        long nowNanos = System.nanoTime();
        if (acceptedSendReportCount > 1L && nowNanos < nextAcceptedSendReportLogNanos) return;
        nextAcceptedSendReportLogNanos = nowNanos + SEND_REPORT_SUCCESS_LOG_INTERVAL_NANOS;
        writeEvent("bluetooth_hid_send_report",
                "accepted=true reason=api_return accepted_total="
                        + acceptedSendReportCount + " logging=rate_limited");
    }

    private void registerBluetoothReceiverLocked() {
        if (receiverRegistered) return;
        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        filter.addAction(BluetoothAdapter.ACTION_STATE_CHANGED);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                appContext.registerReceiver(
                        bluetoothReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
            } else {
                appContext.registerReceiver(bluetoothReceiver, filter);
            }
            receiverRegistered = true;
        } catch (RuntimeException failure) {
            writeEvent("bluetooth_hid_receiver_register_failed",
                    "failure_type=" + safeToken(failure.getClass().getSimpleName()));
        }
    }

    private void unregisterBluetoothReceiverLocked() {
        if (!receiverRegistered) return;
        try {
            appContext.unregisterReceiver(bluetoothReceiver);
        } catch (IllegalArgumentException ignored) {
            // Android can race receiver cleanup during process teardown.
        }
        receiverRegistered = false;
    }

    private static boolean sameDevice(BluetoothDevice left, BluetoothDevice right) {
        if (left == right) return true;
        if (left == null || right == null) return false;
        return left.getAddress().equals(right.getAddress());
    }

    private void writeEvent(String event, String detail) {
        if (events != null) {
            events.write(event, detail);
        }
    }

    private static String stateName(int state) {
        switch (state) {
            case BluetoothProfile.STATE_CONNECTED:
                return "connected";
            case BluetoothProfile.STATE_CONNECTING:
                return "connecting";
            case BluetoothProfile.STATE_DISCONNECTING:
                return "disconnecting";
            case BluetoothProfile.STATE_DISCONNECTED:
                return "disconnected";
            default:
                return "unknown_" + state;
        }
    }

    private static String safeToken(String value) {
        if (value == null || value.isBlank()) return "unspecified";
        return value.replace(' ', '_').replace('\r', '_').replace('\n', '_');
    }
}
