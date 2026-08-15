package com.visionforge.inferencebenchmark;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.Uri;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.SystemClock;
import android.view.WindowManager;

import com.visionforge.inferencebenchmark.ui.ControlPreset;
import com.visionforge.inferencebenchmark.ui.DualMachineAuthorizationUiState;
import com.visionforge.inferencebenchmark.ui.MobileAppActions;
import com.visionforge.inferencebenchmark.ui.MobileAppShell;
import com.visionforge.inferencebenchmark.ui.MobileDestination;
import com.visionforge.inferencebenchmark.ui.MobileUiState;
import com.visionforge.inferencebenchmark.ui.MobileUiStateMapper;
import com.visionforge.inferencebenchmark.ui.UiPreviewState;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Composition root for the Android half of the dual-machine architecture.
 *
 * <p>Lifecycle and dependency wiring stay here. Screen construction, native
 * report interpretation, hardware ownership and business transitions remain
 * behind their dedicated boundaries.</p>
 */
public final class MainActivity extends Activity implements MobileAppActions {
    private static final long ACTIVE_STATUS_REFRESH_MILLIS = 250L;
    private static final long IDLE_STATUS_REFRESH_MILLIS = 1_500L;
    private static final long STATUS_NOTE_TTL_MILLIS = 8_000L;
    private static final int DETECTION_TRACE_FRAME_COUNT = 120;
    private static final int NOTIFICATION_PERMISSION_REQUEST_CODE = 1701;
    private static final int PERSONAL_TRAJECTORY_DOCUMENT_REQUEST_CODE = 1702;
    private static final int BLUETOOTH_HID_PERMISSION_REQUEST_CODE = 1703;
    private static final int BLUETOOTH_HID_ENABLE_REQUEST_CODE = 1704;
    private static final int BLUETOOTH_HID_DISCOVERABLE_REQUEST_CODE = 1705;
    private static final int RUNTIME_LOG_DOCUMENT_REQUEST_CODE = 1706;
    private static final int BLUETOOTH_HID_DISCOVERABLE_SECONDS = 300;
    private static final int MAXIMUM_PERSONAL_PROFILE_BYTES = 256 * 1024;
    private static final String STATE_DESTINATION = "visionforge.selected_destination";
    private static final String EXTRA_DIAGNOSTIC_ACTION = "com.visionforge.mobile.diagnostic.action";
    private static final String EXTRA_TRACE_FRAME_COUNT = "com.visionforge.mobile.diagnostic.trace_frame_count";
    private static final String EXTRA_DEBUG_MOVE_DX =
            "com.visionforge.mobile.diagnostic.bluetooth_hid_move_dx";
    private static final String EXTRA_DEBUG_MOVE_DY =
            "com.visionforge.mobile.diagnostic.bluetooth_hid_move_dy";
    private static final String EXTRA_DEBUG_MOVE_REPORTS =
            "com.visionforge.mobile.diagnostic.bluetooth_hid_move_reports";
    private static final String EXTRA_DEBUG_MOVE_INTERVAL_MS =
            "com.visionforge.mobile.diagnostic.bluetooth_hid_move_interval_ms";
    private static final String DIAGNOSTIC_BEGIN_TRACE = "begin_detection_trace";
    private static final String DIAGNOSTIC_EXPORT_TRACE = "export_detection_trace";
    private static final String DIAGNOSTIC_BLUETOOTH_HID_MOVE_PROBE =
            "bluetooth_hid_move_probe";
    private static final String DIAGNOSTIC_BLUETOOTH_HID_SELECT_ROUTE =
            "bluetooth_hid_select_route";
    // Debug-only UI preview entry. Honour these extras only when the installed
    // package is debuggable; release builds never expose a runtime-free path.
    private static final String EXTRA_UI_PREVIEW_ONLY =
            "com.visionforge.mobile.extra.UI_PREVIEW_ONLY";
    private static final String EXTRA_UI_PREVIEW_DESTINATION =
            "com.visionforge.mobile.extra.UI_PREVIEW_DESTINATION";
    private static final String EXIT_GUIDANCE_PREFERENCES =
            "visionforge_exit_guidance_v1";
    private static final String LAST_TASK_CLEAN_GUIDANCE_TIMESTAMP =
            "last_task_clean_timestamp";

    private MobileEventLogger eventLogger;
    private MobileControlRuntime controlRuntime;
    private MobileDetectionTraceCoordinator detectionTraceCoordinator;
    private BackgroundExecutionPolicy backgroundExecutionPolicy;
    private NotificationExecutionPolicy notificationExecutionPolicy;
    private BluetoothHidPermissionPolicy bluetoothHidPermissionPolicy;
    private MobilePreviousExitInspector.Result previousExit =
            MobilePreviousExitInspector.Result.none();
    private MobileAppShell appShell;
    private MobileUiState latestUiState;
    private String latestNote = "";
    private long latestNoteElapsedMillis;
    private long lastRuntimeStatusRevision = -1L;
    private MobileRuntimeService.Phase lastRuntimeStatusPhase;
    private DualMachineAuthorizationUiState authorizationUiState =
            DualMachineAuthorizationUiState.readyForActivation();
    private boolean backgroundPolicyDialogShown;
    private boolean notificationPolicyDialogShown;
    private boolean lastBatteryOptimizationExempt;
    private boolean lastNotificationPermissionGranted;
    private boolean uiPreviewOnly;
    private boolean activityStarted;
    private volatile boolean activityDestroyed;
    private MobileRuntimeService.LocalBinder runtimeBinder;
    private boolean runtimeServiceBound;

    private final ServiceConnection runtimeServiceConnection =
            new ServiceConnection() {
                @Override
                public void onServiceConnected(
                        ComponentName name, IBinder service) {
                    if (!(service instanceof
                            MobileRuntimeService.LocalBinder)) {
                        onRuntimeServiceUnavailable(
                                "unexpected_runtime_binder");
                        return;
                    }
                    runtimeBinder =
                            (MobileRuntimeService.LocalBinder) service;
                    runtimeServiceBound = true;
                    runtimeBinder.setActivityForeground(activityStarted);
                    runtimeBinder.setAuthorizationObserver(
                            MainActivity.this::onAuthorizationChanged);
                    authorizationUiState =
                            runtimeBinder.authorizationState();
                    refreshStates("");
                }

                @Override
                public void onServiceDisconnected(ComponentName name) {
                    onRuntimeServiceUnavailable(
                            "runtime_service_disconnected");
                }

                @Override
                public void onBindingDied(ComponentName name) {
                    onRuntimeServiceUnavailable(
                            "runtime_service_binding_died");
                }

                @Override
                public void onNullBinding(ComponentName name) {
                    onRuntimeServiceUnavailable(
                            "runtime_service_null_binding");
                }
            };

    private final MobileThroughputTracker throughputTracker = new MobileThroughputTracker();
    private final MobileRuntimeMetricsSampler metricsSampler = new MobileRuntimeMetricsSampler();
    private final Set<String> nativeReportFailures = new HashSet<>();
    private final Handler stateRefreshHandler = new Handler(Looper.getMainLooper());
    private final Runnable stateRefreshTask = new Runnable() {
        @Override
        public void run() {
            refreshStates("");
            stateRefreshHandler.postDelayed(this, nextStatusRefreshDelayMillis());
        }
    };

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        uiPreviewOnly = isUiPreviewRequest(getIntent());
        if (!uiPreviewOnly) {
            // Android 14+ replaces the legacy high-performance Wi-Fi lock
            // with a low-latency lock that is effective only while the
            // display is interactive. Keep the visible runtime screen awake
            // so normal unattended inference cannot silently lose WLAN.
            getWindow().addFlags(
                    WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            initialiseRuntimeDependencies();
        }
        appShell = new MobileAppShell(this, this);
        if (savedInstanceState != null) {
            appShell.restoreDestination(destinationFrom(savedInstanceState.getString(STATE_DESTINATION)));
        } else if (uiPreviewOnly) {
            appShell.restoreDestination(destinationFrom(
                    getIntent().getStringExtra(EXTRA_UI_PREVIEW_DESTINATION)));
        }
        setContentView(appShell.view());
        if (uiPreviewOnly) {
            // Pure UI preview: render a fixed UI-layer state and return before
            // any service, QNN, MediaCodec, UDP, USB or wakelock is touched.
            latestUiState = UiPreviewState.disconnected();
            appShell.render(latestUiState);
            return;
        }
        MobileRuntimeService.ensureRunning(this);
        if (!showTaskCleanedGuidanceIfNeeded()) {
            requestRequiredRuntimePolicies();
        }
        // Discovery starts immediately. Output is still fail-closed until the
        // full video/QNN runtime and the MAKCU protocol identity are healthy.
        controlRuntime.ensureSelectedOutputConnected();
        String diagnosticNote = handleDiagnosticIntent(getIntent());
        refreshStates(diagnosticNote == null
                ? getString(R.string.status_waiting_ethernet) : diagnosticNote);
    }

    private boolean isUiPreviewRequest(Intent intent) {
        return intent != null
                && intent.getBooleanExtra(EXTRA_UI_PREVIEW_ONLY, false)
                && isDebuggableBuild();
    }

    private boolean isDebuggableBuild() {
        return (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

    private void initialiseRuntimeDependencies() {
        eventLogger = new MobileEventLogger(this);
        controlRuntime = MobileControlRuntime.get(this);
        eventLogger.write("mobile_inference_profile_applied",
                controlRuntime.inferenceAuditDetail());
        detectionTraceCoordinator = new MobileDetectionTraceCoordinator(
                new QnnNativeDetectionTracePort(), eventLogger,
                new File(getExternalFilesDir(null), "diagnostics"));
        backgroundExecutionPolicy = new BackgroundExecutionPolicy(this);
        notificationExecutionPolicy = new NotificationExecutionPolicy(this);
        bluetoothHidPermissionPolicy = new BluetoothHidPermissionPolicy(this);
        previousExit = MobilePreviousExitInspector.inspect(this);
        lastBatteryOptimizationExempt = backgroundExecutionPolicy.isExempt();
        lastNotificationPermissionGranted = notificationExecutionPolicy.isGranted();
        eventLogger.write("mobile_power_policy", backgroundExecutionPolicy.auditDetail());
        eventLogger.write("mobile_notification_policy", notificationExecutionPolicy.auditDetail());
        eventLogger.write("mobile_bluetooth_hid_permission_policy",
                bluetoothHidPermissionPolicy.auditDetail());
        eventLogger.write("mobile_previous_process_exit", previousExit.detail());
        eventLogger.write("mobile_app_started",
                "control_gate=automatic_fail_closed ui=inference_navigation_v1");
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        String diagnosticNote = handleDiagnosticIntent(intent);
        if (diagnosticNote != null) refreshStates(diagnosticNote);
    }

    private String handleDiagnosticIntent(Intent intent) {
        if (intent == null || detectionTraceCoordinator == null) return null;
        String action = intent.getStringExtra(EXTRA_DIAGNOSTIC_ACTION);
        if (DIAGNOSTIC_BEGIN_TRACE.equals(action)) {
            int frames = intent.getIntExtra(EXTRA_TRACE_FRAME_COUNT, DETECTION_TRACE_FRAME_COUNT);
            return detectionTraceCoordinator.begin(frames).message;
        } else if (DIAGNOSTIC_EXPORT_TRACE.equals(action)) {
            return detectionTraceCoordinator.export().message;
        } else if (DIAGNOSTIC_BLUETOOTH_HID_MOVE_PROBE.equals(action)) {
            return requestDebugBluetoothHidMoveProbe(intent);
        } else if (DIAGNOSTIC_BLUETOOTH_HID_SELECT_ROUTE.equals(action)) {
            return requestDebugBluetoothHidRouteSelection();
        }
        return null;
    }

    private String requestDebugBluetoothHidRouteSelection() {
        if (!isDebuggableBuild()) {
            eventLogger.write("mobile_control_bluetooth_hid_route_probe_request",
                    "accepted=false reason=debug_disabled");
            return "Bluetooth HID route probe is disabled";
        }
        eventLogger.write("mobile_control_bluetooth_hid_route_probe_request",
                "accepted=true");
        MobileRuntimeService.LocalBinder binder = runtimeBinder;
        if (binder != null) {
            selectBluetoothHidOutputRoute(false);
            return "Bluetooth HID route probe scheduled";
        }
        if (controlRuntime == null) {
            eventLogger.write("mobile_control_bluetooth_hid_route_probe_request",
                    "accepted=false reason=runtime_unavailable");
            return "Bluetooth HID route probe runtime unavailable";
        }
        if (!controlRuntime.isBluetoothHidOutputRouteAvailable()) {
            eventLogger.write("mobile_control_bluetooth_hid_route_probe_request",
                    "accepted=false reason=capability_not_verified");
            refreshStates(getString(R.string.status_output_route_bluetooth_unavailable));
            return "Bluetooth HID route probe unavailable";
        }
        if (!bluetoothHidPermissionPolicy.isGranted()) {
            eventLogger.write("mobile_control_bluetooth_hid_route_probe_request",
                    "accepted=false reason=permission_missing");
            refreshStates(getString(
                    R.string.status_output_route_bluetooth_permission_requested));
            return "Bluetooth HID route probe permission missing";
        }
        String reason = controlRuntime.selectOutputRoute(
                ControlOutputRoute.BLUETOOTH_HID);
        eventLogger.write("mobile_control_bluetooth_hid_route_probe_result",
                "path=control_runtime_debug_fallback reason=" + safeToken(reason));
        refreshStates(getString(R.string.status_output_route_bluetooth_requested));
        return "Bluetooth HID route probe scheduled";
    }

    private String requestDebugBluetoothHidMoveProbe(Intent intent) {
        if (!isDebuggableBuild()) {
            eventLogger.write("mobile_control_bluetooth_hid_move_probe_request",
                    "accepted=false reason=debug_disabled");
            return "Bluetooth HID move probe is disabled";
        }
        MobileRuntimeService.LocalBinder binder = runtimeBinder;
        if (binder == null && controlRuntime == null) {
            eventLogger.write("mobile_control_bluetooth_hid_move_probe_request",
                    "accepted=false reason=runtime_binder_missing");
            return "Bluetooth HID move probe binder missing";
        }
        int deltaX = intent.getIntExtra(EXTRA_DEBUG_MOVE_DX, 1);
        int deltaY = intent.getIntExtra(EXTRA_DEBUG_MOVE_DY, 0);
        int reports = intent.getIntExtra(EXTRA_DEBUG_MOVE_REPORTS, 4);
        int intervalMillis = intent.getIntExtra(EXTRA_DEBUG_MOVE_INTERVAL_MS, 30);
        BluetoothHidDebugMoveProbePolicy.Request request =
                BluetoothHidDebugMoveProbePolicy.sanitize(
                        deltaX, deltaY, reports, intervalMillis);
        eventLogger.write("mobile_control_bluetooth_hid_move_probe_request",
                "accepted=" + request.hasMovement
                        + " dx=" + request.deltaX
                        + " dy=" + request.deltaY
                        + " reports=" + request.reports
                        + " interval_ms=" + request.intervalMillis);
        if (!request.hasMovement) {
            return "Bluetooth HID move probe rejected";
        }
        if (binder != null) {
            binder.runDebugBluetoothHidMoveProbe(
                    request.deltaX,
                    request.deltaY,
                    request.reports,
                    request.intervalMillis);
        } else {
            String result = controlRuntime.runDebugBluetoothHidMoveProbe(
                    request.deltaX,
                    request.deltaY,
                    request.reports,
                    request.intervalMillis);
            eventLogger.write("mobile_control_bluetooth_hid_move_probe",
                    "path=control_runtime_debug_fallback " + safeToken(result));
        }
        return "Bluetooth HID move probe scheduled";
    }

    private static String safeToken(String value) {
        if (value == null || value.isBlank()) return "unspecified";
        return value.replace(' ', '_').replace('\r', '_').replace('\n', '_');
    }

    @Override
    public void onDestinationSelected(MobileDestination destination) {
        if (eventLogger == null) return;
        eventLogger.write("mobile_navigation_changed", "destination="
                + destination.name().toLowerCase(Locale.ROOT));
    }

    @Override
    public void onActivateCard(String cardCode) {
        if (uiPreviewOnly) return;
        MobileRuntimeService.LocalBinder binder = runtimeBinder;
        if (binder == null) {
            onRuntimeServiceUnavailable("activate_without_runtime_binder");
            return;
        }
        binder.activateCard(cardCode);
    }

    @Override
    public void onResumePendingActivation() {
        if (uiPreviewOnly) return;
        MobileRuntimeService.LocalBinder binder = runtimeBinder;
        if (binder == null) {
            onRuntimeServiceUnavailable("resume_without_runtime_binder");
            return;
        }
        binder.resumePendingActivation();
    }

    @Override
    public void onRetryOutputDevice() {
        if (uiPreviewOnly) return;
        if (controlRuntime.isBluetoothHidOutputRouteActive()
                && !controlRuntime.isBluetoothHidSessionReady()) {
            selectBluetoothHidOutputRoute(true);
            return;
        }
        controlRuntime.ensureSelectedOutputConnected();
        refreshStates(getString(R.string.status_retrying_output_device));
    }

    @Override
    public void onSelectMakcuOutputRoute() {
        if (uiPreviewOnly) return;
        MobileRuntimeService.LocalBinder binder = runtimeBinder;
        if (binder == null) {
            controlRuntime.failClosed("output_route_makcu_without_runtime_binder");
            onRuntimeServiceUnavailable("output_route_makcu_without_runtime_binder");
            return;
        }
        binder.selectOutputRoute(ControlOutputRoute.MAKCU_USB.storageToken);
        refreshStates(getString(R.string.status_output_route_makcu_selected));
    }

    @Override
    public void onSelectBluetoothHidOutputRoute() {
        selectBluetoothHidOutputRoute(true);
    }

    @Override
    public void onSelectGameModel(MobileModelCatalog.Profile model) {
        if (uiPreviewOnly || model == null) return;
        MobileRuntimeService.LocalBinder binder = runtimeBinder;
        if (binder == null) {
            controlRuntime.failClosed("game_model_switch_without_runtime_binder");
            refreshStates(getString(R.string.status_model_switch_unavailable));
            return;
        }
        binder.selectGameModel(model.token);
        refreshStates(getString(R.string.status_model_switch_requested));
    }

    @Override
    public void onSetAimTarget(MobileAimTarget target) {
        if (uiPreviewOnly || target == null) return;
        controlRuntime.setAimTarget(target);
        refreshStates(getString(R.string.status_aim_target_adjusted));
    }

    @Override
    public void onSetInferenceConfidence(float confidence) {
        if (uiPreviewOnly) return;
        controlRuntime.setConfidence(confidence);
        refreshStates(getString(R.string.status_confidence_adjusted,
                controlRuntime.confidence()));
    }

    @Override
    public void onSetControlGain(float gain) {
        if (uiPreviewOnly) return;
        controlRuntime.setControlGain(gain);
        refreshStates(getString(R.string.status_gain_adjusted,
                controlRuntime.controlGain()));
    }

    @Override
    public void onSetControlDeadzone(float deadzonePixels) {
        if (uiPreviewOnly) return;
        controlRuntime.setControlDeadzone(deadzonePixels);
        refreshStates(getString(R.string.status_deadzone_adjusted,
                controlRuntime.controlDeadzonePixels()));
    }

    @Override
    public void onSetMaximumAxisDelta(int maximumAxisDelta) {
        if (uiPreviewOnly) return;
        controlRuntime.setMaximumAxisDelta(maximumAxisDelta);
        refreshStates(getString(R.string.status_max_axis_adjusted,
                controlRuntime.maximumAxisDelta()));
    }

    @Override
    public void onSetSwitchConfirmationMillis(int switchConfirmationMillis) {
        if (uiPreviewOnly) return;
        controlRuntime.setSwitchConfirmationMillis(switchConfirmationMillis);
        refreshStates(getString(R.string.status_switch_confirmation_adjusted,
                controlRuntime.switchConfirmationMillis()));
    }

    @Override
    public void onApplyControlPreset(ControlPreset preset) {
        if (uiPreviewOnly) return;
        if (preset == null || !preset.hasValues()) {
            refreshStates(getString(R.string.status_custom_adjustment));
            return;
        }
        MobileModelCatalog.Profile model = controlRuntime.activeModel();
        com.visionforge.inferencebenchmark.MobileControlTuning.Values values =
                preset.valuesFor(model);
        controlRuntime.setConfidence(model.defaultConfidence);
        controlRuntime.setControlProfile(values.gain, values.deadzonePixels,
                values.maximumAxisDelta, values.switchConfirmationMillis);
        eventLogger.write("mobile_control_preset_applied", "preset="
                + preset.name().toLowerCase(Locale.ROOT) + " model=" + model.token
                + " gain=" + values.gain + " deadzone_px=" + values.deadzonePixels
                + " maximum_axis_delta=" + values.maximumAxisDelta
                + " switch_confirmation_ms=" + values.switchConfirmationMillis
                + " output_enabled="
                + controlRuntime.isOutputEnabled());
        int presetLabel = preset == ControlPreset.STANDARD
                ? R.string.preset_standard : R.string.preset_precise;
        refreshStates(getString(R.string.status_preset_applied, getString(presetLabel)));
    }

    @Override
    public void onRestoreControlDefaults() {
        onApplyControlPreset(ControlPreset.STANDARD);
    }

    @Override
    public void onSetControlTrigger(ControlTrigger trigger) {
        if (uiPreviewOnly) return;
        controlRuntime.setControlTrigger(trigger);
        refreshStates(getString(R.string.status_control_trigger_applied,
                triggerLabel(trigger)));
    }

    @Override
    public void onImportPersonalTrajectory() {
        if (uiPreviewOnly) return;
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/json");
        startActivityForResult(intent, PERSONAL_TRAJECTORY_DOCUMENT_REQUEST_CODE);
    }

    @Override
    public void onSetPersonalTrajectoryEnabled(boolean enabled) {
        if (uiPreviewOnly) return;
        controlRuntime.setPersonalTrajectoryEnabled(enabled);
        refreshStates(getString(enabled
                ? R.string.status_personal_trajectory_enabled
                : R.string.status_personal_trajectory_disabled));
    }

    @Override
    public void onSetPersonalTrajectorySpeed(float speedScale) {
        if (uiPreviewOnly) return;
        controlRuntime.setPersonalTrajectoryScales(
                speedScale,
                controlRuntime.personalTrajectoryStabilityScale(),
                controlRuntime.personalTrajectoryVariationScale());
        refreshStates(getString(R.string.status_personal_speed_adjusted, speedScale));
    }

    @Override
    public void onSetPersonalTrajectoryStability(float stabilityScale) {
        if (uiPreviewOnly) return;
        controlRuntime.setPersonalTrajectoryScales(
                controlRuntime.personalTrajectorySpeedScale(),
                stabilityScale,
                controlRuntime.personalTrajectoryVariationScale());
        refreshStates(getString(R.string.status_personal_stability_adjusted, stabilityScale));
    }

    @Override
    public void onSetPersonalTrajectoryVariation(float variationScale) {
        if (uiPreviewOnly) return;
        controlRuntime.setPersonalTrajectoryScales(
                controlRuntime.personalTrajectorySpeedScale(),
                controlRuntime.personalTrajectoryStabilityScale(),
                variationScale);
        refreshStates(getString(R.string.status_personal_variation_adjusted, variationScale));
    }

    @Override
    public void onExportRuntimeLog() {
        if (uiPreviewOnly || eventLogger == null) return;
        eventLogger.write("mobile_runtime_log_export_requested",
                "destination=system_document_picker sensitive_values_redacted=true");
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/x-ndjson")
                .putExtra(Intent.EXTRA_TITLE,
                        getString(R.string.runtime_log_export_filename));
        startActivityForResult(intent, RUNTIME_LOG_DOCUMENT_REQUEST_CODE);
    }

    private void onAuthorizationChanged(
            DualMachineAuthorizationUiState state,
            String note) {
        if (activityDestroyed || state == null) return;
        authorizationUiState = state;
        refreshStates(note);
    }

    private void onRuntimeServiceUnavailable(String reason) {
        runtimeBinder = null;
        authorizationUiState =
                DualMachineAuthorizationUiState.readyForActivation();
        if (controlRuntime != null) {
            controlRuntime.failClosed(reason);
        }
        if (eventLogger != null) {
            eventLogger.write(
                    "mobile_runtime_binding_unavailable",
                    "reason=" + reason + " data_plane_open=false");
        }
        if (!activityDestroyed && !uiPreviewOnly) {
            refreshStates(getString(
                    R.string.authorization_operation_failed));
        }
    }

    private void refreshStates(String note) {
        if (uiPreviewOnly) return;
        long monotonicMillis = SystemClock.elapsedRealtime();
        if (note != null && !note.trim().isEmpty()) {
            latestNote = note;
            latestNoteElapsedMillis = monotonicMillis;
        }
        String video = readNativeReport(
                "video_receiver", QnnHtpBridge::getNativeVideoReceiverReport);
        String decoder = readNativeReport(
                "mediacodec", QnnHtpBridge::getNativeH264DecoderReport);
        String qnn = readNativeReport(
                "qnn_htp", QnnHtpBridge::getNativeQnnRealtimeReport);
        String makcu = controlRuntime.makcuReport();
        MobileRuntimeSnapshot snapshot = MobileRuntimeSnapshot.from(video, decoder, qnn, makcu);
        MobileRuntimeService.RuntimeStatus runtimeStatus = MobileRuntimeService.status();
        String ethernetDiagnostics = MobileRuntimeService.ethernetDiagnostics();
        MobileRuntimeService.Phase previousRuntimeStatusPhase =
                lastRuntimeStatusPhase;
        boolean runtimeStatusChanged =
                runtimeStatus.revision != lastRuntimeStatusRevision;
        lastRuntimeStatusRevision = runtimeStatus.revision;
        lastRuntimeStatusPhase = runtimeStatus.phase;
        if (MobileRuntimePresentationUpdatePolicy.enteredPhase(
                runtimeStatusChanged,
                previousRuntimeStatusPhase == null
                        ? null : previousRuntimeStatusPhase.name(),
                runtimeStatus.phase.name(),
                MobileRuntimeService.Phase.RUNNING.name())) {
            latestNote = getString(R.string.status_pipeline_started);
            latestNoteElapsedMillis = monotonicMillis;
        } else if (runtimeStatusChanged
                && runtimeStatus.phase == MobileRuntimeService.Phase.FAILED) {
            latestNote = MobileRuntimeFailureMessagePolicy.classify(
                    runtimeStatus.failureCode)
                    == MobileRuntimeFailureMessagePolicy.Kind
                    .QNN_HTP_ARCHITECTURE_NOT_PACKAGED
                    ? getString(R.string.status_qnn_htp_architecture_not_packaged)
                    : getString(R.string.status_pipeline_start_failed, runtimeStatus.detail);
            latestNoteElapsedMillis = monotonicMillis;
        }
        MobileThroughputTracker.Rates rates = throughputTracker.update(
                snapshot.reassembledAccessUnits, snapshot.freshContentAccessUnits,
                snapshot.decoderAcceptedAccessUnits, snapshot.renderedFrameCount,
                snapshot.freshDecodedFrameCount, snapshot.qnnExecutionCount,
                monotonicMillis);
        String metricsEvent = metricsSampler.sampleIfDue(snapshot, monotonicMillis);
        if (metricsEvent != null) {
            eventLogger.write(
                    "mobile_pipeline_metrics",
                    controlRuntime.inferenceAuditDetail() + " " + metricsEvent);
        }
        MobileUiStateMapper.Input input = new MobileUiStateMapper.Input();
        input.receiverServiceReady = runtimeStatus.phase == MobileRuntimeService.Phase.READY
                || runtimeStatus.phase == MobileRuntimeService.Phase.STARTING
                || runtimeStatus.phase == MobileRuntimeService.Phase.RUNNING;
        input.receiverRunning = snapshot.receiverRunning;
        input.videoLinkLive = snapshot.videoLinkLive;
        input.decoderReady = snapshot.decoderReady;
        input.qnnReady = snapshot.qnnReady;
        input.makcuReady = snapshot.makcuReady;
        input.controlOutputEnabled = controlRuntime.isOutputEnabled();
        input.controlOutputRecoverySuspended =
                controlRuntime.isOutputRecoverySuspended();
        input.bluetoothHidOutputRouteActive =
                controlRuntime.isBluetoothHidOutputRouteActive();
        input.bluetoothHidOutputRouteAvailable =
                controlRuntime.isBluetoothHidOutputRouteAvailable();
        input.bluetoothHidSessionReady =
                controlRuntime.isBluetoothHidSessionReady();
        input.bluetoothHidPermissionGranted =
                bluetoothHidPermissionPolicy.isGranted();
        input.nativePostprocessApplied = controlRuntime.isNativePostprocessApplied();
        input.authorization = authorizationUiState;
        input.qnnRuntimeLabel = displayRuntimeLabel(snapshot.qnnRuntimeLabel);
        input.accessUnitFps = rates.freshContentFps;
        input.decodedFrameFps = rates.freshDecodedFrameFps;
        input.qnnFps = rates.qnnFps;
        input.preprocessP50 = snapshot.preprocessP50;
        input.qnnP50 = snapshot.qnnP50;
        input.qnnP95 = snapshot.qnnP95;
        input.decodeQueueP50 = snapshot.decodeQueueP50;
        input.preprocessP50Millis = snapshot.preprocessP50Millis;
        input.qnnP50Millis = snapshot.qnnP50Millis;
        input.inferenceTotalP50Millis = snapshot.inferenceTotalP50Millis;
        input.decodeQueueP50Millis = snapshot.decodeQueueP50Millis;
        input.completedAccessUnits = displayCount(snapshot.completedAccessUnits);
        input.renderedFrames = snapshot.renderedFrames;
        input.qnnExecutions = snapshot.qnnExecutions;
        input.qnnFailures = snapshot.qnnFailures;
        input.activeModel = controlRuntime.activeModel();
        input.aimTarget = controlRuntime.aimTarget();
        input.confidence = controlRuntime.confidence();
        input.nmsIou = controlRuntime.nmsIou();
        input.controlGain = controlRuntime.controlGain();
        input.controlDeadzonePixels = controlRuntime.controlDeadzonePixels();
        input.maximumAxisDelta = controlRuntime.maximumAxisDelta();
        input.switchConfirmationMillis = controlRuntime.switchConfirmationMillis();
        input.effectiveUncalibratedMaximumAxisDelta =
                snapshot.effectiveUncalibratedMaximumAxisDelta;
        input.maximumStepCountsPerTick = snapshot.maximumStepCountsPerTick;
        input.maximumJerkCountsPerTick2 = snapshot.maximumJerkCountsPerTick2;
        input.controlTrigger = controlRuntime.controlTrigger();
        input.controlTriggerPressed = controlRuntime.isControlTriggerPressed();
        input.controlTriggerStreamReady =
                controlRuntime.isControlTriggerStreamReady();
        input.personalTrajectoryEnabled =
                controlRuntime.personalTrajectoryEnabled();
        input.personalTrajectoryProfileId =
                controlRuntime.personalTrajectoryProfileId();
        input.personalTrajectorySpeedScale =
                controlRuntime.personalTrajectorySpeedScale();
        input.personalTrajectoryStabilityScale =
                controlRuntime.personalTrajectoryStabilityScale();
        input.personalTrajectoryVariationScale =
                controlRuntime.personalTrajectoryVariationScale();
        input.note = displayNote(monotonicMillis);
        input.ethernetDetail = ethernetStatusDetail(runtimeStatus, ethernetDiagnostics);
        MobileUiState nextUiState = MobileUiStateMapper.map(input);
        boolean presentationChanged = !nextUiState.equals(latestUiState);
        if (presentationChanged) appShell.render(nextUiState);
        latestUiState = nextUiState;
    }

    private long nextStatusRefreshDelayMillis() {
        MobileRuntimeService.RuntimeStatus runtimeStatus = MobileRuntimeService.status();
        if (runtimeStatus.phase == MobileRuntimeService.Phase.STARTING
                || runtimeStatus.phase == MobileRuntimeService.Phase.RUNNING) {
            return ACTIVE_STATUS_REFRESH_MILLIS;
        }
        return IDLE_STATUS_REFRESH_MILLIS;
    }

    private String readNativeReport(String component, NativeReportReader reader) {
        try {
            String report = reader.read();
            nativeReportFailures.remove(component);
            return report;
        } catch (RuntimeException | LinkageError failure) {
            String stack = MobileThrowableDiagnostics.format(failure);
            if (nativeReportFailures.add(component)) {
                eventLogger.write(
                        "mobile_ui_native_report_failure",
                        "component=" + component + " stack={" + stack + "}");
            }
            return "report_unavailable component=" + component + " stack={" + stack + "}";
        }
    }

    private String ethernetStatusDetail(
            MobileRuntimeService.RuntimeStatus runtimeStatus, String diagnostics) {
        if (containsDiagnostic(diagnostics, "accepted=true")) {
            return getString(R.string.connection_ethernet_waiting_host_detail);
        }
        if (containsDiagnostic(diagnostics, "present=false")) {
            return getString(R.string.connection_ethernet_missing_detail);
        }
        if (containsDiagnostic(diagnostics, "has_ipv4=false")
                || containsDiagnostic(diagnostics, "ip_address_missing")
                || containsDiagnostic(diagnostics, "link_addresses_empty")
                || containsDiagnostic(diagnostics, "android_network_unavailable")) {
            return getString(R.string.connection_ethernet_no_ipv4_detail);
        }
        if (containsDiagnostic(diagnostics, "ip_address_mismatch")
                || containsDiagnostic(diagnostics, "prefix_length_mismatch")
                || containsDiagnostic(diagnostics, "interface_name_mismatch")) {
            return getString(R.string.connection_ethernet_wrong_address_detail);
        }
        if (runtimeStatus.phase == MobileRuntimeService.Phase.STARTING
                || runtimeStatus.phase == MobileRuntimeService.Phase.FAILED) {
            return getString(R.string.status_waiting_ethernet);
        }
        return "";
    }

    private static boolean containsDiagnostic(String diagnostics, String marker) {
        return diagnostics != null && diagnostics.contains(marker);
    }

    private void requestRequiredRuntimePolicies() {
        if (notificationExecutionPolicy.requestIfRequired(
                NOTIFICATION_PERMISSION_REQUEST_CODE)) {
            eventLogger.write("mobile_notification_permission_request",
                    "system_dialog_launched=true");
            return;
        }
        if (!notificationExecutionPolicy.isGranted()) {
            showNotificationExecutionRequirement();
            return;
        }
        requestBackgroundExecutionExemptionIfNeeded();
    }

    private void showNotificationExecutionRequirement() {
        if (notificationPolicyDialogShown) return;
        notificationPolicyDialogShown = true;
        new AlertDialog.Builder(this)
                .setTitle(R.string.notification_execution_title)
                .setMessage(R.string.notification_execution_detail)
                .setPositiveButton(R.string.notification_execution_settings, (dialog, which) -> {
                    boolean launched = notificationExecutionPolicy.openSettings();
                    eventLogger.write("mobile_notification_settings_request",
                            "system_settings_launched=" + launched);
                    if (!launched) {
                        refreshStates(getString(R.string.notification_execution_unavailable));
                    }
                })
                .setNegativeButton(R.string.background_execution_later, (dialog, which) ->
                        eventLogger.write("mobile_notification_settings_request",
                                "operator_deferred=true"))
                .show();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions,
                                           int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == BLUETOOTH_HID_PERMISSION_REQUEST_CODE) {
            boolean granted = allPermissionsGranted(grantResults);
            eventLogger.write("mobile_bluetooth_hid_permission_result",
                    "granted=" + granted);
            if (granted) {
                selectBluetoothHidOutputRoute(false);
            } else {
                refreshStates(getString(
                        R.string.status_output_route_bluetooth_permission_denied));
            }
            return;
        }
        if (requestCode != NOTIFICATION_PERMISSION_REQUEST_CODE) return;
        boolean granted = grantResults.length > 0
                && grantResults[0] == PackageManager.PERMISSION_GRANTED;
        eventLogger.write("mobile_notification_permission_result",
                "granted=" + granted);
        MobileRuntimeService.requestPowerPolicyRefresh(this);
        lastNotificationPermissionGranted = granted;
        if (granted) requestBackgroundExecutionExemptionIfNeeded();
        else showNotificationExecutionRequirement();
    }

    private void selectBluetoothHidOutputRoute(boolean requestPermissionIfMissing) {
        if (uiPreviewOnly) return;
        if (!controlRuntime.isBluetoothHidOutputRouteAvailable()) {
            refreshStates(getString(R.string.status_output_route_bluetooth_unavailable));
            return;
        }
        if (!bluetoothHidPermissionPolicy.isGranted()) {
            if (requestPermissionIfMissing) {
                eventLogger.write("mobile_bluetooth_hid_permission_request",
                        "system_dialog_launched=true");
                bluetoothHidPermissionPolicy.request(BLUETOOTH_HID_PERMISSION_REQUEST_CODE);
            }
            refreshStates(getString(
                    R.string.status_output_route_bluetooth_permission_requested));
            return;
        }
        MobileRuntimeService.LocalBinder binder = runtimeBinder;
        if (binder == null) {
            controlRuntime.failClosed("output_route_bluetooth_hid_without_runtime_binder");
            onRuntimeServiceUnavailable("output_route_bluetooth_hid_without_runtime_binder");
            return;
        }
        binder.selectOutputRoute(ControlOutputRoute.BLUETOOTH_HID.storageToken);
        launchBluetoothHidPairingFlow();
        refreshStates(getString(R.string.status_output_route_bluetooth_requested));
    }

    private void launchBluetoothHidPairingFlow() {
        BluetoothManager manager = getSystemService(BluetoothManager.class);
        BluetoothAdapter adapter = manager == null ? null : manager.getAdapter();
        if (adapter == null) {
            refreshStates(getString(R.string.status_output_route_bluetooth_unavailable));
            return;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                && checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                != PackageManager.PERMISSION_GRANTED) {
            eventLogger.write("mobile_bluetooth_hid_permission_missing",
                    "permission=bluetooth_connect pairing_launched=false");
            refreshStates(getString(
                    R.string.status_output_route_bluetooth_permission_denied));
            return;
        }
        try {
            if (!adapter.isEnabled()) {
                eventLogger.write("mobile_bluetooth_hid_enable_request",
                        "system_dialog_launched=true");
                startActivityForResult(
                        new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE),
                        BLUETOOTH_HID_ENABLE_REQUEST_CODE);
                refreshStates(getString(R.string.status_output_route_bluetooth_enabling));
                return;
            }
            Intent discoverable = new Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE)
                    .putExtra(
                            BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION,
                            BLUETOOTH_HID_DISCOVERABLE_SECONDS);
            startActivityForResult(
                    discoverable,
                    BLUETOOTH_HID_DISCOVERABLE_REQUEST_CODE);
            eventLogger.write("mobile_bluetooth_hid_discoverable_request",
                    "duration_seconds=" + BLUETOOTH_HID_DISCOVERABLE_SECONDS
                            + " system_dialog_launched=true");
        } catch (RuntimeException failure) {
            eventLogger.write("mobile_bluetooth_hid_pairing_request_failed",
                    "failure_type=" + failure.getClass().getSimpleName());
            refreshStates(getString(
                    R.string.status_output_route_bluetooth_permission_denied));
        }
    }

    private static boolean allPermissionsGranted(int[] grantResults) {
        if (grantResults.length == 0) return false;
        for (int result : grantResults) {
            if (result != PackageManager.PERMISSION_GRANTED) return false;
        }
        return true;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == RUNTIME_LOG_DOCUMENT_REQUEST_CODE) {
            handleRuntimeLogExportResult(resultCode, data);
            return;
        }
        if (requestCode == BLUETOOTH_HID_ENABLE_REQUEST_CODE) {
            boolean enabled = resultCode == RESULT_OK;
            eventLogger.write("mobile_bluetooth_hid_enable_result",
                    "enabled=" + enabled);
            if (enabled) {
                selectBluetoothHidOutputRoute(false);
            } else {
                refreshStates(getString(
                        R.string.status_output_route_bluetooth_pairing_cancelled));
            }
            return;
        }
        if (requestCode == BLUETOOTH_HID_DISCOVERABLE_REQUEST_CODE) {
            boolean discoverable = resultCode > 0;
            eventLogger.write("mobile_bluetooth_hid_discoverable_result",
                    "discoverable=" + discoverable
                            + " duration_seconds=" + Math.max(0, resultCode));
            refreshStates(getString(discoverable
                    ? R.string.status_output_route_bluetooth_pairing
                    : R.string.status_output_route_bluetooth_pairing_cancelled));
            return;
        }
        if (requestCode != PERSONAL_TRAJECTORY_DOCUMENT_REQUEST_CODE
                || resultCode != RESULT_OK || data == null) {
            return;
        }
        Uri profileUri = data.getData();
        if (profileUri == null) return;
        try {
            String profileJson = readBoundedUtf8(profileUri);
            controlRuntime.importPersonalTrajectory(profileJson);
            refreshStates(getString(R.string.status_personal_trajectory_imported,
                    controlRuntime.personalTrajectoryProfileId()));
        } catch (IllegalArgumentException | IOException exception) {
            eventLogger.write("mobile_personal_trajectory_import_failed",
                    "reason=" + exception.getClass().getSimpleName());
            refreshStates(getString(R.string.status_personal_trajectory_import_failed));
        }
    }

    private void handleRuntimeLogExportResult(int resultCode, Intent data) {
        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            eventLogger.write("mobile_runtime_log_export_cancelled",
                    "document_selected=false");
            return;
        }
        Uri destination = data.getData();
        try (OutputStream output = getContentResolver().openOutputStream(
                     destination, "wt")) {
            if (output == null) throw new IOException("log_output_stream_unavailable");
            long exportedBytes = eventLogger.exportTo(output);
            eventLogger.write("mobile_runtime_log_export_finished",
                    "result=success bytes=" + exportedBytes);
            refreshStates(getString(R.string.status_runtime_log_exported));
        } catch (IOException | RuntimeException failure) {
            eventLogger.write("mobile_runtime_log_export_finished",
                    "result=failed failure_type="
                            + failure.getClass().getSimpleName());
            refreshStates(getString(R.string.status_runtime_log_export_failed));
        }
    }

    private String readBoundedUtf8(Uri uri) throws IOException {
        try (InputStream input = getContentResolver().openInputStream(uri)) {
            if (input == null) throw new IOException("profile_stream_unavailable");
            byte[] buffer = new byte[8 * 1024];
            java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
            int read;
            while ((read = input.read(buffer)) != -1) {
                if (output.size() + read > MAXIMUM_PERSONAL_PROFILE_BYTES) {
                    throw new IOException("profile_too_large");
                }
                output.write(buffer, 0, read);
            }
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private String triggerLabel(ControlTrigger trigger) {
        if (trigger == ControlTrigger.RIGHT_MOUSE) return getString(R.string.trigger_right_mouse);
        if (trigger == ControlTrigger.SIDE_BUTTON_1) return getString(R.string.trigger_mouse4);
        if (trigger == ControlTrigger.SIDE_BUTTON_2) return getString(R.string.trigger_mouse5);
        return getString(R.string.trigger_always);
    }

    private void requestBackgroundExecutionExemptionIfNeeded() {
        if (backgroundPolicyDialogShown || backgroundExecutionPolicy.isExempt()) {
            MobileRuntimeService.requestPowerPolicyRefresh(this);
            return;
        }
        backgroundPolicyDialogShown = true;
        new AlertDialog.Builder(this)
                .setTitle(R.string.background_execution_title)
                .setMessage(R.string.background_execution_detail)
                .setPositiveButton(R.string.background_execution_allow, (dialog, which) -> {
                    boolean launched = backgroundExecutionPolicy.requestExemption();
                    eventLogger.write("mobile_power_policy_request",
                            "system_dialog_launched=" + launched);
                    if (!launched) {
                        refreshStates(getString(R.string.background_execution_unavailable));
                    }
                })
                .setNegativeButton(R.string.background_execution_later, (dialog, which) ->
                        eventLogger.write("mobile_power_policy_request", "operator_deferred=true"))
                .show();
    }

    private boolean showTaskCleanedGuidanceIfNeeded() {
        if (previousExit.kind != MobilePreviousExitPolicy.Kind.TASK_CLEANED
                || previousExit.timestampMillis <= 0L) {
            return false;
        }
        long lastShown = getSharedPreferences(
                EXIT_GUIDANCE_PREFERENCES, MODE_PRIVATE).getLong(
                LAST_TASK_CLEAN_GUIDANCE_TIMESTAMP, 0L);
        if (lastShown == previousExit.timestampMillis) return false;
        getSharedPreferences(EXIT_GUIDANCE_PREFERENCES, MODE_PRIVATE).edit()
                .putLong(
                        LAST_TASK_CLEAN_GUIDANCE_TIMESTAMP,
                        previousExit.timestampMillis)
                .apply();
        eventLogger.write(
                "mobile_task_clean_guidance_shown",
                "previous_exit_timestamp_ms=" + previousExit.timestampMillis
                        + " android_force_stop_cannot_self_restart=true");
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.task_cleaned_guidance_title)
                .setMessage(R.string.task_cleaned_guidance_detail)
                .setPositiveButton(
                        android.R.string.ok,
                        (ignored, which) -> requestRequiredRuntimePolicies())
                .create();
        dialog.setCancelable(false);
        dialog.show();
        return true;
    }

    private String displayNote(long monotonicMillis) {
        return monotonicMillis - latestNoteElapsedMillis <= STATUS_NOTE_TTL_MILLIS
                ? latestNote : "";
    }

    private static String displayCount(long value) {
        return value >= 0L ? Long.toString(value) : "--";
    }

    private String displayRuntimeLabel(String runtimeLabel) {
        if (runtimeLabel == null || runtimeLabel.isBlank()
                || runtimeLabel.contains("QNN")) {
            return getString(R.string.ai_runtime_label);
        }
        return runtimeLabel;
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        if (appShell != null) outState.putString(STATE_DESTINATION,
                appShell.selectedDestination().name());
        super.onSaveInstanceState(outState);
    }

    private static MobileDestination destinationFrom(String value) {
        if (value == null) return MobileDestination.INFERENCE;
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        // Versions before 1.0.1 persisted LINK as a standalone destination.
        // The unified screen keeps that state compatible by routing it to inference.
        if ("LINK".equals(normalized)) return MobileDestination.INFERENCE;
        try {
            return MobileDestination.valueOf(normalized);
        } catch (IllegalArgumentException ignored) {
            return MobileDestination.INFERENCE;
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        activityStarted = true;
        if (uiPreviewOnly || runtimeServiceBound) return;
        Intent serviceIntent = new Intent(
                this, MobileRuntimeService.class);
        runtimeServiceBound = bindService(
                serviceIntent,
                runtimeServiceConnection,
                Context.BIND_AUTO_CREATE);
        if (!runtimeServiceBound) {
            onRuntimeServiceUnavailable(
                    "runtime_service_bind_failed");
        }
    }

    @Override
    public void onUserInteraction() {
        super.onUserInteraction();
        // Pure UI glue: lets ambient decorative layers reset their
        // inactivity sleep budget. No runtime state is touched.
        if (appShell != null) appShell.onUserInteraction();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (uiPreviewOnly) return;
        if (runtimeBinder != null) {
            runtimeBinder.setActivityForeground(true);
        }
        MobileRuntimeService.ensureRunning(this);
        controlRuntime = MobileControlRuntime.get(this);
        boolean notificationPermissionGranted = notificationExecutionPolicy.isGranted();
        if (notificationPermissionGranted != lastNotificationPermissionGranted) {
            lastNotificationPermissionGranted = notificationPermissionGranted;
            eventLogger.write("mobile_notification_policy_changed",
                    notificationExecutionPolicy.auditDetail());
            if (notificationPermissionGranted) {
                MobileRuntimeService.requestPowerPolicyRefresh(this);
                requestBackgroundExecutionExemptionIfNeeded();
            }
        }
        boolean batteryOptimizationExempt = backgroundExecutionPolicy.isExempt();
        if (batteryOptimizationExempt != lastBatteryOptimizationExempt) {
            lastBatteryOptimizationExempt = batteryOptimizationExempt;
            eventLogger.write("mobile_power_policy_changed",
                    backgroundExecutionPolicy.auditDetail());
            if (batteryOptimizationExempt) {
                MobileRuntimeService.requestPowerPolicyRefresh(this);
                refreshStates(getString(R.string.background_execution_enabled));
            }
        }
        stateRefreshHandler.removeCallbacks(stateRefreshTask);
        stateRefreshHandler.post(stateRefreshTask);
    }

    @Override
    protected void onPause() {
        stateRefreshHandler.removeCallbacks(stateRefreshTask);
        super.onPause();
    }

    @Override
    protected void onStop() {
        // Rotation and other configuration changes recreate the Activity while
        // the same foreground UI remains visible.  Publishing a transient
        // foreground=false from onPause used to cancel the live WLAN billing
        // session before the replacement Activity could resume.
        if (!isChangingConfigurations() && runtimeBinder != null) {
            runtimeBinder.setActivityForeground(false);
        }
        activityStarted = false;
        if (runtimeBinder != null) {
            runtimeBinder.setAuthorizationObserver(null);
        }
        runtimeBinder = null;
        if (runtimeServiceBound) {
            runtimeServiceBound = false;
            unbindService(runtimeServiceConnection);
        }
        super.onStop();
    }

    @Override
    protected void onDestroy() {
        boolean changingConfigurations = isChangingConfigurations();
        activityDestroyed = true;
        stateRefreshHandler.removeCallbacks(stateRefreshTask);
        if (eventLogger != null) {
            eventLogger.write("mobile_app_stopped",
                    "service_owned_control_preserved=true changing_configurations="
                            + changingConfigurations);
        }
        // MediaCodec/QNN/UDP and the selected mouse-output route are owned by
        // the foreground service and survive Activity recreation.
        super.onDestroy();
    }

    @FunctionalInterface
    private interface NativeReportReader {
        String read();
    }
}
