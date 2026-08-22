package com.visionforge.inferencebenchmark;

import android.content.Context;

/**
 * Process-level composition root for post-process policy and dual output routes.
 *
 * <p>The foreground runtime service owns health reconciliation. Activities only
 * observe this object and update validated parameters, so an Activity recreation
 * or background transition cannot silently tear down an otherwise healthy CAT6
 * control chain.</p>
 */
final class MobileControlRuntime {
    private static volatile MobileControlRuntime instance;

    private final Context appContext;
    private final MobileRuntimeEventSink events;
    private final MakcuSerialController makcu;
    private final Cat6MouseButtonInput cat6ButtonInput;
    private final ControlOutputRouteStore routeStore;
    private final ControlProfile controlProfile;
    private final InferenceProfile inference;
    private ControlOutputCoordinator output;
    private ControlOutputTransport activeTransport;
    private ControlOutputMoveSink activeMoveSink;
    private ControlOutputRoute activeRoute = ControlOutputRoute.MAKCU_USB;
    private BluetoothHidSessionPort bluetoothHidAdapter;
    private BluetoothHidMouseTransportCore bluetoothHidTransport;
    private MobileTransportEndpoint transportEndpoint;
    private String lastFailClosedReason = "";
    private volatile boolean destroyed;

    static synchronized MobileControlRuntime get(Context context) {
        if (instance == null || instance.destroyed) {
            instance = new MobileControlRuntime(context.getApplicationContext());
        }
        return instance;
    }

    private MobileControlRuntime(Context context) {
        appContext = context.getApplicationContext();
        events = new MobileEventLogger(context);
        makcu = new MakcuSerialController(context, events);
        cat6ButtonInput = new Cat6MouseButtonInput(events);
        routeStore = new ControlOutputRouteStore(context);
        inference = new InferenceProfile(context);
        controlProfile = new ControlProfile(context, inference.model(), inference.aimTarget());
        ControlOutputRoute restoredRoute = routeStore.load();
        if (restoredRoute == ControlOutputRoute.BLUETOOTH_HID
                && isBluetoothHidOutputRouteAvailable()) {
            switchToBluetoothHidOutputRoute("persisted_route_restored");
        } else {
            installOutputRoute(ControlOutputRoute.MAKCU_USB, makcu, makcu, makcu);
            if (restoredRoute != ControlOutputRoute.MAKCU_USB) {
                routeStore.save(ControlOutputRoute.MAKCU_USB);
            }
        }
        events.write("mobile_control_runtime_created",
                "ownership=process_service move_only=true restored_route="
                        + activeRoute.storageToken + " " + inference.auditDetail());
    }

    synchronized void ensureMakcuConnected() {
        if (destroyed) return;
        makcu.connectFirstSupportedDevice();
    }

    synchronized void ensureSelectedOutputConnected() {
        if (destroyed) return;
        if (activeRoute == ControlOutputRoute.BLUETOOTH_HID) {
            BluetoothHidSessionPort adapter = ensureBluetoothHidAdapter();
            adapter.setForegroundSessionActive(true);
            ensureBluetoothHidTransport(adapter).connectFirstSupportedDevice();
            return;
        }
        ensureMakcuConnected();
    }

    synchronized void updateTransportEndpoint(MobileTransportEndpoint endpoint) {
        if (destroyed) return;
        transportEndpoint = endpoint;
        cat6ButtonInput.updateEndpoint(
                activeRoute == ControlOutputRoute.BLUETOOTH_HID ? endpoint : null);
        if (activeRoute == ControlOutputRoute.BLUETOOTH_HID && endpoint == null) {
            output.failClosed("cat6_button_endpoint_unavailable");
        }
    }

    /** Installs the mouse key only after the peer Finished gate has succeeded. */
    synchronized boolean installConfirmedPeerSession(
            ConfirmedAndroidPeerSession session) {
        if (destroyed || activeRoute != ControlOutputRoute.BLUETOOTH_HID) {
            return false;
        }
        boolean installed = cat6ButtonInput.installConfirmedSession(session);
        if (!installed) output.failClosed("cat6_button_session_unavailable");
        return installed;
    }

    synchronized void clearConfirmedPeerSession(String reason) {
        if (destroyed) return;
        cat6ButtonInput.clearConfirmedSession(reason);
        if (activeRoute == ControlOutputRoute.BLUETOOTH_HID) {
            output.failClosed("cat6_button_session_closed");
        }
    }

    synchronized String selectOutputRoute(ControlOutputRoute requestedRoute) {
        if (destroyed) return "runtime_destroyed";
        ControlOutputRoute requested = requestedRoute == null
                ? ControlOutputRoute.MAKCU_USB : requestedRoute;
        if (requested == ControlOutputRoute.MAKCU_USB) {
            switchToMakcuOutputRoute(ControlOutputRoutePolicy.REASON_MAKCU_SELECTED);
            routeStore.save(ControlOutputRoute.MAKCU_USB);
            return ControlOutputRoutePolicy.REASON_MAKCU_SELECTED;
        }
        if (requested != ControlOutputRoute.BLUETOOTH_HID
                || !isBluetoothHidOutputRouteAvailable()) {
            return rejectOutputRoute(
                    requested,
                    ControlOutputRoutePolicy.REASON_BLUETOOTH_HID_PLATFORM_UNAVAILABLE);
        }
        String reason = switchToBluetoothHidOutputRoute("operator_selected");
        routeStore.save(ControlOutputRoute.BLUETOOTH_HID);
        return reason;
    }

    synchronized ControlOutputRoute activeOutputRoute() {
        return activeRoute;
    }

    synchronized boolean isBluetoothHidOutputRouteActive() {
        return activeRoute == ControlOutputRoute.BLUETOOTH_HID;
    }

    synchronized boolean isBluetoothHidOutputRouteAvailable() {
        return AndroidHidMouseSessionFactory.isSupported(appContext);
    }

    synchronized boolean isBluetoothHidSessionReady() {
        return activeRoute == ControlOutputRoute.BLUETOOTH_HID
                && bluetoothHidAdapter != null
                && BluetoothHidOutputFailClosedPolicy.evaluate(
                bluetoothHidAdapter.sessionState()).outputAllowed;
    }

    synchronized String outputRouteReport() {
        BluetoothHidOutputFailClosedPolicy.Decision hidDecision =
                BluetoothHidOutputFailClosedPolicy.evaluate(
                        bluetoothHidAdapter == null ? null : bluetoothHidAdapter.sessionState());
        return "active_route=" + activeRoute.storageToken
                + " bluetooth_available=" + isBluetoothHidOutputRouteAvailable()
                + " bluetooth_state=" + hidDecision.reason
                + " cat6_buttons={" + cat6ButtonInput.report() + "}";
    }

    synchronized String runDebugBluetoothHidMoveProbe(
            int deltaX,
            int deltaY,
            int reports,
            int intervalMillis) {
        if (!BuildConfig.DEBUG) {
            return "debug_probe_disabled";
        }
        BluetoothHidDebugMoveProbePolicy.Request request =
                BluetoothHidDebugMoveProbePolicy.sanitize(
                        deltaX, deltaY, reports, intervalMillis);
        if (!request.hasMovement) {
            return "debug_probe_rejected reason=zero_movement";
        }
        if (activeRoute != ControlOutputRoute.BLUETOOTH_HID) {
            return "debug_probe_rejected reason=route_not_bluetooth_hid"
                    + " active_route=" + activeRoute.storageToken;
        }
        BluetoothHidMouseTransportCore probeTransport = bluetoothHidTransport;
        if (activeTransport == null || probeTransport == null) {
            return "debug_probe_rejected reason=output_sink_missing";
        }
        boolean gateOpened = activeTransport.setOutputDeliveryAllowed(true);
        if (!gateOpened) {
            return "debug_probe_rejected reason=delivery_gate_rejected";
        }
        int sentReports = 0;
        int failedReports = 0;
        try {
            for (int index = 0; index < request.reports; index++) {
                boolean sent = probeTransport.sendDiagnosticMove(
                        request.deltaX, request.deltaY);
                if (sent) {
                    sentReports++;
                } else {
                    failedReports++;
                    break;
                }
                sleepBetweenDebugProbeReports(request.intervalMillis);
            }
        } finally {
            activeTransport.setOutputDeliveryAllowed(false);
        }
        return "debug_probe_completed route=" + activeRoute.storageToken
                + " dx=" + request.deltaX
                + " dy=" + request.deltaY
                + " requested_reports=" + request.reports
                + " sent_reports=" + sentReports
                + " failed_reports=" + failedReports
                + " output_closed=true";
    }

    synchronized void reconcile(
            boolean runtimeHealthy,
            boolean nativeStateKnown,
            boolean nativeRequested,
            boolean nativeEffective,
            boolean nativeRecoverySuspended) {
        if (destroyed) return;
        if (activeRoute == ControlOutputRoute.BLUETOOTH_HID) {
            cat6ButtonInput.updateEndpoint(transportEndpoint);
        }
        output.reconcileDeliveryState();
        output.reconcileAutomaticState(
                runtimeHealthy && inference.isNativeConfigurationApplied(),
                nativeStateKnown,
                nativeRequested,
                nativeEffective,
                nativeRecoverySuspended);
        if (runtimeHealthy && output.isOutputEnabled()) lastFailClosedReason = "";
    }

    synchronized void failClosed(String reason) {
        if (destroyed) return;
        String reasonToken = reportToken(reason);
        output.failClosed(reasonToken);
        if (!reasonToken.equals(lastFailClosedReason)) {
            events.write("mobile_control_runtime_fail_closed",
                    "reason=" + reasonToken + " automatic_retry=true");
            lastFailClosedReason = reasonToken;
        }
    }

    synchronized void closeForServiceStop(String reason) {
        if (destroyed) return;
        destroyed = true;
        output.dispose();
        clearActiveMoveSink();
        cat6ButtonInput.close();
        closeBluetoothHidRoute();
        makcu.destroy();
        events.write("mobile_control_runtime_service_stopped",
                "reason=" + reportToken(reason)
                        + " usb_destroyed=true bluetooth_hid_closed=true fail_closed=true");
        if (instance == this) instance = null;
    }

    synchronized String makcuReport() {
        if (destroyed) return "MAKCU controller destroyed";
        return makcu.report();
    }

    synchronized boolean isOutputEnabled() {
        return !destroyed && output.isOutputEnabled();
    }

    synchronized boolean isOutputRecoverySuspended() {
        return !destroyed && output.isOutputRecoverySuspended();
    }

    synchronized float controlGain() {
        return output.gain();
    }

    synchronized float controlDeadzonePixels() {
        return output.deadzonePixels();
    }

    synchronized int maximumAxisDelta() {
        return output.maximumAxisDelta();
    }

    synchronized int switchConfirmationMillis() {
        return output.switchConfirmationMillis();
    }

    synchronized void setControlGain(float value) {
        if (destroyed) return;
        output.setGain(value);
        events.write(
                "mobile_control_setting_hot_applied",
                "setting=gain value=" + output.gain());
    }

    synchronized void setControlDeadzone(float value) {
        if (destroyed) return;
        output.setDeadzone(value);
        events.write(
                "mobile_control_setting_hot_applied",
                "setting=deadzone_pixels value=" + output.deadzonePixels());
    }

    synchronized void setMaximumAxisDelta(int value) {
        if (destroyed) return;
        output.setMaximumAxisDelta(value);
        events.write(
                "mobile_control_setting_hot_applied",
                "setting=maximum_axis_delta value=" + output.maximumAxisDelta());
    }

    synchronized void setSwitchConfirmationMillis(int value) {
        if (destroyed) return;
        output.setSwitchConfirmationMillis(value);
        events.write(
                "mobile_control_setting_hot_applied",
                "setting=switch_confirmation_ms value="
                        + output.switchConfirmationMillis());
    }

    synchronized void setControlProfile(float gain, float deadzonePixels,
                                        int maximumAxisDelta,
                                        int switchConfirmationMillis) {
        if (destroyed) return;
        output.setProfile(gain, deadzonePixels, maximumAxisDelta,
                switchConfirmationMillis);
        events.write(
                "mobile_control_profile_hot_applied",
                "gain=" + output.gain()
                        + " deadzone_pixels=" + output.deadzonePixels()
                        + " maximum_axis_delta=" + output.maximumAxisDelta()
                        + " switch_confirmation_ms="
                        + output.switchConfirmationMillis());
    }

    synchronized ControlTrigger controlTrigger() {
        return output.controlTrigger();
    }

    synchronized void setControlTrigger(ControlTrigger trigger) {
        if (destroyed) return;
        output.setControlTrigger(trigger);
        events.write(
                "mobile_control_setting_hot_applied",
                "setting=control_trigger value="
                        + output.controlTrigger().storageToken);
    }

    synchronized boolean isControlTriggerPressed() {
        return !destroyed && output.isControlTriggerPressed();
    }

    synchronized boolean isControlTriggerStreamReady() {
        return !destroyed && output.isControlTriggerStreamReady();
    }

    synchronized boolean importPersonalTrajectory(String profileJson) {
        if (destroyed) return false;
        boolean imported = output.importPersonalTrajectory(profileJson);
        events.write("mobile_personal_trajectory_imported",
                "profile_id=" + reportToken(output.personalTrajectoryProfileId())
                        + " enabled=" + output.personalTrajectoryEnabled()
                        + " native_apply_attempted=true");
        return imported;
    }

    synchronized void setPersonalTrajectoryEnabled(boolean enabled) {
        if (destroyed) return;
        output.setPersonalTrajectoryEnabled(enabled);
        events.write(
                "mobile_control_setting_hot_applied",
                "setting=personal_trajectory_enabled value="
                        + output.personalTrajectoryEnabled());
    }

    synchronized void setPersonalTrajectoryScales(
            float speedScale, float stabilityScale, float variationScale) {
        if (destroyed) return;
        output.setPersonalTrajectoryScales(speedScale, stabilityScale, variationScale);
        events.write(
                "mobile_control_trajectory_hot_applied",
                "speed_scale=" + output.personalTrajectorySpeedScale()
                        + " stability_scale="
                        + output.personalTrajectoryStabilityScale()
                        + " variation_scale="
                        + output.personalTrajectoryVariationScale());
    }

    synchronized boolean personalTrajectoryEnabled() {
        return output.personalTrajectoryEnabled();
    }

    synchronized String personalTrajectoryProfileId() {
        return output.personalTrajectoryProfileId();
    }

    synchronized float personalTrajectorySpeedScale() {
        return output.personalTrajectorySpeedScale();
    }

    synchronized float personalTrajectoryStabilityScale() {
        return output.personalTrajectoryStabilityScale();
    }

    synchronized float personalTrajectoryVariationScale() {
        return output.personalTrajectoryVariationScale();
    }

    synchronized float confidence() {
        return inference.confidence();
    }

    synchronized MobileModelCatalog.Profile activeModel() {
        return inference.model();
    }

    synchronized MobileAimTarget aimTarget() {
        return inference.aimTarget();
    }

    synchronized void selectModel(MobileModelCatalog.Profile model) {
        if (destroyed || model == null) return;
        output.failClosed("game_model_changed");
        inference.selectModel(model);
        output.selectTargetProfile(model, inference.aimTarget());
        events.write("mobile_game_model_applied", inference.auditDetail());
    }

    synchronized void setAimTarget(MobileAimTarget target) {
        if (destroyed || target == null || !inference.model().supports(target)) return;
        output.failClosed("aim_target_changed");
        inference.setAimTarget(target);
        output.selectTargetProfile(inference.model(), inference.aimTarget());
        events.write("mobile_aim_target_applied", inference.auditDetail());
    }

    synchronized float nmsIou() {
        return inference.nmsIou();
    }

    synchronized boolean isNativePostprocessApplied() {
        return !destroyed && inference.isNativeConfigurationApplied();
    }

    synchronized void setConfidence(float value) {
        if (destroyed) return;
        inference.setConfidence(value);
        events.write("mobile_inference_profile_applied", inference.auditDetail());
    }

    synchronized String inferenceAuditDetail() {
        if (destroyed) return "runtime_destroyed";
        return inference.auditDetail();
    }

    private static String reportToken(String value) {
        if (value == null || value.isBlank()) return "unspecified";
        return value.replace(' ', '_').replace('\r', '_').replace('\n', '_');
    }

    private void switchToMakcuOutputRoute(String reason) {
        cat6ButtonInput.updateEndpoint(null);
        installOutputRoute(ControlOutputRoute.MAKCU_USB, makcu, makcu, makcu);
        // Disable native delivery and unregister the old sink before closing
        // its Android adapter. Otherwise an in-flight JNI callback can enter
        // the old Bluetooth sink after the adapter has already been closed.
        closeBluetoothHidRoute();
        makcu.connectFirstSupportedDevice();
        events.write("mobile_control_output_route_selected",
                "route=" + activeRoute.storageToken
                        + " reason=" + reportToken(reason)
                        + " fail_closed=false");
    }

    private String switchToBluetoothHidOutputRoute(String selectionReason) {
        BluetoothHidSessionPort adapter = ensureBluetoothHidAdapter();
        BluetoothHidMouseTransportCore transport = ensureBluetoothHidTransport(adapter);
        adapter.setForegroundSessionActive(true);
        transport.connectFirstSupportedDevice();
        installOutputRoute(
                ControlOutputRoute.BLUETOOTH_HID,
                transport,
                transport,
                cat6ButtonInput);
        cat6ButtonInput.updateEndpoint(transportEndpoint);
        ControlOutputRoutePolicy.Decision decision = ControlOutputRoutePolicy.decide(
                ControlOutputRoutePolicy.Selection.bluetooth(
                        isBluetoothHidOutputRouteAvailable(),
                        BluetoothHidOutputFailClosedPolicy.evaluate(adapter.sessionState()),
                        output.controlTrigger(),
                        cat6ButtonInput.isButtonStreamReady()));
        if (!decision.outputAllowed) output.failClosed(decision.reason);
        events.write("mobile_control_output_route_selected",
                "route=" + activeRoute.storageToken
                        + " selection_reason=" + reportToken(selectionReason)
                        + " readiness_reason=" + reportToken(decision.reason)
                        + " fail_closed=" + (!decision.outputAllowed));
        return decision.reason;
    }

    private String rejectOutputRoute(ControlOutputRoute requestedRoute, String reason) {
        events.write("mobile_control_output_route_locked",
                "requested_route=" + (requestedRoute == null
                        ? "unspecified" : requestedRoute.storageToken)
                        + " active_route=" + activeRoute.storageToken
                        + " reason=" + reportToken(reason)
                        + " fail_closed=true");
        return reason;
    }

    private void installOutputRoute(
            ControlOutputRoute route,
            ControlOutputTransport transport,
            ControlOutputMoveSink moveSink,
            ControlButtonInput buttonInput) {
        if (output != null) output.dispose();
        if (activeTransport != null) activeTransport.setReconnectListener(null);
        clearActiveMoveSink();
        activeRoute = route;
        activeTransport = transport;
        activeMoveSink = moveSink;
        ControlOutputMoveDispatcher.registerSink(moveSink);
        output = new ControlOutputCoordinator(transport, buttonInput, controlProfile, events);
    }

    private void clearActiveMoveSink() {
        if (activeMoveSink != null) {
            ControlOutputMoveDispatcher.clearSink(activeMoveSink);
            activeMoveSink = null;
        }
    }

    private BluetoothHidSessionPort ensureBluetoothHidAdapter() {
        if (bluetoothHidAdapter == null) {
            bluetoothHidAdapter = AndroidHidMouseSessionFactory.create(appContext, events);
        }
        return bluetoothHidAdapter;
    }

    private BluetoothHidMouseTransportCore ensureBluetoothHidTransport(
            BluetoothHidMouseTransportCore.SessionPort adapter) {
        if (bluetoothHidTransport == null) {
            bluetoothHidTransport = new BluetoothHidMouseTransportCore(
                    adapter,
                    QnnHtpBridge::reportNativeBluetoothHidMoveAccepted);
        }
        return bluetoothHidTransport;
    }

    private void closeBluetoothHidRoute() {
        if (bluetoothHidTransport != null) {
            bluetoothHidTransport.setReconnectListener(null);
            bluetoothHidTransport.dispose();
        }
        if (bluetoothHidAdapter != null) {
            bluetoothHidAdapter.setForegroundSessionActive(false);
            bluetoothHidAdapter.close();
        }
        bluetoothHidTransport = null;
        bluetoothHidAdapter = null;
    }

    private static void sleepBetweenDebugProbeReports(int intervalMillis) {
        if (intervalMillis <= 0) return;
        try {
            Thread.sleep(intervalMillis);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

}
