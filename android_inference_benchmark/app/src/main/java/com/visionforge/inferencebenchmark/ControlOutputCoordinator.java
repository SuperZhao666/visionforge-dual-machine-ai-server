package com.visionforge.inferencebenchmark;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Coordinates the automatic phone-to-selected-output transport gate.
 *
 * <p>Output becomes effective only while the video/inference runtime, native
 * authorization and the selected output transport are healthy. Any failed
 * prerequisite closes both native and transport delivery gates; the next verified
 * healthy state automatically re-arms them.</p>
 */
final class ControlOutputCoordinator {
    private static final long OUTPUT_RECONNECT_RETRY_NANOS = 1_000_000_000L;
    private static final long MAXIMUM_OUTPUT_RECONNECT_RETRY_NANOS =
            30_000_000_000L;

    private final ControlOutputTransport outputTransport;
    private final ControlButtonInput buttonInput;
    private final ControlProfilePort profile;
    private final MobileRuntimeEventSink events;
    private boolean runtimeHealthy;
    private boolean nativeStateKnown;
    private boolean nativeRequested;
    private boolean nativeEffective;
    private boolean nativeRecoverySuspended;
    private boolean automaticOutputRequested;
    private boolean outputEnabled;
    private boolean outputRecoverySuspended;
    private boolean usbWriteCompletedSinceEnable;
    private boolean automaticRetryDeferred;
    private boolean outputCloseConfirmed;
    private final Set<String> lockReasonsReportedWhileClosed = new HashSet<>();
    private long lastUsbWriteCompletions;
    private long lastDeliveryFailures;
    private long lastDeliveryCircuitTrips;
    private long nextOutputReconnectAttemptNanos;
    private int consecutiveReconnectFailures;

    ControlOutputCoordinator(ControlOutputTransport outputTransport, ControlProfilePort profile,
                             MobileRuntimeEventSink events) {
        this(outputTransport,
                outputTransport instanceof ControlButtonInput
                        ? (ControlButtonInput) outputTransport : null,
                profile,
                events);
    }

    ControlOutputCoordinator(
            ControlOutputTransport outputTransport,
            ControlButtonInput buttonInput,
            ControlProfilePort profile,
            MobileRuntimeEventSink events) {
        if (outputTransport == null) throw new IllegalArgumentException("outputTransport");
        if (profile == null) throw new IllegalArgumentException("profile");
        if (events == null) throw new IllegalArgumentException("events");
        this.outputTransport = outputTransport;
        this.buttonInput = buttonInput;
        this.profile = profile;
        this.events = events;
        outputTransport.setReconnectListener(this::onReconnectResult);
        if (buttonInput != null) {
            buttonInput.setButtonStateListener(this::onButtonMaskChanged);
            buttonInput.setRequiredTriggerMask(profile.controlTrigger().buttonMask);
        }
        closeEffectiveOutput();
        MakcuDeliveryState delivery = outputTransport.deliveryState();
        lastUsbWriteCompletions = delivery.usbWriteCompletionCount;
        lastDeliveryFailures = delivery.failureCount;
        lastDeliveryCircuitTrips = delivery.circuitTripCount;
    }

    /**
     * Reconciles every prerequisite in one state transition so a stale native
     * report cannot re-open a gate after the link has already failed.
     */
    synchronized void reconcileAutomaticState(
            boolean runtimeHealthy,
            boolean nativeStateKnown,
            boolean nativeRequested,
            boolean nativeEffective,
            boolean recoverySuspended) {
        this.runtimeHealthy = runtimeHealthy;
        this.nativeStateKnown = nativeStateKnown;
        this.nativeRequested = nativeRequested;
        this.nativeEffective = nativeEffective;
        this.nativeRecoverySuspended = recoverySuspended;
        MakcuDeliveryState delivery = outputTransport.deliveryState();
        if (!outputTransport.isReady()) {
            closeAutomaticGate(runtimeHealthy
                    ? "output_transport_not_ready" : "runtime_unhealthy");
            connectOutputTransportIfDue();
            return;
        }
        if (!runtimeHealthy) {
            closeAutomaticGate("runtime_unhealthy");
            return;
        }
        if (delivery.circuitOpen) {
            closeAutomaticGate("delivery_circuit_open");
            return;
        }
        if (!triggerPrerequisiteSatisfied()) return;
        if (!nativeStateKnown) {
            closeAutomaticGate("native_authorization_unknown");
            return;
        }
        if (!automaticOutputRequested) {
            if (automaticRetryDeferred) {
                automaticRetryDeferred = false;
                events.write("control_output_retry_deferred",
                        "reason=fresh_health_epoch_after_delivery_failure "
                                + "fail_closed=true automatic_retry=true");
                return;
            }
            enableAutomatically();
            return;
        }
        reconcileNativeState(nativeRequested, nativeEffective, recoverySuspended);
    }

    private void reconcileNativeState(
            boolean nativeRequested, boolean nativeEffective, boolean recoverySuspended) {
        if (recoverySuspended) {
            if (!nativeRequested || nativeEffective) {
                closeAutomaticGate("invalid_native_recovery_state");
                return;
            }
            if (!outputRecoverySuspended) {
                events.write("control_output_recovery_suspended",
                        "automatic_request=true output_effective=false fail_closed=true");
            }
            outputEnabled = false;
            outputRecoverySuspended = true;
            return;
        }
        if (nativeRequested && nativeEffective) {
            if (outputRecoverySuspended) {
                events.write("control_output_recovery_resumed",
                        "automatic_request=true output_effective=true");
            }
            outputEnabled = true;
            outputRecoverySuspended = false;
            outputCloseConfirmed = false;
            return;
        }
        closeAutomaticGate(nativeRequested || nativeEffective
                ? "unexpected_native_authorization" : "native_request_cleared");
    }

    private void enableAutomatically() {
        if (!runtimeHealthy || !outputTransport.isReady()
                || outputTransport.deliveryState().circuitOpen) return;
        // A partial enable must execute a fresh close; the previously
        // confirmed disabled state no longer describes the native gate.
        outputCloseConfirmed = false;
        if (!profile.apply(true)) {
            closeAutomaticGate("native_profile_rejected");
            return;
        }
        if (!outputTransport.setOutputDeliveryAllowed(true)) {
            closeAutomaticGate(outputTransport.deliveryState().circuitOpen
                    ? "delivery_circuit_open" : "delivery_gate_unavailable");
            return;
        }
        automaticOutputRequested = true;
        outputEnabled = true;
        outputRecoverySuspended = false;
        usbWriteCompletedSinceEnable = false;
        lockReasonsReportedWhileClosed.clear();
        events.write("control_output_auto_ready",
                "automatic_request=true output_effective=true");
    }

    private void connectOutputTransportIfDue() {
        long nowNanos = System.nanoTime();
        if (nowNanos < nextOutputReconnectAttemptNanos) return;
        nextOutputReconnectAttemptNanos = nowNanos + OUTPUT_RECONNECT_RETRY_NANOS;
        outputTransport.connectFirstSupportedDevice();
    }

    synchronized void disable() {
        runtimeHealthy = false;
        closeAutomaticGate("runtime_stopped");
    }

    synchronized void dispose() {
        disable();
        outputTransport.setReconnectListener(null);
        if (buttonInput != null) buttonInput.setButtonStateListener(null);
    }

    synchronized void failClosed(String reason) {
        runtimeHealthy = false;
        closeAutomaticGate(reason);
    }

    private void closeAutomaticGate(String reason) {
        closeAutomaticGate(reason, false);
    }

    private void closeAutomaticGate(String reason, boolean forceClose) {
        boolean stateChanged = automaticOutputRequested || outputEnabled
                || outputRecoverySuspended;
        automaticOutputRequested = false;
        if (forceClose || stateChanged || !outputCloseConfirmed) {
            closeEffectiveOutput();
        } else {
            outputEnabled = false;
            outputRecoverySuspended = false;
            usbWriteCompletedSinceEnable = false;
        }
        if (stateChanged) lockReasonsReportedWhileClosed.clear();
        if (lockReasonsReportedWhileClosed.add(reason)) {
            events.write("control_output_auto_locked",
                    "reason=" + reason + " automatic_retry=true fail_closed=true");
        }
    }

    private void closeEffectiveOutput() {
        outputEnabled = false;
        outputRecoverySuspended = false;
        usbWriteCompletedSinceEnable = false;
        boolean transportClosed =
                outputTransport.setOutputDeliveryAllowed(false);
        boolean nativeClosed = profile.apply(false);
        outputCloseConfirmed = transportClosed && nativeClosed;
    }

    synchronized void selectTargetProfile(
            MobileModelCatalog.Profile model, MobileAimTarget aimTarget) {
        closeAutomaticGate("game_target_profile_changed");
        profile.selectTargetProfile(model, aimTarget);
        applyCurrentProfile();
    }

    synchronized void setGain(float value) {
        profile.setGain(value);
        applyCurrentProfile();
    }

    synchronized void setDeadzone(float value) {
        profile.setDeadzone(value);
        applyCurrentProfile();
    }

    synchronized void setMaximumAxisDelta(int value) {
        profile.setMaximumAxisDelta(value);
        applyCurrentProfile();
    }

    synchronized void setSwitchConfirmationMillis(int value) {
        profile.setSwitchConfirmationMillis(value);
        applyCurrentProfile();
    }

    synchronized void setProfile(float gain, float deadzonePixels, int maximumAxisDelta,
                                 int switchConfirmationMillis) {
        profile.setValues(gain, deadzonePixels, maximumAxisDelta,
                switchConfirmationMillis);
        applyCurrentProfile();
    }

    synchronized void setControlTrigger(ControlTrigger trigger) {
        if (trigger == null) {
            events.write("control_trigger_rejected",
                    "reason=null_trigger preserved=" + profile.controlTrigger().storageToken);
            return;
        }
        closeAutomaticGate("activation_trigger_changed");
        ControlTrigger selected = trigger;
        profile.setControlTrigger(selected);
        if (buttonInput != null) {
            buttonInput.setRequiredTriggerMask(selected.buttonMask);
        }
        events.write("control_trigger_applied",
                "trigger=" + selected.storageToken
                        + " physical_read_only=true output_fail_closed=true");
        reconcileCachedState();
    }

    synchronized ControlTrigger controlTrigger() {
        return profile.controlTrigger();
    }

    synchronized boolean isControlTriggerPressed() {
        return profile.controlTrigger().isSatisfiedBy(
                buttonInput == null ? 0 : buttonInput.currentButtonMask());
    }

    synchronized boolean isControlTriggerStreamReady() {
        return !profile.controlTrigger().requiresButtonStream()
                || buttonInput != null && buttonInput.isButtonStreamReady();
    }

    synchronized boolean importPersonalTrajectory(String profileJson) {
        boolean imported = profile.importPersonalTrajectory(profileJson);
        applyCurrentProfile();
        return imported;
    }

    synchronized void setPersonalTrajectoryEnabled(boolean enabled) {
        profile.setPersonalTrajectoryEnabled(enabled);
        applyCurrentProfile();
    }

    synchronized void setPersonalTrajectoryScales(
            float speedScale, float stabilityScale, float variationScale) {
        profile.setPersonalTrajectoryScales(
                speedScale, stabilityScale, variationScale);
        applyCurrentProfile();
    }

    synchronized boolean personalTrajectoryEnabled() {
        return profile.personalTrajectoryEnabled();
    }

    synchronized String personalTrajectoryProfileId() {
        return profile.personalTrajectoryProfileId();
    }

    synchronized float personalTrajectorySpeedScale() {
        return profile.personalTrajectorySpeedScale();
    }

    synchronized float personalTrajectoryStabilityScale() {
        return profile.personalTrajectoryStabilityScale();
    }

    synchronized float personalTrajectoryVariationScale() {
        return profile.personalTrajectoryVariationScale();
    }

    synchronized float gain() {
        return profile.gain();
    }

    synchronized float deadzonePixels() {
        return profile.deadzonePixels();
    }

    synchronized int maximumAxisDelta() {
        return profile.maximumAxisDelta();
    }

    synchronized int switchConfirmationMillis() {
        return profile.switchConfirmationMillis();
    }

    synchronized boolean isOutputEnabled() {
        return outputEnabled;
    }

    synchronized boolean isAutomaticOutputRequested() {
        return automaticOutputRequested;
    }

    synchronized boolean isOutputRecoverySuspended() {
        return outputRecoverySuspended;
    }

    /**
     * Consumes asynchronous local USB write evidence. A write failure closes
     * the gate immediately. A non-open circuit is retried only by the next
     * complete runtime-health reconciliation.
     */
    synchronized void reconcileDeliveryState() {
        MakcuDeliveryState delivery = outputTransport.deliveryState();
        if (delivery.failureCount > lastDeliveryFailures) {
            automaticRetryDeferred = true;
            closeAutomaticGate("delivery_failure");
            events.write("control_output_delivery_failed", String.format(Locale.US,
                    "new_failures=%d total_failures=%d consecutive_failures=%d reason=%s "
                            + "fail_closed=true automatic_retry=true",
                    delivery.failureCount - lastDeliveryFailures, delivery.failureCount,
                    delivery.consecutiveFailures, delivery.lastFailure));
        }
        if (outputEnabled && !usbWriteCompletedSinceEnable
                && delivery.usbWriteCompletionCount > lastUsbWriteCompletions) {
            usbWriteCompletedSinceEnable = true;
            events.write("control_output_usb_write_completed", String.format(Locale.US,
                    "usb_write_completions=%d last_usb_write_call_us=%d "
                            + "semantics=local_usb_sync_write_complete_not_device_or_physical_ack",
                    delivery.usbWriteCompletionCount, delivery.lastUsbWriteCallMicros));
        }
        if (delivery.circuitTripCount > lastDeliveryCircuitTrips || delivery.circuitOpen) {
            closeAutomaticGate("delivery_circuit_open");
            if (delivery.circuitTripCount > lastDeliveryCircuitTrips) {
                events.write("control_output_delivery_circuit_open", String.format(Locale.US,
                        "trip_count=%d consecutive_failures=%d reason=%s reconnect_required=true",
                        delivery.circuitTripCount, delivery.consecutiveFailures,
                        delivery.lastFailure));
            }
        }
        lastUsbWriteCompletions = delivery.usbWriteCompletionCount;
        lastDeliveryFailures = delivery.failureCount;
        lastDeliveryCircuitTrips = delivery.circuitTripCount;
    }

    private void applyCurrentProfile() {
        if (outputRecoverySuspended) {
            closeAutomaticGate("profile_changed_during_recovery");
            events.write("control_profile_applied", auditDetail());
            return;
        }
        boolean activeReconfiguration = automaticOutputRequested;
        boolean applied = activeReconfiguration
                ? reconfigureActiveProfile()
                : applyDisabledProfile();
        if (!applied) {
            closeAutomaticGate("native_profile_rejected");
            events.write("control_profile_rejected",
                    "native_profile_rejected automatic_retry=true " + auditDetail());
            return;
        }
        events.write("control_profile_applied",
                (activeReconfiguration
                        ? "delivery_drained=true native_ticket_reset=true "
                        : "") + auditDetail());
    }

    private boolean reconfigureActiveProfile() {
        outputEnabled = false;
        usbWriteCompletedSinceEnable = false;
        outputCloseConfirmed = false;
        if (!outputTransport.setOutputDeliveryAllowed(false)) return false;
        if (!profile.apply(false)) return false;
        if (!profile.apply(true)) return false;
        if (!outputTransport.setOutputDeliveryAllowed(true)) return false;
        outputEnabled = true;
        return true;
    }

    private boolean applyDisabledProfile() {
        boolean applied = profile.apply(false);
        if (!applied) outputCloseConfirmed = false;
        return applied;
    }

    private String auditDetail() {
        return String.format(Locale.US,
                "gain=%.2f deadzone_px=%.1f maximum_axis_delta=%d "
                        + "switch_confirmation_ms=%d "
                        + "trigger=%s trigger_stream_ready=%s trigger_pressed=%s "
                        + "personal_enabled=%s personal_profile_id=%s "
                        + "personal_speed=%.3f personal_stability=%.3f "
                        + "personal_variation=%.3f automatic_request=%s output_enabled=%s",
                profile.gain(), profile.deadzonePixels(), profile.maximumAxisDelta(),
                profile.switchConfirmationMillis(),
                profile.controlTrigger().storageToken,
                isControlTriggerStreamReady(), isControlTriggerPressed(),
                profile.personalTrajectoryEnabled(),
                reportToken(profile.personalTrajectoryProfileId()),
                profile.personalTrajectorySpeedScale(),
                profile.personalTrajectoryStabilityScale(),
                profile.personalTrajectoryVariationScale(),
                automaticOutputRequested, outputEnabled);
    }

    private boolean triggerPrerequisiteSatisfied() {
        ControlTrigger trigger = profile.controlTrigger();
        if (!trigger.requiresButtonStream()) return true;
        if (buttonInput == null) {
            closeAutomaticGate("activation_trigger_source_unavailable");
            return false;
        }
        buttonInput.setRequiredTriggerMask(trigger.buttonMask);
        if (!buttonInput.isButtonStreamReady()) {
            closeAutomaticGate("activation_trigger_stream_not_ready");
            return false;
        }
        if (!trigger.isSatisfiedBy(buttonInput.currentButtonMask())) {
            closeAutomaticGate("activation_trigger_released");
            return false;
        }
        return true;
    }

    private void onButtonMaskChanged(int completeButtonMask) {
        synchronized (this) {
            ControlTrigger trigger = profile.controlTrigger();
            events.write("control_trigger_state",
                    "trigger=" + trigger.storageToken
                            + " pressed=" + trigger.isSatisfiedBy(completeButtonMask)
                            + " complete_mask=" + completeButtonMask
                            + " physical_read_only=true");
            reconcileCachedState();
        }
    }

    private void reconcileCachedState() {
        reconcileAutomaticState(
                runtimeHealthy,
                nativeStateKnown,
                nativeRequested,
                nativeEffective,
                nativeRecoverySuspended);
    }

    private static String reportToken(String value) {
        if (value == null || value.isBlank()) return "none";
        return value.replace(' ', '_').replace('\r', '_').replace('\n', '_');
    }

    private synchronized void onReconnectResult(boolean succeeded) {
        boolean failedWhileActive = !succeeded
                && (automaticOutputRequested || outputEnabled || outputRecoverySuspended);
        if (failedWhileActive) automaticRetryDeferred = true;
        consecutiveReconnectFailures = succeeded
                ? 0
                : consecutiveReconnectFailures == Integer.MAX_VALUE
                        ? Integer.MAX_VALUE
                        : consecutiveReconnectFailures + 1;
        long retryDelayNanos = reconnectRetryDelayNanos(
                consecutiveReconnectFailures);
        nextOutputReconnectAttemptNanos = succeeded
                ? 0L : System.nanoTime() + retryDelayNanos;
        // A reconnect callback is a transport-generation boundary. Reassert
        // both gates even when the previous generation was already closed.
        closeAutomaticGate(
                succeeded ? "device_reconnected" : "device_reconnect_failed",
                true);
        if (!succeeded) {
            events.write("control_output_reconnect_failed",
                    "fail_closed=true automatic_retry=true consecutive_failures="
                            + consecutiveReconnectFailures
                            + " retry_delay_ms=" + retryDelayNanos / 1_000_000L
                            + " fresh_health_epoch_required=" + automaticRetryDeferred);
            return;
        }
        if (buttonInput != null) {
            buttonInput.setRequiredTriggerMask(profile.controlTrigger().buttonMask);
        }
        if (runtimeHealthy) {
            reconcileCachedState();
            return;
        }
        events.write("control_output_reconnected_waiting_runtime",
                "automatic_request=false output_enabled=false");
    }

    static long reconnectRetryDelayNanos(int consecutiveFailures) {
        int exponent = Math.max(0, Math.min(5, consecutiveFailures - 1));
        return Math.min(
                MAXIMUM_OUTPUT_RECONNECT_RETRY_NANOS,
                OUTPUT_RECONNECT_RETRY_NANOS << exponent);
    }
}
