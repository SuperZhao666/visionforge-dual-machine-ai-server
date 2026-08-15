package com.visionforge.inferencebenchmark;

import java.util.ArrayList;
import java.util.List;

/** Dependency-free contract for the selected automatic mouse-output gate. */
final class ControlOutputCoordinatorSelfTest {
    private static final int RECOVERY_STRESS_CYCLES = 256;
    private static final int ACK_FAILURE_INTERVAL_CYCLES = 4;
    private static final int RECONNECT_FAILURE_INTERVAL_CYCLES = 8;

    static void run() {
        verifiesHardwareAndRuntimeMustBothBeHealthy();
        verifiesDisconnectedTransportReconnectsWhileRuntimeLocked();
        verifiesHealthyChainAutomaticallyEnablesInSafeOrder();
        verifiesHotProfileChangeClosesDeliveryBeforeNativeResetAndRearms();
        verifiesHotProfileChangeDuringRecoveryStaysFailClosed();
        verifiesRejectedProfileFailsClosedAndAutomaticallyRetries();
        verifiesNativeRecoverySuspendsAndResumesAutomatically();
        verifiesLinkLossFailsClosedAndRecoveryAutomaticallyRearms();
        verifiesDeliveryFailureFailsClosedAndCircuitRequiresReconnect();
        verifiesAckFailureReconnectRearmsFreshTicket();
        verifiesMouse5AckTimeoutReconnectRestoresFreshTicket();
        verifiesSuccessfulReconnectAutomaticallyRearmsHealthyRuntime();
        verifiesReconnectBeforeRuntimeHealthStaysLocked();
        verifiesAlternatingClosedReasonsDoNotStormTheLog();
        verifiesRepeatedClosedStateDoesNotReapplyGates();
        verifiesReconnectGenerationForcesFreshClose();
        verifiesPhysicalTriggerPressAndReleaseGateOutput();
        verifiesSeparateOutputTransportCanUseMakcuButtonInput();
        verifiesNullTriggerCannotEnableAlwaysMode();
        verifiesExplicitAlwaysNeedsNoButtonStream();
        verifiesTargetProfileChangeFailsClosedAndAppliesModel();
        verifiesRepeatedHostPauseAckFailureAndModelSwitchAlwaysRearm();
        verifiesReconnectFailuresUseBoundedBackoff();
    }

    private static void verifiesReconnectFailuresUseBoundedBackoff() {
        require(ControlOutputCoordinator.reconnectRetryDelayNanos(0)
                == 1_000_000_000L);
        require(ControlOutputCoordinator.reconnectRetryDelayNanos(2)
                == 2_000_000_000L);
        require(ControlOutputCoordinator.reconnectRetryDelayNanos(5)
                == 16_000_000_000L);
        require(ControlOutputCoordinator.reconnectRetryDelayNanos(6)
                == 30_000_000_000L);
        require(ControlOutputCoordinator.reconnectRetryDelayNanos(Integer.MAX_VALUE)
                == 30_000_000_000L);
    }

    private static void verifiesHardwareAndRuntimeMustBothBeHealthy() {
        FakeMakcu makcu = new FakeMakcu(false);
        FakeProfile profile = new FakeProfile(true);
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(makcu, profile, events);

        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(makcu.connectionRequested);
        require(!coordinator.isOutputEnabled());
        require(!coordinator.isAutomaticOutputRequested());
        require(!makcu.outputDeliveryAllowed);

        makcu.ready = true;
        coordinator.reconcileAutomaticState(false, true, false, false, false);
        require(!coordinator.isOutputEnabled());
        require(!coordinator.isAutomaticOutputRequested());
        require(Boolean.FALSE.equals(profile.lastOutputEnabled));
    }

    private static void verifiesDisconnectedTransportReconnectsWhileRuntimeLocked() {
        FakeMakcu makcu = new FakeMakcu(false);
        FakeProfile profile = new FakeProfile(true);
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                makcu, profile, new FakeEvents());

        coordinator.reconcileAutomaticState(false, false, false, false, false);

        require(makcu.connectionRequested);
        require(!coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        require(!makcu.outputDeliveryAllowed);
        require(Boolean.FALSE.equals(profile.lastOutputEnabled));
    }

    private static void verifiesHealthyChainAutomaticallyEnablesInSafeOrder() {
        List<String> calls = new ArrayList<>();
        FakeMakcu makcu = new FakeMakcu(true, calls);
        FakeProfile profile = new FakeProfile(true, calls);
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(makcu, profile, events);

        calls.clear();
        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(coordinator.isAutomaticOutputRequested());
        require(coordinator.isOutputEnabled());
        require(makcu.outputDeliveryAllowed);
        require(calls.indexOf("profile:true") >= 0);
        require(calls.indexOf("makcu:true") > calls.indexOf("profile:true"));
        require(events.events.endsWith("control_output_auto_ready"));

        calls.clear();
        coordinator.reconcileAutomaticState(true, true, true, true, false);
        require(calls.isEmpty());
        require(coordinator.isOutputEnabled());
    }

    private static void verifiesRejectedProfileFailsClosedAndAutomaticallyRetries() {
        FakeMakcu makcu = new FakeMakcu(true);
        FakeProfile profile = new FakeProfile(false);
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(makcu, profile, events);

        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(!coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        require(!makcu.outputDeliveryAllowed);
        require(Boolean.FALSE.equals(profile.lastOutputEnabled));
        require(events.events.endsWith("control_output_auto_locked"));

        profile.acceptsOutput = true;
        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(coordinator.isAutomaticOutputRequested());
        require(coordinator.isOutputEnabled());
        require(makcu.outputDeliveryAllowed);
    }

    private static void verifiesHotProfileChangeClosesDeliveryBeforeNativeResetAndRearms() {
        List<String> calls = new ArrayList<>();
        FakeMakcu makcu = new FakeMakcu(true, calls);
        FakeProfile profile = new FakeProfile(true, calls);
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                makcu, profile, events);
        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(coordinator.isAutomaticOutputRequested());
        require(coordinator.isOutputEnabled());

        calls.clear();
        coordinator.setGain(0.40f);

        require(calls.equals(List.of(
                "makcu:false",
                "profile:false",
                "profile:true",
                "makcu:true")));
        require(coordinator.isAutomaticOutputRequested());
        require(coordinator.isOutputEnabled());
        require(makcu.outputDeliveryAllowed);
        require(events.lastDetail.contains("delivery_drained=true"));
        require(events.lastDetail.contains("native_ticket_reset=true"));
    }

    private static void verifiesNativeRecoverySuspendsAndResumesAutomatically() {
        FakeMakcu makcu = new FakeMakcu(true);
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                makcu, new FakeProfile(true), events);
        coordinator.reconcileAutomaticState(true, true, false, false, false);

        coordinator.reconcileAutomaticState(true, true, true, false, true);
        require(coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        require(coordinator.isOutputRecoverySuspended());
        require(makcu.outputDeliveryAllowed);
        require(events.events.endsWith("control_output_recovery_suspended"));

        coordinator.reconcileAutomaticState(true, true, true, true, false);
        require(coordinator.isAutomaticOutputRequested());
        require(coordinator.isOutputEnabled());
        require(!coordinator.isOutputRecoverySuspended());
        require(events.events.endsWith("control_output_recovery_resumed"));
    }

    private static void verifiesHotProfileChangeDuringRecoveryStaysFailClosed() {
        List<String> calls = new ArrayList<>();
        FakeMakcu makcu = new FakeMakcu(true, calls);
        FakeProfile profile = new FakeProfile(true, calls);
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                makcu, profile, events);
        coordinator.reconcileAutomaticState(true, true, false, false, false);
        coordinator.reconcileAutomaticState(true, true, true, false, true);
        require(coordinator.isOutputRecoverySuspended());

        calls.clear();
        coordinator.setGain(0.50f);

        require(calls.equals(List.of("makcu:false", "profile:false")));
        require(!coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        require(!coordinator.isOutputRecoverySuspended());
        require(!makcu.outputDeliveryAllowed);
        require(events.events.contains("control_output_auto_locked"));
    }

    private static void verifiesLinkLossFailsClosedAndRecoveryAutomaticallyRearms() {
        FakeMakcu makcu = new FakeMakcu(true);
        FakeProfile profile = new FakeProfile(true);
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(makcu, profile, events);
        coordinator.reconcileAutomaticState(true, true, false, false, false);

        coordinator.reconcileAutomaticState(false, true, true, true, false);
        require(!coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        require(!coordinator.isOutputRecoverySuspended());
        require(!makcu.outputDeliveryAllowed);
        require(Boolean.FALSE.equals(profile.lastOutputEnabled));
        require(events.events.endsWith("control_output_auto_locked"));

        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(coordinator.isAutomaticOutputRequested());
        require(coordinator.isOutputEnabled());
        require(makcu.outputDeliveryAllowed);
        require(events.events.endsWith("control_output_auto_ready"));
    }

    private static void verifiesDeliveryFailureFailsClosedAndCircuitRequiresReconnect() {
        FakeMakcu makcu = new FakeMakcu(true);
        FakeProfile profile = new FakeProfile(true);
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(makcu, profile, events);
        coordinator.reconcileAutomaticState(true, true, false, false, false);

        makcu.delivery = new MakcuDeliveryState(1L, 0L, 0L, 18L, 0, false, "");
        coordinator.reconcileDeliveryState();
        require(events.events.endsWith("control_output_usb_write_completed"));

        makcu.delivery = new MakcuDeliveryState(1L, 1L, 0L, 18L, 1, false, "timeout");
        coordinator.reconcileDeliveryState();
        require(!coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        require(!makcu.outputDeliveryAllowed);
        require(events.events.endsWith("control_output_delivery_failed"));

        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(!coordinator.isOutputEnabled());
        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(coordinator.isOutputEnabled());

        makcu.delivery = new MakcuDeliveryState(1L, 3L, 1L, 18L, 3, true, "timeout");
        coordinator.reconcileDeliveryState();
        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(!coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        require(!makcu.outputDeliveryAllowed);
        require(events.events.endsWith("control_output_delivery_circuit_open"));
    }

    private static void verifiesAckFailureReconnectRearmsFreshTicket() {
        List<String> calls = new ArrayList<>();
        FakeMakcu makcu = new FakeMakcu(true, calls);
        FakeProfile profile = new FakeProfile(true, calls);
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                makcu, profile, events);
        coordinator.reconcileAutomaticState(true, true, false, false, false);

        require(makcu.offerTicket(41L));
        makcu.failDeviceAcknowledgement();
        coordinator.reconcileDeliveryState();
        require(!coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        require(!makcu.offerTicket(42L));

        calls.clear();
        makcu.completeReconnect(false);
        require(!coordinator.isOutputEnabled());
        makcu.completeReconnect(true);

        require(!coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        require(!makcu.outputDeliveryAllowed);
        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(coordinator.isAutomaticOutputRequested());
        require(coordinator.isOutputEnabled());
        require(makcu.outputDeliveryAllowed);
        int profileEnabled = calls.lastIndexOf("profile:true");
        int deliveryEnabled = calls.lastIndexOf("makcu:true");
        require(profileEnabled >= 0 && deliveryEnabled > profileEnabled);
        require(makcu.offerTicket(43L));
        require(makcu.acceptedTickets.equals(List.of(41L, 43L)));
        require(events.events.endsWith("control_output_auto_ready"));
    }

    private static void verifiesMouse5AckTimeoutReconnectRestoresFreshTicket() {
        FakeMakcu makcu = new FakeMakcu(true);
        FakeProfile profile = new FakeProfile(true);
        profile.trigger = ControlTrigger.SIDE_BUTTON_2;
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                makcu, profile, events);

        makcu.completeButtonStreamConfiguration();
        makcu.publishButtonMask(ControlTrigger.SIDE_BUTTON_2.buttonMask);
        coordinator.reconcileAutomaticState(true, true, false, false, false);
        requireHealthyOutput(coordinator, makcu);
        require(makcu.offerTicket(101L));

        makcu.failDeviceAcknowledgement();
        coordinator.reconcileDeliveryState();
        requireClosedOutput(coordinator, makcu);
        require(!makcu.offerTicket(102L));

        makcu.completeReconnect(false);
        requireClosedOutput(coordinator, makcu);
        makcu.completeReconnect(true);
        requireClosedOutput(coordinator, makcu);
        require(makcu.requiredTriggerMask == ControlTrigger.SIDE_BUTTON_2.buttonMask);
        require(!makcu.buttonStreamReady);

        makcu.completeButtonStreamConfiguration();
        makcu.publishButtonMask(ControlTrigger.SIDE_BUTTON_2.buttonMask);
        requireClosedOutput(coordinator, makcu);
        require(events.events.endsWith("control_output_retry_deferred"));

        coordinator.reconcileAutomaticState(true, true, false, false, false);
        requireHealthyOutput(coordinator, makcu);
        require(makcu.offerTicket(103L));
        require(makcu.acceptedTickets.equals(List.of(101L, 103L)));
    }

    private static void verifiesSuccessfulReconnectAutomaticallyRearmsHealthyRuntime() {
        FakeMakcu makcu = new FakeMakcu(true);
        FakeProfile profile = new FakeProfile(true);
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(makcu, profile, events);
        coordinator.reconcileAutomaticState(true, true, false, false, false);

        makcu.completeReconnect(false);
        require(!coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        require(events.events.endsWith("control_output_reconnect_failed"));

        makcu.completeReconnect(true);
        require(!coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(coordinator.isAutomaticOutputRequested());
        require(coordinator.isOutputEnabled());
        require(makcu.outputDeliveryAllowed);
        require(events.events.endsWith("control_output_auto_ready"));
    }

    private static void verifiesReconnectBeforeRuntimeHealthStaysLocked() {
        FakeMakcu makcu = new FakeMakcu(false);
        FakeProfile profile = new FakeProfile(true);
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(makcu, profile, events);

        makcu.completeReconnect(true);
        require(!coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        require(!makcu.outputDeliveryAllowed);
        require(Boolean.FALSE.equals(profile.lastOutputEnabled));
        require(events.events.endsWith("control_output_reconnected_waiting_runtime"));
    }

    private static void verifiesAlternatingClosedReasonsDoNotStormTheLog() {
        FakeMakcu makcu = new FakeMakcu(true);
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                makcu, new FakeProfile(true), events);

        coordinator.failClosed("runtime_unhealthy");
        coordinator.failClosed("formal_usage_closed");
        coordinator.failClosed("runtime_unhealthy");
        coordinator.failClosed("formal_usage_closed");
        require(events.count("control_output_auto_locked") == 2);

        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(coordinator.isOutputEnabled());
        coordinator.failClosed("runtime_unhealthy");
        require(events.count("control_output_auto_locked") == 3);
    }

    private static void verifiesRepeatedClosedStateDoesNotReapplyGates() {
        List<String> calls = new ArrayList<>();
        FakeMakcu makcu = new FakeMakcu(true, calls);
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                makcu, new FakeProfile(true, calls), new FakeEvents());

        require(calls.equals(List.of("makcu:false", "profile:false")));
        calls.clear();
        coordinator.failClosed("runtime_unhealthy");
        coordinator.failClosed("formal_usage_closed");
        coordinator.reconcileAutomaticState(
                false, false, false, false, false);
        require(calls.isEmpty());

        coordinator.reconcileAutomaticState(
                true, true, false, false, false);
        require(calls.equals(List.of("profile:true", "makcu:true")));
        calls.clear();
        coordinator.failClosed("runtime_unhealthy");
        require(calls.equals(List.of("makcu:false", "profile:false")));
        calls.clear();
        coordinator.failClosed("formal_usage_closed");
        coordinator.failClosed("runtime_unhealthy");
        require(calls.isEmpty());
    }

    private static void verifiesReconnectGenerationForcesFreshClose() {
        List<String> calls = new ArrayList<>();
        FakeMakcu makcu = new FakeMakcu(false, calls);
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                makcu, new FakeProfile(true, calls), new FakeEvents());

        calls.clear();
        coordinator.failClosed("runtime_unhealthy");
        require(calls.isEmpty());
        makcu.completeReconnect(true);
        require(calls.equals(List.of("makcu:false", "profile:false")));
        requireClosedOutput(coordinator, makcu);
    }

    private static void verifiesPhysicalTriggerPressAndReleaseGateOutput() {
        FakeMakcu makcu = new FakeMakcu(true);
        FakeProfile profile = new FakeProfile(true);
        profile.trigger = ControlTrigger.SIDE_BUTTON_2;
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                makcu, profile, new FakeEvents());

        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(makcu.requiredTriggerMask == ControlTrigger.SIDE_BUTTON_2.buttonMask);
        require(!coordinator.isOutputEnabled());

        makcu.completeButtonStreamConfiguration();
        makcu.publishButtonMask(0x10);
        require(coordinator.isOutputEnabled());
        require(coordinator.isControlTriggerPressed());

        makcu.publishButtonMask(0x00);
        require(!coordinator.isOutputEnabled());
        require(!makcu.outputDeliveryAllowed);
        require(!coordinator.isControlTriggerPressed());
    }

    private static void verifiesSeparateOutputTransportCanUseMakcuButtonInput() {
        FakeTransport bluetooth = new FakeTransport(true);
        FakeMakcu makcuButtons = new FakeMakcu(true);
        FakeProfile profile = new FakeProfile(true);
        profile.trigger = ControlTrigger.SIDE_BUTTON_2;
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                bluetooth, makcuButtons, profile, new FakeEvents());

        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(makcuButtons.requiredTriggerMask == ControlTrigger.SIDE_BUTTON_2.buttonMask);
        require(!coordinator.isOutputEnabled());
        require(!bluetooth.outputDeliveryAllowed);
        require(!makcuButtons.outputDeliveryAllowed);

        makcuButtons.completeButtonStreamConfiguration();
        makcuButtons.publishButtonMask(ControlTrigger.SIDE_BUTTON_2.buttonMask);

        require(coordinator.isOutputEnabled());
        require(coordinator.isControlTriggerPressed());
        require(bluetooth.outputDeliveryAllowed);
        require(!makcuButtons.outputDeliveryAllowed);
    }

    private static void verifiesNullTriggerCannotEnableAlwaysMode() {
        FakeMakcu makcu = new FakeMakcu(true);
        FakeProfile profile = new FakeProfile(true);
        profile.trigger = ControlTrigger.SIDE_BUTTON_2;
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                makcu, profile, new FakeEvents());

        coordinator.setControlTrigger(null);

        require(profile.trigger == ControlTrigger.SIDE_BUTTON_2);
        require(makcu.requiredTriggerMask == ControlTrigger.SIDE_BUTTON_2.buttonMask);
        require(!coordinator.isOutputEnabled());
    }

    private static void verifiesExplicitAlwaysNeedsNoButtonStream() {
        FakeMakcu makcu = new FakeMakcu(true);
        FakeProfile profile = new FakeProfile(true);
        profile.trigger = ControlTrigger.SIDE_BUTTON_2;
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                makcu, profile, new FakeEvents());

        coordinator.setControlTrigger(ControlTrigger.ALWAYS);
        coordinator.reconcileAutomaticState(true, true, false, false, false);

        require(profile.trigger == ControlTrigger.ALWAYS);
        require(makcu.requiredTriggerMask == 0);
        require(!makcu.buttonStreamReady);
        require(coordinator.isControlTriggerPressed());
        require(coordinator.isControlTriggerStreamReady());
        require(coordinator.isOutputEnabled());
        require(makcu.outputDeliveryAllowed);
    }

    private static void verifiesTargetProfileChangeFailsClosedAndAppliesModel() {
        FakeMakcu makcu = new FakeMakcu(true);
        FakeProfile profile = new FakeProfile(true);
        FakeEvents events = new FakeEvents();
        ControlOutputCoordinator coordinator =
                new ControlOutputCoordinator(makcu, profile, events);

        coordinator.reconcileAutomaticState(true, true, false, false, false);
        require(coordinator.isAutomaticOutputRequested());
        require(coordinator.isOutputEnabled());
        require(makcu.outputDeliveryAllowed);

        coordinator.selectTargetProfile(
                MobileModelCatalog.OVERWATCH_2, MobileAimTarget.HEAD);

        require(!coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        require(!makcu.outputDeliveryAllowed);
        require(Boolean.FALSE.equals(profile.lastOutputEnabled));
        require(profile.selectedModel == MobileModelCatalog.OVERWATCH_2);
        require(profile.selectedAimTarget == MobileAimTarget.HEAD);
        require(profile.selectTargetProfileCalls == 1);
        require(events.events.contains("control_output_auto_locked"));
        require(events.events.endsWith("control_profile_applied"));
    }

    private static void verifiesRepeatedHostPauseAckFailureAndModelSwitchAlwaysRearm() {
        FakeMakcu makcu = new FakeMakcu(true);
        FakeProfile profile = new FakeProfile(true);
        ControlOutputCoordinator coordinator = new ControlOutputCoordinator(
                makcu, profile, new FakeEvents());
        long ticket = 1_000L;
        int successfulOffers = 0;

        coordinator.reconcileAutomaticState(true, true, false, false, false);
        for (int cycle = 0; cycle < RECOVERY_STRESS_CYCLES; cycle++) {
            requireHealthyOutput(coordinator, makcu);
            require(makcu.offerTicket(++ticket));
            successfulOffers++;

            if (cycle % ACK_FAILURE_INTERVAL_CYCLES == 0) {
                makcu.failDeviceAcknowledgement();
                coordinator.reconcileDeliveryState();
                requireClosedOutput(coordinator, makcu);
                require(!makcu.offerTicket(++ticket));
                if (cycle % RECONNECT_FAILURE_INTERVAL_CYCLES == 0) {
                    makcu.completeReconnect(false);
                }
                makcu.completeReconnect(true);
                coordinator.reconcileAutomaticState(true, true, false, false, false);
                requireHealthyOutput(coordinator, makcu);
                require(makcu.offerTicket(++ticket));
                successfulOffers++;
            }

            MobileModelCatalog.Profile selected = MobileModelCatalog.ALL[
                    cycle % MobileModelCatalog.ALL.length];
            coordinator.selectTargetProfile(selected, selected.defaultAimTarget);
            requireClosedOutput(coordinator, makcu);
            coordinator.reconcileAutomaticState(true, true, false, false, false);
            requireHealthyOutput(coordinator, makcu);
            require(profile.selectedModel == selected);

            coordinator.reconcileAutomaticState(false, true, false, false, false);
            requireClosedOutput(coordinator, makcu);
            coordinator.reconcileAutomaticState(true, false, false, false, false);
            requireClosedOutput(coordinator, makcu);
            coordinator.reconcileAutomaticState(true, true, false, false, false);
            requireHealthyOutput(coordinator, makcu);
            require(makcu.offerTicket(++ticket));
            successfulOffers++;
        }
        require(successfulOffers == makcu.acceptedTickets.size());
        require(successfulOffers > RECOVERY_STRESS_CYCLES * 2);
    }

    private static void requireHealthyOutput(
            ControlOutputCoordinator coordinator, FakeMakcu makcu) {
        require(coordinator.isAutomaticOutputRequested());
        require(coordinator.isOutputEnabled());
        require(makcu.outputDeliveryAllowed);
    }

    private static void requireClosedOutput(
            ControlOutputCoordinator coordinator, FakeMakcu makcu) {
        require(!coordinator.isAutomaticOutputRequested());
        require(!coordinator.isOutputEnabled());
        require(!makcu.outputDeliveryAllowed);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Automatic control output gate contract failed");
    }

    private static final class FakeTransport implements ControlOutputTransport {
        private boolean ready;
        private boolean outputDeliveryAllowed;
        private MakcuDeliveryState delivery = new MakcuDeliveryState(
                0L, 0L, 0L, 0L, 0, false, "");

        FakeTransport(boolean ready) {
            this.ready = ready;
        }

        @Override public boolean isReady() { return ready; }
        @Override public void connectFirstSupportedDevice() { }
        @Override public void setReconnectListener(ReconnectListener listener) { }
        @Override public boolean setOutputDeliveryAllowed(boolean allowed) {
            if (allowed && (delivery.circuitOpen || !ready)) return false;
            outputDeliveryAllowed = allowed;
            return true;
        }
        @Override public MakcuDeliveryState deliveryState() { return delivery; }
    }

    private static final class FakeMakcu implements MakcuConnection, MakcuButtonInput {
        private boolean ready;
        private boolean connectionRequested;
        private boolean outputDeliveryAllowed;
        private boolean acceptsDeliveryEnable = true;
        private final List<String> calls;
        private ReconnectListener reconnectListener;
        private MakcuButtonInput.Listener buttonListener;
        private int requiredTriggerMask;
        private boolean buttonStreamReady;
        private int buttonMask;
        private final List<Long> acceptedTickets = new ArrayList<>();
        private MakcuDeliveryState delivery = new MakcuDeliveryState(
                0L, 0L, 0L, 0L, 0, false, "");

        FakeMakcu(boolean ready) { this(ready, null); }
        FakeMakcu(boolean ready, List<String> calls) {
            this.ready = ready;
            this.calls = calls;
        }
        @Override public boolean isReady() { return ready; }
        @Override public void connectFirstSupportedDevice() { connectionRequested = true; }
        @Override public void setReconnectListener(ReconnectListener listener) {
            reconnectListener = listener;
        }
        @Override public boolean setOutputDeliveryAllowed(boolean allowed) {
            if (calls != null) calls.add("makcu:" + allowed);
            if (allowed && (delivery.circuitOpen || !acceptsDeliveryEnable)) return false;
            outputDeliveryAllowed = allowed;
            return true;
        }
        @Override public MakcuDeliveryState deliveryState() { return delivery; }
        @Override public void setButtonStateListener(MakcuButtonInput.Listener listener) {
            buttonListener = listener;
        }
        @Override public void setRequiredTriggerMask(int requiredButtonMask) {
            requiredTriggerMask = requiredButtonMask;
            if (requiredButtonMask == 0) buttonStreamReady = false;
        }
        @Override public int currentButtonMask() { return buttonMask; }
        @Override public boolean isButtonStreamReady() { return buttonStreamReady; }

        void completeButtonStreamConfiguration() {
            buttonStreamReady = requiredTriggerMask != 0;
            if (buttonListener != null) buttonListener.onButtonMaskChanged(buttonMask);
        }

        void publishButtonMask(int mask) {
            buttonMask = mask;
            if (buttonListener != null) buttonListener.onButtonMaskChanged(mask);
        }

        boolean offerTicket(long ticket) {
            if (ticket <= 0L || !ready || !outputDeliveryAllowed || delivery.circuitOpen) {
                return false;
            }
            acceptedTickets.add(ticket);
            return true;
        }

        void failDeviceAcknowledgement() {
            ready = false;
            buttonStreamReady = false;
            outputDeliveryAllowed = false;
            delivery = new MakcuDeliveryState(
                    delivery.usbWriteCompletionCount,
                    delivery.failureCount + 1L,
                    delivery.circuitTripCount,
                    delivery.lastUsbWriteCallMicros,
                    delivery.consecutiveFailures + 1,
                    false,
                    "device_ack_timeout_or_mismatch");
            if (reconnectListener != null) reconnectListener.onReconnectResult(false);
        }

        void completeReconnect(boolean succeeded) {
            outputDeliveryAllowed = false;
            ready = succeeded;
            buttonStreamReady = false;
            buttonMask = 0;
            if (succeeded) {
                delivery = new MakcuDeliveryState(delivery.usbWriteCompletionCount,
                        delivery.failureCount, delivery.circuitTripCount,
                        delivery.lastUsbWriteCallMicros, 0, false, "");
            }
            reconnectListener.onReconnectResult(succeeded);
        }
    }

    private static final class FakeProfile implements ControlProfilePort {
        @Override
        public void selectTargetProfile(
                MobileModelCatalog.Profile model, MobileAimTarget aimTarget) {
            selectedModel = model;
            selectedAimTarget = aimTarget;
            selectTargetProfileCalls++;
        }

        private boolean acceptsOutput;
        private Boolean lastOutputEnabled;
        private MobileModelCatalog.Profile selectedModel;
        private MobileAimTarget selectedAimTarget;
        private int selectTargetProfileCalls;
        private final List<String> calls;
        private ControlTrigger trigger = ControlTrigger.ALWAYS;

        FakeProfile(boolean acceptsOutput) { this(acceptsOutput, null); }
        FakeProfile(boolean acceptsOutput, List<String> calls) {
            this.acceptsOutput = acceptsOutput;
            this.calls = calls;
        }
        @Override public void setGain(float value) { }
        @Override public void setDeadzone(float value) { }
        @Override public void setMaximumAxisDelta(int value) { }
        @Override public void setSwitchConfirmationMillis(int value) { }
        @Override public void setValues(float gain, float deadzonePixels,
                                        int maximumAxisDelta,
                                        int switchConfirmationMillis) { }
        @Override public float gain() { return 0.10f; }
        @Override public float deadzonePixels() { return 2.0f; }
        @Override public int maximumAxisDelta() { return 127; }
        @Override public int switchConfirmationMillis() { return 25; }
        @Override public void setControlTrigger(ControlTrigger trigger) {
            this.trigger = trigger;
        }
        @Override public ControlTrigger controlTrigger() { return trigger; }
        @Override public void setPersonalTrajectoryEnabled(boolean enabled) { }
        @Override public void setPersonalTrajectoryScales(
                float speedScale, float stabilityScale, float variationScale) { }
        @Override public boolean importPersonalTrajectory(String profileJson) { return true; }
        @Override public boolean personalTrajectoryEnabled() { return false; }
        @Override public String personalTrajectoryProfileId() { return ""; }
        @Override public float personalTrajectorySpeedScale() { return 1.0f; }
        @Override public float personalTrajectoryStabilityScale() { return 1.0f; }
        @Override public float personalTrajectoryVariationScale() { return 1.0f; }
        @Override public boolean apply(boolean outputEnabled) {
            if (calls != null) calls.add("profile:" + outputEnabled);
            lastOutputEnabled = outputEnabled;
            return !outputEnabled || acceptsOutput;
        }
    }

    private static final class FakeEvents implements MobileRuntimeEventSink {
        private String events = "";
        private String lastDetail = "";
        @Override public void write(String event, String detail) {
            events = events.isEmpty() ? event : events + "," + event;
            lastDetail = detail;
        }
        int count(String expected) {
            if (events.isEmpty()) return 0;
            int matches = 0;
            for (String event : events.split(",")) {
                if (expected.equals(event)) matches++;
            }
            return matches;
        }
    }
}
