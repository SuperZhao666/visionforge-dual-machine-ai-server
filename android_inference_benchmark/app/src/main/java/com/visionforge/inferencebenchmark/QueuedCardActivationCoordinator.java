package com.visionforge.inferencebenchmark;

import android.content.Context;

import com.visionforge.inferencebenchmark.ui.DualMachineAuthorizationUiState;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Owns the sealed card queue between UI submission and Host-authorized
 * activation.
 *
 * <p>The coordinator shares the service's single authorization-operation gate
 * and executor, so persistence, pending-confirmation replay and fresh
 * activation remain serialized with status/start/stop operations. Card text is
 * never logged and leaves this class only through the authorization runtime.</p>
 */
final class QueuedCardActivationCoordinator {
    private final Context context;
    private final AndroidPendingActivationStore store;
    private final Executor executor;
    private final AtomicBoolean operationInFlight;
    private final Supplier<DualMachineAuthorizationRuntime> runtimeSupplier;
    private final BooleanSupplier unavailable;
    private final Consumer<DualMachineAuthorizationUiState.Status>
            transientPublisher;
    private final Consumer<String> mappedPublisher;
    private final Function<Throwable, String> failureMessage;
    private final Runnable authenticatedControlScheduler;
    private final Runnable unavailablePublisher;
    private final MobileEventLogger events;
    private volatile boolean present;

    QueuedCardActivationCoordinator(
            Context context,
            AndroidPendingActivationStore store,
            Executor executor,
            AtomicBoolean operationInFlight,
            Supplier<DualMachineAuthorizationRuntime> runtimeSupplier,
            BooleanSupplier unavailable,
            Consumer<DualMachineAuthorizationUiState.Status>
                    transientPublisher,
            Consumer<String> mappedPublisher,
            Function<Throwable, String> failureMessage,
            Runnable authenticatedControlScheduler,
            Runnable unavailablePublisher,
            MobileEventLogger events) {
        this.context = Objects.requireNonNull(
                context, "context").getApplicationContext();
        this.store = Objects.requireNonNull(store, "store");
        this.executor = Objects.requireNonNull(executor, "executor");
        this.operationInFlight = Objects.requireNonNull(
                operationInFlight, "operationInFlight");
        this.runtimeSupplier = Objects.requireNonNull(
                runtimeSupplier, "runtimeSupplier");
        this.unavailable = Objects.requireNonNull(
                unavailable, "unavailable");
        this.transientPublisher = Objects.requireNonNull(
                transientPublisher, "transientPublisher");
        this.mappedPublisher = Objects.requireNonNull(
                mappedPublisher, "mappedPublisher");
        this.failureMessage = Objects.requireNonNull(
                failureMessage, "failureMessage");
        this.authenticatedControlScheduler = Objects.requireNonNull(
                authenticatedControlScheduler,
                "authenticatedControlScheduler");
        this.unavailablePublisher = Objects.requireNonNull(
                unavailablePublisher, "unavailablePublisher");
        this.events = Objects.requireNonNull(events, "events");
    }

    boolean restorePresence() {
        try {
            String queuedCard = store.loadQueuedCard();
            present = queuedCard != null;
            queuedCard = null;
        } catch (IOException | GeneralSecurityException
                 | RuntimeException failure) {
            present = false;
            events.write(
                    "dual_machine_queued_card_restore_failed",
                    "failure_type=" + failure.getClass().getSimpleName()
                            + " card_logged=false input_reenabled=true");
        }
        return present;
    }

    void reconcileAfterRuntimeRestore(
            DualMachineAuthorizationRuntime runtime) {
        if (runtime.snapshot().entitlement == null) return;
        present = false;
        try {
            store.clearQueuedCard();
        } catch (IOException | RuntimeException failure) {
            events.write(
                    "dual_machine_queued_card_cleanup_deferred",
                    "reason=entitlement_already_restored failure_type="
                            + failure.getClass().getSimpleName()
                            + " card_logged=false");
        }
    }

    boolean isPresent() {
        return present;
    }

    AndroidPendingActivationStore store() {
        return store;
    }

    DualMachineAuthorizationUiState unactivatedState() {
        return present
                ? DualMachineAuthorizationUiState.cardSavedWaitingForHost()
                : DualMachineAuthorizationUiState.readyForActivation();
    }

    void submit(String cardCode) {
        if (unavailable.getAsBoolean()) {
            unavailablePublisher.run();
            return;
        }
        final String canonicalCardCode;
        try {
            canonicalCardCode =
                    DualMachineCardCode.normalizeAndValidate(cardCode);
        } catch (IllegalArgumentException invalid) {
            mappedPublisher.accept(context.getString(
                    R.string.authorization_card_invalid));
            return;
        }
        if (!operationInFlight.compareAndSet(false, true)) {
            mappedPublisher.accept(context.getString(
                    R.string.authorization_operation_in_progress));
            return;
        }
        transientPublisher.accept(
                DualMachineAuthorizationUiState.Status.ACTIVATING);
        try {
            executor.execute(() -> saveAndActivate(canonicalCardCode));
        } catch (RuntimeException schedulingFailure) {
            operationInFlight.set(false);
            present = false;
            mappedPublisher.accept(context.getString(
                    R.string.authorization_operation_failed));
        }
    }

    private void saveAndActivate(String canonicalCardCode) {
        boolean saved = false;
        try {
            store.saveQueuedCard(canonicalCardCode);
            present = true;
            saved = true;
            events.write(
                    "dual_machine_card_queued",
                    "sealed_with_android_keystore=true "
                            + "card_logged=false automatic_resume=true");
            mappedPublisher.accept("");
        } catch (IOException | GeneralSecurityException
                 | RuntimeException failure) {
            present = false;
            events.write(
                    "dual_machine_card_queue_failed",
                    "failure_type=" + failure.getClass().getSimpleName()
                            + " card_logged=false input_reenabled=true");
            mappedPublisher.accept(context.getString(
                    R.string.authorization_operation_failed));
        } finally {
            operationInFlight.set(false);
        }
        if (saved) activateIfReady();
    }

    void onPairingAuthorizationStateChanged() {
        mappedPublisher.accept("");
        activateIfReady();
    }

    void activateIfReady() {
        DualMachineAuthorizationRuntime runtime = runtimeSupplier.get();
        if (unavailable.getAsBoolean() || !present || runtime == null
                || runtime.snapshot().entitlement != null
                || !runtime.hasCardActivationAuthority()
                || !operationInFlight.compareAndSet(false, true)) {
            return;
        }
        transientPublisher.accept(
                DualMachineAuthorizationUiState.Status.ACTIVATING);
        try {
            executor.execute(() -> activate(runtime));
        } catch (RuntimeException schedulingFailure) {
            operationInFlight.set(false);
            mappedPublisher.accept(context.getString(
                    R.string.authorization_operation_failed));
        }
    }

    private void activate(DualMachineAuthorizationRuntime runtime) {
        boolean activated = false;
        String cardCode = null;
        try {
            cardCode = store.loadQueuedCard();
            if (cardCode == null) {
                present = false;
                mappedPublisher.accept("");
                return;
            }
            if (runtime.snapshot().hasPendingActivationConfirmation()) {
                runtime.resumePendingActivation();
            } else {
                runtime.activateCard(cardCode);
            }
            store.clearQueuedCard();
            present = false;
            activated = true;
            events.write(
                    "dual_machine_queued_card_activation",
                    "result=success card_logged=false "
                            + "queued_card_cleared=true");
            mappedPublisher.accept("");
        } catch (IOException | GeneralSecurityException
                 | RuntimeException failure) {
            boolean discarded = failureIsPermanent(failure);
            if (discarded) {
                try {
                    store.clearQueuedCard();
                    present = false;
                } catch (IOException clearFailure) {
                    discarded = false;
                }
            }
            events.write(
                    "dual_machine_queued_card_activation",
                    "result=failed failure_type="
                            + failure.getClass().getSimpleName()
                            + " card_logged=false retained_for_retry="
                            + !discarded);
            mappedPublisher.accept(failureMessage.apply(failure));
        } finally {
            cardCode = null;
            operationInFlight.set(false);
        }
        if (activated) authenticatedControlScheduler.run();
    }

    private static boolean failureIsPermanent(Throwable failure) {
        if (!(failure instanceof DualMachineSidecarPort.RejectedException)) {
            return false;
        }
        String code = ((DualMachineSidecarPort.RejectedException) failure)
                .safeErrorCode;
        return "license_unavailable".equals(code)
                || "license_bound_to_another_device".equals(code)
                || "license_device_binding_inconsistent".equals(code);
    }
}
