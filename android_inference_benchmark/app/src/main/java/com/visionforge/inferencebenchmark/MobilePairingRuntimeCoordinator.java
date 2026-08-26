package com.visionforge.inferencebenchmark;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlTcpChannelV1;
import com.visionforge.inferencebenchmark.runtime.FirstPairingUiState;
import com.visionforge.inferencebenchmark.runtime.MobileFirstPairingObserver;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.IntConsumer;
import java.util.function.Supplier;

/**
 * Owns first-pairing presentation and the process-local authenticated Host
 * control session.
 *
 * <p>The service still owns formal authorization and the data-plane gate. This
 * coordinator may only hand a mutually authenticated Host capability back to
 * that boundary.</p>
 */
final class MobilePairingRuntimeCoordinator {
    private static final String ACTION_CONFIRM_FIRST_PAIR =
            "com.visionforge.inferencebenchmark.action.CONFIRM_FIRST_PAIR";
    private static final String ACTION_REJECT_FIRST_PAIR =
            "com.visionforge.inferencebenchmark.action.REJECT_FIRST_PAIR";
    private static final String NOTIFICATION_CHANNEL =
            "visionforge_first_pairing";
    private static final long RETRY_BACKOFF_MILLIS = 2_000L;

    @FunctionalInterface
    interface HostAttachment {
        void attach(
                DualMachineCardAuthorizationCoordinator.IdentityBinding
                        hostIdentity,
                String channelBindingSha256,
                BooleanSupplier authenticatedSource);
    }

    private static final class PendingConfirmation {
        final String decimalSas;
        final String hostIpv4;
        final long expiresAtEpoch;
        final CompletableFuture<Boolean> decision = new CompletableFuture<>();

        PendingConfirmation(
                String decimalSas,
                String hostIpv4,
                long expiresAtEpoch) {
            this.decimalSas = decimalSas;
            this.hostIpv4 = hostIpv4;
            this.expiresAtEpoch = expiresAtEpoch;
        }
    }

    private final Context context;
    private final int notificationId;
    private final MobileRuntimeEventSink events;
    private final BooleanSupplier destroying;
    private final Supplier<DualMachineAuthorizationRuntime> runtimeSupplier;
    private final Supplier<MobileTransportEndpoint> endpointSupplier;
    private final Supplier<MobileControlRuntime> controlRuntimeSupplier;
    private final Supplier<MobilePipelineCoordinator> pipelineSupplier;
    private final HostAttachment hostAttachment;
    private final Runnable authorizationStatePublisher;
    private final IntConsumer notificationUpdater;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService executor =
            Executors.newSingleThreadExecutor(runnable -> {
                Thread thread = new Thread(
                        runnable, "visionforge-mobile-first-pairing");
                thread.setDaemon(false);
                return thread;
            });
    private final AtomicBoolean firstPairingAttemptInFlight =
            new AtomicBoolean();
    private final AtomicLong nextFirstPairingAttemptElapsedMillis =
            new AtomicLong();
    private final AtomicBoolean authenticatedControlAttemptInFlight =
            new AtomicBoolean();
    private final AtomicLong nextAuthenticatedControlAttemptElapsedMillis =
            new AtomicLong();
    private final PairGenerationChallengeReplayPolicy replayPolicy;
    private final AtomicReference<PendingConfirmation> pendingConfirmation =
            new AtomicReference<>();

    private volatile MobileFirstPairingObserver observer;
    private volatile FirstPairingUiState uiState = FirstPairingUiState.none();
    private volatile AndroidPairingIdentityStore identityStore;
    private volatile DualMachineCardAuthorizationCoordinator.IdentityBinding
            androidIdentity;
    private volatile AndroidFirstPairingCoordinatorV1 activeFirstPairing;
    private volatile AndroidBoundAuthenticatedControlCoordinatorV1
            activeAuthenticatedControl;

    MobilePairingRuntimeCoordinator(
            Context context,
            int notificationId,
            MobileRuntimeEventSink events,
            BooleanSupplier destroying,
            Supplier<DualMachineAuthorizationRuntime> runtimeSupplier,
            Supplier<MobileTransportEndpoint> endpointSupplier,
            Supplier<MobileControlRuntime> controlRuntimeSupplier,
            Supplier<MobilePipelineCoordinator> pipelineSupplier,
            HostAttachment hostAttachment,
            Runnable authorizationStatePublisher,
            IntConsumer notificationUpdater,
            PairGenerationChallengeReplayPolicy.IdGenerator idGenerator) {
        if (context == null || events == null || destroying == null
                || runtimeSupplier == null || endpointSupplier == null
                || controlRuntimeSupplier == null || pipelineSupplier == null
                || hostAttachment == null
                || authorizationStatePublisher == null
                || notificationUpdater == null || idGenerator == null) {
            throw new IllegalArgumentException(
                    "mobile pairing runtime dependencies are required");
        }
        this.context = context;
        this.notificationId = notificationId;
        this.events = events;
        this.destroying = destroying;
        this.runtimeSupplier = runtimeSupplier;
        this.endpointSupplier = endpointSupplier;
        this.controlRuntimeSupplier = controlRuntimeSupplier;
        this.pipelineSupplier = pipelineSupplier;
        this.hostAttachment = hostAttachment;
        this.authorizationStatePublisher = authorizationStatePublisher;
        this.notificationUpdater = notificationUpdater;
        replayPolicy = new PairGenerationChallengeReplayPolicy(idGenerator);
    }

    void configureIdentity(
            AndroidPairingIdentityStore identityStore,
            DualMachineCardAuthorizationCoordinator.IdentityBinding
                    androidIdentity) {
        this.identityStore = identityStore;
        this.androidIdentity = androidIdentity;
    }

    void clearIdentity() {
        identityStore = null;
        androidIdentity = null;
    }

    void setObserver(MobileFirstPairingObserver nextObserver) {
        observer = nextObserver;
        if (nextObserver != null) {
            postUpdate(nextObserver, uiState);
        }
    }

    void clearObserver() {
        observer = null;
    }

    FirstPairingUiState state() {
        return uiState;
    }

    boolean handleAction(String action) {
        if (!ACTION_CONFIRM_FIRST_PAIR.equals(action)
                && !ACTION_REJECT_FIRST_PAIR.equals(action)) {
            return false;
        }
        confirm(ACTION_CONFIRM_FIRST_PAIR.equals(action));
        return true;
    }

    void confirm(boolean matchingCodes) {
        PendingConfirmation pending = pendingConfirmation.get();
        if (pending != null) pending.decision.complete(matchingCodes);
    }

    void scheduleFirstPairingIfNeeded() {
        if (destroying.getAsBoolean() || firstPairingAttemptInFlight.get()) {
            return;
        }
        DualMachineAuthorizationRuntime runtime = runtimeSupplier.get();
        AndroidPairingIdentityStore currentIdentityStore = identityStore;
        DualMachineCardAuthorizationCoordinator.IdentityBinding
                currentAndroidIdentity = androidIdentity;
        if (runtime == null || currentIdentityStore == null
                || currentAndroidIdentity == null
                || runtime.hasAuthenticatedHost()
                || runtime.snapshot().entitlement != null) {
            return;
        }
        AndroidFirstPairingCoordinatorV1 active = activeFirstPairing;
        if (active != null && active.isInstalled()) return;
        long now = SystemClock.elapsedRealtime();
        if (now < nextFirstPairingAttemptElapsedMillis.get()) return;
        MobileTransportEndpoint endpoint = endpointSupplier.get();
        if (endpoint == null || !endpoint.isReadyForDataPlane()
                || !firstPairingAttemptInFlight.compareAndSet(false, true)) {
            return;
        }
        try {
            executor.execute(() -> runFirstPairing(
                    endpoint,
                    runtime,
                    currentIdentityStore,
                    currentAndroidIdentity));
        } catch (RuntimeException schedulingFailure) {
            firstPairingAttemptInFlight.set(false);
            nextFirstPairingAttemptElapsedMillis.set(
                    now + RETRY_BACKOFF_MILLIS);
        }
    }

    private void runFirstPairing(
            MobileTransportEndpoint endpoint,
            DualMachineAuthorizationRuntime runtime,
            AndroidPairingIdentityStore currentIdentityStore,
            DualMachineCardAuthorizationCoordinator.IdentityBinding
                    currentAndroidIdentity) {
        AndroidFirstPairingCoordinatorV1 coordinator = null;
        try {
            coordinator = new AndroidFirstPairingCoordinatorV1(
                    endpoint,
                    runtime,
                    currentIdentityStore,
                    currentAndroidIdentity,
                    this::awaitConfirmation);
            activeFirstPairing = coordinator;
            coordinator.connectConfirmAndInstall();
            events.write(
                    "dual_machine_first_pairing_ready_for_activation",
                    "two_sided_user_confirmation=true data_plane_open=false");
            authorizationStatePublisher.run();
        } catch (IOException | GeneralSecurityException
                 | InterruptedException | RuntimeException failure) {
            if (failure instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            if (coordinator != null) coordinator.close();
            if (activeFirstPairing == coordinator) activeFirstPairing = null;
            nextFirstPairingAttemptElapsedMillis.set(
                    SystemClock.elapsedRealtime() + RETRY_BACKOFF_MILLIS);
            events.write(
                    "dual_machine_first_pairing_attempt_failed",
                    firstPairingFailureDetail(failure, coordinator));
        } finally {
            firstPairingAttemptInFlight.set(false);
        }
    }

    void scheduleAuthenticatedControlIfNeeded() {
        if (destroying.getAsBoolean()
                || authenticatedControlAttemptInFlight.get()) {
            return;
        }
        DualMachineAuthorizationRuntime runtime = runtimeSupplier.get();
        AndroidPairingIdentityStore currentIdentityStore = identityStore;
        if (runtime == null || currentIdentityStore == null
                || runtime.hasAuthenticatedHost()) {
            return;
        }
        AndroidBoundAuthenticatedControlCoordinatorV1 active =
                activeAuthenticatedControl;
        if (active != null && active.isAuthenticated()) return;
        DualMachineEntitlementRecord entitlement = runtime.snapshot().entitlement;
        if (entitlement == null || entitlement.revoked
                || !entitlement.hasActivePairSecurityBinding()) {
            return;
        }
        long now = SystemClock.elapsedRealtime();
        if (now < nextAuthenticatedControlAttemptElapsedMillis.get()) return;
        MobileTransportEndpoint endpoint = endpointSupplier.get();
        if (endpoint == null || !endpoint.isReadyForDataPlane()
                || !authenticatedControlAttemptInFlight.compareAndSet(
                        false, true)) {
            return;
        }
        try {
            executor.execute(() -> runAuthenticatedControl(
                    endpoint, entitlement, currentIdentityStore));
        } catch (RuntimeException schedulingFailure) {
            authenticatedControlAttemptInFlight.set(false);
            nextAuthenticatedControlAttemptElapsedMillis.set(
                    now + RETRY_BACKOFF_MILLIS);
        }
    }

    private void runAuthenticatedControl(
            MobileTransportEndpoint endpoint,
            DualMachineEntitlementRecord entitlement,
            AndroidPairingIdentityStore currentIdentityStore) {
        AndroidBoundAuthenticatedControlCoordinatorV1 coordinator = null;
        PairGenerationChallengeReplayPolicy.Attempt replayAttempt = null;
        try {
            DualMachineReleaseSecurityConfig.Material security =
                    DualMachineReleaseSecurityConfig.load(
                            context.getApplicationContext());
            replayAttempt = replayPolicy.begin(
                    entitlement.pairId,
                    System.currentTimeMillis() / 1_000L);
            coordinator = new AndroidBoundAuthenticatedControlCoordinatorV1(
                    endpoint,
                    entitlement,
                    currentIdentityStore,
                    security.sidecar,
                    security.pairGenerationCredentialVerifier,
                    replayAttempt::nextHex128);
            activeAuthenticatedControl = coordinator;
            coordinator.connectAndAuthenticate();
            replayPolicy.succeeded(replayAttempt);
            hostAttachment.attach(
                    coordinator.hostIdentityBinding(),
                    coordinator.channelBindingLowercaseHex(),
                    coordinator::isAuthenticated);
            boolean mouseSessionInstalled = coordinator.installMouseSession(
                    controlRuntimeSupplier.get());
            boolean dataPlaneSessionInstalled = coordinator.installDataPlaneSession(
                    pipelineSupplier.get());
            if (!dataPlaneSessionInstalled) {
                throw new GeneralSecurityException(
                        "VFA2 data-plane session install failed");
            }
            events.write(
                    "dual_machine_bound_peer_handshake_ready",
                    "peer_finished=true generation_persisted_by_host=true "
                            + "mouse_session_installed="
                            + mouseSessionInstalled
                            + " vfa2_session_installed="
                            + dataPlaneSessionInstalled
                            + " raw_lease_installed=false "
                            + "data_plane_open=false");
            authorizationStatePublisher.run();
        } catch (IOException | GeneralSecurityException
                 | RuntimeException failure) {
            handleAuthenticatedControlFailure(
                    failure, coordinator, replayAttempt);
        } finally {
            authenticatedControlAttemptInFlight.set(false);
        }
    }

    private void handleAuthenticatedControlFailure(
            Throwable failure,
            AndroidBoundAuthenticatedControlCoordinatorV1 coordinator,
            PairGenerationChallengeReplayPolicy.Attempt replayAttempt) {
        String failureStage = coordinator == null
                ? "" : coordinator.diagnosticStage();
        long failureEpoch = System.currentTimeMillis() / 1_000L;
        if (coordinator != null && replayAttempt != null) {
            replayPolicy.challengeIssued(
                    replayAttempt,
                    coordinator.pairGenerationChallengeExpiresAtEpoch(),
                    failureEpoch);
            replayPolicy.failed(replayAttempt, failureStage, failureEpoch);
        }
        if (coordinator != null) coordinator.close();
        MobilePipelineCoordinator currentPipeline = pipelineSupplier.get();
        if (currentPipeline != null) currentPipeline.clearConfirmedPeerSession();
        if (activeAuthenticatedControl == coordinator) {
            activeAuthenticatedControl = null;
        }
        nextAuthenticatedControlAttemptElapsedMillis.set(
                SystemClock.elapsedRealtime() + RETRY_BACKOFF_MILLIS);
        events.write(
                "dual_machine_bound_peer_handshake_failed",
                "failure_type=" + failure.getClass().getSimpleName()
                        + (failureStage.isEmpty()
                                ? ""
                                : " handshake_stage=" + failureStage)
                        + " data_plane_open=false");
    }

    AndroidBoundAuthenticatedControlCoordinatorV1 authenticatedControl() {
        return activeAuthenticatedControl;
    }

    String authenticatedControlDiagnosticStage() {
        AndroidBoundAuthenticatedControlCoordinatorV1 current =
                activeAuthenticatedControl;
        return current == null ? "unavailable" : current.diagnosticStage();
    }

    private boolean awaitConfirmation(
            String decimalSas,
            String hostIpv4,
            long expiresAtEpoch) throws InterruptedException {
        PendingConfirmation pending = new PendingConfirmation(
                decimalSas, hostIpv4, expiresAtEpoch);
        if (!pendingConfirmation.compareAndSet(null, pending)) return false;
        publishState(FirstPairingUiState.pending(
                decimalSas, hostIpv4, expiresAtEpoch));
        NotificationManager manager =
                context.getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(notificationId, pairingNotification(pending));
        }
        try {
            long remainingSeconds = Math.max(
                    1L,
                    Math.min(
                            300L,
                            expiresAtEpoch
                                    - System.currentTimeMillis() / 1_000L));
            return pending.decision.get(remainingSeconds, TimeUnit.SECONDS);
        } catch (ExecutionException | TimeoutException failure) {
            return false;
        } finally {
            pendingConfirmation.compareAndSet(pending, null);
            publishState(FirstPairingUiState.none());
            notificationUpdater.accept(R.string.runtime_notification_ready);
        }
    }

    void createNotificationChannel() {
        NotificationManager manager =
                context.getSystemService(NotificationManager.class);
        if (manager == null) return;
        NotificationChannel channel = new NotificationChannel(
                NOTIFICATION_CHANNEL,
                context.getString(R.string.first_pairing_notification_channel),
                NotificationManager.IMPORTANCE_HIGH);
        channel.setDescription(context.getString(
                R.string.first_pairing_notification_channel_description));
        manager.createNotificationChannel(channel);
    }

    Notification pendingNotification() {
        PendingConfirmation pending = pendingConfirmation.get();
        return pending == null ? null : pairingNotification(pending);
    }

    private Notification pairingNotification(PendingConfirmation pending) {
        Intent openPairingActivity = new Intent(context, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP
                        | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        Intent accept = new Intent(context, MobileRuntimeService.class)
                .setAction(ACTION_CONFIRM_FIRST_PAIR);
        Intent reject = new Intent(context, MobileRuntimeService.class)
                .setAction(ACTION_REJECT_FIRST_PAIR);
        PendingIntent openIntent = PendingIntent.getActivity(
                context,
                13,
                openPairingActivity,
                PendingIntent.FLAG_IMMUTABLE
                        | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent acceptIntent = PendingIntent.getService(
                context,
                11,
                accept,
                PendingIntent.FLAG_IMMUTABLE
                        | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent rejectIntent = PendingIntent.getService(
                context,
                12,
                reject,
                PendingIntent.FLAG_IMMUTABLE
                        | PendingIntent.FLAG_UPDATE_CURRENT);
        String detail = context.getString(
                R.string.first_pairing_notification_detail,
                pending.decimalSas,
                pending.hostIpv4);
        return new Notification.Builder(context, NOTIFICATION_CHANNEL)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(context.getString(
                        R.string.first_pairing_notification_title))
                .setContentText(detail)
                .setStyle(new Notification.BigTextStyle().bigText(detail))
                .setContentIntent(openIntent)
                .addAction(new Notification.Action.Builder(
                        0,
                        context.getString(R.string.first_pairing_action_reject),
                        rejectIntent).build())
                .addAction(new Notification.Action.Builder(
                        0,
                        context.getString(R.string.first_pairing_action_confirm),
                        acceptIntent).build())
                .setCategory(Notification.CATEGORY_CALL)
                .setOngoing(true)
                .build();
    }

    private void publishState(FirstPairingUiState next) {
        FirstPairingUiState previous = uiState;
        uiState = next;
        MobileFirstPairingObserver currentObserver = observer;
        if (currentObserver == null || next.equals(previous)) return;
        postUpdate(currentObserver, next);
    }

    private void postUpdate(
            MobileFirstPairingObserver expectedObserver,
            FirstPairingUiState state) {
        mainHandler.post(() -> {
            if (!destroying.getAsBoolean()
                    && observer == expectedObserver) {
                expectedObserver.onFirstPairingChanged(state);
            }
        });
    }

    void closeSessions() {
        PendingConfirmation pending = pendingConfirmation.getAndSet(null);
        if (pending != null) pending.decision.complete(false);
        uiState = FirstPairingUiState.none();
        AndroidFirstPairingCoordinatorV1 pairing = activeFirstPairing;
        activeFirstPairing = null;
        if (pairing != null) pairing.close();
        AndroidBoundAuthenticatedControlCoordinatorV1 authenticated =
                activeAuthenticatedControl;
        activeAuthenticatedControl = null;
        if (authenticated != null) authenticated.close();
        replayPolicy.clear();
        MobilePipelineCoordinator currentPipeline = pipelineSupplier.get();
        if (currentPipeline != null) currentPipeline.clearConfirmedPeerSession();
    }

    ExecutorService executor() {
        return executor;
    }

    private static String firstPairingFailureDetail(
            Throwable failure,
            AndroidFirstPairingCoordinatorV1 coordinator) {
        String channelDetail = "";
        if (failure instanceof AuthenticatedControlTcpChannelV1.ChannelException) {
            AuthenticatedControlTcpChannelV1.ChannelException channelFailure =
                    (AuthenticatedControlTcpChannelV1.ChannelException) failure;
            channelDetail = " channel_failure="
                    + channelFailure.failure().name()
                    + " channel_stage=" + channelFailure.stage();
        }
        return "failure_type=" + failure.getClass().getSimpleName()
                + channelDetail
                + (coordinator == null
                        ? ""
                        : " pairing_stage=" + coordinator.diagnosticStage())
                + " data_plane_open=false";
    }
}
