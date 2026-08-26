package com.visionforge.inferencebenchmark;

import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.wifi.WifiManager;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.os.SystemClock;
import android.util.Log;

import com.visionforge.inferencebenchmark.runtime.FirstPairingUiState;
import com.visionforge.inferencebenchmark.runtime.MobileFirstPairingObserver;
import com.visionforge.inferencebenchmark.runtime.MobileRuntimeAuthorizationObserver;
import com.visionforge.inferencebenchmark.runtime.MobileRuntimeBinding;
import com.visionforge.inferencebenchmark.runtime.MobileRuntimeCompositionRoot;
import com.visionforge.inferencebenchmark.runtime.MobileRuntimeCommandProtocol;
import com.visionforge.inferencebenchmark.runtime.MobileRuntimePhase;
import com.visionforge.inferencebenchmark.runtime.MobileRuntimeReadModel;
import com.visionforge.inferencebenchmark.runtime.MobileRuntimeReadModelStore;
import com.visionforge.inferencebenchmark.ui.DualMachineAuthorizationUiMapper;
import com.visionforge.inferencebenchmark.ui.DualMachineAuthorizationUiState;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

/**
 * Process-level owner for the CAT6-first, wireless-fallback receive/decode/QNN pipeline.
 *
 * <p>The visible foreground notification prevents Android from silently
 * suspending an automatically armed CAT6/Wi-Fi session when its Activity is recreated or
 * backgrounded. The selected MAKCU or Bluetooth HID output is reconciled here
 * from live transport, decoder, QNN, native authorization and device health;
 * Activity visibility never grants or revokes output.</p>
 */
public final class MobileRuntimeService extends Service {
    private static final String LOG_TAG = "VisionForgeMobileRuntime";
    private static final String ACTION_ENSURE =
            MobileRuntimeCommandProtocol.ACTION_ENSURE;
    private static final String ACTION_REFRESH_POWER_POLICY =
            MobileRuntimeCommandProtocol.ACTION_REFRESH_POWER_POLICY;
    private static final String NOTIFICATION_CHANNEL = "visionforge_runtime";
    private static final int NOTIFICATION_ID = 320;
    private static final String LEGACY_RUNTIME_PREFERENCES =
            "visionforge_runtime_state";
    private static final String LEGACY_PIPELINE_DESIRED =
            "pipeline_desired_explicit_v2";
    private static final long RECEIVER_ACTIVE_LIVENESS_PROBE_MILLIS = 100L;
    private static final long RECEIVER_IDLE_LIVENESS_PROBE_MILLIS = 1_000L;
    private static final long EXECUTOR_SHUTDOWN_TIMEOUT_MILLIS = 1_000L;
    private static final long AUTHORIZATION_HEALTH_MILLIS = 250L;
    private static final int AUTHORIZATION_STATUS_RETRY_MAX_ATTEMPTS = 4;
    private static final long AUTHORIZATION_STATUS_RETRY_INITIAL_MILLIS = 500L;
    private static final long AUTHORIZATION_STATUS_RETRY_MAX_MILLIS = 2_000L;
    private static final long AUTHORIZATION_RENEWAL_MIN_INTERVAL_MILLIS =
            500L;
    private static final long AUTHORIZATION_RENEWAL_NO_PROGRESS_BACKOFF_MILLIS =
            500L;
    private static final long AUTHORIZATION_RENEWAL_REJECTED_BACKOFF_MILLIS =
            1_000L;
    private static final long AUTHORIZATION_START_RETRY_BACKOFF_MILLIS =
            1_000L;
    private static final long AUTOMATIC_HOST_RETRY_BACKOFF_MILLIS = 1_000L;
    private static final long AUTOMATIC_NO_PROGRESS_STOP_MILLIS = 1_500L;
    private static final long AUTOMATIC_REARM_CLAIM_INTERVAL_MILLIS = 500L;
    private static final long AUTOMATIC_REARM_HOST_ABSENCE_MILLIS = 1_000L;
    // Start the renewal early enough to cover real WAN/TLS/signing latency.
    // The server-issued successor remains future-dated and contiguous, so
    // this does not open the data plane beyond already prepaid lease time.
    private static final long AUTHORIZATION_RENEWAL_WINDOW_SECONDS = 4L;
    private static final long AUTHORIZATION_RENEWAL_WINDOW_GUARD_MILLIS =
            500L;
    static final long WIRELESS_HOST_DISCOVERY_TIMEOUT_MILLIS = 4_000L;
    // Real NVENC startup has reached 2.01 s; keep transport setup jitter out of
    // the fail-closed, pre-billing video-presence decision.
    static final long HOST_VIDEO_PREFLIGHT_TIMEOUT_MILLIS = 8_000L;
    static final long HOST_VIDEO_REVALIDATION_TIMEOUT_MILLIS = 2_000L;
    private static final String AUTOMATIC_USAGE_GUARD_PREFERENCES =
            "visionforge_automatic_usage_guard_v1";
    private static final String AUTOMATIC_USAGE_GUARD_BLOCKED =
            "blocked_until_new_host_stream";
    private static final String AUTOMATIC_USAGE_GUARD_LAST_FRAME =
            "last_host_frame_sequence";
    private static final String AUTOMATIC_USAGE_GUARD_RESUMABLE_BOUNDARY =
            "host_progress_may_resume";
    private static final String RUNTIME_WAKE_LOCK_TAG =
            "VisionForge:MobileRuntime";
    private static final String RUNTIME_WIFI_LOCK_TAG =
            "VisionForge:MobileRuntimeWifi";

    private enum FormalOwnerStopResult {
        CLAIMED,
        ALREADY_QUEUED,
        SUPERSEDED
    }

    /** Same-process command surface; the service is not exported. */
    public final class LocalBinder extends Binder implements MobileRuntimeBinding {
        @Override
        public void setAuthorizationObserver(MobileRuntimeAuthorizationObserver observer) {
            authorizationObserver = observer;
            if (observer != null) {
                postAuthorizationUpdate(
                        observer, authorizationUiState, "");
            }
        }

        @Override
        public void setFirstPairingObserver(
                MobileFirstPairingObserver observer) {
            pairingRuntime.setObserver(observer);
        }

        @Override
        public void setActivityForeground(boolean foreground) {
            updateActivityForeground(foreground);
        }

        @Override
        public DualMachineAuthorizationUiState authorizationState() {
            return authorizationUiState;
        }

        @Override
        public FirstPairingUiState firstPairingState() {
            return pairingRuntime.state();
        }

        @Override
        public void activateCard(String cardCode) {
            requestCardActivation(cardCode);
        }

        @Override
        public void resumePendingActivation() {
            requestPendingActivationResume();
        }

        @Override
        public void confirmFirstPairing(boolean matchingCodes) {
            pairingRuntime.confirm(matchingCodes);
        }

        @Override
        public void refreshAuthorization() {
            requestAuthorizationRefresh();
        }

        @Override
        public void selectGameModel(String modelToken) {
            requestGameModelSelection(modelToken, true);
        }

        @Override
        public void selectOutputRoute(String routeToken) {
            requestOutputRouteSelection(routeToken);
        }

        @Override
        public String outputRouteReport() {
            return controlRuntime == null ? "runtime_not_ready"
                    : controlRuntime.outputRouteReport();
        }

        @Override
        public void runDebugBluetoothHidMoveProbe(
                int deltaX,
                int deltaY,
                int reports,
                int intervalMillis) {
            requestDebugBluetoothHidMoveProbe(deltaX, deltaY, reports, intervalMillis);
        }
    }

    private static volatile MobileRuntimeReadModel runtimeStatus =
            new MobileRuntimeReadModel(MobileRuntimePhase.STOPPED, "runtime_not_started", 0L);
    private static volatile String latestEthernetDiagnostics =
            "ethernet_not_observed "
                    + EthernetNetworkDiagnostics.kernelInterfaceSnapshot(
                            EthernetTransportContract.INTERFACE_NAME);
    private static volatile String latestCat6ReadyDiagnostics = "ready_agent_not_observed";
    private static final MobilePipelineRetryGate PROCESS_RETRY_GATE =
            new MobilePipelineRetryGate();

    private final ExecutorService runtimeExecutor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "visionforge-mobile-runtime");
        thread.setDaemon(false);
        return thread;
    });
    private final ExecutorService authorizationExecutor =
            Executors.newSingleThreadExecutor(runnable -> {
                Thread thread = new Thread(
                        runnable, "visionforge-mobile-authorization");
                thread.setDaemon(false);
                return thread;
            });
    // Renewal dispatch must not share a scheduler with expensive native/QNN
    // health snapshots. The dedicated clock only queues serialized work onto
    // authorizationExecutor; it does not create a second authorization owner.
    private final ScheduledExecutorService authorizationHealthExecutor =
            Executors.newSingleThreadScheduledExecutor(runnable -> {
                Thread thread = new Thread(
                        runnable, "visionforge-mobile-authorization-health");
                thread.setDaemon(false);
                return thread;
            });
    private final ExecutorService startCancellationExecutor =
            Executors.newSingleThreadExecutor(runnable -> {
                Thread thread = new Thread(
                        runnable, "visionforge-mobile-start-cancellation");
                thread.setDaemon(false);
                return thread;
            });
    private final ScheduledExecutorService healthExecutor =
            Executors.newSingleThreadScheduledExecutor(runnable -> {
                Thread thread = new Thread(runnable, "visionforge-mobile-health");
                thread.setDaemon(false);
                return thread;
            });
    private final DualMachineMonotonicDeadlineScheduler runtimePermitDeadlines =
            new DualMachineMonotonicDeadlineScheduler();

    private MobileEventLogger events;
    private DualMachinePresentationBalanceReconciler
            presentationBalanceReconciler;
    private MobilePairingRuntimeCoordinator pairingRuntime;
    private MobileExternalHealthSnapshotWriter externalHealthSnapshotWriter;
    private MobileControlRuntime controlRuntime;
    private MobilePipelineCoordinator pipeline;
    private HostVideoPresenceProbe hostVideoPresenceProbe;
    private Cat6ReadyLifecycleCoordinator cat6ReadyLifecycle;
    private MobileEthernetRecoveryCoordinator<FormalPipelineOwnerReceipt>
            ethernetRecovery;
    private final MobileTransportCatalog transportCatalog = new MobileTransportCatalog();
    private ConnectivityManager connectivityManager;
    private ConnectivityManager.NetworkCallback networkCallback;
    private ConnectivityManager.NetworkCallback authorizationNetworkCallback;
    private ConnectivityManager.NetworkCallback ethernetDemandCallback;
    private PowerManager.WakeLock wakeLock;
    private WifiManager.WifiLock wifiLock;
    private boolean wifiLockRequired;
    private final Object pipelineCommandLock = new Object();
    private final Object modelPreparationLock = new Object();
    private final Object receiverLivenessScheduleLock = new Object();
    private final Object authorizationStatusRetryLock = new Object();
    private final Object authorizationLifecycleLock = new Object();
    private final AtomicLong pipelineSessionGeneration = new AtomicLong();
    private volatile boolean pipelineStarted;
    private volatile boolean pipelineDesired;
    private volatile boolean destroying;
    /** Guarded by {@link #authorizationStatusRetryLock}. */
    private ScheduledFuture<?> authorizationStatusRetryFuture;
    /** Guarded by {@link #authorizationStatusRetryLock}. */
    private int authorizationStatusRetryAttempts;
    /** Guarded by {@link #authorizationStatusRetryLock}. */
    private long authorizationStatusRetryGeneration;
    /** Guarded by {@link #authorizationStatusRetryLock}. */
    private long authorizationStatusRetryNetworkHandle = Long.MIN_VALUE;
    private volatile long pipelineNetworkHandle;
    private volatile String lastNativeDirectory;
    private volatile String lastSkeletonDirectory;
    private volatile MobileInferenceBackendPolicy.Plan lastInferenceBackendPlan;
    private volatile MobileInferenceBackend lastPreparedInferenceBackend;
    /** Guarded by {@link #pipelineCommandLock}. */
    private boolean gameModelHotReloadInProgress;
    /** Guarded by {@link #pipelineCommandLock}. */
    private boolean formalModelPreparationInProgress;
    /** Guarded by {@link #pipelineCommandLock}. */
    private MobileModelCatalog.Profile pendingGameModelSelection;
    private DualMachineFormalUsageCoordinator.DataPlanePermit
            activeRuntimePermit;
    private DualMachineFormalUsageCoordinator.DataPlanePermit
            stagedRuntimePermit;
    private DualMachineFormalUsageCoordinator.DeadlineScheduler
            .ScheduledDeadline runtimePermitDeadline;
    private long runtimePermitGeneration;
    private ScheduledFuture<?> receiverLivenessFuture;
    private final MobileRuntimeHealthLogPolicy healthLogPolicy =
            new MobileRuntimeHealthLogPolicy();
    private final MobileRuntimeMetricsSampler externalHealthMetricsSampler =
            new MobileRuntimeMetricsSampler();
    private final MobileExternalHealthSnapshotPolicy externalHealthSnapshotPolicy =
            new MobileExternalHealthSnapshotPolicy();
    private final MobileEthernetDiagnosticsLogPolicy ethernetDiagnosticsLogPolicy =
            new MobileEthernetDiagnosticsLogPolicy();
    private final Cat6ReadyAgentLogPolicy cat6ReadyAgentLogPolicy =
            new Cat6ReadyAgentLogPolicy();
    private final MobileRuntimePresentationUpdatePolicy runtimePresentationUpdatePolicy =
            new MobileRuntimePresentationUpdatePolicy(
                    R.string.runtime_notification_ready);
    private final AutomaticUsageReservationLogPolicy reservationLogPolicy =
            new AutomaticUsageReservationLogPolicy();
    private final AutomaticUsageGuardCheckpointPolicy automaticUsageCheckpointPolicy =
            new AutomaticUsageGuardCheckpointPolicy();
    private final AutomaticFormalStartRetryPolicy formalStartRetryPolicy =
            new AutomaticFormalStartRetryPolicy();
    private final HostVideoPreflightLogPolicy automaticHostWaitLogPolicy =
            new HostVideoPreflightLogPolicy();
    private final AtomicBoolean healthFailureReported = new AtomicBoolean();
    private final AtomicBoolean externalHealthSnapshotFailureReported =
            new AtomicBoolean();
    private final AtomicBoolean receiverLivenessFailureReported = new AtomicBoolean();
    private final AtomicBoolean cat6ReadyAgentReportFailureReported =
            new AtomicBoolean();
    private final AtomicBoolean automaticRearmProbeFailureReported =
            new AtomicBoolean();
    private final AtomicBoolean wirelessDisplayWaitReported =
            new AtomicBoolean();
    private final AtomicLong lastWirelessDiscoveryTimeoutNetworkHandle =
            new AtomicLong(Long.MIN_VALUE);
    private final AtomicBoolean activityForeground = new AtomicBoolean();
    private final AutomaticFormalUsageSessionGuard automaticUsageGuard =
            new AutomaticFormalUsageSessionGuard();
    /**
     * Process-local capability mirror only. It is never persisted or restored;
     * the formal usage boundary will own every transition to true.
     */
    private final AtomicBoolean formalDataPlanePermitOpen =
            new AtomicBoolean();
    private volatile String formalSessionChannelBinding = "";
    private volatile MobileTransportEndpoint formalSessionEndpoint;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final LocalBinder localBinder = new LocalBinder();
    private final MobileRuntimeCompositionRoot compositionRoot =
            new MobileRuntimeCompositionRoot(localBinder);
    private final AtomicBoolean authorizationOperationInFlight =
            new AtomicBoolean();
    private final AtomicBoolean authorizationMaintenanceQueued =
            new AtomicBoolean();
    private final AtomicBoolean formalRenewalRetryPending =
            new AtomicBoolean();
    private final AtomicLong nextFormalRenewalAttemptElapsedMillis =
            new AtomicLong();
    private final AtomicLong nextFormalStartRetryElapsedMillis =
            new AtomicLong();
    private final AtomicLong nextAutomaticHostAttemptElapsedMillis =
            new AtomicLong();
    private final AtomicBoolean automaticFormalStopQueued =
            new AtomicBoolean();
    private final SecureRandom authorizationRandom = new SecureRandom();
    private volatile MobileRuntimeAuthorizationObserver authorizationObserver;
    private volatile DualMachineAuthorizationUiState authorizationUiState =
            DualMachineAuthorizationUiState.readyForActivation();
    private volatile DualMachineAuthorizationRuntime authorizationRuntime;
    private volatile QueuedCardActivationCoordinator queuedCardActivation;
    private volatile boolean authorizationSecurityFatal;
    /** Guarded by {@link #authorizationLifecycleLock}. */
    private long authorizationInitializationGeneration;
    /** Guarded by {@link #authorizationLifecycleLock}. */
    private DualMachineMonotonicDeadlineScheduler authorizationDeadlines;

    static void ensureRunning(Context context) {
        Intent intent = new Intent(context, MobileRuntimeService.class)
                .setAction(ACTION_ENSURE);
        context.startForegroundService(intent);
    }

    static void requestPowerPolicyRefresh(Context context) {
        context.startService(new Intent(context, MobileRuntimeService.class)
                .setAction(ACTION_REFRESH_POWER_POLICY));
    }

    static MobileRuntimeReadModel status() {
        return MobileRuntimeReadModelStore.snapshot();
    }

    static String ethernetDiagnostics() {
        return MobileRuntimeReadModelStore.ethernetDiagnostics();
    }

    static String cat6ReadyDiagnostics() {
        return latestCat6ReadyDiagnostics;
    }

    private void publishEthernetDiagnostics() {
        compositionRoot.publishEthernetDiagnostics(latestEthernetDiagnostics);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        compositionRoot.publish(runtimeStatus);
        compositionRoot.publishEthernetDiagnostics(latestEthernetDiagnostics);
        events = new MobileEventLogger(this);
        AndroidPendingActivationStore activationStore =
                new AndroidPendingActivationStore(this);
        presentationBalanceReconciler =
                new DualMachinePresentationBalanceReconciler(
                        new SharedPreferencesDualMachinePresentationBalanceStore(
                                this),
                        events);
        externalHealthSnapshotWriter = new MobileExternalHealthSnapshotWriter(
                getExternalFilesDir(null));
        restoreAutomaticUsageGuard();
        controlRuntime = MobileControlRuntime.get(this);
        controlRuntime.ensureSelectedOutputConnected();
        pipeline = new MobilePipelineCoordinator(new QnnNativeVideoInferencePipeline(), events);
        queuedCardActivation = new QueuedCardActivationCoordinator(
                this,
                activationStore,
                authorizationExecutor,
                authorizationOperationInFlight,
                () -> authorizationRuntime,
                () -> destroying || authorizationSecurityFatal,
                this::publishTransientAuthorizationState,
                this::publishMappedAuthorizationState,
                this::authorizationFailureMessage,
                () -> pairingRuntime.scheduleAuthenticatedControlIfNeeded(),
                this::publishFatalAuthorizationState,
                events);
        pairingRuntime = new MobilePairingRuntimeCoordinator(
                this,
                NOTIFICATION_ID,
                events,
                () -> destroying,
                () -> authorizationRuntime,
                this::requiredTransportEndpoint,
                () -> controlRuntime,
                () -> pipeline,
                this::attachAuthenticatedHost,
                queuedCardActivation::onPairingAuthorizationStateChanged,
                this::updateNotification,
                this::nextAuthorizationId);
        hostVideoPresenceProbe = new HostVideoPresenceProbe(events);
        cat6ReadyLifecycle = new Cat6ReadyLifecycleCoordinator(new NativeCat6ReadyAgent());
        ethernetRecovery = createEthernetRecoveryCoordinator();
        createNotificationChannel();
        startForeground(NOTIFICATION_ID, notification(R.string.runtime_notification_ready));
        boolean networkObserverRegistered = registerNetworkObserver();
        boolean authorizationNetworkObserverRegistered =
                networkObserverRegistered
                        && registerAuthorizationNetworkObserver();
        boolean ethernetDemandRegistered = networkObserverRegistered
                && registerEthernetNetworkDemand();
        refreshEthernetDiagnosticsFromKernel("service_created");
        updateCat6ReadyAgent(
                null, "service_created_legacy_ready_fail_closed");
        // A process/service restart never restores a paid session or ticket.
        // A pre-debit reservation or prior session remains blocked until the
        // existing video sequence proves that Host started a fresh stream.
        pipelineDesired = false;
        clearLegacyPipelineRestoreFlag();
        if (!PROCESS_RETRY_GATE.canAttempt()) {
            updateStatus(
                    MobileRuntimePhase.FAILED,
                    "automatic_recovery_suppressed failure_code="
                            + PROCESS_RETRY_GATE.failureCode()
                            + " reason={" + PROCESS_RETRY_GATE.failureDetail() + "}");
            updateNotification(R.string.runtime_notification_failed);
        } else if (networkObserverRegistered) {
            updateStatus(
                    MobileRuntimePhase.READY,
                    "transport_required preferred="
                            + EthernetTransportContract.requiredLink());
        } else {
            updateStatus(
                    MobileRuntimePhase.FAILED,
                    "ethernet_observer_registration_failed diagnostics={"
                            + latestEthernetDiagnostics + "}");
        }
        events.write("mobile_runtime_service_started",
                "foreground=true control_gate=automatic_fail_closed "
                        + "control_owner=service_process move_only=true "
                        + "pipeline_desired=" + pipelineDesired
                        + " wake_lock_held=false "
                        + " wifi_lock_held=false "
                        + " automatic_usage_guard={"
                        + automaticUsageGuard.snapshot().detail() + "} "
                        + "ethernet_demand_registered=" + ethernetDemandRegistered + " "
                        + "authorization_network_observer_registered="
                        + authorizationNetworkObserverRegistered + " "
                        + "transport=cat6 preferred="
                        + EthernetTransportContract.requiredLink());
        initialiseAuthorizationRuntimeAsync();
        healthExecutor.scheduleWithFixedDelay(this::runPeriodicRuntimeHealth,
                5L, 5L, TimeUnit.SECONDS);
        authorizationHealthExecutor.scheduleWithFixedDelay(
                this::runPeriodicAuthorizationMaintenance,
                AUTHORIZATION_HEALTH_MILLIS,
                AUTHORIZATION_HEALTH_MILLIS,
                TimeUnit.MILLISECONDS);
        scheduleReceiverLivenessProbe(receiverLivenessDelayMillis(), true);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (pairingRuntime.handleAction(action)) {
            return START_NOT_STICKY;
        }
        MobileRuntimeCommandProtocol.Command command =
                MobileRuntimeCommandProtocol.parse(
                        action,
                        true);
        if (command == MobileRuntimeCommandProtocol.Command.REFRESH_POWER_POLICY) {
            refreshRuntimeLocks();
        } else if (command == MobileRuntimeCommandProtocol.Command.UNKNOWN
                && events != null) {
            events.write(
                    "mobile_runtime_command_rejected",
                    "reason=unknown_action side_effect=false");
        }
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return (IBinder) compositionRoot.binding();
    }

    @Override
    public boolean onUnbind(Intent intent) {
        authorizationObserver = null;
        pairingRuntime.clearObserver();
        return true;
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        if (events != null) {
            events.write(
                    "mobile_app_task_removed",
                    "service_kept_armed=true billing_state_unchanged=true");
        }
        super.onTaskRemoved(rootIntent);
    }

    @Override
    public void onDestroy() {
        MobileServiceDestroyCleanup cleanup =
                new MobileServiceDestroyCleanup();
        try {
            beginServiceDestroy();
            closeControlAndAuthorizationResources(cleanup);
            closeTransportResources(cleanup);
            closePipelineResources(cleanup);
            publishDestroyOutcome(cleanup);
        } finally {
            super.onDestroy();
        }
    }

    private void initialiseAuthorizationRuntimeAsync() {
        final long initializationGeneration;
        synchronized (authorizationLifecycleLock) {
            if (destroying) return;
            initializationGeneration = ++authorizationInitializationGeneration;
        }
        try {
            authorizationExecutor.execute(() -> {
                DualMachineMonotonicDeadlineScheduler deadlines = null;
                DualMachineAuthorizationRuntime created = null;
                try {
                    DualMachineReleaseSecurityConfig.Material security =
                            DualMachineReleaseSecurityConfig.load(
                                    getApplicationContext());
                    AndroidPairingIdentityStore identityStore =
                            new AndroidPairingIdentityStore();
                    String fingerprint = identityStore.fingerprintHex();
                    String deviceCode = "ANDROID-"
                            + fingerprint.substring(0, 32)
                            .toUpperCase(Locale.ROOT);
                    DualMachineCardAuthorizationCoordinator.IdentityBinding
                            androidIdentity =
                            new DualMachineCardAuthorizationCoordinator
                                    .IdentityBinding(
                                    deviceCode,
                                    BuildConfig
                                            .DUAL_MACHINE_PROTOCOL_CLIENT_VERSION,
                                    identityStore.publicKeyBase64(),
                                    AndroidDeviceProfileCollector.collect(
                                            getApplicationContext()),
                                    identityStore::sign);
                    QueuedCardActivationCoordinator queuedCards =
                            queuedCardActivation;
                    if (queuedCards == null) {
                        throw new GeneralSecurityException(
                                "queued card coordinator is unavailable");
                    }
                    AndroidPendingActivationStore activationStore =
                            queuedCards.store();
                    queuedCards.restorePresence();
                    deadlines =
                            new DualMachineMonotonicDeadlineScheduler();
                    created = new DualMachineAuthorizationRuntime(
                                    security.sidecar,
                                    new DualMachineFormalUsageStateMachine(),
                                    security.leaseKeyring,
                                    new SharedPreferencesDualMachineEntitlementStore(
                                            getApplicationContext()),
                                    activationStore,
                                    androidIdentity,
                                    identityStore.alias(),
                                    this::nextAuthorizationId,
                                    System::nanoTime,
                                    deadlines,
                                    this::readAndroidProgress);
                    if (!installAuthorizationRuntimeIfCurrent(
                            initializationGeneration,
                            created,
                            deadlines,
                            identityStore,
                            androidIdentity)) {
                        created.close();
                        deadlines.close();
                        events.write(
                                "dual_machine_authorization_runtime_discarded",
                                "reason=initialization_superseded");
                        return;
                    }
                    queuedCards.reconcileAfterRuntimeRestore(created);
                    events.write(
                            "dual_machine_authorization_runtime_ready",
                            "card_secret_plaintext_persisted=false "
                                    + "queued_card_sealed="
                                    + queuedCards.isPresent() + " "
                                    + "host_session_persisted=false "
                                    + "authenticated_host_attached=false "
                                    + "formal_lease_restored=false");
                    publishMappedAuthorizationState("");
                    refreshAuthorizationStatusAfterRestore(created);
                    pairingRuntime.scheduleFirstPairingIfNeeded();
                    pairingRuntime.scheduleAuthenticatedControlIfNeeded();
                    queuedCards.activateIfReady();
                } catch (IOException | GeneralSecurityException
                         | RuntimeException failure) {
                    if (created != null) created.close();
                    if (deadlines != null) deadlines.close();
                    boolean reportFailure = markAuthorizationInitializationFailed(
                            initializationGeneration, created, deadlines);
                    if (!reportFailure) return;
                    events.write(
                            "dual_machine_authorization_runtime_failed",
                            "failure_type="
                                    + failure.getClass().getSimpleName()
                                    + " data_plane_open=false stack={"
                                    + MobileThrowableDiagnostics.format(failure)
                                    + "}");
                    publishFatalAuthorizationState();
                }
            });
        } catch (RuntimeException schedulingFailure) {
            if (markAuthorizationInitializationFailed(
                    initializationGeneration, null, null)) {
                publishFatalAuthorizationState();
            }
        }
    }

    private boolean installAuthorizationRuntimeIfCurrent(
            long initializationGeneration,
            DualMachineAuthorizationRuntime runtime,
            DualMachineMonotonicDeadlineScheduler deadlines,
            AndroidPairingIdentityStore identityStore,
            DualMachineCardAuthorizationCoordinator.IdentityBinding
                    androidIdentity) {
        synchronized (authorizationLifecycleLock) {
            if (destroying
                    || initializationGeneration
                    != authorizationInitializationGeneration) {
                return false;
            }
            authorizationDeadlines = deadlines;
            authorizationRuntime = runtime;
            pairingRuntime.configureIdentity(identityStore, androidIdentity);
            authorizationSecurityFatal = false;
            return true;
        }
    }

    private boolean markAuthorizationInitializationFailed(
            long initializationGeneration,
            DualMachineAuthorizationRuntime runtime,
            DualMachineMonotonicDeadlineScheduler deadlines) {
        synchronized (authorizationLifecycleLock) {
            if (runtime != null && authorizationRuntime == runtime) {
                authorizationRuntime = null;
            }
            if (deadlines != null && authorizationDeadlines == deadlines) {
                authorizationDeadlines = null;
            }
            if (destroying
                    || initializationGeneration
                    != authorizationInitializationGeneration) {
                return false;
            }
            authorizationSecurityFatal = true;
            return true;
        }
    }

    private void closePublishedAuthorizationRuntime() {
        final DualMachineAuthorizationRuntime runtime;
        final DualMachineMonotonicDeadlineScheduler deadlines;
        synchronized (authorizationLifecycleLock) {
            runtime = authorizationRuntime;
            deadlines = authorizationDeadlines;
            authorizationRuntime = null;
            authorizationDeadlines = null;
            pairingRuntime.clearIdentity();
        }
        Throwable closeFailure = null;
        if (runtime != null) {
            try {
                runtime.close();
            } catch (RuntimeException | LinkageError failure) {
                closeFailure = MobileServiceDestroyCleanup.appendFailure(
                        closeFailure, failure);
            }
        }
        if (deadlines != null) {
            try {
                deadlines.close();
            } catch (RuntimeException | LinkageError failure) {
                closeFailure = MobileServiceDestroyCleanup.appendFailure(
                        closeFailure, failure);
            }
        }
        MobileServiceDestroyCleanup.rethrowFailure(closeFailure);
    }

    private void refreshAuthorizationStatusAfterRestore(
            DualMachineAuthorizationRuntime runtime) {
        final long generation;
        synchronized (authorizationStatusRetryLock) {
            authorizationStatusRetryAttempts = 0;
            authorizationStatusRetryGeneration++;
            generation = authorizationStatusRetryGeneration;
            cancelAuthorizationStatusRetryLocked();
        }
        attemptAuthorizationStatusRefresh(
                runtime, "startup_restore", generation);
    }

    private void attemptAuthorizationStatusRefresh(
            DualMachineAuthorizationRuntime runtime,
            String source,
            long generation) {
        if (!authorizationStatusRefreshRequired(runtime)
                || !reserveAuthorizationStatusRetryAttempt(generation)) {
            return;
        }
        if (!authorizationOperationInFlight.compareAndSet(false, true)) {
            scheduleAuthorizationStatusRetry(runtime, source, generation);
            return;
        }
        try {
            runtime.refreshStatus();
            if (!authorizationStatusRetryGenerationIsCurrent(generation)) {
                return;
            }
            cancelAuthorizationStatusRetry();
            reconcileRuntimeLocksAfterDataPlaneClose(
                    "authorization_status_restored");
            events.write(
                    "dual_machine_authorization_status_refreshed",
                    "source=" + safeToken(source) + " result=success");
            publishMappedAuthorizationState("");
        } catch (IOException | GeneralSecurityException
                 | RuntimeException failure) {
            events.write(
                    "dual_machine_authorization_status_refreshed",
                    "source=" + safeToken(source)
                            + " result=failed failure_type="
                            + failure.getClass().getSimpleName()
                            + " stack={"
                            + MobileThrowableDiagnostics.format(failure)
                            + "}");
            scheduleAuthorizationStatusRetry(runtime, source, generation);
        } finally {
            authorizationOperationInFlight.set(false);
        }
    }

    private boolean authorizationStatusRefreshRequired(
            DualMachineAuthorizationRuntime runtime) {
        if (runtime == null || runtime != authorizationRuntime
                || authorizationSecurityFatal || destroying) {
            return false;
        }
        DualMachineFormalUsageStateMachine.Snapshot snapshot =
                runtime.snapshot();
        return snapshot.entitlement != null
                && !snapshot.balanceKnown
                && snapshot.canRefreshStatus();
    }

    private boolean reserveAuthorizationStatusRetryAttempt(long generation) {
        synchronized (authorizationStatusRetryLock) {
            if (generation != authorizationStatusRetryGeneration
                    || authorizationStatusRetryAttempts
                    >= AUTHORIZATION_STATUS_RETRY_MAX_ATTEMPTS) {
                return false;
            }
            authorizationStatusRetryAttempts++;
            return true;
        }
    }

    private void scheduleAuthorizationStatusRetry(
            DualMachineAuthorizationRuntime runtime,
            String source,
            long generation) {
        if (!authorizationStatusRefreshRequired(runtime) || destroying) return;
        final long delayMillis;
        synchronized (authorizationStatusRetryLock) {
            if (generation != authorizationStatusRetryGeneration
                    || authorizationStatusRetryAttempts
                    >= AUTHORIZATION_STATUS_RETRY_MAX_ATTEMPTS
                    || (authorizationStatusRetryFuture != null
                    && !authorizationStatusRetryFuture.isDone())) {
                return;
            }
            int completedAttempts = Math.max(
                    1, authorizationStatusRetryAttempts);
            delayMillis = Math.min(
                    AUTHORIZATION_STATUS_RETRY_MAX_MILLIS,
                    AUTHORIZATION_STATUS_RETRY_INITIAL_MILLIS
                            << Math.min(2, completedAttempts - 1));
            try {
                authorizationStatusRetryFuture = healthExecutor.schedule(() -> {
                    synchronized (authorizationStatusRetryLock) {
                        if (generation != authorizationStatusRetryGeneration) {
                            return;
                        }
                        authorizationStatusRetryFuture = null;
                    }
                    try {
                        authorizationExecutor.execute(() ->
                                attemptAuthorizationStatusRefresh(
                                        runtime, source + "_retry", generation));
                    } catch (RuntimeException schedulingFailure) {
                        events.write(
                                "dual_machine_authorization_status_retry",
                                "result=scheduling_failed failure_type="
                                        + schedulingFailure.getClass()
                                        .getSimpleName());
                    }
                }, delayMillis, TimeUnit.MILLISECONDS);
            } catch (RuntimeException schedulingFailure) {
                authorizationStatusRetryFuture = null;
                recordAuthorizationStatusRetryScheduleFailure(
                        source, delayMillis, schedulingFailure);
            }
        }
    }

    private void ensureAuthorizationStatusRetryScheduled() {
        DualMachineAuthorizationRuntime runtime = authorizationRuntime;
        if (!authorizationStatusRefreshRequired(runtime)) return;
        final long generation;
        synchronized (authorizationStatusRetryLock) {
            generation = authorizationStatusRetryGeneration;
        }
        scheduleAuthorizationStatusRetry(
                runtime, "authorization_health_rearm", generation);
    }

    private void recordAuthorizationStatusRetryScheduleFailure(
            String source, long delayMillis, RuntimeException schedulingFailure) {
        Log.e(LOG_TAG, "Authorization status retry scheduling failed", schedulingFailure);
        try {
            if (events != null) {
                events.write(
                        "dual_machine_authorization_status_retry",
                        "source=" + safeToken(source)
                                + " result=scheduling_failed"
                                + " delay_ms=" + delayMillis
                                + " automatic_retry=true periodic_health_rearm=true"
                                + " stack={"
                                + MobileThrowableDiagnostics.format(schedulingFailure)
                                + "}");
            }
        } catch (RuntimeException | LinkageError loggingFailure) {
            Log.e(LOG_TAG,
                    "Cannot record authorization status retry scheduling failure",
                    loggingFailure);
        }
    }

    private void signalAuthorizationNetworkChanged(long networkHandle) {
        DualMachineAuthorizationRuntime runtime = authorizationRuntime;
        if (!authorizationStatusRefreshRequired(runtime)) return;
        final long generation;
        synchronized (authorizationStatusRetryLock) {
            if (networkHandle == authorizationStatusRetryNetworkHandle) return;
            authorizationStatusRetryNetworkHandle = networkHandle;
            authorizationStatusRetryAttempts = 0;
            authorizationStatusRetryGeneration++;
            generation = authorizationStatusRetryGeneration;
            cancelAuthorizationStatusRetryLocked();
        }
        scheduleAuthorizationStatusRetry(
                runtime, "network_changed", generation);
    }

    private boolean authorizationStatusRetryGenerationIsCurrent(
            long generation) {
        synchronized (authorizationStatusRetryLock) {
            return generation == authorizationStatusRetryGeneration;
        }
    }

    private void cancelAuthorizationStatusRetry() {
        synchronized (authorizationStatusRetryLock) {
            authorizationStatusRetryGeneration++;
            authorizationStatusRetryAttempts = 0;
            cancelAuthorizationStatusRetryLocked();
        }
    }

    private void cancelAuthorizationStatusRetryLocked() {
        ScheduledFuture<?> future = authorizationStatusRetryFuture;
        authorizationStatusRetryFuture = null;
        if (future != null) future.cancel(false);
    }

    private String nextAuthorizationId() {
        byte[] value = new byte[16];
        authorizationRandom.nextBytes(value);
        char[] encoded = new char[value.length * 2];
        char[] alphabet = "0123456789abcdef".toCharArray();
        for (int index = 0; index < value.length; index++) {
            int unsigned = value[index] & 0xff;
            encoded[index * 2] = alphabet[unsigned >>> 4];
            encoded[index * 2 + 1] = alphabet[unsigned & 0x0f];
        }
        return new String(encoded);
    }

    private void restoreAutomaticUsageGuard() {
        try {
            boolean blocked = getSharedPreferences(
                    AUTOMATIC_USAGE_GUARD_PREFERENCES,
                    MODE_PRIVATE).getBoolean(
                    AUTOMATIC_USAGE_GUARD_BLOCKED, false);
            if (!blocked) return;
            long lastFrame = getSharedPreferences(
                    AUTOMATIC_USAGE_GUARD_PREFERENCES,
                    MODE_PRIVATE).getLong(
                    AUTOMATIC_USAGE_GUARD_LAST_FRAME, -1L);
            boolean hostProgressMayResume = getSharedPreferences(
                    AUTOMATIC_USAGE_GUARD_PREFERENCES,
                    MODE_PRIVATE).getBoolean(
                    AUTOMATIC_USAGE_GUARD_RESUMABLE_BOUNDARY, false);
            automaticUsageGuard.restoreBlocked(
                    lastFrame, hostProgressMayResume);
            automaticUsageCheckpointPolicy.restorePersisted(lastFrame);
            events.write(
                    "dual_machine_automatic_usage_guard_restored",
                    automaticUsageGuard.snapshot().detail()
                            + " process_restart_rearm=false");
        } catch (RuntimeException failure) {
            automaticUsageGuard.restoreBlocked(-1L);
            automaticUsageCheckpointPolicy.restorePersisted(-1L);
            events.write(
                    "dual_machine_automatic_usage_guard_restore_failed",
                    "fail_closed=true failure_type="
                            + failure.getClass().getSimpleName());
        }
    }

    private void ensureAutomaticFormalStartReserved(
            String expectedStartRequestId,
            String expectedChannelBindingSha256)
            throws GeneralSecurityException {
        boolean newlyReserved = automaticUsageGuard.reserveFormalStart(
                expectedStartRequestId,
                expectedChannelBindingSha256);
        try {
            persistAutomaticUsageBlock(true);
        } catch (GeneralSecurityException failure) {
            automaticUsageGuard.blockPotentiallyBilledGeneration(
                    expectedStartRequestId,
                    expectedChannelBindingSha256);
            throw failure;
        }
        events.write(
                "dual_machine_automatic_usage_start_reserved",
                automaticUsageGuard.snapshot().detail()
                        + " persisted_before_potential_debit=true"
                        + " exact_retry=" + !newlyReserved);
    }

    private void markAutomaticFormalSessionOpened(
            String expectedStartRequestId,
            String expectedChannelBindingSha256) throws IOException {
        try {
            automaticUsageGuard.markFormalSessionOpened(
                    expectedStartRequestId,
                    expectedChannelBindingSha256);
        } catch (IllegalStateException failure) {
            long lastFrame = automaticUsageGuard.snapshot()
                    .lastHostFrameSequence;
            automaticUsageGuard.restoreBlocked(lastFrame);
            try {
                persistAutomaticUsageBlock(true);
            } catch (GeneralSecurityException persistenceFailure) {
                failure.addSuppressed(persistenceFailure);
            }
            throw new IOException(
                    "automatic usage guard rejected paid generation",
                    failure);
        }
        try {
            persistAutomaticUsageBlock(true);
        } catch (GeneralSecurityException failure) {
            throw new IOException(
                    "automatic usage guard could not commit paid generation",
                    failure);
        }
        events.write(
                "dual_machine_automatic_usage_session_opened",
                automaticUsageGuard.snapshot().detail()
                        + " persisted=true");
    }

    private void cancelUnbilledStartReservationIfAborted(
            DualMachineAuthorizationRuntime runtime,
            String reason) {
        // A Runtime reference is not a reservation capability: attachment
        // replacement may already have published a newer generation. Every
        // post-reservation failure carries an immutable terminal handle and is
        // settled by exact owner below. Pre-reservation failures do nothing.
        writeUnchangedAutomaticUsageReservation(reason);
    }

    /** Fatal transport outcomes may still hide one committed paid start. */
    private void settleTerminalFormalStartFailure(
            Throwable failure,
            String reason) {
        if (failure instanceof DualMachineFormalUsageCoordinator
                .GenerationBoundStartFailure) {
            DualMachineFormalUsageCoordinator.TerminalStartFailureHandle
                    handle = ((DualMachineFormalUsageCoordinator
                    .GenerationBoundStartFailure) failure)
                    .terminalStartFailureHandle();
            DualMachineFormalUsageCoordinator.StopOutcome outcome =
                    handle.settle();
            settleAutomaticUsageReservation(
                    handle.startRequestId,
                    handle.channelBindingSha256,
                    outcome,
                    reason);
            events.write(
                    "dual_machine_terminal_start_failure_settled",
                    "reason=" + safeToken(reason)
                            + " start_request_id=" + handle.startRequestId
                            + " local_closed=" + outcome.localClosed
                            + " server_confirmed="
                            + outcome.serverConfirmed
                            + " definitely_not_started="
                            + outcome.definitelyNotStarted
                            + " generation_bound=true");
            return;
        }
        // No reservation owner exists. Never inspect or mutate a possibly
        // newer Runtime generation from this old catch path.
        events.write(
                "dual_machine_terminal_start_failure_unowned",
                "reason=" + safeToken(reason)
                        + " action=no_cross_generation_cleanup");
    }

    private void recordSupersededFormalStartAttempt(String source) {
        events.write(
                "dual_machine_formal_start_superseded",
                "source=" + safeToken(source)
                        + " action=no_cross_generation_cleanup");
    }

    private void blockPotentiallyBilledStartIfAborted(
            DualMachineAuthorizationRuntime runtime,
            String reason) {
        if (runtime != null) {
            DualMachineFormalUsageStateMachine.State state =
                    runtime.snapshot().state;
            if (state
                    == DualMachineFormalUsageStateMachine.State.STARTING) {
                return;
            }
            if (state
                    == DualMachineFormalUsageStateMachine.State.STOPPING) {
                requestFormalUsageStop(reason);
                return;
            }
        }
        blockAutomaticStartForCurrentHostStream(reason);
    }

    private void blockAutomaticStartForCurrentHostStream(String reason) {
        // Only an immutable start owner may mutate the guard. Current-Runtime
        // lookup is intentionally insufficient across attachment replacement.
        writeUnchangedAutomaticUsageReservation(reason);
    }

    private void writeUnchangedAutomaticUsageReservation(String reason) {
        String safeReason = safeToken(reason);
        if (!reservationLogPolicy.shouldWrite(
                safeReason, SystemClock.elapsedRealtime())) {
            return;
        }
        events.write(
                "dual_machine_automatic_usage_reservation_unchanged",
                "reason=" + safeReason + " exact_owner=false"
                        + " stable_heartbeat_ms="
                        + AutomaticUsageReservationLogPolicy
                        .STABLE_HEARTBEAT_MILLIS);
    }

    private void blockAutomaticStartForOwner(
            String expectedStartRequestId,
            String expectedChannelBindingSha256,
            String reason) {
        recordLatestHostFrameFromNative();
        if (!automaticUsageGuard.blockPotentiallyBilledGeneration(
                expectedStartRequestId,
                expectedChannelBindingSha256)) return;
        persistClosedAutomaticUsageGeneration(reason);
    }

    private void closeOpenedAutomaticSessionForBoundary(
            String expectedStartRequestId,
            String expectedChannelBindingSha256,
            String reason) {
        recordLatestHostFrameFromNative();
        if (!automaticUsageGuard.markFormalSessionClosed(
                expectedStartRequestId,
                expectedChannelBindingSha256)) return;
        persistClosedAutomaticUsageGeneration(reason);
    }

    private void settleAutomaticUsageReservation(
            String expectedStartRequestId,
            String expectedChannelBindingSha256,
            DualMachineFormalUsageCoordinator.StopOutcome outcome,
            String reason) {
        if (outcome.definitelyNotStarted) {
            if (!automaticUsageGuard.cancelUnbilledStartReservation(
                    expectedStartRequestId,
                    expectedChannelBindingSha256)) return;
            clearPersistedAutomaticUsageBlock();
            events.write(
                    "dual_machine_automatic_usage_start_reservation_cancelled",
                    "reason=" + safeToken(reason)
                            + " billing_started=false exact_owner=true");
            return;
        }
        blockAutomaticStartForOwner(
                expectedStartRequestId,
                expectedChannelBindingSha256,
                reason);
    }

    private void persistClosedAutomaticUsageGeneration(String reason) {
        try {
            persistAutomaticUsageBlock(true);
        } catch (GeneralSecurityException persistenceFailure) {
            events.write(
                    "dual_machine_automatic_usage_guard_persist_failed",
                    "reason=" + safeToken(reason)
                            + " fail_closed_in_process=true failure_type="
                            + persistenceFailure.getClass().getSimpleName());
        }
        events.write(
                "dual_machine_automatic_usage_rearm_blocked",
                "reason=" + safeToken(reason) + " "
                        + automaticUsageGuard.snapshot().detail());
    }

    private void recordLatestHostFrameFromNative() {
        try {
            MobileRuntimeSnapshot snapshot = MobileRuntimeSnapshot.from(
                    QnnHtpBridge.getNativeVideoReceiverReport(),
                    "", "", "");
            automaticUsageGuard.recordHostFrame(
                    snapshot.lastLogicalFrameSequence);
        } catch (RuntimeException | LinkageError ignored) {
            // An unavailable native metric never unlocks the fail-closed gate.
        }
    }

    private void checkpointAutomaticUsageGuardIfDue(
            long nowElapsedMillis,
            String source) throws GeneralSecurityException {
        AutomaticFormalUsageSessionGuard.Snapshot snapshot =
                automaticUsageGuard.snapshot();
        AutomaticUsageGuardCheckpointPolicy.Decision decision =
                automaticUsageCheckpointPolicy.evaluate(
                        nowElapsedMillis,
                        snapshot.lastHostFrameSequence);
        if (!decision.shouldPersist()) return;
        persistAutomaticUsageBlock(true);
        automaticUsageCheckpointPolicy.recordCheckpointSucceeded(
                nowElapsedMillis);
        events.write(
                "dual_machine_automatic_usage_guard_checkpointed",
                "source=" + safeToken(source)
                        + " checkpoint_reason=" + decision.reasonToken
                        + " interval_ms="
                        + AutomaticUsageGuardCheckpointPolicy
                        .CHECKPOINT_INTERVAL_MILLIS
                        + " " + automaticUsageGuard.snapshot().detail());
    }

    private void persistAutomaticUsageBlock(boolean blocked)
            throws GeneralSecurityException {
        AutomaticFormalUsageSessionGuard.Snapshot snapshot =
                automaticUsageGuard.snapshot();
        boolean committed = getSharedPreferences(
                AUTOMATIC_USAGE_GUARD_PREFERENCES,
                MODE_PRIVATE).edit()
                .putBoolean(AUTOMATIC_USAGE_GUARD_BLOCKED, blocked)
                .putLong(
                        AUTOMATIC_USAGE_GUARD_LAST_FRAME,
                        snapshot.lastHostFrameSequence)
                .putBoolean(
                        AUTOMATIC_USAGE_GUARD_RESUMABLE_BOUNDARY,
                        snapshot.state == AutomaticFormalUsageSessionGuard
                                .State.BLOCKED_UNTIL_HOST_PROGRESS_RESUMES)
                .commit();
        if (!committed) {
            throw new GeneralSecurityException(
                    "automatic usage guard persistence failed");
        }
        automaticUsageCheckpointPolicy.recordPersistence(
                snapshot.lastHostFrameSequence);
    }

    private void clearPersistedAutomaticUsageBlock() {
        boolean committed = getSharedPreferences(
                AUTOMATIC_USAGE_GUARD_PREFERENCES,
                MODE_PRIVATE).edit()
                .remove(AUTOMATIC_USAGE_GUARD_BLOCKED)
                .remove(AUTOMATIC_USAGE_GUARD_LAST_FRAME)
                .remove(AUTOMATIC_USAGE_GUARD_RESUMABLE_BOUNDARY)
                .commit();
        if (!committed) {
            events.write(
                    "dual_machine_automatic_usage_guard_clear_failed",
                    "fail_closed_after_process_restart=true");
            return;
        }
        automaticUsageCheckpointPolicy.clearPersisted();
    }

    private long readHostProgress() {
        String video = QnnHtpBridge.getNativeVideoReceiverReport();
        long progress = MobileRuntimeSnapshot.from(
                video, "", "", "").reassembledAccessUnits;
        if (progress < 0L) {
            throw new SecurityException(
                    "Host video progress is unavailable");
        }
        return progress;
    }

    private long readAndroidProgress() {
        String decoder = QnnHtpBridge.getNativeH264DecoderReport();
        long progress = MobileRuntimeSnapshot.from(
                "", decoder, "", "").renderedFrameCount;
        if (progress < 0L) {
            throw new SecurityException(
                    "Android decoder progress is unavailable");
        }
        return progress;
    }

    private void requestCardActivation(String cardCode) {
        queuedCardActivation.submit(cardCode);
    }

    private void requestPendingActivationResume() {
        executeAuthorizationOperation(
                "resume_activation",
                DualMachineAuthorizationUiState.Status.ACTIVATING,
                DualMachineAuthorizationRuntime::resumePendingActivation);
    }

    private void requestAuthorizationRefresh() {
        executeAuthorizationOperation(
                "refresh_status",
                DualMachineAuthorizationUiState.Status.REFRESHING,
                DualMachineAuthorizationRuntime::refreshStatus);
    }

    private void requestGameModelSelection(
            String modelToken,
            boolean operatorInitiated) {
        MobileModelCatalog.Profile selected = MobileModelCatalog.forProductionToken(modelToken);
        if (modelToken == null || !selected.token.equals(modelToken)
                || !MobileModelCatalog.isProductionSelectable(selected)) {
            events.write(
                    "mobile_game_model_rejected",
                    "reason=unsupported_model_token");
            return;
        }
        if (operatorInitiated) {
            boolean terminalSuppressionCleared =
                    PROCESS_RETRY_GATE.authorizeOperatorAttempt();
            if (terminalSuppressionCleared) {
                events.write(
                        "mobile_pipeline_operator_retry_authorized",
                        "source=game_model_selection model=" + selected.token
                                + " automatic_retry=false");
            }
        }
        try {
            runtimeExecutor.execute(() -> {
                try {
                    hotReloadGameModel(selected);
                } catch (RuntimeException | LinkageError failure) {
                    // Running transitions own their generation-scoped cleanup
                    // inside hotReloadGameModel. This last-resort boundary is
                    // diagnostic only; a stale task must never fail-close a
                    // fresh session after its stop latch has completed.
                    events.write(
                            "mobile_game_model_selection_failed",
                            "requested=" + selected.token
                                    + " active_transition_stopped=false"
                                    + " stack={"
                                    + MobileThrowableDiagnostics.format(failure) + "}");
                }
            });
        } catch (RuntimeException schedulingFailure) {
            controlRuntime.failClosed("game_model_switch_schedule_failed");
            events.write(
                    "mobile_game_model_selection_failed",
                    "stack={" + MobileThrowableDiagnostics.format(schedulingFailure) + "}");
        }
    }

    private void hotReloadGameModel(MobileModelCatalog.Profile selected) {
        FormalPipelineOwnerReceipt formalOwner =
                captureFormalPipelineOwner();
        MobileModelCatalog.Profile previous;
        long generation = -1L;
        MobileTransportEndpoint sessionEndpoint = null;
        boolean reloadBoundFormalPipeline = false;
        boolean reloadOwnerSuperseded = false;
        boolean deferredForFormalPreparation = false;
        boolean appliedWhileArmed = false;
        synchronized (pipelineCommandLock) {
            previous = controlRuntime.activeModel();
            if (destroying) return;
            if (formalModelPreparationInProgress) {
                // This assignment is intentional even when selected equals
                // the currently active model: it lets the user's latest
                // choice cancel an older deferred selection while a captured
                // formal model is still being prepared.
                pendingGameModelSelection = selected;
                deferredForFormalPreparation = true;
            } else {
                if (previous == selected) return;
                pendingGameModelSelection = null;
                generation = pipelineSessionGeneration.get();
                sessionEndpoint = formalSessionEndpoint;
                boolean runningWithPermit = formalDataPlanePermitOpen.get()
                        && runtimePermitIsActiveLocked(
                        System.nanoTime(), true)
                        && pipelineDesired
                        && pipelineStarted
                        && runtimeStatus.phase == MobileRuntimePhase.RUNNING
                        && sessionEndpoint != null;
                boolean preparedFormalGap = sessionEndpoint != null
                        && pipeline.isPreparedDataPlaneClosed();
                reloadBoundFormalPipeline = runningWithPermit
                        || preparedFormalGap;
                if (reloadBoundFormalPipeline) {
                    if (formalOwner == null
                            || !formalOwner.owns(
                            generation, sessionEndpoint)) {
                        reloadOwnerSuperseded = true;
                    } else {
                        gameModelHotReloadInProgress = true;
                        // A staged permit gap has already closed the receiver
                        // and may have set this false. Keep the transition
                        // owned by the same formal session.
                        pipelineDesired = true;
                        pipelineStarted = false;
                        pipelineNetworkHandle = 0L;
                    }
                } else {
                    // Commit the armed selection while holding the same lock
                    // used by formal preparation. A formal start therefore
                    // cannot capture the old model between the state check and
                    // the native post-process side effect.
                    controlRuntime.selectModel(selected);
                    appliedWhileArmed = true;
                }
            }
        }
        if (deferredForFormalPreparation) {
            events.write(
                    "mobile_game_model_selection_deferred",
                    "from=" + previous.token
                            + " to=" + selected.token
                            + " reason=formal_model_preparation_in_progress"
                            + " last_selection_wins=true");
            return;
        }
        if (reloadOwnerSuperseded) {
            events.write(
                    "mobile_game_model_hot_reload_finished",
                    "from=" + previous.token
                            + " to=" + selected.token
                            + " result=superseded action=none");
            return;
        }
        if (appliedWhileArmed) {
            events.write(
                    "mobile_game_model_hot_reload",
                    "from=" + previous.token
                            + " to=" + selected.token
                            + " result=applied_while_armed"
                            + " data_plane_active=false pipeline_restarted=false");
            return;
        }

        try {
            cancelReceiverLivenessProbe();
            controlRuntime.failClosed("game_model_hot_reload");
            updateStatus(
                    MobileRuntimePhase.STARTING,
                    "game_model_hot_reload from=" + previous.token
                            + " to=" + selected.token);
            updateNotification(R.string.runtime_notification_starting);
            events.write(
                    "mobile_game_model_hot_reload_started",
                    "from=" + previous.token
                            + " to=" + selected.token
                            + " lease_reused=true data_plane_temporarily_closed=true");

            MobilePipelineCoordinator.PrepareResult prepared =
                    prepareModelDataPlaneClosed(
                            lastNativeDirectory,
                            lastSkeletonDirectory,
                            selected);
            if (prepared.prepared) {
                HotReloadCommitResult committed;
                try {
                    committed = commitPreparedHotReloadModelIfCurrent(
                            generation,
                            sessionEndpoint,
                            formalOwner,
                            selected,
                            "game_model_hot_reload_applied model="
                                    + selected.token);
                } catch (RuntimeException | LinkageError failure) {
                    committed = HotReloadCommitResult.failure(
                            "native_postprocess_commit_exception stack={"
                                    + MobileThrowableDiagnostics.format(failure)
                                    + "}");
                }
                if (committed.outcome == HotReloadCommitOutcome.OPENED
                        || committed.outcome
                        == HotReloadCommitOutcome.APPLIED_WAITING_FOR_PERMIT) {
                    events.write(
                            "mobile_game_model_hot_reload_finished",
                            "from=" + previous.token
                                    + " to=" + selected.token
                                    + " result="
                                    + (committed.outcome
                                    == HotReloadCommitOutcome.OPENED
                                    ? "success" : "applied_waiting_for_permit")
                                    + " lease_reused=true"
                                    + " service_restarted=false"
                                    + " data_plane_open="
                                    + (committed.outcome
                                    == HotReloadCommitOutcome.OPENED));
                    return;
                }
                if (committed.outcome == HotReloadCommitOutcome.SUPERSEDED) {
                    finishSupersededGameModelHotReload(
                            previous, selected, generation);
                    return;
                }
                prepared = MobilePipelineCoordinator.PrepareResult.failure(
                        committed.message,
                        MobilePipelineCoordinator.FailureDisposition.RETRYABLE,
                        "native_postprocess_apply_failed");
            }
            rollbackGameModelHotReload(
                    previous,
                    selected,
                    generation,
                    sessionEndpoint,
                    formalOwner,
                    prepared);
        } catch (RuntimeException | LinkageError failure) {
            failUnexpectedGameModelHotReloadIfCurrent(
                    previous,
                    selected,
                    generation,
                    sessionEndpoint,
                    formalOwner,
                    failure);
        }
    }

    private MobilePipelineCoordinator.PrepareResult
            prepareModelDataPlaneClosed(
            String nativeDirectory,
            String skeletonDirectory,
            MobileModelCatalog.Profile model) {
        MobileInferenceBackendPolicy.Plan plan = lastInferenceBackendPlan;
        if (plan == null) {
            plan = MobileInferenceBackendPolicy.evaluate(
                    currentSocCompatibility());
        }
        return prepareModelDataPlaneClosed(
                nativeDirectory, skeletonDirectory, model, plan);
    }

    private MobilePipelineCoordinator.PrepareResult
            prepareModelDataPlaneClosed(
            String nativeDirectory,
            String skeletonDirectory,
            MobileModelCatalog.Profile model,
            MobileInferenceBackendPolicy.Plan plan) {
        synchronized (modelPreparationLock) {
            MobileInferenceFailurePolicy.Accumulator failures =
                    new MobileInferenceFailurePolicy.Accumulator();
            MobileInferencePreparationAssets portableAssets = null;
            for (MobileInferenceBackend backend : plan.candidates) {
                MobileInferencePreparationAssets assets;
                if (backend.requiresQnnRuntime) {
                    assets = resolveQnnInferenceAssets(skeletonDirectory);
                } else {
                    if (portableAssets == null) {
                        portableAssets = resolvePortableInferenceAssets(model);
                    }
                    assets = portableAssets;
                }
                if (!assets.ready) {
                    MobilePipelineCoordinator.PrepareResult assetFailure =
                            assetResolutionFailure(backend, assets);
                    failures.record(backend, assetFailure);
                    logInferenceBackendAttempt(
                            backend, "asset_resolution_failed", assets.detail);
                    continue;
                }
                MobilePipelineCoordinator.PrepareResult prepared =
                        pipeline.prepareDataPlaneClosed(
                                backend,
                                nativeDirectory,
                                assets.vendorRuntimeDirectory,
                                assets.portableModelPath,
                                model);
                if (prepared.prepared) {
                    lastPreparedInferenceBackend = backend;
                    if (backend.requiresQnnRuntime) {
                        lastSkeletonDirectory =
                                assets.vendorRuntimeDirectory;
                    }
                    logInferenceBackendAttempt(
                            backend, "prepared", assets.detail);
                    return prepared;
                }
                failures.record(backend, prepared);
                logInferenceBackendAttempt(
                        backend, "prepare_failed", prepared.message);
            }
            lastPreparedInferenceBackend = null;
            return failures.resolve();
        }
    }

    private MobileInferencePreparationAssets resolveQnnInferenceAssets(
            String preferredDirectory) {
        List<String> architectures = QnnAssetBundleInstaller.parseArchitectures(
                BuildConfig.QNN_HTP_ARCHITECTURES);
        File directory = preferredDirectory == null
                ? null : new File(preferredDirectory);
        String installerDetail = "reused_verified_process_install=true";
        if (directory == null || !directory.isDirectory()) {
            QnnAssetBundleInstaller.Result installed =
                    QnnAssetBundleInstaller.ensureInstalled(
                            getFilesDir(),
                            name -> getAssets().open("qnn/" + name),
                            BuildConfig.QNN_HTP_ARCHITECTURES);
            if (!installed.ready || installed.directory == null) {
                return MobileInferencePreparationAssets.failure(
                        installed.detail, installed.failure);
            }
            directory = installed.directory;
            architectures = installed.architectures;
            installerDetail = installed.detail;
        }
        QnnHtpCompatibilityPolicy.Result compatibility =
                QnnHtpCompatibilityPolicy.evaluate(
                        AndroidDeviceProfileCollector.collectSocModel(),
                        architectures);
        events.write(
                "mobile_qnn_htp_compatibility",
                compatibility.detail()
                        + " packaged_architectures="
                        + String.join(",", architectures));
        if (!compatibility.canAttemptBackend) {
            return MobileInferencePreparationAssets.failure(
                    compatibility.failureCode + " " + compatibility.detail(),
                    null,
                    MobilePipelineCoordinator.FailureDisposition
                            .TERMINAL_INCOMPATIBLE,
                    compatibility.failureCode);
        }
        return MobileInferencePreparationAssets.qnn(
                directory.getAbsolutePath(),
                installerDetail + " " + compatibility.detail());
    }

    private MobileInferencePreparationAssets resolvePortableInferenceAssets(
            MobileModelCatalog.Profile model) {
        PortableModelAssetInstaller.Result installed =
                PortableModelAssetInstaller.ensureInstalled(
                        getFilesDir(),
                        model,
                        name -> getAssets().open("portable_models/" + name));
        events.write(
                installed.ready
                        ? "mobile_portable_model_ready"
                        : "mobile_portable_model_failed",
                installed.detail);
        if (!installed.ready || installed.modelFile == null) {
            return MobileInferencePreparationAssets.failure(
                    installed.detail, installed.failure);
        }
        return MobileInferencePreparationAssets.portable(
                installed.modelFile.getAbsolutePath(), installed.detail);
    }

    private MobilePipelineCoordinator.PrepareResult assetResolutionFailure(
            MobileInferenceBackend backend,
            MobileInferencePreparationAssets assets) {
        String stack = assets.failure == null
                ? "none" : MobileThrowableDiagnostics.format(assets.failure);
        return MobilePipelineCoordinator.PrepareResult.failure(
                "inference_asset_resolution_failed backend=" + backend.token
                        + " detail={" + assets.detail + "} stack={" + stack + "}",
                assets.disposition,
                "inference_asset_resolution_failed".equals(assets.failureCode)
                        ? (backend.requiresQnnRuntime
                        ? "qnn_asset_bundle_invalid"
                        : "portable_model_unavailable")
                        : assets.failureCode);
    }

    private void logInferenceBackendAttempt(
            MobileInferenceBackend backend,
            String result,
            String detail) {
        events.write(
                "mobile_inference_backend_attempt",
                "backend=" + backend.token
                        + " result=" + result
                        + " detail={" + detail + "}");
    }

    private static MobileSocCompatibilityPolicy.Result
            currentSocCompatibility() {
        return MobileSocCompatibilityPolicy.evaluate(
                AndroidDeviceProfileCollector.collectSocModel(),
                AndroidDeviceProfileCollector.collectSocManufacturer(),
                AndroidDeviceProfileCollector.collectSocHardwareEvidence());
    }

    private boolean hotReloadSessionIdentityIsCurrent(
            long generation,
            MobileTransportEndpoint expectedEndpoint) {
        MobileTransportEndpoint currentEndpoint = requiredTransportEndpoint();
        synchronized (pipelineCommandLock) {
            return hotReloadSessionIdentityIsCurrentLocked(
                    generation, expectedEndpoint, currentEndpoint);
        }
    }

    private HotReloadCommitResult commitPreparedHotReloadModelIfCurrent(
            long generation,
            MobileTransportEndpoint expectedEndpoint,
            FormalPipelineOwnerReceipt formalOwner,
            MobileModelCatalog.Profile selected,
            String runningDetail) {
        if (formalOwner == null
                || !hotReloadSessionIdentityIsCurrent(
                generation, expectedEndpoint)) {
            return HotReloadCommitResult.superseded();
        }
        final long reconciledAndroidProgress;
        try {
            reconciledAndroidProgress = formalOwner.runtime
                    .reconcileKnownAndroidPipelineRestart(
                            formalOwner.authorizationReceipt);
        } catch (DualMachineFormalUsageCoordinator
                         .AdmissionSupersededException | IOException superseded) {
            return HotReloadCommitResult.superseded();
        }
        events.write(
                "mobile_game_model_hot_reload_progress_reconciled",
                "model=" + selected.token
                        + " android_session_progress="
                        + reconciledAndroidProgress
                        + " reset_sampled_before_data_plane_open=true");
        MobileTransportEndpoint currentEndpoint = requiredTransportEndpoint();
        synchronized (pipelineCommandLock) {
            if (!hotReloadSessionIdentityIsCurrentLocked(
                    generation, expectedEndpoint, currentEndpoint)) {
                return HotReloadCommitResult.superseded();
            }
            // The model-specific native post-process commit and the session
            // generation check are one critical section. A stop or fresh
            // formal start cannot interleave after the check and inherit a
            // stale model side effect.
            controlRuntime.selectModel(selected);
            if (!controlRuntime.isNativePostprocessApplied()) {
                return HotReloadCommitResult.failure(
                        "native_postprocess_apply_failed");
            }
            if (!runtimePermitIsActiveLocked(System.nanoTime(), true)) {
                gameModelHotReloadInProgress = false;
                pipelineStarted = false;
                pipelineNetworkHandle = 0L;
                return HotReloadCommitResult.appliedWaitingForPermit();
            }
            MobilePipelineCoordinator.StartResult opened =
                    pipeline.openPreparedDataPlane(
                            expectedEndpoint, selected);
            if (!opened.started) {
                return HotReloadCommitResult.failure(opened.message);
            }
            currentEndpoint = requiredTransportEndpoint();
            if (!hotReloadSessionIdentityIsCurrentLocked(
                    generation, expectedEndpoint, currentEndpoint)
                    || !runtimePermitIsActiveLocked(
                    System.nanoTime(), true)) {
                pipeline.closeDataPlane();
                return HotReloadCommitResult.failure(
                        "game_model_hot_reload_superseded_after_open");
            }
            pipelineStarted = true;
            pipelineNetworkHandle = expectedEndpoint.networkHandle;
            gameModelHotReloadInProgress = false;
            updateStatus(MobileRuntimePhase.RUNNING, runningDetail);
            updateNotification(R.string.runtime_notification_running);
            scheduleReceiverLivenessProbe(
                    RECEIVER_ACTIVE_LIVENESS_PROBE_MILLIS, true);
            return HotReloadCommitResult.opened();
        }
    }

    private boolean hotReloadSessionIdentityIsCurrentLocked(
            long generation,
            MobileTransportEndpoint expectedEndpoint,
            MobileTransportEndpoint currentEndpoint) {
        return hotReloadOwnerIsCurrentLocked(generation, expectedEndpoint)
                && pipelineDesired
                && expectedEndpoint.hasSameDataPlaneRoute(currentEndpoint)
                && expectedEndpoint.hasSameDataPlaneRoute(formalSessionEndpoint);
    }

    private boolean hotReloadOwnerIsCurrentLocked(
            long generation,
            MobileTransportEndpoint expectedEndpoint) {
        return !destroying
                && generation == pipelineSessionGeneration.get()
                && gameModelHotReloadInProgress
                && expectedEndpoint != null
                && formalSessionEndpoint != null
                && expectedEndpoint.hasSameDataPlaneRoute(
                formalSessionEndpoint);
    }

    private void rollbackGameModelHotReload(
            MobileModelCatalog.Profile previous,
            MobileModelCatalog.Profile requested,
            long generation,
            MobileTransportEndpoint sessionEndpoint,
            FormalPipelineOwnerReceipt formalOwner,
            MobilePipelineCoordinator.PrepareResult failed) {
        MobilePipelineCoordinator.PrepareResult rollback;
        synchronized (modelPreparationLock) {
            // A stopped/superseded reload must never prepare its old model:
            // doing so can stop the receiver of a freshly started session.
            if (!hotReloadSessionIdentityIsCurrent(
                    generation, sessionEndpoint)) {
                finishSupersededGameModelHotReload(
                        previous, requested, generation);
                return;
            }
            rollback = prepareModelDataPlaneClosed(
                    lastNativeDirectory,
                    lastSkeletonDirectory,
                    previous);
        }
        if (rollback.prepared) {
            HotReloadCommitResult committed;
            try {
                committed = commitPreparedHotReloadModelIfCurrent(
                        generation,
                        sessionEndpoint,
                        formalOwner,
                        previous,
                        "game_model_hot_reload_rolled_back model="
                                + previous.token);
            } catch (RuntimeException | LinkageError failure) {
                committed = HotReloadCommitResult.failure(
                        "rollback_native_postprocess_commit_exception stack={"
                                + MobileThrowableDiagnostics.format(failure)
                                + "}");
            }
            if (committed.outcome == HotReloadCommitOutcome.OPENED
                    || committed.outcome
                    == HotReloadCommitOutcome.APPLIED_WAITING_FOR_PERMIT) {
                events.write(
                        "mobile_game_model_hot_reload_finished",
                        "from=" + previous.token
                                + " to=" + requested.token
                                + " result=rolled_back reason={"
                                + failed.message + "} lease_reused=true"
                                + " data_plane_open="
                                + (committed.outcome
                                == HotReloadCommitOutcome.OPENED));
                return;
            }
            if (committed.outcome == HotReloadCommitOutcome.SUPERSEDED) {
                finishSupersededGameModelHotReload(
                        previous, requested, generation);
                return;
            }
            failed = MobilePipelineCoordinator.PrepareResult.failure(
                    committed.message,
                    MobilePipelineCoordinator.FailureDisposition.RETRYABLE,
                    "rollback_native_postprocess_apply_failed");
        }

        String failedMessage = failed.message;
        String rollbackMessage = rollback.message;
        AtomicReference<Throwable> pipelineStopFailure =
                new AtomicReference<>();
        FormalOwnerStopResult stopResult =
                stopFormalUsageIfCurrentOwner(
                        formalOwner,
                        () -> hotReloadSessionIdentityIsCurrentLocked(
                                generation,
                                sessionEndpoint,
                                transportCatalog.selected()),
                        () -> {
                            gameModelHotReloadInProgress = false;
                            try {
                                pipeline.stop();
                            } catch (RuntimeException | LinkageError failure) {
                                pipelineStopFailure.set(failure);
                            }
                            pipelineStarted = false;
                            pipelineNetworkHandle = 0L;
                            updateStatus(
                                    MobileRuntimePhase.FAILED,
                                    "game_model_hot_reload_failed requested="
                                            + requested.token
                                            + " reason={" + failedMessage + "}"
                                            + " rollback_reason={"
                                            + rollbackMessage + "}");
                            updateNotification(
                                    R.string.runtime_notification_failed);
                        },
                        "game_model_hot_reload_failed");
        if (stopResult == FormalOwnerStopResult.SUPERSEDED) {
            finishSupersededGameModelHotReload(
                    previous, requested, generation);
            return;
        }
        events.write(
                "mobile_game_model_hot_reload_finished",
                "from=" + previous.token
                        + " to=" + requested.token
                        + " result=failed lease_reused=false"
                        + " formal_stop="
                        + stopResult.name().toLowerCase(Locale.ROOT)
                        + " reason={" + failedMessage + "}"
                        + " rollback_reason={" + rollbackMessage + "}"
                        + failureDetail(
                        "pipeline_stop", pipelineStopFailure.get()));
    }

    private void finishSupersededGameModelHotReload(
            MobileModelCatalog.Profile previous,
            MobileModelCatalog.Profile requested,
            long generation) {
        synchronized (pipelineCommandLock) {
            if (generation == pipelineSessionGeneration.get()) {
                gameModelHotReloadInProgress = false;
            }
        }
        events.write(
                "mobile_game_model_hot_reload_finished",
                "from=" + previous.token
                        + " to=" + requested.token
                        + " result=superseded action=none");
    }

    private void failUnexpectedGameModelHotReloadIfCurrent(
            MobileModelCatalog.Profile previous,
            MobileModelCatalog.Profile requested,
            long generation,
            MobileTransportEndpoint expectedEndpoint,
            FormalPipelineOwnerReceipt formalOwner,
            Throwable failure) {
        AtomicReference<Throwable> pipelineStopFailure =
                new AtomicReference<>();
        FormalOwnerStopResult stopResult =
                stopFormalUsageIfCurrentOwner(
                        formalOwner,
                        () -> hotReloadOwnerIsCurrentLocked(
                                generation, expectedEndpoint),
                        () -> {
                            // Revoke the capability before either executor can
                            // publish a replacement formal pipeline.
                            invalidateRuntimePermitWindowLocked();
                            pipelineSessionGeneration.incrementAndGet();
                            pipelineDesired = false;
                            pipelineStarted = false;
                            pipelineNetworkHandle = 0L;
                            formalSessionChannelBinding = "";
                            formalSessionEndpoint = null;
                            gameModelHotReloadInProgress = false;
                            try {
                                pipeline.stop();
                            } catch (RuntimeException | LinkageError
                                     stopFailure) {
                                pipelineStopFailure.set(stopFailure);
                            }
                        },
                        "game_model_hot_reload_unexpected_exception");
        if (stopResult == FormalOwnerStopResult.SUPERSEDED) {
            events.write(
                    "mobile_game_model_hot_reload_failed",
                    "from=" + previous.token
                            + " to=" + requested.token
                            + " result=superseded action=none"
                            + " stack={"
                            + MobileThrowableDiagnostics.format(failure) + "}");
            return;
        }
        events.write(
                "mobile_game_model_hot_reload_failed",
                "from=" + previous.token
                        + " to=" + requested.token
                        + " current_generation_revoked=true"
                        + " formal_stop="
                        + stopResult.name().toLowerCase(Locale.ROOT)
                        + " action="
                        + (stopResult == FormalOwnerStopResult.CLAIMED
                        ? "exact_owner_stop" : "no_cross_generation_cleanup")
                        + " stack={"
                        + MobileThrowableDiagnostics.format(failure) + "}"
                        + failureDetail(
                        "pipeline_stop", pipelineStopFailure.get()));
    }

    private enum HotReloadCommitOutcome {
        OPENED,
        APPLIED_WAITING_FOR_PERMIT,
        SUPERSEDED,
        FAILED
    }

    private static final class HotReloadCommitResult {
        final HotReloadCommitOutcome outcome;
        final String message;

        private HotReloadCommitResult(
                HotReloadCommitOutcome outcome,
                String message) {
            this.outcome = outcome;
            this.message = message;
        }

        static HotReloadCommitResult opened() {
            return new HotReloadCommitResult(
                    HotReloadCommitOutcome.OPENED, "opened");
        }

        static HotReloadCommitResult appliedWaitingForPermit() {
            return new HotReloadCommitResult(
                    HotReloadCommitOutcome.APPLIED_WAITING_FOR_PERMIT,
                    "applied_waiting_for_permit");
        }

        static HotReloadCommitResult superseded() {
            return new HotReloadCommitResult(
                    HotReloadCommitOutcome.SUPERSEDED, "superseded");
        }

        static HotReloadCommitResult failure(String message) {
            return new HotReloadCommitResult(
                    HotReloadCommitOutcome.FAILED, message);
        }
    }

    private void requestOutputRouteSelection(String routeToken) {
        ControlOutputRoute requestedRoute = ControlOutputRoute.fromStorageToken(routeToken);
        if (requestedRoute == ControlOutputRoute.NONE) {
            events.write("mobile_control_output_route_rejected",
                    "reason=unsupported_route route=" + safeToken(routeToken));
            return;
        }
        try {
            runtimeExecutor.execute(() -> {
                String reason = controlRuntime.selectOutputRoute(requestedRoute);
                events.write("mobile_control_output_route_command",
                        "requested_route=" + requestedRoute.storageToken
                                + " reason=" + safeToken(reason)
                                + " hot_applied=true pipeline_restarted=false");
            });
        } catch (RuntimeException schedulingFailure) {
            controlRuntime.failClosed("control_output_route_switch_schedule_failed");
            events.write("mobile_control_output_route_selection_failed",
                    "stack={" + MobileThrowableDiagnostics.format(schedulingFailure) + "}");
        }
    }

    private void requestDebugBluetoothHidMoveProbe(
            int deltaX,
            int deltaY,
            int reports,
            int intervalMillis) {
        if (controlRuntime == null) {
            events.write("mobile_control_bluetooth_hid_move_probe",
                    "scheduled=false reason=runtime_not_ready");
            return;
        }
        try {
            runtimeExecutor.execute(() -> {
                String result = controlRuntime.runDebugBluetoothHidMoveProbe(
                        deltaX, deltaY, reports, intervalMillis);
                events.write("mobile_control_bluetooth_hid_move_probe", safeToken(result));
            });
        } catch (RuntimeException schedulingFailure) {
            controlRuntime.failClosed("bluetooth_hid_move_probe_schedule_failed");
            events.write("mobile_control_bluetooth_hid_move_probe_failed",
                    "stack={" + MobileThrowableDiagnostics.format(schedulingFailure) + "}");
        }
    }

    /**
     * Captures authorization first and the downstream pipeline second. Never
     * call this while holding {@link #pipelineCommandLock}.
     */
    private FormalPipelineOwnerReceipt captureFormalPipelineOwner() {
        DualMachineAuthorizationRuntime runtime = authorizationRuntime;
        if (runtime == null) return null;
        final DualMachineAuthorizationRuntime.CurrentGenerationReceipt
                authorizationReceipt;
        try {
            authorizationReceipt = runtime.captureCurrentGenerationReceipt();
        } catch (DualMachineFormalUsageCoordinator
                         .AdmissionSupersededException superseded) {
            return null;
        }
        AtomicReference<FormalPipelineOwnerReceipt> captured =
                new AtomicReference<>();
        boolean current = runtime.commitIfCurrent(
                authorizationReceipt,
                () -> {
                    synchronized (pipelineCommandLock) {
                        if (authorizationRuntime != runtime) return;
                        captured.set(new FormalPipelineOwnerReceipt(
                                runtime,
                                authorizationReceipt,
                                pipelineSessionGeneration.get(),
                                formalSessionEndpoint));
                    }
                });
        return current ? captured.get() : null;
    }

    private boolean formalPipelineOwnerIsCurrentLocked(
            FormalPipelineOwnerReceipt owner) {
        if (owner == null || authorizationRuntime != owner.runtime
                || owner.pipelineGeneration
                != pipelineSessionGeneration.get()) {
            return false;
        }
        MobileTransportEndpoint current = formalSessionEndpoint;
        if (owner.endpoint == null || current == null) {
            return owner.endpoint == current;
        }
        return owner.endpoint.hasSameDataPlaneRoute(current);
    }

    private boolean commitFormalPipelineOwnerIfCurrent(
            FormalPipelineOwnerReceipt owner,
            Runnable commit) {
        if (owner == null || commit == null) return false;
        AtomicBoolean committed = new AtomicBoolean();
        boolean authorizationCurrent = owner.runtime.commitIfCurrent(
                owner.authorizationReceipt,
                () -> {
                    synchronized (pipelineCommandLock) {
                        if (!formalPipelineOwnerIsCurrentLocked(owner)) {
                            return;
                        }
                        commit.run();
                        committed.set(true);
                    }
                });
        return authorizationCurrent && committed.get();
    }

    /**
     * Rechecks one immutable owner and failure predicate under the canonical
     * attachment-to-pipeline lock order, claims the global stop latch there,
     * then queues only the exact lifecycle handle outside both locks.
     */
    private FormalOwnerStopResult stopFormalUsageIfCurrentOwner(
            FormalPipelineOwnerReceipt owner,
            BooleanSupplier failureStillPresentLocked,
            Runnable claimedPipelineMutationLocked,
            String reason) {
        if (owner == null || failureStillPresentLocked == null
                || claimedPipelineMutationLocked == null) {
            return FormalOwnerStopResult.SUPERSEDED;
        }
        AtomicBoolean ownerAndFailureCurrent = new AtomicBoolean();
        AtomicBoolean claimedByThisCall = new AtomicBoolean();
        AtomicBoolean alreadyQueued = new AtomicBoolean();
        AtomicReference<Throwable> claimMutationFailure =
                new AtomicReference<>();
        DualMachineAuthorizationRuntime.FormalUsageLifecycleHandle handle;
        try {
            handle = owner.runtime.beginFormalUsageLifecycleStopIfCurrent(
                    owner.authorizationReceipt,
                    () -> {
                        synchronized (pipelineCommandLock) {
                            if (!formalPipelineOwnerIsCurrentLocked(owner)
                                    || !failureStillPresentLocked
                                    .getAsBoolean()) {
                                return false;
                            }
                            ownerAndFailureCurrent.set(true);
                            if (!automaticFormalStopQueued.compareAndSet(
                                    false, true)) {
                                alreadyQueued.set(true);
                                return false;
                            }
                            claimedByThisCall.set(true);
                            try {
                                claimedPipelineMutationLocked.run();
                            } catch (RuntimeException | LinkageError failure) {
                                claimMutationFailure.set(failure);
                            }
                            return true;
                        }
                    });
        } catch (RuntimeException | LinkageError failure) {
            if (claimedByThisCall.get()) {
                automaticFormalStopQueued.compareAndSet(true, false);
            }
            throw failure;
        }
        if (handle == null) {
            return ownerAndFailureCurrent.get() && alreadyQueued.get()
                    ? FormalOwnerStopResult.ALREADY_QUEUED
                    : FormalOwnerStopResult.SUPERSEDED;
        }
        try {
            clearFormalSessionBinding();
            queuePendingFormalStartCancellation(
                    handle.startCancellationHandle(), reason);
            queueClaimedFormalUsageStop(handle, reason);
        } catch (RuntimeException | LinkageError queueFailure) {
            // The exact handle remains owned; complete it inline rather than
            // release the latch or touch a later generation.
            runClaimedFormalUsageStop(handle, reason);
            throw queueFailure;
        }
        if (claimMutationFailure.get() != null) {
            events.write(
                    "dual_machine_formal_owner_stop_cleanup_failed",
                    "reason=" + safeToken(reason)
                            + " exact_stop_queued=true stack={"
                            + MobileThrowableDiagnostics.format(
                            claimMutationFailure.get())
                            + "}");
        }
        return FormalOwnerStopResult.CLAIMED;
    }

    private FormalOwnerStopResult stopFormalUsageIfCurrentOwner(
            FormalPipelineOwnerReceipt owner,
            BooleanSupplier failureStillPresentLocked,
            String reason) {
        return stopFormalUsageIfCurrentOwner(
                owner, failureStillPresentLocked, () -> { }, reason);
    }

    private void requestFormalUsageStop(String reason) {
        DualMachineAuthorizationRuntime runtime = authorizationRuntime;
        if (runtime == null) {
            stopPipeline("formal_stop_without_authorization_runtime_" + reason);
            blockAutomaticStartForCurrentHostStream(reason);
            clearFormalSessionBinding();
            events.write(
                    "dual_machine_formal_stop_deferred",
                    "reason=" + safeToken(reason)
                            + " authorization_runtime_ready=false");
            return;
        }
        boolean claimedStop = automaticFormalStopQueued.compareAndSet(
                false, true);
        if (!claimedStop) {
            runtime.requestImmediateLocalStop();
            blockAutomaticStartForCurrentHostStream(reason);
            clearFormalSessionBinding();
            return;
        }
        // The Runtime creates an epoch owner before local closure. Even an
        // empty handle blocks a start already queued behind this command.
        DualMachineAuthorizationRuntime.FormalUsageLifecycleHandle
                lifecycleStopHandle =
                runtime.beginFormalUsageLifecycleStop();
        DualMachineFormalUsageCoordinator.StartCancellationHandle
                cancellationHandle =
                lifecycleStopHandle.startCancellationHandle();
        blockAutomaticStartForCurrentHostStream(reason);
        clearFormalSessionBinding();
        queuePendingFormalStartCancellation(cancellationHandle, reason);
        queueClaimedFormalUsageStop(lifecycleStopHandle, reason);
    }

    /**
     * Replays one ambiguous formal stop only when its generation-bound retry
     * window is due. The Runtime evaluates ownership and backoff before this
     * service acquires the global stop latch, so 250 ms maintenance ticks do
     * not manufacture empty lifecycle owners or repeated teardown work.
     */
    private void retryFormalUsageStopIfDue(
            DualMachineAuthorizationRuntime runtime,
            DualMachineAuthorizationRuntime.CurrentGenerationReceipt receipt,
            String reason) {
        AtomicBoolean claimedByThisCall = new AtomicBoolean();
        DualMachineAuthorizationRuntime.FormalUsageLifecycleHandle handle;
        try {
            handle = runtime.beginFormalUsageLifecycleStopRetryIfCurrent(
                    receipt,
                    () -> {
                        boolean claimed = automaticFormalStopQueued
                                .compareAndSet(false, true);
                        claimedByThisCall.set(claimed);
                        return claimed;
                    });
        } catch (RuntimeException | LinkageError failure) {
            if (claimedByThisCall.get()) {
                automaticFormalStopQueued.compareAndSet(true, false);
            }
            throw failure;
        }
        if (handle == null) return;
        try {
            blockAutomaticStartForCurrentHostStream(reason);
            clearFormalSessionBinding();
            queuePendingFormalStartCancellation(
                    handle.startCancellationHandle(), reason);
            queueClaimedFormalUsageStop(handle, reason);
        } catch (RuntimeException | LinkageError queueFailure) {
            runClaimedFormalUsageStop(handle, reason);
            throw queueFailure;
        }
    }

    private void retryFormalUsageStopWithoutAuthenticatedHostIfDue(
            DualMachineAuthorizationRuntime runtime,
            String reason) {
        AtomicBoolean claimedByThisCall = new AtomicBoolean();
        DualMachineAuthorizationRuntime.FormalUsageLifecycleHandle handle;
        try {
            handle = runtime
                    .beginFormalUsageLifecycleStopRetryWithoutAuthenticatedHost(
                    () -> {
                        boolean claimed = automaticFormalStopQueued
                                .compareAndSet(false, true);
                        claimedByThisCall.set(claimed);
                        return claimed;
                    });
        } catch (RuntimeException | LinkageError failure) {
            if (claimedByThisCall.get()) {
                automaticFormalStopQueued.compareAndSet(true, false);
            }
            throw failure;
        }
        if (handle == null) return;
        try {
            blockAutomaticStartForCurrentHostStream(reason);
            clearFormalSessionBinding();
            queuePendingFormalStartCancellation(
                    handle.startCancellationHandle(), reason);
            queueClaimedFormalUsageStop(handle, reason);
        } catch (RuntimeException | LinkageError queueFailure) {
            runClaimedFormalUsageStop(handle, reason);
            throw queueFailure;
        }
    }

    private void queuePendingFormalStartCancellation(
            DualMachineFormalUsageCoordinator.StartCancellationHandle handle,
            String reason) {
        if (handle == null) {
            events.write(
                    "dual_machine_formal_start_cancellation",
                    "reason=" + safeToken(reason)
                            + " exact_request=false pending_start=false");
            return;
        }
        try {
            startCancellationExecutor.execute(() -> {
                boolean confirmed = handle.sendExactCancellation();
                events.write(
                        "dual_machine_formal_start_cancellation",
                        "reason=" + safeToken(reason)
                                + " start_request_id="
                                + handle.startRequestId
                                + " exact_request=true server_confirmed="
                                + confirmed);
            });
        } catch (RuntimeException | LinkageError schedulingFailure) {
            events.write(
                    "dual_machine_formal_start_cancellation_deferred",
                    "reason=" + safeToken(reason)
                            + " exact_retry_owned_by_formal_stop=true");
        }
    }

    private void queueClaimedFormalUsageStop(
            DualMachineAuthorizationRuntime.FormalUsageLifecycleHandle handle,
            String reason) {
        try {
            publishTransientAuthorizationState(
                    DualMachineAuthorizationUiState.Status.STOPPING);
            authorizationExecutor.execute(
                    () -> runClaimedFormalUsageStop(handle, reason));
        } catch (RuntimeException | LinkageError schedulingFailure) {
            try {
                // The cancellation executor is independent from a blocked or
                // shutting-down authorization worker. Its earlier exact cancel
                // runs first; this fallback then owns the STOPPING transition.
                startCancellationExecutor.execute(
                        () -> runClaimedFormalUsageStop(handle, reason));
            } catch (RuntimeException | LinkageError fallbackFailure) {
                // Catastrophic executor rejection is rare and local closure is
                // already complete. Finish inline rather than release the stop
                // latch and accidentally permit an exact start replay.
                runClaimedFormalUsageStop(handle, reason);
            }
        }
    }

    private void runClaimedFormalUsageStop(
            DualMachineAuthorizationRuntime.FormalUsageLifecycleHandle handle,
            String reason) {
        try {
            if (handle == null) {
                events.write(
                        "dual_machine_formal_stop_finished",
                        "reason=" + safeToken(reason)
                                + " local_closed=true server_confirmed=false"
                                + " formal_generation=false");
                publishMappedAuthorizationState("");
                return;
            }
            if (!handle.hasFormalGeneration()) {
                handle.stopFormalUsage();
                events.write(
                        "dual_machine_formal_stop_finished",
                        "reason=" + safeToken(reason)
                                + " local_closed=true server_confirmed=false"
                                + " formal_generation=false"
                                + " empty_stop_barrier_completed=true");
                publishMappedAuthorizationState("");
                return;
            }
            DualMachineFormalUsageCoordinator.StopOutcome outcome =
                    handle.stopFormalUsage();
            settleAutomaticUsageReservation(
                    handle.startRequestId,
                    handle.channelBindingSha256,
                    outcome,
                    reason);
            events.write(
                    "dual_machine_formal_stop_finished",
                    "reason=" + safeToken(reason)
                            + " local_closed=" + outcome.localClosed
                            + " server_confirmed="
                            + outcome.serverConfirmed);
            publishMappedAuthorizationState("");
        } catch (RuntimeException failure) {
            if (handle != null && handle.hasFormalGeneration()) {
                blockAutomaticStartForOwner(
                        handle.startRequestId,
                        handle.channelBindingSha256,
                        reason + "_settlement_failed");
            }
            events.write(
                    "dual_machine_formal_stop_failed",
                    "failure_type=" + failure.getClass().getSimpleName()
                            + " local_stop_latched=true");
            publishMappedAuthorizationState(getString(
                    R.string.authorization_operation_failed));
        } finally {
            try {
                releaseFormalTransportPinAfterSession(
                        "formal_stop_finished");
                reconcileRuntimeLocksAfterDataPlaneClose(
                        "formal_stop_finished");
            } finally {
                automaticFormalStopQueued.set(false);
            }
        }
    }

    private void executeAuthorizationOperation(
            String operation,
            DualMachineAuthorizationUiState.Status busyStatus,
            AuthorizationOperation action) {
        DualMachineAuthorizationRuntime runtime = authorizationRuntime;
        if (runtime == null || authorizationSecurityFatal) {
            publishFatalAuthorizationState();
            return;
        }
        if (!authorizationOperationInFlight.compareAndSet(false, true)) {
            publishMappedAuthorizationState(getString(
                    R.string.authorization_operation_in_progress));
            return;
        }
        publishTransientAuthorizationState(busyStatus);
        try {
            authorizationExecutor.execute(() -> {
                try {
                    action.run(runtime);
                    events.write(
                            "dual_machine_authorization_operation",
                            "operation=" + operation
                                    + " result=success card_logged=false");
                    publishMappedAuthorizationState("");
                } catch (IOException | GeneralSecurityException
                         | RuntimeException failure) {
                    events.write(
                            "dual_machine_authorization_operation",
                            "operation=" + operation
                                    + " result=failed failure_type="
                                    + failure.getClass().getSimpleName()
                                    + " card_logged=false data_plane_open=false"
                                    + " stack={"
                                    + MobileThrowableDiagnostics.format(
                                    failure) + "}");
                    publishMappedAuthorizationState(
                            authorizationFailureMessage(failure));
                } finally {
                    reconcileRuntimeLocksAfterDataPlaneClose(
                            "authorization_operation_" + operation);
                    authorizationOperationInFlight.set(false);
                }
            });
        } catch (RuntimeException schedulingFailure) {
            authorizationOperationInFlight.set(false);
            publishMappedAuthorizationState(getString(
                    R.string.authorization_operation_failed));
        }
    }

    private String authorizationFailureMessage(Throwable failure) {
        if (failure instanceof
                HostVideoPresenceProbe.HostVideoNotObservedException) {
            return getString(R.string.authorization_host_video_not_ready);
        }
        if (failure instanceof DualMachineSidecarPort.RejectedException) {
            AuthorizationFailureMessagePolicy.Message message =
                    AuthorizationFailureMessagePolicy.forSafeErrorCode(
                            ((DualMachineSidecarPort.RejectedException) failure)
                                    .safeErrorCode);
            if (message == AuthorizationFailureMessagePolicy.Message
                    .DEVICE_REBIND_REQUIRED) {
                return getString(
                        R.string.authorization_device_rebind_required);
            }
            if (message == AuthorizationFailureMessagePolicy.Message
                    .DEVICE_BINDING_INCONSISTENT) {
                return getString(
                        R.string.authorization_device_binding_inconsistent);
            }
        }
        return getString(R.string.authorization_operation_failed);
    }

    private long trustedEpochSeconds() {
        long millis = System.currentTimeMillis();
        if (millis <= 0L) {
            throw new SecurityException("trusted epoch is unavailable");
        }
        return TimeUnit.MILLISECONDS.toSeconds(millis);
    }

    private String requiredAuthenticatedHostChannelBinding()
            throws GeneralSecurityException {
        DualMachineAuthorizationRuntime runtime = authorizationRuntime;
        if (runtime == null) {
            throw new GeneralSecurityException(
                    "authenticated Host runtime is unavailable");
        }
        return runtime.authenticatedHostChannelBindingSha256();
    }

    private void closeFormalDataPlaneLocally(String reason) {
        if (hostVideoPresenceProbe != null) hostVideoPresenceProbe.cancel();
        formalRenewalRetryPending.set(false);
        nextFormalRenewalAttemptElapsedMillis.set(0L);
        nextFormalStartRetryElapsedMillis.set(0L);
        boolean hadPermit;
        boolean wasStarted;
        boolean prepared;
        Throwable closeFailure = null;
        synchronized (pipelineCommandLock) {
            hadPermit = formalDataPlanePermitOpen.get()
                    || activeRuntimePermit != null
                    || stagedRuntimePermit != null;
            invalidateRuntimePermitWindowLocked();
            pipelineSessionGeneration.incrementAndGet();
            pipelineDesired = false;
            gameModelHotReloadInProgress = false;
            wasStarted = pipelineStarted;
            pipelineStarted = false;
            pipelineNetworkHandle = 0L;
            prepared = pipeline != null
                    && pipeline.isPreparedDataPlaneClosed();
            if (pipeline != null && (hadPermit || wasStarted || prepared)) {
                try {
                    pipeline.closeDataPlane();
                } catch (RuntimeException | LinkageError failure) {
                    closeFailure = failure;
                }
            }
        }
        cancelReceiverLivenessProbe();
        if (controlRuntime != null) controlRuntime.failClosed(reason);
        reconcileRuntimeLocksAfterDataPlaneClose(reason);
        if (hadPermit || wasStarted || runtimeStatus.phase == MobileRuntimePhase.STARTING) {
            updateStatus(MobileRuntimePhase.READY,
                    "pipeline_data_plane_closed reason=" + reason);
            updateNotification(R.string.runtime_notification_ready);
        }
        if (closeFailure != null && events != null) {
            events.write(
                    "mobile_pipeline_data_plane_close_failed",
                    "reason=" + reason + " stack={"
                            + MobileThrowableDiagnostics.format(closeFailure)
                            + "}");
        }
    }

    private void clearFormalSessionBinding() {
        synchronized (pipelineCommandLock) {
            formalSessionChannelBinding = "";
            formalSessionEndpoint = null;
            formalModelPreparationInProgress = false;
        }
    }

    private void abandonFormalPreparation(
            String reason,
            boolean pipelinePreparationAttempted) {
        clearFormalSessionBinding();
        synchronized (pipelineCommandLock) {
            invalidateRuntimePermitWindowLocked();
            pipelineSessionGeneration.incrementAndGet();
            pipelineDesired = false;
            pipelineStarted = false;
            pipelineNetworkHandle = 0L;
        }
        if (controlRuntime != null) controlRuntime.failClosed(reason);
        if (pipelinePreparationAttempted) stopPreparedPipeline();
        reconcileRuntimeLocksAfterDataPlaneClose(reason);
        updateStatus(MobileRuntimePhase.READY,
                "formal_usage_armed reason=" + reason);
        updateNotification(R.string.runtime_notification_ready);
    }

    private void installActiveRuntimePermitLocked(
            DualMachineFormalUsageCoordinator.DataPlanePermit permit,
            long nowNanos) throws IOException {
        requireRuntimePermitWindow(permit, nowNanos, true);
        requireRuntimePermitBindingLocked(permit);
        if (activeRuntimePermit != null) {
            requireCompatibleRuntimePermit(activeRuntimePermit, permit);
            if (permit.sequence < activeRuntimePermit.sequence) {
                throw new IOException("runtime permit sequence moved backwards");
            }
            if (permit.sequence == activeRuntimePermit.sequence
                    && !permit.leaseSha256.equals(
                    activeRuntimePermit.leaseSha256)) {
                throw new IOException("runtime permit sequence drifted");
            }
        }
        activeRuntimePermit = permit;
        if (stagedRuntimePermit != null
                && stagedRuntimePermit.sequence <= permit.sequence) {
            stagedRuntimePermit = null;
        }
        formalDataPlanePermitOpen.set(true);
        runtimePermitGeneration++;
        scheduleRuntimePermitDeadlineLocked(
                runtimePermitGeneration,
                permit.expiresAtMonotonicNanos);
    }

    private void stageRuntimePermitLocked(
            DualMachineFormalUsageCoordinator.DataPlanePermit permit,
            long nowNanos) throws IOException {
        requireRuntimePermitWindow(permit, nowNanos, false);
        requireRuntimePermitBindingLocked(permit);
        if (activeRuntimePermit != null) {
            requireCompatibleRuntimePermit(activeRuntimePermit, permit);
            if (permit.sequence <= activeRuntimePermit.sequence) {
                throw new IOException(
                        "staged runtime permit sequence is not newer");
            }
        }
        if (stagedRuntimePermit != null) {
            requireCompatibleRuntimePermit(stagedRuntimePermit, permit);
            if (permit.sequence < stagedRuntimePermit.sequence
                    || (permit.sequence == stagedRuntimePermit.sequence
                    && !permit.leaseSha256.equals(
                    stagedRuntimePermit.leaseSha256))) {
                throw new IOException("staged runtime permit drifted");
            }
        }
        stagedRuntimePermit = permit;
        runtimePermitGeneration++;
        if (activeRuntimePermit != null
                && runtimePermitIsWithinWindow(
                activeRuntimePermit, nowNanos)) {
            scheduleRuntimePermitDeadlineLocked(
                    runtimePermitGeneration,
                    activeRuntimePermit.expiresAtMonotonicNanos);
        } else {
            scheduleRuntimePermitDeadlineLocked(
                    runtimePermitGeneration,
                    permit.notBeforeMonotonicNanos);
        }
    }

    private boolean runtimePermitIsActiveLocked(
            long nowNanos,
            boolean allowStagedPromotionWithoutActive) {
        DualMachineFormalUsageCoordinator.DataPlanePermit previous =
                activeRuntimePermit;
        if (runtimePermitIsWithinWindow(previous, nowNanos)) {
            formalDataPlanePermitOpen.set(true);
            return true;
        }
        activeRuntimePermit = null;
        DualMachineFormalUsageCoordinator.DataPlanePermit staged =
                stagedRuntimePermit;
        boolean canPromote = runtimePermitIsWithinWindow(staged, nowNanos)
                && (previous != null
                || allowStagedPromotionWithoutActive);
        if (!canPromote) {
            formalDataPlanePermitOpen.set(false);
            return false;
        }
        if (previous != null) {
            try {
                requireCompatibleRuntimePermit(previous, staged);
            } catch (IOException incompatible) {
                stagedRuntimePermit = null;
                formalDataPlanePermitOpen.set(false);
                return false;
            }
        }
        activeRuntimePermit = staged;
        stagedRuntimePermit = null;
        formalDataPlanePermitOpen.set(true);
        runtimePermitGeneration++;
        scheduleRuntimePermitDeadlineLocked(
                runtimePermitGeneration,
                staged.expiresAtMonotonicNanos);
        return true;
    }

    private DualMachineFormalUsageCoordinator.DataPlanePermitState
            enforceRuntimePermitWindow() {
        boolean stagedWaiting = false;
        boolean closedForStagedGap = false;
        Throwable closeFailure = null;
        synchronized (pipelineCommandLock) {
            long nowNanos = System.nanoTime();
            boolean hadActivePermit = activeRuntimePermit != null
                    || formalDataPlanePermitOpen.get();
            if (runtimePermitIsActiveLocked(nowNanos, true)) {
                if (runtimePermitDeadline == null
                        && activeRuntimePermit != null) {
                    scheduleRuntimePermitDeadlineLocked(
                             runtimePermitGeneration,
                             activeRuntimePermit.expiresAtMonotonicNanos);
                }
                return DualMachineFormalUsageCoordinator
                        .DataPlanePermitState.OPEN;
            }
            if (runtimePermitIsFutureLocked(
                    stagedRuntimePermit, nowNanos)) {
                stagedWaiting = true;
                if (runtimePermitDeadline == null) {
                    runtimePermitGeneration++;
                    scheduleRuntimePermitDeadlineLocked(
                            runtimePermitGeneration,
                            stagedRuntimePermit.notBeforeMonotonicNanos);
                }
                if (hadActivePermit || pipelineDesired || pipelineStarted) {
                    closeFailure = closeRuntimeDataPlaneForPermitBoundaryLocked(
                            "formal_usage_renewal_gap");
                    closedForStagedGap = true;
                }
            } else {
                stagedRuntimePermit = null;
            }
        }
        if (closedForStagedGap) {
            writeRuntimePermitExpiredEvent(true, closeFailure);
        }
        if (stagedWaiting) {
            return DualMachineFormalUsageCoordinator
                    .DataPlanePermitState.STAGED_WAITING;
        }
        closeFormalDataPlaneLocally("formal_usage_lease_window_closed");
        return DualMachineFormalUsageCoordinator.DataPlanePermitState.CLOSED;
    }

    private void enforceRuntimePermitDeadline(long expectedGeneration) {
        boolean futurePermitPreserved = false;
        boolean dataPlaneClosed = false;
        Throwable closeFailure = null;
        synchronized (pipelineCommandLock) {
            if (destroying
                    || expectedGeneration != runtimePermitGeneration) {
                return;
            }
            runtimePermitDeadline = null;
            long nowNanos = System.nanoTime();
            boolean hadActivePermit = activeRuntimePermit != null
                    || formalDataPlanePermitOpen.get();
            if (runtimePermitIsActiveLocked(nowNanos, true)) {
                if (runtimePermitDeadline == null
                        && activeRuntimePermit != null) {
                    scheduleRuntimePermitDeadlineLocked(
                            runtimePermitGeneration,
                            activeRuntimePermit.expiresAtMonotonicNanos);
                }
                return;
            }

            boolean preserveFuturePermit = runtimePermitIsFutureLocked(
                    stagedRuntimePermit, nowNanos);
            futurePermitPreserved = preserveFuturePermit;
            activeRuntimePermit = null;
            if (!preserveFuturePermit) stagedRuntimePermit = null;
            formalDataPlanePermitOpen.set(false);
            runtimePermitGeneration++;
            if (preserveFuturePermit) {
                scheduleRuntimePermitDeadlineLocked(
                        runtimePermitGeneration,
                        stagedRuntimePermit.notBeforeMonotonicNanos);
            } else {
                cancelRuntimePermitDeadlineLocked();
            }
            if (hadActivePermit || pipelineDesired || pipelineStarted) {
                closeFailure = closeRuntimeDataPlaneForPermitBoundaryLocked(
                        "formal_usage_lease_expired");
                dataPlaneClosed = true;
            }
        }
        if (dataPlaneClosed) {
            writeRuntimePermitExpiredEvent(
                    futurePermitPreserved, closeFailure);
        }
    }

    private Throwable closeRuntimeDataPlaneForPermitBoundaryLocked(
            String reason) {
        Throwable closeFailure = null;
        boolean preservePreparedModelCommit =
                gameModelHotReloadInProgress
                        && formalSessionEndpoint != null;
        if (!preservePreparedModelCommit) {
            pipelineSessionGeneration.incrementAndGet();
            pipelineDesired = false;
        }
        boolean closedRuntime = pipelineStarted
                || (pipeline != null && pipeline.isPreparedDataPlaneClosed());
        pipelineStarted = false;
        pipelineNetworkHandle = 0L;
        if (pipeline != null && closedRuntime) {
            try {
                pipeline.closeDataPlane();
            } catch (RuntimeException | LinkageError failure) {
                closeFailure = failure;
            }
        }
        cancelReceiverLivenessProbe();
        if (controlRuntime != null) controlRuntime.failClosed(reason);
        reconcileRuntimeLocksAfterDataPlaneClose(reason);
        updateStatus(
                MobileRuntimePhase.READY,
                "pipeline_data_plane_closed reason=" + reason
                        + " model_commit_preserved="
                        + preservePreparedModelCommit);
        updateNotification(R.string.runtime_notification_ready);
        return closeFailure;
    }

    private void writeRuntimePermitExpiredEvent(
            boolean futurePermitPreserved,
            Throwable closeFailure) {
        events.write(
                "dual_machine_runtime_permit_expired",
                "data_plane_closed=true staged_future_preserved="
                        + futurePermitPreserved);
        if (closeFailure != null) {
            events.write(
                    "dual_machine_runtime_permit_close_failed",
                    "stack={"
                            + MobileThrowableDiagnostics.format(closeFailure)
                            + "}");
        }
    }

    private void requireRuntimePermitBindingLocked(
            DualMachineFormalUsageCoordinator.DataPlanePermit permit)
            throws IOException {
        if (formalSessionEndpoint == null
                || formalSessionChannelBinding.isEmpty()
                || !formalSessionChannelBinding.equals(
                permit.channelBindingSha256)) {
            throw new IOException("runtime permit binding changed");
        }
    }

    private static void requireRuntimePermitWindow(
            DualMachineFormalUsageCoordinator.DataPlanePermit permit,
            long nowNanos,
            boolean requireActiveNow) throws IOException {
        if (permit == null
                || permit.expiresAtMonotonicNanos
                - permit.notBeforeMonotonicNanos <= 0L
                || permit.expiresAtMonotonicNanos - nowNanos <= 0L
                || (requireActiveNow
                && nowNanos - permit.notBeforeMonotonicNanos < 0L)) {
            throw new IOException("runtime permit window is not active");
        }
    }

    private static void requireCompatibleRuntimePermit(
            DualMachineFormalUsageCoordinator.DataPlanePermit previous,
            DualMachineFormalUsageCoordinator.DataPlanePermit next)
            throws IOException {
        if (!previous.sessionId.equals(next.sessionId)
                || !previous.channelBindingSha256.equals(
                next.channelBindingSha256)) {
            throw new IOException("runtime permit generation changed");
        }
    }

    private static boolean runtimePermitIsWithinWindow(
            DualMachineFormalUsageCoordinator.DataPlanePermit permit,
            long nowNanos) {
        return permit != null
                && nowNanos - permit.notBeforeMonotonicNanos >= 0L
                && permit.expiresAtMonotonicNanos - nowNanos > 0L;
    }

    private static boolean runtimePermitIsFutureLocked(
            DualMachineFormalUsageCoordinator.DataPlanePermit permit,
            long nowNanos) {
        return permit != null
                && nowNanos - permit.notBeforeMonotonicNanos < 0L
                && permit.expiresAtMonotonicNanos - nowNanos > 0L;
    }

    private void scheduleRuntimePermitDeadlineLocked(
            long expectedGeneration,
            long deadlineNanos) {
        cancelRuntimePermitDeadlineLocked();
        runtimePermitDeadline = runtimePermitDeadlines.scheduleAt(
                deadlineNanos,
                () -> enforceRuntimePermitDeadline(expectedGeneration));
    }

    private void cancelRuntimePermitDeadlineLocked() {
        DualMachineFormalUsageCoordinator.DeadlineScheduler
                .ScheduledDeadline scheduled = runtimePermitDeadline;
        runtimePermitDeadline = null;
        if (scheduled != null) scheduled.cancel();
    }

    private void invalidateRuntimePermitWindowLocked() {
        runtimePermitGeneration++;
        cancelRuntimePermitDeadlineLocked();
        activeRuntimePermit = null;
        stagedRuntimePermit = null;
        formalDataPlanePermitOpen.set(false);
        gameModelHotReloadInProgress = false;
        formalModelPreparationInProgress = false;
    }

    private final class AuthenticatedHostFormalRuntimeBoundary
            implements DualMachineFormalUsageCoordinator.RuntimeBoundary {
        private volatile String reservedStartRequestId = "";
        private volatile String reservedChannelBindingSha256 = "";

        @Override
        public DualMachineFormalUsageCoordinator.StartReadiness
                prepareWithDataPlaneClosed(
                BooleanSupplier cancellationRequested)
                throws IOException, GeneralSecurityException {
            requireFormalStartNotCancelled(cancellationRequested);
            selectPreferredTransportForFormalStart();
            MobileTransportEndpoint transportCandidate =
                    transportCatalog.selected();
            if (transportCandidate != null) {
                // Wi-Fi persistence must be active before discovery and the
                // first pre-billing Host-video observation, including while
                // the display is off.
                acquireRuntimeLocks(transportCandidate);
            }
            MobileTransportEndpoint endpoint = awaitRequiredTransportEndpoint(
                    cancellationRequested);
            if (endpoint == null) {
                throw new IOException("required transport network is unavailable");
            }
            final long preparationGeneration;
            final MobileModelCatalog.Profile preparationModel;
            synchronized (pipelineCommandLock) {
                preparationGeneration = pipelineSessionGeneration.get();
                formalModelPreparationInProgress = true;
                preparationModel = pendingGameModelSelection == null
                        ? controlRuntime.activeModel()
                        : pendingGameModelSelection;
                pendingGameModelSelection = null;
            }
            acquireRuntimeLocks(endpoint);
            boolean pipelinePreparationAttempted = false;
            try {
                requireFormalStartNotCancelled(cancellationRequested);
                MobileTransportEndpoint verifiedBeforePreparation =
                        requiredTransportEndpoint();
                if (!endpoint.hasSameDataPlaneRoute(verifiedBeforePreparation)) {
                    throw new IOException(
                            "required transport changed during formal preparation");
                }
                updateStatus(MobileRuntimePhase.STARTING,
                        "formal_usage_preparing authenticated_control=true data_plane_closed=true");
                updateNotification(R.string.runtime_notification_starting);
                String nativeDirectory = lastNativeDirectory == null
                        ? defaultNativeDirectory()
                        : lastNativeDirectory;
                MobileSocCompatibilityPolicy.Result socCompatibility =
                        currentSocCompatibility();
                MobileInferenceBackendPolicy.Plan inferencePlan =
                        MobileInferenceBackendPolicy.evaluate(
                                socCompatibility);
                events.write(
                        "mobile_soc_compatibility",
                        socCompatibility.detail());
                events.write(
                        "mobile_inference_backend_plan",
                        inferencePlan.detail());
                pipelinePreparationAttempted = true;
                MobilePipelineCoordinator.PrepareResult prepared =
                        prepareModelDataPlaneClosed(
                                nativeDirectory,
                                lastSkeletonDirectory,
                                preparationModel,
                                inferencePlan);
                requireFormalStartNotCancelled(cancellationRequested);
                if (!prepared.prepared) {
                    if (prepared.disposition == MobilePipelineCoordinator
                            .FailureDisposition.TERMINAL_INCOMPATIBLE
                            && PROCESS_RETRY_GATE.latchTerminalFailure(
                            prepared.failureCode, prepared.message)) {
                        events.write(
                                "mobile_pipeline_automatic_recovery_suppressed",
                                "failure_code=" + prepared.failureCode
                                        + " source=formal_usage_prepare retryable=false"
                                        + " reason={" + prepared.message + "}");
                    }
                    throw new IOException(prepared.message);
                }
                synchronized (pipelineCommandLock) {
                    if (destroying
                            || preparationGeneration
                            != pipelineSessionGeneration.get()
                            || !formalModelPreparationInProgress) {
                        throw new IOException(
                                "formal usage preparation was superseded"
                                        + " before model commit");
                    }
                    // The captured QNN graph and model-specific native
                    // post-process are committed under the same generation
                    // lock. A concurrent UI selection is already staged in
                    // pendingGameModelSelection and is hot-reloaded later.
                    controlRuntime.selectModel(preparationModel);
                    if (!controlRuntime.isNativePostprocessApplied()) {
                        throw new IOException(
                                "native_postprocess_apply_failed");
                    }
                }
                lastNativeDirectory = nativeDirectory;
                lastInferenceBackendPlan =
                        MobileInferenceBackendPolicy.resumeFrom(
                                lastPreparedInferenceBackend);
                MobileTransportEndpoint verifiedEndpoint =
                        requiredTransportEndpoint();
                if (!verifiedBeforePreparation.hasSameDataPlaneRoute(
                        verifiedEndpoint)) {
                    throw new IOException(
                            "required transport changed during QNN preparation");
                }
                requireFormalStartNotCancelled(cancellationRequested);
                MobileTransportEndpoint verifiedAfterPreparation =
                        requiredTransportEndpoint();
                if (!verifiedEndpoint.hasSameDataPlaneRoute(
                        verifiedAfterPreparation)) {
                    throw new IOException(
                            "required transport changed before formal pin");
                }
                MobileTransportEndpoint pinnedEndpoint =
                        transportCatalog.pinForFormalSession(
                                verifiedAfterPreparation.networkHandle);
                if (!verifiedAfterPreparation.hasSameDataPlaneRoute(
                        pinnedEndpoint)) {
                    throw new IOException(
                            "formal session transport pin changed the data-plane route");
                }
                String channelBinding =
                        requiredAuthenticatedHostChannelBinding();
                synchronized (pipelineCommandLock) {
                    if (destroying
                            || preparationGeneration
                            != pipelineSessionGeneration.get()) {
                        throw new IOException(
                                "formal usage preparation was superseded");
                    }
                    formalSessionEndpoint = pinnedEndpoint;
                    formalSessionChannelBinding = channelBinding;
                }
                events.write(
                        "mobile_transport_formal_session_pinned",
                        pinnedEndpoint.detail()
                                + " preference_changes_deferred=true"
                                + " authenticated_control=true"
                                + " host_video_wait_deferred_until_lease_commit=true");
                return new DualMachineFormalUsageCoordinator.StartReadiness(
                        channelBinding,
                        true,
                        true);
            } catch (IOException | GeneralSecurityException
                     | RuntimeException failure) {
                abandonFormalPreparation(
                        "formal_usage_prepare_failed",
                        pipelinePreparationAttempted);
                if (!PROCESS_RETRY_GATE.canAttempt()) {
                    updateStatus(
                            MobileRuntimePhase.FAILED,
                            "automatic_recovery_suppressed failure_code="
                                    + PROCESS_RETRY_GATE.failureCode()
                                    + " reason={"
                                    + PROCESS_RETRY_GATE.failureDetail() + "}");
                    updateNotification(R.string.runtime_notification_failed);
                }
                throw failure;
            }
        }

        @Override
        public void verifyFreshHostVideoBeforePotentialDebit(
                String expectedChannelBindingSha256,
                String expectedStartRequestId,
                BooleanSupplier cancellationRequested)
                throws IOException, GeneralSecurityException {
            requireFormalStartNotCancelled(cancellationRequested);
            final MobileTransportEndpoint expectedEndpoint;
            final long expectedGeneration;
            synchronized (pipelineCommandLock) {
                expectedEndpoint = formalSessionEndpoint;
                expectedGeneration = pipelineSessionGeneration.get();
                if (expectedEndpoint == null
                        || formalSessionChannelBinding.isEmpty()
                        || !formalSessionChannelBinding.equals(
                        expectedChannelBindingSha256)) {
                    throw new IOException(
                            "prepared formal usage binding is unavailable");
                }
            }
            acquireRuntimeLocks(expectedEndpoint);
            try {
                requireWirelessForegroundDisplay(expectedEndpoint);
                requireFormalStartNotCancelled(cancellationRequested);
                MobileTransportEndpoint currentEndpoint =
                        requiredTransportEndpoint();
                String currentAuthenticatedBinding =
                        requiredAuthenticatedHostChannelBinding();
                AndroidBoundAuthenticatedControlCoordinatorV1 control =
                        pairingRuntime.authenticatedControl();
                synchronized (pipelineCommandLock) {
                    if (destroying
                            || expectedGeneration
                            != pipelineSessionGeneration.get()
                            || control == null
                            || !control.isAuthenticated()
                            || formalSessionEndpoint == null
                            || !expectedEndpoint.hasSameDataPlaneRoute(
                            currentEndpoint)
                            || !expectedEndpoint.hasSameDataPlaneRoute(
                            formalSessionEndpoint)
                            || !expectedChannelBindingSha256.equals(
                            formalSessionChannelBinding)
                            || !expectedChannelBindingSha256.equals(
                            currentAuthenticatedBinding)) {
                        throw new IOException(
                                    "formal usage authenticated control was superseded");
                    }
                }
                requireWirelessForegroundDisplay(expectedEndpoint);
                ensureAutomaticFormalStartReserved(
                        expectedStartRequestId,
                        expectedChannelBindingSha256);
                reservedStartRequestId = expectedStartRequestId;
                reservedChannelBindingSha256 =
                        expectedChannelBindingSha256;
                events.write(
                        "dual_machine_authenticated_host_revalidated",
                        "before_potential_debit=true route_unchanged=true "
                                + "data_plane_closed=true");
            } catch (IOException | GeneralSecurityException
                     | RuntimeException failure) {
                closeFormalDataPlaneLocally(
                        "formal_start_authenticated_control_revalidation_failed");
                throw failure;
            }
        }

        @Override
        public void openDataPlane(
                DualMachineFormalUsageCoordinator.DataPlanePermit permit)
                throws IOException {
            MobileTransportEndpoint endpoint = requiredTransportEndpoint();
            if (endpoint == null) {
                closeFormalDataPlaneLocally(
                        "required_transport_unavailable");
                throw new IOException(
                        "required transport network is unavailable");
            }
            if (!isWirelessForegroundDisplayReady(endpoint)) {
                closeFormalDataPlaneLocally(
                        "wireless_foreground_display_unavailable");
                throw new IOException(
                        "wireless runtime requires a foreground interactive display");
            }
            synchronized (pipelineCommandLock) {
                MobileTransportEndpoint preparedEndpoint =
                        formalSessionEndpoint;
                if (permit == null || preparedEndpoint == null
                        || formalSessionChannelBinding.isEmpty()
                        || !preparedEndpoint.hasSameDataPlaneRoute(endpoint)
                        || !formalSessionChannelBinding.equals(
                                permit.channelBindingSha256)) {
                    throw new IOException("formal usage binding changed");
                }
            }
            AndroidBoundAuthenticatedControlCoordinatorV1 control =
                    pairingRuntime.authenticatedControl();
            if (control == null || !control.isAuthenticated()) {
                closeFormalDataPlaneLocally(
                        "authenticated_control_unavailable");
                throw new IOException(
                        "authenticated Host control channel is unavailable");
            }
            try {
                control.installVerifiedUsageLease(permit);
            } catch (GeneralSecurityException failure) {
                closeFormalDataPlaneLocally(
                        "host_lease_install_rejected");
                throw new IOException(
                        "Host rejected the verified usage lease", failure);
            }
            events.write(
                    "dual_machine_host_usage_lease_committed",
                    "sequence=" + permit.sequence
                            + " raw_bytes_unchanged=true"
                            + " host_independent_verification=true");
            if (permit.sequence == 0L) {
                // The paid generation is latched only after Host acceptance
                // and the authenticated Android commit have completed.
                markAutomaticFormalSessionOpened(
                        permit.startRequestId,
                        permit.channelBindingSha256);
            }
            long networkHandle = endpoint.networkHandle;
            boolean continued;
            boolean hotReloadOwnsReopen;
            MobileModelCatalog.Profile deferredModel = null;
            MobilePipelineCoordinator.StartResult startFailure = null;
            synchronized (pipelineCommandLock) {
                MobileTransportEndpoint preparedEndpoint =
                        formalSessionEndpoint;
                String preparedBinding = formalSessionChannelBinding;
                if (preparedEndpoint == null
                        || preparedBinding.isEmpty()
                        || !preparedEndpoint.hasSameDataPlaneRoute(endpoint)
                        || !preparedBinding.equals(
                        permit.channelBindingSha256)) {
                    throw new IOException("formal usage binding changed");
                }
                installActiveRuntimePermitLocked(
                        permit, System.nanoTime());
                if (gameModelHotReloadInProgress
                        && pipelineDesired
                        && !pipelineStarted) {
                    // A contiguous permit promotion must not steal the
                    // prepared-pipeline reopen from the model reload worker.
                    // Advancing the pipeline generation here would supersede
                    // the requested model after it was already prepared.
                    continued = true;
                    hotReloadOwnsReopen = true;
                } else if (pipelineDesired
                        && pipelineStarted
                        && pipelineNetworkHandle == networkHandle
                        && nativeVideoReceiverRunningSafely()) {
                    updateStatus(MobileRuntimePhase.RUNNING,
                            "formal_usage_lease_continued host_authorization=true");
                    updateNotification(R.string.runtime_notification_running);
                    continued = true;
                    hotReloadOwnsReopen = false;
                } else {
                    continued = false;
                    hotReloadOwnsReopen = false;
                    acquireRuntimeLocks(endpoint);
                    long generation =
                            pipelineSessionGeneration.incrementAndGet();
                    pipelineDesired = true;
                    MobileModelCatalog.Profile activeModel =
                            controlRuntime.activeModel();
                    MobilePipelineCoordinator.StartResult result =
                            pipeline.openPreparedDataPlane(
                                    endpoint, activeModel);
                    if (!result.started) {
                        startFailure = result;
                        invalidateRuntimePermitWindowLocked();
                        pipelineDesired = false;
                        pipelineStarted = false;
                        pipelineNetworkHandle = 0L;
                    } else if (!pipelineSessionIsCurrentLocked(generation)
                            || !pipelineDesired
                            || !runtimePermitIsActiveLocked(
                            System.nanoTime(), true)) {
                        pipeline.closeDataPlane();
                        invalidateRuntimePermitWindowLocked();
                        pipelineDesired = false;
                        pipelineStarted = false;
                        pipelineNetworkHandle = 0L;
                        throw new IOException(
                                "formal usage open was superseded");
                    } else {
                        pipelineStarted = true;
                        pipelineNetworkHandle = networkHandle;
                        updateStatus(MobileRuntimePhase.RUNNING,
                                "formal_usage_running host_authorization=true");
                        updateNotification(R.string.runtime_notification_running);
                    }
                }
                if (startFailure == null && permit.sequence == 0L) {
                    formalModelPreparationInProgress = false;
                    if (pendingGameModelSelection != null
                            && pendingGameModelSelection
                            != controlRuntime.activeModel()) {
                        deferredModel = pendingGameModelSelection;
                    }
                    pendingGameModelSelection = null;
                }
            }
            if (startFailure != null) {
                clearFormalSessionBinding();
                closeFormalDataPlaneLocally(
                        "pipeline_data_plane_open_failed");
                handlePipelineStartFailure(
                        startFailure,
                        "formal_usage_android_only");
                throw new IOException(startFailure.message);
            }
            nextFormalStartRetryElapsedMillis.set(0L);
            formalRenewalRetryPending.set(false);
            // Let the next 250 ms maintenance tick align the first renewal to
            // the verified lease window. A fixed three-second delay leaves a
            // five-second permit too little time for WAN/TLS/signing and turns
            // every renewal into a close/reopen cycle.
            nextFormalRenewalAttemptElapsedMillis.set(0L);
            events.write(
                    hotReloadOwnsReopen
                            ? "dual_machine_formal_permit_continued"
                            : continued
                            ? "dual_machine_formal_data_plane_continued"
                            : "dual_machine_formal_data_plane_opened",
                    "network_handle=" + networkHandle
                            + " host_authorization=true "
                            + "video_encrypted=true "
                            + "presence_authenticated=true "
                            + "idr_authenticated=true "
                            + "plaintext_fallback=false "
                            + "data_plane_open="
                            + !hotReloadOwnsReopen + " "
                            + "pipeline_reopen_deferred_to_hot_reload="
                            + hotReloadOwnsReopen + " "
                            + endpoint.detail());
            if (!hotReloadOwnsReopen) {
                scheduleReceiverLivenessProbe(
                        RECEIVER_ACTIVE_LIVENESS_PROBE_MILLIS, true);
            }
            if (deferredModel != null) {
                requestGameModelSelection(deferredModel.token, false);
            }
        }

        @Override
        public void stageFutureLease(
                DualMachineFormalUsageCoordinator.DataPlanePermit permit)
                throws IOException {
            AndroidBoundAuthenticatedControlCoordinatorV1 control =
                    pairingRuntime.authenticatedControl();
            if (control == null || !control.isAuthenticated()) {
                throw new IOException(
                        "authenticated Host control channel is unavailable");
            }
            try {
                control.installVerifiedUsageLease(permit);
            } catch (GeneralSecurityException failure) {
                closeFormalDataPlaneLocally(
                        "host_future_lease_install_rejected");
                throw new IOException(
                        "Host rejected the verified future usage lease",
                        failure);
            }
            synchronized (pipelineCommandLock) {
                stageRuntimePermitLocked(permit, System.nanoTime());
            }
        }

        @Override
        public DualMachineFormalUsageCoordinator.DataPlanePermitState
                enforceLeaseWindow() {
            MobileTransportEndpoint currentEndpoint = requiredTransportEndpoint();
            MobileTransportEndpoint preparedEndpoint = formalSessionEndpoint;
            if (preparedEndpoint == null
                    || !preparedEndpoint.hasSameDataPlaneRoute(currentEndpoint)) {
                closeFormalDataPlaneLocally(
                        "required_transport_changed_or_unavailable");
                return DualMachineFormalUsageCoordinator
                        .DataPlanePermitState.CLOSED;
            }
            return enforceRuntimePermitWindow();
        }

        @Override
        public void closeDataPlane() {
            closeOpenedAutomaticSessionForBoundary(
                    reservedStartRequestId,
                    reservedChannelBindingSha256,
                    "formal_runtime_boundary_closed");
            closeFormalDataPlaneLocally("formal_usage_closed");
        }

        @Override
        public void finalizeFormalGeneration(
                String expectedStartRequestId,
                String expectedChannelBindingSha256,
                DualMachineFormalUsageCoordinator.StopOutcome outcome) {
            settleAutomaticUsageReservation(
                    expectedStartRequestId,
                    expectedChannelBindingSha256,
                    outcome,
                    "formal_generation_terminal");
        }

    }

    private void scheduleAuthorizationMaintenance() {
        pairingRuntime.scheduleFirstPairingIfNeeded();
        pairingRuntime.scheduleAuthenticatedControlIfNeeded();
        QueuedCardActivationCoordinator queuedCards = queuedCardActivation;
        if (queuedCards != null) queuedCards.activateIfReady();
        ensureAuthorizationStatusRetryScheduled();
        DualMachineAuthorizationRuntime runtime = authorizationRuntime;
        if (destroying || runtime == null) {
            return;
        }
        if (!authorizationMaintenanceQueued.compareAndSet(
                false, true)) {
            return;
        }
        try {
            authorizationExecutor.execute(() -> {
                DualMachineAuthorizationRuntime currentRuntime =
                        authorizationRuntime;
                DualMachineAuthorizationRuntime.CurrentGenerationReceipt
                        generationReceipt = null;
                try {
                    if (currentRuntime != null) {
                        if (currentRuntime
                                .hasRetiringFormalUsageGeneration()) {
                            AtomicBoolean claimedByMaintenance =
                                    new AtomicBoolean();
                            DualMachineAuthorizationRuntime
                                    .FormalUsageLifecycleHandle retiringStop;
                            try {
                                retiringStop = currentRuntime
                                        .captureRetiringFormalUsageStopForMaintenance(
                                                () -> {
                                                    boolean claimed =
                                                            automaticFormalStopQueued
                                                                    .compareAndSet(
                                                                            false,
                                                                            true);
                                                    claimedByMaintenance.set(
                                                            claimed);
                                                    return claimed;
                                                });
                            } catch (RuntimeException | LinkageError failure) {
                                if (claimedByMaintenance.get()) {
                                    automaticFormalStopQueued.compareAndSet(
                                            true, false);
                                }
                                throw failure;
                            }
                            if (retiringStop != null) {
                                runClaimedFormalUsageStop(
                                        retiringStop,
                                        "retiring_generation_recovery");
                            }
                            return;
                        }
                        if (!currentRuntime.hasAuthenticatedHost()) {
                            DualMachineFormalUsageStateMachine.Snapshot
                                    unavailableHostSnapshot =
                                    currentRuntime.snapshot();
                            if (unavailableHostSnapshot.state
                                    == DualMachineFormalUsageStateMachine.State
                                    .STOPPING) {
                                retryFormalUsageStopWithoutAuthenticatedHostIfDue(
                                        currentRuntime,
                                        "authenticated_host_unavailable_retry");
                            } else if (unavailableHostSnapshot
                                    .canFormalStop()) {
                                requestFormalUsageStop(
                                        "authenticated_host_unavailable");
                            }
                            publishMappedAuthorizationState("");
                            return;
                        }
                        generationReceipt = currentRuntime
                                .captureCurrentGenerationReceipt();
                        AtomicBoolean wirelessStartStopped =
                                new AtomicBoolean();
                        commitFormalGeneration(
                                currentRuntime,
                                generationReceipt,
                                () -> wirelessStartStopped.set(
                                        stopWirelessStartWhenDisplayUnavailable(
                                                currentRuntime,
                                                "authorization_health_starting")));
                        if (wirelessStartStopped.get()) return;
                        maintainAuthorizationRuntime(
                                currentRuntime, generationReceipt);
                        currentRuntime.commitIfCurrent(
                                generationReceipt,
                                () -> publishMappedAuthorizationState(""));
                    }
                } catch (DualMachineFormalUsageCoordinator
                                 .AdmissionSupersededException superseded) {
                    events.write(
                            "dual_machine_authorization_maintenance_superseded",
                            "action=no_cross_generation_cleanup");
                } catch (IOException | GeneralSecurityException
                         | RuntimeException failure) {
                    if (currentRuntime != null
                            && generationReceipt != null) {
                        currentRuntime.commitIfCurrent(
                                generationReceipt,
                                () -> {
                                    closeFormalDataPlaneLocally(
                                            "authorization_health_failed");
                                    events.write(
                                            "dual_machine_authorization_health_failed",
                                            "failure_type="
                                                    + failure.getClass()
                                                    .getSimpleName()
                                                    + " control_stage="
                                                    + pairingRuntime
                                                            .authenticatedControlDiagnosticStage()
                                                    + " stack={"
                                                    + MobileThrowableDiagnostics
                                                            .format(failure)
                                                    + "}"
                                                    + " data_plane_open=false");
                                    publishMappedAuthorizationState(getString(
                                            R.string
                                                    .authorization_operation_failed));
                                });
                    }
                } finally {
                    authorizationMaintenanceQueued.set(false);
                }
            });
        } catch (RuntimeException schedulingFailure) {
            authorizationMaintenanceQueued.set(false);
        }
    }

    private void runPeriodicAuthorizationMaintenance() {
        runPeriodicTaskSafely(
                "authorization_maintenance",
                this::scheduleAuthorizationMaintenance);
    }

    private void runPeriodicRuntimeHealth() {
        runPeriodicTaskSafely("runtime_health", this::writeRuntimeHealth);
    }

    /**
     * Keeps a fixed-rate maintenance future alive after one isolated failure.
     * ScheduledExecutorService otherwise suppresses every later execution when
     * a task lets a RuntimeException or LinkageError escape.
     */
    private void runPeriodicTaskSafely(String taskName, Runnable task) {
        try {
            task.run();
        } catch (RuntimeException | LinkageError failure) {
            Log.e(LOG_TAG, "Periodic task failed task=" + taskName, failure);
            try {
                if (controlRuntime != null) {
                    controlRuntime.failClosed(
                            "periodic_task_failed_" + taskName);
                }
            } catch (RuntimeException | LinkageError closeFailure) {
                Log.e(LOG_TAG,
                        "Cannot fail-close after periodic task failure task="
                                + taskName,
                        closeFailure);
            }
            try {
                if (events != null) {
                    events.write(
                            "mobile_periodic_task_failure",
                            "task=" + taskName
                                    + " scheduled_future_retained=true"
                                    + " output_fail_closed=true"
                                    + " automatic_retry=true stack={"
                                    + MobileThrowableDiagnostics.format(failure)
                                    + "}");
                }
            } catch (RuntimeException | LinkageError loggingFailure) {
                Log.e(LOG_TAG,
                        "Cannot record periodic task failure task=" + taskName,
                        loggingFailure);
            }
        }
    }

    private void maintainAuthorizationRuntime(
            DualMachineAuthorizationRuntime runtime,
            DualMachineAuthorizationRuntime.CurrentGenerationReceipt
                    generationReceipt)
            throws IOException, GeneralSecurityException {
        if (automaticFormalStopQueued.get()) {
            // This includes a generation-scoped reload failure cleanup that
            // has claimed the stop latch but has not yet queued/finished the
            // blocking server stop. No pending or fresh start may pass it.
            return;
        }
        if (runtime.snapshot().state
                == DualMachineFormalUsageStateMachine.State.STOPPING
                || runtime.hasPendingFormalStartCancellation()) {
            retryFormalUsageStopIfDue(
                    runtime,
                    generationReceipt,
                    "pending_start_cancellation_confirmation");
            return;
        }
        if (runtime.snapshot().canFormalStop()
                && !isWirelessForegroundDisplayReady(
                formalSessionEndpoint)) {
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        reportWirelessDisplayWait("formal_session");
                        requestFormalUsageStop(
                                "wireless_foreground_display_unavailable");
                    });
            return;
        }
        if (recoverPendingFormalStart(runtime, generationReceipt)) {
            return;
        }
        if (runtime.snapshot().canFormalStart()) {
            AtomicBoolean automaticStartAllowed = new AtomicBoolean();
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        reconcileAutomaticUsageGuardWithIdleRuntime(runtime);
                        automaticStartAllowed.set(
                                automaticUsageGuard.isAutomaticStartAllowed());
                    });
            if (!automaticStartAllowed.get()) {
                maintainAutomaticUsageRearm(runtime, generationReceipt);
                return;
            }
            attemptAutomaticFormalUsageStart(runtime, generationReceipt);
            return;
        }
        DualMachineFormalUsageCoordinator.DataPlanePermitState permitState =
                runtime.enforceDataPlanePermitState();
        if (permitState
                == DualMachineFormalUsageCoordinator
                .DataPlanePermitState.SUPERSEDED) {
            return;
        }
        if (permitState
                == DualMachineFormalUsageCoordinator
                .DataPlanePermitState.STAGED_WAITING) {
            // Keep the paid session and binding while the data plane remains
            // closed until the verified next permit reaches its not-before.
            return;
        }
        if (permitState
                == DualMachineFormalUsageCoordinator
                .DataPlanePermitState.CLOSED) {
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        formalRenewalRetryPending.set(false);
                        nextFormalRenewalAttemptElapsedMillis.set(0L);
                        clearFormalSessionBinding();
                        DualMachineFormalUsageStateMachine.Snapshot snapshot =
                                runtime.snapshot();
                        reconcileRuntimeLocksAfterDataPlaneClose(
                                "formal_permit_state_closed");
                        if (snapshot.canFormalStop()) {
                            requestFormalUsageStop("formal_permit_closed");
                        }
                    });
            return;
        }
        if (runtimeStatus.phase == MobileRuntimePhase.STARTING) {
            return;
        }
        long now = SystemClock.elapsedRealtime();
        long nextAttempt = nextFormalRenewalAttemptElapsedMillis.get();
        if (now < nextAttempt) {
            return;
        }
        AtomicBoolean deferRenewal = new AtomicBoolean();
        AtomicBoolean retryPending = new AtomicBoolean();
        commitFormalGeneration(
                runtime,
                generationReceipt,
                () -> {
                    deferRenewal.set(deferRenewalUntilWindow(runtime, now));
                    if (!deferRenewal.get()) {
                        retryPending.set(formalRenewalRetryPending.get());
                        nextFormalRenewalAttemptElapsedMillis.set(
                                now
                                        + AUTHORIZATION_RENEWAL_MIN_INTERVAL_MILLIS);
                    }
                });
        if (deferRenewal.get()) return;
        DualMachineFormalUsageCoordinator.RenewalOutcome outcome;
        try {
            if (retryPending.get()) {
                outcome = runtime.retryPendingRenewal(generationReceipt);
            } else {
                outcome = runtime.renewAfterObservedProgress(
                        generationReceipt);
            }
        } catch (DualMachineSidecarPort.RejectedException failure) {
            writeFormalRenewalTiming(
                    runtime, generationReceipt, "rejected", failure);
            if (failure.statusCode != 429) {
                throw failure;
            }
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        formalRenewalRetryPending.set(true);
                        nextFormalRenewalAttemptElapsedMillis.set(
                                now
                                        + AUTHORIZATION_RENEWAL_REJECTED_BACKOFF_MILLIS);
                        events.write(
                                "dual_machine_formal_renewal_deferred",
                                "reason=server_rejected_too_early status_code="
                                        + failure.statusCode);
                    });
            return;
        } catch (IOException failure) {
            writeFormalRenewalTiming(
                    runtime, generationReceipt, "network_failure", failure);
            if (isFatalAuthorizationIoFailure(failure)) {
                throw failure;
            }
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        formalRenewalRetryPending.set(true);
                        nextFormalRenewalAttemptElapsedMillis.set(
                                now
                                        + AUTHORIZATION_RENEWAL_REJECTED_BACKOFF_MILLIS);
                        events.write(
                                "dual_machine_formal_renewal_deferred",
                                "reason=network_retry_required failure_type="
                                        + failure.getClass().getSimpleName());
                    });
            return;
        } catch (GeneralSecurityException | RuntimeException failure) {
            writeFormalRenewalTiming(
                    runtime, generationReceipt, "local_failure", failure);
            throw failure;
        }
        writeFormalRenewalTiming(
                runtime,
                generationReceipt,
                outcome.name().toLowerCase(Locale.ROOT),
                null);
        final String noProgressDetail = outcome
                == DualMachineFormalUsageCoordinator.RenewalOutcome.NO_PROGRESS
                ? noProgressRenewalDetail(
                runtime.latestRenewalProgressObservation(generationReceipt))
                : "";
        commitFormalGeneration(
                runtime,
                generationReceipt,
                () -> {
                    formalRenewalRetryPending.set(false);
                    if (outcome == DualMachineFormalUsageCoordinator
                            .RenewalOutcome.NO_PROGRESS) {
                        nextFormalRenewalAttemptElapsedMillis.set(
                                now
                                        + AUTHORIZATION_RENEWAL_NO_PROGRESS_BACKOFF_MILLIS);
                        events.write(
                                "dual_machine_formal_renewal",
                                "outcome=no_progress " + noProgressDetail);
                        stopAutomaticallyAfterSustainedInferenceStall(now);
                    } else {
                        recordLatestHostFrameFromNative();
                        automaticUsageGuard.markProgressRenewed();
                        checkpointAutomaticUsageGuardIfDue(
                                now, "successful_formal_renewal");
                        if (!deferRenewalUntilWindow(runtime, now)) {
                            nextFormalRenewalAttemptElapsedMillis.set(
                                    now
                                            + AUTHORIZATION_RENEWAL_MIN_INTERVAL_MILLIS);
                        }
                    }
                    if (outcome != DualMachineFormalUsageCoordinator
                            .RenewalOutcome.NO_PROGRESS) {
                        events.write(
                                "dual_machine_formal_renewal",
                                "outcome=" + outcome.name()
                                        .toLowerCase(Locale.ROOT));
                    }
                });
    }

    private void writeFormalRenewalTiming(
            DualMachineAuthorizationRuntime runtime,
            DualMachineAuthorizationRuntime.CurrentGenerationReceipt receipt,
            String outcome,
            Throwable failure) {
        try {
            DualMachineFormalUsageCoordinator.RenewalTiming timing =
                    runtime.latestRenewalTiming(receipt);
            if (!timing.attempted) return;
            events.write(
                    "dual_machine_formal_renewal_timing",
                    "sequence=" + timing.sequence
                            + " outcome=" + safeToken(outcome)
                            + " terminal_phase="
                            + safeToken(timing.terminalPhase)
                            + " proof_ms=" + timing.proofMillis
                            + " sidecar_ms=" + timing.sidecarMillis
                            + " install_ms=" + timing.installMillis
                            + " total_ms=" + timing.totalMillis
                            + (failure == null
                            ? ""
                            : " failure_type="
                            + failure.getClass().getSimpleName()));
        } catch (RuntimeException staleGeneration) {
            // Diagnostics must never revive or retain a superseded generation.
        }
    }

    private String noProgressRenewalDetail(
            DualMachineFormalUsageCoordinator.RenewalProgressObservation
                    observation) {
        String counters = "observed_host_progress="
                + observation.observedHostProgress
                + " last_host_progress=" + observation.lastHostProgress
                + " observed_android_progress="
                + observation.observedAndroidProgress
                + " last_android_progress="
                + observation.lastAndroidProgress;
        try {
            MobileRuntimeSnapshot snapshot = MobileRuntimeSnapshot.from(
                    QnnHtpBridge.getNativeVideoReceiverReport(),
                    QnnHtpBridge.getNativeH264DecoderReport(),
                    "", "");
            return counters
                    + " video_age_ms=" + snapshot.lastVideoAgeMillis
                    + " qnn_age_ms=" + snapshot.lastQnnSuccessAgeMillis;
        } catch (RuntimeException | LinkageError ignored) {
            return counters + " video_age_ms=-1 qnn_age_ms=-1";
        }
    }

    private void commitFormalGeneration(
            DualMachineAuthorizationRuntime runtime,
            DualMachineAuthorizationRuntime.CurrentGenerationReceipt receipt,
            DualMachineAuthorizationRuntime.CheckedGenerationCommit commit)
            throws IOException, GeneralSecurityException {
        if (!runtime.commitCheckedIfCurrent(receipt, commit)) {
            throw new DualMachineFormalUsageCoordinator
                    .AdmissionSupersededException(
                    "formal generation follow-up was superseded");
        }
    }

    private void reconcileAutomaticUsageGuardWithIdleRuntime(
            DualMachineAuthorizationRuntime runtime) {
        AutomaticFormalUsageSessionGuard.State state =
                automaticUsageGuard.snapshot().state;
        if (state == AutomaticFormalUsageSessionGuard.State.START_RESERVED) {
            cancelUnbilledStartReservationIfAborted(
                    runtime, "formal_runtime_returned_idle");
            return;
        }
        if (state == AutomaticFormalUsageSessionGuard.State.ACTIVE) {
            blockAutomaticStartForCurrentHostStream(
                    "formal_runtime_returned_idle");
        }
    }

    private void maintainAutomaticUsageRearm(
            DualMachineAuthorizationRuntime runtime,
            DualMachineAuthorizationRuntime.CurrentGenerationReceipt
                    generationReceipt)
            throws IOException, GeneralSecurityException {
        long now = SystemClock.elapsedRealtime();
        AtomicBoolean shouldClaim = new AtomicBoolean();
        commitFormalGeneration(
                runtime,
                generationReceipt,
                () -> {
                    if (!automaticUsageGuard.requiresHostRearmProbe()
                            || now
                            < nextAutomaticHostAttemptElapsedMillis.get()) {
                        return;
                    }
                    nextAutomaticHostAttemptElapsedMillis.set(
                            now + AUTOMATIC_REARM_CLAIM_INTERVAL_MILLIS);
                    boolean wasConfirmed = automaticUsageGuard
                            .snapshot().hostAbsenceConfirmed;
                    boolean confirmed = automaticUsageGuard.recordHostAbsent(
                            now, AUTOMATIC_REARM_HOST_ABSENCE_MILLIS);
                    if (confirmed && !wasConfirmed) {
                        events.write(
                                "dual_machine_automatic_usage_host_absence_confirmed",
                                "required_absence_ms="
                                        + AUTOMATIC_REARM_HOST_ABSENCE_MILLIS
                                        + " billing_started=false");
                    }
                    shouldClaim.set(confirmed);
                });
        if (!shouldClaim.get()) return;
        AndroidBoundAuthenticatedControlCoordinatorV1 coordinator =
                pairingRuntime.authenticatedControl();
        if (coordinator == null || !coordinator.isAuthenticated()) return;
        try {
            AuthenticatedHostStartIntentClaimV1.Claim claim =
                    coordinator.claimHostStartIntent();
            if (!claim.present()) {
                automaticRearmProbeFailureReported.set(false);
                return;
            }
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        AutomaticFormalUsageSessionGuard.HostStartIntentOutcome
                                outcome = automaticUsageGuard
                                .recordAuthenticatedHostStartIntent(
                                        claim.connectionId,
                                        claim.intentToken);
                        automaticRearmProbeFailureReported.set(false);
                        if (outcome == AutomaticFormalUsageSessionGuard
                                .HostStartIntentOutcome
                                .NEW_START_INTENT_REARMED) {
                            clearPersistedAutomaticUsageBlock();
                            nextAutomaticHostAttemptElapsedMillis.set(0L);
                            nextFormalStartRetryElapsedMillis.set(0L);
                            formalStartRetryPolicy.reset();
                            events.write(
                                    "dual_machine_automatic_usage_rearmed",
                                    "reason=authenticated_host_start_intent "
                                            + "one_shot_claim=true "
                                            + "prelease_video=false "
                                            + "billing_started=false "
                                            + automaticUsageGuard.snapshot()
                                            .detail());
                        }
                    });
        } catch (IOException | GeneralSecurityException failure) {
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        if (automaticRearmProbeFailureReported.compareAndSet(
                                false, true)) {
                            events.write(
                                    "dual_machine_automatic_usage_rearm_probe_failed",
                                    "channel=authenticated_control "
                                            + "prelease_video=false "
                                            + "billing_started=false failure_type="
                                            + failure.getClass()
                                            .getSimpleName()
                                            + " stack={"
                                            + MobileThrowableDiagnostics
                                            .format(failure)
                                            + "}");
                        }
                    });
        }
    }

    private void attemptAutomaticFormalUsageStart(
            DualMachineAuthorizationRuntime runtime,
            DualMachineAuthorizationRuntime.CurrentGenerationReceipt
                    generationReceipt)
            throws IOException, GeneralSecurityException {
        long now = SystemClock.elapsedRealtime();
        AtomicBoolean shouldStart = new AtomicBoolean();
        AtomicReference<String> attemptedRouteIdentity =
                new AtomicReference<>("transport_unavailable");
        commitFormalGeneration(
                runtime,
                generationReceipt,
                () -> {
                    MobileTransportEndpoint transportCandidate =
                            transportCatalog.selected();
                    if (now < nextAutomaticHostAttemptElapsedMillis.get()
                            || now < nextFormalStartRetryElapsedMillis.get()
                            || authorizationOperationInFlight.get()
                            || automaticFormalStopQueued.get()
                            || !PROCESS_RETRY_GATE.canAttempt()
                            || transportCandidate == null) {
                        return;
                    }
                    attemptedRouteIdentity.set(transportCandidate.detail());
                    nextAutomaticHostAttemptElapsedMillis.set(
                            now + AUTOMATIC_HOST_RETRY_BACKOFF_MILLIS);
                    if (!isWirelessForegroundDisplayReady(
                            transportCandidate)) {
                        reportWirelessDisplayWait("automatic_start");
                        return;
                    }
                    wirelessDisplayWaitReported.set(false);
                    // Lock acquisition is local and bounded; Host probing and
                    // HTTPS remain outside attachmentLock below.
                    acquireRuntimeLocks(transportCandidate);
                    if (requiredTransportEndpoint() == null) return;
                    publishTransientAuthorizationState(
                            DualMachineAuthorizationUiState.Status.STARTING);
                    shouldStart.set(true);
                });
        if (!shouldStart.get()) return;
        try {
            runtime.startFormalUsage(generationReceipt);
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        nextAutomaticHostAttemptElapsedMillis.set(0L);
                        nextFormalStartRetryElapsedMillis.set(0L);
                        formalStartRetryPolicy.reset();
                        automaticHostWaitLogPolicy.clearFailure();
                        events.write(
                                "dual_machine_formal_start_automatic",
                                "result=success trigger=authenticated_host_lease_commit");
                    });
        } catch (HostVideoPresenceProbe.HostVideoProbeCancelledException cancelled) {
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        automaticHostWaitLogPolicy.clearFailure();
                        nextFormalStartRetryElapsedMillis.set(0L);
                        if (!automaticFormalStopQueued.get() && !destroying) {
                            events.write(
                                    "dual_machine_formal_start_cancelled",
                                    "reason=local_preflight_cancelled"
                                            + " billing_started=false"
                                            + " exact_start_retry=false");
                        }
                    });
        } catch (HostVideoPresenceProbe.HostVideoNotObservedException waiting) {
            long failureObservedAt = SystemClock.elapsedRealtime();
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        if (automaticFormalStopQueued.get()) return;
                        cancelUnbilledStartReservationIfAborted(
                                runtime, "host_video_not_observed");
                        formalStartRetryPolicy.reset();
                        nextFormalStartRetryElapsedMillis.set(
                                SystemClock.elapsedRealtime()
                                        + AUTOMATIC_HOST_RETRY_BACKOFF_MILLIS);
                        if (automaticHostWaitLogPolicy.shouldWriteFailure(
                                attemptedRouteIdentity.get(),
                                "armed_waiting_host",
                                failureObservedAt)) {
                            events.write(
                                    "dual_machine_formal_start_automatic",
                                    "result=armed_waiting_host"
                                            + " log_policy=state_change_or_heartbeat"
                                            + " billing_started=false");
                        }
                    });
        } catch (DualMachineFormalUsageCoordinator
                         .StartCancelledException cancelled) {
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        nextFormalStartRetryElapsedMillis.set(0L);
                        automaticHostWaitLogPolicy.clearFailure();
                        events.write(
                                "dual_machine_formal_start_cancelled",
                                "late_verified_lease="
                                        + cancelled.billingStarted
                                        + " server_confirmed="
                                        + cancelled.serverConfirmed
                                        + " exact_start_retry=false");
                    });
        } catch (DualMachineSidecarPort.RejectedException rejected) {
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        if (automaticFormalStopQueued.get()) {
                            automaticHostWaitLogPolicy.clearFailure();
                            events.write(
                                    "dual_machine_formal_start_cancelled",
                                    "server_rejected_after_stop=true status_code="
                                            + rejected.statusCode
                                            + " exact_start_retry=false");
                            return;
                        }
                        AutomaticFormalStartRetryPolicy.Decision retry =
                                formalStartRetryPolicy.recordRejection();
                        automaticHostWaitLogPolicy.clearFailure();
                        nextFormalStartRetryElapsedMillis.set(
                                SystemClock.elapsedRealtime()
                                        + retry.retryDelayMillis);
                        cancelUnbilledStartReservationIfAborted(
                                runtime,
                                "server_rejected_" + rejected.statusCode);
                        events.write(
                                "dual_machine_formal_start_automatic",
                                "result=server_rejected status_code="
                                        + rejected.statusCode
                                        + " safe_error_code="
                                        + safeToken(rejected.safeErrorCode)
                                        + " consecutive_rejections="
                                        + retry.consecutiveRejections
                                        + " retry_delay_ms="
                                        + retry.retryDelayMillis
                                        + " billing_started=false");
                    });
        } catch (IOException ambiguousStartFailure) {
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    automaticHostWaitLogPolicy::clearFailure);
            if (ambiguousStartFailure
                    instanceof DualMachineFormalUsageCoordinator
                    .GenerationBoundRejectedException) {
                DualMachineFormalUsageCoordinator
                        .GenerationBoundRejectedException rejected =
                        (DualMachineFormalUsageCoordinator
                        .GenerationBoundRejectedException)
                        ambiguousStartFailure;
                settleTerminalFormalStartFailure(
                        rejected,
                        "dispatched_start_rejected_"
                                + rejected.statusCode);
                return;
            }
            if (isFatalAuthorizationIoFailure(ambiguousStartFailure)) {
                settleTerminalFormalStartFailure(
                        ambiguousStartFailure,
                        "fatal_start_transport_failure");
                throw new GeneralSecurityException(
                        "automatic formal start TLS failure",
                        ambiguousStartFailure);
            }
            if (ambiguousStartFailure
                    instanceof DualMachineFormalUsageCoordinator
                    .GenerationBoundStartFailure) {
                commitFormalGeneration(
                        runtime,
                        generationReceipt,
                        () -> {
                            nextFormalStartRetryElapsedMillis.set(
                                    now
                                            + AUTHORIZATION_START_RETRY_BACKOFF_MILLIS);
                            events.write(
                                    "dual_machine_formal_start_exact_retry",
                                    "reason=ambiguous_response same_request=true"
                                            + " action=deferred_generation_bound");
                        });
                return;
            }
            AtomicBoolean shouldRetry = new AtomicBoolean();
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        if (runtime.snapshot().state
                                != DualMachineFormalUsageStateMachine.State
                                .STARTING) {
                            cancelUnbilledStartReservationIfAborted(
                                    runtime,
                                    "network_failure_before_debit");
                            events.write(
                                    "dual_machine_formal_start_automatic",
                                    "result=network_deferred billing_started=false");
                            return;
                        }
                        events.write(
                                "dual_machine_formal_start_exact_retry",
                                "reason=ambiguous_response same_request=true");
                        shouldRetry.set(!automaticFormalStopQueued.get());
                    });
            if (!shouldRetry.get()) return;
            try {
                runtime.retryPendingFormalStart(generationReceipt);
                commitFormalGeneration(
                        runtime,
                        generationReceipt,
                        () -> nextAutomaticHostAttemptElapsedMillis.set(0L));
            } catch (DualMachineFormalUsageCoordinator
                             .StartCancelledException cancelled) {
                commitFormalGeneration(
                        runtime,
                        generationReceipt,
                        () -> {
                            nextFormalStartRetryElapsedMillis.set(0L);
                            events.write(
                                    "dual_machine_formal_start_cancelled",
                                    "late_verified_lease="
                                            + cancelled.billingStarted
                                            + " server_confirmed="
                                            + cancelled.serverConfirmed
                                            + " exact_start_retry=false");
                        });
            } catch (IOException retryFailure) {
                if (retryFailure instanceof DualMachineFormalUsageCoordinator
                        .GenerationBoundRejectedException) {
                    settleTerminalFormalStartFailure(
                            retryFailure,
                            "exact_retry_rejected");
                    return;
                }
                if (isFatalAuthorizationIoFailure(retryFailure)) {
                    settleTerminalFormalStartFailure(
                            retryFailure,
                            "fatal_exact_retry_transport_failure");
                    throw new GeneralSecurityException(
                            "automatic formal start retry TLS failure",
                            retryFailure);
                }
                if (retryFailure
                        instanceof DualMachineFormalUsageCoordinator
                        .GenerationBoundStartFailure) {
                    commitFormalGeneration(
                            runtime,
                            generationReceipt,
                            () -> nextFormalStartRetryElapsedMillis.set(
                                    SystemClock.elapsedRealtime()
                                            + AUTHORIZATION_START_RETRY_BACKOFF_MILLIS));
                    return;
                }
                commitFormalGeneration(
                        runtime,
                        generationReceipt,
                        () -> {
                            DualMachineFormalUsageStateMachine.State
                                    retryState = runtime.snapshot().state;
                            if (retryState
                                    == DualMachineFormalUsageStateMachine.State
                                    .STOPPING
                                    || runtime
                                    .hasPendingFormalStartCancellation()
                                    && retryState
                                    != DualMachineFormalUsageStateMachine.State
                                    .STARTING) {
                                blockPotentiallyBilledStartIfAborted(
                                        runtime,
                                        "exact_retry_terminal_failure");
                                return;
                            }
                            if (retryState
                                    == DualMachineFormalUsageStateMachine.State
                                    .STARTING) {
                                nextFormalStartRetryElapsedMillis.set(
                                        SystemClock.elapsedRealtime()
                                                + AUTHORIZATION_START_RETRY_BACKOFF_MILLIS);
                                return;
                            }
                            cancelUnbilledStartReservationIfAborted(
                                    runtime, "exact_retry_aborted");
                        });
            } catch (GeneralSecurityException retryFailure) {
                settleTerminalFormalStartFailure(
                        retryFailure, "exact_retry_security_failure");
                throw retryFailure;
            } catch (DualMachineFormalUsageCoordinator
                             .AdmissionSupersededException superseded) {
                recordSupersededFormalStartAttempt("exact_retry");
                return;
            } catch (RuntimeException retryFailure) {
                settleTerminalFormalStartFailure(
                        retryFailure, "exact_retry_runtime_failure");
                throw retryFailure;
            }
        } catch (GeneralSecurityException failure) {
            settleTerminalFormalStartFailure(
                    failure, "start_security_failure");
            throw failure;
        } catch (DualMachineFormalUsageCoordinator
                         .AdmissionSupersededException superseded) {
            recordSupersededFormalStartAttempt("fresh_start");
        } catch (RuntimeException failure) {
            settleTerminalFormalStartFailure(
                    failure, "start_runtime_failure");
            throw failure;
        } finally {
            runtime.commitIfCurrent(
                    generationReceipt,
                    () -> publishMappedAuthorizationState(""));
        }
    }

    private void stopAutomaticallyAfterSustainedInferenceStall(long now) {
        if (!automaticUsageGuard.shouldStopAfterNoProgress(
                now, AUTOMATIC_NO_PROGRESS_STOP_MILLIS)) {
            return;
        }
        events.write(
                "dual_machine_formal_idle_detected",
                "action=automatic_stop reason=inference_progress_stalled"
                        + " progress_was_previously_renewed=true");
        requestFormalUsageStop("inference_progress_stalled");
    }

    private boolean recoverPendingFormalStart(
            DualMachineAuthorizationRuntime runtime,
            DualMachineAuthorizationRuntime.CurrentGenerationReceipt
                    generationReceipt)
            throws IOException, GeneralSecurityException {
        long now = SystemClock.elapsedRealtime();
        AtomicBoolean shouldRetry = new AtomicBoolean();
        AtomicBoolean handled = new AtomicBoolean();
        commitFormalGeneration(
                runtime,
                generationReceipt,
                () -> {
                    if (automaticFormalStopQueued.get()) {
                        handled.set(true);
                        return;
                    }
                    DualMachineFormalUsageStateMachine.State initialState =
                            runtime.snapshot().state;
                    if (initialState
                            == DualMachineFormalUsageStateMachine.State.STOPPING
                            || runtime.hasPendingFormalStartCancellation()
                            && initialState
                            != DualMachineFormalUsageStateMachine.State
                            .STARTING) {
                        blockPotentiallyBilledStartIfAborted(
                                runtime,
                                "pending_start_requires_cancellation");
                        handled.set(true);
                        return;
                    }
                    if (initialState
                            != DualMachineFormalUsageStateMachine.State
                            .STARTING) {
                        nextFormalStartRetryElapsedMillis.set(0L);
                        cancelUnbilledStartReservationIfAborted(
                                runtime, "no_pending_formal_start");
                        return;
                    }
                    handled.set(true);
                    if (now < nextFormalStartRetryElapsedMillis.get()) return;
                    nextFormalStartRetryElapsedMillis.set(
                            now + AUTHORIZATION_START_RETRY_BACKOFF_MILLIS);
                    shouldRetry.set(true);
                });
        if (!shouldRetry.get()) return handled.get();
        try {
            runtime.retryPendingFormalStart(generationReceipt);
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        nextFormalStartRetryElapsedMillis.set(0L);
                        events.write(
                                "dual_machine_formal_start_recovered",
                                "same_request=true data_plane_open=true");
                    });
            return true;
        } catch (DualMachineFormalUsageCoordinator
                         .StartCancelledException cancelled) {
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        nextFormalStartRetryElapsedMillis.set(0L);
                        events.write(
                                "dual_machine_formal_start_cancelled",
                                "source=pending_recovery late_verified_lease="
                                        + cancelled.billingStarted
                                        + " server_confirmed="
                                        + cancelled.serverConfirmed
                                        + " exact_start_retry=false");
                    });
            return true;
        } catch (DualMachineSidecarPort.RejectedException failure) {
            AtomicBoolean rethrow = new AtomicBoolean();
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        if (automaticFormalStopQueued.get()) return;
                        if (runtime.snapshot().state
                                == DualMachineFormalUsageStateMachine.State
                                .STOPPING
                                || runtime
                                .hasPendingFormalStartCancellation()) {
                            blockPotentiallyBilledStartIfAborted(
                                    runtime,
                                    "pending_start_rejected_"
                                            + failure.statusCode);
                            return;
                        }
                        if (runtime.snapshot().state
                                != DualMachineFormalUsageStateMachine.State
                                .STARTING
                                || failure.statusCode < 500) {
                            cancelUnbilledStartReservationIfAborted(
                                    runtime,
                                    "pending_start_rejected_"
                                            + failure.statusCode);
                            rethrow.set(true);
                            return;
                        }
                        nextFormalStartRetryElapsedMillis.set(
                                SystemClock.elapsedRealtime()
                                        + AUTHORIZATION_START_RETRY_BACKOFF_MILLIS);
                        events.write(
                                "dual_machine_formal_start_retry_deferred",
                                "reason=server_error same_request=true status_code="
                                        + failure.statusCode);
                    });
            if (rethrow.get()) throw failure;
            return true;
        } catch (IOException failure) {
            if (failure instanceof DualMachineFormalUsageCoordinator
                    .GenerationBoundRejectedException) {
                settleTerminalFormalStartFailure(
                        failure, "pending_start_rejected");
                return true;
            }
            if (isFatalAuthorizationIoFailure(failure)) {
                settleTerminalFormalStartFailure(
                        failure,
                        "fatal_pending_start_transport_failure");
                throw failure;
            }
            if (failure instanceof DualMachineFormalUsageCoordinator
                    .GenerationBoundStartFailure) {
                commitFormalGeneration(
                        runtime,
                        generationReceipt,
                        () -> nextFormalStartRetryElapsedMillis.set(
                                SystemClock.elapsedRealtime()
                                        + AUTHORIZATION_START_RETRY_BACKOFF_MILLIS));
                return true;
            }
            AtomicBoolean rethrow = new AtomicBoolean();
            commitFormalGeneration(
                    runtime,
                    generationReceipt,
                    () -> {
                        if (automaticFormalStopQueued.get()) return;
                        DualMachineFormalUsageStateMachine.State retryState =
                                runtime.snapshot().state;
                        if (retryState
                                == DualMachineFormalUsageStateMachine.State
                                .STOPPING
                                || runtime.hasPendingFormalStartCancellation()
                                && retryState
                                != DualMachineFormalUsageStateMachine.State
                                .STARTING) {
                            blockPotentiallyBilledStartIfAborted(
                                    runtime,
                                    "pending_start_io_requires_cancellation");
                            return;
                        }
                        if (retryState
                                != DualMachineFormalUsageStateMachine.State
                                .STARTING) {
                            cancelUnbilledStartReservationIfAborted(
                                    runtime, "pending_start_io_aborted");
                            rethrow.set(true);
                            return;
                        }
                        nextFormalStartRetryElapsedMillis.set(
                                SystemClock.elapsedRealtime()
                                        + AUTHORIZATION_START_RETRY_BACKOFF_MILLIS);
                        events.write(
                                "dual_machine_formal_start_retry_deferred",
                                "reason=ambiguous_response same_request=true failure_type="
                                        + failure.getClass().getSimpleName());
                    });
            if (rethrow.get()) throw failure;
            return true;
        } catch (GeneralSecurityException failure) {
            settleTerminalFormalStartFailure(
                    failure, "pending_start_security_failure");
            throw failure;
        } catch (DualMachineFormalUsageCoordinator
                         .AdmissionSupersededException superseded) {
            recordSupersededFormalStartAttempt("pending_recovery");
            return true;
        } catch (RuntimeException failure) {
            settleTerminalFormalStartFailure(
                    failure, "pending_start_runtime_failure");
            throw failure;
        }
    }

    private boolean deferRenewalUntilWindow(
            DualMachineAuthorizationRuntime runtime, long nowElapsedMillis) {
        long waitMillis = runtime.millisUntilRenewalWindow(
                AUTHORIZATION_RENEWAL_WINDOW_SECONDS);
        if (waitMillis <= 0L) {
            return false;
        }
        nextFormalRenewalAttemptElapsedMillis.set(
                nowElapsedMillis + waitMillis
                        + AUTHORIZATION_RENEWAL_WINDOW_GUARD_MILLIS);
        return true;
    }

    private static boolean isFatalAuthorizationIoFailure(IOException failure) {
        for (Throwable cursor = failure; cursor != null;
                cursor = cursor.getCause()) {
            if (cursor instanceof GeneralSecurityException) {
                return true;
            }
        }
        String message = failure.getMessage();
        return message != null
                && message.toLowerCase(Locale.ROOT).contains("tls");
    }

    /**
     * Internal handoff for a mutually authenticated control-session owner,
     * never for Binder UI. The service owns the formal runtime boundary so a
     * peer adapter cannot substitute a route-derived channel binding.
     */
    void attachAuthenticatedHost(
            DualMachineCardAuthorizationCoordinator.IdentityBinding
                    hostIdentity,
            String channelBindingSha256,
            BooleanSupplier authenticatedSource) {
        DualMachineAuthorizationRuntime.Attachment attachment =
                new DualMachineAuthorizationRuntime.Attachment(
                        hostIdentity,
                        channelBindingSha256,
                        new AuthenticatedHostFormalRuntimeBoundary(),
                        authenticatedSource,
                        this::readHostProgress,
                        this::trustedEpochSeconds);
        FormalPipelineOwnerReceipt schedulingOwner =
                captureFormalPipelineOwner();
        try {
            authorizationExecutor.execute(() -> {
                DualMachineAuthorizationRuntime runtime =
                        authorizationRuntime;
                if (runtime == null) return;
                FormalPipelineOwnerReceipt priorOwner =
                        captureFormalPipelineOwner();
                try {
                    runtime.attachAuthenticatedHost(attachment);
                    events.write(
                            "dual_machine_authenticated_host_attached",
                            "channel_binding_verified=true");
                    publishMappedAuthorizationState("");
                    refreshAuthorizationStatusAfterRestore(runtime);
                } catch (GeneralSecurityException
                         | RuntimeException failure) {
                    stopFormalUsageIfCurrentOwner(
                            priorOwner,
                            () -> true,
                            "authenticated_host_attach_rejected");
                    events.write(
                            "dual_machine_authenticated_host_rejected",
                            "failure_type="
                                    + failure.getClass().getSimpleName());
                    publishMappedAuthorizationState(getString(
                            R.string.authorization_operation_failed));
                }
            });
        } catch (RuntimeException ignored) {
            detachAuthenticatedHost(
                    schedulingOwner,
                    "authenticated_host_attach_schedule_rejected");
        }
    }

    /** Synchronous local fail-close entry for video transport loss callbacks. */
    void detachAuthenticatedHost() {
        detachAuthenticatedHost(
                captureFormalPipelineOwner(),
                "video_transport_detached");
    }

    private void detachAuthenticatedHost(
            FormalPipelineOwnerReceipt owner,
            String reason) {
        FormalOwnerStopResult stopResult =
                stopFormalUsageIfCurrentOwner(
                        owner, () -> true, reason);
        closeFormalDataPlaneLocally(reason);
        DualMachineAuthorizationRuntime runtime = authorizationRuntime;
        if (runtime != null) {
            try {
                authorizationExecutor.execute(() -> {
                    if (authorizationRuntime != runtime) return;
                    try {
                        runtime.detachAuthenticatedHost();
                        events.write(
                                "dual_machine_authenticated_host_detached",
                                "reason=" + safeToken(reason)
                                        + " authority_revoked=true");
                    } catch (RuntimeException | LinkageError failure) {
                        runtime.requestImmediateLocalStop();
                        events.write(
                                "dual_machine_authenticated_host_detach_failed",
                                "reason=" + safeToken(reason)
                                        + " local_stop=true failure_type="
                                        + failure.getClass().getSimpleName());
                    }
                    publishMappedAuthorizationState("");
                });
            } catch (RuntimeException schedulingFailure) {
                runtime.requestImmediateLocalStop();
                events.write(
                        "dual_machine_authenticated_host_detach_deferred",
                        "reason=" + safeToken(reason)
                                + " local_stop=true failure_type="
                                + schedulingFailure.getClass().getSimpleName());
            }
        }
        events.write(
                "dual_machine_video_transport_detached",
                "formal_session_closed=true automatic_rearm=true"
                        + " host_authorization=false owner_result="
                        + stopResult.name().toLowerCase(Locale.ROOT));
        publishMappedAuthorizationState("");
    }

    private void publishMappedAuthorizationState(String detail) {
        DualMachineAuthorizationRuntime runtime = authorizationRuntime;
        QueuedCardActivationCoordinator queuedCards = queuedCardActivation;
        if (runtime == null) {
            if (authorizationSecurityFatal) {
                publishFatalAuthorizationState();
            } else {
                publishAuthorizationState(
                        queuedCards == null
                                ? DualMachineAuthorizationUiState
                                .readyForActivation()
                                : queuedCards.unactivatedState(),
                        detail);
            }
            return;
        }
        boolean cardQueued = queuedCards != null && queuedCards.isPresent();
        DualMachineFormalUsageStateMachine.Snapshot snapshot =
                runtime.snapshot();
        DualMachinePresentationBalance cachedBalance =
                presentationBalanceReconciler.reconcile(
                        snapshot, authorizationUiState.balanceKnown);
        DualMachineAuthorizationUiState mapped =
                DualMachineAuthorizationUiMapper.map(
                        snapshot,
                        runtime.hasAuthenticatedHost(),
                        runtime.hasCardActivationAuthority(),
                        authorizationSecurityFatal,
                        detail,
                        cachedBalance,
                        cardQueued);
        publishAuthorizationState(mapped, detail);
    }

    private void publishFatalAuthorizationState() {
        DualMachineFormalUsageStateMachine state =
                new DualMachineFormalUsageStateMachine();
        DualMachineAuthorizationRuntime runtime = authorizationRuntime;
        DualMachineFormalUsageStateMachine.Snapshot snapshot = runtime == null
                ? state.snapshot() : runtime.snapshot();
        String detail = getString(
                R.string.authorization_security_configuration_failed);
        publishAuthorizationState(
                DualMachineAuthorizationUiMapper.map(
                        snapshot, false, true, detail),
                detail);
    }

    private void publishTransientAuthorizationState(
            DualMachineAuthorizationUiState.Status status) {
        DualMachineAuthorizationUiState current = authorizationUiState;
        publishAuthorizationState(
                new DualMachineAuthorizationUiState(
                        status,
                        current.authorizationReady,
                        current.activationReady,
                        current.remainingSeconds,
                        current.totalConsumedSeconds,
                        current.balanceKnown,
                        current.displayBalanceKnown,
                        current.balanceStale,
                        current.balanceSynchronizedAtEpochSeconds,
                        current.permanent,
                        ""),
                "");
    }

    private void publishAuthorizationState(
            DualMachineAuthorizationUiState next,
            String note) {
        DualMachineAuthorizationUiState previous = authorizationUiState;
        authorizationUiState = next;
        MobileRuntimeAuthorizationObserver observer = authorizationObserver;
        if (observer == null
                || (next.equals(previous)
                && (note == null || note.isEmpty()))) {
            return;
        }
        postAuthorizationUpdate(observer, next, note);
    }

    private void postAuthorizationUpdate(
            MobileRuntimeAuthorizationObserver observer,
            DualMachineAuthorizationUiState state,
            String note) {
        mainHandler.post(() -> {
            if (!destroying && authorizationObserver == observer) {
                observer.onAuthorizationChanged(
                        state, note == null ? "" : note);
            }
        });
    }

    @FunctionalInterface
    private interface AuthorizationOperation {
        Object run(DualMachineAuthorizationRuntime runtime)
                throws IOException, GeneralSecurityException;
    }

    private void stopPipeline(String reason) {
        clearFormalSessionBinding();
        formalDataPlanePermitOpen.set(false);
        synchronized (pipelineCommandLock) {
            pipelineSessionGeneration.incrementAndGet();
            pipelineDesired = false;
        }
        cancelReceiverLivenessProbe();
        controlRuntime.failClosed(reason);
        if (destroying) return;
        try {
            runtimeExecutor.execute(() -> stopPipelineSynchronously(reason));
        } catch (RuntimeException schedulingFailure) {
            events.write("mobile_pipeline_stop_schedule_failed",
                    "reason=" + reason + " stack={"
                            + MobileThrowableDiagnostics.format(schedulingFailure) + "}");
            stopPipelineSynchronously(reason);
        }
    }

    private void stopPipelineBeforeDestroy() {
        clearFormalSessionBinding();
        formalDataPlanePermitOpen.set(false);
        synchronized (pipelineCommandLock) {
            pipelineDesired = false;
        }
        cancelReceiverLivenessProbe();
        try {
            runtimeExecutor.submit(() -> stopPipelineSynchronously("service_destroyed"))
                    .get(5L, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            events.write(
                    "mobile_pipeline_shutdown_interrupted",
                    "stack={" + MobileThrowableDiagnostics.format(interrupted) + "}");
        } catch (ExecutionException | TimeoutException failure) {
            events.write(
                    "mobile_pipeline_shutdown_failed",
                    "stack={" + MobileThrowableDiagnostics.format(failure) + "}");
        } catch (RuntimeException schedulingFailure) {
            events.write(
                    "mobile_pipeline_destroy_stop_schedule_failed",
                    "stack={" + MobileThrowableDiagnostics.format(schedulingFailure) + "}");
            try {
                stopPipelineSynchronously("service_destroyed_inline_fallback");
            } catch (RuntimeException | LinkageError stopFailure) {
                events.write(
                        "mobile_pipeline_shutdown_failed",
                        "fallback=inline stack={"
                                + MobileThrowableDiagnostics.format(stopFailure) + "}");
            }
        }
    }

    private void stopPipelineSynchronously(String reason) {
        clearFormalSessionBinding();
        formalDataPlanePermitOpen.set(false);
        controlRuntime.failClosed(reason);
        if (pipelineResourcesMayBeRunning()) stopPreparedPipeline();
        pipelineStarted = false;
        pipelineNetworkHandle = 0L;
        reconcileRuntimeLocksAfterDataPlaneClose(reason);
        updateStatus(MobileRuntimePhase.READY, "pipeline_stopped reason=" + reason);
        updateNotification(R.string.runtime_notification_ready);
    }

    private boolean pipelineResourcesMayBeRunning() {
        return pipelineStarted
                || runtimeStatus.phase == MobileRuntimePhase.STARTING
                || pipeline.isPreparedDataPlaneClosed()
                || nativeVideoReceiverRunningSafely();
    }

    private void stopPreparedPipeline() {
        if (pipeline == null) return;
        synchronized (modelPreparationLock) {
            pipeline.stop();
        }
    }

    private boolean pipelineSessionIsCurrentLocked(long generation) {
        return generation == pipelineSessionGeneration.get()
                && pipelineDesired
                && !destroying
                && PROCESS_RETRY_GATE.canAttempt();
    }

    private boolean registerNetworkObserver() {
        connectivityManager = getSystemService(ConnectivityManager.class);
        if (connectivityManager == null) {
            latestEthernetDiagnostics =
                    "observer_registration accepted=false rejection_reason="
                            + "connectivity_manager_unavailable";
            publishEthernetDiagnostics();
            events.write("mobile_ethernet_observer_registration_failed",
                    latestEthernetDiagnostics);
            return false;
        }
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) {
                networkChanged(
                        "available", network,
                        readLinkPropertiesForDiagnostics(network, "available"));
            }

            @Override public void onLost(Network network) {
                networkChanged("lost", network, null);
            }

            @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
                networkChanged("link_properties_changed", network, properties);
            }

            @Override public void onCapabilitiesChanged(
                    Network network, NetworkCapabilities capabilities) {
                networkChanged(
                        "capabilities_changed", network,
                        readLinkPropertiesForDiagnostics(network, "capabilities_changed"));
            }
        };
        NetworkRequest request = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .build();
        try {
            connectivityManager.registerNetworkCallback(request, networkCallback);
            events.write(
                    "mobile_ethernet_observer_registered",
                    "transports=ethernet,wifi not_vpn=true preference=cat6_then_wireless_lan_udp "
                            + "preferred="
                            + EthernetTransportContract.requiredLink());
            return true;
        } catch (RuntimeException failure) {
            latestEthernetDiagnostics =
                    "observer_registration accepted=false rejection_reason="
                            + "network_callback_registration_exception stack={"
                            + MobileThrowableDiagnostics.format(failure) + "}";
            publishEthernetDiagnostics();
            events.write("mobile_ethernet_observer_registration_failed",
                    latestEthernetDiagnostics);
            networkCallback = null;
            return false;
        }
    }

    /** Observes only the active Android Internet route, including VPN. */
    private boolean registerAuthorizationNetworkObserver() {
        ConnectivityManager manager = connectivityManager;
        if (manager == null) return false;
        authorizationNetworkCallback =
                new ConnectivityManager.NetworkCallback() {
                    @Override public void onAvailable(Network network) {
                        signalValidatedAuthorizationNetwork(network);
                    }

                    @Override public void onCapabilitiesChanged(
                            Network network,
                            NetworkCapabilities capabilities) {
                        if (capabilities != null
                                && capabilities.hasCapability(
                                NetworkCapabilities.NET_CAPABILITY_INTERNET)
                                && capabilities.hasCapability(
                                NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                            signalAuthorizationNetworkChanged(
                                    network.getNetworkHandle());
                        }
                    }
                };
        try {
            manager.registerDefaultNetworkCallback(
                    authorizationNetworkCallback);
            return true;
        } catch (RuntimeException failure) {
            events.write(
                    "mobile_authorization_network_observer_failed",
                    "failure_type=" + failure.getClass().getSimpleName());
            authorizationNetworkCallback = null;
            return false;
        }
    }

    private void signalValidatedAuthorizationNetwork(Network network) {
        if (network == null || connectivityManager == null) return;
        NetworkCapabilities capabilities =
                connectivityManager.getNetworkCapabilities(network);
        if (capabilities != null
                && capabilities.hasCapability(
                NetworkCapabilities.NET_CAPABILITY_INTERNET)
                && capabilities.hasCapability(
                NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
            signalAuthorizationNetworkChanged(network.getNetworkHandle());
        }
    }

    private void unregisterAuthorizationNetworkObserver() {
        ConnectivityManager manager = connectivityManager;
        ConnectivityManager.NetworkCallback callback =
                authorizationNetworkCallback;
        authorizationNetworkCallback = null;
        if (manager == null || callback == null) return;
        try {
            manager.unregisterNetworkCallback(callback);
        } catch (IllegalArgumentException failure) {
            events.write(
                    "mobile_authorization_network_observer_unregister_failed",
                    "failure_type=" + failure.getClass().getSimpleName());
        }
    }

    /**
     * Keeps Android's local-only Ethernet network alive while the foreground
     * service exists. Some OEM network stacks otherwise tear down DHCP on an
     * unvalidated point-to-point link even though the cable remains connected.
     * This request does not bind the process or replace the default Internet
     * network, so authorization traffic continues to use Wi-Fi or cellular.
     */
    private boolean registerEthernetNetworkDemand() {
        ConnectivityManager manager = connectivityManager;
        if (manager == null) return false;
        ethernetDemandCallback = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) {
                events.write("mobile_ethernet_demand_satisfied",
                        "network_handle=" + network.getNetworkHandle()
                                + " process_bound=false default_route_unchanged=true");
            }

            @Override public void onLost(Network network) {
                events.write("mobile_ethernet_demand_lost",
                        "network_handle=" + network.getNetworkHandle()
                                + " demand_retained=true automatic_retry=true");
            }

            @Override public void onUnavailable() {
                events.write("mobile_ethernet_demand_unavailable",
                        "demand_retained=true automatic_retry=true");
            }
        };
        NetworkRequest request = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
                .build();
        try {
            manager.requestNetwork(request, ethernetDemandCallback);
            events.write("mobile_ethernet_demand_registered",
                    "transport=ethernet internet_capability=false "
                            + "process_bound=false default_route_unchanged=true");
            return true;
        } catch (RuntimeException failure) {
            events.write("mobile_ethernet_demand_registration_failed",
                    "stack={" + MobileThrowableDiagnostics.format(failure) + "}");
            ethernetDemandCallback = null;
            return false;
        }
    }

    private void unregisterEthernetNetworkDemand() {
        ConnectivityManager manager = connectivityManager;
        ConnectivityManager.NetworkCallback callback = ethernetDemandCallback;
        ethernetDemandCallback = null;
        if (manager == null || callback == null) return;
        try {
            manager.unregisterNetworkCallback(callback);
        } catch (IllegalArgumentException failure) {
            events.write("mobile_ethernet_demand_unregister_failed",
                    "stack={" + MobileThrowableDiagnostics.format(failure) + "}");
        }
    }

    private void unregisterNetworkObserver() {
        ConnectivityManager manager = connectivityManager;
        ConnectivityManager.NetworkCallback callback = networkCallback;
        networkCallback = null;
        if (manager == null || callback == null) return;
        try {
            manager.unregisterNetworkCallback(callback);
        } catch (IllegalArgumentException failure) {
            // Process teardown can race Android's own callback cleanup, but the
            // durable stack still distinguishes that race from a registration bug.
            events.write(
                    "mobile_ethernet_observer_unregister_failed",
                    "stack={" + MobileThrowableDiagnostics.format(failure) + "}");
        }
    }

    private void networkChanged(String transition, Network network, LinkProperties properties) {
        if (destroying) return;
        FormalPipelineOwnerReceipt eventOwner =
                captureFormalPipelineOwner();
        long networkHandle = network == null ? 0L : network.getNetworkHandle();
        if (!"lost".equals(transition) && networkHandle != 0L) {
            signalAuthorizationNetworkChanged(networkHandle);
        }
        boolean candidateReady = false;
        MobileTransportEndpoint evaluatedEndpoint = null;
        String evaluationDetail;
        try {
            EthernetNetworkDiagnostics.Evaluation evaluation =
                    EthernetNetworkDiagnostics.evaluate(
                            connectivityManager, network, properties);
            candidateReady = !"lost".equals(transition) && evaluation.accepted;
            evaluatedEndpoint = candidateReady ? evaluation.endpoint : null;
            evaluationDetail = evaluation.detail();
            if ("lost".equals(transition)) {
                evaluationDetail =
                        "accepted=false rejection_reason=network_lost evaluation={"
                                + evaluationDetail + "}";
            }
        } catch (RuntimeException failure) {
            evaluationDetail =
                    "accepted=false rejection_reason=network_evaluation_exception stack={"
                            + MobileThrowableDiagnostics.format(failure) + "}";
        }
        latestEthernetDiagnostics =
                "transition=" + transition + " " + evaluationDetail;
        publishEthernetDiagnostics();
        MobileTransportEndpoint selectedEndpoint;
        if (candidateReady && evaluatedEndpoint != null) {
            selectedEndpoint = transportCatalog.upsert(evaluatedEndpoint);
        } else {
            selectedEndpoint = transportCatalog.remove(networkHandle);
        }
        String source = "network_" + transition;
        MobileTransportEndpoint routeCandidate = evaluatedEndpoint;
        boolean formalRouteMutated = formalSessionRouteWasMutated(
                evaluatedEndpoint, selectedEndpoint);
        if (selectedEndpoint != null) {
            ethernetRecovery.onLinkReady(
                    selectedEndpoint.networkHandle, source, eventOwner);
        } else {
            ethernetRecovery.onLinkUnavailable(
                    networkHandle, source, eventOwner);
        }
        boolean selectedTransportReady = selectedEndpoint != null;
        controlRuntime.updateTransportEndpoint(selectedEndpoint);
        updateCat6ReadyAgent(selectedEndpoint, source);
        events.write("mobile_ethernet_changed", "transition=" + transition
                + " candidate_ready=" + candidateReady
                + " selected_transport_ready=" + selectedTransportReady
                + " network_handle=" + networkHandle
                + " selected_endpoint={"
                + (selectedEndpoint == null ? "none" : selectedEndpoint.detail()) + "}"
                + " diagnostics={" + latestEthernetDiagnostics + "}");
        if (formalRouteMutated) {
            events.write(
                    "mobile_transport_pinned_route_changed",
                    "network_handle=" + networkHandle
                            + " action=fresh_formal_session"
                            + " candidate={" + evaluatedEndpoint.detail() + "}");
            // A same-handle address/kind change is not a transient loss: the
            // signed v2 channel binding names the complete route. Close the
            // capability immediately instead of keeping the data plane alive
            // for the ordinary link-loss debounce window.
            stopFormalUsageIfCurrentOwner(
                    eventOwner,
                    () -> routeCandidate != null
                            && formalSessionEndpoint != null
                            && formalSessionEndpoint.networkHandle
                            == routeCandidate.networkHandle
                            && !formalSessionEndpoint.hasSameDataPlaneRoute(
                            routeCandidate),
                    "transport_route_changed_" + safeToken(source));
        }
        if (!selectedTransportReady) {
            detachAuthenticatedHost(
                    eventOwner,
                    "video_transport_detached_" + safeToken(source));
            return;
        }
    }

    private boolean formalSessionRouteWasMutated(
            MobileTransportEndpoint evaluatedEndpoint,
            MobileTransportEndpoint selectedEndpoint) {
        if (evaluatedEndpoint == null || selectedEndpoint != null) return false;
        synchronized (pipelineCommandLock) {
            return formalSessionEndpoint != null
                    && formalSessionEndpoint.networkHandle
                    == evaluatedEndpoint.networkHandle
                    && !formalSessionEndpoint.hasSameDataPlaneRoute(
                    evaluatedEndpoint);
        }
    }

    private void refreshEthernetDiagnosticsFromKernel(String source) {
        if (transportCatalog.selected() != null) return;
        String diagnosticState =
                "accepted=false rejection_reason=android_network_unavailable"
                        + " preferred=" + EthernetTransportContract.requiredLink()
                        + " " + EthernetNetworkDiagnostics.kernelInterfaceSnapshot(
                                EthernetTransportContract.INTERFACE_NAME)
                        + " product_impact=app_cannot_bind_transport_without_android_network";
        latestEthernetDiagnostics =
                "transition=" + source
                        + " " + diagnosticState;
                publishEthernetDiagnostics();
        MobileEventLogger logger = events;
        if (logger != null && ethernetDiagnosticsLogPolicy.shouldWrite(
                diagnosticState, TimeUnit.NANOSECONDS.toMillis(System.nanoTime()))) {
            logger.write("mobile_ethernet_kernel_snapshot", latestEthernetDiagnostics);
        }
    }

    private LinkProperties readLinkPropertiesForDiagnostics(
            Network network, String transition) {
        ConnectivityManager manager = connectivityManager;
        if (manager == null || network == null) return null;
        try {
            return manager.getLinkProperties(network);
        } catch (RuntimeException failure) {
            String detail =
                    "transition=" + transition
                            + " accepted=false rejection_reason="
                            + "link_properties_read_exception network_handle="
                            + network.getNetworkHandle() + " stack={"
                            + MobileThrowableDiagnostics.format(failure) + "}";
            latestEthernetDiagnostics = detail;
            publishEthernetDiagnostics();
            events.write("mobile_ethernet_link_properties_read_failed", detail);
            return null;
        }
    }

    private void queueEthernetOwnerCallback(
            String callback,
            Runnable action) {
        try {
            authorizationExecutor.execute(action);
        } catch (RuntimeException schedulingFailure) {
            events.write(
                    "mobile_ethernet_owner_callback_deferred",
                    "callback=" + safeToken(callback)
                            + " action=no_cross_generation_cleanup"
                            + " failure_type="
                            + schedulingFailure.getClass().getSimpleName());
        }
    }

    private MobileEthernetRecoveryCoordinator<FormalPipelineOwnerReceipt>
            createEthernetRecoveryCoordinator() {
        MobileEthernetRecoveryCoordinator.Scheduler scheduler = (task, delayMillis) -> {
            ScheduledFuture<?> scheduled = healthExecutor.schedule(
                    task, delayMillis, TimeUnit.MILLISECONDS);
            return () -> scheduled.cancel(false);
        };
        MobileEthernetRecoveryCoordinator.Listener
                <FormalPipelineOwnerReceipt> listener =
                new MobileEthernetRecoveryCoordinator.Listener
                        <FormalPipelineOwnerReceipt>() {
                    @Override
                    public void failClosed(
                            long networkHandle,
                            String source,
                            FormalPipelineOwnerReceipt owner) {
                        // This callback runs under the Ethernet monitor. It
                        // takes only the downstream pipeline lock for an
                        // immediate physical fail-close; formal lifecycle I/O
                        // remains queued below and takes attachment first.
                        synchronized (pipelineCommandLock) {
                            if (!formalPipelineOwnerIsCurrentLocked(owner)
                                    || formalSessionEndpoint == null
                                    || formalSessionEndpoint.networkHandle
                                    != networkHandle) {
                                return;
                            }
                            failClosedControlOutputForEthernetLoss(
                                    networkHandle, source);
                        }
                    }

                    @Override
                    public void debounceStarted(
                            long networkHandle,
                            String source,
                            long delayMillis,
                            FormalPipelineOwnerReceipt owner) {
                        queueEthernetOwnerCallback("debounce_started", () ->
                                events.write(
                                        "mobile_ethernet_debounce_started",
                                        "network_handle=" + networkHandle
                                                + " source=" + source
                                                + " delay_ms=" + delayMillis
                                                + " pipeline_kept_running=true"
                                                + " owner_captured="
                                                + (owner != null)));
                    }

                    @Override
                    public void debounceCancelled(
                            long lostNetworkHandle,
                            long readyNetworkHandle,
                            String source,
                            FormalPipelineOwnerReceipt owner) {
                        queueEthernetOwnerCallback("debounce_cancelled", () ->
                                events.write(
                                        "mobile_ethernet_debounce_cancelled",
                                        "lost_network_handle="
                                                + lostNetworkHandle
                                                + " ready_network_handle="
                                                + readyNetworkHandle
                                                + " source=" + source
                                                + " owner_captured="
                                                + (owner != null)));
                    }

                    @Override
                    public void debounceExpired(
                            long networkHandle,
                            String source,
                            FormalPipelineOwnerReceipt owner) {
                        queueEthernetOwnerCallback("debounce_expired", () -> {
                            events.write(
                                    "mobile_ethernet_debounce_expired",
                                    "network_handle=" + networkHandle
                                            + " source=" + source);
                            stopFormalUsageIfCurrentOwner(
                                    owner,
                                    () -> formalSessionEndpoint != null
                                            && formalSessionEndpoint
                                            .networkHandle == networkHandle,
                                    "transport_lost_" + safeToken(source));
                        });
                    }

                    @Override
                    public void rebindRequired(
                            long previousNetworkHandle,
                            long replacementNetworkHandle,
                            String source,
                            FormalPipelineOwnerReceipt owner) {
                        queueEthernetOwnerCallback("rebind_required", () -> {
                            events.write(
                                    "mobile_transport_rebind_requested",
                                    "previous_network_handle="
                                            + previousNetworkHandle
                                            + " replacement_network_handle="
                                            + replacementNetworkHandle
                                            + " source=" + safeToken(source)
                                            + " action=fresh_formal_session");
                            stopFormalUsageIfCurrentOwner(
                                    owner,
                                    () -> formalSessionEndpoint != null
                                            && formalSessionEndpoint
                                            .networkHandle
                                            == previousNetworkHandle,
                                    "transport_replaced_"
                                            + safeToken(source));
                        });
                    }
                };
        return new MobileEthernetRecoveryCoordinator<>(scheduler, listener);
    }

    private void failClosedControlOutputForEthernetLoss(long networkHandle, String source) {
        controlRuntime.failClosed("ethernet_unavailable_" + source);
        boolean nativeGateClosed = true;
        try {
            QnnHtpBridge.failClosedNativeMakcuOutput();
        } catch (RuntimeException | LinkageError failure) {
            nativeGateClosed = false;
            events.write("mobile_control_output_fail_closed_failure",
                    "reason=ethernet_unavailable network_handle=" + networkHandle
                            + " source=" + source
                            + " stack={" + MobileThrowableDiagnostics.format(failure) + "}");
        }
        events.write("mobile_control_output_fail_closed",
                "reason=ethernet_unavailable network_handle=" + networkHandle
                        + " source=" + source
                        + " native_gate_closed=" + nativeGateClosed
                        + " output_enabled=" + (nativeGateClosed ? "false" : "unknown")
                        + " automatic_retry=true");
    }

    private boolean nativeVideoReceiverRunningSafely() {
        try {
            return QnnHtpBridge.isNativeVideoReceiverRunning();
        } catch (RuntimeException | LinkageError failure) {
            events.write("mobile_video_receiver_state_read_failed",
                    "stack={" + MobileThrowableDiagnostics.format(failure) + "}");
            return false;
        }
    }

    private boolean isWirelessForegroundDisplayReady(
            MobileTransportEndpoint endpoint) {
        if (endpoint == null || endpoint.isCat6()) return true;
        return isDisplayInteractive()
                && activityForeground.get();
    }

    private boolean isDisplayInteractive() {
        PowerManager power = getSystemService(PowerManager.class);
        return power != null && power.isInteractive();
    }

    private boolean stopWirelessStartWhenDisplayUnavailable(
            DualMachineAuthorizationRuntime runtime,
            String source) {
        if (runtime == null || automaticFormalStopQueued.get()
                || runtime.snapshot().state
                != DualMachineFormalUsageStateMachine.State.STARTING) {
            return false;
        }
        MobileTransportEndpoint endpoint = formalSessionEndpoint;
        if (endpoint == null) endpoint = transportCatalog.selected();
        if (endpoint == null || endpoint.isCat6()
                || isWirelessForegroundDisplayReady(endpoint)) {
            return false;
        }
        reportWirelessDisplayWait(source);
        requestFormalUsageStop(
                "wireless_start_display_unavailable_" + safeToken(source));
        return true;
    }

    private void requireWirelessForegroundDisplay(
            MobileTransportEndpoint endpoint) throws IOException {
        if (isWirelessForegroundDisplayReady(endpoint)) {
            wirelessDisplayWaitReported.set(false);
            return;
        }
        reportWirelessDisplayWait("before_potential_debit");
        throw new IOException(
                "wireless runtime requires a foreground interactive display");
    }

    private void reportWirelessDisplayWait(String source) {
        if (!wirelessDisplayWaitReported.compareAndSet(false, true)) return;
        DualMachineAuthorizationRuntime runtime = authorizationRuntime;
        DualMachineFormalUsageStateMachine.Snapshot snapshot =
                runtime == null ? null : runtime.snapshot();
        boolean displayInteractive = isDisplayInteractive();
        boolean billingStarted = snapshot != null && snapshot.billingStarted;
        boolean statePermitsDataPlane =
                snapshot != null && snapshot.permitsDataPlane;
        boolean localDataPlaneOpen =
                formalDataPlanePermitOpen.get() && pipelineStarted;
        events.write(
                "dual_machine_wireless_display_required",
                "source=" + safeToken(source)
                        + " display_interactive=" + displayInteractive
                        + " activity_foreground="
                        + activityForeground.get()
                        + " billing_started=" + billingStarted
                        + " state_permits_data_plane="
                        + statePermitsDataPlane
                        + " data_plane_open=" + localDataPlaneOpen
                        + " action=wait_or_stop_fail_closed");
    }

    private void updateActivityForeground(boolean foreground) {
        boolean changed = activityForeground.getAndSet(foreground)
                != foreground;
        if (foreground) {
            wirelessDisplayWaitReported.set(false);
        }
        if (changed && events != null) {
            events.write(
                    "mobile_activity_foreground_state",
                    "foreground=" + foreground
                            + " wireless_billing_requires_foreground=true");
        }
        if (foreground || destroying) return;
        try {
            authorizationExecutor.execute(() -> {
                DualMachineAuthorizationRuntime runtime =
                        authorizationRuntime;
                if (runtime == null || destroying
                        || activityForeground.get()) return;
                try {
                    DualMachineAuthorizationRuntime.CurrentGenerationReceipt
                            receipt = runtime
                            .captureCurrentGenerationReceipt();
                    commitFormalGeneration(
                            runtime,
                            receipt,
                            () -> {
                                if (destroying || activityForeground.get()) {
                                    return;
                                }
                                if (stopWirelessStartWhenDisplayUnavailable(
                                        runtime,
                                        "activity_paused_starting")) {
                                    return;
                                }
                                MobileTransportEndpoint endpoint =
                                        formalSessionEndpoint;
                                if (endpoint == null) {
                                    endpoint = transportCatalog.selected();
                                }
                                if (endpoint == null || endpoint.isCat6()
                                        || !runtime.snapshot()
                                        .canFormalStop()) {
                                    return;
                                }
                                reportWirelessDisplayWait("activity_paused");
                                requestFormalUsageStop(
                                        "wireless_activity_not_foreground");
                            });
                } catch (DualMachineFormalUsageCoordinator
                                 .AdmissionSupersededException superseded) {
                    // A paused callback from A must not inspect or stop B.
                } catch (IOException | GeneralSecurityException failure) {
                    events.write(
                            "dual_machine_activity_pause_guard_failed",
                            "failure_type="
                                    + failure.getClass().getSimpleName()
                                    + " fail_closed_by_runtime=true");
                }
            });
        } catch (RuntimeException schedulingFailure) {
            events.write(
                    "dual_machine_activity_pause_guard_deferred",
                    "failure_type="
                            + schedulingFailure.getClass().getSimpleName());
        }
    }

    private boolean updateCat6ReadyAgent(MobileTransportEndpoint endpoint, String source) {
        long networkHandle = endpoint == null ? 0L : endpoint.networkHandle;
        try {
            boolean running = cat6ReadyLifecycle.update(endpoint);
            observeCat6ReadyAgentState(endpoint, source, running);
            return running;
        } catch (RuntimeException | LinkageError failure) {
            latestCat6ReadyDiagnostics =
                    "source=" + source
                            + " running=false network_handle=" + networkHandle
                            + " stack={" + MobileThrowableDiagnostics.format(failure) + "}";
            events.write(
                    "mobile_cat6_ready_agent_failure",
                    latestCat6ReadyDiagnostics
                            + " diagnostics={" + latestEthernetDiagnostics + "}");
            return false;
        }
    }

    private void observeCat6ReadyAgentState(
            MobileTransportEndpoint endpoint,
            String source,
            boolean running) {
        long networkHandle = endpoint == null ? 0L : endpoint.networkHandle;
        String endpointDetail = endpoint == null ? "none" : endpoint.detail();
        String nativeReport = readCat6ReadyAgentReport();
        latestCat6ReadyDiagnostics =
                "source=" + source
                        + " running=" + running
                        + " network_handle=" + networkHandle
                        + " network_handle_present=" + (networkHandle > 0L)
                        + " endpoint={" + endpointDetail + "}"
                        + " native={" + nativeReport + "}";
        long monotonicMillis =
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime());
        if (!cat6ReadyAgentLogPolicy.shouldWrite(
                running, endpointDetail, nativeReport, monotonicMillis)) return;
        events.write(
                "mobile_cat6_ready_agent_state",
                latestCat6ReadyDiagnostics
                        + " log_policy=state_change_or_heartbeat"
                        + " heartbeat_ms="
                        + Cat6ReadyAgentLogPolicy.STABLE_HEARTBEAT_MILLIS
                        + " diagnostics={" + latestEthernetDiagnostics + "}");
    }

    private String readCat6ReadyAgentReport() {
        try {
            String report = cat6ReadyLifecycle.report();
            if (cat6ReadyAgentReportFailureReported.compareAndSet(
                    true, false)) {
                events.write(
                        "mobile_cat6_ready_agent_report_recovered",
                        "native_report_available=true");
            }
            return report;
        } catch (RuntimeException | LinkageError failure) {
            String stack = MobileThrowableDiagnostics.format(failure);
            if (cat6ReadyAgentReportFailureReported.compareAndSet(
                    false, true)) {
                events.write(
                        "mobile_cat6_ready_agent_report_failure",
                        "stack={" + stack + "} repeated_failures_suppressed=true");
            }
            return "report_unavailable stack={" + stack + "}";
        }
    }

    private Network requiredEthernetNetwork() {
        MobileTransportEndpoint endpoint = requiredTransportEndpoint();
        return endpoint == null ? null : endpoint.network;
    }

    private void selectPreferredTransportForFormalStart() {
        MobileTransportEndpoint selected =
                transportCatalog.releaseFormalSessionPin();
        if (selected == null) return;
        ethernetRecovery.adoptLinkWhileDataPlaneClosed(
                selected.networkHandle,
                "formal_start_transport_selection");
        controlRuntime.updateTransportEndpoint(selected);
        updateCat6ReadyAgent(
                selected, "formal_start_transport_selection");
        events.write(
                "mobile_transport_formal_start_selected",
                selected.detail()
                        + " cat6_preferred=true data_plane_open=false"
                        + " discovered_host_preserved=true");
    }

    private static void requireFormalStartNotCancelled(
            BooleanSupplier cancellationRequested)
            throws HostVideoPresenceProbe.HostVideoProbeCancelledException {
        if (cancellationRequested == null) {
            throw new IllegalArgumentException(
                    "formal start cancellation signal is required");
        }
        if (cancellationRequested.getAsBoolean()) {
            throw new HostVideoPresenceProbe.HostVideoProbeCancelledException(
                    "host_video_preflight_cancelled", null);
        }
    }

    private void releaseFormalTransportPinAfterSession(String source) {
        try {
            MobileTransportEndpoint selected =
                    transportCatalog.releaseFormalSessionPin();
            if (controlRuntime != null) {
                controlRuntime.updateTransportEndpoint(selected);
            }
            if (cat6ReadyLifecycle != null) {
                updateCat6ReadyAgent(selected, source);
            }
            events.write(
                    "mobile_transport_formal_session_released",
                    "source=" + safeToken(source)
                            + " selected_endpoint={"
                            + (selected == null ? "none" : selected.detail())
                            + "} cat6_preferred=true data_plane_open=false");
        } catch (RuntimeException | LinkageError failure) {
            events.write(
                    "mobile_transport_formal_session_release_failed",
                    "source=" + safeToken(source)
                            + " failure_type="
                            + failure.getClass().getSimpleName()
                            + " stack={"
                            + MobileThrowableDiagnostics.format(failure)
                            + "}");
        }
    }

    private MobileTransportEndpoint requiredTransportEndpoint() {
        MobileTransportEndpoint endpoint = transportCatalog.selected();
        if (endpoint == null || endpoint.isCat6() || endpoint.hostDiscovered) {
            return endpoint;
        }
        String requesterIpv4;
        try {
            requesterIpv4 = QnnHtpBridge.getNativeCat6ReadyAgentRequesterIpv4();
        } catch (RuntimeException | LinkageError failure) {
            events.write(
                    "mobile_wireless_lan_host_discovery_failure",
                    "stage=native_requester_read stack={"
                            + MobileThrowableDiagnostics.format(failure) + "}");
            return null;
        }
        if (!MobileTransportEndpoint.isUsableUnicastIpv4(requesterIpv4)) return null;
        try {
            MobileTransportEndpoint discovered = endpoint.withDiscoveredHost(requesterIpv4);
            MobileTransportEndpoint selected = transportCatalog.upsert(discovered);
            if (selected == null || selected.networkHandle != discovered.networkHandle) {
                return selected != null && selected.isReadyForDataPlane() ? selected : null;
            }
            controlRuntime.updateTransportEndpoint(discovered);
            updateCat6ReadyAgent(discovered, "wireless_host_discovered");
            events.write(
                    "mobile_wireless_lan_host_discovered",
                    discovered.detail());
            lastWirelessDiscoveryTimeoutNetworkHandle.set(Long.MIN_VALUE);
            return discovered;
        } catch (IllegalArgumentException failure) {
            events.write(
                    "mobile_wireless_lan_host_discovery_failure",
                    "stage=validate_requester requester_ipv4=" + requesterIpv4
                            + " stack={" + MobileThrowableDiagnostics.format(failure) + "}");
            return null;
        }
    }

    private MobileTransportEndpoint awaitRequiredTransportEndpoint(
            BooleanSupplier cancellationRequested)
            throws IOException {
        requireFormalStartNotCancelled(cancellationRequested);
        long deadline = SystemClock.elapsedRealtime()
                + WIRELESS_HOST_DISCOVERY_TIMEOUT_MILLIS;
        MobileTransportEndpoint endpoint;
        do {
            requireFormalStartNotCancelled(cancellationRequested);
            endpoint = requiredTransportEndpoint();
            if (endpoint != null && endpoint.isReadyForDataPlane()) return endpoint;
            SystemClock.sleep(50L);
        } while (!destroying && SystemClock.elapsedRealtime() < deadline);
        requireFormalStartNotCancelled(cancellationRequested);
        long networkHandle = endpoint == null ? 0L : endpoint.networkHandle;
        if (lastWirelessDiscoveryTimeoutNetworkHandle.getAndSet(networkHandle)
                != networkHandle) {
            events.write(
                    "mobile_wireless_lan_host_discovery_timeout",
                    "timeout_ms=" + WIRELESS_HOST_DISCOVERY_TIMEOUT_MILLIS
                            + " selected_endpoint={"
                            + (endpoint == null ? "none" : endpoint.detail())
                            + "} ready_agent={"
                            + latestCat6ReadyDiagnostics + "}");
        }
        throw new IOException(
                "required transport unavailable after automatic CAT6/Wi-Fi discovery");
    }

    private void writeRuntimeHealth() {
        FormalPipelineOwnerReceipt owner = null;
        try {
            ensureReceiverLivenessProbeScheduled();
            owner = captureFormalPipelineOwner();
            writeRuntimeHealthUnchecked(owner);
            healthFailureReported.set(false);
        } catch (RuntimeException | LinkageError failure) {
            if (healthFailureReported.compareAndSet(false, true)) {
                if (!recordPeriodicRuntimeFailure(
                        owner,
                        "mobile_runtime_health_failure",
                        failure)) {
                    healthFailureReported.set(false);
                }
            }
        }
    }

    private void writeRuntimeHealthUnchecked(
            FormalPipelineOwnerReceipt owner) {
        MobileTransportEndpoint selectedEndpoint = requiredTransportEndpoint();
        recoverCat6ReadyAgentIfStopped(selectedEndpoint);
        String videoReport = QnnHtpBridge.getNativeVideoReceiverReport();
        String decoderReport = QnnHtpBridge.getNativeH264DecoderReport();
        String qnnReport = QnnHtpBridge.getNativeQnnRealtimeReport();
        String makcuReport = controlRuntime.makcuReport();
        MobileRuntimeSnapshot healthSnapshot = MobileRuntimeSnapshot.from(
                videoReport, decoderReport, qnnReport, makcuReport);
        String inferenceReport = controlRuntime.inferenceAuditDetail();
        long healthMonotonicMillis =
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime());
        writeExternalHealthSnapshot(
                runtimeStatus.phase.name().toLowerCase(Locale.ROOT),
                decoderReport, inferenceReport,
                healthSnapshot, healthMonotonicMillis);
        commitFormalPipelineOwnerIfCurrent(
                owner,
                () -> {
                    if (pipelineStarted && healthSnapshot.videoLinkLive) {
                        automaticUsageGuard.recordHostFrame(
                                healthSnapshot.lastLogicalFrameSequence);
                    }
                });
        String phase = runtimeStatus.phase.name().toLowerCase(Locale.ROOT);
        if (healthLogPolicy.shouldWrite(
                phase, videoReport, decoderReport, qnnReport,
                healthMonotonicMillis)) {
            events.write("mobile_control_health",
                    MobileControlHealthSummary.format(decoderReport));
            events.write("mobile_runtime_health",
                    "phase=" + phase
                            + " inference={" + inferenceReport + "}"
                            + " video={" + videoReport + "}"
                            + " decoder={" + decoderReport + "}"
                            + " qnn={" + qnnReport + "}"
                            + " makcu={" + makcuReport + "}");
        }
        if (pipelineDesired && !pipelineStarted
                && (selectedEndpoint == null || selectedEndpoint.network == null)) {
            stopFormalUsageIfCurrentOwner(
                    owner,
                    () -> {
                        MobileTransportEndpoint current =
                                transportCatalog.selected();
                        return pipelineDesired && !pipelineStarted
                                && (current == null
                                || current.network == null);
                    },
                    () -> refreshEthernetDiagnosticsFromKernel(
                            "health_probe"),
                    "transport_unavailable_health_probe");
            return;
        }
        commitFormalPipelineOwnerIfCurrent(
                owner, this::reconcileControlOutput);
        if (pipelineDesired && pipelineStarted
                && !nativeVideoReceiverRunningSafely()) {
            stopFormalUsageIfCurrentOwner(
                    owner,
                    () -> pipelineDesired && pipelineStarted
                            && !nativeVideoReceiverRunningSafely(),
                    "video_receiver_stopped_health_probe");
        }
    }

    private void recoverCat6ReadyAgentIfStopped(
            MobileTransportEndpoint selectedEndpoint) {
        if (destroying
                || selectedEndpoint == null
                || cat6ReadyLifecycle == null
                || cat6ReadyLifecycle.isRunning()) {
            return;
        }
        updateCat6ReadyAgent(
                selectedEndpoint, "health_ready_agent_recovery");
    }

    private void writeExternalHealthSnapshot(
            String phase, String decoderReport, String inferenceReport,
            MobileRuntimeSnapshot snapshot, long monotonicMillis) {
        String metrics = externalHealthMetricsSampler.sampleIfDue(
                snapshot, monotonicMillis);
        if (!externalHealthSnapshotPolicy.shouldWrite(
                phase, inferenceReport, snapshot, metrics != null, monotonicMillis)) return;
        if (metrics == null) {
            metrics = externalHealthMetricsSampler.formatCurrent(snapshot);
        }
        String payload = MobileExternalHealthSnapshotFormatter.format(
                System.currentTimeMillis(), monotonicMillis, phase,
                inferenceReport, metrics,
                MobileControlHealthSummary.format(decoderReport));
        if (externalHealthSnapshotWriter != null
                && externalHealthSnapshotWriter.overwrite(payload)) {
            externalHealthSnapshotPolicy.recordSuccessfulWrite(
                    phase, inferenceReport, snapshot, monotonicMillis);
            externalHealthSnapshotFailureReported.set(false);
            return;
        }
        if (externalHealthSnapshotFailureReported.compareAndSet(false, true)) {
            events.write(
                    "mobile_external_health_snapshot_failure",
                    "external_files_unavailable_or_write_failed");
        }
    }

    private void checkReceiverLiveness() {
        FormalPipelineOwnerReceipt owner = null;
        try {
            owner = captureFormalPipelineOwner();
            checkReceiverLivenessUnchecked(owner);
            receiverLivenessFailureReported.set(false);
        } catch (RuntimeException | LinkageError failure) {
            if (receiverLivenessFailureReported.compareAndSet(false, true)) {
                if (!recordPeriodicRuntimeFailure(
                        owner,
                        "mobile_receiver_liveness_failure",
                        failure)) {
                    receiverLivenessFailureReported.set(false);
                }
            }
        }
    }

    private void checkReceiverLivenessUnchecked(
            FormalPipelineOwnerReceipt owner) {
        if (destroying || !pipelineDesired || !PROCESS_RETRY_GATE.canAttempt()) return;
        if (pipelineDesired && requiredEthernetNetwork() == null) {
            long activeNetworkHandle =
                    ethernetRecovery.activeNetworkHandle();
            AtomicBoolean shouldRegisterLoss = new AtomicBoolean();
            commitFormalPipelineOwnerIfCurrent(
                    owner,
                    () -> {
                        if (!pipelineDesired
                                || requiredEthernetNetwork() != null) {
                            return;
                        }
                        refreshEthernetDiagnosticsFromKernel(
                                "receiver_100ms_probe");
                        controlRuntime.failClosed(
                                "required_ethernet_unavailable");
                        if (pipelineStarted
                                || pipelineNetworkHandle != 0L) {
                            shouldRegisterLoss.set(true);
                        }
                    });
            if (shouldRegisterLoss.get()) {
                ethernetRecovery.onLinkUnavailable(
                        activeNetworkHandle,
                        "receiver_100ms_probe",
                        owner);
            }
            return;
        }
        commitFormalPipelineOwnerIfCurrent(
                owner, this::reconcileControlOutput);
        if (pipelineStarted && !nativeVideoReceiverRunningSafely()) {
            stopFormalUsageIfCurrentOwner(
                    owner,
                    () -> pipelineStarted
                            && !nativeVideoReceiverRunningSafely(),
                    "video_receiver_stopped_liveness_probe");
        }
    }

    private void runReceiverLivenessProbe() {
        synchronized (receiverLivenessScheduleLock) {
            receiverLivenessFuture = null;
        }
        try {
            checkReceiverLiveness();
        } finally {
            scheduleReceiverLivenessProbe(receiverLivenessDelayMillis(), false);
        }
    }

    private long receiverLivenessDelayMillis() {
        if (destroying || !pipelineDesired || !PROCESS_RETRY_GATE.canAttempt()) {
            return -1L;
        }
        return pipelineStarted || pipelineNetworkHandle != 0L
                ? RECEIVER_ACTIVE_LIVENESS_PROBE_MILLIS
                : RECEIVER_IDLE_LIVENESS_PROBE_MILLIS;
    }

    private void ensureReceiverLivenessProbeScheduled() {
        scheduleReceiverLivenessProbe(receiverLivenessDelayMillis(), false);
    }

    private void scheduleReceiverLivenessProbe(long delayMillis, boolean replaceExisting) {
        if (delayMillis < 0L || destroying || healthExecutor.isShutdown()) return;
        synchronized (receiverLivenessScheduleLock) {
            if (destroying || healthExecutor.isShutdown()) return;
            if (receiverLivenessFuture != null && !receiverLivenessFuture.isDone()) {
                if (!replaceExisting) return;
                receiverLivenessFuture.cancel(false);
            }
            try {
                receiverLivenessFuture = healthExecutor.schedule(
                        this::runReceiverLivenessProbe,
                        Math.max(0L, delayMillis),
                        TimeUnit.MILLISECONDS);
            } catch (RuntimeException schedulingFailure) {
                receiverLivenessFuture = null;
                recordReceiverLivenessScheduleFailure(delayMillis, schedulingFailure);
            }
        }
    }

    private void recordReceiverLivenessScheduleFailure(
            long delayMillis, RuntimeException schedulingFailure) {
        Log.e(LOG_TAG, "Receiver liveness scheduling failed", schedulingFailure);
        try {
            if (events != null) {
                events.write("mobile_receiver_liveness_schedule_failed",
                        "delay_ms=" + delayMillis
                                + " automatic_retry=true periodic_health_rearm=true"
                                + " stack={"
                                + MobileThrowableDiagnostics.format(schedulingFailure) + "}");
            }
        } catch (RuntimeException | LinkageError loggingFailure) {
            Log.e(LOG_TAG,
                    "Cannot record receiver liveness scheduling failure",
                    loggingFailure);
        }
    }

    private void cancelReceiverLivenessProbe() {
        synchronized (receiverLivenessScheduleLock) {
            ScheduledFuture<?> future = receiverLivenessFuture;
            receiverLivenessFuture = null;
            if (future != null) future.cancel(false);
        }
    }

    private boolean recordPeriodicRuntimeFailure(
            FormalPipelineOwnerReceipt owner,
            String event,
            Throwable failure) {
        String detail = "ethernet={" + latestEthernetDiagnostics + "} stack={"
                + MobileThrowableDiagnostics.format(failure) + "}";
        events.write(event, detail);
        boolean committed = commitFormalPipelineOwnerIfCurrent(
                owner,
                () -> {
                    controlRuntime.failClosed(event);
                    if (runtimeStatus.phase != MobileRuntimePhase.FAILED
                            || !runtimeStatus.detail.startsWith(event)) {
                        updateStatus(MobileRuntimePhase.FAILED, event + " " + detail);
                        updateNotification(
                                R.string.runtime_notification_failed);
                    }
                });
        if (!committed) {
            events.write(
                    event,
                    "action=no_cross_generation_cleanup superseded=true");
        }
        return committed;
    }

    private void reconcileControlOutput() {
        if (controlRuntime == null || destroying) return;
        String videoReport = QnnHtpBridge.getNativeVideoReceiverReport();
        String decoderReport = QnnHtpBridge.getNativeH264DecoderReport();
        String qnnReport = QnnHtpBridge.getNativeQnnRealtimeReport();
        MobileRuntimeSnapshot snapshot = MobileRuntimeSnapshot.from(
                videoReport, decoderReport, qnnReport, controlRuntime.makcuReport());
        boolean runtimeHealthy = formalDataPlanePermitOpen.get()
                && pipelineDesired
                && pipelineStarted
                && runtimeStatus.phase == MobileRuntimePhase.RUNNING
                && requiredEthernetNetwork() != null
                && snapshot.videoLinkLive
                && snapshot.decoderReady
                && snapshot.qnnReady
                && snapshot.qnnExecutionLive;
        controlRuntime.reconcile(
                runtimeHealthy,
                snapshot.nativeControlOutputRequestedKnown,
                snapshot.nativeControlOutputRequested,
                snapshot.nativeControlOutputEffective,
                snapshot.nativeControlOutputRecoverySuspended);
    }

    private void beginServiceDestroy() {
        synchronized (pipelineCommandLock) {
            pipelineSessionGeneration.incrementAndGet();
            destroying = true;
        }
        synchronized (authorizationLifecycleLock) {
            authorizationInitializationGeneration++;
        }
        pairingRuntime.closeSessions();
    }

    private void closeControlAndAuthorizationResources(
            MobileServiceDestroyCleanup cleanup) {
        cleanup.run(
                MobileServiceDestroyCleanup.Step.CONTROL_RUNTIME_CLOSE,
                () -> {
                    if (controlRuntime != null) {
                        controlRuntime.closeForServiceStop("service_destroyed");
                    }
        });
        authorizationObserver = null;
        pairingRuntime.clearObserver();
        cleanup.run(
                MobileServiceDestroyCleanup.Step.FORMAL_USAGE_STOP,
                () -> requestFormalUsageStop("service_destroyed"));
        cleanup.run(
                MobileServiceDestroyCleanup.Step
                        .AUTHORIZATION_STATUS_RETRY_CANCEL,
                this::cancelAuthorizationStatusRetry);
        cleanup.run(
                MobileServiceDestroyCleanup.Step
                        .RUNTIME_PERMIT_DEADLINES_CLOSE,
                runtimePermitDeadlines::close);
        cleanup.run(
                MobileServiceDestroyCleanup.Step
                        .AUTHORIZATION_HEALTH_EXECUTOR_SHUTDOWN,
                () -> shutdownExecutor(
                        authorizationHealthExecutor, "authorization_health"));
        cleanup.run(
                MobileServiceDestroyCleanup.Step
                        .AUTHORIZATION_EXECUTOR_SHUTDOWN,
                () -> shutdownExecutor(
                        authorizationExecutor, "authorization"));
        cleanup.run(
                MobileServiceDestroyCleanup.Step
                        .FIRST_PAIRING_EXECUTOR_SHUTDOWN,
                () -> shutdownExecutor(
                        pairingRuntime.executor(), "first_pairing"));
        cleanup.run(
                MobileServiceDestroyCleanup.Step
                        .START_CANCELLATION_EXECUTOR_SHUTDOWN,
                () -> shutdownExecutor(
                        startCancellationExecutor, "start_cancellation"));
        cleanup.run(
                MobileServiceDestroyCleanup.Step.AUTHORIZATION_RUNTIME_CLOSE,
                this::closePublishedAuthorizationRuntime);
    }

    private void closeTransportResources(
            MobileServiceDestroyCleanup cleanup) {
        cleanup.run(
                MobileServiceDestroyCleanup.Step.ETHERNET_RECOVERY_DESTROY,
                () -> {
                    if (ethernetRecovery != null) ethernetRecovery.destroy();
                });
        cleanup.run(
                MobileServiceDestroyCleanup.Step.ETHERNET_DEMAND_UNREGISTER,
                this::unregisterEthernetNetworkDemand);
        cleanup.run(
                MobileServiceDestroyCleanup.Step
                        .AUTHORIZATION_NETWORK_OBSERVER_UNREGISTER,
                this::unregisterAuthorizationNetworkObserver);
        cleanup.run(
                MobileServiceDestroyCleanup.Step
                        .TRANSPORT_NETWORK_OBSERVER_UNREGISTER,
                this::unregisterNetworkObserver);
        cleanup.run(
                MobileServiceDestroyCleanup.Step.TRANSPORT_CATALOG_CLEAR,
                transportCatalog::clear);
        cleanup.run(
                MobileServiceDestroyCleanup.Step.RECEIVER_LIVENESS_CANCEL,
                this::cancelReceiverLivenessProbe);
        cleanup.run(
                MobileServiceDestroyCleanup.Step.HEALTH_EXECUTOR_SHUTDOWN,
                () -> shutdownExecutor(healthExecutor, "health"));
    }

    private void closePipelineResources(
            MobileServiceDestroyCleanup cleanup) {
        cleanup.run(
                MobileServiceDestroyCleanup.Step.PIPELINE_STOP,
                this::stopPipelineBeforeDestroy);
        cleanup.run(
                MobileServiceDestroyCleanup.Step.READY_AGENT_STOP,
                () -> {
                    if (cat6ReadyLifecycle != null) cat6ReadyLifecycle.stop();
                });
        cleanup.run(
                MobileServiceDestroyCleanup.Step.RUNTIME_LOCKS_RELEASE,
                this::releaseRuntimeLocks);
        cleanup.run(
                MobileServiceDestroyCleanup.Step.RUNTIME_EXECUTOR_SHUTDOWN,
                () -> shutdownExecutor(runtimeExecutor, "runtime"));
        cleanup.run(
                MobileServiceDestroyCleanup.Step.STOPPED_STATUS_PUBLISH,
                () -> updateStatus(
                        MobileRuntimePhase.STOPPED, "runtime_service_stopped"));
    }

    private void publishDestroyOutcome(
            MobileServiceDestroyCleanup cleanup) {
        int cleanupFailureCount = cleanup.failureCount();
        cleanup.run(
                MobileServiceDestroyCleanup.Step.STOPPED_EVENT_WRITE,
                () -> {
                    if (events != null) {
                        events.write(
                                "mobile_runtime_service_stopped",
                                "resources_released="
                                        + (cleanupFailureCount == 0)
                                        + " cleanup_failures="
                                        + cleanupFailureCount);
                    }
                });
        reportDestroyCleanupFailures(cleanup);
    }

    private void reportDestroyCleanupFailures(
            MobileServiceDestroyCleanup cleanup) {
        for (int index = 0; index < cleanup.failureCount(); index++) {
            MobileServiceDestroyCleanup.Failure failure =
                    cleanup.failureAt(index);
            Log.e(
                    LOG_TAG,
                    "Service destroy cleanup failed step="
                            + failure.step.token,
                    failure.cause);
            if (events == null) continue;
            try {
                events.write(
                        "mobile_runtime_service_cleanup_failed",
                        "step=" + failure.step.token
                                + " cleanup_continued=true stack={"
                                + MobileThrowableDiagnostics.format(
                                failure.cause)
                                + "}");
            } catch (RuntimeException | LinkageError loggingFailure) {
                Log.e(
                        LOG_TAG,
                        "Cannot persist service destroy cleanup failure step="
                                + failure.step.token,
                        loggingFailure);
            }
        }
    }

    private void shutdownExecutor(ExecutorService executor, String name) {
        try {
            executor.shutdown();
            if (executor.awaitTermination(
                    EXECUTOR_SHUTDOWN_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)) {
                return;
            }
            List<Runnable> cancelled = executor.shutdownNow();
            if (events != null) {
                events.write("mobile_executor_forced_shutdown",
                        "name=" + name + " cancelled_tasks=" + cancelled.size());
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            List<Runnable> cancelled;
            try {
                cancelled = executor.shutdownNow();
            } catch (RuntimeException | LinkageError forcedShutdownFailure) {
                forcedShutdownFailure.addSuppressed(interrupted);
                throw forcedShutdownFailure;
            }
            if (events != null) {
                events.write("mobile_executor_shutdown_interrupted",
                        "name=" + name + " cancelled_tasks=" + cancelled.size()
                                + " stack={"
                                + MobileThrowableDiagnostics.format(interrupted)
                                + "}");
            } else {
                Log.e(LOG_TAG,
                        "Executor shutdown interrupted name=" + name,
                        interrupted);
            }
        } catch (RuntimeException | LinkageError shutdownFailure) {
            forceShutdownExecutorAfterFailure(
                    executor, name, shutdownFailure);
        }
    }

    private void forceShutdownExecutorAfterFailure(
            ExecutorService executor,
            String name,
            Throwable primaryFailure) {
        int cancelledTaskCount = -1;
        try {
            cancelledTaskCount = executor.shutdownNow().size();
        } catch (RuntimeException | LinkageError forcedShutdownFailure) {
            primaryFailure = MobileServiceDestroyCleanup.appendFailure(
                    primaryFailure, forcedShutdownFailure);
        }
        if (events != null) {
            try {
                events.write(
                        "mobile_executor_shutdown_failed",
                        "name=" + name
                                + " cancelled_tasks=" + cancelledTaskCount
                                + " force_shutdown_attempted=true stack={"
                                + MobileThrowableDiagnostics.format(
                                primaryFailure)
                                + "}");
            } catch (RuntimeException | LinkageError loggingFailure) {
                primaryFailure = MobileServiceDestroyCleanup.appendFailure(
                        primaryFailure, loggingFailure);
            }
        }
        MobileServiceDestroyCleanup.rethrowFailure(primaryFailure);
    }

    @SuppressLint({"Wakelock", "WakelockTimeout"})
    private synchronized void acquireRuntimeLocks(
            MobileTransportEndpoint endpoint) throws IOException {
        boolean changed = false;
        try {
            if (wakeLock == null || !wakeLock.isHeld()) {
                PowerManager power = getSystemService(PowerManager.class);
                if (power == null) {
                    throw new IOException("power manager is unavailable");
                }
                wakeLock = power.newWakeLock(
                        PowerManager.PARTIAL_WAKE_LOCK,
                        RUNTIME_WAKE_LOCK_TAG);
                wakeLock.setReferenceCounted(false);
                wakeLock.acquire();
                if (!wakeLock.isHeld()) {
                    throw new IOException("runtime wake lock was not acquired");
                }
                changed = true;
            }

            boolean requiresWifi = endpoint != null && !endpoint.isCat6();
            wifiLockRequired = requiresWifi;
            if (requiresWifi) {
                changed |= acquireWifiRuntimeLock();
            } else {
                changed |= releaseWifiRuntimeLock();
            }
        } catch (IOException failure) {
            suppressRuntimeLockReleaseFailure(failure);
            throw failure;
        } catch (RuntimeException failure) {
            IOException wrapped = new IOException(
                    "runtime lock acquisition failed", failure);
            suppressRuntimeLockReleaseFailure(wrapped);
            throw wrapped;
        }
        if (changed) {
            events.write("mobile_power_policy", describeRuntimeLocks());
        }
    }

    @SuppressWarnings("deprecation")
    private boolean acquireWifiRuntimeLock() throws IOException {
        if (wifiLock != null && wifiLock.isHeld()) return false;
        WifiManager wifi = getApplicationContext().getSystemService(
                WifiManager.class);
        if (wifi == null) {
            throw new IOException("Wi-Fi manager is unavailable");
        }
        wifiLock = wifi.createWifiLock(
                WifiManager.WIFI_MODE_FULL_HIGH_PERF,
                RUNTIME_WIFI_LOCK_TAG);
        wifiLock.setReferenceCounted(false);
        wifiLock.acquire();
        if (!wifiLock.isHeld()) {
            throw new IOException("runtime Wi-Fi lock was not acquired");
        }
        return true;
    }

    private boolean releaseWifiRuntimeLock() {
        boolean held = wifiLock != null && wifiLock.isHeld();
        if (held) wifiLock.release();
        wifiLock = null;
        return held;
    }

    private synchronized void refreshRuntimeLocks() {
        if (!shouldRetainAutomaticRuntimeLocks()
                && !(pipelineDesired && PROCESS_RETRY_GATE.canAttempt()
                && (pipelineStarted || runtimeStatus.phase == MobileRuntimePhase.STARTING))) {
            releaseRuntimeLocks();
            events.write(
                    "mobile_power_policy_refreshed",
                    describeRuntimeLocks());
            return;
        }
        try {
            acquireRuntimeLocks(transportCatalog.selected());
        } catch (IOException failure) {
            events.write(
                    "mobile_power_policy_refresh_failed",
                    "failure_type=" + failure.getClass().getSimpleName()
                            + " stack={"
                            + MobileThrowableDiagnostics.format(failure)
                            + "}");
        }
        events.write("mobile_power_policy_refreshed", describeRuntimeLocks());
    }

    private boolean shouldRetainAutomaticRuntimeLocks() {
        if (destroying || authorizationSecurityFatal
                || !PROCESS_RETRY_GATE.canAttempt()) {
            return false;
        }
        DualMachineAuthorizationRuntime runtime = authorizationRuntime;
        if (runtime == null) return false;
        DualMachineFormalUsageStateMachine.Snapshot snapshot =
                runtime.snapshot();
        return snapshot.entitlement != null
                && snapshot.state
                != DualMachineFormalUsageStateMachine.State.EXHAUSTED
                && snapshot.state
                != DualMachineFormalUsageStateMachine.State.REVOKED
                && snapshot.state
                != DualMachineFormalUsageStateMachine.State.UNACTIVATED;
    }

    private void reconcileRuntimeLocksAfterDataPlaneClose(String source) {
        final boolean retain;
        try {
            retain = shouldRetainAutomaticRuntimeLocks();
        } catch (RuntimeException failure) {
            releaseRuntimeLocks();
            events.write(
                    "mobile_power_policy_retention_failed",
                    "source=" + safeToken(source)
                            + " state_read_failed=true failure_type="
                            + failure.getClass().getSimpleName()
                            + " stack={"
                            + MobileThrowableDiagnostics.format(failure)
                            + "}");
            return;
        }
        if (!retain) {
            releaseRuntimeLocks();
            return;
        }
        try {
            acquireRuntimeLocks(transportCatalog.selected());
        } catch (IOException failure) {
            events.write(
                    "mobile_power_policy_retention_failed",
                    "source=" + safeToken(source)
                            + " failure_type="
                            + failure.getClass().getSimpleName()
                            + " stack={"
                            + MobileThrowableDiagnostics.format(failure)
                            + "}");
        }
    }

    private void handlePipelineStartFailure(
            MobilePipelineCoordinator.StartResult result, String source) {
        clearFormalSessionBinding();
        formalDataPlanePermitOpen.set(false);
        boolean terminal = result.disposition
                == MobilePipelineCoordinator.FailureDisposition.TERMINAL_INCOMPATIBLE;
        boolean reportSuppression = terminal
                && PROCESS_RETRY_GATE.latchTerminalFailure(
                        result.failureCode, result.message);
        reconcileRuntimeLocksAfterDataPlaneClose(
                "pipeline_start_failed_" + safeToken(source));
        pipelineStarted = false;
        pipelineNetworkHandle = 0L;
        controlRuntime.failClosed("pipeline_start_failed");
        if (reportSuppression) {
            events.write("mobile_pipeline_automatic_recovery_suppressed",
                    "failure_code=" + result.failureCode
                            + " source=" + source
                            + " retryable=false"
                            + " release=process_cold_start"
                            + " reason={" + result.message + "}");
        }
        updateStatus(MobileRuntimePhase.FAILED,
                result.message
                        + " failure_code=" + result.failureCode
                        + " retryable="
                        + !terminal
                        + " source=" + source,
                result.failureCode);
        updateNotification(R.string.runtime_notification_failed);
    }

    private synchronized String describeRuntimeLocks() {
        PowerManager power = getSystemService(PowerManager.class);
        boolean batteryExempt = power != null
                && power.isIgnoringBatteryOptimizations(getPackageName());
        return "battery_optimization_exempt=" + batteryExempt
                + " display_interactive="
                + (power != null && power.isInteractive())
                + " activity_foreground=" + activityForeground.get()
                + " wake_lock_held=" + (wakeLock != null && wakeLock.isHeld())
                + " wifi_lock_required=" + wifiLockRequired
                + " wifi_lock_held=" + (wifiLock != null && wifiLock.isHeld());
    }

    private synchronized void releaseRuntimeLocks() {
        WifiManager.WifiLock currentWifiLock = wifiLock;
        PowerManager.WakeLock currentWakeLock = wakeLock;
        wifiLock = null;
        wakeLock = null;
        wifiLockRequired = false;

        Throwable releaseFailure = null;
        if (currentWifiLock != null) {
            releaseFailure = MobileServiceDestroyCleanup.releaseIfHeld(
                    releaseFailure,
                    currentWifiLock::isHeld,
                    currentWifiLock::release);
        }
        if (currentWakeLock != null) {
            releaseFailure = MobileServiceDestroyCleanup.releaseIfHeld(
                    releaseFailure,
                    currentWakeLock::isHeld,
                    currentWakeLock::release);
        }
        MobileServiceDestroyCleanup.rethrowFailure(releaseFailure);
    }

    private void suppressRuntimeLockReleaseFailure(Throwable primaryFailure) {
        try {
            releaseRuntimeLocks();
        } catch (RuntimeException | LinkageError releaseFailure) {
            primaryFailure.addSuppressed(releaseFailure);
        }
    }

    private void clearLegacyPipelineRestoreFlag() {
        if (!getSharedPreferences(
                LEGACY_RUNTIME_PREFERENCES,
                MODE_PRIVATE).edit().remove(
                LEGACY_PIPELINE_DESIRED).commit()) {
            events.write("mobile_runtime_state_persist_failed",
                    "legacy_pipeline_restore_flag_cleared=false");
        }
    }

    private String defaultNativeDirectory() {
        return getApplicationInfo().nativeLibraryDir;
    }

    private void createNotificationChannel() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager == null) return;
        NotificationChannel channel = new NotificationChannel(NOTIFICATION_CHANNEL,
                getString(R.string.runtime_notification_channel), NotificationManager.IMPORTANCE_LOW);
        manager.createNotificationChannel(channel);
        pairingRuntime.createNotificationChannel();
    }

    private Notification notification(int textResource) {
        Notification pairing = pairingRuntime.pendingNotification();
        if (pairing != null) return pairing;
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent openIntent = PendingIntent.getActivity(this, 0, open,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this, NOTIFICATION_CHANNEL)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(textResource))
                .setContentIntent(openIntent)
                .setOngoing(true)
                .build();
    }

    private void updateNotification(int textResource) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager == null
                || !runtimePresentationUpdatePolicy.shouldPublishNotification(
                textResource)) return;
        manager.notify(NOTIFICATION_ID, notification(textResource));
    }

    private boolean updateStatus(MobileRuntimePhase phase, String detail) {
        return updateStatus(phase, detail, "none");
    }

    private boolean updateStatus(
            MobileRuntimePhase phase,
            String detail,
            String failureCode) {
        MobileRuntimeReadModel previous;
        MobileRuntimeReadModel current;
        synchronized (MobileRuntimeService.class) {
            previous = runtimeStatus;
            MobileRuntimeReadModel candidate = new MobileRuntimeReadModel(
                    phase,
                    detail,
                    failureCode,
                    previous.revision);
            MobileRuntimePresentationUpdatePolicy.StatusDecision decision =
                    MobileRuntimePresentationUpdatePolicy.evaluateStatus(
                            previous.revision,
                            previous.phase.name(),
                            previous.detail,
                            previous.failureCode,
                            candidate.phase.name(),
                            candidate.detail,
                            candidate.failureCode);
            if (!decision.shouldPublish) return false;
            current = new MobileRuntimeReadModel(
                    candidate.phase,
                    candidate.detail,
                    candidate.failureCode,
                    decision.revision);
            runtimeStatus = current;
            compositionRoot.publish(current);
        }
        MobileEventLogger logger = events;
        if (logger != null && previous.phase != current.phase) {
            logger.write(
                    "mobile_runtime_phase_changed",
                    "from=" + previous.phase.name().toLowerCase(Locale.ROOT)
                            + " to=" + current.phase.name().toLowerCase(Locale.ROOT)
                            + " revision=" + current.revision
                            + " detail={" + detail + "}"
                            + " ethernet={" + latestEthernetDiagnostics + "}");
        }
        return true;
    }

    private static String safeToken(String value) {
        if (value == null || value.trim().isEmpty()) return "unspecified";
        return value.trim().replace(' ', '_').replace('\r', '_').replace('\n', '_');
    }

    private static String failureDetail(String label, Throwable failure) {
        if (failure == null) return "";
        return " " + safeToken(label) + "_stack={"
                + MobileThrowableDiagnostics.format(failure) + "}";
    }
}
