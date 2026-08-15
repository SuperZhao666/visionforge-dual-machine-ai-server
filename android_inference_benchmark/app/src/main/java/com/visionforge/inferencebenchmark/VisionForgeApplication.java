package com.visionforge.inferencebenchmark;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Process;
import android.util.Log;

import java.util.concurrent.atomic.AtomicBoolean;

/** Owns process-level mobile diagnostics and durable uncaught-crash reporting. */
public final class VisionForgeApplication extends Application {
    private static final String TAG = "VisionForgeMobile";
    private static final String PROCESS_STARTED_EVENT = "mobile_process_started";
    private static final String PREVIOUS_ABNORMAL_EXIT_EVENT =
            "mobile_previous_abnormal_exit";

    private MobileEventLogger eventLogger;

    @Override
    public void onCreate() {
        super.onCreate();
        eventLogger = new MobileEventLogger(this);
        AbnormalExitMarker abnormalExitMarker = new AbnormalExitMarker(this);
        boolean crashHandlerInstalled = installCrashHandler(abnormalExitMarker);
        PreviousExitState previousExit = abnormalExitMarker.consumePrevious();

        eventLogger.write(
                PROCESS_STARTED_EVENT,
                "crash_handler_installed=" + crashHandlerInstalled
                        + " previous_abnormal_exit=" + previousExit.detected);
        reportPreviousExit(previousExit);
    }

    private boolean installCrashHandler(AbnormalExitMarker abnormalExitMarker) {
        Thread.UncaughtExceptionHandler previousHandler =
                Thread.getDefaultUncaughtExceptionHandler();
        if (previousHandler instanceof ProcessCrashHandler) {
            return true;
        }
        ProcessCrashHandler handler = new ProcessCrashHandler(
                eventLogger, abnormalExitMarker, previousHandler);
        try {
            Thread.setDefaultUncaughtExceptionHandler(handler);
            return true;
        } catch (SecurityException failure) {
            eventLogger.write(
                    "mobile_crash_handler_install_failed",
                    "stack={" + MobileThrowableDiagnostics.format(failure) + "}");
            return false;
        }
    }

    private void reportPreviousExit(PreviousExitState previousExit) {
        if (previousExit.failure != null) {
            eventLogger.write(
                    "mobile_previous_abnormal_exit_marker_read_failed",
                    "stack={" + MobileThrowableDiagnostics.format(
                            previousExit.failure) + "}");
            return;
        }
        if (!previousExit.detected) return;
        eventLogger.write(
                PREVIOUS_ABNORMAL_EXIT_EVENT,
                "source=uncaught_exception_marker marker_consumed="
                        + previousExit.consumed);
    }

    private static final class ProcessCrashHandler
            implements Thread.UncaughtExceptionHandler {
        private static final int UNCAUGHT_EXCEPTION_EXIT_STATUS = 10;

        private final MobileEventLogger events;
        private final AbnormalExitMarker abnormalExitMarker;
        private final Thread.UncaughtExceptionHandler previousHandler;
        private final AtomicBoolean handlingCrash = new AtomicBoolean();

        private ProcessCrashHandler(
                MobileEventLogger events,
                AbnormalExitMarker abnormalExitMarker,
                Thread.UncaughtExceptionHandler previousHandler) {
            this.events = events;
            this.abnormalExitMarker = abnormalExitMarker;
            this.previousHandler = previousHandler;
        }

        @Override
        public synchronized void uncaughtException(Thread thread, Throwable failure) {
            if (!handlingCrash.compareAndSet(false, true)) {
                terminateProcess();
                return;
            }
            try {
                recordCrashWithoutThrowing(thread, failure);
            } catch (Throwable ignoredCrashReportingFailure) {
                Log.e(TAG, "mobile uncaught exception reporting failed");
            }
            delegateOrTerminate(thread, failure);
        }

        private void recordCrashWithoutThrowing(Thread thread, Throwable failure) {
            MarkerWriteState markerState = abnormalExitMarker.markAbnormal();
            String markerFailure = markerState.failure == null
                    ? ""
                    : " marker_failure={" + safeStackTrace(markerState.failure) + "}";
            String threadName = thread == null ? "unknown" : thread.getName();
            try {
                events.write(
                        "mobile_process_uncaught_exception",
                        "crashed_thread=" + threadName
                                + " marker_persisted=" + markerState.persisted
                                + " failure_type=" + failureType(failure)
                                + markerFailure
                                + " stack={" + safeStackTrace(failure) + "}");
            } catch (Throwable ignoredLoggingFailure) {
                // The process is already failing. Never feed logger failure back
                // into this handler or include possibly sensitive exception text.
                Log.e(TAG, "mobile uncaught exception log write failed");
            }
        }

        private void delegateOrTerminate(Thread thread, Throwable failure) {
            if (previousHandler != null && previousHandler != this) {
                try {
                    previousHandler.uncaughtException(thread, failure);
                } catch (Throwable ignoredDelegationFailure) {
                    Log.e(TAG, "previous uncaught exception handler failed");
                }
            }
            terminateProcess();
        }

        private static String safeStackTrace(Throwable failure) {
            try {
                return MobileThrowableDiagnostics.format(failure);
            } catch (Throwable ignoredFormattingFailure) {
                return "stack_unavailable failure_type=" + failureType(failure);
            }
        }

        private static String failureType(Throwable failure) {
            return failure == null ? "unknown" : failure.getClass().getName();
        }

        private static void terminateProcess() {
            try {
                Process.killProcess(Process.myPid());
            } finally {
                System.exit(UNCAUGHT_EXCEPTION_EXIT_STATUS);
            }
        }
    }

    /** A crash marker is consumed once; ordinary Android process eviction never sets it. */
    private static final class AbnormalExitMarker {
        private static final String PREFERENCES_NAME =
                "visionforge_mobile_process_lifecycle_v1";
        private static final String PENDING_ABNORMAL_EXIT_KEY =
                "pending_uncaught_exception";

        private final Context context;

        private AbnormalExitMarker(Context context) {
            this.context = context.getApplicationContext();
        }

        private PreviousExitState consumePrevious() {
            try {
                SharedPreferences preferences = preferences();
                boolean detected = preferences.getBoolean(
                        PENDING_ABNORMAL_EXIT_KEY, false);
                boolean consumed = !detected || preferences.edit()
                        .remove(PENDING_ABNORMAL_EXIT_KEY)
                        .commit();
                return new PreviousExitState(detected, consumed, null);
            } catch (RuntimeException failure) {
                return new PreviousExitState(false, false, failure);
            }
        }

        private MarkerWriteState markAbnormal() {
            try {
                boolean persisted = preferences().edit()
                        .putBoolean(PENDING_ABNORMAL_EXIT_KEY, true)
                        .commit();
                return new MarkerWriteState(persisted, null);
            } catch (Throwable failure) {
                // This executes inside the final uncaught-exception path.
                return new MarkerWriteState(false, failure);
            }
        }

        private SharedPreferences preferences() {
            return context.getSharedPreferences(
                    PREFERENCES_NAME, Context.MODE_PRIVATE);
        }
    }

    private static final class PreviousExitState {
        private final boolean detected;
        private final boolean consumed;
        private final RuntimeException failure;

        private PreviousExitState(
                boolean detected,
                boolean consumed,
                RuntimeException failure) {
            this.detected = detected;
            this.consumed = consumed;
            this.failure = failure;
        }
    }

    private static final class MarkerWriteState {
        private final boolean persisted;
        private final Throwable failure;

        private MarkerWriteState(boolean persisted, Throwable failure) {
            this.persisted = persisted;
            this.failure = failure;
        }
    }
}
