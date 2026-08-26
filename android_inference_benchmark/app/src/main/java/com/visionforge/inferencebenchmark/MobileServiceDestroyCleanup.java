package com.visionforge.inferencebenchmark;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;

/** Runs service-destruction steps independently while retaining exact failures. */
final class MobileServiceDestroyCleanup {
    enum Step {
        CONTROL_RUNTIME_CLOSE("control_runtime_close"),
        FORMAL_USAGE_STOP("formal_usage_stop"),
        AUTHORIZATION_STATUS_RETRY_CANCEL("authorization_status_retry_cancel"),
        RUNTIME_PERMIT_DEADLINES_CLOSE("runtime_permit_deadlines_close"),
        AUTHORIZATION_HEALTH_EXECUTOR_SHUTDOWN(
                "authorization_health_executor_shutdown"),
        AUTHORIZATION_EXECUTOR_SHUTDOWN("authorization_executor_shutdown"),
        FIRST_PAIRING_EXECUTOR_SHUTDOWN("first_pairing_executor_shutdown"),
        START_CANCELLATION_EXECUTOR_SHUTDOWN("start_cancellation_executor_shutdown"),
        AUTHORIZATION_RUNTIME_CLOSE("authorization_runtime_close"),
        ETHERNET_RECOVERY_DESTROY("ethernet_recovery_destroy"),
        ETHERNET_DEMAND_UNREGISTER("ethernet_demand_unregister"),
        AUTHORIZATION_NETWORK_OBSERVER_UNREGISTER(
                "authorization_network_observer_unregister"),
        TRANSPORT_NETWORK_OBSERVER_UNREGISTER("transport_network_observer_unregister"),
        TRANSPORT_CATALOG_CLEAR("transport_catalog_clear"),
        RECEIVER_LIVENESS_CANCEL("receiver_liveness_cancel"),
        HEALTH_EXECUTOR_SHUTDOWN("health_executor_shutdown"),
        PIPELINE_STOP("pipeline_stop"),
        READY_AGENT_STOP("ready_agent_stop"),
        RUNTIME_LOCKS_RELEASE("runtime_locks_release"),
        RUNTIME_EXECUTOR_SHUTDOWN("runtime_executor_shutdown"),
        STOPPED_STATUS_PUBLISH("stopped_status_publish"),
        STOPPED_EVENT_WRITE("stopped_event_write");

        final String token;

        Step(String token) {
            this.token = token;
        }
    }

    static final class Failure {
        final Step step;
        final Throwable cause;

        Failure(Step step, Throwable cause) {
            this.step = step;
            this.cause = cause;
        }
    }

    private final List<Failure> failures = new ArrayList<>();

    void run(Step step, Runnable action) {
        if (step == null) throw new IllegalArgumentException("step");
        if (action == null) throw new IllegalArgumentException("action");
        try {
            action.run();
        } catch (RuntimeException | LinkageError failure) {
            failures.add(new Failure(step, failure));
        }
    }

    boolean succeeded() {
        return failures.isEmpty();
    }

    int failureCount() {
        return failures.size();
    }

    Failure failureAt(int index) {
        return failures.get(index);
    }

    static Throwable appendFailure(Throwable primary, Throwable additional) {
        if (additional == null) return primary;
        if (primary == null) return additional;
        if (primary != additional) primary.addSuppressed(additional);
        return primary;
    }

    static Throwable releaseIfHeld(
            Throwable primary,
            BooleanSupplier heldObservation,
            Runnable release) {
        if (heldObservation == null) {
            throw new IllegalArgumentException("heldObservation");
        }
        if (release == null) throw new IllegalArgumentException("release");
        boolean shouldRelease;
        try {
            shouldRelease = heldObservation.getAsBoolean();
        } catch (RuntimeException | LinkageError observationFailure) {
            primary = appendFailure(primary, observationFailure);
            // An observation failure cannot prove the lock is absent. Attempt
            // the idempotent, non-reference-counted release before teardown.
            shouldRelease = true;
        }
        if (!shouldRelease) return primary;
        try {
            release.run();
        } catch (RuntimeException | LinkageError releaseFailure) {
            primary = appendFailure(primary, releaseFailure);
        }
        return primary;
    }

    static void rethrowFailure(Throwable failure) {
        if (failure == null) return;
        if (failure instanceof RuntimeException) {
            throw (RuntimeException) failure;
        }
        if (failure instanceof LinkageError) throw (LinkageError) failure;
        throw new IllegalArgumentException("unsupported cleanup failure", failure);
    }
}
