package com.visionforge.inferencebenchmark;

/**
 * Debounces transient Android Ethernet loss callbacks without weakening the
 * immediate fail-closed control-output boundary.
 */
final class MobileEthernetRecoveryCoordinator<Owner> {
    static final long DEFAULT_DEBOUNCE_MILLIS = 1_800L;

    interface Cancellation {
        void cancel();
    }

    interface Scheduler {
        Cancellation schedule(Runnable task, long delayMillis);
    }

    interface Listener<Owner> {
        void failClosed(long networkHandle, String source, Owner owner);

        void debounceStarted(
                long networkHandle,
                String source,
                long delayMillis,
                Owner owner);

        void debounceCancelled(
                long lostNetworkHandle,
                long readyNetworkHandle,
                String source,
                Owner owner);

        void debounceExpired(long networkHandle, String source, Owner owner);

        void rebindRequired(
                long previousNetworkHandle,
                long replacementNetworkHandle,
                String source,
                Owner owner);
    }

    private final Scheduler scheduler;
    private final Listener<Owner> listener;
    private final long debounceMillis;
    private long activeNetworkHandle;
    private long generation;
    private PendingLoss<Owner> pendingLoss;
    private boolean destroyed;

    MobileEthernetRecoveryCoordinator(
            Scheduler scheduler,
            Listener<Owner> listener) {
        this(scheduler, listener, DEFAULT_DEBOUNCE_MILLIS);
    }

    MobileEthernetRecoveryCoordinator(
            Scheduler scheduler,
            Listener<Owner> listener,
            long debounceMillis) {
        if (scheduler == null || listener == null) {
            throw new IllegalArgumentException("scheduler and listener are required");
        }
        if (debounceMillis <= 0L) {
            throw new IllegalArgumentException("debounceMillis must be positive");
        }
        this.scheduler = scheduler;
        this.listener = listener;
        this.debounceMillis = debounceMillis;
    }

    synchronized void onLinkReady(
            long networkHandle,
            String source,
            Owner owner) {
        if (destroyed || networkHandle <= 0L) return;

        long previousNetworkHandle = activeNetworkHandle;
        boolean lossWasPending = pendingLoss != null;
        if (lossWasPending) {
            PendingLoss<Owner> cancelled = pendingLoss;
            pendingLoss = null;
            cancelled.cancellation.cancel();
            listener.debounceCancelled(
                    cancelled.networkHandle,
                    networkHandle,
                    source,
                    cancelled.owner);
        }

        activeNetworkHandle = networkHandle;
        if (previousNetworkHandle > 0L && previousNetworkHandle != networkHandle) {
            if (!lossWasPending) {
                listener.failClosed(
                        previousNetworkHandle,
                        "network_handle_changed_" + source,
                        owner);
            }
            listener.rebindRequired(
                    previousNetworkHandle,
                    networkHandle,
                    source,
                    owner);
        }
    }

    synchronized void onLinkUnavailable(
            long networkHandle,
            String source,
            Owner owner) {
        if (destroyed || networkHandle <= 0L || networkHandle != activeNetworkHandle
                || pendingLoss != null) {
            return;
        }

        listener.failClosed(networkHandle, source, owner);
        long pendingGeneration = ++generation;
        PendingLoss<Owner> pending = new PendingLoss<>(
                networkHandle, source, pendingGeneration, owner);
        pendingLoss = pending;
        try {
            listener.debounceStarted(
                    networkHandle, source, debounceMillis, owner);
            Cancellation cancellation = scheduler.schedule(
                    () -> expire(pendingGeneration), debounceMillis);
            if (cancellation == null) {
                throw new IllegalStateException(
                        "Ethernet recovery scheduler returned no cancellation");
            }
            pending.cancellation = cancellation;
        } catch (RuntimeException setupFailure) {
            expireAfterDebounceSetupFailure(pending, setupFailure);
        }
    }

    synchronized long activeNetworkHandle() {
        return activeNetworkHandle;
    }

    /** Selects a preferred link between formal sessions without a rebind. */
    synchronized void adoptLinkWhileDataPlaneClosed(
            long networkHandle,
            String source) {
        if (destroyed || networkHandle <= 0L) return;
        if (pendingLoss != null) {
            PendingLoss<Owner> cancelled = pendingLoss;
            pendingLoss = null;
            cancelled.cancellation.cancel();
            listener.debounceCancelled(
                    cancelled.networkHandle,
                    networkHandle,
                    source,
                    cancelled.owner);
        }
        activeNetworkHandle = networkHandle;
    }

    synchronized boolean isDebouncePending() {
        return pendingLoss != null;
    }

    synchronized void destroy() {
        if (destroyed) return;
        destroyed = true;
        if (pendingLoss != null) {
            PendingLoss<Owner> cancelled = pendingLoss;
            cancelled.cancellation.cancel();
            pendingLoss = null;
            listener.debounceCancelled(
                    cancelled.networkHandle,
                    0L,
                    "coordinator_destroyed",
                    cancelled.owner);
        }
        activeNetworkHandle = 0L;
        ++generation;
    }

    private synchronized void expire(long pendingGeneration) {
        if (destroyed || pendingLoss == null
                || pendingLoss.generation != pendingGeneration) {
            return;
        }
        PendingLoss<Owner> expired = pendingLoss;
        pendingLoss = null;
        if (activeNetworkHandle == expired.networkHandle) {
            activeNetworkHandle = 0L;
        }
        listener.debounceExpired(
                expired.networkHandle, expired.source, expired.owner);
    }

    private void expireAfterDebounceSetupFailure(
            PendingLoss<Owner> pending,
            RuntimeException failure) {
        if (pendingLoss != pending) return;
        pendingLoss = null;
        if (activeNetworkHandle == pending.networkHandle) {
            activeNetworkHandle = 0L;
        }
        listener.debounceExpired(
                pending.networkHandle,
                pending.source + "_debounce_setup_failed_"
                        + failure.getClass().getSimpleName(),
                pending.owner);
    }

    private static final class PendingLoss<Owner> {
        final long networkHandle;
        final String source;
        final long generation;
        final Owner owner;
        Cancellation cancellation = () -> { };

        PendingLoss(
                long networkHandle,
                String source,
                long generation,
                Owner owner) {
            this.networkHandle = networkHandle;
            this.source = source;
            this.generation = generation;
            this.owner = owner;
        }
    }
}
