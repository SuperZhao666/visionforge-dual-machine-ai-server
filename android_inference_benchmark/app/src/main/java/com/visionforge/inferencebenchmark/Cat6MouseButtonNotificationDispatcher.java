package com.visionforge.inferencebenchmark;

import java.util.ArrayDeque;

/**
 * Serializes button-state callbacks without holding the lease or coordinator lock.
 *
 * <p>Transitions may be produced by the UDP receiver, a socket-timeout worker, or a runtime health
 * caller. Revision checks discard a notification that was overtaken before it reached the sink,
 * while a single lock-free-at-callback drainer preserves delivery order and avoids an ABBA lock
 * cycle with {@link ControlOutputCoordinator}.
 */
final class Cat6MouseButtonNotificationDispatcher {
    interface StateProbe {
        boolean matches(long revision, boolean streamReady, int buttonMask);
    }

    interface Sink {
        void onButtonMaskChanged(int buttonMask);
    }

    private static final class PendingNotification {
        final long revision;
        final boolean streamReady;
        final int buttonMask;

        PendingNotification(
                long revision,
                boolean streamReady,
                int buttonMask) {
            this.revision = revision;
            this.streamReady = streamReady;
            this.buttonMask = buttonMask;
        }
    }

    private final Object queueLock = new Object();
    private final ArrayDeque<PendingNotification> pending = new ArrayDeque<>();
    private final StateProbe stateProbe;
    private final Sink sink;
    private boolean draining;
    private long lastHandledRevision;

    Cat6MouseButtonNotificationDispatcher(
            StateProbe stateProbe,
            Sink sink) {
        if (stateProbe == null) throw new IllegalArgumentException("stateProbe");
        if (sink == null) throw new IllegalArgumentException("sink");
        this.stateProbe = stateProbe;
        this.sink = sink;
    }

    void enqueue(
            long revision,
            boolean streamReady,
            int buttonMask) {
        if (revision <= 0L) throw new IllegalArgumentException("revision");
        boolean shouldDrain = false;
        synchronized (queueLock) {
            if (revision <= lastHandledRevision) return;
            pending.addLast(new PendingNotification(
                    revision, streamReady, buttonMask));
            if (!draining) {
                draining = true;
                shouldDrain = true;
            }
        }
        if (shouldDrain) drain();
    }

    private void drain() {
        while (true) {
            PendingNotification notification;
            synchronized (queueLock) {
                notification = pending.pollFirst();
                if (notification == null) {
                    draining = false;
                    return;
                }
                if (notification.revision <= lastHandledRevision) continue;
                lastHandledRevision = notification.revision;
            }
            // No dispatcher lock is held across either external call.
            if (stateProbe.matches(
                    notification.revision,
                    notification.streamReady,
                    notification.buttonMask)) {
                sink.onButtonMaskChanged(notification.buttonMask);
            }
        }
    }
}
