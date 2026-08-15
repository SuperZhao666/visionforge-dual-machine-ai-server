package com.visionforge.inferencebenchmark;

/**
 * Owns the button-stream lease as one atomic state.
 *
 * <p>The UDP receiver and runtime-health callers run on different threads. Keeping the packet
 * timestamp, readiness bit, and button mask behind one lock prevents a lease check based on an
 * old timestamp from clearing a concurrently accepted fresh packet. Callers perform logging and
 * listener notification only after these methods release the lock.
 */
final class Cat6MouseButtonLeaseState {
    static final class PacketUpdate {
        final boolean readyEventRequired;
        final boolean listenerNotificationRequired;
        final long revision;
        final int buttonMask;

        private PacketUpdate(
                boolean readyEventRequired,
                boolean listenerNotificationRequired,
                long revision,
                int buttonMask) {
            this.readyEventRequired = readyEventRequired;
            this.listenerNotificationRequired = listenerNotificationRequired;
            this.revision = revision;
            this.buttonMask = buttonMask;
        }
    }

    static final class Expiration {
        final boolean stateChanged;
        final long revision;

        private Expiration(boolean stateChanged, long revision) {
            this.stateChanged = stateChanged;
            this.revision = revision;
        }
    }

    static final class Snapshot {
        final long lastPacketNanos;
        final long revision;
        final int buttonMask;
        final boolean streamReady;

        private Snapshot(
                long lastPacketNanos,
                long revision,
                int buttonMask,
                boolean streamReady) {
            this.lastPacketNanos = lastPacketNanos;
            this.revision = revision;
            this.buttonMask = buttonMask;
            this.streamReady = streamReady;
        }
    }

    private long lastPacketNanos;
    private long revision;
    private int buttonMask;
    private boolean streamReady;

    synchronized PacketUpdate acceptPacket(
            int acceptedButtonMask,
            long receivedAtNanos,
            boolean newSession) {
        if (receivedAtNanos < 0L) {
            throw new IllegalArgumentException("receivedAtNanos");
        }
        boolean wasReady = streamReady;
        int previousMask = buttonMask;
        lastPacketNanos = receivedAtNanos;
        buttonMask = acceptedButtonMask;
        streamReady = true;
        boolean listenerNotificationRequired =
                !wasReady || previousMask != acceptedButtonMask;
        if (listenerNotificationRequired) revision++;
        return new PacketUpdate(
                !wasReady || newSession,
                listenerNotificationRequired,
                revision,
                acceptedButtonMask);
    }

    synchronized Expiration expireIfStale(
            long observedAtNanos,
            long leaseNanos) {
        if (observedAtNanos < 0L) {
            throw new IllegalArgumentException("observedAtNanos");
        }
        if (leaseNanos < 0L) {
            throw new IllegalArgumentException("leaseNanos");
        }
        if (!streamReady
                || observedAtNanos < lastPacketNanos
                || observedAtNanos - lastPacketNanos <= leaseNanos) {
            return new Expiration(false, revision);
        }
        return clearLocked();
    }

    synchronized Expiration clear() {
        return clearLocked();
    }

    synchronized Snapshot snapshot() {
        return new Snapshot(lastPacketNanos, revision, buttonMask, streamReady);
    }

    synchronized boolean matchesNotification(
            long expectedRevision,
            boolean expectedStreamReady,
            int expectedButtonMask) {
        return revision == expectedRevision
                && streamReady == expectedStreamReady
                && buttonMask == expectedButtonMask;
    }

    private Expiration clearLocked() {
        boolean changed = streamReady || buttonMask != 0;
        streamReady = false;
        buttonMask = 0;
        lastPacketNanos = 0L;
        if (changed) revision++;
        return new Expiration(changed, revision);
    }
}
