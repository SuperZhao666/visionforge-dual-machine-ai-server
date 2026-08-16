package com.visionforge.inferencebenchmark;

/** Latest-only MAKCU move mailbox whose displacement and native ticket are atomic. */
final class MakcuPendingMoveSlot {
    static final class PendingMove {
        long packed;
        long ticket;
        long deadlineNanos;

        PendingMove() {
        }
    }

    private long packed;
    private long ticket;
    private long deadlineNanos;

    synchronized void offer(long packed, long ticket) {
        offer(packed, ticket, Long.MAX_VALUE);
    }

    synchronized void offer(long packed, long ticket, long deadlineNanos) {
        if (packed == 0L || ticket <= 0L) {
            throw new IllegalArgumentException("MAKCU move and ticket must be non-zero");
        }
        if (deadlineNanos <= 0L) {
            throw new IllegalArgumentException("MAKCU move deadline must be positive");
        }
        this.packed = packed;
        this.ticket = ticket;
        this.deadlineNanos = deadlineNanos;
    }

    synchronized boolean takeInto(PendingMove destination) {
        if (destination == null) throw new IllegalArgumentException("destination");
        if (packed == 0L) return false;
        destination.packed = packed;
        destination.ticket = ticket;
        destination.deadlineNanos = deadlineNanos;
        packed = 0L;
        ticket = 0L;
        deadlineNanos = 0L;
        return true;
    }

    synchronized long clear() {
        long rejectedTicket = ticket;
        packed = 0L;
        ticket = 0L;
        deadlineNanos = 0L;
        return rejectedTicket;
    }

    synchronized boolean clearIfMatches(long packed, long ticket) {
        if (this.packed == 0L || this.packed != packed || this.ticket != ticket) {
            return false;
        }
        this.packed = 0L;
        this.ticket = 0L;
        this.deadlineNanos = 0L;
        return true;
    }

    synchronized boolean hasPending() {
        return packed != 0L;
    }
}
