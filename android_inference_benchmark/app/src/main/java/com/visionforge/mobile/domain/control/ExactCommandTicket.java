package com.visionforge.mobile.domain.control;

import com.visionforge.mobile.domain.runtime.AbsoluteDeadline;

import java.util.Objects;

/** 每个控制 ticket 只有一个终态；错 ticket、复用 ticket 与 late ACK 都不能完成当前操作。 */
public final class ExactCommandTicket {
    public enum Result { COMPLETED, EXPIRED, STALE, WRONG_TICKET }

    private boolean pending;
    private long ticketId;
    private long highestTicketId;
    private AbsoluteDeadline deadline;
    private long transitionId;

    public synchronized void begin(long id, AbsoluteDeadline absoluteDeadline) {
        if (id <= 0L) {
            throw new IllegalArgumentException("ticket id must be positive");
        }
        if (pending) {
            throw new IllegalStateException("another ticket is already pending");
        }
        if (id <= highestTicketId) {
            throw new IllegalArgumentException("ticket ids must be strictly increasing");
        }
        advanceTransition();
        ticketId = id;
        highestTicketId = id;
        deadline = Objects.requireNonNull(absoluteDeadline, "absoluteDeadline");
        pending = true;
    }

    public synchronized Result complete(long id, long nowNanos) {
        if (!pending) {
            return Result.STALE;
        }
        if (id != ticketId) {
            return Result.WRONG_TICKET;
        }
        boolean expired = deadline.expiredAt(nowNanos);
        advanceTransition();
        pending = false;
        return expired ? Result.EXPIRED : Result.COMPLETED;
    }

    public synchronized Result expire(long nowNanos) {
        if (!pending || !deadline.expiredAt(nowNanos)) {
            return Result.STALE;
        }
        advanceTransition();
        pending = false;
        return Result.EXPIRED;
    }

    public synchronized boolean pending() {
        return pending;
    }

    public synchronized long transitionId() {
        return transitionId;
    }

    private void advanceTransition() {
        if (transitionId == Long.MAX_VALUE) {
            throw new IllegalStateException("ticket transition id space exhausted");
        }
        transitionId++;
    }
}
