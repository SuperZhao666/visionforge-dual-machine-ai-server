package com.visionforge.inferencebenchmark;

import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Small ordered handoff between UDP reassembly and MediaCodec input.
 *
 * <p>Compressed H.264 access units are reference-dependent, so overflow rejects the newest
 * arrival instead of replacing an older queued unit. Admission is bounded by queued age and
 * compressed bytes rather than an assumed frame rate, so a short high-FPS burst can be absorbed
 * without turning ordinary scheduler jitter into an unnecessary IDR recovery.</p>
 */
final class DecoderAccessUnitQueue {
    enum OfferResult {
        ACCEPTED(0),
        INVALID(1),
        CLOSED(2),
        CAPACITY(3),
        REFERENCE_RECOVERY(5);

        final int nativeCode;

        OfferResult(int nativeCode) {
            this.nativeCode = nativeCode;
        }
    }

    static final class AccessUnit {
        final byte[] bytes;
        int size;
        long presentationTimeUs;
        boolean syncFrame;
        long enqueuedNanos;

        AccessUnit(int capacity) {
            bytes = new byte[capacity];
        }

        void reset(int size, long presentationTimeUs, boolean syncFrame, long enqueuedNanos) {
            this.size = size;
            this.presentationTimeUs = presentationTimeUs;
            this.syncFrame = syncFrame;
            this.enqueuedNanos = enqueuedNanos;
        }
    }

    private static final int MAX_REUSABLE_ACCESS_UNIT_COUNT = 16;

    private final long maximumAgeNanos;
    private final long maximumQueuedBytes;
    private final long maximumReusableBytes;
    private final ArrayDeque<AccessUnit> pending = new ArrayDeque<>();
    private final ArrayList<AccessUnit> reusableAccessUnits =
            new ArrayList<>(MAX_REUSABLE_ACCESS_UNIT_COUNT);
    private boolean closed;
    // A fresh or restarted H.264 decoder has no reference picture.  Admit the
    // stream only at an IDR so a P-frame received between restart and the
    // host's recovery response cannot poison MediaCodec's first GOP.
    private boolean awaitingSyncFrame = true;
    private int highWatermark;
    private long queuedBytes;
    private long highWatermarkBytes;
    private long reusableBytes;

    DecoderAccessUnitQueue(long maximumAgeNanos, long maximumQueuedBytes) {
        if (maximumAgeNanos <= 0) {
            throw new IllegalArgumentException("maximumAgeNanos must be positive");
        }
        if (maximumQueuedBytes <= 0) {
            throw new IllegalArgumentException("maximumQueuedBytes must be positive");
        }
        this.maximumAgeNanos = maximumAgeNanos;
        this.maximumQueuedBytes = maximumQueuedBytes;
        // Pool memory is bounded independently from queued work.  A one-off
        // large IDR must not leave sixteen oversized byte arrays retained for
        // the lifetime of the foreground service.
        this.maximumReusableBytes = maximumQueuedBytes;
    }

    synchronized OfferResult offer(ByteBuffer source, int size, long presentationTimeUs,
                                    boolean syncFrame, long enqueuedNanos) {
        if (source == null || size <= 0 || size > source.capacity()) {
            return OfferResult.INVALID;
        }
        if (closed) return OfferResult.CLOSED;
        if (awaitingSyncFrame && !syncFrame) return OfferResult.REFERENCE_RECOVERY;
        if (wouldExceedFreshnessOrByteBudget(size, enqueuedNanos)) {
            // A missing compressed AU breaks the predictive reference chain. Keep all older
            // accepted AUs in order, but do not admit another P-frame until an IDR is queued.
            awaitingSyncFrame = true;
            return OfferResult.CAPACITY;
        }

        AccessUnit accessUnit = takeReusableAccessUnit(size);
        copyWithoutChangingSource(source, accessUnit.bytes, size);
        accessUnit.reset(size, presentationTimeUs, syncFrame, enqueuedNanos);
        pending.addLast(accessUnit);
        queuedBytes += size;
        if (syncFrame) awaitingSyncFrame = false;
        highWatermark = Math.max(highWatermark, pending.size());
        highWatermarkBytes = Math.max(highWatermarkBytes, queuedBytes);
        notifyAll();
        return OfferResult.ACCEPTED;
    }

    synchronized AccessUnit awaitNext(long waitMillis) throws InterruptedException {
        if (pending.isEmpty() && !closed) wait(waitMillis);
        AccessUnit next = pending.pollFirst();
        if (next != null) queuedBytes -= next.size;
        return next;
    }

    /**
     * Drops every queued prediction frame after an accepted access unit became
     * too old to enter MediaCodec.  A partial H.264 reference chain must never
     * be replayed; admission resumes only when the next IDR arrives.
     */
    synchronized List<AccessUnit> enterReferenceRecoveryAndDrain() {
        awaitingSyncFrame = true;
        if (pending.isEmpty()) return Collections.emptyList();
        List<AccessUnit> discarded = new ArrayList<>(pending);
        pending.clear();
        queuedBytes = 0L;
        return discarded;
    }

    /**
     * Makes an incoming IDR the next queued access unit when the predictive
     * chain is already broken or the queue is full.  Keeping older P frames in
     * front of that IDR only extends the visible recovery stall.
     */
    synchronized List<AccessUnit> prepareForIncomingSyncFrame(
            int incomingSize, long enqueuedNanos) {
        if (pending.isEmpty()
                || (!awaitingSyncFrame
                && !wouldExceedFreshnessOrByteBudget(incomingSize, enqueuedNanos))) {
            return Collections.emptyList();
        }
        List<AccessUnit> discarded = new ArrayList<>(pending);
        pending.clear();
        queuedBytes = 0L;
        return discarded;
    }

    synchronized void recycle(AccessUnit accessUnit) {
        if (accessUnit == null) return;
        reusableAccessUnits.add(accessUnit);
        reusableBytes += accessUnit.bytes.length;
        while (reusableAccessUnits.size() > MAX_REUSABLE_ACCESS_UNIT_COUNT
                || reusableBytes > maximumReusableBytes) {
            removeLargestReusableAccessUnit();
        }
    }

    synchronized List<AccessUnit> closeAndDrain() {
        closed = true;
        List<AccessUnit> discarded = new ArrayList<>(pending);
        pending.clear();
        queuedBytes = 0L;
        reusableAccessUnits.clear();
        reusableBytes = 0L;
        notifyAll();
        return discarded;
    }

    synchronized int size() {
        return pending.size();
    }

    synchronized int highWatermark() {
        return highWatermark;
    }

    synchronized long queuedBytes() {
        return queuedBytes;
    }

    synchronized long highWatermarkBytes() {
        return highWatermarkBytes;
    }

    synchronized long reusableBytes() {
        return reusableBytes;
    }

    synchronized boolean isClosed() {
        return closed;
    }

    synchronized boolean isAwaitingSyncFrame() {
        return awaitingSyncFrame;
    }

    static boolean isStale(long enqueuedNanos, long nowNanos, long maximumAgeNanos) {
        if (maximumAgeNanos < 0L || nowNanos < enqueuedNanos) {
            return false;
        }
        return nowNanos - enqueuedNanos >= maximumAgeNanos;
    }

    private boolean wouldExceedFreshnessOrByteBudget(int incomingSize, long nowNanos) {
        AccessUnit oldest = pending.peekFirst();
        boolean staleBacklog = oldest != null
                && isStale(oldest.enqueuedNanos, nowNanos, maximumAgeNanos);
        boolean byteBudgetExceeded = incomingSize > maximumQueuedBytes - queuedBytes;
        return staleBacklog || byteBudgetExceeded;
    }

    private AccessUnit takeReusableAccessUnit(int minimumSize) {
        int bestIndex = -1;
        for (int index = 0; index < reusableAccessUnits.size(); index++) {
            AccessUnit candidate = reusableAccessUnits.get(index);
            if (candidate.bytes.length >= minimumSize
                    && (bestIndex < 0 || candidate.bytes.length
                    < reusableAccessUnits.get(bestIndex).bytes.length)) {
                bestIndex = index;
            }
        }
        if (bestIndex >= 0) {
            AccessUnit reused = reusableAccessUnits.remove(bestIndex);
            reusableBytes -= reused.bytes.length;
            return reused;
        }
        return new AccessUnit(minimumSize);
    }

    private static void copyWithoutChangingSource(
            ByteBuffer source, byte[] destination, int size) {
        int originalPosition = source.position();
        int originalLimit = source.limit();
        try {
            source.position(0);
            source.limit(size);
            source.get(destination, 0, size);
        } finally {
            source.limit(originalLimit);
            source.position(originalPosition);
        }
    }

    private void removeLargestReusableAccessUnit() {
        int largestIndex = -1;
        for (int index = 0; index < reusableAccessUnits.size(); index++) {
            AccessUnit candidate = reusableAccessUnits.get(index);
            if (largestIndex < 0 || candidate.bytes.length
                    > reusableAccessUnits.get(largestIndex).bytes.length) {
                largestIndex = index;
            }
        }
        if (largestIndex >= 0) {
            AccessUnit removed = reusableAccessUnits.remove(largestIndex);
            reusableBytes -= removed.bytes.length;
        }
    }
}
