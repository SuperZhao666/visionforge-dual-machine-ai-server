package com.visionforge.inferencebenchmark;

import java.nio.ByteBuffer;
import java.util.List;

final class DecoderAccessUnitQueueSelfTest {
    private DecoderAccessUnitQueueSelfTest() {
    }

    static void run() throws Exception {
        preservesAcceptedOrderAndRejectsNewestOnByteBudgetOverflow();
        acceptsHighFrequencyBurstWithinAgeAndByteBudgets();
        rejectsStaleBacklogExactlyOnceBeforeReferenceRecovery();
        drainsAStalledBurstAndResumesOnlyAtIdr();
        prioritizesRecoverySyncFrameOverQueuedPredictionFrames();
        closesWithoutAcceptingAStaleProducerReference();
        enforcesTheBoundedFreshnessBoundary();
        reusesAccessUnitWithoutMutatingSourceView();
    }

    private static void prioritizesRecoverySyncFrameOverQueuedPredictionFrames()
            throws Exception {
        DecoderAccessUnitQueue queue = new DecoderAccessUnitQueue(50_000, 2);
        require(queue.offer(directBytes(1), 1, 10, true, 100)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        require(queue.offer(directBytes(2), 1, 20, false, 200)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        List<DecoderAccessUnitQueue.AccessUnit> fullQueueFlush =
                queue.prepareForIncomingSyncFrame(1, 250);
        require(fullQueueFlush.size() == 2 && queue.size() == 0);
        require(queue.offer(directBytes(3), 1, 30, true, 300)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);

        require(queue.offer(directBytes(4), 1, 40, false, 400)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        require(queue.offer(directBytes(5), 1, 50, false, 500)
                == DecoderAccessUnitQueue.OfferResult.CAPACITY);
        require(queue.isAwaitingSyncFrame());
        List<DecoderAccessUnitQueue.AccessUnit> recoveryFlush =
                queue.prepareForIncomingSyncFrame(1, 550);
        require(recoveryFlush.size() == 2 && queue.size() == 0);
        require(queue.offer(directBytes(6), 1, 60, true, 600)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        require(!queue.isAwaitingSyncFrame());
    }

    private static void preservesAcceptedOrderAndRejectsNewestOnByteBudgetOverflow()
            throws Exception {
        DecoderAccessUnitQueue queue = new DecoderAccessUnitQueue(50_000, 5);
        require(queue.isAwaitingSyncFrame());
        require(queue.offer(directBytes(0), 1, 5, false, 50)
                == DecoderAccessUnitQueue.OfferResult.REFERENCE_RECOVERY);
        ByteBuffer first = directBytes(1, 2, 3);
        ByteBuffer second = directBytes(4, 5);
        require(queue.offer(first, 3, 10, true, 100)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        require(queue.offer(second, 2, 20, false, 200)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        require(queue.offer(directBytes(9), 1, 30, false, 300)
                == DecoderAccessUnitQueue.OfferResult.CAPACITY);
        require(queue.highWatermark() == 2);
        require(queue.isAwaitingSyncFrame());

        first.put(0, (byte) 99);
        DecoderAccessUnitQueue.AccessUnit acceptedFirst = queue.awaitNext(0);
        require(acceptedFirst.presentationTimeUs == 10);
        require(acceptedFirst.bytes[0] == 1);
        queue.recycle(acceptedFirst);
        DecoderAccessUnitQueue.AccessUnit acceptedSecond = queue.awaitNext(0);
        require(acceptedSecond.presentationTimeUs == 20 && !acceptedSecond.syncFrame);
        queue.recycle(acceptedSecond);
        require(queue.offer(directBytes(10), 1, 40, false, 400)
                == DecoderAccessUnitQueue.OfferResult.REFERENCE_RECOVERY);
        require(queue.offer(directBytes(11), 1, 50, true, 500)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        require(!queue.isAwaitingSyncFrame());
        require(queue.offer(directBytes(12), 1, 60, false, 600)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
    }

    private static void closesWithoutAcceptingAStaleProducerReference() {
        DecoderAccessUnitQueue queue = new DecoderAccessUnitQueue(50_000, 2);
        require(queue.offer(directBytes(7), 1, 40, true, 400)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        List<DecoderAccessUnitQueue.AccessUnit> discarded = queue.closeAndDrain();
        require(discarded.size() == 1 && queue.size() == 0 && queue.isClosed());
        require(queue.offer(directBytes(8), 1, 50, false, 500)
                == DecoderAccessUnitQueue.OfferResult.CLOSED);
    }

    private static void enforcesTheBoundedFreshnessBoundary() {
        require(!DecoderAccessUnitQueue.isStale(1_000, 50_999, 50_000));
        require(DecoderAccessUnitQueue.isStale(1_000, 51_000, 50_000));
    }

    private static void reusesAccessUnitWithoutMutatingSourceView() throws Exception {
        DecoderAccessUnitQueue queue = new DecoderAccessUnitQueue(50_000, 16);
        ByteBuffer firstSource = directBytes(1, 2, 3);
        firstSource.position(1);
        require(queue.offer(firstSource, 3, 10, true, 100)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        require(firstSource.position() == 1 && firstSource.limit() == 3);
        DecoderAccessUnitQueue.AccessUnit first = queue.awaitNext(0);
        require(first != null && first.bytes[0] == 1 && first.bytes[2] == 3);
        queue.recycle(first);

        ByteBuffer secondSource = directBytes(4, 5, 6);
        secondSource.position(2);
        require(queue.offer(secondSource, 3, 20, false, 200)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        require(secondSource.position() == 2 && secondSource.limit() == 3);
        DecoderAccessUnitQueue.AccessUnit second = queue.awaitNext(0);
        require(second == first);
        require(second.presentationTimeUs == 20 && !second.syncFrame);
        require(second.bytes[0] == 4 && second.bytes[2] == 6);
    }

    private static void acceptsHighFrequencyBurstWithinAgeAndByteBudgets()
            throws Exception {
        DecoderAccessUnitQueue queue = new DecoderAccessUnitQueue(50_000, 64);
        for (int index = 0; index < 12; index++) {
            require(queue.offer(directBytes(index), 1, index,
                    index == 0, 1_000 + index * 1_000)
                    == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        }
        require(queue.size() == 12);
        require(queue.highWatermark() == 12);
        require(queue.queuedBytes() == 12);
        for (int index = 0; index < 12; index++) {
            DecoderAccessUnitQueue.AccessUnit accessUnit = queue.awaitNext(0);
            require(accessUnit != null && accessUnit.presentationTimeUs == index);
            queue.recycle(accessUnit);
        }
        require(queue.queuedBytes() == 0);
    }

    private static void rejectsStaleBacklogExactlyOnceBeforeReferenceRecovery() {
        DecoderAccessUnitQueue queue = new DecoderAccessUnitQueue(50_000, 64);
        require(queue.offer(directBytes(1), 1, 1, true, 1_000)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        require(queue.offer(directBytes(2), 1, 2, false, 51_000)
                == DecoderAccessUnitQueue.OfferResult.CAPACITY);
        require(queue.offer(directBytes(3), 1, 3, false, 52_000)
                == DecoderAccessUnitQueue.OfferResult.REFERENCE_RECOVERY);
        List<DecoderAccessUnitQueue.AccessUnit> flushed =
                queue.prepareForIncomingSyncFrame(1, 53_000);
        require(flushed.size() == 1 && queue.queuedBytes() == 0);
        require(queue.offer(directBytes(4), 1, 4, true, 53_000)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
    }

    private static void drainsAStalledBurstAndResumesOnlyAtIdr() throws Exception {
        DecoderAccessUnitQueue queue = new DecoderAccessUnitQueue(50_000, 256);
        for (int index = 0; index < 125; index++) {
            require(queue.offer(directBytes(index), 1, index + 1,
                    index == 0, 1_000 + index)
                    == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        }
        DecoderAccessUnitQueue.AccessUnit stale = queue.awaitNext(0);
        require(stale != null
                && DecoderAccessUnitQueue.isStale(stale.enqueuedNanos, 51_000, 50_000));
        List<DecoderAccessUnitQueue.AccessUnit> dependent =
                queue.enterReferenceRecoveryAndDrain();
        require(dependent.size() == 124);
        require(queue.size() == 0 && queue.queuedBytes() == 0);
        require(queue.isAwaitingSyncFrame());
        require(queue.offer(directBytes(7), 1, 200, false, 52_000)
                == DecoderAccessUnitQueue.OfferResult.REFERENCE_RECOVERY);
        require(queue.offer(directBytes(8), 1, 201, true, 52_001)
                == DecoderAccessUnitQueue.OfferResult.ACCEPTED);
        require(!queue.isAwaitingSyncFrame());
    }

    private static ByteBuffer directBytes(int... values) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(values.length);
        for (int value : values) buffer.put((byte) value);
        buffer.flip();
        return buffer;
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("decoder access-unit queue contract failed");
    }
}
