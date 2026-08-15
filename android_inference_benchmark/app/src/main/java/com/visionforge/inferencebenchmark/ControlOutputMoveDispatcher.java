package com.visionforge.inferencebenchmark;

import java.util.concurrent.atomic.AtomicReference;

/** Stable JNI callback target that delegates native move delivery to the active transport. */
final class ControlOutputMoveDispatcher {
    private static final AtomicReference<ControlOutputMoveSink> sink = new AtomicReference<>();

    private ControlOutputMoveDispatcher() {
    }

    static void registerSink(ControlOutputMoveSink nextSink) {
        if (nextSink == null) {
            throw new IllegalArgumentException("nextSink is required");
        }
        sink.set(nextSink);
    }

    static void clearSink(ControlOutputMoveSink expectedSink) {
        if (expectedSink == null) {
            sink.set(null);
            return;
        }
        sink.compareAndSet(expectedSink, null);
    }

    static boolean offerNativeMove(int deltaX, int deltaY, long ticket) {
        ControlOutputMoveSink current = sink.get();
        return current != null && current.offerMoveFromNative(deltaX, deltaY, ticket);
    }

    private static boolean suspendNativeDeliveryForRecovery(long generation) {
        ControlOutputMoveSink current = sink.get();
        return current != null && current.suspendMoveDeliveryForNativeRecovery(generation);
    }

    private static boolean resumeNativeDeliveryAfterRecovery(long generation) {
        ControlOutputMoveSink current = sink.get();
        return current != null && current.resumeMoveDeliveryAfterNativeRecovery(generation);
    }

    private static boolean failClosedNativeDelivery() {
        ControlOutputMoveSink current = sink.get();
        return current != null && current.failClosedNativeMoveDelivery();
    }
}
