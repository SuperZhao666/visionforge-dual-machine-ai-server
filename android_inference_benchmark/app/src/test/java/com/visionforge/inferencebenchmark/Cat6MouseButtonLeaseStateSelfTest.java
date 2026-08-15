package com.visionforge.inferencebenchmark;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Dependency-free regressions for atomic CAT6 button-stream lease ownership. */
final class Cat6MouseButtonLeaseStateSelfTest {
    private static final long LEASE_NANOS = 200L;

    private Cat6MouseButtonLeaseStateSelfTest() {
    }

    static void run() throws Exception {
        preservesExistingReadyAndListenerSemantics();
        expiresOnlyAfterTheStrictLeaseBoundary();
        ignoresMonotonicClockRollback();
        concurrentExpiryNotifiesExactlyOnce();
        concurrentFreshPacketCannotBeClearedAsStale();
    }

    private static void preservesExistingReadyAndListenerSemantics() {
        Cat6MouseButtonLeaseState state = new Cat6MouseButtonLeaseState();

        Cat6MouseButtonLeaseState.PacketUpdate first =
                state.acceptPacket(16, 1_000L, true);
        require(first.readyEventRequired);
        require(first.listenerNotificationRequired);
        require(first.revision == 1L);

        Cat6MouseButtonLeaseState.PacketUpdate unchanged =
                state.acceptPacket(16, 1_001L, false);
        require(!unchanged.readyEventRequired);
        require(!unchanged.listenerNotificationRequired);
        require(unchanged.revision == 1L);

        Cat6MouseButtonLeaseState.PacketUpdate newSession =
                state.acceptPacket(16, 1_002L, true);
        require(newSession.readyEventRequired);
        require(!newSession.listenerNotificationRequired);
        require(newSession.revision == 1L);

        Cat6MouseButtonLeaseState.PacketUpdate changed =
                state.acceptPacket(0, 1_003L, false);
        require(!changed.readyEventRequired);
        require(changed.listenerNotificationRequired);
        require(changed.revision == 2L);
    }

    private static void expiresOnlyAfterTheStrictLeaseBoundary() {
        Cat6MouseButtonLeaseState state = new Cat6MouseButtonLeaseState();
        state.acceptPacket(16, 0L, false);

        require(!state.expireIfStale(LEASE_NANOS, LEASE_NANOS).stateChanged);
        require(state.snapshot().streamReady);
        require(state.expireIfStale(LEASE_NANOS + 1L, LEASE_NANOS).stateChanged);
        require(!state.snapshot().streamReady);
        require(state.snapshot().revision == 2L);
        require(!state.clear().stateChanged);
    }

    private static void ignoresMonotonicClockRollback() {
        Cat6MouseButtonLeaseState state = new Cat6MouseButtonLeaseState();
        state.acceptPacket(16, 10_000L, false);
        require(!state.expireIfStale(9_000L, LEASE_NANOS).stateChanged);
        require(state.snapshot().streamReady);
        require(state.snapshot().buttonMask == 16);
    }

    private static void concurrentExpiryNotifiesExactlyOnce() throws Exception {
        Cat6MouseButtonLeaseState state = new Cat6MouseButtonLeaseState();
        state.acceptPacket(16, 1L, false);
        AtomicInteger expirations = new AtomicInteger();
        runConcurrently(
                () -> {
                    if (state.expireIfStale(1_000L, LEASE_NANOS).stateChanged) {
                        expirations.incrementAndGet();
                    }
                },
                () -> {
                    if (state.expireIfStale(1_000L, LEASE_NANOS).stateChanged) {
                        expirations.incrementAndGet();
                    }
                });
        require(expirations.get() == 1);
    }

    private static void concurrentFreshPacketCannotBeClearedAsStale()
            throws Exception {
        for (int iteration = 0; iteration < 100; iteration++) {
            Cat6MouseButtonLeaseState state = new Cat6MouseButtonLeaseState();
            state.acceptPacket(16, 1L, false);
            runConcurrently(
                    () -> state.acceptPacket(8, 1_000L, false),
                    () -> state.expireIfStale(1_000L, LEASE_NANOS));
            Cat6MouseButtonLeaseState.Snapshot snapshot = state.snapshot();
            require(snapshot.streamReady);
            require(snapshot.buttonMask == 8);
            require(snapshot.lastPacketNanos == 1_000L);
            require(snapshot.revision >= 1L);
        }
    }

    private static void runConcurrently(
            CheckedAction first,
            CheckedAction second) throws Exception {
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread firstThread = worker(first, ready, start, failure);
        Thread secondThread = worker(second, ready, start, failure);
        firstThread.start();
        secondThread.start();
        ready.await();
        start.countDown();
        firstThread.join();
        secondThread.join();
        if (failure.get() != null) {
            throw new AssertionError("concurrent lease action failed", failure.get());
        }
    }

    private static Thread worker(
            CheckedAction action,
            CountDownLatch ready,
            CountDownLatch start,
            AtomicReference<Throwable> failure) {
        return new Thread(() -> {
            ready.countDown();
            try {
                start.await();
                action.run();
            } catch (Throwable problem) {
                failure.compareAndSet(null, problem);
            }
        }, "cat6-button-lease-self-test");
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("CAT6 mouse-button lease state failed");
        }
    }

    @FunctionalInterface
    private interface CheckedAction {
        void run() throws Exception;
    }
}
