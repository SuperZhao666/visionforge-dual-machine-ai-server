package com.visionforge.inferencebenchmark;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Dependency-free contract for continuous, session-scoped usage progress. */
public final class DualMachineSessionProgressCounterSelfTest {
    private DualMachineSessionProgressCounterSelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        verifiesBaselineGrowthAndNativeReset();
        verifiesInvalidSourcesFailClosed();
        verifiesAccumulatedSegmentsCannotOverflow();
        verifiesConcurrentCallersCannotSubmitStaleSnapshots();
        System.out.println("DUAL_MACHINE_SESSION_PROGRESS_COUNTER_OK");
    }

    private static void verifiesBaselineGrowthAndNativeReset() {
        AtomicLong source = new AtomicLong(100L);
        DualMachineSessionProgressCounter counter =
                new DualMachineSessionProgressCounter(source::get);
        expectState(counter::observe);
        counter.beginSession();
        check(counter.currentTotal() == 0L);
        source.set(108L);
        check(counter.observe() == 8L);
        source.set(0L);
        check(counter.observe() == 8L);
        source.set(3L);
        check(counter.observe() == 11L);
        check(counter.isUsable());
        expectState(counter::beginSession);
        counter.failClosed();
        check(!counter.isUsable());
        expectState(counter::currentTotal);
    }

    private static void verifiesInvalidSourcesFailClosed() {
        AtomicLong negative = new AtomicLong(-1L);
        DualMachineSessionProgressCounter invalid =
                new DualMachineSessionProgressCounter(negative::get);
        expectSecurity(invalid::beginSession);
        check(!invalid.isUsable());

        DualMachineSessionProgressCounter failing =
                new DualMachineSessionProgressCounter(() -> {
                    throw new IllegalStateException("native unavailable");
                });
        expectSecurity(failing::beginSession);
        check(!failing.isUsable());
    }

    private static void verifiesAccumulatedSegmentsCannotOverflow() {
        long[] samples = {0L, Long.MAX_VALUE, 0L, 1L};
        AtomicLong index = new AtomicLong();
        DualMachineSessionProgressCounter counter =
                new DualMachineSessionProgressCounter(
                        () -> samples[(int) index.getAndIncrement()]);
        counter.beginSession();
        check(counter.observe() == Long.MAX_VALUE);
        check(counter.observe() == Long.MAX_VALUE);
        expectSecurity(counter::observe);
        check(!counter.isUsable());
    }

    private static void verifiesConcurrentCallersCannotSubmitStaleSnapshots()
            throws Exception {
        AtomicLong source = new AtomicLong();
        DualMachineSessionProgressCounter counter =
                new DualMachineSessionProgressCounter(source::incrementAndGet);
        counter.beginSession();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Runnable observer = () -> {
            try {
                for (int index = 0; index < 2_000; index++) {
                    counter.observe();
                }
            } catch (Throwable throwable) {
                failure.compareAndSet(null, throwable);
            }
        };
        Thread first = new Thread(observer, "progress-observer-1");
        Thread second = new Thread(observer, "progress-observer-2");
        first.start();
        second.start();
        first.join();
        second.join();
        check(failure.get() == null);
        check(counter.currentTotal() == 4_000L);
    }

    private static void expectSecurity(CheckedAction action) {
        try {
            action.run();
            throw new AssertionError("expected security rejection");
        } catch (SecurityException expected) {
            // Expected.
        }
    }

    private static void expectState(CheckedAction action) {
        try {
            action.run();
            throw new AssertionError("expected state rejection");
        } catch (IllegalStateException expected) {
            // Expected.
        }
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("progress counter check failed");
    }

    @FunctionalInterface
    private interface CheckedAction {
        void run();
    }
}
