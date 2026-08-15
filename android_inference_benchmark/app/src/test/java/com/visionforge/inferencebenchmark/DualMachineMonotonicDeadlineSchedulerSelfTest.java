package com.visionforge.inferencebenchmark;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public final class DualMachineMonotonicDeadlineSchedulerSelfTest {
    private DualMachineMonotonicDeadlineSchedulerSelfTest() {
    }

    public static void main(String[] args) {
        delayIsMonotonicAndSaturating();
        actionRunsExactlyOnce();
        cancellationAndCloseFailClosed();
        actionFailureIsReported();
        System.out.println("DUAL_MACHINE_MONOTONIC_DEADLINE_SCHEDULER_OK");
    }

    private static void delayIsMonotonicAndSaturating() {
        check(DualMachineMonotonicDeadlineScheduler.delayNanos(9L, 10L)
                == 0L, "past deadline must be immediate");
        check(DualMachineMonotonicDeadlineScheduler.delayNanos(10L, 10L)
                == 0L, "due deadline must be immediate");
        check(DualMachineMonotonicDeadlineScheduler.delayNanos(15L, 10L)
                == 5L, "future delay mismatch");
        check(DualMachineMonotonicDeadlineScheduler.delayNanos(
                Long.MAX_VALUE, -1L) == Long.MAX_VALUE,
                "overflowing delay must saturate");
    }

    private static void actionRunsExactlyOnce() {
        Fixture fixture = new Fixture();
        AtomicInteger calls = new AtomicInteger();
        fixture.owner.scheduleAt(125L, calls::incrementAndGet);
        check(fixture.scheduler.lastDelay == 25L, "monotonic delay mismatch");
        fixture.scheduler.fireLast();
        fixture.scheduler.fireLast();
        check(calls.get() == 1, "deadline action must be one-shot");
        fixture.owner.close();
    }

    private static void cancellationAndCloseFailClosed() {
        Fixture fixture = new Fixture();
        AtomicInteger calls = new AtomicInteger();
        DualMachineFormalUsageCoordinator.DeadlineScheduler.ScheduledDeadline
                first = fixture.owner.scheduleAt(101L, calls::incrementAndGet);
        first.cancel();
        first.cancel();
        fixture.scheduler.fire(0);
        check(calls.get() == 0, "cancelled action ran");
        check(fixture.scheduler.tasks.get(0).cancelled,
                "delegate was not cancelled");

        fixture.owner.scheduleAt(102L, calls::incrementAndGet);
        fixture.owner.close();
        fixture.owner.close();
        fixture.scheduler.fire(1);
        check(calls.get() == 0, "closed owner allowed pending action");
        check(fixture.shutdownCalls.get() == 1, "shutdown must be idempotent");
        expectRejected(() -> fixture.owner.scheduleAt(
                103L, calls::incrementAndGet));
    }

    private static void actionFailureIsReported() {
        Fixture fixture = new Fixture();
        IllegalStateException failure = new IllegalStateException("boom");
        fixture.owner.scheduleAt(100L, () -> {
            throw failure;
        });
        try {
            fixture.scheduler.fireLast();
            throw new AssertionError("deadline failure was swallowed");
        } catch (IllegalStateException expected) {
            check(expected == failure, "action failure identity changed");
        }
        check(fixture.reported.get() == failure,
                "action failure was not reported");
        fixture.owner.close();
    }

    private static final class Fixture {
        final AtomicLong clock = new AtomicLong(100L);
        final FakeScheduler scheduler = new FakeScheduler();
        final AtomicInteger shutdownCalls = new AtomicInteger();
        final AtomicReference<Throwable> reported = new AtomicReference<>();
        final DualMachineMonotonicDeadlineScheduler owner =
                new DualMachineMonotonicDeadlineScheduler(
                        clock::get,
                        scheduler,
                        shutdownCalls::incrementAndGet,
                        reported::set);
    }

    private static final class FakeScheduler implements
            DualMachineMonotonicDeadlineScheduler.OneShotScheduler {
        final List<FakeTask> tasks = new ArrayList<>();
        long lastDelay = -1L;

        @Override
        public DualMachineMonotonicDeadlineScheduler.ScheduledTask schedule(
                Runnable action,
                long delayNanos) {
            lastDelay = delayNanos;
            FakeTask task = new FakeTask(action);
            tasks.add(task);
            return task;
        }

        void fireLast() {
            fire(tasks.size() - 1);
        }

        void fire(int index) {
            tasks.get(index).action.run();
        }
    }

    private static final class FakeTask implements
            DualMachineMonotonicDeadlineScheduler.ScheduledTask {
        final Runnable action;
        boolean cancelled;

        private FakeTask(Runnable action) {
            this.action = action;
        }

        @Override
        public void cancel() {
            cancelled = true;
        }
    }

    private static void expectRejected(Runnable action) {
        try {
            action.run();
            throw new AssertionError("operation should be rejected");
        } catch (IllegalStateException expected) {
            // Required.
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
