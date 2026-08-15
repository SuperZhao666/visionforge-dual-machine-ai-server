package com.visionforge.inferencebenchmark;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Service-owned monotonic one-shot scheduler for five-second usage leases.
 *
 * <p>Deadlines use the {@link System#nanoTime()} domain only. Closing the
 * scheduler synchronously prevents every not-yet-running action from acquiring
 * a data-plane capability after the owning service has stopped.</p>
 */
public final class DualMachineMonotonicDeadlineScheduler
        implements DualMachineFormalUsageCoordinator.DeadlineScheduler,
        AutoCloseable {
    @FunctionalInterface
    interface MonotonicClock {
        long nowNanos();
    }

    interface ScheduledTask {
        void cancel();
    }

    @FunctionalInterface
    interface OneShotScheduler {
        ScheduledTask schedule(Runnable action, long delayNanos);
    }

    @FunctionalInterface
    interface FailureReporter {
        void report(Throwable failure);
    }

    private final Object lock = new Object();
    private final MonotonicClock clock;
    private final OneShotScheduler scheduler;
    private final Runnable shutdown;
    private final FailureReporter failureReporter;
    private final Set<TrackedDeadline> deadlines = new HashSet<>();
    private boolean closed;

    public DualMachineMonotonicDeadlineScheduler() {
        ScheduledThreadPoolExecutor executor =
                new ScheduledThreadPoolExecutor(1, runnable -> {
                    Thread thread = new Thread(
                            runnable, "visionforge-dual-machine-lease-deadline");
                    thread.setDaemon(false);
                    return thread;
                });
        executor.setRemoveOnCancelPolicy(true);
        executor.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        executor.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
        clock = System::nanoTime;
        scheduler = (action, delayNanos) -> {
            ScheduledFuture<?> future = executor.schedule(
                    action, delayNanos, TimeUnit.NANOSECONDS);
            return () -> future.cancel(false);
        };
        shutdown = executor::shutdownNow;
        failureReporter =
                DualMachineMonotonicDeadlineScheduler::reportUncaught;
    }

    DualMachineMonotonicDeadlineScheduler(
            MonotonicClock clock,
            OneShotScheduler scheduler,
            Runnable shutdown,
            FailureReporter failureReporter) {
        if (clock == null || scheduler == null || shutdown == null
                || failureReporter == null) {
            throw new IllegalArgumentException(
                    "deadline scheduler dependencies are required");
        }
        this.clock = clock;
        this.scheduler = scheduler;
        this.shutdown = shutdown;
        this.failureReporter = failureReporter;
    }

    @Override
    public ScheduledDeadline scheduleAt(
            long deadlineMonotonicNanos,
            Runnable action) {
        if (action == null) {
            throw new IllegalArgumentException("deadline action is required");
        }
        synchronized (lock) {
            if (closed) {
                throw new IllegalStateException("deadline scheduler is closed");
            }
            TrackedDeadline tracked = new TrackedDeadline(action);
            deadlines.add(tracked);
            try {
                long delay = delayNanos(
                        deadlineMonotonicNanos, clock.nowNanos());
                tracked.install(scheduler.schedule(tracked::runOnce, delay));
                return tracked;
            } catch (RuntimeException | Error failure) {
                deadlines.remove(tracked);
                tracked.markFinished();
                throw failure;
            }
        }
    }

    @Override
    public void close() {
        List<TrackedDeadline> pending;
        synchronized (lock) {
            if (closed) return;
            closed = true;
            pending = new ArrayList<>(deadlines);
            deadlines.clear();
        }
        for (TrackedDeadline deadline : pending) {
            deadline.cancel();
        }
        shutdown.run();
    }

    static long delayNanos(long deadlineNanos, long nowNanos) {
        if (deadlineNanos <= nowNanos) return 0L;
        long delay = deadlineNanos - nowNanos;
        return delay < 0L ? Long.MAX_VALUE : delay;
    }

    private static void reportUncaught(Throwable failure) {
        Thread thread = Thread.currentThread();
        Thread.UncaughtExceptionHandler handler =
                thread.getUncaughtExceptionHandler();
        if (handler != null) handler.uncaughtException(thread, failure);
    }

    private final class TrackedDeadline implements ScheduledDeadline {
        private final Runnable action;
        private final AtomicBoolean finished = new AtomicBoolean();
        private volatile ScheduledTask scheduledTask;

        private TrackedDeadline(Runnable action) {
            this.action = action;
        }

        private void install(ScheduledTask task) {
            if (task == null) {
                throw new IllegalStateException(
                        "one-shot scheduler returned no task");
            }
            scheduledTask = task;
            if (finished.get()) task.cancel();
        }

        private void runOnce() {
            if (!finished.compareAndSet(false, true)) return;
            synchronized (lock) {
                deadlines.remove(this);
                if (closed) return;
            }
            try {
                action.run();
            } catch (RuntimeException | Error failure) {
                failureReporter.report(failure);
                throw failure;
            }
        }

        private void markFinished() {
            finished.set(true);
        }

        @Override
        public void cancel() {
            if (!finished.compareAndSet(false, true)) return;
            synchronized (lock) {
                deadlines.remove(this);
            }
            ScheduledTask task = scheduledTask;
            if (task != null) task.cancel();
        }
    }
}
