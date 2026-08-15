package com.visionforge.inferencebenchmark;

final class MobileServiceDestroyCleanupSelfTest {
    private MobileServiceDestroyCleanupSelfTest() {}

    static void run() {
        verifiesIndependentStepExecutionAndExactFailures();
        verifiesLockReleaseAfterObservationFailure();
        verifiesFailureAggregationAndRethrowIdentity();
    }

    private static void verifiesIndependentStepExecutionAndExactFailures() {
        MobileServiceDestroyCleanup cleanup = new MobileServiceDestroyCleanup();
        StringBuilder order = new StringBuilder();
        IllegalStateException runtimeFailure = new IllegalStateException("runtime");
        UnsatisfiedLinkError linkageFailure = new UnsatisfiedLinkError("linkage");

        cleanup.run(
                MobileServiceDestroyCleanup.Step.CONTROL_RUNTIME_CLOSE,
                () -> order.append("first,"));
        cleanup.run(
                MobileServiceDestroyCleanup.Step.FORMAL_USAGE_STOP,
                () -> {
                    order.append("runtime,");
                    throw runtimeFailure;
                });
        cleanup.run(
                MobileServiceDestroyCleanup.Step.RUNTIME_LOCKS_RELEASE,
                () -> order.append("after-runtime,"));
        cleanup.run(
                MobileServiceDestroyCleanup.Step.READY_AGENT_STOP,
                () -> {
                    order.append("linkage,");
                    throw linkageFailure;
                });
        cleanup.run(
                MobileServiceDestroyCleanup.Step.RUNTIME_EXECUTOR_SHUTDOWN,
                () -> order.append("last"));

        require("first,runtime,after-runtime,linkage,last".contentEquals(order),
                "a failed cleanup step must not skip later resources");
        require(!cleanup.succeeded() && cleanup.failureCount() == 2,
                "both cleanup failures remain visible");
        require(cleanup.failureAt(0).step
                        == MobileServiceDestroyCleanup.Step.FORMAL_USAGE_STOP
                        && cleanup.failureAt(0).cause == runtimeFailure,
                "runtime failure identity and step are retained");
        require(cleanup.failureAt(1).step
                        == MobileServiceDestroyCleanup.Step.READY_AGENT_STOP
                        && cleanup.failureAt(1).cause == linkageFailure,
                "linkage failure identity and step are retained");
    }

    private static void verifiesLockReleaseAfterObservationFailure() {
        IllegalStateException observationFailure =
                new IllegalStateException("held observation");
        boolean[] released = {false};
        Throwable failure = MobileServiceDestroyCleanup.releaseIfHeld(
                null,
                () -> {
                    throw observationFailure;
                },
                () -> released[0] = true);
        require(released[0],
                "lock release is still attempted when held observation fails");
        require(failure == observationFailure,
                "held-observation failure remains the primary failure");

        boolean[] absentRelease = {false};
        require(MobileServiceDestroyCleanup.releaseIfHeld(
                        null, () -> false, () -> absentRelease[0] = true) == null,
                "an observed-absent lock has no failure");
        require(!absentRelease[0], "an observed-absent lock is not released");
    }

    private static void verifiesFailureAggregationAndRethrowIdentity() {
        IllegalStateException primary = new IllegalStateException("primary");
        UnsatisfiedLinkError additional = new UnsatisfiedLinkError("additional");
        Throwable aggregated = MobileServiceDestroyCleanup.appendFailure(
                primary, additional);
        require(aggregated == primary
                        && primary.getSuppressed().length == 1
                        && primary.getSuppressed()[0] == additional,
                "later cleanup failures are suppressed on the exact primary");
        try {
            MobileServiceDestroyCleanup.rethrowFailure(aggregated);
            throw new AssertionError("cleanup failure must be rethrown");
        } catch (IllegalStateException expected) {
            require(expected == primary, "rethrow preserves primary identity");
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
