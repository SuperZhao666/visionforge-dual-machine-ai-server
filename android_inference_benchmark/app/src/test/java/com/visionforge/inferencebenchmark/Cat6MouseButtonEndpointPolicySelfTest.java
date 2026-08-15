package com.visionforge.inferencebenchmark;

/** Dependency-free behavior contract for idempotent CAT6 button endpoint updates. */
final class Cat6MouseButtonEndpointPolicySelfTest {
    private Cat6MouseButtonEndpointPolicySelfTest() {
    }

    static void run() {
        firstUnavailableObservationIsHandled();
        repeatedUnavailableCallbacksStaySideEffectFree();
        unavailableTransitionAfterAStartedEndpointIsHandledAgain();
        aResidualWorkerIsAlwaysStopped();
    }

    private static void firstUnavailableObservationIsHandled() {
        Cat6MouseButtonEndpointPolicy policy =
                new Cat6MouseButtonEndpointPolicy();
        require(policy.shouldHandleUnavailable(true));
    }

    private static void repeatedUnavailableCallbacksStaySideEffectFree() {
        Cat6MouseButtonEndpointPolicy policy =
                new Cat6MouseButtonEndpointPolicy();
        require(policy.shouldHandleUnavailable(true));
        for (int callback = 0; callback < 1_000; callback++) {
            require(!policy.shouldHandleUnavailable(true));
        }
    }

    private static void unavailableTransitionAfterAStartedEndpointIsHandledAgain() {
        Cat6MouseButtonEndpointPolicy policy =
                new Cat6MouseButtonEndpointPolicy();
        require(policy.shouldHandleUnavailable(true));
        policy.recordEndpointStarting();
        require(policy.shouldHandleUnavailable(false));
        require(!policy.shouldHandleUnavailable(true));
    }

    private static void aResidualWorkerIsAlwaysStopped() {
        Cat6MouseButtonEndpointPolicy policy =
                new Cat6MouseButtonEndpointPolicy();
        require(policy.shouldHandleUnavailable(true));
        require(policy.shouldHandleUnavailable(false));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("CAT6 mouse button endpoint policy failed");
        }
    }
}
