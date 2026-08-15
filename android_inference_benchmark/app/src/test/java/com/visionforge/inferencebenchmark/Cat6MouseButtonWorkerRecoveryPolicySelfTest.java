package com.visionforge.inferencebenchmark;

/** Deterministic liveness contract for CAT6 button-worker recovery. */
final class Cat6MouseButtonWorkerRecoveryPolicySelfTest {
    private Cat6MouseButtonWorkerRecoveryPolicySelfTest() {
    }

    static void run() {
        retriesOnlyAtTheDueBoundary();
        failureDelayIsExponentiallyBounded();
        aHealthyPacketRestoresImmediateRecovery();
        anEndpointChangeClearsOldFailureState();
    }

    private static void retriesOnlyAtTheDueBoundary() {
        Cat6MouseButtonWorkerRecoveryPolicy policy =
                new Cat6MouseButtonWorkerRecoveryPolicy();
        require(policy.canAttempt(1_000L));
        Cat6MouseButtonWorkerRecoveryPolicy.Failure failure =
                policy.recordFailure(1_000L);
        require(failure.consecutiveFailures == 1);
        require(failure.retryDelayNanos == 1_000_000_000L);
        require(!policy.canAttempt(1_000_000_999L));
        require(policy.canAttempt(1_000_001_000L));
    }

    private static void failureDelayIsExponentiallyBounded() {
        long[] expected = {
                1_000_000_000L,
                2_000_000_000L,
                4_000_000_000L,
                8_000_000_000L,
                16_000_000_000L,
                30_000_000_000L,
                30_000_000_000L
        };
        for (int index = 0; index < expected.length; index++) {
            require(Cat6MouseButtonWorkerRecoveryPolicy.retryDelayNanos(
                    index + 1) == expected[index]);
        }
        require(Cat6MouseButtonWorkerRecoveryPolicy.retryDelayNanos(
                Integer.MAX_VALUE) == 30_000_000_000L);
    }

    private static void aHealthyPacketRestoresImmediateRecovery() {
        Cat6MouseButtonWorkerRecoveryPolicy policy =
                new Cat6MouseButtonWorkerRecoveryPolicy();
        policy.recordFailure(10L);
        policy.recordFailure(20L);
        require(policy.consecutiveFailures() == 2);
        policy.recordHealthyPacket();
        require(policy.consecutiveFailures() == 0);
        require(policy.canAttempt(21L));
        require(policy.recordFailure(21L).retryDelayNanos
                == 1_000_000_000L);
    }

    private static void anEndpointChangeClearsOldFailureState() {
        Cat6MouseButtonWorkerRecoveryPolicy policy =
                new Cat6MouseButtonWorkerRecoveryPolicy();
        policy.recordFailure(100L);
        require(!policy.canAttempt(101L));
        policy.reset();
        require(policy.canAttempt(101L));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError(
                    "CAT6 mouse-button worker recovery policy failed");
        }
    }
}
