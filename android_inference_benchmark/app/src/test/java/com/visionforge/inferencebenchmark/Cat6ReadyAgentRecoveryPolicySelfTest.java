package com.visionforge.inferencebenchmark;

/** Deterministic timing contract for Ready-agent failure recovery. */
final class Cat6ReadyAgentRecoveryPolicySelfTest {
    private Cat6ReadyAgentRecoveryPolicySelfTest() {
    }

    static void run() {
        retriesAtTheExactDueBoundary();
        delayIsExponentiallyBounded();
        healthyObservationRestoresImmediateAttempt();
        deadlineComparisonSurvivesNanoTimeWrap();
    }

    private static void retriesAtTheExactDueBoundary() {
        Cat6ReadyAgentRecoveryPolicy policy =
                new Cat6ReadyAgentRecoveryPolicy();
        require(policy.canAttempt(1_000L));
        Cat6ReadyAgentRecoveryPolicy.Failure failure =
                policy.recordFailure(1_000L);
        require(failure.consecutiveFailures == 1);
        require(failure.retryDelayNanos == 1_000_000_000L);
        require(!policy.canAttempt(1_000_000_999L));
        require(policy.canAttempt(1_000_001_000L));
    }

    private static void delayIsExponentiallyBounded() {
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
            require(Cat6ReadyAgentRecoveryPolicy.retryDelayNanos(index + 1)
                    == expected[index]);
        }
    }

    private static void healthyObservationRestoresImmediateAttempt() {
        Cat6ReadyAgentRecoveryPolicy policy =
                new Cat6ReadyAgentRecoveryPolicy();
        policy.recordFailure(10L);
        require(!policy.canAttempt(11L));
        policy.recordHealthyObservation();
        require(policy.consecutiveFailures() == 0);
        require(policy.canAttempt(11L));
    }

    private static void deadlineComparisonSurvivesNanoTimeWrap() {
        Cat6ReadyAgentRecoveryPolicy policy =
                new Cat6ReadyAgentRecoveryPolicy();
        long started = Long.MAX_VALUE - 500_000_000L;
        policy.recordFailure(started);
        long due = started + 1_000_000_000L;
        require(!policy.canAttempt(due - 1L));
        require(policy.canAttempt(due));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("CAT6 Ready-agent recovery policy failed");
        }
    }
}
