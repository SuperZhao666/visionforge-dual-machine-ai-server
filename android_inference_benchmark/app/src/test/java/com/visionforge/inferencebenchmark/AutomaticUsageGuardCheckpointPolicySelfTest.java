package com.visionforge.inferencebenchmark;

/** Regression contract for bounded automatic-usage progress persistence. */
final class AutomaticUsageGuardCheckpointPolicySelfTest {
    static void run() {
        firstLiveCheckpointIsImmediate();
        transitionPersistenceDoesNotDelayFirstCheckpoint();
        forwardProgressIsCoalescedUntilDeadline();
        sequenceRegressionCheckpointsImmediately();
        invalidSequencesDoNotImitateRegression();
        monotonicClockRollbackDoesNotForcePeriodicPersistence();
        successfulRegressionRecalculatesDeadline();
        clearingPersistenceRearmsImmediateCheckpoint();
        deadlineAdditionSaturates();
    }

    private static void firstLiveCheckpointIsImmediate() {
        AutomaticUsageGuardCheckpointPolicy policy =
                new AutomaticUsageGuardCheckpointPolicy();
        require(policy.evaluate(1_000L, 10L)
                == AutomaticUsageGuardCheckpointPolicy.Decision.PERIODIC_DUE);
    }

    private static void transitionPersistenceDoesNotDelayFirstCheckpoint() {
        AutomaticUsageGuardCheckpointPolicy policy =
                new AutomaticUsageGuardCheckpointPolicy();
        policy.recordPersistence(100L);
        require(policy.evaluate(2_000L, 101L)
                == AutomaticUsageGuardCheckpointPolicy.Decision.PERIODIC_DUE);
    }

    private static void forwardProgressIsCoalescedUntilDeadline() {
        AutomaticUsageGuardCheckpointPolicy policy = checkpointedAt(
                10_000L, 1_000L);
        require(policy.evaluate(39_999L, 9_000L)
                == AutomaticUsageGuardCheckpointPolicy.Decision.NOT_DUE);
        require(policy.evaluate(40_000L, 9_001L)
                == AutomaticUsageGuardCheckpointPolicy.Decision.PERIODIC_DUE);
    }

    private static void sequenceRegressionCheckpointsImmediately() {
        AutomaticUsageGuardCheckpointPolicy policy = checkpointedAt(
                10_000L, 50_000L);
        require(policy.evaluate(10_001L, 10L)
                == AutomaticUsageGuardCheckpointPolicy.Decision
                .FRAME_SEQUENCE_REGRESSED);
    }

    private static void invalidSequencesDoNotImitateRegression() {
        AutomaticUsageGuardCheckpointPolicy policy = checkpointedAt(
                10_000L, 500L);
        require(policy.evaluate(10_001L, -1L)
                == AutomaticUsageGuardCheckpointPolicy.Decision.NOT_DUE);
        require(policy.evaluate(
                10_002L,
                AutomaticFormalUsageSessionGuard.MAX_LOGICAL_FRAME_SEQUENCE
                        + 1L)
                == AutomaticUsageGuardCheckpointPolicy.Decision.NOT_DUE);

        policy.restorePersisted(-1L);
        policy.recordCheckpointSucceeded(20_000L);
        require(policy.evaluate(20_001L, 5L)
                == AutomaticUsageGuardCheckpointPolicy.Decision.NOT_DUE);
    }

    private static void monotonicClockRollbackDoesNotForcePeriodicPersistence() {
        AutomaticUsageGuardCheckpointPolicy policy = checkpointedAt(
                100_000L, 1_000L);
        require(policy.evaluate(90_000L, 1_001L)
                == AutomaticUsageGuardCheckpointPolicy.Decision.NOT_DUE);
    }

    private static void successfulRegressionRecalculatesDeadline() {
        AutomaticUsageGuardCheckpointPolicy policy = checkpointedAt(
                10_000L, 1_000L);
        require(policy.evaluate(20_000L, 100L)
                == AutomaticUsageGuardCheckpointPolicy.Decision
                .FRAME_SEQUENCE_REGRESSED);
        policy.recordPersistence(100L);
        policy.recordCheckpointSucceeded(20_000L);
        require(policy.evaluate(49_999L, 500L)
                == AutomaticUsageGuardCheckpointPolicy.Decision.NOT_DUE);
        require(policy.evaluate(50_000L, 501L)
                == AutomaticUsageGuardCheckpointPolicy.Decision.PERIODIC_DUE);
    }

    private static void clearingPersistenceRearmsImmediateCheckpoint() {
        AutomaticUsageGuardCheckpointPolicy policy = checkpointedAt(
                10_000L, 1_000L);
        policy.clearPersisted();
        require(policy.evaluate(10_001L, 1L)
                == AutomaticUsageGuardCheckpointPolicy.Decision.PERIODIC_DUE);
    }

    private static void deadlineAdditionSaturates() {
        AutomaticUsageGuardCheckpointPolicy policy =
                new AutomaticUsageGuardCheckpointPolicy();
        policy.recordPersistence(1L);
        policy.recordCheckpointSucceeded(Long.MAX_VALUE - 1L);
        require(policy.evaluate(Long.MAX_VALUE - 1L, 2L)
                == AutomaticUsageGuardCheckpointPolicy.Decision.NOT_DUE);
        require(policy.evaluate(Long.MAX_VALUE, 3L)
                == AutomaticUsageGuardCheckpointPolicy.Decision.PERIODIC_DUE);
    }

    private static AutomaticUsageGuardCheckpointPolicy checkpointedAt(
            long nowElapsedMillis,
            long frameSequence) {
        AutomaticUsageGuardCheckpointPolicy policy =
                new AutomaticUsageGuardCheckpointPolicy();
        policy.recordPersistence(frameSequence);
        policy.recordCheckpointSucceeded(nowElapsedMillis);
        return policy;
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError(
                    "automatic usage guard checkpoint policy contract failed");
        }
    }
}
