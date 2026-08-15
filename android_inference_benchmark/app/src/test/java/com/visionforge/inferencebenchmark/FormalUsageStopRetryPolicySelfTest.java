package com.visionforge.inferencebenchmark;

import java.util.concurrent.TimeUnit;

/** Regression for the historical 250 ms formal-stop retry storm. */
final class FormalUsageStopRetryPolicySelfTest {
    private static final String OWNER_A = "11".repeat(16);
    private static final String OWNER_B = "22".repeat(16);
    private static final String CHANNEL = "33".repeat(32);

    private FormalUsageStopRetryPolicySelfTest() {}

    static void run() {
        verifiesCappedExponentialCadence();
        verifiesMaintenanceTicksDoNotCreateAStorm();
        verifiesNewOwnerDoesNotInheritBackoff();
        verifiesStaleResolutionCannotClearCurrentOwner();
    }

    private static void verifiesCappedExponentialCadence() {
        FormalUsageStopRetryPolicy policy =
                new FormalUsageStopRetryPolicy();
        long now = 0L;
        long[] expectedSeconds = {1L, 2L, 4L, 8L, 16L, 30L, 30L};
        for (int index = 0; index < expectedSeconds.length; index++) {
            require(policy.canAttempt(OWNER_A, CHANNEL, now));
            FormalUsageStopRetryPolicy.Decision decision =
                    policy.recordUnconfirmed(OWNER_A, CHANNEL, now);
            long expectedDelay = TimeUnit.SECONDS.toNanos(
                    expectedSeconds[index]);
            require(decision.consecutiveUnconfirmedAttempts == index + 1);
            require(decision.retryDelayNanos == expectedDelay);
            require(!policy.canAttempt(
                    OWNER_A, CHANNEL, decision.nextAttemptNanos - 1L));
            now = decision.nextAttemptNanos;
        }
    }

    private static void verifiesMaintenanceTicksDoNotCreateAStorm() {
        FormalUsageStopRetryPolicy policy =
                new FormalUsageStopRetryPolicy();
        long tickNanos = TimeUnit.MILLISECONDS.toNanos(250L);
        long now = 0L;
        int attempts = 0;
        for (int tick = 0; tick < 80; tick++) {
            if (policy.canAttempt(OWNER_A, CHANNEL, now)) {
                attempts++;
                policy.recordUnconfirmed(OWNER_A, CHANNEL, now);
            }
            now += tickNanos;
        }
        // Attempts occur at 0, 1, 3, 7 and 15 seconds, not on all 80 ticks.
        require(attempts == 5);
    }

    private static void verifiesNewOwnerDoesNotInheritBackoff() {
        FormalUsageStopRetryPolicy policy =
                new FormalUsageStopRetryPolicy();
        policy.recordUnconfirmed(OWNER_A, CHANNEL, 0L);
        require(!policy.canAttempt(
                OWNER_A, CHANNEL, TimeUnit.MILLISECONDS.toNanos(250L)));
        require(policy.canAttempt(
                OWNER_B, CHANNEL, TimeUnit.MILLISECONDS.toNanos(250L)));
    }

    private static void verifiesStaleResolutionCannotClearCurrentOwner() {
        FormalUsageStopRetryPolicy policy =
                new FormalUsageStopRetryPolicy();
        long now = TimeUnit.SECONDS.toNanos(1L);
        policy.recordUnconfirmed(OWNER_B, CHANNEL, now);
        policy.recordResolved(OWNER_A, CHANNEL);
        require(!policy.canAttempt(
                OWNER_B, CHANNEL, now + TimeUnit.MILLISECONDS.toNanos(250L)));
        policy.recordResolved(OWNER_B, CHANNEL);
        require(policy.canAttempt(
                OWNER_B, CHANNEL, now + TimeUnit.MILLISECONDS.toNanos(250L)));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError(
                    "formal usage stop retry policy failed");
        }
    }
}
