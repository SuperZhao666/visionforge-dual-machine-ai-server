package com.visionforge.inferencebenchmark;

/** Dependency-free regression for the automatic-usage no-op log storm. */
final class AutomaticUsageReservationLogPolicySelfTest {
    static void run() {
        AutomaticUsageReservationLogPolicy policy =
                new AutomaticUsageReservationLogPolicy();
        require(policy.shouldWrite("no_pending_formal_start", 1_000L));
        require(!policy.shouldWrite("no_pending_formal_start", 1_250L));
        require(!policy.shouldWrite(
                "no_pending_formal_start",
                1_000L + AutomaticUsageReservationLogPolicy
                        .STABLE_HEARTBEAT_MILLIS - 1L));
        require(policy.shouldWrite(
                "no_pending_formal_start",
                1_000L + AutomaticUsageReservationLogPolicy
                        .STABLE_HEARTBEAT_MILLIS));
        require(policy.shouldWrite(
                "pending_start_cancellation_confirmation",
                1_001L + AutomaticUsageReservationLogPolicy
                        .STABLE_HEARTBEAT_MILLIS));
        require(!policy.shouldWrite(
                "pending_start_cancellation_confirmation", 1L));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("automatic-usage reservation log policy failed");
        }
    }
}
