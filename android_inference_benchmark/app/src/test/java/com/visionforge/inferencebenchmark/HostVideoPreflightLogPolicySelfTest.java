package com.visionforge.inferencebenchmark;

/** Dependency-free regression for repeated Host-video preflight failures. */
final class HostVideoPreflightLogPolicySelfTest {
    static void run() {
        throttlesStableNineSecondFailureCycles();
        writesRouteAndReasonTransitionsImmediately();
        clearsTheFailureEpochAfterHostVideoReturns();
        ignoresARegressedMonotonicClock();
    }

    private static void throttlesStableNineSecondFailureCycles() {
        HostVideoPreflightLogPolicy policy =
                new HostVideoPreflightLogPolicy();
        int writes = 0;
        for (long now = 0L;
             now < HostVideoPreflightLogPolicy.STABLE_HEARTBEAT_MILLIS;
             now += 9_000L) {
            if (policy.shouldWriteFailure(
                    "wireless:17:192.168.1.42->192.168.1.18",
                    "valid_host_video_not_observed",
                    now)) {
                writes++;
            }
        }
        require(writes == 1);
        require(policy.shouldWriteFailure(
                "wireless:17:192.168.1.42->192.168.1.18",
                "valid_host_video_not_observed",
                HostVideoPreflightLogPolicy.STABLE_HEARTBEAT_MILLIS));
    }

    private static void writesRouteAndReasonTransitionsImmediately() {
        HostVideoPreflightLogPolicy policy =
                new HostVideoPreflightLogPolicy();
        require(policy.shouldWriteFailure(
                "wireless:17", "valid_host_video_not_observed", 1_000L));
        require(!policy.shouldWriteFailure(
                "wireless:17", "valid_host_video_not_observed", 1_250L));
        require(policy.shouldWriteFailure(
                "cat6:21", "valid_host_video_not_observed", 1_500L));
        require(policy.shouldWriteFailure(
                "cat6:21", "socket_failure:BindException", 1_750L));
    }

    private static void clearsTheFailureEpochAfterHostVideoReturns() {
        HostVideoPreflightLogPolicy policy =
                new HostVideoPreflightLogPolicy();
        require(policy.shouldWriteFailure(
                "wireless:17", "valid_host_video_not_observed", 1_000L));
        require(!policy.shouldWriteFailure(
                "wireless:17", "valid_host_video_not_observed", 2_000L));
        policy.clearFailure();
        require(policy.shouldWriteFailure(
                "wireless:17", "valid_host_video_not_observed", 2_001L));
    }

    private static void ignoresARegressedMonotonicClock() {
        HostVideoPreflightLogPolicy policy =
                new HostVideoPreflightLogPolicy();
        require(policy.shouldWriteFailure(
                "wireless:17", "valid_host_video_not_observed", 5_000L));
        require(!policy.shouldWriteFailure(
                "wireless:17", "valid_host_video_not_observed", 1_000L));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("Host-video preflight log policy failed");
        }
    }
}
