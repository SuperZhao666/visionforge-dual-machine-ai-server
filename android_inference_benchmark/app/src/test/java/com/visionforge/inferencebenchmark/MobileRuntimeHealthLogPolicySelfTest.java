package com.visionforge.inferencebenchmark;

/** Dependency-free contract for idle health-log suppression and wake transitions. */
public final class MobileRuntimeHealthLogPolicySelfTest {
    static void run() {
        MobileRuntimeHealthLogPolicy policy = new MobileRuntimeHealthLogPolicy();
        String decoder = "configured=1 decoder_failed=0";
        String qnn = "ready=1 backend=QNN HTP";

        require(policy.shouldWrite("running", video(10L, 0L), decoder, qnn, 5_000L));
        require(policy.shouldWrite("running", video(20L, 0L), decoder, qnn, 10_000L));
        require(policy.shouldWrite("running", video(20L, 0L), decoder, qnn, 15_000L));
        require(!policy.shouldWrite("running", video(20L, 0L), decoder, qnn, 20_000L));
        require(!policy.shouldWrite("running", video(20L, 0L), decoder, qnn, 314_999L));
        require(policy.shouldWrite("running", video(20L, 0L), decoder, qnn, 315_000L));

        // Returning data and fault-state transitions are never hidden by idle throttling.
        require(policy.shouldWrite("running", video(21L, 0L), decoder, qnn, 320_000L));
        require(policy.shouldWrite("running", video(21L, 1L), decoder, qnn, 325_000L));
        require(policy.shouldWrite("failed", video(21L, 1L), decoder, qnn, 330_000L));

        verifiesPrefixedFieldsDoNotCreateFalseProgress();
    }

    private static void verifiesPrefixedFieldsDoNotCreateFalseProgress() {
        MobileRuntimeHealthLogPolicy policy = new MobileRuntimeHealthLogPolicy();
        String first = "shadow_running=1 running=0 "
                + "shadow_accepted_datagrams=10 accepted_datagrams=0 "
                + "fatal_socket_errors=0 source_restart_failures=0";
        String second = "shadow_running=0 running=0 "
                + "shadow_accepted_datagrams=20 accepted_datagrams=0 "
                + "fatal_socket_errors=0 source_restart_failures=0";

        require(policy.shouldWrite(
                "ready", first, "configured=0", "ready=0", 1_000L));
        require(!policy.shouldWrite(
                "ready", second, "configured=0", "ready=0", 2_000L));
    }

    private static String video(long acceptedDatagrams, long fatalSocketErrors) {
        return "UDP receiver running=1 accepted_datagrams=" + acceptedDatagrams
                + " fatal_socket_errors=" + fatalSocketErrors
                + " source_restart_failures=0 receiver_timeouts=999";
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Mobile runtime health log policy failed");
    }
}
