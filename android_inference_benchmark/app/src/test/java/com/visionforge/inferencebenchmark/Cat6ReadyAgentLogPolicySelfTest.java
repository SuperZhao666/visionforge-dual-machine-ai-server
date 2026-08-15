package com.visionforge.inferencebenchmark;

/** Dependency-free behavior contract for CAT6 ready-agent state logging. */
final class Cat6ReadyAgentLogPolicySelfTest {
    private Cat6ReadyAgentLogPolicySelfTest() {
    }

    static void run() {
        writesFirstObservationAndSuppressesEquivalentCallbacks();
        writesRouteAndRuntimeStateChangesImmediately();
        writesErrorAndRequesterChangesImmediately();
        writesStableHeartbeatAndHandlesClockRollback();
    }

    private static void writesFirstObservationAndSuppressesEquivalentCallbacks() {
        Cat6ReadyAgentLogPolicy policy = new Cat6ReadyAgentLogPolicy();
        require(policy.shouldWrite(true, endpoint("10.57.23.1"), report(0, 0, "none"), 1_000L));
        // Successful send counters are throughput, not lifecycle state.
        require(!policy.shouldWrite(
                true,
                endpoint("10.57.23.1"),
                reportWithSuccessCounters(0, 0, "none", 100, 50),
                1_250L));
        for (int callback = 0; callback < 1_000; callback++) {
            require(!policy.shouldWrite(
                    true,
                    endpoint("10.57.23.1"),
                    reportWithSuccessCounters(0, 0, "none", 101 + callback, 51),
                    1_500L + callback));
        }
    }

    private static void writesRouteAndRuntimeStateChangesImmediately() {
        Cat6ReadyAgentLogPolicy policy = new Cat6ReadyAgentLogPolicy();
        require(policy.shouldWrite(true, endpoint("192.168.1.18"), report(0, 0, "none"), 1_000L));
        require(policy.shouldWrite(true, endpoint("192.168.1.19"), report(0, 0, "none"), 1_001L));
        require(policy.shouldWrite(false, "none", stoppedReport(), 1_002L));
    }

    private static void writesErrorAndRequesterChangesImmediately() {
        Cat6ReadyAgentLogPolicy policy = new Cat6ReadyAgentLogPolicy();
        require(policy.shouldWrite(true, endpoint("192.168.1.18"), report(0, 0, "none"), 1_000L));
        require(policy.shouldWrite(true, endpoint("192.168.1.18"), report(1, 0, "none"), 1_001L));
        require(policy.shouldWrite(true, endpoint("192.168.1.18"), report(1, 1, "none"), 1_002L));
        require(policy.shouldWrite(
                true,
                endpoint("192.168.1.18"),
                report(1, 1, "192.168.1.20"),
                1_003L));
    }

    private static void writesStableHeartbeatAndHandlesClockRollback() {
        Cat6ReadyAgentLogPolicy policy = new Cat6ReadyAgentLogPolicy();
        String report = report(0, 0, "none");
        require(policy.shouldWrite(true, endpoint("10.57.23.1"), report, 10_000L));
        require(!policy.shouldWrite(true, endpoint("10.57.23.1"), report, 9_000L));
        require(!policy.shouldWrite(
                true,
                endpoint("10.57.23.1"),
                report,
                10_000L + Cat6ReadyAgentLogPolicy.STABLE_HEARTBEAT_MILLIS - 1L));
        require(policy.shouldWrite(
                true,
                endpoint("10.57.23.1"),
                report,
                10_000L + Cat6ReadyAgentLogPolicy.STABLE_HEARTBEAT_MILLIS));
    }

    private static String endpoint(String hostIpv4) {
        return "transport=cat6 network_handle=57 local_ipv4=10.57.23.2 host_ipv4="
                + hostIpv4 + " host_discovered=true";
    }

    private static String report(
            long readySendFailures,
            long probeAckFailures,
            String requesterIpv4) {
        return reportWithSuccessCounters(
                readySendFailures, probeAckFailures, requesterIpv4, 2, 1);
    }

    private static String reportWithSuccessCounters(
            long readySendFailures,
            long probeAckFailures,
            String requesterIpv4,
            long readyMessagesSent,
            long probeAcksSent) {
        return "CAT6 ready agent running=1 stage=running startup_errno=0 "
                + "last_socket_errno=0 ethernet_network_bound=1 "
                + "ready_messages_sent=" + readyMessagesSent
                + " ready_send_failures=" + readySendFailures
                + " primary_ready_send_failures=0 broadcast_enabled=0 "
                + "broadcast_socket_errno=0 broadcast_ready_send_failures=0 "
                + "multicast_interface_configured=0 multicast_ttl_configured=0 "
                + "probe_acks_sent=" + probeAcksSent
                + " probe_ack_failures=" + probeAckFailures
                + " last_requester_ipv4=" + requesterIpv4;
    }

    private static String stoppedReport() {
        return "CAT6 ready agent running=0 stage=stopped startup_errno=0 "
                + "last_socket_errno=0 ethernet_network_bound=0 "
                + "ready_send_failures=0 primary_ready_send_failures=0 "
                + "broadcast_enabled=0 broadcast_socket_errno=0 "
                + "broadcast_ready_send_failures=0 "
                + "multicast_interface_configured=0 multicast_ttl_configured=0 "
                + "probe_ack_failures=0 last_requester_ipv4=none";
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("CAT6 ready-agent log policy failed");
        }
    }
}
