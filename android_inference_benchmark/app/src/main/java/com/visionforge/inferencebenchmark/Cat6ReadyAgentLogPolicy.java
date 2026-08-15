package com.visionforge.inferencebenchmark;

/** Preserves CAT6 ready-agent transitions without repeating equivalent network callbacks. */
final class Cat6ReadyAgentLogPolicy {
    static final long STABLE_HEARTBEAT_MILLIS = 300_000L;

    private boolean initialized;
    private long lastWriteMillis;
    private String lastState = "";

    synchronized boolean shouldWrite(
            boolean running,
            String endpointIdentity,
            String nativeReport,
            long monotonicMillis) {
        String state = "running=" + running
                + "|endpoint=" + normalized(endpointIdentity)
                + "|native_running=" + value(nativeReport, "running")
                + "|stage=" + value(nativeReport, "stage")
                + "|startup_errno=" + value(nativeReport, "startup_errno")
                + "|last_socket_errno=" + value(nativeReport, "last_socket_errno")
                + "|network_bound=" + value(nativeReport, "ethernet_network_bound")
                + "|ready_send_failures=" + value(nativeReport, "ready_send_failures")
                + "|primary_send_failures="
                + value(nativeReport, "primary_ready_send_failures")
                + "|broadcast_enabled=" + value(nativeReport, "broadcast_enabled")
                + "|broadcast_socket_errno="
                + value(nativeReport, "broadcast_socket_errno")
                + "|broadcast_send_failures="
                + value(nativeReport, "broadcast_ready_send_failures")
                + "|multicast_interface="
                + value(nativeReport, "multicast_interface_configured")
                + "|multicast_ttl="
                + value(nativeReport, "multicast_ttl_configured")
                + "|probe_ack_failures=" + value(nativeReport, "probe_ack_failures")
                + "|last_requester=" + value(nativeReport, "last_requester_ipv4");
        boolean stateChanged = initialized && !state.equals(lastState);
        boolean heartbeatDue = initialized
                && nonNegativeDifference(monotonicMillis, lastWriteMillis)
                >= STABLE_HEARTBEAT_MILLIS;
        boolean write = !initialized || stateChanged || heartbeatDue;

        initialized = true;
        lastState = state;
        if (write) lastWriteMillis = monotonicMillis;
        return write;
    }

    private static String value(String report, String field) {
        return MobileDiagnosticFieldParser.valueOr(report, field, "missing");
    }

    private static String normalized(String value) {
        return value == null || value.isEmpty() ? "none" : value;
    }

    private static long nonNegativeDifference(long newer, long older) {
        return newer >= older ? newer - older : 0L;
    }
}
