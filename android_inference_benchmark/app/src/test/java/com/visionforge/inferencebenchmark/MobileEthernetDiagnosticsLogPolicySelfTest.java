package com.visionforge.inferencebenchmark;

/** Dependency-free contract for throttled Ethernet diagnostics. */
public final class MobileEthernetDiagnosticsLogPolicySelfTest {
    private MobileEthernetDiagnosticsLogPolicySelfTest() {
    }

    public static void run() {
        writesFirstObservation();
        suppressesUnchangedStableStateUntilHeartbeat();
        writesStateChangesImmediately();
    }

    private static void writesFirstObservation() {
        MobileEthernetDiagnosticsLogPolicy policy = new MobileEthernetDiagnosticsLogPolicy();
        require(policy.shouldWrite("eth0:no_ipv4", 1_000L));
    }

    private static void suppressesUnchangedStableStateUntilHeartbeat() {
        MobileEthernetDiagnosticsLogPolicy policy = new MobileEthernetDiagnosticsLogPolicy();
        require(policy.shouldWrite("eth0:no_ipv4", 1_000L));
        require(!policy.shouldWrite("eth0:no_ipv4", 1_100L));
        require(!policy.shouldWrite("eth0:no_ipv4",
                1_000L + MobileEthernetDiagnosticsLogPolicy.STABLE_HEARTBEAT_MILLIS - 1L));
        require(policy.shouldWrite("eth0:no_ipv4",
                1_000L + MobileEthernetDiagnosticsLogPolicy.STABLE_HEARTBEAT_MILLIS));
    }

    private static void writesStateChangesImmediately() {
        MobileEthernetDiagnosticsLogPolicy policy = new MobileEthernetDiagnosticsLogPolicy();
        require(policy.shouldWrite("eth0:no_ipv4", 1_000L));
        require(policy.shouldWrite("eth0:ready_ipv4", 1_100L));
        require(!policy.shouldWrite("eth0:ready_ipv4", 1_200L));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("Mobile Ethernet diagnostics log policy contract failed");
        }
    }
}
