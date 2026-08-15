package com.visionforge.inferencebenchmark;

/** Keeps Ethernet diagnostics actionable without turning a missing link into a log storm. */
final class MobileEthernetDiagnosticsLogPolicy {
    static final long STABLE_HEARTBEAT_MILLIS = 30_000L;

    private boolean initialized;
    private long lastWriteMillis;
    private String lastDiagnosticState = "";

    synchronized boolean shouldWrite(String diagnosticState, long monotonicMillis) {
        boolean stateChanged = initialized && !diagnosticState.equals(lastDiagnosticState);
        boolean heartbeatDue = initialized
                && nonNegativeDifference(monotonicMillis, lastWriteMillis)
                >= STABLE_HEARTBEAT_MILLIS;
        boolean write = !initialized || stateChanged || heartbeatDue;

        initialized = true;
        lastDiagnosticState = diagnosticState;
        if (write) lastWriteMillis = monotonicMillis;
        return write;
    }

    private static long nonNegativeDifference(long newer, long older) {
        return newer >= older ? newer - older : 0L;
    }
}
