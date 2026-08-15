package com.visionforge.inferencebenchmark;

/**
 * Process-scoped circuit breaker for a device/model incompatibility.
 *
 * <p>A Service recreation must not restart a known-incompatible QNN backend.
 * Only an explicit operator start or a genuinely new process grants one fresh
 * attempt.</p>
 */
final class MobilePipelineRetryGate {
    private boolean terminalFailureLatched;
    private boolean suppressionReported;
    private String failureCode = "none";
    private String failureDetail = "";

    synchronized boolean canAttempt() {
        return !terminalFailureLatched;
    }

    synchronized boolean authorizeOperatorAttempt() {
        boolean suppressionCleared = terminalFailureLatched;
        terminalFailureLatched = false;
        suppressionReported = false;
        failureCode = "none";
        failureDetail = "";
        return suppressionCleared;
    }

    synchronized boolean latchTerminalFailure(String code, String detail) {
        terminalFailureLatched = true;
        failureCode = code == null ? "unknown" : code;
        failureDetail = detail == null ? "" : detail;
        if (suppressionReported) return false;
        suppressionReported = true;
        return true;
    }

    synchronized String failureCode() {
        return failureCode;
    }

    synchronized String failureDetail() {
        return failureDetail;
    }
}
