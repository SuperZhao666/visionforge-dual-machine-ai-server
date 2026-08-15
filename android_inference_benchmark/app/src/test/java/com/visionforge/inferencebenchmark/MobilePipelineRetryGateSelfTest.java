package com.visionforge.inferencebenchmark;

/** Dependency-free contract for the process-scoped terminal retry circuit. */
final class MobilePipelineRetryGateSelfTest {
    static void run() {
        MobilePipelineRetryGate gate = new MobilePipelineRetryGate();
        require(gate.canAttempt());
        require(!gate.authorizeOperatorAttempt());
        require(gate.latchTerminalFailure("unsupported", "device mismatch"));
        require(!gate.canAttempt());
        require(!gate.latchTerminalFailure("unsupported", "device mismatch"));
        require(!gate.canAttempt());
        require("unsupported".equals(gate.failureCode()));
        require("device mismatch".equals(gate.failureDetail()));

        require(gate.authorizeOperatorAttempt());
        require(gate.canAttempt());
        require(!gate.authorizeOperatorAttempt());
        require(gate.latchTerminalFailure("unsupported", "second attempt"));
        require(!gate.canAttempt());

        MobilePipelineRetryGate coldProcessGate = new MobilePipelineRetryGate();
        require(coldProcessGate.canAttempt());
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Mobile retry gate contract failed");
    }
}
