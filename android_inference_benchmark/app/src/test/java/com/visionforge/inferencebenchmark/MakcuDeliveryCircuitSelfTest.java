package com.visionforge.inferencebenchmark;

/** Dependency-free contract for local USB write completion and fail-closed delivery. */
final class MakcuDeliveryCircuitSelfTest {
    static void run() {
        verifiesUsbWriteCompletionResetsOnlyConsecutiveFailures();
        verifiesThresholdTripsUntilExplicitReconnect();
    }

    private static void verifiesUsbWriteCompletionResetsOnlyConsecutiveFailures() {
        MakcuDeliveryCircuit circuit = new MakcuDeliveryCircuit(3);
        circuit.recordFailure("timeout");
        circuit.recordFailure("partial write");
        require(circuit.snapshot().consecutiveFailures == 2);

        circuit.recordUsbWriteCompletion(41L);
        MakcuDeliveryState state = circuit.snapshot();
        require(state.usbWriteCompletionCount == 1L);
        require(state.failureCount == 2L);
        require(state.consecutiveFailures == 0);
        require(state.lastUsbWriteCallMicros == 41L);
        require(!state.circuitOpen);
    }

    private static void verifiesThresholdTripsUntilExplicitReconnect() {
        MakcuDeliveryCircuit circuit = new MakcuDeliveryCircuit(3);
        circuit.recordFailure("one");
        circuit.recordFailure("two");
        require(!circuit.snapshot().circuitOpen);
        circuit.recordFailure("three");
        require(circuit.snapshot().circuitOpen);
        require(circuit.snapshot().circuitTripCount == 1L);

        circuit.recordUsbWriteCompletion(7L);
        require(circuit.snapshot().circuitOpen);
        circuit.resetAfterSuccessfulReconnect();
        MakcuDeliveryState recovered = circuit.snapshot();
        require(!recovered.circuitOpen);
        require(recovered.consecutiveFailures == 0);
        require(recovered.usbWriteCompletionCount == 1L);
        require(recovered.failureCount == 3L);
        require(recovered.circuitTripCount == 1L);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("MAKCU delivery circuit contract failed");
    }
}
