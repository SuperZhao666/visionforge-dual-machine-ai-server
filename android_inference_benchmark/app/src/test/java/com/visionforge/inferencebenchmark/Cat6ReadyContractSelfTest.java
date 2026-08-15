package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;

public final class Cat6ReadyContractSelfTest {
    public static void main(String[] arguments) {
        String ready = new String(Cat6ReadyContract.ready(42L), StandardCharsets.US_ASCII);
        require("VF_CAT6_READY_V1|10.57.23.2|42".equals(ready), "ready heartbeat");
        require(Cat6ReadyContract.READY_INTERVAL_MILLIS == 250L, "ready interval");
        require(Cat6ReadyContract.READY_PORT == 5003 && Cat6ReadyContract.PROBE_PORT == 5004,
                "fixed ports");

        byte[] probe = Cat6ReadyContract.probe("host_42-A");
        require(probe.length == Cat6ReadyContract.PROBE_DATAGRAM_BYTES, "fixed probe size");
        byte[] ack = Cat6ReadyContract.probeAck(probe, probe.length);
        require(ack != null && ack.length == probe.length, "fixed ack size");
        String ackHeader = "VF_CAT6_PROBE_ACK_V1|host_42-A|";
        require(ackHeader.equals(new String(ack, 0, ackHeader.length(), StandardCharsets.US_ASCII)),
                "probe ack token");
        require(isZeroPadded(ack, ackHeader.length()), "zero padded ack");

        require(Cat6ReadyContract.probeAck(probe, probe.length - 1) == null,
                "reject non-fixed probe size");
        probe[probe.length - 1] = 1;
        require(Cat6ReadyContract.probeAck(probe, probe.length) == null,
                "reject nonzero tail");
        rejectToken("bad token");
        rejectSequence(-1L);
        rejectSequence(0x1_0000_0000L);
    }

    private static void rejectToken(String token) {
        try {
            Cat6ReadyContract.probe(token);
            throw new AssertionError("invalid token accepted");
        } catch (IllegalArgumentException expected) {
            // Expected contract rejection.
        }
    }

    private static void rejectSequence(long sequence) {
        try {
            Cat6ReadyContract.ready(sequence);
            throw new AssertionError("invalid sequence accepted");
        } catch (IllegalArgumentException expected) {
            // Expected contract rejection.
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static boolean isZeroPadded(byte[] datagram, int headerLength) {
        for (int index = headerLength; index < datagram.length; index++) {
            if (datagram[index] != 0) return false;
        }
        return true;
    }
}
