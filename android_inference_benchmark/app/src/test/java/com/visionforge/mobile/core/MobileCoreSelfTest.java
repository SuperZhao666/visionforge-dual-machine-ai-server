package com.visionforge.mobile.core;

import com.visionforge.mobile.domain.video.VideoFragmentHeader;

import java.time.Duration;
import java.util.Arrays;

public final class MobileCoreSelfTest {
    private MobileCoreSelfTest() {}

    private static void check(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }

    private static void testWireVector() {
        WireHeader header = new WireHeader(WirePacketKind.DATA, 0x0102030405060708L,
                0x11223344L, 2, 5);
        byte[] expected = new byte[] {
                'V', 'F', '2', 'G',
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x11, 0x22, 0x33, 0x44,
                0x00, 0x02, 0x00, 0x05
        };
        check(Arrays.equals(header.encode(), expected), "wire vector drifted from native protocol");
        check(WireHeader.decode(expected).equals(header), "wire header failed to round-trip");
        try {
            WireHeader.decode(new byte[19]);
            throw new AssertionError("short header was accepted");
        } catch (IllegalArgumentException expectedFailure) {
            // Expected.
        }
        try {
            new WireHeader(WirePacketKind.DATA, 1L, 1L, 0, WireHeader.MAX_FRAGMENTS + 1);
            throw new AssertionError("fragment limit drifted from native protocol");
        } catch (IllegalArgumentException expectedFailure) {
            // Expected.
        }
    }

    private static void testEpochRetirement() {
        EpochGuard guard = new EpochGuard(2);
        check(guard.observe(10L) == EpochGuard.Decision.SWITCHED, "initial epoch not selected");
        check(guard.observe(10L) == EpochGuard.Decision.CURRENT, "current epoch not recognized");
        check(guard.observe(11L) == EpochGuard.Decision.SWITCHED, "new epoch not selected");
        check(guard.observe(10L) == EpochGuard.Decision.RETIRED, "retired epoch reclaimed receiver");
        check(guard.observe(12L) == EpochGuard.Decision.SWITCHED, "second switch failed");
        check(guard.observe(13L) == EpochGuard.Decision.SWITCHED, "third switch failed");
        check(guard.isRetired(10L), "old epoch revived after retirement history pressure");
    }

    private static void testRestartCoalescing() {
        DecoderRestartCoordinator coordinator = new DecoderRestartCoordinator();
        check(coordinator.request(20L) == DecoderRestartCoordinator.RequestDecision.START_NOW,
                "first restart was not started");
        check(coordinator.request(21L) == DecoderRestartCoordinator.RequestDecision.COALESCED,
                "newer epoch was not coalesced");
        DecoderRestartCoordinator.Completion completion = coordinator.complete(20L);
        check(!completion.settled() && completion.nextEpoch().orElseThrow() == 21L,
                "completion did not converge on latest epoch");
        check(coordinator.complete(20L).decision()
                        == DecoderRestartCoordinator.CompletionDecision.STALE_CALLBACK,
                "late completion was not classified as stale");
        check(coordinator.complete(21L).settled(), "latest restart did not settle");
        check(!coordinator.inFlight(), "restart remained in flight");

        check(coordinator.request(30L) == DecoderRestartCoordinator.RequestDecision.START_NOW,
                "second restart did not start");
        check(coordinator.request(29L) == DecoderRestartCoordinator.RequestDecision.STALE,
                "older epoch changed restart target");
        check(coordinator.complete(31L).decision()
                        == DecoderRestartCoordinator.CompletionDecision.INVALID_FUTURE_CALLBACK,
                "future completion was not rejected");
        check(coordinator.abort(30L), "active restart could not be aborted");
    }

    private static void testReadModel() {
        AtomicRuntimeReadModel readModel = new AtomicRuntimeReadModel("corr-1");
        RuntimeSnapshot next = new RuntimeSnapshot(
                RuntimeSnapshot.Lifecycle.RECOVERING,
                RuntimeSnapshot.VideoState.WAITING_FOR_IDR,
                RuntimeSnapshot.TransportState.READY,
                RuntimeSnapshot.ControlBlocker.WAITING_FRESH_IDR,
                99L,
                7L,
                3L,
                Duration.ofMillis(12),
                "corr-1");
        readModel.publish(next);
        check(readModel.snapshot().equals(next), "read model did not publish atomically");
        RuntimeSnapshot maximumEpoch = new RuntimeSnapshot(
                RuntimeSnapshot.Lifecycle.RUNNING,
                RuntimeSnapshot.VideoState.DECODING,
                RuntimeSnapshot.TransportState.READY,
                RuntimeSnapshot.ControlBlocker.RUNNABLE,
                Long.MAX_VALUE,
                VideoFragmentHeader.UINT32_MAX,
                1L,
                Duration.ZERO,
                "corr-max");
        check(maximumEpoch.streamEpoch() == Long.MAX_VALUE,
                "maximum shared signed-long epoch was rejected by read model");
        try {
            new RuntimeSnapshot(
                    RuntimeSnapshot.Lifecycle.RUNNING,
                    RuntimeSnapshot.VideoState.DECODING,
                    RuntimeSnapshot.TransportState.READY,
                    RuntimeSnapshot.ControlBlocker.RUNNABLE,
                    Long.MIN_VALUE,
                    1L,
                    1L,
                    Duration.ZERO,
                    "corr-invalid");
            throw new AssertionError("negative Java epoch escaped the cross-language contract");
        } catch (IllegalArgumentException expectedFailure) {
            // Expected: C++ and Java share the positive signed-long epoch range.
        }
    }

    public static void main(String[] args) {
        testWireVector();
        testEpochRetirement();
        testRestartCoalescing();
        testReadModel();
        System.out.println("VISIONFORGE_MOBILE_CORE_TESTS_OK");
    }
}
