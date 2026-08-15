package com.visionforge.inferencebenchmark;

/** Protects the 150 FPS codec-restart grace window and low-rate true-stall detection. */
final class DecoderOutputStallPolicySelfTest {
    static void run() {
        require(!DecoderOutputStallPolicy.isStalled(30L, 85_000_000L, 1_000_000L));
        require(DecoderOutputStallPolicy.isStalled(30L, 500_000_000L, 1_000_000L));
        require(DecoderOutputStallPolicy.isStalled(3L, 500_000_000L, 1_000_000L));
        require(!DecoderOutputStallPolicy.isStalled(2L, 900_000_000L, 1_000_000L));
        require(!DecoderOutputStallPolicy.isStalled(30L, 900_000_000L, 201_000_000L));
        verifiesStaticResumeReceivesFreshGraceWindow();
        verifiesOutputProgressRestartsGraceWindow();
        verifiesFallbackClassification();
    }

    private static void verifiesStaticResumeReceivesFreshGraceWindow() {
        DecoderOutputProgressTracker tracker = new DecoderOutputProgressTracker();
        tracker.recordQueuedInput(0L);
        tracker.recordDecodedOutput(1_000_000L);

        tracker.recordQueuedInput(5_500_000_000L);
        tracker.recordQueuedInput(5_507_000_000L);
        tracker.recordQueuedInput(5_514_000_000L);
        DecoderOutputProgressTracker.Snapshot resumed = tracker.snapshot(5_514_000_000L);
        require(resumed.backlog == 3L);
        require(!DecoderOutputStallPolicy.isStalled(
                resumed.backlog, resumed.stalledNanos, resumed.inputIdleNanos));

        for (long inputNanos = 5_521_000_000L;
             inputNanos <= 5_997_000_000L; inputNanos += 7_000_000L) {
            tracker.recordQueuedInput(inputNanos);
        }
        DecoderOutputProgressTracker.Snapshot beforeDeadline = tracker.snapshot(5_999_000_000L);
        require(!DecoderOutputStallPolicy.isStalled(
                beforeDeadline.backlog, beforeDeadline.stalledNanos,
                beforeDeadline.inputIdleNanos));
        DecoderOutputProgressTracker.Snapshot atDeadline = tracker.snapshot(6_000_000_000L);
        require(DecoderOutputStallPolicy.isStalled(
                atDeadline.backlog, atDeadline.stalledNanos, atDeadline.inputIdleNanos));
    }

    private static void verifiesOutputProgressRestartsGraceWindow() {
        DecoderOutputProgressTracker tracker = new DecoderOutputProgressTracker();
        tracker.recordQueuedInput(1_000_000_000L);
        tracker.recordQueuedInput(1_007_000_000L);
        tracker.recordQueuedInput(1_014_000_000L);
        tracker.recordQueuedInput(1_021_000_000L);
        for (long inputNanos = 1_028_000_000L;
             inputNanos <= 1_399_000_000L; inputNanos += 7_000_000L) {
            tracker.recordQueuedInput(inputNanos);
        }
        tracker.recordDecodedOutput(1_400_000_000L);
        for (long inputNanos = 1_407_000_000L;
             inputNanos <= 1_897_000_000L; inputNanos += 7_000_000L) {
            tracker.recordQueuedInput(inputNanos);
        }
        DecoderOutputProgressTracker.Snapshot progressed = tracker.snapshot(1_899_000_000L);
        require(!DecoderOutputStallPolicy.isStalled(
                progressed.backlog, progressed.stalledNanos, progressed.inputIdleNanos));
        DecoderOutputProgressTracker.Snapshot stalled = tracker.snapshot(1_900_000_000L);
        require(DecoderOutputStallPolicy.isStalled(
                stalled.backlog, stalled.stalledNanos, stalled.inputIdleNanos));
    }

    private static void verifiesFallbackClassification() {
        require(!DecoderFallbackPolicy.permitsSoftwareFallback(
                DecoderFallbackPolicy.FailureKind.WATCHDOG_STALL));
        require(DecoderFallbackPolicy.permitsSoftwareFallback(
                DecoderFallbackPolicy.FailureKind.CODEC_EXCEPTION));
        require(DecoderFallbackPolicy.permitsSoftwareFallback(
                DecoderFallbackPolicy.FailureKind.CODEC_CONTRACT));
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Decoder output stall policy contract failed");
    }
}
