package com.visionforge.inferencebenchmark;

/** Dependency-free contract for bounded mobile metrics logging. */
final class MobileRuntimeMetricsSamplerSelfTest {
    static void run() {
        verifiesSamplingIsBoundedAndIncludesPerformanceFields();
        verifiesStoppedReceiverDoesNotCreateMetricEvents();
        verifiesStoppedSnapshotCanStillBeFormattedForLifecycleEvidence();
    }

    private static void verifiesSamplingIsBoundedAndIncludesPerformanceFields() {
        MobileRuntimeMetricsSampler sampler = new MobileRuntimeMetricsSampler();
        MobileRuntimeSnapshot snapshot = liveSnapshot();
        String first = sampler.sampleIfDue(snapshot, 1_000);
        require(first != null && first.contains("reassembled_access_units=44")
                && first.contains("decoder_accepted_access_units=42")
                && first.contains("network_reassembly_fps=--")
                && first.contains("qnn_p50=1.70 ms"));
        require(sampler.sampleIfDue(snapshot, 5_999) == null);
        String next = sampler.sampleIfDue(
                liveSnapshotWithCounters(342, 110, 340, 230, 230), 6_000);
        require(next != null && next.contains("wire_reassembly_fps=60.0 FPS")
                && next.contains("network_reassembly_fps=40.0 FPS")
                && next.contains("fresh_content_fps=40.0 FPS")
                && next.contains("repeated_content_fps=20.0 FPS")
                && next.contains("decoder_submit_fps=60.0 FPS")
                && next.contains("decoder_output_fps=60.0 FPS")
                && next.contains("fresh_decoder_fps=40.0 FPS")
                && next.contains("qnn_fps=40.0 FPS"));
        MobileRuntimeSnapshot idle =
                liveSnapshotWithCounters(342, 110, 340, 230, 230);
        require(sampler.sampleIfDue(idle, 11_000) != null);
        require(sampler.sampleIfDue(idle, 16_000) == null);
        require(sampler.sampleIfDue(idle, 310_999) == null);
        require(sampler.sampleIfDue(idle, 315_999) != null);
        require(sampler.sampleIfDue(
                liveSnapshotWithCounters(343, 110, 341, 231, 231), 320_999) != null);
    }

    private static void verifiesStoppedReceiverDoesNotCreateMetricEvents() {
        MobileRuntimeSnapshot stopped = MobileRuntimeSnapshot.from("running=0", "configured=0", "ready=0", "");
        require(new MobileRuntimeMetricsSampler().sampleIfDue(stopped, 1_000) == null);
    }

    private static void verifiesStoppedSnapshotCanStillBeFormattedForLifecycleEvidence() {
        MobileRuntimeSnapshot stopped = MobileRuntimeSnapshot.from(
                "running=0 reassembled_access_units=0 completed_access_units=0",
                "configured=0 rendered_frames=0 qnn_executions=0 qnn_failures=0",
                "ready=1", "");
        String current = new MobileRuntimeMetricsSampler().formatCurrent(stopped);
        require(current.contains("rendered_frames=0")
                && current.contains("qnn_executions=0")
                && current.contains("qnn_failures=0")
                && current.contains("qnn_fps=--"));
    }

    private static MobileRuntimeSnapshot liveSnapshot() {
        return MobileRuntimeSnapshot.from(
                "running=1 reassembled_access_units=44 decoder_accepted_access_units=42 "
                        + "completed_access_units=42 repeated_content_access_units=10 "
                        + "last_reassembled_access_unit_age_ms=11 "
                        + "last_completed_access_unit_age_ms=11",
                "configured=1 rendered_frames=40 fresh_content_outputs=30 "
                        + "repeated_content_outputs=10 qnn_executions=30 qnn_failures=0 "
                        + "preprocess{n=40 p50_us=2560 p95_us=3000} "
                        + "qnn{n=40 p50_us=1700 p95_us=2000} "
                        + "decode_queue{n=40 p50_us=6200 p95_us=8000}",
                "ready=1", "MAKCU not connected");
    }

    private static MobileRuntimeSnapshot liveSnapshotWithCounters(
            long accessUnits, long repeatedAccessUnits, long renderedFrames,
            long freshRenderedFrames, long qnnExecutions) {
        return MobileRuntimeSnapshot.from(
                "running=1 reassembled_access_units=" + (accessUnits + 2)
                        + " decoder_accepted_access_units=" + accessUnits
                        + " completed_access_units=" + accessUnits
                        + " repeated_content_access_units=" + repeatedAccessUnits
                        + " last_reassembled_access_unit_age_ms=11 last_completed_access_unit_age_ms=11",
                "configured=1 rendered_frames=" + renderedFrames
                        + " fresh_content_outputs=" + freshRenderedFrames
                        + " repeated_content_outputs=" + (renderedFrames - freshRenderedFrames)
                        + " qnn_executions=" + qnnExecutions
                        + " qnn_failures=0 preprocess{n=1 p50_us=2560 p95_us=3000} "
                        + "qnn{n=1 p50_us=1700 p95_us=2000} decode_queue{n=1 p50_us=6200 p95_us=8000}",
                "ready=1", "");
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Mobile runtime metrics sampler contract failed");
    }
}
