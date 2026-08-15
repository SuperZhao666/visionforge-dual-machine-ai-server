package com.visionforge.inferencebenchmark;

/** Dependency-free contract proving the latest snapshot carries CS2 model ownership. */
final class MobileExternalHealthSnapshotFormatterSelfTest {
    private MobileExternalHealthSnapshotFormatterSelfTest() {}

    static void run() {
        String payload = MobileExternalHealthSnapshotFormatter.format(
                1_785_653_754_606L,
                94_123_456L,
                "ready",
                "model=counter-strike-2-vombit-416-v8s aim_target=t_head "
                        + "confidence=0.25 iou=0.45 native_applied=true",
                "rendered_frames=0 qnn_executions=0 qnn_failures=0 qnn_fps=--",
                "target_switches=0 motion_plans=0 direction_flips=0,0");

        require(payload.startsWith(
                "timestamp_unix_ms=1785653754606 monotonic_ms=94123456 phase=ready "));
        require(payload.contains("model=counter-strike-2-vombit-416-v8s"));
        require(payload.contains("aim_target=t_head"));
        require(payload.contains("native_applied=true"));
        require(payload.contains("rendered_frames=0 qnn_executions=0 qnn_failures=0"));
        require(payload.contains("target_switches=0 motion_plans=0 direction_flips=0,0"));
        require(payload.endsWith("\n") && payload.indexOf('\n') == payload.length() - 1);
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("external health snapshot formatting contract failed");
        }
    }
}
