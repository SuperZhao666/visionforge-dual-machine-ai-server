package com.visionforge.inferencebenchmark;

/** Dependency-free lifecycle contract for replacing stale external health snapshots. */
final class MobileExternalHealthSnapshotPolicySelfTest {
    private static final String CS2_INFERENCE =
            "model=counter-strike-2-vombit-416-v8s aim_target=t_head "
                    + "confidence=0.25 iou=0.45 native_applied=true";

    private MobileExternalHealthSnapshotPolicySelfTest() {}

    static void run() {
        verifiesInitialIdleSnapshotAndBoundedHeartbeat();
        verifiesModelChangeWritesWithoutCounterProgress();
        verifiesRunningToReadyTransitionReplacesRunningSnapshot();
        verifiesFailedWriteRemainsPending();
    }

    private static void verifiesInitialIdleSnapshotAndBoundedHeartbeat() {
        MobileExternalHealthSnapshotPolicy policy = new MobileExternalHealthSnapshotPolicy();
        MobileRuntimeSnapshot idle = idleSnapshot();
        require(policy.shouldWrite("ready", CS2_INFERENCE, idle, false, 1_000L));
        policy.recordSuccessfulWrite("ready", CS2_INFERENCE, idle, 1_000L);
        require(!policy.shouldWrite("ready", CS2_INFERENCE, idle, false, 6_000L));
        require(!policy.shouldWrite("ready", CS2_INFERENCE, idle, false, 300_999L));
        require(policy.shouldWrite("ready", CS2_INFERENCE, idle, false, 301_000L));
    }

    private static void verifiesModelChangeWritesWithoutCounterProgress() {
        MobileExternalHealthSnapshotPolicy policy = new MobileExternalHealthSnapshotPolicy();
        MobileRuntimeSnapshot idle = idleSnapshot();
        String valorant = "model=valorant-yellow-416-v11s-no-flash aim_target=head "
                + "confidence=0.27 iou=0.45 native_applied=true";
        require(policy.shouldWrite("ready", valorant, idle, false, 1_000L));
        policy.recordSuccessfulWrite("ready", valorant, idle, 1_000L);
        require(policy.shouldWrite("ready", CS2_INFERENCE, idle, false, 6_000L));
    }

    private static void verifiesRunningToReadyTransitionReplacesRunningSnapshot() {
        MobileExternalHealthSnapshotPolicy policy = new MobileExternalHealthSnapshotPolicy();
        MobileRuntimeSnapshot running = runningSnapshot();
        require(policy.shouldWrite("running", CS2_INFERENCE, running, true, 1_000L));
        policy.recordSuccessfulWrite("running", CS2_INFERENCE, running, 1_000L);
        require(!policy.shouldWrite("running", CS2_INFERENCE, running, false, 6_000L));
        require(policy.shouldWrite("ready", CS2_INFERENCE, idleSnapshot(), false, 11_000L));
    }

    private static void verifiesFailedWriteRemainsPending() {
        MobileExternalHealthSnapshotPolicy policy = new MobileExternalHealthSnapshotPolicy();
        MobileRuntimeSnapshot idle = idleSnapshot();
        require(policy.shouldWrite("ready", CS2_INFERENCE, idle, false, 1_000L));
        require(policy.shouldWrite("ready", CS2_INFERENCE, idle, false, 6_000L));
        policy.recordSuccessfulWrite("ready", CS2_INFERENCE, idle, 6_000L);
        require(!policy.shouldWrite("ready", CS2_INFERENCE, idle, false, 11_000L));
    }

    private static MobileRuntimeSnapshot idleSnapshot() {
        return MobileRuntimeSnapshot.from("running=0", "configured=0", "ready=1", "");
    }

    private static MobileRuntimeSnapshot runningSnapshot() {
        return MobileRuntimeSnapshot.from(
                "running=1 reassembled_access_units=8 decoder_accepted_access_units=8 "
                        + "completed_access_units=8 repeated_content_access_units=0 "
                        + "last_reassembled_access_unit_age_ms=5",
                "configured=1 rendered_frames=8 fresh_content_outputs=8 "
                        + "repeated_content_outputs=0 qnn_executions=8 qnn_failures=0 "
                        + "consecutive_qnn_failures=0 last_qnn_success_age_ms=5",
                "ready=1", "");
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("external health snapshot lifecycle contract failed");
        }
    }
}
