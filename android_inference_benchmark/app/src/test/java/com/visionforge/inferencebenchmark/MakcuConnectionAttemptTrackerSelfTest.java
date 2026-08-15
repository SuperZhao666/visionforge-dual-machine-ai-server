package com.visionforge.inferencebenchmark;

/** Dependency-free contract for stale USB permission and reconnect rejection. */
final class MakcuConnectionAttemptTrackerSelfTest {
    static void run() {
        MakcuConnectionAttemptTracker tracker = new MakcuConnectionAttemptTracker();
        MakcuConnectionAttemptTracker.Attempt first = tracker.begin("device-a", true);
        require(tracker.isPermissionPendingFor("device-a"));
        require(!tracker.consumePermission(first.generation, "device-b"));
        require(tracker.consumePermission(first.generation, "device-a"));
        require(!tracker.consumePermission(first.generation, "device-a"));

        MakcuConnectionAttemptTracker.Attempt second = tracker.begin("device-b", false);
        require(!tracker.isCurrent(first.generation, "device-a"));
        require(tracker.isCurrent(second.generation, "device-b"));
        require(tracker.isForDevice("device-b"));
        tracker.cancel();
        require(!tracker.isCurrent(second.generation, "device-b"));

        MakcuConnectionAttemptTracker.Attempt third = tracker.begin("device-c", false);
        tracker.clearIfCurrent(third.generation, "device-c");
        require(!tracker.isForDevice("device-c"));
        MakcuConnectionAttemptTracker.Snapshot snapshot = tracker.snapshot();
        require(snapshot.deviceName == null);
        require(!snapshot.permissionPending);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("MAKCU connection attempt contract failed");
    }
}
