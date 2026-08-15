package com.visionforge.inferencebenchmark;

/** Tracks one generation-bound USB permission/open attempt. */
final class MakcuConnectionAttemptTracker {
    static final class Attempt {
        final long generation;
        final String deviceName;

        Attempt(long generation, String deviceName) {
            this.generation = generation;
            this.deviceName = deviceName;
        }
    }

    static final class Snapshot {
        final long generation;
        final String deviceName;
        final boolean permissionPending;

        private Snapshot(long generation, String deviceName, boolean permissionPending) {
            this.generation = generation;
            this.deviceName = deviceName;
            this.permissionPending = permissionPending;
        }
    }

    private long generation;
    private String deviceName;
    private boolean permissionPending;

    synchronized Attempt begin(String nextDeviceName, boolean waitingForPermission) {
        generation++;
        deviceName = nextDeviceName;
        permissionPending = waitingForPermission;
        return new Attempt(generation, nextDeviceName);
    }

    synchronized boolean isCurrent(long expectedGeneration, String expectedDeviceName) {
        return generation == expectedGeneration && sameDevice(deviceName, expectedDeviceName);
    }

    synchronized boolean consumePermission(long expectedGeneration, String expectedDeviceName) {
        if (!permissionPending || !isCurrent(expectedGeneration, expectedDeviceName)) return false;
        permissionPending = false;
        return true;
    }

    synchronized boolean isPermissionPendingFor(String expectedDeviceName) {
        return permissionPending && sameDevice(deviceName, expectedDeviceName);
    }

    synchronized boolean isForDevice(String expectedDeviceName) {
        return sameDevice(deviceName, expectedDeviceName);
    }

    synchronized void clearIfCurrent(long expectedGeneration, String expectedDeviceName) {
        if (!isCurrent(expectedGeneration, expectedDeviceName)) return;
        deviceName = null;
        permissionPending = false;
    }

    synchronized void cancel() {
        generation++;
        deviceName = null;
        permissionPending = false;
    }

    synchronized Snapshot snapshot() {
        return new Snapshot(generation, deviceName, permissionPending);
    }

    private static boolean sameDevice(String first, String second) {
        return first != null && first.equals(second);
    }
}
