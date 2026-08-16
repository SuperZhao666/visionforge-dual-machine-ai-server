package com.visionforge.inferencebenchmark;

/** Pure JVM boundary tests for the shared native-move deadline helpers. */
public final class ControlMoveDeadlineSelfTest {
    private ControlMoveDeadlineSelfTest() {
    }

    public static void main(String[] args) {
        run();
    }

    static void run() {
        require(ControlMoveDeadline.deadlineNanos(1_000L, 250L) == 251_000L);
        require(ControlMoveDeadline.deadlineNanos(1_000L, 0L) == 1_000L);
        require(ControlMoveDeadline.deadlineNanos(Long.MAX_VALUE - 10L, 1L)
                == Long.MAX_VALUE);
        require(ControlMoveDeadline.boundedDeadlineNanos(
                Long.MAX_VALUE - 10L, 20L) == Long.MAX_VALUE);
        require(ControlMoveDeadline.earlierDeadline(10L, 20L) == 10L);
        require(ControlMoveDeadline.isExpired(10L, 10L));
        require(!ControlMoveDeadline.isExpired(9L, 10L));
        require(ControlMoveDeadline.remainingNanos(9L, 10L) == 1L);
        require(ControlMoveDeadline.boundedTimeoutMillis(0L, 1L, 25) == 1);
        require(ControlMoveDeadline.boundedTimeoutMillis(
                0L, 24_000_001L, 25) == 25);
        require(ControlMoveDeadline.boundedTimeoutMillis(
                1L, Long.MAX_VALUE, 25) == 25);
        require(ControlMoveDeadline.boundedTimeoutMillis(10L, 10L, 25) == 0);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Control move deadline contract failed");
    }
}
