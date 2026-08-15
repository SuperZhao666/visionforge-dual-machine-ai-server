package com.visionforge.inferencebenchmark;

/** Regression contract for Xiaomi task-clean and ordinary Android exits. */
final class MobilePreviousExitPolicySelfTest {
    private MobilePreviousExitPolicySelfTest() {}

    static void run() {
        require(MobilePreviousExitPolicy.classify(
                10, "stop com.visionforge.mobile due to SwipeUpClean")
                == MobilePreviousExitPolicy.Kind.TASK_CLEANED);
        require(MobilePreviousExitPolicy.classify(
                10, "force stop requested by user")
                == MobilePreviousExitPolicy.Kind.USER_STOPPED);
        require(MobilePreviousExitPolicy.classify(3, "lmkd")
                == MobilePreviousExitPolicy.Kind.LOW_MEMORY);
        require(MobilePreviousExitPolicy.classify(4, "java crash")
                == MobilePreviousExitPolicy.Kind.CRASH);
        require(MobilePreviousExitPolicy.classify(5, "native crash")
                == MobilePreviousExitPolicy.Kind.CRASH);
        require(MobilePreviousExitPolicy.classify(6, "input dispatch timeout")
                == MobilePreviousExitPolicy.Kind.ANR);
        require(MobilePreviousExitPolicy.classify(0, null)
                == MobilePreviousExitPolicy.Kind.NONE);
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError(
                    "mobile previous-exit policy contract failed");
        }
    }
}
