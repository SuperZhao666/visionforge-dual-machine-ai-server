package com.visionforge.inferencebenchmark;

/** Regression for the repeated HTTP-rejection prepare/start loop. */
final class AutomaticFormalStartRetryPolicySelfTest {
    private AutomaticFormalStartRetryPolicySelfTest() {}

    static void run() {
        AutomaticFormalStartRetryPolicy policy =
                new AutomaticFormalStartRetryPolicy();
        long[] expectedDelays = {
                1_000L, 2_000L, 4_000L, 8_000L,
                16_000L, 30_000L, 30_000L
        };
        for (int index = 0; index < expectedDelays.length; index++) {
            AutomaticFormalStartRetryPolicy.Decision decision =
                    policy.recordRejection();
            require(decision.consecutiveRejections == index + 1);
            require(decision.retryDelayMillis == expectedDelays[index]);
        }
        policy.reset();
        AutomaticFormalStartRetryPolicy.Decision reset =
                policy.recordRejection();
        require(reset.consecutiveRejections == 1);
        require(reset.retryDelayMillis == 1_000L);
        require(AutomaticFormalStartRetryPolicy.retryDelayMillis(0)
                == 1_000L);
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError(
                    "automatic formal-start retry policy failed");
        }
    }
}
