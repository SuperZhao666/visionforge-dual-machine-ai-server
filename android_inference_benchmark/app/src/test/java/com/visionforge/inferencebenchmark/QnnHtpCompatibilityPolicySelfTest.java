package com.visionforge.inferencebenchmark;

import java.util.Arrays;

/** Regression matrix for known, missing and future Snapdragon devices. */
final class QnnHtpCompatibilityPolicySelfTest {
    private QnnHtpCompatibilityPolicySelfTest() {}

    static void run() {
        QnnHtpCompatibilityPolicy.Result reference =
                QnnHtpCompatibilityPolicy.evaluate(
                        "Qualcomm SM8650", Arrays.asList("v68", "v75", "v79"));
        require(reference.canAttemptBackend
                && "known_supported".equals(reference.status)
                && "none".equals(reference.failureCode)
                && "SM8650".equals(reference.socModel)
                && "v75".equals(reference.expectedArchitecture));

        QnnHtpCompatibilityPolicy.Result suffixed =
                QnnHtpCompatibilityPolicy.evaluate(
                        "Qualcomm SM8650P", Arrays.asList("v68", "v75", "v79"));
        require(suffixed.canAttemptBackend
                && "known_supported".equals(suffixed.status)
                && "SM8650".equals(suffixed.socModel)
                && "v75".equals(suffixed.expectedArchitecture));

        QnnHtpCompatibilityPolicy.Result iqoo15 =
                QnnHtpCompatibilityPolicy.evaluate(
                        "SM8850-AC", Arrays.asList("v68", "v69", "v73", "v75", "v79"));
        require(!iqoo15.canAttemptBackend
                && "known_architecture_not_packaged".equals(iqoo15.status)
                && "qnn_htp_architecture_not_packaged".equals(iqoo15.failureCode)
                && "v81".equals(iqoo15.expectedArchitecture));

        QnnHtpCompatibilityPolicy.Result iqoo15Ready =
                QnnHtpCompatibilityPolicy.evaluate(
                        "SM8850", Arrays.asList("v75", "V81"));
        require(iqoo15Ready.canAttemptBackend
                && "known_supported".equals(iqoo15Ready.status));

        QnnHtpCompatibilityPolicy.Result future =
                QnnHtpCompatibilityPolicy.evaluate(
                        "future-oem-soc", Arrays.asList("v68", "v79"));
        require(future.canAttemptBackend
                && "unknown_runtime_probe".equals(future.status)
                && "none".equals(future.failureCode)
                && "unknown".equals(future.expectedArchitecture));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("QNN HTP compatibility policy contract failed");
        }
    }
}
