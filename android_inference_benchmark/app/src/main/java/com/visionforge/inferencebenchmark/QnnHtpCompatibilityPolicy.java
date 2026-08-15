package com.visionforge.inferencebenchmark;

import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Fail-fast policy for known Snapdragon HTP generations.
 *
 * <p>Unknown SoCs deliberately continue to the QNN backend probe. The table is
 * only authoritative when a known SoC requires an architecture that the APK
 * does not contain; graph finalisation remains the final readiness proof.</p>
 */
final class QnnHtpCompatibilityPolicy {
    private static final Pattern SOC_TOKEN = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9])((?:SM|QCM)[0-9]{4})"
                    + "(?:[A-Z])?(?:$|[^A-Z0-9])");

    private QnnHtpCompatibilityPolicy() {}

    static Result evaluate(String reportedSocModel, List<String> packagedArchitectures) {
        String socModel = extractSocModel(reportedSocModel);
        String expectedArchitecture =
                MobileSocCompatibilityPolicy.expectedHtpArchitecture(socModel);
        if (expectedArchitecture == null) {
            return new Result(true, "unknown_runtime_probe", "none",
                    socModel, "unknown");
        }
        boolean packaged = packagedArchitectures != null
                && packagedArchitectures.stream().anyMatch(
                value -> expectedArchitecture.equals(normalizeArchitecture(value)));
        return packaged
                ? new Result(true, "known_supported", "none",
                socModel, expectedArchitecture)
                : new Result(false, "known_architecture_not_packaged",
                "qnn_htp_architecture_not_packaged",
                socModel, expectedArchitecture);
    }

    private static String extractSocModel(String value) {
        if (value == null) return "unknown";
        Matcher matcher = SOC_TOKEN.matcher(value.trim());
        return matcher.find()
                ? matcher.group(1).toUpperCase(Locale.ROOT)
                : "unknown";
    }

    private static String normalizeArchitecture(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    static final class Result {
        final boolean canAttemptBackend;
        final String status;
        final String failureCode;
        final String socModel;
        final String expectedArchitecture;

        Result(
                boolean canAttemptBackend,
                String status,
                String failureCode,
                String socModel,
                String expectedArchitecture) {
            this.canAttemptBackend = canAttemptBackend;
            this.status = status;
            this.failureCode = failureCode;
            this.socModel = socModel;
            this.expectedArchitecture = expectedArchitecture;
        }

        String detail() {
            return "status=" + status
                    + " failure_code=" + failureCode
                    + " soc_model=" + socModel
                    + " expected_htp_architecture=" + expectedArchitecture
                    + " backend_probe_allowed=" + canAttemptBackend;
        }
    }
}
