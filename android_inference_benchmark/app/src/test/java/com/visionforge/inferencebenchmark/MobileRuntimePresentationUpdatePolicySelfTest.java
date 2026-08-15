package com.visionforge.inferencebenchmark;

/** Dependency-free behavior contract for runtime presentation deduplication. */
public final class MobileRuntimePresentationUpdatePolicySelfTest {
    private MobileRuntimePresentationUpdatePolicySelfTest() {
    }

    static void run() {
        identicalMaintenanceTicksDoNotAdvanceRevision();
        semanticChangesAdvanceRevisionImmediately();
        onlyRealRunningEntryShowsTheStartedPresentation();
        identicalForegroundNotificationsAreSuppressed();
    }

    private static void identicalMaintenanceTicksDoNotAdvanceRevision() {
        long revision = 7L;
        for (int tick = 0; tick < 80; tick++) {
            MobileRuntimePresentationUpdatePolicy.StatusDecision decision =
                    MobileRuntimePresentationUpdatePolicy.evaluateStatus(
                            revision,
                            "RUNNING",
                            "formal_usage_lease_continued host_authorization=false",
                            "none",
                            "RUNNING",
                            "formal_usage_lease_continued host_authorization=false",
                            "none");
            require(!decision.shouldPublish);
            require(decision.revision == 7L);
            revision = decision.revision;
        }
    }

    private static void semanticChangesAdvanceRevisionImmediately() {
        MobileRuntimePresentationUpdatePolicy.StatusDecision detailChanged =
                MobileRuntimePresentationUpdatePolicy.evaluateStatus(
                        3L,
                        "RUNNING",
                        "formal_usage_running host_authorization=false",
                        "none",
                        "RUNNING",
                        "formal_usage_lease_continued host_authorization=false",
                        "none");
        require(detailChanged.shouldPublish && detailChanged.revision == 4L);

        MobileRuntimePresentationUpdatePolicy.StatusDecision phaseChanged =
                MobileRuntimePresentationUpdatePolicy.evaluateStatus(
                        detailChanged.revision,
                        "RUNNING",
                        "formal_usage_lease_continued host_authorization=false",
                        "none",
                        "FAILED",
                        "qnn_runtime_failed",
                        "qnn_runtime_failed");
        require(phaseChanged.shouldPublish && phaseChanged.revision == 5L);

        MobileRuntimePresentationUpdatePolicy.StatusDecision failureChanged =
                MobileRuntimePresentationUpdatePolicy.evaluateStatus(
                        phaseChanged.revision,
                        "FAILED",
                        "qnn_runtime_failed",
                        "qnn_runtime_failed",
                        "FAILED",
                        "qnn_runtime_failed",
                        "qnn_htp_architecture_not_packaged");
        require(failureChanged.shouldPublish && failureChanged.revision == 6L);
    }

    private static void onlyRealRunningEntryShowsTheStartedPresentation() {
        require(MobileRuntimePresentationUpdatePolicy.enteredPhase(
                true, "READY", "RUNNING", "RUNNING"));
        require(MobileRuntimePresentationUpdatePolicy.enteredPhase(
                true, null, "RUNNING", "RUNNING"));
        require(!MobileRuntimePresentationUpdatePolicy.enteredPhase(
                true, "RUNNING", "RUNNING", "RUNNING"));
        require(!MobileRuntimePresentationUpdatePolicy.enteredPhase(
                false, "READY", "RUNNING", "RUNNING"));
        require(!MobileRuntimePresentationUpdatePolicy.enteredPhase(
                true, "READY", "FAILED", "RUNNING"));
    }

    private static void identicalForegroundNotificationsAreSuppressed() {
        MobileRuntimePresentationUpdatePolicy policy =
                new MobileRuntimePresentationUpdatePolicy(100);
        require(!policy.shouldPublishNotification(100));
        require(policy.shouldPublishNotification(200));
        require(!policy.shouldPublishNotification(200));
        require(policy.shouldPublishNotification(100));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError(
                    "Mobile runtime presentation update policy failed");
        }
    }
}
