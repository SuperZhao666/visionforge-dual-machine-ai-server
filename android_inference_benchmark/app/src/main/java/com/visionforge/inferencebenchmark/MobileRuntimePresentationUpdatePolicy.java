package com.visionforge.inferencebenchmark;

import java.util.Objects;

/**
 * Pure policy for publishing user-visible runtime status and notification changes.
 *
 * <p>Formal lease continuation is a data-plane obligation, not a new UI transition.
 * Keeping the semantic comparison here prevents maintenance ticks from manufacturing
 * revisions, transient "started" notes, or repeated foreground notifications.</p>
 */
final class MobileRuntimePresentationUpdatePolicy {
    static final class StatusDecision {
        final boolean shouldPublish;
        final long revision;

        private StatusDecision(boolean shouldPublish, long revision) {
            this.shouldPublish = shouldPublish;
            this.revision = revision;
        }
    }

    private int lastNotificationTextResource;

    MobileRuntimePresentationUpdatePolicy(int initialNotificationTextResource) {
        lastNotificationTextResource = initialNotificationTextResource;
    }

    static StatusDecision evaluateStatus(
            long previousRevision,
            String previousPhase,
            String previousDetail,
            String previousFailureCode,
            String nextPhase,
            String nextDetail,
            String nextFailureCode) {
        boolean changed = !Objects.equals(previousPhase, nextPhase)
                || !Objects.equals(previousDetail, nextDetail)
                || !Objects.equals(previousFailureCode, nextFailureCode);
        return new StatusDecision(
                changed,
                changed ? previousRevision + 1L : previousRevision);
    }

    static boolean enteredPhase(
            boolean statusChanged,
            String previousPhase,
            String currentPhase,
            String expectedPhase) {
        return statusChanged
                && Objects.equals(currentPhase, expectedPhase)
                && !Objects.equals(previousPhase, expectedPhase);
    }

    synchronized boolean shouldPublishNotification(int textResource) {
        if (textResource == lastNotificationTextResource) return false;
        lastNotificationTextResource = textResource;
        return true;
    }
}
