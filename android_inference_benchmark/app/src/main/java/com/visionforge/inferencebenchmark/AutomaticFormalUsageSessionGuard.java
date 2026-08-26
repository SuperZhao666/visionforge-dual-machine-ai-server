package com.visionforge.inferencebenchmark;

import java.util.Locale;

/**
 * Process-local safety policy for automatic formal-usage generations.
 *
 * <p>A paid generation may be opened only while armed. Once that generation
 * closes, ordinary maintenance ticks and a still-running Host stream cannot
 * create another session. The guard re-arms only after the existing 31-bit
 * authenticated control claim proves that the Host operator requested a new
 * stream after the previous data plane was absent. Raw/pre-lease video can
 * update diagnostics but can never re-arm billing.</p>
 */
final class AutomaticFormalUsageSessionGuard {
    static final long MAX_LOGICAL_FRAME_SEQUENCE = 0x7fff_ffffL;

    enum State {
        ARMED,
        START_RESERVED,
        ACTIVE,
        BLOCKED_UNTIL_HOST_PROGRESS_RESUMES,
        BLOCKED_UNTIL_NEW_HOST_STREAM
    }

    enum HostFrameOutcome {
        RECORDED,
        SAME_STREAM_BLOCKED,
        INVALID_IGNORED
    }

    enum HostStartIntentOutcome {
        NEW_START_INTENT_REARMED,
        HOST_ABSENCE_NOT_CONFIRMED,
        DUPLICATE_IGNORED,
        STATE_IGNORED,
        INVALID_IGNORED
    }

    static final class Snapshot {
        final State state;
        final String startRequestId;
        final String channelBindingSha256;
        final long lastHostFrameSequence;
        final boolean progressObserved;
        final long noProgressSinceElapsedMillis;
        final boolean automaticStopSignalled;
        final boolean hostAbsenceConfirmed;
        final long restartCandidateSequence;
        final int restartCandidateConfirmations;
        final long lastHostStartIntentConnectionId;
        final long lastHostStartIntentToken;

        Snapshot(
                State state,
                String startRequestId,
                String channelBindingSha256,
                long lastHostFrameSequence,
                boolean progressObserved,
                long noProgressSinceElapsedMillis,
                boolean automaticStopSignalled,
                boolean hostAbsenceConfirmed,
                long restartCandidateSequence,
                int restartCandidateConfirmations,
                long lastHostStartIntentConnectionId,
                long lastHostStartIntentToken) {
            this.state = state;
            this.startRequestId = startRequestId;
            this.channelBindingSha256 = channelBindingSha256;
            this.lastHostFrameSequence = lastHostFrameSequence;
            this.progressObserved = progressObserved;
            this.noProgressSinceElapsedMillis = noProgressSinceElapsedMillis;
            this.automaticStopSignalled = automaticStopSignalled;
            this.hostAbsenceConfirmed = hostAbsenceConfirmed;
            this.restartCandidateSequence = restartCandidateSequence;
            this.restartCandidateConfirmations =
                    restartCandidateConfirmations;
            this.lastHostStartIntentConnectionId =
                    lastHostStartIntentConnectionId;
            this.lastHostStartIntentToken = lastHostStartIntentToken;
        }

        String detail() {
            return "state=" + state.name().toLowerCase(Locale.ROOT)
                    + " reservation_owned=" + !startRequestId.isEmpty()
                    + " last_host_frame_sequence=" + lastHostFrameSequence
                    + " progress_observed=" + progressObserved
                    + " automatic_stop_signalled=" + automaticStopSignalled
                    + " host_absence_confirmed=" + hostAbsenceConfirmed
                    + " restart_candidate_sequence="
                    + restartCandidateSequence
                    + " restart_candidate_confirmations="
                    + restartCandidateConfirmations
                    + " last_host_start_intent_connection_id="
                    + Long.toUnsignedString(lastHostStartIntentConnectionId)
                    + " last_host_start_intent_token="
                    + lastHostStartIntentToken;
        }
    }

    private State state = State.ARMED;
    private String startRequestId = "";
    private String channelBindingSha256 = "";
    private long lastHostFrameSequence = -1L;
    private boolean progressObserved;
    private long noProgressSinceElapsedMillis = -1L;
    private boolean automaticStopSignalled;
    private long hostAbsentSinceElapsedMillis = -1L;
    private boolean hostAbsenceConfirmed;
    private long restartCandidateSequence = -1L;
    private int restartCandidateConfirmations;
    private long lastHostStartIntentConnectionId;
    private long lastHostStartIntentToken;

    synchronized boolean isAutomaticStartAllowed() {
        return state == State.ARMED;
    }

    synchronized boolean requiresHostRearmProbe() {
        return state == State.BLOCKED_UNTIL_HOST_PROGRESS_RESUMES
                || state == State.BLOCKED_UNTIL_NEW_HOST_STREAM;
    }

    synchronized HostFrameOutcome recordHostFrame(long logicalFrameSequence) {
        if (!isValidFrameSequence(logicalFrameSequence)) {
            return HostFrameOutcome.INVALID_IGNORED;
        }
        boolean blocked = state == State.BLOCKED_UNTIL_HOST_PROGRESS_RESUMES
                || state == State.BLOCKED_UNTIL_NEW_HOST_STREAM;
        lastHostFrameSequence = logicalFrameSequence;
        if (!blocked) {
            resetHostRestartEvidence();
            return HostFrameOutcome.RECORDED;
        }
        // Defense in depth: even a syntactically valid sequence reset is not
        // an authority to create a new paid generation. Only the one-shot
        // claim on the VFB1-derived authenticated control channel can re-arm.
        resetHostRestartEvidence();
        return HostFrameOutcome.SAME_STREAM_BLOCKED;
    }

    synchronized HostStartIntentOutcome recordAuthenticatedHostStartIntent(
            long connectionId,
            long intentToken) {
        if (connectionId == 0L || intentToken <= 0L) {
            return HostStartIntentOutcome.INVALID_IGNORED;
        }
        if (!requiresHostRearmProbe()) {
            return HostStartIntentOutcome.STATE_IGNORED;
        }
        if (connectionId == lastHostStartIntentConnectionId
                && intentToken == lastHostStartIntentToken) {
            return HostStartIntentOutcome.DUPLICATE_IGNORED;
        }
        if (!hostAbsenceConfirmed) {
            return HostStartIntentOutcome.HOST_ABSENCE_NOT_CONFIRMED;
        }
        state = State.ARMED;
        clearOwner();
        lastHostStartIntentConnectionId = connectionId;
        lastHostStartIntentToken = intentToken;
        resetProgressWatchdog();
        resetHostRestartEvidence();
        return HostStartIntentOutcome.NEW_START_INTENT_REARMED;
    }

    synchronized boolean reserveFormalStart(
            String expectedStartRequestId,
            String expectedChannelBindingSha256) {
        requireOwner(expectedStartRequestId, expectedChannelBindingSha256);
        if (state == State.START_RESERVED
                && isOwnedBy(
                expectedStartRequestId,
                expectedChannelBindingSha256)) {
            return false;
        }
        if (state != State.ARMED) {
            throw new IllegalStateException(
                    "automatic formal usage is not armed");
        }
        state = State.START_RESERVED;
        startRequestId = expectedStartRequestId;
        channelBindingSha256 = expectedChannelBindingSha256;
        resetProgressWatchdog();
        resetHostRestartEvidence();
        return true;
    }

    synchronized boolean cancelUnbilledStartReservation(
            String expectedStartRequestId,
            String expectedChannelBindingSha256) {
        if (state != State.START_RESERVED
                || !isOwnedBy(
                expectedStartRequestId,
                expectedChannelBindingSha256)) {
            return false;
        }
        state = State.ARMED;
        clearOwner();
        resetProgressWatchdog();
        resetHostRestartEvidence();
        return true;
    }

    synchronized void markFormalSessionOpened(
            String expectedStartRequestId,
            String expectedChannelBindingSha256) {
        if (state != State.START_RESERVED
                || !isOwnedBy(
                expectedStartRequestId,
                expectedChannelBindingSha256)) {
            throw new IllegalStateException(
                    "automatic formal usage start owner does not match");
        }
        state = State.ACTIVE;
        resetProgressWatchdog();
        resetHostRestartEvidence();
    }

    synchronized boolean markFormalSessionClosed(
            String expectedStartRequestId,
            String expectedChannelBindingSha256) {
        if (state != State.ACTIVE
                || !isOwnedBy(
                expectedStartRequestId,
                expectedChannelBindingSha256)) {
            return false;
        }
        state = State.BLOCKED_UNTIL_HOST_PROGRESS_RESUMES;
        clearOwner();
        resetProgressWatchdog();
        resetHostRestartEvidence();
        return true;
    }

    synchronized boolean blockPotentiallyBilledGeneration(
            String expectedStartRequestId,
            String expectedChannelBindingSha256) {
        if ((state != State.ACTIVE && state != State.START_RESERVED)
                || !isOwnedBy(
                expectedStartRequestId,
                expectedChannelBindingSha256)) {
            return false;
        }
        state = State.BLOCKED_UNTIL_NEW_HOST_STREAM;
        clearOwner();
        resetProgressWatchdog();
        resetHostRestartEvidence();
        return true;
    }

    synchronized void restoreBlocked(long logicalFrameSequence) {
        restoreBlocked(logicalFrameSequence, false);
    }

    synchronized void restoreBlocked(
            long logicalFrameSequence,
            boolean hostProgressMayResume) {
        state = hostProgressMayResume
                ? State.BLOCKED_UNTIL_HOST_PROGRESS_RESUMES
                : State.BLOCKED_UNTIL_NEW_HOST_STREAM;
        clearOwner();
        lastHostFrameSequence = isValidFrameSequence(logicalFrameSequence)
                ? logicalFrameSequence : -1L;
        resetProgressWatchdog();
        resetHostRestartEvidence();
    }

    synchronized boolean recordHostAbsent(
            long nowElapsedMillis,
            long requiredAbsenceMillis) {
        if (nowElapsedMillis < 0L || requiredAbsenceMillis <= 0L) {
            throw new IllegalArgumentException(
                    "valid monotonic time and absence threshold are required");
        }
        if (state != State.BLOCKED_UNTIL_NEW_HOST_STREAM
                && state != State.BLOCKED_UNTIL_HOST_PROGRESS_RESUMES) {
            resetHostRestartEvidence();
            return false;
        }
        if (hostAbsentSinceElapsedMillis < 0L) {
            hostAbsentSinceElapsedMillis = nowElapsedMillis;
            return false;
        }
        if (nowElapsedMillis - hostAbsentSinceElapsedMillis
                < requiredAbsenceMillis) {
            return false;
        }
        hostAbsenceConfirmed = true;
        return true;
    }

    synchronized void markProgressRenewed() {
        if (state != State.ACTIVE) return;
        progressObserved = true;
        noProgressSinceElapsedMillis = -1L;
        automaticStopSignalled = false;
    }

    synchronized boolean shouldStopAfterNoProgress(
            long nowElapsedMillis,
            long sustainedNoProgressMillis) {
        if (nowElapsedMillis < 0L || sustainedNoProgressMillis <= 0L) {
            throw new IllegalArgumentException(
                    "valid monotonic time and threshold are required");
        }
        if (state != State.ACTIVE || !progressObserved
                || automaticStopSignalled) {
            noProgressSinceElapsedMillis = -1L;
            return false;
        }
        if (noProgressSinceElapsedMillis < 0L) {
            noProgressSinceElapsedMillis = nowElapsedMillis;
            return false;
        }
        if (nowElapsedMillis - noProgressSinceElapsedMillis
                < sustainedNoProgressMillis) {
            return false;
        }
        automaticStopSignalled = true;
        return true;
    }

    synchronized Snapshot snapshot() {
        return new Snapshot(
                state,
                startRequestId,
                channelBindingSha256,
                lastHostFrameSequence,
                progressObserved,
                noProgressSinceElapsedMillis,
                automaticStopSignalled,
                hostAbsenceConfirmed,
                restartCandidateSequence,
                restartCandidateConfirmations,
                lastHostStartIntentConnectionId,
                lastHostStartIntentToken);
    }

    private void resetProgressWatchdog() {
        progressObserved = false;
        noProgressSinceElapsedMillis = -1L;
        automaticStopSignalled = false;
    }

    private void resetHostRestartEvidence() {
        hostAbsentSinceElapsedMillis = -1L;
        hostAbsenceConfirmed = false;
        restartCandidateSequence = -1L;
        restartCandidateConfirmations = 0;
    }

    private boolean isOwnedBy(
            String expectedStartRequestId,
            String expectedChannelBindingSha256) {
        return startRequestId.equals(expectedStartRequestId)
                && channelBindingSha256.equals(
                expectedChannelBindingSha256);
    }

    private void clearOwner() {
        startRequestId = "";
        channelBindingSha256 = "";
    }

    private static void requireOwner(
            String expectedStartRequestId,
            String expectedChannelBindingSha256) {
        if (expectedStartRequestId == null
                || expectedStartRequestId.isEmpty()
                || expectedChannelBindingSha256 == null
                || expectedChannelBindingSha256.isEmpty()) {
            throw new IllegalArgumentException(
                    "automatic formal usage owner is required");
        }
    }

    private static boolean isValidFrameSequence(long value) {
        return value >= 0L && value <= MAX_LOGICAL_FRAME_SEQUENCE;
    }

}
