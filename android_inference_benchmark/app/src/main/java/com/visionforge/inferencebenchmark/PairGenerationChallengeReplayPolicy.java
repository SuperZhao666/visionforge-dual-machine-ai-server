package com.visionforge.inferencebenchmark;

import java.util.Objects;

/**
 * Retains the exact request/allocation IDs for an issued pair-generation
 * challenge. A transport retry can therefore ask the sidecar for its existing
 * challenge instead of colliding with it until the 30-second TTL expires.
 */
final class PairGenerationChallengeReplayPolicy {
    interface IdGenerator {
        String nextHex128();
    }

    static final class Attempt {
        private final String pairContext;
        private final String requestId;
        private final String allocationRequestId;
        private int nextIndex;

        private Attempt(
                String pairContext,
                String requestId,
                String allocationRequestId) {
            this.pairContext = pairContext;
            this.requestId = requestId;
            this.allocationRequestId = allocationRequestId;
        }

        synchronized String nextHex128() {
            if (nextIndex == 0) {
                nextIndex++;
                return requestId;
            }
            if (nextIndex == 1) {
                nextIndex++;
                return allocationRequestId;
            }
            throw new IllegalStateException(
                    "pair-generation attempt requested more than two IDs");
        }
    }

    private final IdGenerator idGenerator;
    private String pairContext;
    private String requestId;
    private String allocationRequestId;
    private long challengeExpiresAtEpoch;

    PairGenerationChallengeReplayPolicy(IdGenerator idGenerator) {
        this.idGenerator = Objects.requireNonNull(idGenerator, "idGenerator");
    }

    synchronized Attempt begin(String expectedPairContext, long nowEpoch) {
        requirePairContext(expectedPairContext);
        requireEpoch(nowEpoch);
        if (requestId == null
                || !expectedPairContext.equals(pairContext)
                || (challengeExpiresAtEpoch > 0L
                        && challengeExpiresAtEpoch <= nowEpoch)) {
            rotate(expectedPairContext);
        }
        return new Attempt(pairContext, requestId, allocationRequestId);
    }

    synchronized void challengeIssued(
            Attempt attempt,
            long expiresAtEpoch,
            long nowEpoch) {
        if (!matches(attempt) || expiresAtEpoch <= nowEpoch || nowEpoch <= 0L) {
            return;
        }
        challengeExpiresAtEpoch = expiresAtEpoch;
    }

    synchronized void failed(
            Attempt attempt,
            String diagnosticStage,
            long nowEpoch) {
        if (!matches(attempt)) return;
        if (nowEpoch <= 0L
                || challengeExpiresAtEpoch <= nowEpoch
                || !challengeReplaySafe(diagnosticStage)) {
            clear();
        }
    }

    synchronized void succeeded(Attempt attempt) {
        if (matches(attempt)) clear();
    }

    synchronized void clear() {
        pairContext = null;
        requestId = null;
        allocationRequestId = null;
        challengeExpiresAtEpoch = 0L;
    }

    private void rotate(String expectedPairContext) {
        String nextRequestId = idGenerator.nextHex128();
        String nextAllocationRequestId = idGenerator.nextHex128();
        requireHex128(nextRequestId);
        requireHex128(nextAllocationRequestId);
        if (nextRequestId.equals(nextAllocationRequestId)) {
            throw new IllegalStateException(
                    "pair-generation request IDs must be distinct");
        }
        pairContext = expectedPairContext;
        requestId = nextRequestId;
        allocationRequestId = nextAllocationRequestId;
        challengeExpiresAtEpoch = 0L;
    }

    private boolean matches(Attempt attempt) {
        return attempt != null
                && attempt.pairContext.equals(pairContext)
                && attempt.requestId.equals(requestId)
                && attempt.allocationRequestId.equals(allocationRequestId);
    }

    private static boolean challengeReplaySafe(String stage) {
        return "channel_connect".equals(stage)
                || "host_hello".equals(stage)
                || "host_challenge_proof".equals(stage)
                || "host_final_proof".equals(stage);
    }

    private static void requirePairContext(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    "pair-generation pair context is required");
        }
    }

    private static void requireEpoch(long value) {
        if (value <= 0L) {
            throw new IllegalArgumentException(
                    "pair-generation epoch is invalid");
        }
    }

    private static void requireHex128(String value) {
        if (value == null || value.length() != 32) {
            throw new IllegalStateException(
                    "pair-generation ID is malformed");
        }
        boolean nonzero = false;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f'))) {
                throw new IllegalStateException(
                        "pair-generation ID is malformed");
            }
            nonzero |= character != '0';
        }
        if (!nonzero) {
            throw new IllegalStateException(
                    "pair-generation ID is malformed");
        }
    }
}
