package com.visionforge.inferencebenchmark;

import java.util.ArrayDeque;
import java.util.Arrays;

/** Regression for the 30-second pending pair-generation challenge stall. */
final class PairGenerationChallengeReplayPolicySelfTest {
    private static final String PAIR_A = "1".repeat(32);
    private static final String PAIR_B = "2".repeat(32);

    private PairGenerationChallengeReplayPolicySelfTest() {}

    static void run() {
        reusesExactIdsUntilTheIssuedChallengeExpires();
        rotatesAfterCredentialPhaseOrPairChange();
    }

    private static void reusesExactIdsUntilTheIssuedChallengeExpires() {
        ArrayDeque<String> ids = ids('a', 'b', 'c', 'd');
        PairGenerationChallengeReplayPolicy policy =
                new PairGenerationChallengeReplayPolicy(ids::removeFirst);

        PairGenerationChallengeReplayPolicy.Attempt first =
                policy.begin(PAIR_A, 100L);
        require("a".repeat(32).equals(first.nextHex128()));
        require("b".repeat(32).equals(first.nextHex128()));
        policy.challengeIssued(first, 130L, 101L);
        policy.failed(first, "host_final_proof", 102L);

        PairGenerationChallengeReplayPolicy.Attempt replay =
                policy.begin(PAIR_A, 104L);
        require("a".repeat(32).equals(replay.nextHex128()));
        require("b".repeat(32).equals(replay.nextHex128()));
        policy.failed(replay, "host_challenge_proof", 105L);

        PairGenerationChallengeReplayPolicy.Attempt stillReplay =
                policy.begin(PAIR_A, 129L);
        require("a".repeat(32).equals(stillReplay.nextHex128()));
        require("b".repeat(32).equals(stillReplay.nextHex128()));

        PairGenerationChallengeReplayPolicy.Attempt expired =
                policy.begin(PAIR_A, 130L);
        require("c".repeat(32).equals(expired.nextHex128()));
        require("d".repeat(32).equals(expired.nextHex128()));
    }

    private static void rotatesAfterCredentialPhaseOrPairChange() {
        ArrayDeque<String> ids = ids('1', '2', '3', '4', '5', '6');
        PairGenerationChallengeReplayPolicy policy =
                new PairGenerationChallengeReplayPolicy(ids::removeFirst);

        PairGenerationChallengeReplayPolicy.Attempt first =
                policy.begin(PAIR_A, 200L);
        first.nextHex128();
        first.nextHex128();
        policy.challengeIssued(first, 230L, 201L);
        policy.failed(first, "host_handshake_signature", 202L);

        PairGenerationChallengeReplayPolicy.Attempt afterCredential =
                policy.begin(PAIR_A, 203L);
        require("3".repeat(32).equals(afterCredential.nextHex128()));
        require("4".repeat(32).equals(afterCredential.nextHex128()));

        PairGenerationChallengeReplayPolicy.Attempt changedPair =
                policy.begin(PAIR_B, 204L);
        require("5".repeat(32).equals(changedPair.nextHex128()));
        require("6".repeat(32).equals(changedPair.nextHex128()));
    }

    private static ArrayDeque<String> ids(char... values) {
        ArrayDeque<String> output = new ArrayDeque<>();
        Arrays.stream(new String(values).split(""))
                .forEach(value -> output.add(value.repeat(32)));
        return output;
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError(
                    "pair-generation challenge replay policy failed");
        }
    }
}
