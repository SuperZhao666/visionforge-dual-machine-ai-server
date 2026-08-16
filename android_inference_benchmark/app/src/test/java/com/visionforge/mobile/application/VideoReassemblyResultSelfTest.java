package com.visionforge.mobile.application;

import java.util.Arrays;

/** Verifies defensive-copy diagnostics and one-shot production ownership transfer. */
public final class VideoReassemblyResultSelfTest {
    private VideoReassemblyResultSelfTest() {}

    public static void main(String[] args) {
        byte[] owned = new byte[] {1, 2, 3, 4};
        VideoReassemblyResult result = new VideoReassemblyResult(
                VideoPreflightReassemblyWindow.Code.COMPLETE,
                11L,
                12L,
                owned,
                true,
                false);

        byte[] diagnosticCopy = result.accessUnit();
        check(Arrays.equals(diagnosticCopy, owned), "diagnostic copy must preserve bytes");
        diagnosticCopy[0] = 99;
        check(result.accessUnit()[0] == 1, "diagnostic caller must not mutate owned bytes");

        byte[] transferred = result.takeAccessUnit();
        check(transferred == owned, "production transfer must not copy the complete access unit");
        check(result.accessUnit().length == 0, "ownership transfer must be one-shot");
        check(result.takeAccessUnit().length == 0, "second transfer must be empty");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
