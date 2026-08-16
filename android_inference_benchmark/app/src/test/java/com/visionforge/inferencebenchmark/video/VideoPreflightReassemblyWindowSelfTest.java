package com.visionforge.inferencebenchmark.video;

public final class VideoPreflightReassemblyWindowSelfTest {
    public static void main(String[] ignored) {
        VideoPreflightReassemblyWindow window =
                new VideoPreflightReassemblyWindow(2, 64);
        VideoFrameIdentity identity = new VideoFrameIdentity(5L, 9L);
        byte[] first = VideoWireProtocol.encodeForTest(
                identity, false, 0, 2, new byte[] {0, 0, 0, 1});
        byte[] last = VideoWireProtocol.encodeForTest(
                identity, false, 1, 2, new byte[] {0x65, (byte) 0x80});
        require(window.offer(last, last.length, 1L) == null);
        VideoPreflightReassemblyWindow.CompletedCandidate completed =
                window.offer(first, first.length, 2L);
        require(completed != null && completed.isCommittableIdr());
        require(window.inflightFrames() == 0 && window.inflightBytes() == 0);

        byte[] conflictA = VideoWireProtocol.encodeForTest(
                new VideoFrameIdentity(6L, 1L), false, 0, 2, new byte[] {1});
        byte[] conflictB = VideoWireProtocol.encodeForTest(
                new VideoFrameIdentity(6L, 1L), false, 0, 2, new byte[] {2});
        require(window.offer(conflictA, conflictA.length, 3L) == null);
        require(window.offer(conflictB, conflictB.length, 4L) == null);
        require(window.conflicts() == 1L && window.inflightFrames() == 0);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("preflight reassembly failed");
    }
}
