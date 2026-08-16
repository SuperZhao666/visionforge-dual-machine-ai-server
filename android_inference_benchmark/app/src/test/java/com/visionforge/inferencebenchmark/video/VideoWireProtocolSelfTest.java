package com.visionforge.inferencebenchmark.video;

import java.util.Arrays;

public final class VideoWireProtocolSelfTest {
    public static void main(String[] ignored) {
        byte[] golden = VideoWireProtocol.encodeForTest(
                new VideoFrameIdentity(0x0102_0304_0506_0708L, 0x1122_3344L),
                false, 2, 5, new byte[] {0x7f});
        byte[] expectedHeader = new byte[] {
                0x56, 0x46, 0x32, 0x47,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x11, 0x22, 0x33, 0x44,
                0x00, 0x02, 0x00, 0x05
        };
        require(Arrays.equals(
                Arrays.copyOf(golden, VideoWireProtocol.HEADER_BYTES),
                expectedHeader));

        VideoFrameIdentity identity = new VideoFrameIdentity(77L, 0xffff_fffeL);
        byte[] normal = VideoWireProtocol.encodeForTest(
                identity, false, 0, 2, new byte[] {0, 0, 0, 1, 0x65});
        VideoFragmentHeader header = VideoWireProtocol.parse(normal, normal.length);
        require(header != null && header.identity.equals(identity));
        require(!header.repeatedContent && header.isFrameStart());
        require(VideoAccessUnitInspector.containsIdr(
                Arrays.copyOfRange(normal, VideoWireProtocol.HEADER_BYTES, normal.length)));

        byte[] repeated = VideoWireProtocol.encodeForTest(
                new VideoFrameIdentity(77L, 0xffff_ffffL), true, 0, 1,
                new byte[] {1});
        VideoFragmentHeader repeatedHeader =
                VideoWireProtocol.parse(repeated, repeated.length);
        require(repeatedHeader != null && repeatedHeader.repeatedContent);
        require(VideoWireProtocol.isForwardFrameStart(header, repeatedHeader));

        byte[] newEpoch = VideoWireProtocol.encodeForTest(
                new VideoFrameIdentity(78L, 0L), false, 0, 1, new byte[] {1});
        require(VideoWireProtocol.isForwardFrameStart(
                repeatedHeader, VideoWireProtocol.parse(newEpoch, newEpoch.length)));
        require(!VideoWireProtocol.isForwardFrameStart(
                VideoWireProtocol.parse(newEpoch, newEpoch.length), repeatedHeader));
        require(VideoWireProtocol.HEADER_BYTES == 20);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("video wire contract failed");
    }
}
