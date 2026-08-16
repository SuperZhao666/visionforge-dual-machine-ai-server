package com.visionforge.inferencebenchmark.video;

/** Immutable result of parsing one 20-byte VisionForge video header. */
public final class VideoFragmentHeader {
    public final VideoFrameIdentity identity;
    public final boolean repeatedContent;
    public final int fragmentIndex;
    public final int fragmentCount;
    public final int payloadBytes;

    VideoFragmentHeader(
            VideoFrameIdentity identity,
            boolean repeatedContent,
            int fragmentIndex,
            int fragmentCount,
            int payloadBytes) {
        this.identity = identity;
        this.repeatedContent = repeatedContent;
        this.fragmentIndex = fragmentIndex;
        this.fragmentCount = fragmentCount;
        this.payloadBytes = payloadBytes;
    }

    public boolean isFrameStart() {
        return fragmentIndex == 0;
    }
}
