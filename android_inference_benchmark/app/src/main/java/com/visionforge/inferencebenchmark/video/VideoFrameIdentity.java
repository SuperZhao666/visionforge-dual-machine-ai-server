package com.visionforge.inferencebenchmark.video;

import java.util.Objects;

/**
 * 视频帧在一条 Host 会话中的稳定身份。
 *
 * <p>仅比较 frameSequence 会把 Host 重启后的 0 号帧误判为旧帧；因此所有
 * 新鲜度、ACK 可见性和解码回调都必须携带完整的 epoch + sequence。</p>
 */
public final class VideoFrameIdentity implements Comparable<VideoFrameIdentity> {
    public static final long MAX_STREAM_EPOCH = Long.MAX_VALUE;

    public final long streamEpoch;
    public final long frameSequence;

    public VideoFrameIdentity(long streamEpoch, long frameSequence) {
        if (streamEpoch <= 0L) {
            throw new IllegalArgumentException("streamEpoch must be positive");
        }
        if (frameSequence < 0L || frameSequence > 0xffff_ffffL) {
            throw new IllegalArgumentException("frameSequence must be unsigned 32-bit");
        }
        this.streamEpoch = streamEpoch;
        this.frameSequence = frameSequence;
    }

    public boolean isNextAfter(VideoFrameIdentity previous) {
        return previous != null
                && streamEpoch == previous.streamEpoch
                && previous.frameSequence != 0xffff_ffffL
                && frameSequence == previous.frameSequence + 1L;
    }

    @Override
    public int compareTo(VideoFrameIdentity other) {
        int epochOrder = Long.compare(streamEpoch, other.streamEpoch);
        return epochOrder != 0 ? epochOrder
                : Long.compareUnsigned(frameSequence, other.frameSequence);
    }

    @Override
    public boolean equals(Object candidate) {
        if (this == candidate) return true;
        if (!(candidate instanceof VideoFrameIdentity)) return false;
        VideoFrameIdentity other = (VideoFrameIdentity) candidate;
        return streamEpoch == other.streamEpoch
                && frameSequence == other.frameSequence;
    }

    @Override
    public int hashCode() {
        return Objects.hash(streamEpoch, frameSequence);
    }

    @Override
    public String toString() {
        return streamEpoch + ":" + Long.toUnsignedString(frameSequence);
    }
}
