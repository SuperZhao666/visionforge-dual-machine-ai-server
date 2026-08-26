package com.visionforge.inferencebenchmark.video;

import com.visionforge.mobile.domain.video.VideoPacketKind;

/**
 * Host、正式接收器、付费前探针和诊断工具共同使用的视频协议入口。
 *
 * <p>真正的 20 字节编解码只由
 * {@code com.visionforge.mobile.domain.video.VideoFragmentHeader} 持有。
 * 本类负责把纯领域头映射为 App 现有的只读 DTO，并补充数据报长度、
 * Access Unit 上限和连续帧判断。这样探针、正式接收器和测试不会再各自
 * 复制魔数、偏移或字节序实现。</p>
 */
public final class VideoWireProtocol {
    public static final int NORMAL_MAGIC = 0x5646_3247;   // VF2G
    public static final int REPEATED_MAGIC = 0x5646_3252; // VF2R
    public static final int HEADER_BYTES =
            com.visionforge.mobile.domain.video.VideoFragmentHeader.BYTE_LENGTH;
    /** Inner payload leaves exactly 48 bytes for the mandatory VFA2 header/tag. */
    public static final int PAYLOAD_BYTES = 1_344;
    public static final int MAX_DATAGRAM_BYTES = HEADER_BYTES + PAYLOAD_BYTES;
    public static final int MAX_ACCESS_UNIT_BYTES = 2 * 1024 * 1024;
    public static final int MAX_FRAGMENT_COUNT =
            com.visionforge.mobile.domain.video.VideoFragmentHeader.MAX_FRAGMENT_COUNT;

    private VideoWireProtocol() {}

    public static VideoFragmentHeader parse(byte[] bytes, int length) {
        if (bytes == null || length <= HEADER_BYTES
                || length > MAX_DATAGRAM_BYTES || length > bytes.length) {
            return null;
        }
        try {
            com.visionforge.mobile.domain.video.VideoFragmentHeader wire =
                    com.visionforge.mobile.domain.video.VideoFragmentHeader.decode(
                            bytes, 0, length);
            return new VideoFragmentHeader(
                    new VideoFrameIdentity(wire.streamEpoch(), wire.frameSequence()),
                    wire.kind() == VideoPacketKind.REPEAT,
                    wire.fragmentIndex(),
                    wire.fragmentCount(),
                    length - HEADER_BYTES);
        } catch (IllegalArgumentException | NullPointerException ignored) {
            return null;
        }
    }

    public static byte[] encodeForTest(
            VideoFrameIdentity identity,
            boolean repeatedContent,
            int fragmentIndex,
            int fragmentCount,
            byte[] payload) {
        if (identity == null || payload == null || payload.length == 0
                || payload.length > PAYLOAD_BYTES) {
            throw new IllegalArgumentException("invalid video fragment payload");
        }
        com.visionforge.mobile.domain.video.VideoFragmentHeader wire =
                new com.visionforge.mobile.domain.video.VideoFragmentHeader(
                        repeatedContent ? VideoPacketKind.REPEAT : VideoPacketKind.DATA,
                        identity.streamEpoch,
                        identity.frameSequence,
                        fragmentIndex,
                        fragmentCount);
        byte[] result = new byte[HEADER_BYTES + payload.length];
        byte[] encodedHeader = wire.encode();
        System.arraycopy(encodedHeader, 0, result, 0, HEADER_BYTES);
        System.arraycopy(payload, 0, result, HEADER_BYTES, payload.length);
        return result;
    }

    public static boolean isForwardFrameStart(
            VideoFragmentHeader previous,
            VideoFragmentHeader current) {
        if (previous == null || current == null
                || !previous.isFrameStart() || !current.isFrameStart()) {
            return false;
        }
        // A Host restart legitimately advances the epoch while resetting the
        // 32-bit frame sequence to zero. Comparing only the sequence would
        // therefore reject the first healthy frame of every new Host session.
        return current.identity.compareTo(previous.identity) > 0;
    }
}
