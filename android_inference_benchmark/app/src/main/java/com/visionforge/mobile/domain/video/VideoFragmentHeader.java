package com.visionforge.mobile.domain.video;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;

/**
 * Host→APP 视频 UDP v2 头。
 *
 * <p>字节布局固定为：magic[4]、streamEpoch[8]、frameSequence[4]、
 * fragmentIndex[2]、fragmentCount[2]，所有多字节字段均为网络字节序。</p>
 *
 * <p>Java 没有无符号 long。为避免 C++ uint64 与 Java long 在最高位上的解释分裂，
 * streamEpoch 被契约性限制为 1..Long.MAX_VALUE；Host 端执行同一限制。</p>
 */
public record VideoFragmentHeader(
        VideoPacketKind kind,
        long streamEpoch,
        long frameSequence,
        int fragmentIndex,
        int fragmentCount) {

    public static final int PROTOCOL_VERSION = 2;
    public static final int BYTE_LENGTH = 20;
    public static final int PAYLOAD_BYTES = 1_400;
    public static final int MAX_ACCESS_UNIT_BYTES = 2 * 1024 * 1024;
    public static final int MAX_FRAGMENT_COUNT =
            (MAX_ACCESS_UNIT_BYTES + PAYLOAD_BYTES - 1) / PAYLOAD_BYTES;
    public static final long UINT32_MAX = 0xffff_ffffL;

    public VideoFragmentHeader {
        Objects.requireNonNull(kind, "kind");
        if (streamEpoch <= 0L) {
            throw new IllegalArgumentException("streamEpoch must be within positive signed-long range");
        }
        if (frameSequence < 0L || frameSequence > UINT32_MAX) {
            throw new IllegalArgumentException("frameSequence is outside uint32 range");
        }
        if (fragmentCount < 1 || fragmentCount > MAX_FRAGMENT_COUNT) {
            throw new IllegalArgumentException("fragmentCount exceeds the shared 2 MiB Access Unit budget");
        }
        if (fragmentIndex < 0 || fragmentIndex >= fragmentCount) {
            throw new IllegalArgumentException("fragmentIndex must be within fragmentCount");
        }
    }

    public byte[] encode() {
        ByteBuffer buffer = ByteBuffer.allocate(BYTE_LENGTH).order(ByteOrder.BIG_ENDIAN);
        buffer.putInt(kind.magicCode());
        buffer.putLong(streamEpoch);
        buffer.putInt((int) frameSequence);
        buffer.putShort((short) fragmentIndex);
        buffer.putShort((short) fragmentCount);
        return buffer.array();
    }

    public static VideoFragmentHeader decode(byte[] datagram) {
        Objects.requireNonNull(datagram, "datagram");
        return decode(datagram, 0, datagram.length);
    }

    /**
     * 从现有数据报直接解析头，不复制 payload。
     * availableLength 用于拒绝短包；只读取固定的前 20 字节。
     */
    public static VideoFragmentHeader decode(
            byte[] datagram, int offset, int availableLength) {
        Objects.requireNonNull(datagram, "datagram");
        if (offset < 0 || availableLength < BYTE_LENGTH
                || offset > datagram.length - BYTE_LENGTH
                || availableLength > datagram.length - offset) {
            throw new IllegalArgumentException("datagram is shorter than the v2 header");
        }
        ByteBuffer buffer = ByteBuffer.wrap(datagram, offset, BYTE_LENGTH)
                .order(ByteOrder.BIG_ENDIAN);
        VideoPacketKind kind = VideoPacketKind.fromMagicCode(buffer.getInt());
        long epoch = buffer.getLong();
        long sequence = Integer.toUnsignedLong(buffer.getInt());
        int index = Short.toUnsignedInt(buffer.getShort());
        int count = Short.toUnsignedInt(buffer.getShort());
        return new VideoFragmentHeader(kind, epoch, sequence, index, count);
    }

    /** 当前序号已用尽；发送端必须先切换 epoch，不能让 uint32 回绕到零。 */
    public boolean requiresEpochRolloverBeforeNextFrame() {
        return frameSequence == UINT32_MAX;
    }
}
