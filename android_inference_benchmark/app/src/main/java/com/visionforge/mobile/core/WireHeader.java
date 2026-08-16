package com.visionforge.mobile.core;

import com.visionforge.mobile.domain.video.VideoFragmentHeader;
import com.visionforge.mobile.domain.video.VideoPacketKind;

import java.util.Objects;

/**
 * 兼容旧调用点的协议适配记录。新业务代码应直接使用 domain.video.VideoFragmentHeader；
 * 本类通过委托保证旧 API 不再拥有一份会漂移的独立协议实现。
 */
public record WireHeader(
        WirePacketKind kind,
        long streamEpoch,
        long frameSequence,
        int fragmentIndex,
        int fragmentCount) {

    public static final int PROTOCOL_VERSION = VideoFragmentHeader.PROTOCOL_VERSION;
    public static final int BYTE_LENGTH = VideoFragmentHeader.BYTE_LENGTH;
    /**
     * 旧调用点使用的兼容名称。数值仍由领域协议头统一提供，避免 core 与
     * domain.video 各自维护一份上限后发生跨语言漂移。
     */
    public static final int MAX_FRAGMENTS = VideoFragmentHeader.MAX_FRAGMENT_COUNT;

    public WireHeader {
        Objects.requireNonNull(kind, "kind");
        // 构造并丢弃领域头，统一执行所有跨语言范围校验。
        new VideoFragmentHeader(toDomain(kind), streamEpoch, frameSequence,
                fragmentIndex, fragmentCount);
    }

    public byte[] encode() {
        return toDomain().encode();
    }

    public static WireHeader decode(byte[] datagram) {
        VideoFragmentHeader header = VideoFragmentHeader.decode(datagram);
        return new WireHeader(
                fromDomain(header.kind()),
                header.streamEpoch(),
                header.frameSequence(),
                header.fragmentIndex(),
                header.fragmentCount());
    }

    private VideoFragmentHeader toDomain() {
        return new VideoFragmentHeader(toDomain(kind), streamEpoch, frameSequence,
                fragmentIndex, fragmentCount);
    }

    private static VideoPacketKind toDomain(WirePacketKind kind) {
        return switch (kind) {
            case DATA -> VideoPacketKind.DATA;
            case REPEAT -> VideoPacketKind.REPEAT;
        };
    }

    private static WirePacketKind fromDomain(VideoPacketKind kind) {
        return switch (kind) {
            case DATA -> WirePacketKind.DATA;
            case REPEAT -> WirePacketKind.REPEAT;
        };
    }
}
