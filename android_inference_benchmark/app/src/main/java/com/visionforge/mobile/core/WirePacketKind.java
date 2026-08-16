package com.visionforge.mobile.core;

import com.visionforge.mobile.domain.video.VideoPacketKind;

/** 旧 API 兼容枚举；稳定 magic 的唯一事实来源在 VideoPacketKind。 */
public enum WirePacketKind {
    DATA(VideoPacketKind.DATA),
    REPEAT(VideoPacketKind.REPEAT);

    private final VideoPacketKind delegate;

    WirePacketKind(VideoPacketKind delegate) {
        this.delegate = delegate;
    }

    public String magic() {
        return new String(delegate.magic(), java.nio.charset.StandardCharsets.US_ASCII);
    }

    public static WirePacketKind fromMagic(String value) {
        if (value == null) {
            throw new IllegalArgumentException("wire magic is required");
        }
        VideoPacketKind domain = VideoPacketKind.fromMagic(
                value.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return domain == VideoPacketKind.DATA ? DATA : REPEAT;
    }
}
