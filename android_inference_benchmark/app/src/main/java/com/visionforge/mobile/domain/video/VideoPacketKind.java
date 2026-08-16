package com.visionforge.mobile.domain.video;

import java.util.Arrays;

/** 视频数据面的稳定包类型；四字节 magic 与 Host C++ 协议逐字节一致。 */
public enum VideoPacketKind {
    DATA(new byte[] {'V', 'F', '2', 'G'}),
    REPEAT(new byte[] {'V', 'F', '2', 'R'});

    private final byte[] magic;

    VideoPacketKind(byte[] magic) {
        this.magic = magic;
    }

    public byte[] magic() {
        return magic.clone();
    }

    public static VideoPacketKind fromMagic(byte[] value) {
        if (value == null || value.length != 4) {
            throw new IllegalArgumentException("wire magic must contain exactly four bytes");
        }
        for (VideoPacketKind kind : values()) {
            if (Arrays.equals(kind.magic, value)) {
                return kind;
            }
        }
        throw new IllegalArgumentException("unsupported video wire magic");
    }
}
