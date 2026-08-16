package com.visionforge.mobile.domain.video;

/** 视频数据面的稳定包类型；四字节 magic 与 Host C++ 协议逐字节一致。 */
public enum VideoPacketKind {
    DATA(0x5646_3247),   // VF2G
    REPEAT(0x5646_3252); // VF2R

    private final int magicCode;

    VideoPacketKind(int magicCode) {
        this.magicCode = magicCode;
    }

    public int magicCode() {
        return magicCode;
    }

    /** 兼容测试/诊断 API；生产热路径使用 magicCode()，不分配临时数组。 */
    public byte[] magic() {
        return new byte[] {
                (byte) (magicCode >>> 24),
                (byte) (magicCode >>> 16),
                (byte) (magicCode >>> 8),
                (byte) magicCode
        };
    }

    public static VideoPacketKind fromMagicCode(int value) {
        if (value == DATA.magicCode) return DATA;
        if (value == REPEAT.magicCode) return REPEAT;
        throw new IllegalArgumentException("unsupported video wire magic");
    }

    public static VideoPacketKind fromMagic(byte[] value) {
        if (value == null || value.length != 4) {
            throw new IllegalArgumentException("wire magic must contain exactly four bytes");
        }
        int code = (Byte.toUnsignedInt(value[0]) << 24)
                | (Byte.toUnsignedInt(value[1]) << 16)
                | (Byte.toUnsignedInt(value[2]) << 8)
                | Byte.toUnsignedInt(value[3]);
        return fromMagicCode(code);
    }
}
