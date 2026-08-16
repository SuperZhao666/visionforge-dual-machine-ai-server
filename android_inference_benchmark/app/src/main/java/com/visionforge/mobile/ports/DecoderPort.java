package com.visionforge.mobile.ports;

/** MediaCodec 适配器端口；application 层不依赖 android.media 类型。 */
public interface DecoderPort {
    void restartForEpoch(long streamEpoch);
    void submit(long streamEpoch, long frameSequence, boolean idr, byte[] accessUnit);
}
