package com.visionforge.mobile.ports;

/** 向 Host 请求 IDR 或完整会话重建的边界。 */
public interface RecoveryPort {
    void requestIdr(long streamEpoch, String reason);
    void requestSessionRebuild(long streamEpoch, String reason);
}
