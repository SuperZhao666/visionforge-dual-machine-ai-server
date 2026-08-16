package com.visionforge.mobile.core;

import java.time.Duration;
import java.util.Objects;

/** Activity/UI 读取的不可变快照；界面层不接触 Service、JNI 或 MediaCodec 实现类型。 */
public record RuntimeSnapshot(
        Lifecycle lifecycle,
        VideoState videoState,
        TransportState transportState,
        ControlBlocker controlBlocker,
        long streamEpoch,
        long frameSequence,
        long transitionId,
        Duration blockerAge,
        String correlationId) {

    public enum Lifecycle { STOPPED, STARTING, RUNNING, RECOVERING, FAILED }
    public enum VideoState { IDLE, WAITING_FOR_IDR, DECODING, RESTARTING, DEGRADED }
    public enum TransportState { DISCONNECTED, CONNECTING, READY, CIRCUIT_OPEN }
    public enum ControlBlocker {
        RUNNABLE,
        NO_FRESH_CONTENT,
        WAITING_FRESH_IDR,
        WAITING_POST_ACK_VISIBILITY,
        TICKET_PENDING,
        TICKET_DEADLINE_EXPIRED,
        DETECTED_NOT_TRACK_ELIGIBLE,
        SUBCOUNT_UNRESOLVABLE,
        TRANSPORT_NOT_READY,
        RECOVERY_REQUIRED
    }

    public RuntimeSnapshot {
        Objects.requireNonNull(lifecycle, "lifecycle");
        Objects.requireNonNull(videoState, "videoState");
        Objects.requireNonNull(transportState, "transportState");
        Objects.requireNonNull(controlBlocker, "controlBlocker");
        Objects.requireNonNull(blockerAge, "blockerAge");
        Objects.requireNonNull(correlationId, "correlationId");
        // 跨语言协议明确把 epoch 限制在 1..Long.MAX_VALUE；0 仅表示尚无活动流。
        if (streamEpoch < 0L || frameSequence < 0L || transitionId < 0L || blockerAge.isNegative()) {
            throw new IllegalArgumentException("snapshot counters, epoch and age must be non-negative");
        }
        if (frameSequence > 0xffff_ffffL) {
            throw new IllegalArgumentException("frameSequence is outside uint32 range");
        }
        if (correlationId.isBlank() || correlationId.length() > 128) {
            throw new IllegalArgumentException("correlationId must be non-blank and at most 128 characters");
        }
    }
}
