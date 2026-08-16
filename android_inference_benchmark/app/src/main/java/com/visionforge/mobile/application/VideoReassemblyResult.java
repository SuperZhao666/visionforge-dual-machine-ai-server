package com.visionforge.mobile.application;

import java.util.Objects;

/**
 * 有界重组器向应用组合根交付的单次结果。
 *
 * <p>完整 Access Unit 由重组器独占创建。只读诊断调用 {@link #accessUnit()}
 * 获得防御性副本；生产消费者通过 {@link #takeAccessUnit()} 一次性接管原数组，
 * 避免最大 2 MiB IDR 在分类、排队和解码前被反复复制。</p>
 */
public final class VideoReassemblyResult {
    private static final byte[] EMPTY = new byte[0];

    private final VideoPreflightReassemblyWindow.Code code;
    private final long streamEpoch;
    private final long frameSequence;
    private final boolean requiresEpochCommit;
    private final boolean repeatedContent;
    private byte[] accessUnit;

    VideoReassemblyResult(
            VideoPreflightReassemblyWindow.Code code,
            long streamEpoch,
            long frameSequence,
            byte[] accessUnit,
            boolean requiresEpochCommit,
            boolean repeatedContent) {
        this.code = Objects.requireNonNull(code, "code");
        this.streamEpoch = streamEpoch;
        this.frameSequence = frameSequence;
        this.accessUnit = accessUnit == null ? EMPTY : accessUnit;
        this.requiresEpochCommit = requiresEpochCommit;
        this.repeatedContent = repeatedContent;
    }

    public VideoPreflightReassemblyWindow.Code code() { return code; }
    public long streamEpoch() { return streamEpoch; }
    public long frameSequence() { return frameSequence; }
    public boolean requiresEpochCommit() { return requiresEpochCommit; }
    public boolean repeatedContent() { return repeatedContent; }

    /** 兼容只读调用方；返回防御性副本。 */
    public synchronized byte[] accessUnit() {
        return accessUnit.clone();
    }

    /**
     * 一次性转交完整访问单元所有权；再次读取将得到空数组。
     */
    public synchronized byte[] takeAccessUnit() {
        byte[] owned = accessUnit;
        accessUnit = EMPTY;
        return owned;
    }
}
