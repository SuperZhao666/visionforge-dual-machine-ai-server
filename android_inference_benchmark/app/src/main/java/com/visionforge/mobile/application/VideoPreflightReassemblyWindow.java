package com.visionforge.mobile.application;

import com.visionforge.mobile.domain.video.VideoFragmentHeader;
import com.visionforge.mobile.domain.video.VideoPacketKind;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * MediaCodec 之前的有界分片重组窗口。
 *
 * <p>该类集中执行 epoch 高水位、分片冲突、重复、超时和内存上限规则。新 epoch
 * 先进入单一候选槽；只有组合根确认完整访问单元是新鲜 IDR 后，才通过
 * {@link #commitCandidateEpoch(long)} 获得会话所有权。高 epoch 半帧、冲突帧、
 * malformed 帧和 REPEAT 因而都不能退休正在工作的流。</p>
 */
public final class VideoPreflightReassemblyWindow {
    private static final byte[] EMPTY_ACCESS_UNIT = new byte[0];

    public static final class Config {
        private final int maxInflightFrames;
        private final long maxTotalBytes;
        private final int maxAccessUnitBytes;
        private final long frameTimeoutNanos;
        public Config(
                int maxInflightFrames,
                long maxTotalBytes,
                int maxAccessUnitBytes,
                long frameTimeoutNanos) {
            if (maxInflightFrames < 1 || maxTotalBytes < 1L || maxAccessUnitBytes < 1
                    || frameTimeoutNanos < 1L) {
                throw new IllegalArgumentException("all reassembly limits must be positive");
            }
            if (maxAccessUnitBytes > maxTotalBytes) {
                throw new IllegalArgumentException("one access unit cannot exceed the global byte budget");
            }
            this.maxInflightFrames = maxInflightFrames;
            this.maxTotalBytes = maxTotalBytes;
            this.maxAccessUnitBytes = maxAccessUnitBytes;
            this.frameTimeoutNanos = frameTimeoutNanos;
        }
        public int maxInflightFrames() { return maxInflightFrames; }
        public long maxTotalBytes() { return maxTotalBytes; }
        public int maxAccessUnitBytes() { return maxAccessUnitBytes; }
        public long frameTimeoutNanos() { return frameTimeoutNanos; }
        public static Config productionDefaults() {
            return new Config(16, 8L * 1024L * 1024L, 2 * 1024 * 1024, 500_000_000L);
        }
    }
    public enum Code {
        ACCEPTED,
        COMPLETE,
        DUPLICATE,
        CONFLICT,
        INVALID,
        STALE_EPOCH,
        RESOURCE_LIMIT,
        CANDIDATE_REJECTED,
        GAP_DETECTED,
        REPEAT
    }
    private static final class FrameKey {
        private final long epoch;
        private final long sequence;

        private FrameKey(long epoch, long sequence) {
            this.epoch = epoch;
            this.sequence = sequence;
        }
        private long epoch() { return epoch; }
        private long sequence() { return sequence; }
        @Override
        public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof FrameKey)) return false;
            FrameKey key = (FrameKey) other;
            return epoch == key.epoch && sequence == key.sequence;
        }
        @Override
        public int hashCode() {
            return Objects.hash(epoch, sequence);
        }
    }
    private static final class FrameAssembly {
        private final byte[][] fragments;
        private final long createdAtNanos;
        private int receivedCount;
        private int bytes;
        private FrameAssembly(int fragmentCount, long createdAtNanos) {
            fragments = new byte[fragmentCount][];
            this.createdAtNanos = createdAtNanos;
        }
    }
    private final Config config;
    private final Map<FrameKey, FrameAssembly> frames = new LinkedHashMap<>();
    private Long currentEpoch;
    private Long candidateEpoch;
    private boolean candidateReady;
    private long totalBytes;
    private boolean gapDetected;
    private long payloadBytesCopied;
    private long duplicatePayloadBytesAvoided;
    private long completedAccessUnitBytes;
    private long resourceLimitEvents;
    public VideoPreflightReassemblyWindow(Config config) {
        this.config = Objects.requireNonNull(config, "config");
    }

    public synchronized VideoReassemblyResult ingest(
            VideoFragmentHeader header,
            byte[] payload,
            long nowNanos) {
        Objects.requireNonNull(payload, "payload");
        return ingest(header, payload, 0, payload.length, nowNanos);
    }

    /**
     * 直接从接收数据报的 payload 区间入队。调用方不必先 copyOfRange；本类只在
     * 分片真正通过全部边界检查后复制一次，从而避免每个 UDP 包的双重临时分配。
     */
    public synchronized VideoReassemblyResult ingest(
            VideoFragmentHeader header,
            byte[] source,
            int payloadOffset,
            int payloadLength,
            long nowNanos) {
        Objects.requireNonNull(header, "header");
        Objects.requireNonNull(source, "source");
        if (payloadOffset < 0 || payloadLength < 0
                || payloadOffset > source.length - payloadLength) {
            return result(Code.INVALID, header);
        }
        if (nowNanos < 0L) {
            return result(Code.INVALID, header);
        }

        expire(nowNanos);
        if (isStale(header.streamEpoch())) {
            return result(Code.STALE_EPOCH, header);
        }
        if (gapDetected && currentEpoch != null
                && header.streamEpoch() == currentEpoch.longValue()) {
            gapDetected = false;
            clearInflight();
            return result(Code.GAP_DETECTED, header);
        }

        // REPEAT 仍携带完整编码访问单元，以维持 H.264 参考链；它只是不具备
        // “新鲜视觉内容”语义。REPEAT 绝不能建立新 epoch 候选。
        if (header.kind() == VideoPacketKind.REPEAT
                && (currentEpoch == null
                || header.streamEpoch() != currentEpoch.longValue())) {
            return result(Code.CANDIDATE_REJECTED, header);
        }

        // 在建立候选槽之前验证载荷，防止空包或超大包占用会话状态。
        if (payloadLength == 0 || payloadLength > config.maxAccessUnitBytes()) {
            return result(Code.INVALID, header);
        }

        boolean candidate = isCandidate(header.streamEpoch());
        if (candidate && !selectCandidateEpoch(header.streamEpoch())) {
            return result(Code.CANDIDATE_REJECTED, header);
        }

        FrameKey key = new FrameKey(header.streamEpoch(), header.frameSequence());
        FrameAssembly frame = frames.get(key);
        if (frame == null) {
            if (frames.size() >= config.maxInflightFrames()) {
                if (!candidate) {
                    eraseNonCurrentEpochs();
                }
                if (frames.size() >= config.maxInflightFrames()) {
                    return resourceFailure(header, candidate);
                }
            }
            frame = new FrameAssembly(header.fragmentCount(), nowNanos);
            frames.put(key, frame);
        } else if (frame.fragments.length != header.fragmentCount()) {
            if (candidate) {
                return candidateFailure(header);
            }
            removeFrame(key);
            return result(Code.CONFLICT, header);
        }

        byte[] previous = frame.fragments[header.fragmentIndex()];
        if (previous != null) {
            if (rangeEquals(previous, source, payloadOffset, payloadLength)) {
                duplicatePayloadBytesAvoided += payloadLength;
                return result(Code.DUPLICATE, header);
            }
            if (candidate) {
                return candidateFailure(header);
            }
            removeFrame(key);
            return result(Code.CONFLICT, header);
        }

        if (!candidate && payloadLength > config.maxTotalBytes() - totalBytes) {
            eraseNonCurrentEpochs();
        }
        if (payloadLength > config.maxAccessUnitBytes() - frame.bytes
                || payloadLength > config.maxTotalBytes() - totalBytes) {
            return resourceFailure(header, candidate);
        }

        frame.fragments[header.fragmentIndex()] = Arrays.copyOfRange(
                source, payloadOffset, payloadOffset + payloadLength);
        payloadBytesCopied += payloadLength;
        frame.receivedCount++;
        frame.bytes += payloadLength;
        totalBytes += payloadLength;

        if (frame.receivedCount != frame.fragments.length) {
            return result(Code.ACCEPTED, header);
        }

        byte[] accessUnit = new byte[frame.bytes];
        int offset = 0;
        for (byte[] fragment : frame.fragments) {
            if (fragment == null) {
                throw new IllegalStateException("receivedCount diverged from fragment occupancy");
            }
            System.arraycopy(fragment, 0, accessUnit, offset, fragment.length);
            offset += fragment.length;
        }
        removeFrame(key);
        completedAccessUnitBytes += accessUnit.length;
        if (candidate) {
            candidateReady = true;
        }
        return new VideoReassemblyResult(
                Code.COMPLETE,
                header.streamEpoch(),
                header.frameSequence(),
                accessUnit,
                candidate,
                header.kind() == VideoPacketKind.REPEAT);
    }

    /**
     * 提交刚完成且已经由上层验证为 IDR 的候选 epoch。
     *
     * @return 候选身份与状态完全匹配时返回 true；任何迟到、重复或越权提交均返回 false
     */
    public synchronized boolean commitCandidateEpoch(long epoch) {
        if (candidateEpoch == null || candidateEpoch.longValue() != epoch || !candidateReady
                || (currentEpoch != null && epoch <= currentEpoch.longValue())) {
            return false;
        }
        currentEpoch = epoch;
        candidateEpoch = null;
        candidateReady = false;
        eraseEpochsOlderThan(epoch);
        gapDetected = false;
        return true;
    }

    /** 丢弃指定候选及其全部半帧，不改变已经提交的当前 epoch。 */
    public synchronized void rejectCandidateEpoch(long epoch) {
        if (candidateEpoch == null || candidateEpoch.longValue() != epoch) {
            return;
        }
        eraseEpoch(epoch);
    }

    public synchronized void expire(long nowNanos) {
        if (nowNanos < 0L) {
            throw new IllegalArgumentException("nowNanos must be non-negative");
        }
        Iterator<Map.Entry<FrameKey, FrameAssembly>> iterator = frames.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<FrameKey, FrameAssembly> entry = iterator.next();
            FrameAssembly frame = entry.getValue();
            boolean expired = nowNanos >= frame.createdAtNanos
                    && nowNanos - frame.createdAtNanos >= config.frameTimeoutNanos();
            if (!expired) {
                continue;
            }
            if (currentEpoch != null && entry.getKey().epoch() == currentEpoch.longValue()) {
                gapDetected = true;
            }
            totalBytes -= frame.bytes;
            iterator.remove();
        }
        if (candidateEpoch != null && !candidateReady
                && !hasFramesForEpoch(candidateEpoch.longValue())) {
            candidateEpoch = null;
        }
    }

    public synchronized int inflightCount() { return frames.size(); }
    public synchronized long inflightBytes() { return totalBytes; }
    public synchronized long payloadBytesCopied() { return payloadBytesCopied; }
    public synchronized long duplicatePayloadBytesAvoided() {
        return duplicatePayloadBytesAvoided;
    }
    public synchronized long completedAccessUnitBytes() { return completedAccessUnitBytes; }
    public synchronized long resourceLimitEvents() { return resourceLimitEvents; }

    public synchronized OptionalLong currentEpoch() {
        return currentEpoch == null
                ? OptionalLong.empty()
                : OptionalLong.of(currentEpoch.longValue());
    }

    public synchronized OptionalLong candidateEpoch() {
        return candidateEpoch == null
                ? OptionalLong.empty()
                : OptionalLong.of(candidateEpoch.longValue());
    }

    /** 恢复流程丢弃所有半帧和候选，但保留 epoch 高水位，防止旧 UDP 包重新夺回会话。 */
    public synchronized void discardInflight() {
        clearInflight();
    }

    private boolean isStale(long epoch) {
        return currentEpoch != null && epoch < currentEpoch.longValue();
    }

    private boolean isCandidate(long epoch) {
        return currentEpoch == null || epoch > currentEpoch.longValue();
    }

    private boolean selectCandidateEpoch(long epoch) {
        if (candidateEpoch == null) {
            candidateEpoch = epoch;
            candidateReady = false;
            return true;
        }
        if (candidateEpoch.longValue() == epoch) {
            return !candidateReady;
        }
        if (candidateReady || epoch < candidateEpoch.longValue()) {
            return false;
        }

        // 更高 epoch 可替代尚未完成的旧候选；待确认完整候选不能被任何包抢占。
        long superseded = candidateEpoch.longValue();
        eraseEpoch(superseded);
        candidateEpoch = epoch;
        candidateReady = false;
        return true;
    }

    private static boolean rangeEquals(
            byte[] stored, byte[] source, int offset, int length) {
        if (stored.length != length) {
            return false;
        }
        for (int index = 0; index < length; index++) {
            if (stored[index] != source[offset + index]) {
                return false;
            }
        }
        return true;
    }

    private VideoReassemblyResult candidateFailure(VideoFragmentHeader header) {
        rejectCandidateEpoch(header.streamEpoch());
        return result(Code.CANDIDATE_REJECTED, header);
    }

    private VideoReassemblyResult resourceFailure(VideoFragmentHeader header, boolean candidate) {
        resourceLimitEvents++;
        if (candidate) {
            return candidateFailure(header);
        }
        clearInflight();
        return result(Code.RESOURCE_LIMIT, header);
    }

    private boolean hasFramesForEpoch(long epoch) {
        for (FrameKey key : frames.keySet()) {
            if (key.epoch() == epoch) {
                return true;
            }
        }
        return false;
    }

    private void removeFrame(FrameKey key) {
        FrameAssembly removed = frames.remove(key);
        if (removed != null) {
            totalBytes -= removed.bytes;
        }
    }

    private void eraseEpoch(long epoch) {
        Iterator<Map.Entry<FrameKey, FrameAssembly>> iterator = frames.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<FrameKey, FrameAssembly> entry = iterator.next();
            if (entry.getKey().epoch() == epoch) {
                totalBytes -= entry.getValue().bytes;
                iterator.remove();
            }
        }
        if (candidateEpoch != null && candidateEpoch.longValue() == epoch) {
            candidateEpoch = null;
            candidateReady = false;
        }
    }

    private void eraseNonCurrentEpochs() {
        Iterator<Map.Entry<FrameKey, FrameAssembly>> iterator = frames.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<FrameKey, FrameAssembly> entry = iterator.next();
            if (currentEpoch == null || entry.getKey().epoch() != currentEpoch.longValue()) {
                totalBytes -= entry.getValue().bytes;
                iterator.remove();
            }
        }
        candidateEpoch = null;
        candidateReady = false;
    }

    private void eraseEpochsOlderThan(long epoch) {
        Iterator<Map.Entry<FrameKey, FrameAssembly>> iterator = frames.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<FrameKey, FrameAssembly> entry = iterator.next();
            if (entry.getKey().epoch() < epoch) {
                totalBytes -= entry.getValue().bytes;
                iterator.remove();
            }
        }
    }

    private void clearInflight() {
        frames.clear();
        totalBytes = 0L;
        candidateEpoch = null;
        candidateReady = false;
    }

    private static VideoReassemblyResult result(Code code, VideoFragmentHeader header) {
        return new VideoReassemblyResult(
                code,
                header.streamEpoch(),
                header.frameSequence(),
                EMPTY_ACCESS_UNIT,
                false,
                header.kind() == VideoPacketKind.REPEAT);
    }
}
