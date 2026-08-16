package com.visionforge.inferencebenchmark.video;

import com.visionforge.mobile.application.VideoPreflightReassemblyWindow;
import com.visionforge.mobile.application.VideoReassemblyResult;
import com.visionforge.mobile.domain.video.H264AccessUnitClassifier;
import com.visionforge.mobile.domain.video.VideoPacketKind;

import java.util.Objects;

/**
 * 付费开始前的视频连续性验证器。
 *
 * <p>旧探针只观察两个 frame-start 分片：如果 Host 只发出了每帧的第一个 UDP
 * 分片，或者后续分片全部丢失，仍可能误判“视频链路可用”。本类将协议解析、
 * 有界重组、候选 epoch 两阶段提交、IDR 建链和连续帧验证收口为一个纯 Java
 * 状态机。Socket 只负责收包；只有完整真实 IDR 加上一张完整连续访问单元才会
 * 返回 READY。</p>
 */
public final class HostVideoPreflightVerifier {
    public enum Decision {
        BUFFERED,
        COMPLETE_BUT_NOT_READY,
        READY,
        REJECTED,
        RECOVERY_REQUIRED
    }

    public record Snapshot(
            boolean ready,
            int confirmedCompleteAccessUnits,
            VideoFrameIdentity lastCompleteIdentity,
            long rejectedDatagrams,
            long continuityFailures,
            long completedAccessUnits) {}

    private final VideoPreflightReassemblyWindow reassembly;
    private final int requiredCompleteAccessUnits;
    private VideoFrameIdentity lastCompleteIdentity;
    // Counts complete, non-REPEAT access units in the current proof. The
    // committed IDR is proof #1; a VFRR frame may preserve decoder continuity
    // but cannot prove that fresh visual content is moving.
    private int confirmedCompleteAccessUnits;
    private long rejectedDatagrams;
    private long continuityFailures;
    private long completedAccessUnits;

    public HostVideoPreflightVerifier(int requiredCompleteAccessUnits) {
        this(
                requiredCompleteAccessUnits,
                VideoPreflightReassemblyWindow.Config.productionDefaults());
    }

    HostVideoPreflightVerifier(
            int requiredCompleteAccessUnits,
            VideoPreflightReassemblyWindow.Config config) {
        if (requiredCompleteAccessUnits < 2) {
            throw new IllegalArgumentException(
                    "preflight requires an IDR and at least one continuous access unit");
        }
        this.requiredCompleteAccessUnits = requiredCompleteAccessUnits;
        reassembly = new VideoPreflightReassemblyWindow(
                Objects.requireNonNull(config, "config"));
    }

    /**
     * Consumes exactly one UDP datagram. The method never retains the caller's
     * receive buffer; only the bounded reassembler owns copied fragment bytes.
     */
    public synchronized Decision offer(
            byte[] datagram,
            int length,
            long nowNanos) {
        VideoFragmentHeader parsed = VideoWireProtocol.parse(datagram, length);
        if (parsed == null || nowNanos < 0L) {
            rejectedDatagrams++;
            return Decision.REJECTED;
        }

        com.visionforge.mobile.domain.video.VideoFragmentHeader header;
        try {
            header = new com.visionforge.mobile.domain.video.VideoFragmentHeader(
                    parsed.repeatedContent ? VideoPacketKind.REPEAT : VideoPacketKind.DATA,
                    parsed.identity.streamEpoch,
                    parsed.identity.frameSequence,
                    parsed.fragmentIndex,
                    parsed.fragmentCount);
        } catch (IllegalArgumentException failure) {
            rejectedDatagrams++;
            return Decision.REJECTED;
        }

        VideoReassemblyResult result = reassembly.ingest(
                header,
                datagram,
                VideoWireProtocol.HEADER_BYTES,
                length - VideoWireProtocol.HEADER_BYTES,
                nowNanos);
        return switch (result.code()) {
            case ACCEPTED, DUPLICATE -> Decision.BUFFERED;
            case COMPLETE -> onComplete(result);
            case GAP_DETECTED, RESOURCE_LIMIT, CONFLICT -> {
                continuityFailures++;
                yield Decision.RECOVERY_REQUIRED;
            }
            case INVALID, STALE_EPOCH, CANDIDATE_REJECTED, REPEAT -> {
                rejectedDatagrams++;
                yield Decision.REJECTED;
            }
        };
    }

    public synchronized Snapshot snapshot() {
        return new Snapshot(
                confirmedCompleteAccessUnits >= requiredCompleteAccessUnits,
                confirmedCompleteAccessUnits,
                lastCompleteIdentity,
                rejectedDatagrams,
                continuityFailures,
                completedAccessUnits);
    }

    private Decision onComplete(VideoReassemblyResult result) {
        byte[] accessUnit = result.takeAccessUnit();
        H264AccessUnitClassifier.Classification classification =
                H264AccessUnitClassifier.classify(accessUnit);
        VideoFrameIdentity identity = new VideoFrameIdentity(
                result.streamEpoch(), result.frameSequence());
        completedAccessUnits++;

        if (classification.malformed()) {
            if (result.requiresEpochCommit()) {
                reassembly.rejectCandidateEpoch(result.streamEpoch());
            }
            rejectedDatagrams++;
            return Decision.REJECTED;
        }

        if (result.requiresEpochCommit()) {
            if (result.repeatedContent() || !classification.containsIdr()
                    || !reassembly.commitCandidateEpoch(result.streamEpoch())) {
                reassembly.rejectCandidateEpoch(result.streamEpoch());
                rejectedDatagrams++;
                return Decision.REJECTED;
            }
            // A new epoch starts a new proof. Its complete real IDR is proof #1.
            lastCompleteIdentity = identity;
            confirmedCompleteAccessUnits = 1;
            return Decision.COMPLETE_BUT_NOT_READY;
        }

        if (lastCompleteIdentity == null) {
            continuityFailures++;
            return Decision.RECOVERY_REQUIRED;
        }

        int identityOrder = identity.compareTo(lastCompleteIdentity);
        if (identityOrder <= 0) {
            // A duplicated complete Access Unit is harmless UDP duplication,
            // not a reference-chain break. Ignore it without resetting a
            // proof already in progress.
            rejectedDatagrams++;
            return Decision.REJECTED;
        }

        if (!identity.isNextAfter(lastCompleteIdentity)) {
            // A complete IDR can re-establish the reference chain inside the
            // same epoch after packet loss; an ordinary P-frame cannot.
            if (!result.repeatedContent() && classification.containsIdr()
                    && identityOrder > 0) {
                lastCompleteIdentity = identity;
                confirmedCompleteAccessUnits = 1;
                return Decision.COMPLETE_BUT_NOT_READY;
            }
            continuityFailures++;
            return Decision.RECOVERY_REQUIRED;
        }

        lastCompleteIdentity = identity;
        if (result.repeatedContent()) {
            return Decision.COMPLETE_BUT_NOT_READY;
        }
        confirmedCompleteAccessUnits++;
        return confirmedCompleteAccessUnits >= requiredCompleteAccessUnits
                ? Decision.READY
                : Decision.COMPLETE_BUT_NOT_READY;
    }
}
