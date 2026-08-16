package com.visionforge.mobile.domain.video;

import java.util.Optional;

/** APP 端解码后新鲜度账本；规则与 Host C++ DecodedFrameMetadataLedger 对称。 */
public final class DecodedFrameMetadataLedger {
    public enum Disposition {
        FRESH,
        EPOCH_ADVANCED,
        DUPLICATE,
        SEQUENCE_CONFLICT,
        STALE_SEQUENCE,
        STALE_EPOCH,
        NOT_FRESH
    }

    public record Metadata(
            long streamEpoch,
            long frameSequence,
            long contentFingerprint,
            boolean idr,
            boolean repeat,
            boolean contentUpdated,
            long decodedAtNanos) {
        public Metadata {
            if (streamEpoch <= 0L || frameSequence < 0L
                    || frameSequence > VideoFragmentHeader.UINT32_MAX || decodedAtNanos < 0L) {
                throw new IllegalArgumentException("invalid decoded-frame metadata");
            }
        }
    }

    public record Observation(Disposition disposition, boolean acceptedForInference,
                              boolean epochChanged) {}

    private long epoch;
    private Long lastObservedSequence;
    private Metadata lastObserved;
    private Metadata lastFresh;
    private long transitionId;

    public synchronized Observation observe(Metadata metadata) {
        if (epoch != 0L && metadata.streamEpoch() < epoch) {
            return new Observation(Disposition.STALE_EPOCH, false, false);
        }
        boolean changed = false;
        if (epoch == 0L || metadata.streamEpoch() > epoch) {
            epoch = metadata.streamEpoch();
            lastObservedSequence = null;
            lastObserved = null;
            advanceTransition();
            lastFresh = null;
            changed = true;
        }
        if (lastObservedSequence != null) {
            if (metadata.frameSequence() < lastObservedSequence.longValue()) {
                return new Observation(Disposition.STALE_SEQUENCE, false, changed);
            }
            if (metadata.frameSequence() == lastObservedSequence.longValue()) {
                if (lastObserved != null
                        && (metadata.contentFingerprint() != lastObserved.contentFingerprint()
                        || metadata.idr() != lastObserved.idr()
                        || metadata.repeat() != lastObserved.repeat()
                        || metadata.contentUpdated() != lastObserved.contentUpdated())) {
                    // 同一身份的语义必须逐字段一致；否则 Host/APP 可能分别把它解释为
                    // repeat、预测帧或 IDR，属于必须 fail-closed 的跨语言协议冲突。
                    return new Observation(Disposition.SEQUENCE_CONFLICT, false, changed);
                }
                return new Observation(Disposition.DUPLICATE, false, changed);
            }
        }
        lastObservedSequence = metadata.frameSequence();
        lastObserved = metadata;
        if (metadata.repeat() || !metadata.contentUpdated()) {
            return new Observation(Disposition.NOT_FRESH, false, changed);
        }
        lastFresh = metadata;
        return new Observation(changed ? Disposition.EPOCH_ADVANCED : Disposition.FRESH, true, changed);
    }

    public synchronized Optional<Metadata> lastFresh() {
        return Optional.ofNullable(lastFresh);
    }

    public synchronized long transitionId() {
        return transitionId;
    }

    private void advanceTransition() {
        if (transitionId == Long.MAX_VALUE) {
            throw new IllegalStateException("decoded-frame transition id space exhausted");
        }
        transitionId++;
    }
}
