package com.visionforge.mobile.application;

import com.visionforge.mobile.core.AtomicRuntimeReadModel;
import com.visionforge.mobile.core.DecoderRestartCoordinator;
import com.visionforge.mobile.core.RuntimeSnapshot;
import com.visionforge.mobile.domain.video.H264AccessUnitClassifier;
import com.visionforge.mobile.domain.video.OrderedAccessUnitHandoff;
import com.visionforge.mobile.domain.video.VideoFragmentHeader;
import com.visionforge.mobile.ports.DecoderPort;
import com.visionforge.mobile.ports.RecoveryPort;
import com.visionforge.mobile.ports.RuntimeDiagnosticsPort;

import java.time.Duration;
import java.util.Locale;
import java.util.Objects;

/**
 * APP 视频运行时唯一组合根。
 *
 * <p>UDP、重组、码流分类、按序交接、解码器重启合并和可观测状态在这里连接；Activity
 * 与 Service 只调用该门面，不再直接持有这些易竞态对象。外部适配器异常一律转成
 * fail-closed 恢复状态，不允许异常穿透接收线程。</p>
 */
public final class MobileRuntimeCompositionRoot {
    public enum DatagramOutcome {
        BUFFERED,
        REPEAT_REJECTED,
        ACCESS_UNIT_SUBMITTED,
        STALE_OR_DUPLICATE,
        RECOVERY_REQUESTED,
        INVALID
    }

    private final VideoPreflightReassemblyWindow reassembly;
    private final OrderedAccessUnitHandoff handoff;
    private final DecoderRestartCoordinator restarts = new DecoderRestartCoordinator();
    private final DecoderPort decoder;
    private final RecoveryPort recovery;
    private final RuntimeDiagnosticsPort diagnostics;
    private final AtomicRuntimeReadModel readModel;

    private long receiveEpoch;
    private long decoderEpoch;
    private long transitionId;
    private long lastNowNanos;
    private long blockerChangedAtNanos;
    private RuntimeSnapshot.ControlBlocker currentBlocker =
            RuntimeSnapshot.ControlBlocker.TRANSPORT_NOT_READY;

    public MobileRuntimeCompositionRoot(
            VideoPreflightReassemblyWindow.Config reassemblyConfig,
            int compressedHandoffCapacity,
            DecoderPort decoder,
            RecoveryPort recovery,
            String correlationId) {
        this(reassemblyConfig, compressedHandoffCapacity, decoder, recovery,
                RuntimeDiagnosticsPort.noop(), correlationId);
    }

    public MobileRuntimeCompositionRoot(
            VideoPreflightReassemblyWindow.Config reassemblyConfig,
            int compressedHandoffCapacity,
            DecoderPort decoder,
            RecoveryPort recovery,
            RuntimeDiagnosticsPort diagnostics,
            String correlationId) {
        reassembly = new VideoPreflightReassemblyWindow(reassemblyConfig);
        handoff = new OrderedAccessUnitHandoff(compressedHandoffCapacity);
        this.decoder = Objects.requireNonNull(decoder, "decoder");
        this.recovery = Objects.requireNonNull(recovery, "recovery");
        this.diagnostics = Objects.requireNonNull(diagnostics, "diagnostics");
        readModel = new AtomicRuntimeReadModel(correlationId);
    }

    public synchronized DatagramOutcome onDatagram(byte[] datagram, long nowNanos) {
        Objects.requireNonNull(datagram, "datagram");
        advanceClock(nowNanos);
        final VideoFragmentHeader header;
        try {
            header = VideoFragmentHeader.decode(datagram);
        } catch (IllegalArgumentException error) {
            safeDiagnostic("wire_header_rejected", error.getClass().getSimpleName());
            return DatagramOutcome.INVALID;
        }
        VideoReassemblyResult result = reassembly.ingest(
                header,
                datagram,
                VideoFragmentHeader.BYTE_LENGTH,
                datagram.length - VideoFragmentHeader.BYTE_LENGTH,
                nowNanos);
        return switch (result.code()) {
            case ACCEPTED -> DatagramOutcome.BUFFERED;
            case DUPLICATE, STALE_EPOCH -> DatagramOutcome.STALE_OR_DUPLICATE;
            case CANDIDATE_REJECTED -> requestCandidateIdrPreservingCurrent(
                    result.streamEpoch(), "reassembly_candidate_rejected", nowNanos);
            case REPEAT -> onRepeat(result.streamEpoch(), nowNanos);
            case CONFLICT, INVALID, RESOURCE_LIMIT, GAP_DETECTED -> requestRecovery(
                    result.streamEpoch(), "reassembly_" + lower(result.code().name()), nowNanos);
            case COMPLETE -> onComplete(result, nowNanos);
        };
    }

    public AtomicRuntimeReadModel readModel() {
        return readModel;
    }

    /** 兼容旧适配器；新适配器应传入同一单调时钟的完成时间。 */
    public synchronized void onDecoderRestartComplete(long completedEpoch) {
        onDecoderRestartComplete(completedEpoch, lastNowNanos);
    }

    /**
     * 由 MediaCodec 适配器在一次 restart 真正完成后回调。迟到的旧回调只记录并忽略；
     * 不可能的未来回调才升级为会话重建。
     */
    public synchronized void onDecoderRestartComplete(long completedEpoch, long nowNanos) {
        advanceClock(nowNanos);
        DecoderRestartCoordinator.Completion completion = restarts.complete(completedEpoch);
        switch (completion.decision()) {
            case STALE_CALLBACK -> {
                safeDiagnostic("decoder_restart_stale_completion", Long.toString(completedEpoch));
                return;
            }
            case INVALID_FUTURE_CALLBACK -> {
                safeDiagnostic("decoder_restart_future_completion", Long.toString(completedEpoch));
                requestSessionRebuild(receiveEpoch, "decoder_restart_future_completion", nowNanos);
                return;
            }
            case START_NEXT -> {
                long nextEpoch = completion.nextEpoch().orElseThrow();
                if (!startDecoderRestart(nextEpoch, nowNanos)) {
                    return;
                }
                publish(RuntimeSnapshot.VideoState.RESTARTING,
                        RuntimeSnapshot.ControlBlocker.WAITING_FRESH_IDR,
                        nextEpoch, 0L, nowNanos);
                return;
            }
            case SETTLED -> decoderEpoch = completedEpoch;
        }
        drainReadyAccessUnits(nowNanos);
    }

    /** 兼容旧适配器；新适配器应传入失败发生的单调时钟。 */
    public synchronized void onDecoderRestartFailed(long failedEpoch, String reason) {
        onDecoderRestartFailed(failedEpoch, reason, lastNowNanos);
    }

    /** 解码器主动报告重启失败时，关闭当前交接并升级为完整会话重建。 */
    public synchronized void onDecoderRestartFailed(long failedEpoch, String reason, long nowNanos) {
        advanceClock(nowNanos);
        if (restarts.abort(failedEpoch)) {
            safeDiagnostic("decoder_restart_failed", sanitizeDetail(reason));
            requestSessionRebuild(failedEpoch, "decoder_restart_failed", nowNanos);
            return;
        }
        long activeEpoch = restarts.activeEpoch().orElse(0L);
        if (activeEpoch != 0L && failedEpoch > activeEpoch) {
            safeDiagnostic("decoder_restart_future_failure", Long.toString(failedEpoch));
            requestSessionRebuild(receiveEpoch, "decoder_restart_future_failure", nowNanos);
        } else {
            safeDiagnostic("decoder_restart_stale_failure", Long.toString(failedEpoch));
        }
    }

    private DatagramOutcome onRepeat(long epoch, long nowNanos) {
        reassembly.discardInflight();
        handoff.requireFreshIdr();
        if (!requestIdr(epoch, "repeat_packet_is_not_fresh_content", nowNanos)) {
            return DatagramOutcome.RECOVERY_REQUESTED;
        }
        publish(RuntimeSnapshot.VideoState.WAITING_FOR_IDR,
                RuntimeSnapshot.ControlBlocker.WAITING_FRESH_IDR, epoch, 0L, nowNanos);
        return DatagramOutcome.REPEAT_REJECTED;
    }

    private DatagramOutcome onComplete(VideoReassemblyResult result, long nowNanos) {
        // The completed Access Unit is transferred exactly once from the bounded
        // reassembler to classification and decode handoff. Diagnostic readers
        // still receive defensive copies through VideoReassemblyResult.accessUnit().
        byte[] accessUnit = result.takeAccessUnit();
        H264AccessUnitClassifier.Classification classification =
                H264AccessUnitClassifier.classify(accessUnit);

        if (result.requiresEpochCommit()) {
            if (result.repeatedContent()) {
                reassembly.rejectCandidateEpoch(result.streamEpoch());
                return requestCandidateIdrPreservingCurrent(
                        result.streamEpoch(), "candidate_repeat_cannot_commit_epoch", nowNanos);
            }
            if (classification.malformed()) {
                reassembly.rejectCandidateEpoch(result.streamEpoch());
                return requestCandidateIdrPreservingCurrent(
                        result.streamEpoch(), "candidate_malformed_annex_b_access_unit", nowNanos);
            }
            if (!classification.containsIdr()) {
                reassembly.rejectCandidateEpoch(result.streamEpoch());
                return requestCandidateIdrPreservingCurrent(
                        result.streamEpoch(), "candidate_epoch_requires_fresh_idr", nowNanos);
            }
            if (!reassembly.commitCandidateEpoch(result.streamEpoch())) {
                reassembly.rejectCandidateEpoch(result.streamEpoch());
                safeDiagnostic("candidate_epoch_commit_failed", Long.toString(result.streamEpoch()));
                requestSessionRebuild(result.streamEpoch(), "candidate_epoch_commit_failed", nowNanos);
                return DatagramOutcome.RECOVERY_REQUESTED;
            }
        } else if (classification.malformed()) {
            return requestRecovery(result.streamEpoch(), "malformed_annex_b_access_unit", nowNanos);
        }
        receiveEpoch = Math.max(receiveEpoch, result.streamEpoch());

        OrderedAccessUnitHandoff.AccessUnit unit = new OrderedAccessUnitHandoff.AccessUnit(
                result.streamEpoch(), result.frameSequence(), classification.containsIdr(),
                result.repeatedContent(), accessUnit);
        OrderedAccessUnitHandoff.OfferDecision offer = handoff.offer(unit);
        switch (offer) {
            case STALE, DUPLICATE -> {
                return DatagramOutcome.STALE_OR_DUPLICATE;
            }
            case EPOCH_EXHAUSTED -> {
                requestSessionRebuild(result.streamEpoch(), "frame_sequence_epoch_exhausted", nowNanos);
                return DatagramOutcome.RECOVERY_REQUESTED;
            }
            case CONFLICT, OVERFLOW, NEED_IDR -> {
                reassembly.discardInflight();
                handoff.requireFreshIdr();
                if (!requestIdr(result.streamEpoch(), "compressed_handoff_" + lower(offer.name()), nowNanos)) {
                    return DatagramOutcome.RECOVERY_REQUESTED;
                }
                publish(RuntimeSnapshot.VideoState.WAITING_FOR_IDR,
                        RuntimeSnapshot.ControlBlocker.WAITING_FRESH_IDR,
                        result.streamEpoch(), result.frameSequence(), nowNanos);
                return DatagramOutcome.RECOVERY_REQUESTED;
            }
            case ACCEPTED, EPOCH_ADVANCED -> {
                // Continue below.
            }
        }

        if (decoderEpoch != result.streamEpoch()) {
            DecoderRestartCoordinator.RequestDecision restart = restarts.request(result.streamEpoch());
            if (restart == DecoderRestartCoordinator.RequestDecision.STALE) {
                return DatagramOutcome.STALE_OR_DUPLICATE;
            }
            if (restart == DecoderRestartCoordinator.RequestDecision.START_NOW
                    && !startDecoderRestart(result.streamEpoch(), nowNanos)) {
                return DatagramOutcome.RECOVERY_REQUESTED;
            }
        }

        // restart 未稳定前只缓存压缩帧，禁止向旧 MediaCodec 会话提交新 epoch 数据。
        if (restarts.inFlight()) {
            publish(RuntimeSnapshot.VideoState.RESTARTING,
                    RuntimeSnapshot.ControlBlocker.WAITING_FRESH_IDR,
                    result.streamEpoch(), result.frameSequence(), nowNanos);
            return DatagramOutcome.BUFFERED;
        }
        int submitted = drainReadyAccessUnits(nowNanos);
        if (submitted < 0) {
            return DatagramOutcome.RECOVERY_REQUESTED;
        }
        return submitted == 0 ? DatagramOutcome.BUFFERED : DatagramOutcome.ACCESS_UNIT_SUBMITTED;
    }

    private int drainReadyAccessUnits(long nowNanos) {
        int submitted = 0;
        OrderedAccessUnitHandoff.AccessUnit last = null;
        while (true) {
            OrderedAccessUnitHandoff.AccessUnit ready = handoff.pollReady().orElse(null);
            if (ready == null) {
                break;
            }
            if (ready.streamEpoch() != decoderEpoch) {
                safeDiagnostic("decoder_epoch_mismatch", ready.streamEpoch() + "_vs_" + decoderEpoch);
                requestSessionRebuild(ready.streamEpoch(), "decoder_epoch_mismatch", nowNanos);
                return -1;
            }
            try {
                decoder.submit(ready.streamEpoch(), ready.frameSequence(), ready.idr(), ready.bytes());
            } catch (RuntimeException error) {
                safeDiagnostic("decoder_submit_failed", error.getClass().getSimpleName());
                requestSessionRebuild(ready.streamEpoch(), "decoder_submit_failed", nowNanos);
                return -1;
            }
            last = ready;
            submitted++;
        }
        if (last != null) {
            publish(RuntimeSnapshot.VideoState.DECODING,
                    last.repeatedContent()
                            ? RuntimeSnapshot.ControlBlocker.WAITING_FRESH_IDR
                            : RuntimeSnapshot.ControlBlocker.RUNNABLE,
                    last.streamEpoch(), last.frameSequence(), nowNanos);
        }
        return submitted;
    }

    private DatagramOutcome requestRecovery(long epoch, String reason, long nowNanos) {
        handoff.requireFreshIdr();
        reassembly.discardInflight();
        if (!requestIdr(epoch, reason, nowNanos)) {
            return DatagramOutcome.RECOVERY_REQUESTED;
        }
        publish(RuntimeSnapshot.VideoState.WAITING_FOR_IDR,
                RuntimeSnapshot.ControlBlocker.RECOVERY_REQUIRED, epoch, 0L, nowNanos);
        return DatagramOutcome.RECOVERY_REQUESTED;
    }

    private DatagramOutcome requestCandidateIdrPreservingCurrent(
            long epoch,
            String reason,
            long nowNanos) {
        boolean hasCommittedCurrent = reassembly.currentEpoch().isPresent();
        try {
            recovery.requestIdr(epoch, reason);
        } catch (RuntimeException error) {
            safeDiagnostic("candidate_idr_request_failed", error.getClass().getSimpleName());
            if (!hasCommittedCurrent) {
                requestSessionRebuild(epoch, "candidate_idr_request_failed", nowNanos);
            }
            return DatagramOutcome.RECOVERY_REQUESTED;
        }

        safeDiagnostic("candidate_epoch_recovery_requested", epoch + "_" + reason);
        if (!hasCommittedCurrent) {
            publish(RuntimeSnapshot.VideoState.WAITING_FOR_IDR,
                    RuntimeSnapshot.ControlBlocker.WAITING_FRESH_IDR,
                    epoch, 0L, nowNanos);
        }
        return DatagramOutcome.RECOVERY_REQUESTED;
    }

    private boolean startDecoderRestart(long epoch, long nowNanos) {
        try {
            decoder.restartForEpoch(epoch);
            return true;
        } catch (RuntimeException error) {
            restarts.abort(epoch);
            safeDiagnostic("decoder_restart_dispatch_failed", error.getClass().getSimpleName());
            requestSessionRebuild(epoch, "decoder_restart_dispatch_failed", nowNanos);
            return false;
        }
    }

    private boolean requestIdr(long epoch, String reason, long nowNanos) {
        try {
            recovery.requestIdr(epoch, reason);
            return true;
        } catch (RuntimeException error) {
            safeDiagnostic("idr_request_failed", error.getClass().getSimpleName());
            requestSessionRebuild(epoch, "idr_request_failed", nowNanos);
            return false;
        }
    }

    private void requestSessionRebuild(long epoch, String reason, long nowNanos) {
        restarts.activeEpoch().ifPresent(restarts::abort);
        decoderEpoch = 0L;
        handoff.requireFreshIdr();
        reassembly.discardInflight();
        RuntimeSnapshot.TransportState transportState = RuntimeSnapshot.TransportState.CONNECTING;
        try {
            recovery.requestSessionRebuild(epoch, reason);
        } catch (RuntimeException error) {
            transportState = RuntimeSnapshot.TransportState.CIRCUIT_OPEN;
            safeDiagnostic("session_rebuild_request_failed", error.getClass().getSimpleName());
        }
        publish(RuntimeSnapshot.VideoState.DEGRADED,
                transportState,
                RuntimeSnapshot.ControlBlocker.RECOVERY_REQUIRED, epoch, 0L, nowNanos);
    }

    private void publish(
            RuntimeSnapshot.VideoState videoState,
            RuntimeSnapshot.ControlBlocker blocker,
            long epoch,
            long sequence,
            long nowNanos) {
        publish(videoState, RuntimeSnapshot.TransportState.READY, blocker, epoch, sequence, nowNanos);
    }

    private void publish(
            RuntimeSnapshot.VideoState videoState,
            RuntimeSnapshot.TransportState transportState,
            RuntimeSnapshot.ControlBlocker blocker,
            long epoch,
            long sequence,
            long nowNanos) {
        advanceClock(nowNanos);
        if (blocker != currentBlocker) {
            currentBlocker = blocker;
            blockerChangedAtNanos = lastNowNanos;
        }
        long ageNanos = lastNowNanos - blockerChangedAtNanos;
        RuntimeSnapshot.Lifecycle lifecycle = switch (blocker) {
            case RECOVERY_REQUIRED, WAITING_FRESH_IDR -> RuntimeSnapshot.Lifecycle.RECOVERING;
            default -> videoState == RuntimeSnapshot.VideoState.DEGRADED
                    ? RuntimeSnapshot.Lifecycle.RECOVERING
                    : RuntimeSnapshot.Lifecycle.RUNNING;
        };
        RuntimeSnapshot previous = readModel.snapshot();
        boolean stateChanged = previous.lifecycle() != lifecycle
                || previous.videoState() != videoState
                || previous.transportState() != transportState
                || previous.controlBlocker() != blocker;
        if (stateChanged) {
            if (transitionId == Long.MAX_VALUE) {
                throw new IllegalStateException("runtime transition id space exhausted");
            }
            transitionId++;
        }
        readModel.publish(new RuntimeSnapshot(
                lifecycle,
                videoState,
                transportState,
                blocker,
                requireNonNegative(epoch, "epoch"),
                requireNonNegative(sequence, "sequence"),
                transitionId,
                Duration.ofNanos(ageNanos),
                readModel.snapshot().correlationId()));
    }

    private void advanceClock(long nowNanos) {
        if (nowNanos < 0L) {
            throw new IllegalArgumentException("nowNanos must be non-negative");
        }
        if (nowNanos < lastNowNanos) {
            throw new IllegalArgumentException("monotonic clock moved backwards");
        }
        lastNowNanos = nowNanos;
    }

    private void safeDiagnostic(String code, String detail) {
        try {
            diagnostics.record(sanitizeDetail(code), sanitizeDetail(detail));
        } catch (RuntimeException ignored) {
            // 诊断端口绝不能反向击穿视频接收线程。
        }
    }

    private static String sanitizeDetail(String value) {
        if (value == null || value.isBlank()) {
            return "unspecified";
        }
        String compact = value.replaceAll("[^A-Za-z0-9_.-]", "_");
        return compact.length() > 96 ? compact.substring(0, 96) : compact;
    }

    private static String lower(String value) {
        return value.toLowerCase(Locale.ROOT);
    }

    private static long requireNonNegative(long value, String name) {
        if (value < 0L) {
            throw new IllegalArgumentException(name + " must be non-negative");
        }
        return value;
    }
}
