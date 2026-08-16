package com.visionforge.mobile.application;

import com.visionforge.mobile.domain.control.BluetoothReconcileCoordinator;
import com.visionforge.mobile.domain.control.ControlDecisionEngine;
import com.visionforge.mobile.domain.control.ExactCommandTicket;
import com.visionforge.mobile.domain.control.PostAckVisibilityGate;
import com.visionforge.mobile.domain.runtime.AbsoluteDeadline;
import com.visionforge.mobile.domain.video.DecodedFrameMetadataLedger;
import com.visionforge.mobile.domain.video.H264AccessUnitClassifier;
import com.visionforge.mobile.domain.video.OrderedAccessUnitHandoff;
import com.visionforge.mobile.domain.video.VideoFragmentHeader;
import com.visionforge.mobile.domain.video.VideoPacketKind;
import com.visionforge.mobile.ports.DecoderPort;
import com.visionforge.mobile.ports.RecoveryPort;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class MobileArchitectureSelfTest {
    private MobileArchitectureSelfTest() {}

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static byte[] datagram(long epoch, long sequence, int index, int count, byte[] payload) {
        byte[] header = new VideoFragmentHeader(
                VideoPacketKind.DATA, epoch, sequence, index, count).encode();
        byte[] result = Arrays.copyOf(header, header.length + payload.length);
        System.arraycopy(payload, 0, result, header.length, payload.length);
        return result;
    }

    private static byte[] repeat(long epoch, long sequence) {
        byte[] payload = predicted(77);
        byte[] header = new VideoFragmentHeader(
                VideoPacketKind.REPEAT, epoch, sequence, 0, 1).encode();
        byte[] result = Arrays.copyOf(header, header.length + payload.length);
        System.arraycopy(payload, 0, result, header.length, payload.length);
        return result;
    }

    private static byte[] idr(int marker) {
        return new byte[] {0, 0, 0, 1, 0x65, (byte) marker};
    }

    private static byte[] predicted(int marker) {
        return new byte[] {0, 0, 1, 0x41, (byte) marker};
    }

    private static void testProtocolAndReassembly() {
        VideoFragmentHeader header = new VideoFragmentHeader(
                VideoPacketKind.DATA, 0x0102030405060708L, 0x11223344L, 2, 5);
        byte[] expected = new byte[] {
                'V', 'F', '2', 'G',
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x11, 0x22, 0x33, 0x44,
                0x00, 0x02, 0x00, 0x05
        };
        check(Arrays.equals(header.encode(), expected), "Java wire vector drifted from C++");
        check(VideoFragmentHeader.decode(expected).equals(header), "wire round-trip failed");
        try {
            new VideoFragmentHeader(VideoPacketKind.DATA, 1L, 0L, 0, 4097);
            throw new AssertionError("fragment count above shared cap was accepted");
        } catch (IllegalArgumentException expectedFailure) {
            // expected
        }

        VideoPreflightReassemblyWindow window = new VideoPreflightReassemblyWindow(
                new VideoPreflightReassemblyWindow.Config(3, 64, 32, 100));
        byte[] first = new byte[] {1, 2};
        byte[] second = new byte[] {3, 4};
        var result = window.ingest(
                new VideoFragmentHeader(VideoPacketKind.DATA, 10, 7, 1, 2), second, 0);
        check(result.code() == VideoPreflightReassemblyWindow.Code.ACCEPTED,
                "out-of-order second fragment not buffered");
        result = window.ingest(
                new VideoFragmentHeader(VideoPacketKind.DATA, 10, 7, 0, 2), first, 1);
        check(result.code() == VideoPreflightReassemblyWindow.Code.COMPLETE
                        && result.requiresEpochCommit()
                        && Arrays.equals(result.accessUnit(), new byte[] {1, 2, 3, 4})
                        && window.currentEpoch().isEmpty(),
                "candidate access unit bypassed two-phase epoch confirmation");
        check(window.commitCandidateEpoch(10L)
                        && window.currentEpoch().orElseThrow() == 10L,
                "validated candidate epoch was not committed");
        check(!window.commitCandidateEpoch(10L),
                "candidate epoch accepted a duplicate commit");

        result = window.ingest(
                new VideoFragmentHeader(VideoPacketKind.DATA, 11, 0, 0, 1), new byte[0], 2);
        check(result.code() == VideoPreflightReassemblyWindow.Code.INVALID
                        && window.currentEpoch().orElseThrow() == 10L,
                "empty DATA packet stole epoch ownership");
        result = window.ingest(
                new VideoFragmentHeader(VideoPacketKind.REPEAT, 11, 0, 0, 1), new byte[0], 3);
        check(result.code() == VideoPreflightReassemblyWindow.Code.CANDIDATE_REJECTED
                        && window.currentEpoch().orElseThrow() == 10L,
                "repeat-only packet stole epoch ownership");

        // 高 epoch 半帧只能占用候选槽；当前流仍可继续接收并保持高水位。
        result = window.ingest(
                new VideoFragmentHeader(VideoPacketKind.DATA, 999, 0, 0, 2), first, 4);
        check(result.code() == VideoPreflightReassemblyWindow.Code.ACCEPTED
                        && window.currentEpoch().orElseThrow() == 10L
                        && window.candidateEpoch().orElseThrow() == 999L,
                "partial candidate stole or failed to isolate the current epoch");
        result = window.ingest(
                new VideoFragmentHeader(VideoPacketKind.DATA, 10, 8, 0, 1), first, 5);
        check(result.code() == VideoPreflightReassemblyWindow.Code.COMPLETE
                        && !result.requiresEpochCommit()
                        && window.currentEpoch().orElseThrow() == 10L,
                "healthy current stream was blocked by an incomplete candidate");
        window.rejectCandidateEpoch(999L);
        check(window.candidateEpoch().isEmpty() && window.currentEpoch().orElseThrow() == 10L,
                "candidate rejection damaged the committed current epoch");

        // 候选内部出现语义冲突时，只回收候选，不能破坏当前流。
        result = window.ingest(
                new VideoFragmentHeader(VideoPacketKind.DATA, 11, 0, 0, 2), first, 6);
        check(result.code() == VideoPreflightReassemblyWindow.Code.ACCEPTED,
                "candidate first fragment was not buffered");
        result = window.ingest(
                new VideoFragmentHeader(VideoPacketKind.DATA, 11, 0, 0, 2), second, 7);
        check(result.code() == VideoPreflightReassemblyWindow.Code.CANDIDATE_REJECTED
                        && window.currentEpoch().orElseThrow() == 10L
                        && window.candidateEpoch().isEmpty(),
                "candidate conflict corrupted the active session");

        VideoPreflightReassemblyWindow timeoutWindow = new VideoPreflightReassemblyWindow(
                new VideoPreflightReassemblyWindow.Config(3, 64, 32, 10));
        result = timeoutWindow.ingest(
                new VideoFragmentHeader(VideoPacketKind.DATA, 20, 0, 0, 1), first, 0);
        check(result.code() == VideoPreflightReassemblyWindow.Code.COMPLETE
                        && timeoutWindow.commitCandidateEpoch(20L),
                "timeout test could not establish a committed epoch");
        result = timeoutWindow.ingest(
                new VideoFragmentHeader(VideoPacketKind.DATA, 20, 7, 0, 2), first, 1);
        check(result.code() == VideoPreflightReassemblyWindow.Code.ACCEPTED,
                "partial current frame was not buffered before timeout");
        result = timeoutWindow.ingest(
                new VideoFragmentHeader(VideoPacketKind.DATA, 20, 8, 0, 1), first, 12);
        check(result.code() == VideoPreflightReassemblyWindow.Code.GAP_DETECTED
                        && timeoutWindow.inflightCount() == 0,
                "expired current prediction dependency was silently ignored");
        result = timeoutWindow.ingest(
                new VideoFragmentHeader(VideoPacketKind.DATA, 20, 8, 0, 1), first, 13);
        check(result.code() == VideoPreflightReassemblyWindow.Code.COMPLETE
                        && !result.requiresEpochCommit(),
                "current receiver did not resume after the explicit gap was observed");

        for (long epoch = 11; epoch < 50; epoch++) {
            result = window.ingest(
                    new VideoFragmentHeader(VideoPacketKind.DATA, epoch, 0, 0, 1), first, epoch + 10);
            check(result.code() == VideoPreflightReassemblyWindow.Code.COMPLETE
                            && result.requiresEpochCommit()
                            && window.commitCandidateEpoch(epoch),
                    "new epoch did not complete its two-phase commit");
        }
        result = window.ingest(
                new VideoFragmentHeader(VideoPacketKind.DATA, 10, 99, 0, 1), first, 100);
        check(result.code() == VideoPreflightReassemblyWindow.Code.STALE_EPOCH,
                "very old epoch reclaimed the receiver");
    }

    private static void testH264AndOrderedHandoff() {
        var classification = H264AccessUnitClassifier.classify(idr(1));
        check(!classification.malformed() && classification.containsIdr(),
                "IDR Annex-B unit was not recognized");
        check(H264AccessUnitClassifier.classify(new byte[] {1, 2, 3}).malformed(),
                "malformed access unit was accepted");
        check(H264AccessUnitClassifier.classify(new byte[] {9, 0, 0, 1, 0x65}).malformed(),
                "non-zero leading garbage was accepted");
        check(H264AccessUnitClassifier.classify(new byte[] {0, 0, 1, 0x65}).malformed(),
                "header-only NAL was accepted");
        check(H264AccessUnitClassifier.classify(new byte[] {0, 0, 1, (byte) 0x80}).malformed(),
                "forbidden_zero_bit was accepted");

        OrderedAccessUnitHandoff handoff = new OrderedAccessUnitHandoff(4);
        check(handoff.offer(new OrderedAccessUnitHandoff.AccessUnit(1, 1, false, false, predicted(1)))
                        == OrderedAccessUnitHandoff.OfferDecision.NEED_IDR,
                "predictive frame bypassed initial IDR gate");
        check(handoff.offer(new OrderedAccessUnitHandoff.AccessUnit(1, 0, true, false, idr(0)))
                        == OrderedAccessUnitHandoff.OfferDecision.ACCEPTED,
                "IDR did not establish running state");
        check(handoff.offer(new OrderedAccessUnitHandoff.AccessUnit(1, 2, false, false, predicted(2)))
                        == OrderedAccessUnitHandoff.OfferDecision.ACCEPTED,
                "future frame was not buffered");
        check(handoff.offer(new OrderedAccessUnitHandoff.AccessUnit(1, 1, false, false, predicted(1)))
                        == OrderedAccessUnitHandoff.OfferDecision.ACCEPTED,
                "missing intermediate frame was not accepted");
        check(handoff.pollReady().orElseThrow().frameSequence() == 0,
                "IDR was not delivered first");
        check(handoff.pollReady().orElseThrow().frameSequence() == 1,
                "predictive frame 1 was not delivered second");
        check(handoff.pollReady().orElseThrow().frameSequence() == 2,
                "predictive frame 2 was not delivered third");

        OrderedAccessUnitHandoff rollover = new OrderedAccessUnitHandoff(2);
        check(rollover.offer(new OrderedAccessUnitHandoff.AccessUnit(
                        8, VideoFragmentHeader.UINT32_MAX, true, false, idr(8)))
                        == OrderedAccessUnitHandoff.OfferDecision.EPOCH_ADVANCED,
                "terminal sequence IDR was rejected");
        check(rollover.pollReady().orElseThrow().frameSequence() == VideoFragmentHeader.UINT32_MAX,
                "terminal sequence was not delivered");
        check(rollover.offer(new OrderedAccessUnitHandoff.AccessUnit(8, 0, true, false, idr(9)))
                        == OrderedAccessUnitHandoff.OfferDecision.EPOCH_EXHAUSTED,
                "sequence wrap reused an exhausted epoch");
        check(rollover.offer(new OrderedAccessUnitHandoff.AccessUnit(9, 0, true, false, idr(10)))
                        == OrderedAccessUnitHandoff.OfferDecision.EPOCH_ADVANCED,
                "new epoch did not recover sequence exhaustion");

        OrderedAccessUnitHandoff conflict = new OrderedAccessUnitHandoff(2);
        conflict.offer(new OrderedAccessUnitHandoff.AccessUnit(12, 0, true, false, idr(1)));
        check(conflict.offer(new OrderedAccessUnitHandoff.AccessUnit(12, 0, true, false, idr(2)))
                        == OrderedAccessUnitHandoff.OfferDecision.CONFLICT
                        && conflict.state() == OrderedAccessUnitHandoff.State.WAITING_IDR,
                "same identity with different bytes did not fail closed");
    }

    private static void testDecodedMetadataSemanticConflicts() {
        DecodedFrameMetadataLedger ledger = new DecodedFrameMetadataLedger();
        var first = new DecodedFrameMetadataLedger.Metadata(
                3L, 7L, 99L, true, false, true, 10L);
        check(ledger.observe(first).acceptedForInference(),
                "fresh decoded metadata was rejected");
        var semanticConflict = new DecodedFrameMetadataLedger.Metadata(
                3L, 7L, 99L, false, false, true, 11L);
        check(ledger.observe(semanticConflict).disposition()
                        == DecodedFrameMetadataLedger.Disposition.SEQUENCE_CONFLICT,
                "same identity with different IDR semantics was treated as a duplicate");
    }

    private static void testControlStateMachines() {
        ExactCommandTicket ticket = new ExactCommandTicket();
        ticket.begin(7L, AbsoluteDeadline.after(10L, 20L));
        check(ticket.complete(8L, 11L) == ExactCommandTicket.Result.WRONG_TICKET,
                "wrong ticket completed current command");
        check(ticket.complete(7L, 30L) == ExactCommandTicket.Result.EXPIRED,
                "late ACK was accepted");
        check(ticket.complete(7L, 32L) == ExactCommandTicket.Result.STALE,
                "ticket produced a second terminal state");
        try {
            ticket.begin(7L, AbsoluteDeadline.after(40L, 10L));
            throw new AssertionError("completed ticket id was reused");
        } catch (IllegalArgumentException expectedFailure) {
            // Expected.
        }

        PostAckVisibilityGate gate = new PostAckVisibilityGate();
        try {
            gate.arm(3L, 10L, 5L, new AbsoluteDeadline(5L));
            throw new AssertionError("zero-length ACK visibility window was accepted");
        } catch (IllegalArgumentException expectedFailure) {
            // Expected.
        }
        gate.arm(3L, 10L, 5L, AbsoluteDeadline.after(5L, 10L));
        check(gate.evaluate(true, 3L, 10L, 6L, 6L)
                        == PostAckVisibilityGate.Decision.BLOCKED,
                "same source frame opened visibility gate");
        check(gate.evaluate(true, 3L, 11L, 20L, 7L)
                        == PostAckVisibilityGate.Decision.BLOCKED,
                "future-dated observation opened visibility gate");
        check(gate.evaluate(true, 4L, 0L, 7L, 7L)
                        == PostAckVisibilityGate.Decision.ALLOWED,
                "new epoch IDR was mistaken for a sequence rollback");
        gate.arm(4L, 0L, 8L, AbsoluteDeadline.after(8L, 8L));
        check(gate.evaluate(true, 4L, 1L, 9L, 16L)
                        == PostAckVisibilityGate.Decision.RECOVERY_REQUIRED,
                "visibility timeout auto-released stale content");

        ControlDecisionEngine engine = new ControlDecisionEngine();
        var decision = engine.decide(new ControlDecisionEngine.Facts(
                true, true, true, false, false, true, false, true, false));
        check(!decision.outputAllowed()
                        && decision.blocker() == ControlDecisionEngine.Blocker.DETECTED_NOT_TRACK_ELIGIBLE,
                "detection presence was confused with tracking eligibility");
        decision = engine.decide(new ControlDecisionEngine.Facts(
                true, true, true, true, false, false, false, true, false));
        check(decision.blocker() == ControlDecisionEngine.Blocker.SUBCOUNT_UNRESOLVABLE,
                "subcount state was confused with deadzone");

        BluetoothReconcileCoordinator bluetooth = new BluetoothReconcileCoordinator(100L, 0L);
        var request = bluetooth.onBluetoothRecovered("event-1");
        var duplicate = bluetooth.onBluetoothRecovered("event-1");
        check(request.generation() == duplicate.generation() && !duplicate.newlyScheduled(),
                "duplicate Bluetooth event created duplicate reconcile work");
        check(bluetooth.poll(100L).generation() == request.generation(),
                "periodic poll duplicated an outstanding reconcile");
        check(bluetooth.acknowledge(request.generation()), "reconcile ACK failed");
        check(bluetooth.poll(99L) == null && bluetooth.poll(100L) != null,
                "periodic health fallback timing is wrong");
    }

    private static void testCompositionRoot() {
        RecordingDecoder decoder = new RecordingDecoder();
        RecordingRecovery recovery = new RecordingRecovery();
        MobileRuntimeCompositionRoot runtime = new MobileRuntimeCompositionRoot(
                new VideoPreflightReassemblyWindow.Config(8, 1024, 256, 1_000_000L),
                4,
                decoder,
                recovery,
                "corr-e2e");

        check(runtime.onDatagram(datagram(1, 0, 0, 1, idr(0)), 0)
                        == MobileRuntimeCompositionRoot.DatagramOutcome.BUFFERED,
                "epoch IDR should wait for decoder restart completion");
        check(decoder.restarts.equals(List.of(1L)) && decoder.submissions.isEmpty(),
                "new epoch was submitted into old decoder session");
        check(runtime.onDatagram(datagram(1, 1, 0, 1, predicted(1)), 1)
                        == MobileRuntimeCompositionRoot.DatagramOutcome.BUFFERED,
                "predictive frame was not buffered during restart");
        runtime.onDecoderRestartComplete(1L);
        check(decoder.submissions.equals(List.of("1:0:I", "1:1:P")),
                "restart completion did not drain ordered frames");

        check(runtime.onDatagram(repeat(1, 2), 2)
                        == MobileRuntimeCompositionRoot.DatagramOutcome.ACCESS_UNIT_SUBMITTED,
                "repeat access unit did not maintain the decoder reference chain");
        check(decoder.submissions.get(decoder.submissions.size() - 1).equals("1:2:P"),
                "repeat access unit was not delivered in decode order");
        check(recovery.idrReasons.isEmpty(),
                "healthy repeat access unit incorrectly requested IDR recovery");
        check(runtime.readModel().snapshot().controlBlocker()
                        == com.visionforge.mobile.core.RuntimeSnapshot.ControlBlocker.WAITING_FRESH_IDR,
                "repeat access unit was incorrectly exposed as fresh visual content");

        // epoch 2 restart is superseded by epoch 3 before completion. Only latest epoch may drain.
        runtime.onDatagram(datagram(2, 0, 0, 1, idr(2)), 3);
        runtime.onDatagram(datagram(3, 0, 0, 1, idr(3)), 4);
        check(decoder.restarts.equals(List.of(1L, 2L)),
                "restart requests were not coalesced while one was in flight");
        runtime.onDecoderRestartComplete(2L);
        check(decoder.restarts.equals(List.of(1L, 2L, 3L)),
                "completion did not converge on latest epoch");
        runtime.onDecoderRestartComplete(3L);
        check(decoder.submissions.get(decoder.submissions.size() - 1).equals("3:0:I"),
                "retired epoch frame reached decoder after coalesced restart");

        int submissionsBeforeLateCallback = decoder.submissions.size();
        runtime.onDecoderRestartComplete(2L);
        check(decoder.submissions.size() == submissionsBeforeLateCallback,
                "late decoder completion drained frames twice");

        runtime.onDatagram(datagram(4, 0, 0, 1, idr(4)), 5);
        runtime.onDecoderRestartComplete(5L);
        check(!recovery.rebuildReasons.isEmpty()
                        && recovery.rebuildReasons.get(recovery.rebuildReasons.size() - 1)
                                .contains("decoder_restart_future_completion"),
                "impossible future completion did not fail closed");


        runtime.onDatagram(datagram(6, 0, 0, 1, idr(6)), 6);
        runtime.onDecoderRestartFailed(7L, "future", 7L);
        check(recovery.rebuildReasons.get(recovery.rebuildReasons.size() - 1)
                        .contains("decoder_restart_future_failure"),
                "impossible future failure did not fail closed");

        // 恶意或损坏的高 epoch 完整帧不得退休健康当前流，也不得触发解码器重启。
        RecordingDecoder candidateDecoder = new RecordingDecoder();
        RecordingRecovery candidateRecovery = new RecordingRecovery();
        MobileRuntimeCompositionRoot candidateRuntime = new MobileRuntimeCompositionRoot(
                new VideoPreflightReassemblyWindow.Config(8, 1024, 256, 1_000_000L),
                4,
                candidateDecoder,
                candidateRecovery,
                "corr-candidate");
        check(candidateRuntime.onDatagram(datagram(1, 0, 0, 1, idr(1)), 0L)
                        == MobileRuntimeCompositionRoot.DatagramOutcome.BUFFERED,
                "candidate test could not start epoch 1");
        candidateRuntime.onDecoderRestartComplete(1L, 1L);
        check(candidateRuntime.readModel().snapshot().streamEpoch() == 1L,
                "candidate test did not settle the initial stream");
        check(candidateRuntime.onDatagram(
                        datagram(99, 0, 0, 1, new byte[] {1, 2, 3}), 2L)
                        == MobileRuntimeCompositionRoot.DatagramOutcome.RECOVERY_REQUESTED
                        && candidateRuntime.readModel().snapshot().streamEpoch() == 1L
                        && candidateDecoder.restarts.equals(List.of(1L)),
                "malformed high epoch retired or restarted the healthy current stream");
        check(candidateRuntime.onDatagram(datagram(2, 0, 0, 1, predicted(2)), 3L)
                        == MobileRuntimeCompositionRoot.DatagramOutcome.RECOVERY_REQUESTED
                        && candidateRuntime.readModel().snapshot().streamEpoch() == 1L,
                "non-IDR candidate epoch stole current ownership");
        check(candidateRuntime.onDatagram(datagram(2, 0, 0, 1, idr(2)), 4L)
                        == MobileRuntimeCompositionRoot.DatagramOutcome.BUFFERED
                        && candidateDecoder.restarts.equals(List.of(1L, 2L)),
                "fresh IDR could not recover after rejected candidates");

        try {
            runtime.onDatagram(datagram(8, 0, 0, 1, idr(8)), 6L);
            throw new AssertionError("backward monotonic time was accepted");
        } catch (IllegalArgumentException expectedFailure) {
            // Expected.
        }
    }

    private static final class RecordingDecoder implements DecoderPort {
        private final List<Long> restarts = new ArrayList<>();
        private final List<String> submissions = new ArrayList<>();

        @Override
        public void restartForEpoch(long streamEpoch) {
            restarts.add(streamEpoch);
        }

        @Override
        public void submit(long streamEpoch, long frameSequence, boolean idr, byte[] accessUnit) {
            submissions.add(streamEpoch + ":" + frameSequence + ":" + (idr ? "I" : "P"));
        }
    }

    private static final class RecordingRecovery implements RecoveryPort {
        private final List<String> idrReasons = new ArrayList<>();
        private final List<String> rebuildReasons = new ArrayList<>();

        @Override
        public void requestIdr(long streamEpoch, String reason) {
            idrReasons.add(streamEpoch + ":" + reason);
        }

        @Override
        public void requestSessionRebuild(long streamEpoch, String reason) {
            rebuildReasons.add(streamEpoch + ":" + reason);
        }
    }

    public static void main(String[] args) {
        testProtocolAndReassembly();
        testH264AndOrderedHandoff();
        testDecodedMetadataSemanticConflicts();
        testControlStateMachines();
        testCompositionRoot();
        System.out.println("VISIONFORGE_MOBILE_ARCHITECTURE_TESTS_OK");
    }
}
