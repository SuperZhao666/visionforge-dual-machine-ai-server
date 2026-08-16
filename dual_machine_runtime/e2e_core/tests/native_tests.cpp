#include "vf/host_pipeline.hpp"
#include "vf/host/domain/stream_identity_generator.hpp"
#include "vf/reassembly.hpp"
#include "vf/recovery.hpp"
#include "vf/wire_protocol.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace std::chrono_literals;

void expect(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void test_wire_roundtrip() {
    const vf::WireHeader original{vf::PacketKind::Data, 0x0102030405060708ULL, 0x11223344U, 2, 5};
    const auto bytes = vf::serialize_wire_header(original);
    const std::array<std::uint8_t, vf::kWireHeaderSize> expected{
        'V', 'F', '2', 'G',
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x02, 0x00, 0x05};
    expect(bytes == expected, "wire vector drifted from mobile protocol");
    const auto parsed = vf::parse_wire_header(bytes);
    expect(parsed.has_value() && *parsed == original, "wire header roundtrip failed");
    auto bad = bytes;
    bad[18] = 0;
    bad[19] = 0;
    expect(!vf::parse_wire_header(bad), "zero fragment count was accepted");
}

void test_reassembly_and_retired_epoch() {
    vf::AccessUnitReassembler reassembler({.max_inflight_frames = 3, .max_total_bytes = 64,
                                           .max_access_unit_bytes = 32, .frame_timeout = 10ms,
                                           .retired_epoch_capacity = 2});
    const auto t0 = vf::AccessUnitReassembler::TimePoint{};
    const std::array<std::uint8_t, 2> a{'a', 'b'};
    const std::array<std::uint8_t, 2> b{'c', 'd'};
    auto result = reassembler.ingest({vf::PacketKind::Data, 1, 7, 0, 2}, a, t0);
    expect(result.code == vf::IngestCode::Accepted, "first fragment not accepted");
    result = reassembler.ingest({vf::PacketKind::Data, 1, 7, 0, 2}, a, t0);
    expect(result.code == vf::IngestCode::Duplicate, "duplicate fragment not recognized");
    result = reassembler.ingest({vf::PacketKind::Data, 1, 7, 1, 2}, b, t0);
    expect(result.code == vf::IngestCode::Complete && result.access_unit.size() == 4 &&
               result.requires_epoch_commit && !reassembler.current_epoch(),
           "initial candidate bypassed two-phase epoch confirmation");
    expect(reassembler.commit_candidate_epoch(1), "validated initial epoch did not commit");
    expect(!reassembler.commit_candidate_epoch(1), "duplicate epoch commit was accepted");

    // 高 epoch 半帧不能退休或阻塞健康当前会话。
    result = reassembler.ingest({vf::PacketKind::Data, 99, 0, 0, 2}, a, t0 + 1ms);
    expect(result.code == vf::IngestCode::Accepted && reassembler.current_epoch() == 1 &&
               reassembler.candidate_epoch() == 99,
           "partial candidate stole current epoch ownership");
    result = reassembler.ingest({vf::PacketKind::Data, 1, 8, 0, 1}, a, t0 + 2ms);
    expect(result.code == vf::IngestCode::Complete && !result.requires_epoch_commit &&
               reassembler.current_epoch() == 1,
           "current stream was blocked by an incomplete candidate");
    reassembler.reject_candidate_epoch(99);
    expect(!reassembler.candidate_epoch() && reassembler.current_epoch() == 1,
           "candidate rejection damaged current epoch");

    result = reassembler.ingest({vf::PacketKind::Data, 2, 0, 0, 1}, a, t0 + 3ms);
    expect(result.code == vf::IngestCode::Complete && result.requires_epoch_commit,
           "new epoch packet did not enter candidate completion");
    expect(reassembler.commit_candidate_epoch(2), "new epoch candidate did not commit");
    result = reassembler.ingest({vf::PacketKind::Data, 1, 8, 0, 1}, a, t0 + 4ms);
    expect(result.code == vf::IngestCode::RetiredEpoch, "retired epoch reclaimed session");
}
void test_reassembly_gap_is_explicit_and_fail_closed() {
    vf::AccessUnitReassembler reassembler({.max_inflight_frames = 3,
                                           .max_total_bytes = 64,
                                           .max_access_unit_bytes = 32,
                                           .frame_timeout = 10ms,
                                           .retired_epoch_capacity = 1});
    const auto t0 = vf::AccessUnitReassembler::TimePoint{};
    const std::array<std::uint8_t, 1> payload{'x'};
    auto result = reassembler.ingest({vf::PacketKind::Data, 3, 0, 0, 1}, payload, t0);
    expect(result.code == vf::IngestCode::Complete && result.requires_epoch_commit &&
               reassembler.commit_candidate_epoch(3),
           "gap test could not establish a committed epoch");
    result = reassembler.ingest({vf::PacketKind::Data, 3, 7, 0, 2}, payload, t0 + 1ms);
    expect(result.code == vf::IngestCode::Accepted, "partial current frame was not buffered");
    result = reassembler.ingest({vf::PacketKind::Data, 3, 8, 0, 1}, payload, t0 + 12ms);
    expect(result.code == vf::IngestCode::GapDetected && reassembler.inflight_count() == 0,
           "expired dependency gap was silently ignored");
    result = reassembler.ingest({vf::PacketKind::Data, 3, 8, 0, 1}, payload, t0 + 13ms);
    expect(result.code == vf::IngestCode::Complete && !result.requires_epoch_commit,
           "receiver did not resume after the caller observed the explicit gap");
}
void test_persisted_stream_identity_rotation() {
    using vf::host::domain::StreamIdentityGenerator;
    StreamIdentityGenerator generator(41, std::numeric_limits<std::uint32_t>::max());
    const auto terminal = generator.next();
    expect(terminal.stream_epoch == 41 &&
               terminal.frame_sequence == std::numeric_limits<std::uint32_t>::max(),
           "terminal frame identity was not emitted exactly once");
    bool reservation_required = false;
    try {
        static_cast<void>(generator.next());
    } catch (const std::overflow_error&) {
        reservation_required = true;
    }
    expect(reservation_required, "sequence exhaustion silently invented an unpersisted epoch");
    generator.rotate_to(52);
    const auto rotated = generator.next();
    expect(rotated.stream_epoch == 52 && rotated.frame_sequence == 0,
           "persisted epoch rotation did not restart the sequence safely");
}

void test_invalid_new_epoch_cannot_steal_session() {
    vf::AccessUnitReassembler reassembler;
    const auto now = vf::AccessUnitReassembler::TimePoint{};
    const std::array<std::uint8_t, 1> payload{'x'};
    auto result = reassembler.ingest({vf::PacketKind::Data, 10, 1, 0, 1}, payload, now);
    expect(result.code == vf::IngestCode::Complete && result.requires_epoch_commit &&
               reassembler.commit_candidate_epoch(10) && reassembler.current_epoch() == 10,
           "initial data epoch was not committed");
    result = reassembler.ingest({vf::PacketKind::Data, 11, 1, 0, 1}, {}, now);
    expect(result.code == vf::IngestCode::Invalid && reassembler.current_epoch() == 10,
           "empty data packet stole epoch ownership");
    result = reassembler.ingest({vf::PacketKind::Repeat, 11, 1, 0, 1}, {}, now);
    expect(result.code == vf::IngestCode::Invalid && reassembler.current_epoch() == 10,
           "repeat-only packet stole epoch ownership");
    result = reassembler.ingest({vf::PacketKind::Repeat, 10, 2, 0, 1}, payload, now);
    expect(result.code == vf::IngestCode::Invalid,
           "repeat packet with payload was accepted");
}
void test_conflicting_fragment_discards_frame() {
    vf::AccessUnitReassembler reassembler;
    const auto now = vf::AccessUnitReassembler::TimePoint{};
    const std::array<std::uint8_t, 1> a{'a'};
    const std::array<std::uint8_t, 1> b{'b'};
    auto established = reassembler.ingest({vf::PacketKind::Data, 1, 0, 0, 1}, a, now);
    expect(established.code == vf::IngestCode::Complete &&
               reassembler.commit_candidate_epoch(1),
           "conflict test could not establish current epoch");
    const auto first = reassembler.ingest({vf::PacketKind::Data, 1, 1, 0, 2}, a, now);
    expect(first.code == vf::IngestCode::Accepted, "first fragment must be accepted");
    const auto result = reassembler.ingest({vf::PacketKind::Data, 1, 1, 0, 2}, b, now);
    expect(result.code == vf::IngestCode::Conflict && reassembler.inflight_count() == 0,
           "conflicting current fragment did not discard frame");
}
void test_repeat_recovery_is_bounded_and_fail_closed() {
    const auto t0 = vf::ReceiverRepeatResyncPolicy::TimePoint{};
    vf::ReceiverRepeatResyncPolicy policy(10ms, 2);
    policy.on_repeat(t0);
    expect(!policy.should_accept(false, false, true, t0 + 1ms), "ordinary frame bypassed IDR wait");
    expect(!policy.should_accept(true, true, true, t0 + 2ms), "repeat IDR bypassed freshness wait");
    expect(policy.poll_action(t0 + 11ms) == vf::RecoveryAction::RequestIdr,
           "first recovery did not request IDR");
    expect(policy.poll_action(t0 + 22ms) == vf::RecoveryAction::RebuildSession,
           "second recovery did not rebuild session");
    expect(!policy.should_accept(false, false, true, t0 + 23ms), "stale content was auto-released");
    policy.on_session_rebuilt(t0 + 23ms);
    expect(!policy.should_accept(false, false, true, t0 + 24ms),
           "rebuilt session accepted a dependent non-IDR frame");
    expect(policy.should_accept(true, false, true, t0 + 25ms),
           "fresh IDR did not recover rebuilt session");

    vf::ReceiverRepeatResyncPolicy no_idr(10ms, 2);
    no_idr.on_repeat(t0);
    expect(no_idr.poll_action(t0 + 11ms) == vf::RecoveryAction::RequestIdr,
           "bounded recovery did not issue its first IDR request");
    expect(no_idr.poll_action(t0 + 22ms) == vf::RecoveryAction::RebuildSession,
           "bounded recovery did not spend its final rebuild attempt");
    no_idr.on_session_rebuilt(t0 + 23ms);
    expect(no_idr.poll_action(t0 + 34ms) == vf::RecoveryAction::None &&
               no_idr.phase() == vf::RecoveryPhase::Exhausted,
           "session rebuild reset the retry budget and created an infinite recovery loop");
}

void test_post_ack_gate_never_auto_allows_on_timeout() {
    const auto t0 = vf::PostAckVisibilityGate::TimePoint{};
    vf::PostAckVisibilityGate gate(10ms);
    bool rejected_zero_window = false;
    try {
        gate.arm_until(3, 10, t0 + 1ms, t0 + 1ms);
    } catch (const std::invalid_argument&) {
        rejected_zero_window = true;
    }
    expect(rejected_zero_window, "zero-length ACK visibility window was accepted");
    gate.arm_until(3, 10, t0 + 1ms, t0 + 11ms);
    expect(gate.evaluate(true, 3, 10, t0 + 2ms, t0 + 2ms) == vf::GateDecision::Blocked,
           "same frame identity unlocked gate");
    expect(gate.evaluate(true, 3, 11, t0, t0 + 3ms) == vf::GateDecision::Blocked,
           "pre-ACK observation unlocked gate");
    expect(gate.evaluate(true, 3, 11, t0 + 8ms, t0 + 3ms) == vf::GateDecision::Blocked,
           "future-dated observation unlocked gate");
    expect(gate.evaluate(false, 3, 11, t0 + 2ms, t0 + 4ms) == vf::GateDecision::Blocked,
           "unchanged content unlocked gate");
    expect(gate.evaluate(true, 4, 0, t0 + 5ms, t0 + 5ms) == vf::GateDecision::Allowed,
           "new epoch IDR was mistaken for a sequence rollback");

    gate.arm_until(4, 0, t0 + 6ms, t0 + 11ms);
    expect(gate.evaluate(true, 4, 1, t0 + 7ms, t0 + 11ms) == vf::GateDecision::RecoveryRequired,
           "deadline boundary did not become recovery-required");
    expect(gate.armed(), "timeout incorrectly auto-released gate");
    gate.reset();
    expect(gate.evaluate(false, 0, t0, t0) == vf::GateDecision::Allowed, "reset gate still blocked");
}

void test_exact_ticket_single_terminal_state() {
    const auto t0 = vf::ExactTicket::TimePoint{};
    vf::ExactTicket ticket;
    ticket.begin(7, t0 + 10ms);
    expect(ticket.complete(8, t0 + 1ms) == vf::TicketResult::WrongTicket,
           "wrong ticket completed pending operation");
    expect(ticket.complete(7, t0 + 2ms) == vf::TicketResult::Completed,
           "correct ticket did not complete");
    expect(ticket.complete(7, t0 + 3ms) == vf::TicketResult::Stale,
           "late duplicate produced second terminal state");

    ticket.begin(8, t0 + 10ms);
    expect(ticket.complete(8, t0 + 10ms) == vf::TicketResult::Expired,
           "late ACK was not expired");
    expect(ticket.expire(t0 + 12ms) == vf::TicketResult::Stale,
           "expired ticket produced second terminal state");

    bool reused_rejected = false;
    try {
        ticket.begin(8, t0 + 20ms);
    } catch (const std::invalid_argument&) {
        reused_rejected = true;
    }
    expect(reused_rejected, "completed ticket id was reused");

    ticket.begin(9, t0 + 30ms);
    expect(ticket.cancel() == vf::TicketResult::Cancelled && !ticket.pending(),
           "ticket cancellation did not produce exactly one terminal state");
    expect(ticket.cancel() == vf::TicketResult::Stale &&
               ticket.complete(9, t0 + 5ms) == vf::TicketResult::Stale,
           "cancelled ticket produced a second terminal state");
}

void test_capture_region_and_idr_publish_semantics() {
    const vf::DesktopBounds desktop{-1920, 0, 3840, 1080};
    expect(vf::CaptureRegion{-1920, 0, 1920, 1080}.valid_within(desktop),
           "negative monitor coordinates were rejected");
    expect(!vf::CaptureRegion{1900, 0, 100, 100}.valid_within(desktop),
           "out-of-bounds region was accepted");

    vf::IdrDeliveryTracker tracker;
    tracker.on_access_unit(1, 10, true,
                           {.fragments_total = 4, .fragments_sent = 3, .socket_error = false});
    expect(tracker.idr_requested() && tracker.delivered_idr_count() == 0,
           "partial IDR was acknowledged");
    tracker.on_access_unit(1, 10, true,
                           {.fragments_total = 4, .fragments_sent = 4, .socket_error = false});
    expect(!tracker.idr_requested() && tracker.delivered_idr_count() == 1,
           "same-IDR retry did not complete the failed publication");

    tracker.on_access_unit(1, 12, true,
                           {.fragments_total = 4, .fragments_sent = 2, .socket_error = true});
    expect(tracker.idr_requested(), "newer failed IDR did not rearm recovery");
    tracker.on_access_unit(1, 11, true,
                           {.fragments_total = 4, .fragments_sent = 4, .socket_error = false});
    expect(tracker.idr_requested() && tracker.delivered_idr_count() == 1,
           "late older IDR cleared a newer failed request");
    tracker.on_access_unit(1, 12, true,
                           {.fragments_total = 4, .fragments_sent = 4, .socket_error = false});
    expect(!tracker.idr_requested() && tracker.delivered_idr_count() == 2,
           "same newer IDR retry did not recover publication");

    tracker.on_access_unit(1, 11, true,
                           {.fragments_total = 4, .fragments_sent = 1, .socket_error = true});
    expect(!tracker.idr_requested(),
           "stale failed IDR reopened recovery after a newer success");
    tracker.request_idr();
    tracker.on_access_unit(1, 12, true,
                           {.fragments_total = 4, .fragments_sent = 4, .socket_error = false});
    expect(tracker.idr_requested() && tracker.delivered_idr_count() == 2,
           "duplicate delivered IDR cleared a later explicit request");

}

void test_blocker_transition_is_low_cardinality() {
    const auto t0 = vf::BlockerTracker::TimePoint{};
    vf::BlockerTracker tracker(t0);
    tracker.set(vf::ControlBlocker::WaitingFreshIdr, t0 + 1ms);
    tracker.set(vf::ControlBlocker::WaitingFreshIdr, t0 + 2ms);
    expect(tracker.transition_id() == 1, "stable blocker incremented transition id");
    expect(vf::blocker_name(tracker.current()) == "WAITING_FRESH_IDR", "blocker name mismatch");
    expect(tracker.age(t0 + 6ms) == 5ms, "blocker age mismatch");
}

}  // namespace

int main() {
    try {
        test_wire_roundtrip();
        test_reassembly_and_retired_epoch();
        test_reassembly_gap_is_explicit_and_fail_closed();
        test_persisted_stream_identity_rotation();
        test_invalid_new_epoch_cannot_steal_session();
        test_conflicting_fragment_discards_frame();
        test_repeat_recovery_is_bounded_and_fail_closed();
        test_post_ack_gate_never_auto_allows_on_timeout();
        test_exact_ticket_single_terminal_state();
        test_capture_region_and_idr_publish_semantics();
        test_blocker_transition_is_low_cardinality();
        std::cout << "VISIONFORGE_NATIVE_TESTS_OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "VISIONFORGE_NATIVE_TESTS_FAILED: " << error.what() << '\n';
        return 1;
    }
}
