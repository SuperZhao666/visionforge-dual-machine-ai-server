#include "MakcuOutputGate.hpp"

#include <atomic>
#include <barrier>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <latch>
#include <limits>
#include <thread>

namespace {

[[noreturn]] void check_failed(const char* expression, int line) {
  std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
  std::abort();
}

#define CHECK(expression) \
  do { if (!(expression)) check_failed(#expression, __LINE__); } while (false)

void verify_stale_resume_cannot_release_new_recovery() {
  constexpr std::uint64_t kIterations = 20'000U;
  vfdual_android::MakcuOutputGate gate;
  std::barrier phase(3);
  std::atomic_bool failed{};

  std::thread stale_resumer([&] {
    for (std::uint64_t generation = 1U; generation <= kIterations; ++generation) {
      phase.arrive_and_wait();
      static_cast<void>(gate.complete_after_valid_frame(generation * 2U));
      phase.arrive_and_wait();
    }
  });
  std::thread new_recovery([&] {
    for (std::uint64_t generation = 1U; generation <= kIterations; ++generation) {
      phase.arrive_and_wait();
      gate.suspend_for_recovery(generation * 2U + 1U);
      phase.arrive_and_wait();
    }
  });

  CHECK(gate.set_user_requested(true));
  for (std::uint64_t generation = 1U; generation <= kIterations; ++generation) {
    gate.suspend_for_recovery(generation * 2U);
    phase.arrive_and_wait();
    phase.arrive_and_wait();
    const bool recovery_suspended = gate.recovery_suspended();
    const auto stale = gate.complete_after_valid_frame(generation * 2U);
    const auto current = gate.complete_after_valid_frame(generation * 2U + 1U);
    if (!recovery_suspended || stale.matched || !current.matched ||
        !current.output_enabled) {
      failed.store(true, std::memory_order_release);
    }
  }
  stale_resumer.join();
  new_recovery.join();
  CHECK(!failed.load(std::memory_order_acquire));
  CHECK(gate.output_enabled());
}

void verify_delivery_fail_close_preserves_active_stream_generation() {
  using vfdual_android::MakcuStreamCloseScope;
  vfdual_android::MakcuStreamGenerationGate generation_gate;

  generation_gate.activate(73U);
  CHECK(generation_gate.active() == 73U);
  CHECK(generation_gate.accepts(73U));
  CHECK(!generation_gate.accepts(0U));
  CHECK(!generation_gate.accepts(74U));

  generation_gate.fail_closed(MakcuStreamCloseScope::delivery_failure);
  CHECK(generation_gate.active() == 73U);
  CHECK(generation_gate.accepts(73U));

  generation_gate.activate(74U);
  CHECK(generation_gate.accepts(74U));
  CHECK(!generation_gate.accepts(73U));

  generation_gate.fail_closed(MakcuStreamCloseScope::stream_lifecycle);
  CHECK(generation_gate.active() == 0U);
  CHECK(!generation_gate.accepts(74U));
}

void verify_offer_and_suspend_are_linearized() {
  vfdual_android::MakcuOutputGate gate;
  CHECK(gate.set_user_requested(true));

  std::latch offer_entered(1);
  std::latch release_offer(1);
  std::latch suspend_started(1);
  std::atomic_bool offer_completed{};
  std::atomic_bool suspend_returned{};

  std::thread dispatcher([&] {
    const bool executed = gate.execute_if_enabled([&] {
      offer_entered.count_down();
      release_offer.wait();
      offer_completed.store(true, std::memory_order_release);
    });
    CHECK(executed);
  });
  offer_entered.wait();

  std::thread suspender([&] {
    suspend_started.count_down();
    gate.suspend_for_recovery(101U);
    suspend_returned.store(true, std::memory_order_release);
  });
  suspend_started.wait();
  CHECK(!suspend_returned.load(std::memory_order_acquire));

  release_offer.count_down();
  dispatcher.join();
  suspender.join();
  CHECK(offer_completed.load(std::memory_order_acquire));
  CHECK(suspend_returned.load(std::memory_order_acquire));
  CHECK(gate.recovery_suspended());
  CHECK(!gate.output_enabled());

  bool stale_offer_entered = false;
  CHECK(!gate.execute_if_enabled([&] { stale_offer_entered = true; }));
  CHECK(!stale_offer_entered);
}

void verify_two_phase_suspend_cancellation_fails_closed() {
  vfdual_android::MakcuOutputGate gate;
  CHECK(gate.set_user_requested(true));
  constexpr std::uint64_t kGeneration = 201U;

  gate.suspend_for_recovery(kGeneration);
  // Simulate explicit close/reopen while the native-to-Java suspend callback
  // is blocked. Java may still report that its late suspend succeeded.
  gate.fail_closed();
  CHECK(gate.set_user_requested(true));
  const bool java_suspend_succeeded = true;
  const bool same_native_hold = gate.recovery_suspended_for(kGeneration);
  CHECK(java_suspend_succeeded && !same_native_hold);
  if (!same_native_hold) gate.fail_closed();

  CHECK(!gate.user_requested());
  CHECK(!gate.output_enabled());
  CHECK(!gate.recovery_suspended());
}

void verify_move_commit_requires_matching_device_ack() {
  vfdual_android::MakcuMoveCommitGate gate;
  CHECK(gate.begin(0U, 1U) == 0U);
  CHECK(gate.begin(1'000U, 0U) == 0U);
  const std::uint64_t first = gate.begin(1'000U, 41U);
  CHECK(first != 0U);
  CHECK(gate.pending());
  CHECK(gate.pending_ticket() == first);
  CHECK(gate.begin(1'001U, 42U) == 0U);
  const auto inspected = gate.inspect(first);
  CHECK(inspected.matched && inspected.source_sequence == 41U);
  CHECK(!gate.inspect(first + 1U).matched);
  CHECK(!gate.complete(first + 1U).matched);
  CHECK(gate.pending_ticket() == first);
  const auto completed = gate.complete(first);
  CHECK(completed.matched && completed.source_sequence == 41U);
  CHECK(!gate.pending());
  CHECK(!gate.complete(first).matched);
}

void verify_stale_or_duplicate_feedback_never_revokes_current_output() {
  using vfdual_android::MakcuMoveFeedbackAction;
  CHECK(vfdual_android::classify_makcu_move_feedback(false, false) ==
        MakcuMoveFeedbackAction::ignore_stale);
  CHECK(vfdual_android::classify_makcu_move_feedback(false, true) ==
        MakcuMoveFeedbackAction::ignore_stale);
  CHECK(vfdual_android::classify_makcu_move_feedback(true, false) ==
        MakcuMoveFeedbackAction::fail_current);
  CHECK(vfdual_android::classify_makcu_move_feedback(true, true) ==
        MakcuMoveFeedbackAction::complete_current);

  vfdual_android::MakcuOutputGate output_gate;
  vfdual_android::MakcuMoveCommitGate commit_gate;
  vfdual_android::MakcuMoveVisibilityGate visibility_gate;
  CHECK(output_gate.set_user_requested(true));
  output_gate.revoke_immediately();
  bool revoked_action_ran = false;
  CHECK(!output_gate.execute_if_enabled([&] {
    revoked_action_ran = true;
  }));
  CHECK(!revoked_action_ran);
  CHECK(!output_gate.output_enabled());
  CHECK(output_gate.set_user_requested(true));
  CHECK(output_gate.output_enabled());
  const std::uint64_t ticket = commit_gate.begin(1'000U, 41U);
  CHECK(ticket != 0U);
  const auto completion = commit_gate.complete(ticket);
  CHECK(completion.matched && completion.source_sequence == 41U);
  visibility_gate.arm(completion.source_sequence, 2'000U, 0U);

  const auto duplicate = vfdual_android::classify_makcu_move_feedback(
      commit_gate.inspect(ticket).matched, true);
  CHECK(duplicate == MakcuMoveFeedbackAction::ignore_stale);
  CHECK(output_gate.output_enabled());
  CHECK(visibility_gate.armed());

  vfdual_android::MakcuMoveCommitGate ordered_commit;
  vfdual_android::MakcuMoveVisibilityGate ordered_visibility;
  const std::uint64_t ordered_ticket = ordered_commit.begin(3'000U, 42U);
  bool dependent_state_committed = false;
  const auto ordered_completion = ordered_commit.complete_with(
      ordered_ticket, [&](std::uint64_t source_sequence) noexcept {
        ordered_visibility.arm(source_sequence, 4'000U, 0U);
        dependent_state_committed = true;
      });
  CHECK(ordered_completion.matched);
  CHECK(dependent_state_committed);
  CHECK(!ordered_commit.pending());
  CHECK(ordered_visibility.armed());
  bool stale_action_ran = false;
  CHECK(!ordered_commit.complete_with(
      ordered_ticket, [&](std::uint64_t) noexcept {
        stale_action_ran = true;
      }).matched);
  CHECK(!stale_action_ran);
  CHECK(ordered_visibility.armed());
}

void verify_stale_device_ack_cannot_commit_after_fail_close() {
  vfdual_android::MakcuMoveCommitGate gate;
  const std::uint64_t stale = gate.begin(1'000U, 1U);
  CHECK(stale != 0U);
  gate.fail_closed();
  CHECK(!gate.pending());

  const std::uint64_t current = gate.begin(2'000U, 2U);
  CHECK(current != 0U && current != stale);
  CHECK(!gate.complete(stale).matched);
  CHECK(gate.pending_ticket() == current);
  CHECK(gate.complete(current).matched);
}

void verify_ack_failure_then_reauthorization_continues_same_stream() {
  using vfdual_android::MakcuStreamCloseScope;
  vfdual_android::MakcuOutputGate output_gate;
  vfdual_android::MakcuMoveCommitGate commit_gate;
  vfdual_android::MakcuMoveVisibilityGate visibility_gate;
  vfdual_android::MakcuStreamGenerationGate generation_gate;
  generation_gate.activate(7U);
  CHECK(output_gate.set_user_requested(true));

  const std::uint64_t failed_ticket = commit_gate.begin(1'000U, 41U);
  CHECK(failed_ticket != 0U);
  CHECK(commit_gate.inspect(failed_ticket).matched);

  // A real negative device ACK executes the same two fail-closed transitions:
  // revoke native output authorization and invalidate the in-flight ticket.
  generation_gate.fail_closed(MakcuStreamCloseScope::delivery_failure);
  output_gate.fail_closed();
  commit_gate.fail_closed();
  visibility_gate.fail_closed();
  CHECK(generation_gate.accepts(7U));
  CHECK(!output_gate.output_enabled());
  CHECK(!commit_gate.pending());

  // A freshly verified reconnect reapplies the user's profile. That explicit
  // authorization must admit a new ticket without reviving the failed one.
  CHECK(output_gate.set_user_requested(true));
  bool fresh_offer_authorized = false;
  CHECK(output_gate.execute_if_enabled([&] { fresh_offer_authorized = true; }));
  CHECK(fresh_offer_authorized);
  CHECK(generation_gate.accepts(7U));
  const std::uint64_t fresh_ticket = commit_gate.begin(2'000U, 42U);
  CHECK(fresh_ticket != 0U && fresh_ticket != failed_ticket);
  CHECK(!commit_gate.complete(failed_ticket).matched);
  const auto completion = commit_gate.complete_with(
      fresh_ticket, [&](std::uint64_t source_sequence) noexcept {
        visibility_gate.arm(source_sequence, 2'100U, 0U);
      });
  CHECK(completion.matched && completion.source_sequence == 42U);
  CHECK(visibility_gate.armed());

  // Reconnection alone must not replay the acknowledged observation. The next
  // real content update from the preserved stream makes another correction
  // eligible without requiring a decoder restart or a new stream generation.
  CHECK(!visibility_gate.consume_if_visible(42U, 2'200U, true));
  CHECK(!visibility_gate.consume_if_visible(43U, 2'200U, false));
  CHECK(visibility_gate.consume_if_visible(43U, 2'200U, true));
  CHECK(!visibility_gate.armed());
  CHECK(generation_gate.accepts(7U));
  bool continued_offer_authorized = false;
  CHECK(output_gate.execute_if_enabled(
      [&] { continued_offer_authorized = true; }));
  CHECK(continued_offer_authorized);
  const std::uint64_t continued_ticket = commit_gate.begin(3'000U, 43U);
  CHECK(continued_ticket != 0U && continued_ticket != fresh_ticket);
  CHECK(commit_gate.complete(continued_ticket).matched);
}

void verify_repeated_restart_and_ack_failure_never_stick_output() {
  constexpr std::uint64_t kCycles = 10'000U;
  vfdual_android::MakcuOutputGate output_gate;
  vfdual_android::MakcuMoveCommitGate commit_gate;
  std::uint64_t previous_ticket{};

  for (std::uint64_t generation = 1U; generation <= kCycles; ++generation) {
    CHECK(output_gate.set_user_requested(true));
    bool offer_authorized = false;
    CHECK(output_gate.execute_if_enabled([&] { offer_authorized = true; }));
    CHECK(offer_authorized);

    const std::uint64_t ticket = commit_gate.begin(generation, generation);
    CHECK(ticket != 0U && ticket != previous_ticket);
    previous_ticket = ticket;
    if (generation % 3U == 0U) {
      output_gate.fail_closed();
      commit_gate.fail_closed();
      CHECK(!commit_gate.complete(ticket).matched);
      CHECK(output_gate.set_user_requested(true));
      const std::uint64_t fresh_ticket = commit_gate.begin(
          kCycles + generation, kCycles + generation);
      CHECK(fresh_ticket != 0U && fresh_ticket != previous_ticket);
      CHECK(!commit_gate.complete(ticket).matched);
      CHECK(commit_gate.complete(fresh_ticket).matched);
      previous_ticket = fresh_ticket;
    } else {
      CHECK(commit_gate.complete(ticket).matched);
    }

    // Host pause/stop closes both authorizations. The next verified start must
    // admit a fresh command without reviving any earlier ticket.
    output_gate.fail_closed();
    commit_gate.fail_closed();
    CHECK(!output_gate.output_enabled());
    CHECK(!commit_gate.pending());
  }
  CHECK(output_gate.set_user_requested(true));
  CHECK(output_gate.output_enabled());
}

void verify_concurrent_duplicate_device_ack_commits_once() {
  vfdual_android::MakcuMoveCommitGate gate;
  vfdual_android::MakcuMoveVisibilityGate visibility_gate;
  const std::uint64_t ticket = gate.begin(1'000U, 1U);
  CHECK(ticket != 0U);
  std::atomic_uint32_t completions{};
  std::atomic_uint32_t dependent_commits{};
  std::barrier start(3);
  auto complete = [&] {
    start.arrive_and_wait();
    if (gate.complete_with(
            ticket, [&](std::uint64_t source_sequence) noexcept {
              visibility_gate.arm(source_sequence, 2'000U, 0U);
              dependent_commits.fetch_add(1U, std::memory_order_relaxed);
            }).matched) {
      completions.fetch_add(1U, std::memory_order_relaxed);
    }
  };
  std::thread first(complete);
  std::thread second(complete);
  start.arrive_and_wait();
  first.join();
  second.join();
  CHECK(completions.load(std::memory_order_relaxed) == 1U);
  CHECK(dependent_commits.load(std::memory_order_relaxed) == 1U);
  CHECK(!gate.pending());
  CHECK(visibility_gate.armed());
}

void verify_move_ack_timeout_is_strict_and_stale_safe() {
  vfdual_android::MakcuMoveCommitGate gate;
  const std::uint64_t stale = gate.begin(1'000U, 1U);
  CHECK(stale != 0U);
  CHECK(!gate.expire_if_older(101'000U, 100'000U));
  CHECK(gate.pending_ticket() == stale);
  CHECK(gate.expire_if_older(101'001U, 100'000U));
  CHECK(!gate.pending());

  const std::uint64_t boundary = gate.begin(200'000U, 8U);
  CHECK(boundary != 0U);
  CHECK(!gate.expire_if_deadline_reached(299'999U, 100'000U));
  CHECK(gate.expire_if_deadline_reached(300'000U, 100'000U));
  CHECK(!gate.pending());

  const std::uint64_t current = gate.begin(302'000U, 2U);
  CHECK(current != 0U && current != stale);
  CHECK(!gate.complete(stale).matched);
  CHECK(gate.pending_ticket() == current);
  CHECK(gate.complete(current).matched);
}

void verify_post_ack_visibility_requires_newer_delayed_frame() {
  vfdual_android::MakcuMoveVisibilityGate gate;
  bool became_visible = true;
  CHECK(gate.consume_if_visible(1U, 1'000U, false, &became_visible));
  CHECK(!became_visible);
  gate.arm(41U, 10'000U, 8'000U);
  CHECK(gate.armed());
  CHECK(!gate.consume_if_visible(41U, 18'000U, true, &became_visible));
  CHECK(!became_visible);
  CHECK(!gate.consume_if_visible(42U, 17'999U, true, &became_visible));
  CHECK(!became_visible);
  CHECK(gate.consume_if_visible(42U, 18'000U, true, &became_visible));
  CHECK(became_visible);
  CHECK(!gate.armed());
  CHECK(gate.consume_if_visible(43U, 18'001U, false, &became_visible));
  CHECK(!became_visible);

  constexpr std::uint64_t maximum =
      std::numeric_limits<std::uint64_t>::max();
  gate.arm(50U, maximum - 3U, 8U);
  CHECK(!gate.consume_if_visible(51U, maximum - 1U, true));
  CHECK(gate.consume_if_visible(51U, maximum, true));
  gate.arm(60U, 20'000U, 8'000U);
  gate.fail_closed();
  CHECK(gate.consume_if_visible(60U, 20'000U, false));
}

void verify_post_ack_visibility_timeout_is_bounded_and_fail_closed() {
  using vfdual_android::MakcuMoveVisibilityDecision;
  vfdual_android::MakcuMoveVisibilityGate gate;
  gate.arm(100U, 1'000U, 0U);
  const auto armed = gate.snapshot();
  CHECK(armed.armed);
  CHECK(armed.source_sequence == 100U);
  CHECK(armed.armed_at_us == 1'000U);
  CHECK(armed.visible_not_before_us == 1'000U);

  CHECK(gate.evaluate(101U, 1'500U, false, 2'999U, 2'000U) ==
        MakcuMoveVisibilityDecision::waiting);
  CHECK(gate.armed());
  CHECK(gate.evaluate(101U, 1'500U, false, 3'000U, 2'000U) ==
        MakcuMoveVisibilityDecision::timed_out);
  CHECK(!gate.armed());

  // A qualifying fresh observation at the timeout boundary is the exact
  // causal evidence being awaited and therefore wins over timeout.
  gate.arm(200U, 10'000U, 0U);
  CHECK(gate.evaluate(201U, 12'000U, true, 12'000U, 2'000U) ==
        MakcuMoveVisibilityDecision::became_visible);
  CHECK(!gate.armed());
  CHECK(gate.evaluate(202U, 12'001U, true, 12'001U, 2'000U) ==
        MakcuMoveVisibilityDecision::open);
}

void verify_route_specific_post_completion_visibility() {
  vfdual_android::MakcuMoveVisibilityGate makcu;
  CHECK(vfdual_android::kPostAcknowledgementAdditionalDelayUs == 0U);
  makcu.arm(
      70U, 20'000U,
      vfdual_android::kPostAcknowledgementAdditionalDelayUs);
  CHECK(!makcu.consume_if_visible(70U, 20'001U, true));
  CHECK(!makcu.consume_if_visible(71U, 19'999U, true));
  CHECK(makcu.consume_if_visible(71U, 20'000U, true));

  vfdual_android::MakcuMoveVisibilityGate bluetooth;
  bluetooth.arm(
      80U, 30'000U,
      vfdual_android::kPostAcknowledgementAdditionalDelayUs);
  CHECK(!bluetooth.consume_if_visible(81U, 29'999U, true));
  CHECK(bluetooth.consume_if_visible(81U, 30'000U, true));
}

void verify_repeated_content_never_drives_control() {
  vfdual_android::MakcuMoveVisibilityGate gate;
  gate.arm(41U, 10'000U, 8'000U);
  CHECK(gate.armed());

  // A synthetic repeat has a new wire sequence but no new visual evidence.
  // It cannot drive a move or prove that a previous response became visible.
  CHECK(!vfdual_android::control_frame_is_actionable(true, false));
  CHECK(!gate.consume_if_visible(42U, 18'000U, false));
  CHECK(gate.armed());
  CHECK(gate.consume_if_visible(43U, 18'001U, true));
  CHECK(!gate.armed());

  CHECK(vfdual_android::control_frame_is_actionable(true, true));
  CHECK(!vfdual_android::control_frame_is_actionable(false, true));
  CHECK(!vfdual_android::control_frame_is_actionable(false, false));

  CHECK(vfdual_android::content_frame_can_supersede(false, false));
  CHECK(vfdual_android::content_frame_can_supersede(false, true));
  CHECK(vfdual_android::content_frame_can_supersede(true, true));
  CHECK(!vfdual_android::content_frame_can_supersede(true, false));
}

}  // namespace

int main() {
  vfdual_android::MakcuOutputGate gate;
  CHECK(!gate.user_requested());
  CHECK(!gate.output_enabled());

  CHECK(gate.set_user_requested(true));
  CHECK(gate.output_enabled());

  gate.suspend_for_recovery(10U);
  CHECK(gate.user_requested());
  CHECK(gate.recovery_suspended());
  CHECK(!gate.output_enabled());
  CHECK(!gate.complete_after_valid_frame(9U).matched);
  CHECK(!gate.output_enabled());
  const auto generation_10 = gate.complete_after_valid_frame(10U);
  CHECK(generation_10.matched && generation_10.output_enabled);
  CHECK(gate.output_enabled());
  CHECK(!gate.complete_after_valid_frame(10U).matched);

  gate.suspend_for_recovery(11U);
  CHECK(gate.set_user_requested(false));
  CHECK(gate.recovery_suspended());
  const auto generation_11 = gate.complete_after_valid_frame(11U);
  CHECK(generation_11.matched && !generation_11.output_enabled);
  CHECK(!gate.recovery_suspended());
  CHECK(!gate.output_enabled());

  CHECK(gate.set_user_requested(true));
  gate.suspend_for_recovery(12U);
  gate.suspend_for_recovery(13U);
  CHECK(!gate.complete_after_valid_frame(12U).matched);
  const auto generation_13 = gate.complete_after_valid_frame(13U);
  CHECK(generation_13.matched && generation_13.output_enabled);
  CHECK(gate.output_enabled());

  gate.suspend_for_recovery(14U);
  gate.fail_closed();
  CHECK(!gate.user_requested());
  CHECK(!gate.recovery_suspended());
  CHECK(!gate.complete_after_valid_frame(14U).matched);
  CHECK(!gate.output_enabled());

  gate.suspend_for_recovery(15U);
  CHECK(!gate.set_user_requested(true));
  CHECK(gate.recovery_suspended());
  CHECK(!gate.output_enabled());
  const auto generation_15 = gate.complete_after_valid_frame(15U);
  CHECK(generation_15.matched && !generation_15.output_enabled);
  CHECK(!gate.output_enabled());
  CHECK(gate.set_user_requested(true));
  CHECK(gate.output_enabled());

  verify_stale_resume_cannot_release_new_recovery();
  verify_delivery_fail_close_preserves_active_stream_generation();
  verify_offer_and_suspend_are_linearized();
  verify_two_phase_suspend_cancellation_fails_closed();
  verify_move_commit_requires_matching_device_ack();
  verify_stale_or_duplicate_feedback_never_revokes_current_output();
  verify_stale_device_ack_cannot_commit_after_fail_close();
  verify_ack_failure_then_reauthorization_continues_same_stream();
  verify_repeated_restart_and_ack_failure_never_stick_output();
  verify_concurrent_duplicate_device_ack_commits_once();
  verify_move_ack_timeout_is_strict_and_stale_safe();
  verify_post_ack_visibility_requires_newer_delayed_frame();
  verify_post_ack_visibility_timeout_is_bounded_and_fail_closed();
  verify_route_specific_post_completion_visibility();
  verify_repeated_content_never_drives_control();
  return 0;
}
