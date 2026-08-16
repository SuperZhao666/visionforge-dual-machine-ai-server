#pragma once

#include <cstdint>
#include <mutex>

namespace vfdual_android {

enum class ControlBlockerReason : std::uint8_t {
  initializing,
  runnable,
  stale_stream_generation,
  ticket_pending,
  ticket_deadline_expired,
  post_ack_visibility,
  post_ack_visibility_timeout,
  no_valid_target,
  detected_not_control_eligible,
  target_held,
  switch_pending,
  deadzone,
  response_guard,
  device_resolution_guard,
  settle_guard,
  direction_flip,
  motion_invalid,
  output_disabled,
  dispatch_unavailable,
  dispatch_rejected,
  ticket_begin_failed,
  transport_failure,
  recovery_suspended,
  user_disabled,
};

[[nodiscard]] constexpr const char* control_blocker_reason_name(
    ControlBlockerReason reason) noexcept {
  switch (reason) {
    case ControlBlockerReason::initializing: return "initializing";
    case ControlBlockerReason::runnable: return "runnable";
    case ControlBlockerReason::stale_stream_generation:
      return "stale_stream_generation";
    case ControlBlockerReason::ticket_pending: return "ticket_pending";
    case ControlBlockerReason::ticket_deadline_expired:
      return "ticket_deadline_expired";
    case ControlBlockerReason::post_ack_visibility:
      return "post_ack_visibility";
    case ControlBlockerReason::post_ack_visibility_timeout:
      return "post_ack_visibility_timeout";
    case ControlBlockerReason::no_valid_target: return "no_valid_target";
    case ControlBlockerReason::detected_not_control_eligible:
      return "detected_not_control_eligible";
    case ControlBlockerReason::target_held: return "target_held";
    case ControlBlockerReason::switch_pending: return "switch_pending";
    case ControlBlockerReason::deadzone: return "deadzone";
    case ControlBlockerReason::response_guard: return "response_guard";
    case ControlBlockerReason::device_resolution_guard:
      return "device_resolution_guard";
    case ControlBlockerReason::settle_guard: return "settle_guard";
    case ControlBlockerReason::direction_flip: return "direction_flip";
    case ControlBlockerReason::motion_invalid: return "motion_invalid";
    case ControlBlockerReason::output_disabled: return "output_disabled";
    case ControlBlockerReason::dispatch_unavailable:
      return "dispatch_unavailable";
    case ControlBlockerReason::dispatch_rejected: return "dispatch_rejected";
    case ControlBlockerReason::ticket_begin_failed:
      return "ticket_begin_failed";
    case ControlBlockerReason::transport_failure: return "transport_failure";
    case ControlBlockerReason::recovery_suspended:
      return "recovery_suspended";
    case ControlBlockerReason::user_disabled: return "user_disabled";
  }
  return "unknown";
}

struct ControlBlockerSnapshot final {
  ControlBlockerReason reason{ControlBlockerReason::initializing};
  std::uint64_t since_us{};
  std::uint64_t transition_id{};
};

/**
 * Low-cardinality current-state diagnostic for the control hot path.
 *
 * Counters answer what happened in the past; this state answers why the current
 * fresh frame cannot produce a move. Transitions are serialized so report()
 * never combines a new reason with the previous reason's timestamp.
 */
class ControlBlockerState final {
public:
  void update(ControlBlockerReason reason, std::uint64_t now_us) noexcept {
    std::scoped_lock lock(mutex_);
    if (reason_ == reason) return;
    reason_ = reason;
    since_us_ = now_us;
    ++transition_id_;
    if (transition_id_ == 0U) ++transition_id_;
  }

  [[nodiscard]] ControlBlockerSnapshot snapshot() const noexcept {
    std::scoped_lock lock(mutex_);
    return {
        .reason = reason_,
        .since_us = since_us_,
        .transition_id = transition_id_,
    };
  }

  void reset(std::uint64_t now_us) noexcept {
    std::scoped_lock lock(mutex_);
    reason_ = ControlBlockerReason::initializing;
    since_us_ = now_us;
    ++transition_id_;
    if (transition_id_ == 0U) ++transition_id_;
  }

private:
  mutable std::mutex mutex_;
  ControlBlockerReason reason_{ControlBlockerReason::initializing};
  std::uint64_t since_us_{};
  std::uint64_t transition_id_{};
};

}  // namespace vfdual_android
