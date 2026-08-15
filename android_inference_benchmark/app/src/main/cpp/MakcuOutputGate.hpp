#pragma once

#include <atomic>
#include <cstdint>
#include <limits>
#include <mutex>
#include <utility>

namespace vfdual_android {

/**
 * A matching device acknowledgement still requires a newer real content frame
 * before another move. Do not add a fixed time delay on top of that causal
 * boundary: it would turn display/QNN throughput into an artificial move-rate
 * ceiling.
 */
inline constexpr std::uint64_t kPostAcknowledgementAdditionalDelayUs = 0U;

/**
 * A synthetic repeat has a new transport sequence but no new visual evidence.
 * It may keep the decoder/reference chain alive, but it must never be counted
 * as a fresh observation or drive another physical correction. Real content
 * updates remain event-driven and have no software FPS ceiling.
 */
[[nodiscard]] constexpr bool control_frame_is_actionable(
    bool current_stream_generation, bool content_updated) noexcept {
  return current_stream_generation && content_updated;
}

/**
 * A synthetic repeat may replace another repeat, but it must never evict an
 * observed content update from the latest-wins inference queue.
 */
[[nodiscard]] constexpr bool content_frame_can_supersede(
    bool pending_content_updated, bool incoming_content_updated) noexcept {
  return incoming_content_updated || !pending_content_updated;
}

enum class MakcuStreamCloseScope {
  delivery_failure,
  stream_lifecycle,
};

/**
 * Separates a recoverable output-transport failure from the lifetime of the
 * decoded stream. A MAKCU reconnect reuses the current decoder generation;
 * only a real pipeline stop or stream discontinuity may invalidate it.
 */
class MakcuStreamGenerationGate final {
public:
  void activate(std::uint64_t generation) noexcept {
    active_generation_.store(generation, std::memory_order_release);
  }

  void fail_closed(MakcuStreamCloseScope scope) noexcept {
    if (scope == MakcuStreamCloseScope::stream_lifecycle) {
      active_generation_.store(0U, std::memory_order_release);
    }
  }

  [[nodiscard]] bool accepts(std::uint64_t generation) const noexcept {
    return generation != 0U &&
        generation == active_generation_.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::uint64_t active() const noexcept {
    return active_generation_.load(std::memory_order_acquire);
  }

private:
  std::atomic_uint64_t active_generation_{};
};

struct MakcuRecoveryCompletion final {
  bool matched{};
  bool output_enabled{};
};

struct MakcuMoveCompletion final {
  bool matched{};
  std::uint64_t source_sequence{};
};

enum class MakcuMoveFeedbackAction {
  ignore_stale,
  fail_current,
  complete_current,
};

/**
 * Feedback is authoritative only for the exact in-flight ticket. A late or
 * duplicate callback is already isolated by the monotonically increasing
 * ticket and must not revoke a newer command.
 */
[[nodiscard]] constexpr MakcuMoveFeedbackAction classify_makcu_move_feedback(
    bool ticket_matches, bool device_acknowledged) noexcept {
  if (!ticket_matches) return MakcuMoveFeedbackAction::ignore_stale;
  return device_acknowledged
      ? MakcuMoveFeedbackAction::complete_current
      : MakcuMoveFeedbackAction::fail_current;
}

/**
 * Allows one physical move command to be in flight at a time.
 *
 * The ticket prevents a late firmware acknowledgement from committing a newer
 * command after fail-close/recovery. A zero ticket always means "not started".
 */
class MakcuMoveCommitGate final {
public:
  [[nodiscard]] std::uint64_t begin(
      std::uint64_t started_at_us, std::uint64_t source_sequence) noexcept {
    std::scoped_lock lock(commit_mutex_);
    if (started_at_us == 0U || source_sequence == 0U ||
        pending_ticket_ != 0U) {
      return 0U;
    }
    ++next_ticket_;
    if (next_ticket_ == 0U) ++next_ticket_;
    pending_ticket_ = next_ticket_;
    pending_started_at_us_ = started_at_us;
    pending_source_sequence_ = source_sequence;
    return pending_ticket_;
  }

  [[nodiscard]] MakcuMoveCompletion complete(std::uint64_t ticket) noexcept {
    std::scoped_lock lock(commit_mutex_);
    if (ticket == 0U || ticket != pending_ticket_) return {};
    const std::uint64_t source_sequence = pending_source_sequence_;
    pending_ticket_ = 0U;
    pending_started_at_us_ = 0U;
    pending_source_sequence_ = 0U;
    return {.matched = true, .source_sequence = source_sequence};
  }

  /**
   * Commits dependent state while the matching ticket is still pending. A
   * publisher checking pending() therefore cannot observe a cleared ticket
   * before the caller's visibility barrier or local fail-close is installed.
   */
  template <typename BeforeClear>
  [[nodiscard]] MakcuMoveCompletion complete_with(
      std::uint64_t ticket, BeforeClear&& before_clear) noexcept {
    std::scoped_lock lock(commit_mutex_);
    if (ticket == 0U || ticket != pending_ticket_) return {};
    const std::uint64_t source_sequence = pending_source_sequence_;
    std::forward<BeforeClear>(before_clear)(source_sequence);
    pending_ticket_ = 0U;
    pending_started_at_us_ = 0U;
    pending_source_sequence_ = 0U;
    return {.matched = true, .source_sequence = source_sequence};
  }

  [[nodiscard]] MakcuMoveCompletion inspect(
      std::uint64_t ticket) const noexcept {
    std::scoped_lock lock(commit_mutex_);
    if (ticket == 0U || ticket != pending_ticket_) return {};
    return {.matched = true, .source_sequence = pending_source_sequence_};
  }

  [[nodiscard]] bool expire_if_older(
      std::uint64_t now_us, std::uint64_t maximum_age_us) noexcept {
    std::scoped_lock lock(commit_mutex_);
    if (pending_ticket_ == 0U || pending_started_at_us_ == 0U ||
        now_us < pending_started_at_us_ ||
        now_us - pending_started_at_us_ <= maximum_age_us) {
      return false;
    }
    pending_ticket_ = 0U;
    pending_started_at_us_ = 0U;
    pending_source_sequence_ = 0U;
    return true;
  }

  void fail_closed() noexcept {
    std::scoped_lock lock(commit_mutex_);
    pending_ticket_ = 0U;
    pending_started_at_us_ = 0U;
    pending_source_sequence_ = 0U;
  }

  [[nodiscard]] bool pending() const noexcept {
    std::scoped_lock lock(commit_mutex_);
    return pending_ticket_ != 0U;
  }

  [[nodiscard]] std::uint64_t pending_ticket() const noexcept {
    std::scoped_lock lock(commit_mutex_);
    return pending_ticket_;
  }

private:
  mutable std::mutex commit_mutex_;
  std::uint64_t next_ticket_{};
  std::uint64_t pending_ticket_{};
  std::uint64_t pending_started_at_us_{};
  std::uint64_t pending_source_sequence_{};
};

/**
 * Holds further movement until a newer received content frame exists after the
 * matching ACK. Callers may request an additional interval, but the realtime
 * control route uses none: source sequence and observation time already enforce
 * the causal post-ACK boundary.
 */
class MakcuMoveVisibilityGate final {
public:
  void arm(
      std::uint64_t source_sequence, std::uint64_t acknowledged_at_us,
      std::uint64_t minimum_visibility_us) noexcept {
    std::scoped_lock lock(visibility_mutex_);
    constexpr std::uint64_t maximum =
        std::numeric_limits<std::uint64_t>::max();
    source_sequence_ = source_sequence;
    visible_not_before_us_ =
        acknowledged_at_us > maximum - minimum_visibility_us
        ? maximum
        : acknowledged_at_us + minimum_visibility_us;
    armed_ = source_sequence != 0U && acknowledged_at_us != 0U;
  }

  [[nodiscard]] bool consume_if_visible(
      std::uint64_t frame_sequence, std::uint64_t observed_at_us,
      bool content_updated, bool* became_visible = nullptr) noexcept {
    std::scoped_lock lock(visibility_mutex_);
    if (became_visible != nullptr) *became_visible = false;
    if (!armed_) return true;
    if (!content_updated || frame_sequence <= source_sequence_ ||
        observed_at_us < visible_not_before_us_) {
      return false;
    }
    armed_ = false;
    source_sequence_ = 0U;
    visible_not_before_us_ = 0U;
    if (became_visible != nullptr) *became_visible = true;
    return true;
  }

  void fail_closed() noexcept {
    std::scoped_lock lock(visibility_mutex_);
    armed_ = false;
    source_sequence_ = 0U;
    visible_not_before_us_ = 0U;
  }

  [[nodiscard]] bool armed() const noexcept {
    std::scoped_lock lock(visibility_mutex_);
    return armed_;
  }

private:
  mutable std::mutex visibility_mutex_;
  bool armed_{};
  std::uint64_t source_sequence_{};
  std::uint64_t visible_not_before_us_{};
};

/**
 * Separates the user's persistent output authorization from a short-lived
 * decoder-recovery hold. A stale recovery completion can never reopen output
 * after a newer recovery or a fail-closed transition.
 */
class MakcuOutputGate final {
public:
  [[nodiscard]] bool set_user_requested(bool requested) noexcept {
    std::scoped_lock lock(output_mutex_);
    if (requested && recovery_suspended_) return false;
    user_requested_ = requested;
    if (!requested) recovery_resume_eligible_ = false;
    force_disabled_.store(!requested, std::memory_order_release);
    return true;
  }

  /** Lock-free first phase used while an exact failed ticket is still owned. */
  void revoke_immediately() noexcept {
    force_disabled_.store(true, std::memory_order_release);
  }

  void suspend_for_recovery(std::uint64_t generation) noexcept {
    std::scoped_lock lock(output_mutex_);
    if (!recovery_suspended_) recovery_resume_eligible_ = user_requested_;
    recovery_generation_ = generation;
    recovery_suspended_ = true;
  }

  [[nodiscard]] MakcuRecoveryCompletion complete_after_valid_frame(
      std::uint64_t generation) noexcept {
    std::scoped_lock lock(output_mutex_);
    if (recovery_generation_ != generation || !recovery_suspended_) return {};
    const bool output_enabled =
        !force_disabled_.load(std::memory_order_acquire) &&
        recovery_resume_eligible_ && user_requested_;
    recovery_suspended_ = false;
    recovery_resume_eligible_ = false;
    return {.matched = true, .output_enabled = output_enabled};
  }

  [[nodiscard]] bool recovery_suspended_for(std::uint64_t generation) const noexcept {
    std::scoped_lock lock(output_mutex_);
    return recovery_suspended_ && recovery_generation_ == generation;
  }

  void fail_closed() noexcept {
    revoke_immediately();
    std::scoped_lock lock(output_mutex_);
    user_requested_ = false;
    cancel_recovery_locked();
  }

  /**
   * Linearizes the final authorization check with the non-blocking Java
   * latest-wins offer. Recovery suspension waits for an offer already in this
   * critical section, and no later offer can start after suspension returns.
   */
  template <typename Action>
  [[nodiscard]] bool execute_if_enabled(Action&& action) {
    if (force_disabled_.load(std::memory_order_acquire)) return false;
    std::scoped_lock lock(output_mutex_);
    if (force_disabled_.load(std::memory_order_acquire) ||
        !user_requested_ || recovery_suspended_) return false;
    std::forward<Action>(action)();
    return true;
  }

  [[nodiscard]] bool user_requested() const noexcept {
    std::scoped_lock lock(output_mutex_);
    return user_requested_;
  }

  [[nodiscard]] bool recovery_suspended() const noexcept {
    std::scoped_lock lock(output_mutex_);
    return recovery_suspended_;
  }

  [[nodiscard]] bool output_enabled() const noexcept {
    if (force_disabled_.load(std::memory_order_acquire)) return false;
    std::scoped_lock lock(output_mutex_);
    return !force_disabled_.load(std::memory_order_acquire) &&
        user_requested_ && !recovery_suspended_;
  }

private:
  void cancel_recovery_locked() noexcept {
    ++recovery_generation_;
    recovery_suspended_ = false;
    recovery_resume_eligible_ = false;
  }

  mutable std::mutex output_mutex_;
  std::atomic_bool force_disabled_{true};
  bool user_requested_{};
  bool recovery_suspended_{};
  bool recovery_resume_eligible_{};
  std::uint64_t recovery_generation_{};
};

}  // namespace vfdual_android
