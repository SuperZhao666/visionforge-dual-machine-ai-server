#include "vf/recovery.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace vf {

ReceiverRepeatResyncPolicy::ReceiverRepeatResyncPolicy(
    std::chrono::milliseconds wait_timeout,
    unsigned max_retries)
    : wait_timeout_(wait_timeout), max_retries_(max_retries) {
    constexpr auto kMaximumWait = std::chrono::hours{1};
    constexpr unsigned kMaximumRetries = 1'000;
    if (wait_timeout_ <= std::chrono::milliseconds::zero()
        || wait_timeout_ > kMaximumWait
        || max_retries_ == 0
        || max_retries_ > kMaximumRetries) {
        throw std::invalid_argument("recovery timing or retry budget is outside bounded range");
    }
}

void ReceiverRepeatResyncPolicy::on_repeat(TimePoint now) {
    if (phase_ == RecoveryPhase::Running) {
        phase_ = RecoveryPhase::WaitingFreshIdr;
        deadline_ = now + wait_timeout_;
    }
}

void ReceiverRepeatResyncPolicy::update_timeout(TimePoint now) {
    if (phase_ == RecoveryPhase::WaitingFreshIdr && deadline_ && now >= *deadline_) {
        phase_ = RecoveryPhase::RecoveryRequired;
    }
}

bool ReceiverRepeatResyncPolicy::should_accept(
    bool is_idr,
    bool is_repeat,
    bool content_updated,
    TimePoint now) {
    update_timeout(now);
    if (phase_ == RecoveryPhase::Running) {
        return content_updated && !is_repeat;
    }
    if (phase_ != RecoveryPhase::WaitingFreshIdr) {
        return false;
    }
    const bool fresh_non_repeat_idr = is_idr && !is_repeat && content_updated;
    if (fresh_non_repeat_idr) {
        phase_ = RecoveryPhase::Running;
        retries_ = 0;
        deadline_.reset();
        return true;
    }
    return false;
}

RecoveryAction ReceiverRepeatResyncPolicy::poll_action(TimePoint now) {
    update_timeout(now);
    if (phase_ != RecoveryPhase::RecoveryRequired) {
        return RecoveryAction::None;
    }
    ++retries_;
    if (retries_ < max_retries_) {
        phase_ = RecoveryPhase::WaitingFreshIdr;
        deadline_ = now + wait_timeout_;
        return RecoveryAction::RequestIdr;
    }
    if (retries_ == max_retries_) {
        phase_ = RecoveryPhase::WaitingFreshIdr;
        deadline_ = now + wait_timeout_;
        return RecoveryAction::RebuildSession;
    }
    phase_ = RecoveryPhase::Exhausted;
    deadline_.reset();
    return RecoveryAction::None;
}

void ReceiverRepeatResyncPolicy::on_session_rebuilt(TimePoint now) {
    // 新建解码会话并不代表参考链已经可用；重建后仍然只接受真正的新鲜 IDR。
    // 关键点：这里不能归零 retries_。否则远端永远不给 IDR 时，每次重建都会重新
    // 获得完整预算，恢复循环永不进入 Exhausted。只有成功接收新鲜 IDR 才开始新周期。
    phase_ = RecoveryPhase::WaitingFreshIdr;
    deadline_ = now + wait_timeout_;
}

PostAckVisibilityGate::PostAckVisibilityGate(std::chrono::milliseconds timeout) : timeout_(timeout) {
    if (timeout_ <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument("visibility timeout must be positive");
    }
}

void PostAckVisibilityGate::validate_identity(
    std::uint64_t epoch,
    std::uint64_t sequence) {
    if (epoch == 0 || epoch > kMaxStreamEpoch ||
        sequence > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("frame identity is outside the shared protocol range");
    }
}

void PostAckVisibilityGate::arm_until(
    std::uint64_t source_epoch,
    std::uint32_t source_sequence,
    TimePoint ack_time,
    TimePoint absolute_deadline) {
    validate_identity(source_epoch, source_sequence);
    if (absolute_deadline <= ack_time) {
        throw std::invalid_argument("visibility deadline must be strictly later than ACK time");
    }
    source_epoch_ = source_epoch;
    source_sequence_ = source_sequence;
    ack_time_ = ack_time;
    deadline_ = absolute_deadline;
    recovery_required_ = false;
    armed_ = true;
}

void PostAckVisibilityGate::arm(
    std::uint64_t source_epoch,
    std::uint32_t source_sequence,
    TimePoint ack_time,
    TimePoint now) {
    const auto base = std::max(now, ack_time);
    arm_until(source_epoch, source_sequence, ack_time, base + timeout_);
}

void PostAckVisibilityGate::arm(
    std::uint64_t source_sequence,
    TimePoint ack_time,
    TimePoint now) {
    validate_identity(1, source_sequence);
    arm(1, static_cast<std::uint32_t>(source_sequence), ack_time, now);
}

GateDecision PostAckVisibilityGate::evaluate(
    bool content_updated,
    std::uint64_t observed_epoch,
    std::uint32_t frame_sequence,
    TimePoint observed_at,
    TimePoint now) {
    validate_identity(observed_epoch, frame_sequence);
    if (!armed_) {
        return GateDecision::Allowed;
    }
    if (recovery_required_ || now >= deadline_) {
        recovery_required_ = true;
        return GateDecision::RecoveryRequired;
    }
    const bool identity_advanced = observed_epoch > source_epoch_ ||
        (observed_epoch == source_epoch_ && frame_sequence > source_sequence_);
    const bool timestamp_valid = observed_at >= ack_time_ && observed_at <= now;
    if (content_updated && identity_advanced && timestamp_valid) {
        reset();
        return GateDecision::Allowed;
    }
    return GateDecision::Blocked;
}

GateDecision PostAckVisibilityGate::evaluate(
    bool content_updated,
    std::uint64_t frame_sequence,
    TimePoint observed_at,
    TimePoint now) {
    validate_identity(armed_ ? source_epoch_ : 1, frame_sequence);
    return evaluate(content_updated,
                    armed_ ? source_epoch_ : 1,
                    static_cast<std::uint32_t>(frame_sequence),
                    observed_at,
                    now);
}

void PostAckVisibilityGate::reset() noexcept {
    armed_ = false;
    recovery_required_ = false;
    source_epoch_ = 0;
    source_sequence_ = 0;
}

std::optional<std::uint64_t> PostAckVisibilityGate::source_epoch() const noexcept {
    return armed_ ? std::optional<std::uint64_t>{source_epoch_} : std::nullopt;
}

std::optional<std::uint32_t> PostAckVisibilityGate::source_sequence() const noexcept {
    return armed_ ? std::optional<std::uint32_t>{source_sequence_} : std::nullopt;
}

void ExactTicket::begin(std::uint64_t ticket_id, TimePoint deadline) {
    if (ticket_id == 0) {
        throw std::invalid_argument("ticket id must be positive");
    }
    if (pending_) {
        throw std::logic_error("another ticket is already pending");
    }
    if (ticket_id <= highest_ticket_id_) {
        throw std::invalid_argument("ticket ids must be strictly increasing");
    }
    if (transition_id_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("ticket transition id space exhausted");
    }
    pending_ = true;
    ticket_id_ = ticket_id;
    highest_ticket_id_ = ticket_id;
    deadline_ = deadline;
    ++transition_id_;
}

TicketResult ExactTicket::complete(std::uint64_t ticket_id, TimePoint now) {
    if (!pending_) {
        return TicketResult::Stale;
    }
    if (ticket_id != ticket_id_) {
        return TicketResult::WrongTicket;
    }
    if (now >= deadline_) {
        pending_ = false;
        if (transition_id_ != std::numeric_limits<std::uint64_t>::max()) {
            ++transition_id_;
        }
        return TicketResult::Expired;
    }
    pending_ = false;
    if (transition_id_ != std::numeric_limits<std::uint64_t>::max()) {
        ++transition_id_;
    }
    return TicketResult::Completed;
}

TicketResult ExactTicket::expire(TimePoint now) {
    if (!pending_) {
        return TicketResult::Stale;
    }
    if (now < deadline_) {
        return TicketResult::Stale;
    }
    pending_ = false;
    if (transition_id_ != std::numeric_limits<std::uint64_t>::max()) {
        ++transition_id_;
    }
    return TicketResult::Expired;
}

TicketResult ExactTicket::cancel() noexcept {
    if (!pending_) {
        return TicketResult::Stale;
    }
    pending_ = false;
    if (transition_id_ != std::numeric_limits<std::uint64_t>::max()) {
        ++transition_id_;
    }
    return TicketResult::Cancelled;
}

void BlockerTracker::set(ControlBlocker blocker, TimePoint now) noexcept {
    if (blocker == current_) {
        return;
    }
    current_ = blocker;
    changed_at_ = std::max(changed_at_, now);
    if (transition_id_ != std::numeric_limits<std::uint64_t>::max()) {
        ++transition_id_;
    }
}

std::chrono::milliseconds BlockerTracker::age(TimePoint now) const noexcept {
    if (now <= changed_at_) {
        return std::chrono::milliseconds::zero();
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - changed_at_);
}

std::string_view blocker_name(ControlBlocker blocker) noexcept {
    switch (blocker) {
        case ControlBlocker::Runnable: return "RUNNABLE";
        case ControlBlocker::WaitingFreshIdr: return "WAITING_FRESH_IDR";
        case ControlBlocker::WaitingPostAckVisibility: return "WAITING_POST_ACK_VISIBILITY";
        case ControlBlocker::TicketPending: return "TICKET_PENDING";
        case ControlBlocker::TicketDeadlineExpired: return "TICKET_DEADLINE_EXPIRED";
        case ControlBlocker::PostAckVisibilityTimeout: return "POST_ACK_VISIBILITY_TIMEOUT";
        case ControlBlocker::DetectedNotTrackEligible: return "DETECTED_NOT_TRACK_ELIGIBLE";
        case ControlBlocker::ResponseGuardNoProgress: return "RESPONSE_GUARD_NO_PROGRESS";
        case ControlBlocker::SubcountUnresolvable: return "SUBCOUNT_UNRESOLVABLE";
        case ControlBlocker::TransportNotReady: return "TRANSPORT_NOT_READY";
        case ControlBlocker::CircuitOpen: return "CIRCUIT_OPEN";
        case ControlBlocker::RecoveryExhausted: return "RECOVERY_EXHAUSTED";
    }
    return "UNKNOWN";
}

}  // namespace vf
