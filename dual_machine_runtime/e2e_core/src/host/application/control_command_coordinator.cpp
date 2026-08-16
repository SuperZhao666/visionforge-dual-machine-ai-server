#include "vf/host/application/control_command_coordinator.hpp"

#include <stdexcept>

namespace vf::host::application {

ControlCommandCoordinator::ControlCommandCoordinator(
    std::chrono::milliseconds visibility_timeout,
    TimePoint now)
    : visibility_(visibility_timeout), blockers_(now) {}

ControlObservation ControlCommandCoordinator::begin(
    std::uint64_t ticket_id,
    host::domain::FrameIdentity source_frame,
    TimePoint ticket_deadline,
    TimePoint now) {
    if (!source_frame.valid() || ticket_deadline <= now || visibility_.armed() ||
        blockers_.current() != ControlBlocker::Runnable) {
        throw std::invalid_argument("command source/deadline/state is invalid");
    }
    ticket_.begin(ticket_id, ticket_deadline);
    source_frame_ = source_frame;
    command_started_at_ = now;
    blockers_.set(ControlBlocker::TicketPending, now);
    return ControlObservation::CommandStarted;
}

ControlObservation ControlCommandCoordinator::on_ack(
    std::uint64_t ticket_id,
    TimePoint acknowledged_at,
    TimePoint now) {
    if (!command_started_at_ || acknowledged_at < *command_started_at_ ||
        acknowledged_at > now) {
        return ControlObservation::StaleAck;
    }
    const auto result = ticket_.complete(ticket_id, now);
    switch (result) {
        case TicketResult::WrongTicket:
            return ControlObservation::WrongAck;
        case TicketResult::Stale:
        case TicketResult::Cancelled:
            return ControlObservation::StaleAck;
        case TicketResult::Expired:
            blockers_.set(ControlBlocker::TicketDeadlineExpired, now);
            return ControlObservation::LateAck;
        case TicketResult::Completed:
            break;
    }
    if (!source_frame_) {
        blockers_.set(ControlBlocker::RecoveryExhausted, now);
        return ControlObservation::RecoveryRequired;
    }
    visibility_.arm(source_frame_->stream_epoch, source_frame_->frame_sequence,
                    acknowledged_at, now);
    blockers_.set(ControlBlocker::WaitingPostAckVisibility, now);
    return ControlObservation::AckAccepted;
}

ControlObservation ControlCommandCoordinator::observe_frame(
    host::domain::FrameIdentity frame,
    bool content_updated,
    TimePoint observed_at,
    TimePoint now) {
    if (!frame.valid() || observed_at > now) {
        blockers_.set(ControlBlocker::RecoveryExhausted, now);
        return ControlObservation::RecoveryRequired;
    }
    if (ticket_.pending()) {
        return ControlObservation::VisibilityBlocked;
    }
    const auto decision = visibility_.evaluate(content_updated, frame.stream_epoch,
                                               frame.frame_sequence, observed_at, now);
    switch (decision) {
        case GateDecision::Allowed:
            blockers_.set(ControlBlocker::Runnable, now);
            source_frame_.reset();
            command_started_at_.reset();
            return ControlObservation::VisibilityConfirmed;
        case GateDecision::Blocked:
            blockers_.set(ControlBlocker::WaitingPostAckVisibility, now);
            return ControlObservation::VisibilityBlocked;
        case GateDecision::RecoveryRequired:
            blockers_.set(ControlBlocker::PostAckVisibilityTimeout, now);
            return ControlObservation::RecoveryRequired;
    }
    blockers_.set(ControlBlocker::RecoveryExhausted, now);
    return ControlObservation::RecoveryRequired;
}

ControlObservation ControlCommandCoordinator::poll(TimePoint now) {
    if (ticket_.pending()) {
        if (ticket_.expire(now) == TicketResult::Expired) {
            blockers_.set(ControlBlocker::TicketDeadlineExpired, now);
            return ControlObservation::RecoveryRequired;
        }
        return ControlObservation::VisibilityBlocked;
    }
    if (visibility_.armed() && source_frame_) {
        return observe_frame(*source_frame_, false, now, now);
    }
    return output_allowed() ? ControlObservation::VisibilityConfirmed
                            : ControlObservation::RecoveryRequired;
}

void ControlCommandCoordinator::on_recovery_verified(TimePoint now) noexcept {
    static_cast<void>(ticket_.cancel());
    visibility_.reset();
    source_frame_.reset();
    command_started_at_.reset();
    blockers_.set(ControlBlocker::Runnable, now);
}

bool ControlCommandCoordinator::output_allowed() const noexcept {
    return !ticket_.pending() && !visibility_.armed() &&
           blockers_.current() == ControlBlocker::Runnable;
}

}  // namespace vf::host::application
