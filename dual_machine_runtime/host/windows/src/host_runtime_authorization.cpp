#include "vfdual/host_runtime_service.hpp"

#include <utility>

namespace vfdual {

bool HostRuntimeService::install_confirmed_peer_binding(
    UsageLeaseBinding binding) {
    return authorization_gate_ != nullptr &&
        authorization_gate_->install_confirmed_peer_binding(std::move(binding));
}

void HostRuntimeService::reset_data_plane_authorization_for_new_session()
    noexcept {
    if (authorization_gate_ != nullptr) authorization_gate_->reset();
}

bool HostRuntimeService::install_authenticated_data_plane_session(
    const ConfirmedPeerHandshakeSessionV1& session) noexcept {
    auto candidate = HostAuthenticatedDataPlaneSessionV2::create(session);
    if (!candidate) return false;
    std::lock_guard lock(mutex_);
    if (authenticated_data_plane_session_ &&
        authenticated_data_plane_session_->connection_id() ==
            candidate->connection_id()) {
        return true;
    }
    authenticated_data_plane_session_ = std::move(candidate);
    return true;
}

UsageLeaseAdmission HostRuntimeService::submit_verified_usage_lease(
    const VerifiedUsageLease& lease,
    const std::uint64_t trusted_now_epoch) {
    if (authorization_gate_ == nullptr) {
        return UsageLeaseAdmission::rejected_gate_closed;
    }
    return authorization_gate_->submit_verified_ticket(
        lease, trusted_now_epoch);
}

std::uint64_t HostRuntimeService::offer_pending_start_intent() noexcept {
    std::lock_guard lock(mutex_);
    return start_intent_gate_.offer();
}

std::uint64_t HostRuntimeService::claim_pending_start_intent() noexcept {
    std::lock_guard lock(mutex_);
    const auto claimed = start_intent_gate_.claim();
    return claimed.value_or(0U);
}

void HostRuntimeService::complete_pending_start_intent() noexcept {
    std::lock_guard lock(mutex_);
    start_intent_gate_.complete();
}

void HostRuntimeService::cancel_pending_start_intent() noexcept {
    std::lock_guard lock(mutex_);
    start_intent_gate_.cancel();
}

void HostRuntimeService::revoke_data_plane_authorization() noexcept {
    if (authorization_gate_ != nullptr) authorization_gate_->revoke();
    std::lock_guard lock(mutex_);
    authenticated_data_plane_session_.reset();
    start_intent_gate_.authenticated_channel_closed();
}

HostDataPlaneAuthorizationGate::Snapshot
HostRuntimeService::authorization_snapshot() noexcept {
    if (authorization_gate_ == nullptr) return {};
    return authorization_gate_->snapshot();
}

}  // namespace vfdual
