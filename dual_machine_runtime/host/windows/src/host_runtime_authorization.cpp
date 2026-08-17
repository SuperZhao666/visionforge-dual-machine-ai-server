#include "vfdual/host_runtime_service.hpp"

#include <utility>

namespace vfdual {

bool HostRuntimeService::install_confirmed_peer_binding(
    UsageLeaseBinding binding) {
    return authorization_gate_ != nullptr &&
        authorization_gate_->install_confirmed_peer_binding(std::move(binding));
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

void HostRuntimeService::revoke_data_plane_authorization() noexcept {
    if (authorization_gate_ != nullptr) authorization_gate_->revoke();
}

HostDataPlaneAuthorizationGate::Snapshot
HostRuntimeService::authorization_snapshot() noexcept {
    if (authorization_gate_ == nullptr) return {};
    return authorization_gate_->snapshot();
}

}  // namespace vfdual
