#include "vfdual/usage_lease_gate.hpp"

#include <limits>
#include <utility>

namespace vfdual {
namespace {

constexpr std::size_t kIdentifierCharacters = 32U;
constexpr std::size_t kSha256Characters = 64U;
constexpr std::string_view kEmptyPreviousTicketSha256{
    "0000000000000000000000000000000000000000000000000000000000000000"};

[[nodiscard]] bool is_lower_hex(
    const std::string_view value, const std::size_t expected) noexcept {
    if (value.size() != expected) return false;
    for (const char character : value) {
        if (!((character >= '0' && character <= '9') ||
                (character >= 'a' && character <= 'f'))) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool is_nonzero_lower_hex(
    const std::string_view value, const std::size_t expected) noexcept {
    if (!is_lower_hex(value, expected)) return false;
    for (const char character : value) {
        if (character != '0') return true;
    }
    return false;
}

[[nodiscard]] bool binding_valid(const UsageLeaseBinding& binding) noexcept {
    return is_nonzero_lower_hex(
            binding.entitlement_id, kIdentifierCharacters) &&
        is_nonzero_lower_hex(binding.pair_id, kIdentifierCharacters) &&
        is_nonzero_lower_hex(binding.session_id, kIdentifierCharacters) &&
        binding.protocol_version == kUsageLeaseProtocolVersion &&
        binding.revocation_version > 0U &&
        is_nonzero_lower_hex(
            binding.host_key_sha256, kSha256Characters) &&
        is_nonzero_lower_hex(
            binding.android_key_sha256, kSha256Characters) &&
        is_nonzero_lower_hex(
            binding.channel_binding_sha256, kSha256Characters);
}

[[nodiscard]] bool claims_valid(
    const VerifiedUsageLease& ticket,
    const std::uint64_t trusted_now_epoch) noexcept {
    const auto& claims = ticket.claims;
    if (trusted_now_epoch == 0U ||
        claims.type != kUsageLeaseType ||
        claims.issuer != kUsageLeaseIssuer ||
        claims.audience != kUsageLeaseAudience ||
        !is_nonzero_lower_hex(
            claims.entitlement_id, kIdentifierCharacters) ||
        !is_nonzero_lower_hex(claims.pair_id, kIdentifierCharacters) ||
        !is_nonzero_lower_hex(claims.session_id, kIdentifierCharacters) ||
        claims.protocol_version != kUsageLeaseProtocolVersion ||
        claims.revocation_version == 0U ||
        !is_nonzero_lower_hex(
            claims.host_key_sha256, kSha256Characters) ||
        !is_nonzero_lower_hex(
            claims.android_key_sha256, kSha256Characters) ||
        !is_nonzero_lower_hex(
            claims.channel_binding_sha256, kSha256Characters) ||
        !is_lower_hex(claims.previous_ticket_sha256, kSha256Characters) ||
        !is_nonzero_lower_hex(ticket.ticket_sha256, kSha256Characters) ||
        claims.phase != kUsageLeaseActivePhase ||
        claims.issued_at_epoch == 0U ||
        claims.issued_at_epoch > claims.not_before_epoch ||
        claims.issued_at_epoch > trusted_now_epoch ||
        claims.expires_at_epoch <= claims.not_before_epoch) {
        return false;
    }
    return claims.expires_at_epoch - claims.not_before_epoch <=
        kMaximumUsageLeaseTtlSeconds;
}

[[nodiscard]] bool binding_matches(
    const UsageLeaseBinding& binding,
    const VerifiedUsageLeaseClaims& claims) noexcept {
    return claims.entitlement_id == binding.entitlement_id &&
        claims.pair_id == binding.pair_id &&
        claims.session_id == binding.session_id &&
        claims.protocol_version == binding.protocol_version &&
        claims.revocation_version == binding.revocation_version &&
        claims.host_key_sha256 == binding.host_key_sha256 &&
        claims.android_key_sha256 == binding.android_key_sha256 &&
        claims.channel_binding_sha256 == binding.channel_binding_sha256;
}

[[nodiscard]] bool terminal(const UsageLeaseGateState state) noexcept {
    return state == UsageLeaseGateState::invalid_binding ||
        state == UsageLeaseGateState::stopped ||
        state == UsageLeaseGateState::revoked ||
        state == UsageLeaseGateState::trusted_time_rollback;
}

}  // namespace

UsageLeaseGate::UsageLeaseGate(UsageLeaseBinding binding)
    : binding_(std::move(binding)),
      state_(binding_valid(binding_)
              ? UsageLeaseGateState::empty
              : UsageLeaseGateState::invalid_binding) {}

UsageLeaseAdmission UsageLeaseGate::submit_verified_ticket(
    const VerifiedUsageLease& ticket,
    const std::uint64_t trusted_now_epoch) {
    std::lock_guard lock(mutex_);
    static_cast<void>(evaluate_locked(trusted_now_epoch));
    if (terminal(state_)) {
        return UsageLeaseAdmission::rejected_gate_closed;
    }
    if (!claims_valid(ticket, trusted_now_epoch)) {
        return UsageLeaseAdmission::rejected_claims;
    }
    if (!binding_matches(binding_, ticket.claims)) {
        return UsageLeaseAdmission::rejected_binding;
    }

    const auto& claims = ticket.claims;
    if (state_ == UsageLeaseGateState::empty) {
        if (claims.sequence != 0U) {
            return UsageLeaseAdmission::rejected_sequence;
        }
        if (claims.previous_ticket_sha256 != kEmptyPreviousTicketSha256) {
            return UsageLeaseAdmission::rejected_previous_ticket;
        }
        if (trusted_now_epoch < claims.not_before_epoch ||
            trusted_now_epoch >= claims.expires_at_epoch) {
            return UsageLeaseAdmission::rejected_time;
        }
        current_ = StoredLease{claims, ticket.ticket_sha256};
        state_ = UsageLeaseGateState::active;
        return UsageLeaseAdmission::accepted_current;
    }

    if (!current_.has_value()) {
        return UsageLeaseAdmission::rejected_gate_closed;
    }
    const VerifiedUsageLease current_ticket{
        current_->claims, current_->ticket_sha256};
    if (ticket == current_ticket) {
        return UsageLeaseAdmission::accepted_idempotent;
    }
    if (future_.has_value()) {
        const VerifiedUsageLease future_ticket{
            future_->claims, future_->ticket_sha256};
        if (ticket == future_ticket) {
            return UsageLeaseAdmission::accepted_idempotent;
        }
    }

    if (current_->claims.sequence ==
            std::numeric_limits<std::uint64_t>::max() ||
        claims.sequence != current_->claims.sequence + 1U) {
        return UsageLeaseAdmission::rejected_sequence;
    }
    if (claims.previous_ticket_sha256 != current_->ticket_sha256) {
        return UsageLeaseAdmission::rejected_previous_ticket;
    }
    if (claims.not_before_epoch < current_->claims.expires_at_epoch) {
        return UsageLeaseAdmission::rejected_overlap;
    }

    if (state_ == UsageLeaseGateState::expired) {
        if (claims.not_before_epoch > trusted_now_epoch ||
            claims.expires_at_epoch <= trusted_now_epoch) {
            return UsageLeaseAdmission::rejected_time;
        }
        current_ = StoredLease{claims, ticket.ticket_sha256};
        state_ = UsageLeaseGateState::active;
        return UsageLeaseAdmission::accepted_current;
    }

    if (future_.has_value()) {
        return UsageLeaseAdmission::rejected_future_capacity;
    }
    if (claims.not_before_epoch > current_->claims.expires_at_epoch) {
        return UsageLeaseAdmission::rejected_gap;
    }
    if (claims.not_before_epoch <= trusted_now_epoch) {
        return UsageLeaseAdmission::rejected_time;
    }

    future_ = StoredLease{claims, ticket.ticket_sha256};
    return UsageLeaseAdmission::staged_future;
}

UsageLeaseGateSnapshot UsageLeaseGate::evaluate(
    const std::uint64_t trusted_now_epoch) {
    std::lock_guard lock(mutex_);
    return evaluate_locked(trusted_now_epoch);
}

void UsageLeaseGate::stop() {
    std::lock_guard lock(mutex_);
    if (state_ != UsageLeaseGateState::revoked) {
        close_locked(UsageLeaseGateState::stopped);
    }
}

void UsageLeaseGate::revoke() {
    std::lock_guard lock(mutex_);
    close_locked(UsageLeaseGateState::revoked);
}

UsageLeaseGateSnapshot UsageLeaseGate::evaluate_locked(
    const std::uint64_t trusted_now_epoch) {
    const auto state_only_snapshot = [this]() {
        UsageLeaseGateSnapshot snapshot{};
        snapshot.state = state_;
        return snapshot;
    };
    const auto current_snapshot = [this](
        const bool permits_data_plane,
        const bool future_ticket_staged) {
        UsageLeaseGateSnapshot snapshot{};
        snapshot.state = state_;
        snapshot.permits_data_plane = permits_data_plane;
        snapshot.future_ticket_staged = future_ticket_staged;
        if (current_.has_value()) {
            snapshot.current_ticket_sha256 = current_->ticket_sha256;
            snapshot.sequence = current_->claims.sequence;
            snapshot.not_before_epoch = current_->claims.not_before_epoch;
            snapshot.expires_at_epoch = current_->claims.expires_at_epoch;
        }
        if (future_.has_value()) {
            snapshot.future_ticket_sha256 = future_->ticket_sha256;
        }
        return snapshot;
    };

    if (terminal(state_)) {
        return state_only_snapshot();
    }
    if (trusted_now_epoch == 0U) {
        if (last_trusted_now_epoch_ != 0U) {
            close_locked(UsageLeaseGateState::trusted_time_rollback);
        }
        return state_only_snapshot();
    }
    if (last_trusted_now_epoch_ != 0U &&
        trusted_now_epoch < last_trusted_now_epoch_) {
        close_locked(UsageLeaseGateState::trusted_time_rollback);
        return state_only_snapshot();
    }
    last_trusted_now_epoch_ = trusted_now_epoch;

    if (state_ == UsageLeaseGateState::expired && current_.has_value()) {
        return current_snapshot(false, false);
    }
    if (state_ != UsageLeaseGateState::active || !current_.has_value()) {
        return state_only_snapshot();
    }

    if (trusted_now_epoch >= current_->claims.expires_at_epoch) {
        if (future_.has_value() &&
            trusted_now_epoch >= future_->claims.not_before_epoch &&
            trusted_now_epoch < future_->claims.expires_at_epoch) {
            current_ = std::move(future_);
            future_.reset();
        } else {
            expire_locked();
            return current_snapshot(false, false);
        }
    }

    const bool within_window =
        trusted_now_epoch >= current_->claims.not_before_epoch &&
        trusted_now_epoch < current_->claims.expires_at_epoch;
    return current_snapshot(within_window, future_.has_value());
}

void UsageLeaseGate::expire_locked() {
    if (future_.has_value()) {
        current_ = std::move(future_);
        future_.reset();
    }
    state_ = UsageLeaseGateState::expired;
}

void UsageLeaseGate::close_locked(const UsageLeaseGateState state) {
    current_.reset();
    future_.reset();
    state_ = state;
}

}  // namespace vfdual
