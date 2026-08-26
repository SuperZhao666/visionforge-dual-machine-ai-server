#include "vfdual/host_data_plane_authorization_gate.hpp"

#include <cassert>
#include <cstdint>
#include <string>

namespace {

constexpr char kZeroSha256[] =
    "0000000000000000000000000000000000000000000000000000000000000000";

std::string hex(char value, std::size_t count) {
    return std::string(count, value);
}

vfdual::UsageLeaseBinding binding() {
    return vfdual::UsageLeaseBinding{
        .entitlement_id = hex('1', 32U),
        .pair_id = hex('2', 32U),
        .session_id = hex('3', 32U),
        .protocol_version = vfdual::kUsageLeaseProtocolVersion,
        .revocation_version = 7U,
        .host_key_sha256 = hex('4', 64U),
        .android_key_sha256 = hex('5', 64U),
        .channel_binding_sha256 = hex('6', 64U),
    };
}

vfdual::VerifiedUsageLease ticket(
    std::uint64_t sequence,
    std::uint64_t not_before,
    std::uint64_t expires,
    std::string previous,
    char ticket_hash) {
    const auto expected = binding();
    return vfdual::VerifiedUsageLease{
        .claims = vfdual::VerifiedUsageLeaseClaims{
            .type = std::string{vfdual::kUsageLeaseType},
            .issuer = std::string{vfdual::kUsageLeaseIssuer},
            .audience = std::string{vfdual::kUsageLeaseAudience},
            .entitlement_id = expected.entitlement_id,
            .pair_id = expected.pair_id,
            .session_id = expected.session_id,
            .protocol_version = expected.protocol_version,
            .revocation_version = expected.revocation_version,
            .host_key_sha256 = expected.host_key_sha256,
            .android_key_sha256 = expected.android_key_sha256,
            .channel_binding_sha256 = expected.channel_binding_sha256,
            .previous_ticket_sha256 = std::move(previous),
            .sequence = sequence,
            .phase = std::string{vfdual::kUsageLeaseActivePhase},
            .issued_at_epoch = not_before,
            .not_before_epoch = not_before,
            .expires_at_epoch = expires,
        },
        .ticket_sha256 = hex(ticket_hash, 64U),
    };
}

void test_fail_closed_until_peer_and_lease() {
    std::uint64_t monotonic = 100'000U;
    vfdual::HostDataPlaneAuthorizationGate gate(
        [&monotonic] { return monotonic; });
    assert(!gate.permits_data_plane());

    auto invalid = binding();
    invalid.channel_binding_sha256 = hex('0', 64U);
    assert(!gate.install_confirmed_peer_binding(std::move(invalid)));
    assert(!gate.permits_data_plane());

    assert(gate.install_confirmed_peer_binding(binding()));
    assert(!gate.permits_data_plane());

    const auto initial = ticket(0U, 1'000U, 1'010U, kZeroSha256, 'a');
    assert(gate.submit_verified_ticket(initial, 1'000U) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    assert(gate.permits_data_plane());

    monotonic += 9'000U;
    assert(gate.permits_data_plane());
    monotonic += 1'000U;
    assert(!gate.permits_data_plane());
}

void test_binding_revoke_and_wrong_ticket() {
    std::uint64_t monotonic = 5'000U;
    vfdual::HostDataPlaneAuthorizationGate gate(
        [&monotonic] { return monotonic; });
    assert(gate.install_confirmed_peer_binding(binding()));

    auto wrong = ticket(0U, 2'000U, 2'010U, kZeroSha256, 'b');
    wrong.claims.android_key_sha256 = hex('7', 64U);
    assert(gate.submit_verified_ticket(wrong, 2'000U) ==
        vfdual::UsageLeaseAdmission::rejected_binding);
    assert(!gate.permits_data_plane());

    const auto valid = ticket(0U, 2'000U, 2'010U, kZeroSha256, 'c');
    assert(gate.submit_verified_ticket(valid, 2'000U) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    assert(gate.permits_data_plane());
    gate.revoke();
    assert(!gate.permits_data_plane());
    assert(gate.submit_verified_ticket(valid, 2'000U) ==
        vfdual::UsageLeaseAdmission::rejected_gate_closed);
}

void test_monotonic_rollback_is_terminal() {
    std::uint64_t monotonic = 500'000U;
    vfdual::HostDataPlaneAuthorizationGate gate(
        [&monotonic] { return monotonic; });
    assert(gate.install_confirmed_peer_binding(binding()));
    const auto valid = ticket(0U, 3'000U, 3'010U, kZeroSha256, 'd');
    assert(gate.submit_verified_ticket(valid, 3'000U) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    monotonic = 499'000U;
    const auto snapshot = gate.snapshot();
    assert(!snapshot.permits_data_plane);
    assert(snapshot.monotonic_clock_rollback);
    monotonic = 600'000U;
    assert(!gate.permits_data_plane());
}

void test_contiguous_renewal() {
    std::uint64_t monotonic = 10'000U;
    vfdual::HostDataPlaneAuthorizationGate gate(
        [&monotonic] { return monotonic; });
    assert(gate.install_confirmed_peer_binding(binding()));
    const auto initial = ticket(0U, 4'000U, 4'010U, kZeroSha256, 'e');
    assert(gate.submit_verified_ticket(initial, 4'000U) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    auto renewal = ticket(1U, 4'010U, 4'020U, hex('e', 64U), 'f');
    renewal.claims.issued_at_epoch = 4'009U;
    assert(gate.submit_verified_ticket(renewal, 4'009U) ==
        vfdual::UsageLeaseAdmission::staged_future);
    monotonic += 1'000U;
    assert(gate.permits_data_plane());
    const auto snapshot = gate.snapshot();
    assert(snapshot.sequence == 1U);
    assert(snapshot.expires_at_epoch == 4'020U);
}

void test_subsecond_commit_retransmit_does_not_revoke() {
    std::uint64_t monotonic = 100'900U;
    vfdual::HostDataPlaneAuthorizationGate gate(
        [&monotonic] { return monotonic; });
    assert(gate.install_confirmed_peer_binding(binding()));
    const auto initial = ticket(0U, 5'000U, 5'010U, kZeroSha256, '7');
    assert(gate.submit_verified_ticket(initial, 5'000U) ==
        vfdual::UsageLeaseAdmission::accepted_current);

    // This crosses both a monotonic and wall-clock second boundary with only
    // 1.2 seconds elapsed. Second-granularity anchoring used to derive two
    // elapsed seconds and permanently revoke the healthy session.
    monotonic += 1'200U;
    assert(gate.submit_verified_ticket(initial, 5'001U) ==
        vfdual::UsageLeaseAdmission::accepted_idempotent);
    assert(gate.permits_data_plane());
    assert(!gate.snapshot().monotonic_clock_rollback);
}

void test_explicit_reset_accepts_a_new_server_session() {
    std::uint64_t monotonic = 200'000U;
    vfdual::HostDataPlaneAuthorizationGate gate(
        [&monotonic] { return monotonic; });
    assert(gate.install_confirmed_peer_binding(binding()));
    const auto first = ticket(0U, 6'000U, 6'010U, kZeroSha256, '8');
    assert(gate.submit_verified_ticket(first, 6'000U) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    gate.stop();
    assert(!gate.permits_data_plane());

    gate.reset();
    auto next_binding = binding();
    next_binding.session_id = hex('9', 32U);
    assert(gate.install_confirmed_peer_binding(next_binding));
    auto next = ticket(0U, 6'001U, 6'011U, kZeroSha256, '9');
    next.claims.session_id = next_binding.session_id;
    assert(gate.submit_verified_ticket(next, 6'001U) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    assert(gate.permits_data_plane());
}

}  // namespace

int main() {
    test_fail_closed_until_peer_and_lease();
    test_binding_revoke_and_wrong_ticket();
    test_monotonic_rollback_is_terminal();
    test_contiguous_renewal();
    test_subsecond_commit_retransmit_does_not_revoke();
    test_explicit_reset_accepts_a_new_server_session();
    return 0;
}
