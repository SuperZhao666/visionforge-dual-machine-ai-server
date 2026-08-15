#include "vfdual/usage_lease_gate.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>

namespace {

void require(
    const bool condition,
    const char* expression,
    const char* file,
    const int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
    std::exit(EXIT_FAILURE);
}

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

constexpr std::uint64_t kInitialNotBefore = 1'700'000'100U;
constexpr std::uint64_t kInitialExpires = kInitialNotBefore + 5U;

[[nodiscard]] std::string repeated(const char value, const std::size_t count) {
    return std::string(count, value);
}

[[nodiscard]] vfdual::UsageLeaseBinding make_binding() {
    return vfdual::UsageLeaseBinding{
        .entitlement_id = repeated('a', 32U),
        .pair_id = repeated('b', 32U),
        .session_id = repeated('c', 32U),
        .protocol_version = vfdual::kUsageLeaseProtocolVersion,
        .revocation_version = 7U,
        .host_key_sha256 = repeated('d', 64U),
        .android_key_sha256 = repeated('e', 64U),
        .channel_binding_sha256 = repeated('f', 64U),
    };
}

[[nodiscard]] vfdual::VerifiedUsageLease make_ticket(
    const std::uint64_t sequence,
    const std::uint64_t issued_at_epoch,
    const std::uint64_t not_before_epoch,
    const std::uint64_t expires_at_epoch,
    std::string previous_ticket_sha256,
    const char ticket_digest_character) {
    const auto binding = make_binding();
    return vfdual::VerifiedUsageLease{
        .claims = {
            .type = std::string(vfdual::kUsageLeaseType),
            .issuer = std::string(vfdual::kUsageLeaseIssuer),
            .audience = std::string(vfdual::kUsageLeaseAudience),
            .entitlement_id = binding.entitlement_id,
            .pair_id = binding.pair_id,
            .session_id = binding.session_id,
            .protocol_version = binding.protocol_version,
            .revocation_version = binding.revocation_version,
            .host_key_sha256 = binding.host_key_sha256,
            .android_key_sha256 = binding.android_key_sha256,
            .channel_binding_sha256 = binding.channel_binding_sha256,
            .previous_ticket_sha256 = std::move(previous_ticket_sha256),
            .sequence = sequence,
            .phase = std::string(vfdual::kUsageLeaseActivePhase),
            .issued_at_epoch = issued_at_epoch,
            .not_before_epoch = not_before_epoch,
            .expires_at_epoch = expires_at_epoch,
        },
        .ticket_sha256 = repeated(ticket_digest_character, 64U),
    };
}

[[nodiscard]] vfdual::VerifiedUsageLease make_initial_ticket() {
    return make_ticket(
        0U,
        kInitialNotBefore,
        kInitialNotBefore,
        kInitialExpires,
        repeated('0', 64U),
        '1');
}

void verify_tampered_contract_fields_are_rejected() {
    auto expect_claim_rejection = [](vfdual::VerifiedUsageLease ticket) {
        vfdual::UsageLeaseGate gate(make_binding());
        CHECK(gate.submit_verified_ticket(ticket, kInitialNotBefore) ==
            vfdual::UsageLeaseAdmission::rejected_claims);
        CHECK(!gate.evaluate(kInitialNotBefore).permits_data_plane);
    };
    auto expect_binding_rejection = [](vfdual::VerifiedUsageLease ticket) {
        vfdual::UsageLeaseGate gate(make_binding());
        CHECK(gate.submit_verified_ticket(ticket, kInitialNotBefore) ==
            vfdual::UsageLeaseAdmission::rejected_binding);
        CHECK(!gate.evaluate(kInitialNotBefore).permits_data_plane);
    };

    auto ticket = make_initial_ticket();
    ticket.claims.type += "-tampered";
    expect_claim_rejection(ticket);
    ticket = make_initial_ticket();
    ticket.claims.issuer += "-tampered";
    expect_claim_rejection(ticket);
    ticket = make_initial_ticket();
    ticket.claims.audience += "-tampered";
    expect_claim_rejection(ticket);
    ticket = make_initial_ticket();
    ticket.claims.phase = "stopped";
    expect_claim_rejection(ticket);
    ticket = make_initial_ticket();
    ticket.claims.protocol_version = 1U;
    expect_claim_rejection(ticket);

    ticket = make_initial_ticket();
    ticket.claims.entitlement_id = repeated('1', 32U);
    expect_binding_rejection(ticket);
    ticket = make_initial_ticket();
    ticket.claims.pair_id = repeated('2', 32U);
    expect_binding_rejection(ticket);
    ticket = make_initial_ticket();
    ticket.claims.session_id = repeated('3', 32U);
    expect_binding_rejection(ticket);
    ticket = make_initial_ticket();
    ticket.claims.revocation_version += 1U;
    expect_binding_rejection(ticket);
    ticket = make_initial_ticket();
    ticket.claims.host_key_sha256 = repeated('4', 64U);
    expect_binding_rejection(ticket);
    ticket = make_initial_ticket();
    ticket.claims.android_key_sha256 = repeated('5', 64U);
    expect_binding_rejection(ticket);
    ticket = make_initial_ticket();
    ticket.claims.channel_binding_sha256 = repeated('6', 64U);
    expect_binding_rejection(ticket);
}

void verify_invalid_binding_is_terminal() {
    auto invalid_binding = make_binding();
    invalid_binding.session_id.clear();
    vfdual::UsageLeaseGate gate(std::move(invalid_binding));
    CHECK(gate.evaluate(kInitialNotBefore).state ==
        vfdual::UsageLeaseGateState::invalid_binding);
    CHECK(!gate.evaluate(kInitialNotBefore).permits_data_plane);
    CHECK(gate.submit_verified_ticket(
              make_initial_ticket(), kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::rejected_gate_closed);
}

void verify_zero_identity_and_digest_values_are_rejected() {
    const auto all_zero_identifier = repeated('0', 32U);
    const auto all_zero_sha256 = repeated('0', 64U);

    auto expect_invalid_binding = [](vfdual::UsageLeaseBinding binding) {
        vfdual::UsageLeaseGate gate(std::move(binding));
        CHECK(gate.evaluate(kInitialNotBefore).state ==
            vfdual::UsageLeaseGateState::invalid_binding);
    };
    auto binding = make_binding();
    binding.entitlement_id = all_zero_identifier;
    expect_invalid_binding(std::move(binding));
    binding = make_binding();
    binding.pair_id = all_zero_identifier;
    expect_invalid_binding(std::move(binding));
    binding = make_binding();
    binding.session_id = all_zero_identifier;
    expect_invalid_binding(std::move(binding));
    binding = make_binding();
    binding.host_key_sha256 = all_zero_sha256;
    expect_invalid_binding(std::move(binding));
    binding = make_binding();
    binding.android_key_sha256 = all_zero_sha256;
    expect_invalid_binding(std::move(binding));
    binding = make_binding();
    binding.channel_binding_sha256 = all_zero_sha256;
    expect_invalid_binding(std::move(binding));

    auto expect_claim_rejection = [](vfdual::VerifiedUsageLease ticket) {
        vfdual::UsageLeaseGate gate(make_binding());
        CHECK(gate.submit_verified_ticket(ticket, kInitialNotBefore) ==
            vfdual::UsageLeaseAdmission::rejected_claims);
    };
    auto ticket = make_initial_ticket();
    ticket.claims.entitlement_id = all_zero_identifier;
    expect_claim_rejection(std::move(ticket));
    ticket = make_initial_ticket();
    ticket.claims.pair_id = all_zero_identifier;
    expect_claim_rejection(std::move(ticket));
    ticket = make_initial_ticket();
    ticket.claims.session_id = all_zero_identifier;
    expect_claim_rejection(std::move(ticket));
    ticket = make_initial_ticket();
    ticket.claims.host_key_sha256 = all_zero_sha256;
    expect_claim_rejection(std::move(ticket));
    ticket = make_initial_ticket();
    ticket.claims.android_key_sha256 = all_zero_sha256;
    expect_claim_rejection(std::move(ticket));
    ticket = make_initial_ticket();
    ticket.claims.channel_binding_sha256 = all_zero_sha256;
    expect_claim_rejection(std::move(ticket));
    ticket = make_initial_ticket();
    ticket.ticket_sha256 = all_zero_sha256;
    expect_claim_rejection(std::move(ticket));

    vfdual::UsageLeaseGate initial_sentinel_gate(make_binding());
    CHECK(initial_sentinel_gate.submit_verified_ticket(
              make_initial_ticket(), kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
}

void verify_time_boundaries_and_ttl() {
    vfdual::UsageLeaseGate early_gate(make_binding());
    CHECK(early_gate.submit_verified_ticket(
              make_initial_ticket(), kInitialNotBefore - 1U) ==
        vfdual::UsageLeaseAdmission::rejected_claims);

    vfdual::UsageLeaseGate boundary_gate(make_binding());
    CHECK(boundary_gate.submit_verified_ticket(
              make_initial_ticket(), kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    CHECK(boundary_gate.evaluate(kInitialNotBefore).permits_data_plane);
    CHECK(boundary_gate.evaluate(kInitialExpires - 1U).permits_data_plane);
    CHECK(!boundary_gate.evaluate(kInitialExpires).permits_data_plane);
    CHECK(boundary_gate.evaluate(kInitialExpires).state ==
        vfdual::UsageLeaseGateState::expired);

    auto maximum_ttl = make_initial_ticket();
    maximum_ttl.claims.expires_at_epoch =
        maximum_ttl.claims.not_before_epoch +
        vfdual::kMaximumUsageLeaseTtlSeconds;
    vfdual::UsageLeaseGate maximum_ttl_gate(make_binding());
    CHECK(maximum_ttl_gate.submit_verified_ticket(
              maximum_ttl, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);

    auto excessive_ttl = maximum_ttl;
    excessive_ttl.claims.expires_at_epoch += 1U;
    vfdual::UsageLeaseGate excessive_ttl_gate(make_binding());
    CHECK(excessive_ttl_gate.submit_verified_ticket(
              excessive_ttl, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::rejected_claims);

    auto future_issued = make_initial_ticket();
    future_issued.claims.issued_at_epoch = kInitialNotBefore + 1U;
    vfdual::UsageLeaseGate future_issued_gate(make_binding());
    CHECK(future_issued_gate.submit_verified_ticket(
              future_issued, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::rejected_claims);
}

void verify_future_ticket_switches_without_overlap_or_gap() {
    vfdual::UsageLeaseGate gate(make_binding());
    const auto initial = make_initial_ticket();
    CHECK(gate.submit_verified_ticket(initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);

    const auto future = make_ticket(
        1U,
        kInitialExpires - 2U,
        kInitialExpires,
        kInitialExpires + 5U,
        initial.ticket_sha256,
        '2');
    CHECK(gate.submit_verified_ticket(future, kInitialExpires - 2U) ==
        vfdual::UsageLeaseAdmission::staged_future);
    auto snapshot = gate.evaluate(kInitialExpires - 1U);
    CHECK(snapshot.permits_data_plane);
    CHECK(snapshot.sequence == 0U);
    CHECK(snapshot.future_ticket_staged);
    CHECK(snapshot.current_ticket_sha256 == initial.ticket_sha256);
    CHECK(snapshot.future_ticket_sha256 == future.ticket_sha256);

    snapshot = gate.evaluate(kInitialExpires);
    CHECK(snapshot.permits_data_plane);
    CHECK(snapshot.sequence == 1U);
    CHECK(!snapshot.future_ticket_staged);
    CHECK(snapshot.current_ticket_sha256 == future.ticket_sha256);
    CHECK(snapshot.future_ticket_sha256.empty());
    CHECK(snapshot.not_before_epoch == kInitialExpires);

    CHECK(gate.submit_verified_ticket(future, kInitialExpires) ==
        vfdual::UsageLeaseAdmission::accepted_idempotent);
    CHECK(!gate.evaluate(kInitialExpires + 5U).permits_data_plane);
    CHECK(gate.evaluate(kInitialExpires + 5U).state ==
        vfdual::UsageLeaseGateState::expired);
}

void verify_chain_and_continuity_rejections() {
    const auto initial = make_initial_ticket();

    vfdual::UsageLeaseGate replay_gate(make_binding());
    CHECK(replay_gate.submit_verified_ticket(initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    CHECK(replay_gate.submit_verified_ticket(initial, kInitialNotBefore + 1U) ==
        vfdual::UsageLeaseAdmission::accepted_idempotent);

    vfdual::UsageLeaseGate sequence_gap_gate(make_binding());
    CHECK(sequence_gap_gate.submit_verified_ticket(
              initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    auto candidate = make_ticket(
        2U, kInitialExpires - 1U, kInitialExpires, kInitialExpires + 5U,
        initial.ticket_sha256, '3');
    CHECK(sequence_gap_gate.submit_verified_ticket(
              candidate, kInitialExpires - 1U) ==
        vfdual::UsageLeaseAdmission::rejected_sequence);

    vfdual::UsageLeaseGate wrong_previous_gate(make_binding());
    CHECK(wrong_previous_gate.submit_verified_ticket(
              initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    candidate = make_ticket(
        1U, kInitialExpires - 1U, kInitialExpires, kInitialExpires + 5U,
        repeated('9', 64U), '3');
    CHECK(wrong_previous_gate.submit_verified_ticket(
              candidate, kInitialExpires - 1U) ==
        vfdual::UsageLeaseAdmission::rejected_previous_ticket);

    vfdual::UsageLeaseGate overlap_gate(make_binding());
    CHECK(overlap_gate.submit_verified_ticket(initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    candidate = make_ticket(
        1U, kInitialExpires - 2U, kInitialExpires - 1U,
        kInitialExpires + 4U, initial.ticket_sha256, '3');
    CHECK(overlap_gate.submit_verified_ticket(
              candidate, kInitialExpires - 2U) ==
        vfdual::UsageLeaseAdmission::rejected_overlap);

    vfdual::UsageLeaseGate gap_gate(make_binding());
    CHECK(gap_gate.submit_verified_ticket(initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    candidate = make_ticket(
        1U, kInitialExpires - 1U, kInitialExpires + 1U,
        kInitialExpires + 6U, initial.ticket_sha256, '3');
    CHECK(gap_gate.submit_verified_ticket(
              candidate, kInitialExpires - 1U) ==
        vfdual::UsageLeaseAdmission::rejected_gap);

    vfdual::UsageLeaseGate capacity_gate(make_binding());
    CHECK(capacity_gate.submit_verified_ticket(initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    candidate = make_ticket(
        1U, kInitialExpires - 2U, kInitialExpires, kInitialExpires + 5U,
        initial.ticket_sha256, '3');
    CHECK(capacity_gate.submit_verified_ticket(
              candidate, kInitialExpires - 2U) ==
        vfdual::UsageLeaseAdmission::staged_future);
    CHECK(capacity_gate.submit_verified_ticket(
              candidate, kInitialExpires - 1U) ==
        vfdual::UsageLeaseAdmission::accepted_idempotent);
    auto replacement = candidate;
    replacement.ticket_sha256 = repeated('4', 64U);
    CHECK(capacity_gate.submit_verified_ticket(
              replacement, kInitialExpires - 1U) ==
        vfdual::UsageLeaseAdmission::rejected_future_capacity);
}

void verify_late_chained_ticket_reopens_only_its_own_window() {
    const auto initial = make_initial_ticket();
    vfdual::UsageLeaseGate gate(make_binding());
    CHECK(gate.submit_verified_ticket(initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);

    const auto gap_epoch = kInitialExpires + 3U;
    CHECK(!gate.evaluate(kInitialExpires).permits_data_plane);
    CHECK(gate.evaluate(gap_epoch).state ==
        vfdual::UsageLeaseGateState::expired);
    CHECK(gate.submit_verified_ticket(initial, gap_epoch) ==
        vfdual::UsageLeaseAdmission::accepted_idempotent);
    CHECK(!gate.evaluate(gap_epoch).permits_data_plane);

    const auto late = make_ticket(
        1U,
        gap_epoch,
        gap_epoch,
        gap_epoch + 5U,
        initial.ticket_sha256,
        '2');
    CHECK(gate.submit_verified_ticket(late, gap_epoch) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    auto snapshot = gate.evaluate(gap_epoch);
    CHECK(snapshot.permits_data_plane);
    CHECK(snapshot.sequence == 1U);
    CHECK(snapshot.not_before_epoch == gap_epoch);

    CHECK(gate.submit_verified_ticket(late, gap_epoch + 1U) ==
        vfdual::UsageLeaseAdmission::accepted_idempotent);
    CHECK(gate.evaluate(gap_epoch + 4U).permits_data_plane);
    CHECK(!gate.evaluate(gap_epoch + 5U).permits_data_plane);
}

void verify_invalid_late_tickets_do_not_reopen() {
    const auto initial = make_initial_ticket();
    const auto gap_epoch = kInitialExpires + 3U;

    vfdual::UsageLeaseGate wrong_sequence(make_binding());
    CHECK(wrong_sequence.submit_verified_ticket(initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    CHECK(!wrong_sequence.evaluate(gap_epoch).permits_data_plane);
    auto candidate = make_ticket(
        2U, gap_epoch, gap_epoch, gap_epoch + 5U,
        initial.ticket_sha256, '2');
    CHECK(wrong_sequence.submit_verified_ticket(candidate, gap_epoch) ==
        vfdual::UsageLeaseAdmission::rejected_sequence);
    CHECK(!wrong_sequence.evaluate(gap_epoch).permits_data_plane);

    vfdual::UsageLeaseGate wrong_previous(make_binding());
    CHECK(wrong_previous.submit_verified_ticket(initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    CHECK(!wrong_previous.evaluate(gap_epoch).permits_data_plane);
    candidate = make_ticket(
        1U, gap_epoch, gap_epoch, gap_epoch + 5U,
        repeated('9', 64U), '2');
    CHECK(wrong_previous.submit_verified_ticket(candidate, gap_epoch) ==
        vfdual::UsageLeaseAdmission::rejected_previous_ticket);
    CHECK(!wrong_previous.evaluate(gap_epoch).permits_data_plane);

    vfdual::UsageLeaseGate expired_late(make_binding());
    CHECK(expired_late.submit_verified_ticket(initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    CHECK(!expired_late.evaluate(gap_epoch).permits_data_plane);
    candidate = make_ticket(
        1U, kInitialExpires + 1U, kInitialExpires + 1U, gap_epoch,
        initial.ticket_sha256, '2');
    CHECK(expired_late.submit_verified_ticket(candidate, gap_epoch) ==
        vfdual::UsageLeaseAdmission::rejected_time);
    CHECK(!expired_late.evaluate(gap_epoch).permits_data_plane);

    vfdual::UsageLeaseGate overlapping_late(make_binding());
    CHECK(overlapping_late.submit_verified_ticket(initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    CHECK(!overlapping_late.evaluate(gap_epoch).permits_data_plane);
    candidate = make_ticket(
        1U, kInitialExpires - 1U, kInitialExpires - 1U, gap_epoch + 4U,
        initial.ticket_sha256, '2');
    CHECK(overlapping_late.submit_verified_ticket(candidate, gap_epoch) ==
        vfdual::UsageLeaseAdmission::rejected_overlap);
    CHECK(!overlapping_late.evaluate(gap_epoch).permits_data_plane);
}

void verify_stop_and_revoke_are_terminal() {
    const auto initial = make_initial_ticket();

    vfdual::UsageLeaseGate stopped(make_binding());
    CHECK(stopped.submit_verified_ticket(initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    stopped.stop();
    CHECK(!stopped.evaluate(kInitialNotBefore + 1U).permits_data_plane);
    CHECK(stopped.evaluate(kInitialNotBefore + 1U).state ==
        vfdual::UsageLeaseGateState::stopped);
    CHECK(stopped.submit_verified_ticket(initial, kInitialNotBefore + 1U) ==
        vfdual::UsageLeaseAdmission::rejected_gate_closed);

    vfdual::UsageLeaseGate revoked(make_binding());
    CHECK(revoked.submit_verified_ticket(initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    revoked.revoke();
    CHECK(!revoked.evaluate(kInitialNotBefore + 1U).permits_data_plane);
    CHECK(revoked.evaluate(kInitialNotBefore + 1U).state ==
        vfdual::UsageLeaseGateState::revoked);
    CHECK(revoked.submit_verified_ticket(initial, kInitialNotBefore + 1U) ==
        vfdual::UsageLeaseAdmission::rejected_gate_closed);

}

void verify_trusted_time_rollback_is_terminal() {
    const auto initial = make_initial_ticket();
    vfdual::UsageLeaseGate gate(make_binding());
    CHECK(gate.submit_verified_ticket(initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    CHECK(gate.evaluate(kInitialNotBefore + 3U).permits_data_plane);

    auto snapshot = gate.evaluate(kInitialNotBefore + 2U);
    CHECK(snapshot.state ==
        vfdual::UsageLeaseGateState::trusted_time_rollback);
    CHECK(!snapshot.permits_data_plane);
    CHECK(!gate.evaluate(kInitialNotBefore + 4U).permits_data_plane);
    CHECK(gate.submit_verified_ticket(
              initial, kInitialNotBefore + 4U) ==
        vfdual::UsageLeaseAdmission::rejected_gate_closed);

    vfdual::UsageLeaseGate zero_rollback(make_binding());
    CHECK(zero_rollback.submit_verified_ticket(
              initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::accepted_current);
    snapshot = zero_rollback.evaluate(0U);
    CHECK(snapshot.state ==
        vfdual::UsageLeaseGateState::trusted_time_rollback);
    CHECK(!snapshot.permits_data_plane);

    vfdual::UsageLeaseGate pre_admission_rollback(make_binding());
    CHECK(pre_admission_rollback.evaluate(kInitialNotBefore + 1U).state ==
        vfdual::UsageLeaseGateState::empty);
    CHECK(pre_admission_rollback.submit_verified_ticket(
              initial, kInitialNotBefore) ==
        vfdual::UsageLeaseAdmission::rejected_gate_closed);
    CHECK(pre_admission_rollback.evaluate(kInitialNotBefore).state ==
        vfdual::UsageLeaseGateState::trusted_time_rollback);
}

}  // namespace

int main() {
    verify_tampered_contract_fields_are_rejected();
    verify_invalid_binding_is_terminal();
    verify_zero_identity_and_digest_values_are_rejected();
    verify_time_boundaries_and_ttl();
    verify_future_ticket_switches_without_overlap_or_gap();
    verify_chain_and_continuity_rejections();
    verify_late_chained_ticket_reopens_only_its_own_window();
    verify_invalid_late_tickets_do_not_reopen();
    verify_stop_and_revoke_are_terminal();
    verify_trusted_time_rollback_is_terminal();
    return EXIT_SUCCESS;
}
