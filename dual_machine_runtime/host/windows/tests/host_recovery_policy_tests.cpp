#include "vfdual/host_recovery_policy.hpp"
#include "vfdual/host_preferred_probe_log_policy.hpp"

#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>

namespace {

using namespace std::chrono_literals;

void test_backoff_is_exponential_and_bounded_without_a_terminal_budget() {
    vfdual::HostRecoveryPolicy policy;
    constexpr std::array expected{
        200ms, 400ms, 800ms, 1600ms, 3200ms, 5000ms, 5000ms, 5000ms,
    };

    for (std::size_t index = 0; index < expected.size(); ++index) {
        const auto decision = policy.record_failure();
        assert(decision.consecutive_failures == index + 1U);
        assert(decision.total_failures == index + 1U);
        assert(decision.retry_delay == expected[index]);
        assert(decision.backoff_capped == (expected[index] == 5000ms));
    }

    // There is intentionally no "budget exhausted" state: repeated transient
    // failures keep returning a bounded retry decision.
    for (std::uint32_t index = 0; index < 1000U; ++index) {
        const auto decision = policy.record_failure();
        assert(decision.retry_delay == 5000ms);
        assert(decision.backoff_capped);
    }
}

void test_sustained_published_frames_reset_only_the_failure_streak() {
    vfdual::HostRecoveryPolicy policy({
        .stable_frames_to_reset = 3U,
        .initial_backoff = 10ms,
        .maximum_backoff = 40ms,
    });

    assert(policy.record_failure().retry_delay == 10ms);
    assert(policy.record_failure().retry_delay == 20ms);
    assert(!policy.record_published_frame());
    assert(!policy.record_published_frame());
    assert(policy.consecutive_failures() == 2U);
    assert(policy.record_published_frame());
    assert(policy.consecutive_failures() == 0U);
    assert(policy.stable_published_frames() == 0U);
    assert(policy.total_failures() == 2U);

    const auto next = policy.record_failure();
    assert(next.consecutive_failures == 1U);
    assert(next.total_failures == 3U);
    assert(next.retry_delay == 10ms);
}

void test_invalid_zero_configuration_is_normalized_to_safe_minimums() {
    vfdual::HostRecoveryPolicy policy({
        .stable_frames_to_reset = 0U,
        .initial_backoff = 0ms,
        .maximum_backoff = 0ms,
    });

    const auto failure = policy.record_failure();
    assert(failure.retry_delay == 1ms);
    assert(failure.backoff_capped);
    assert(policy.record_published_frame());
    assert(policy.consecutive_failures() == 0U);
}

void test_cat6_recovery_precedes_video_restart() {
    using vfdual::HostRecoveryCause;
    assert(vfdual::choose_host_recovery_cause(false, true) ==
           HostRecoveryCause::none);
    assert(vfdual::choose_host_recovery_cause(false, false) ==
           HostRecoveryCause::video_pipeline);
    assert(vfdual::choose_host_recovery_cause(true, true) ==
           HostRecoveryCause::cat6_link);
    assert(vfdual::choose_host_recovery_cause(true, false) ==
           HostRecoveryCause::cat6_link);
}

void test_preferred_transport_upgrade_precedes_link_and_video_recovery() {
    using vfdual::HostRecoveryCause;
    assert(vfdual::choose_host_recovery_cause(true, false, true) ==
           HostRecoveryCause::preferred_transport_upgrade);
    assert(vfdual::choose_host_recovery_cause(true, true, false) ==
           HostRecoveryCause::preferred_transport_upgrade);
    assert(vfdual::choose_host_recovery_cause(false, true, false) ==
           HostRecoveryCause::cat6_link);
    assert(vfdual::choose_host_recovery_cause(false, false, false) ==
           HostRecoveryCause::video_pipeline);
}

void test_preferred_cat6_probe_has_single_flight_and_commit_guards() {
    assert(vfdual::should_start_preferred_cat6_probe(
        false, false, false, true));
    assert(!vfdual::should_start_preferred_cat6_probe(
        true, false, false, true));
    assert(!vfdual::should_start_preferred_cat6_probe(
        false, true, false, true));
    assert(!vfdual::should_start_preferred_cat6_probe(
        false, false, true, true));
    assert(!vfdual::should_start_preferred_cat6_probe(
        false, false, false, false));
    assert(vfdual::should_commit_preferred_cat6_upgrade(false, true));
    assert(!vfdual::should_commit_preferred_cat6_upgrade(true, true));
    assert(!vfdual::should_commit_preferred_cat6_upgrade(false, false));
}

void test_preferred_probe_failure_log_has_change_and_heartbeat_semantics() {
    using namespace std::chrono_literals;
    vfdual::HostPreferredProbeLogPolicy policy{5min};
    const auto started_at = std::chrono::steady_clock::time_point{1h};
    const vfdual::HostPreferredProbeFailureState failure{
        .failure_stage = "direct_link",
        .failure_status = "no_wired_adapter",
        .failure_reason = "reason=no_unnumbered_wired_adapter",
    };

    assert(policy.should_log_failure(failure, started_at));
    assert(!policy.should_log_failure(failure, started_at + 5s));
    assert(!policy.should_log_failure(failure, started_at + 299s));
    assert(policy.should_log_failure(failure, started_at + 300s));
}

void test_preferred_probe_failure_log_records_every_state_change() {
    using namespace std::chrono_literals;
    vfdual::HostPreferredProbeLogPolicy policy{5min};
    const auto started_at = std::chrono::steady_clock::time_point{1h};

    assert(policy.should_log_failure({"direct_link", "failed", "reason_a"},
                                     started_at));
    assert(policy.should_log_failure({"firewall", "failed", "reason_a"},
                                     started_at + 1s));
    assert(policy.should_log_failure({"firewall", "requires_elevation", "reason_a"},
                                     started_at + 2s));
    assert(policy.should_log_failure({"firewall", "requires_elevation", "reason_b"},
                                     started_at + 3s));
}

void test_preferred_probe_success_reset_allows_same_failure_immediately() {
    using namespace std::chrono_literals;
    vfdual::HostPreferredProbeLogPolicy policy{5min};
    const auto started_at = std::chrono::steady_clock::time_point{1h};
    const vfdual::HostPreferredProbeFailureState failure{
        "direct_link", "no_wired_adapter", "no_adapter",
    };

    assert(policy.should_log_failure(failure, started_at));
    assert(!policy.should_log_failure(failure, started_at + 1s));
    policy.reset();
    assert(policy.should_log_failure(failure, started_at + 2s));
}

void test_preferred_probe_reason_excludes_volatile_adapter_inventory() {
    assert(vfdual::host_preferred_probe_root_reason(
               "reason=no_unnumbered_wired_adapter inventory_count=8 inventory=[a]") ==
           "reason=no_unnumbered_wired_adapter");
    assert(vfdual::host_preferred_probe_root_reason(
               "reason=ambiguous candidate_count=2 adapter_ids=a,b inventory_count=8") ==
           "reason=ambiguous candidate_count=2 adapter_ids=a,b");
    assert(vfdual::host_preferred_probe_root_reason("requires_elevation") ==
           "requires_elevation");
}

void test_soft_cat6_degradation_never_escalates_video_recovery() {
    using vfdual::HostRecoveryCause;
    constexpr bool soft_degradation_recovery_required = false;
    assert(vfdual::choose_host_recovery_cause(
               soft_degradation_recovery_required, false) ==
           HostRecoveryCause::video_pipeline);
    assert(vfdual::choose_host_recovery_cause(
               soft_degradation_recovery_required, true) ==
           HostRecoveryCause::none);
}

void test_video_forward_progress_accepts_unbounded_fast_publish_progress() {
    using namespace vfdual;
    HostVideoForwardProgressPolicy policy({
        .maximum_publish_silence = 1500ms,
        .maximum_fresh_frame_age = 1500ms,
    });

    for (std::uint64_t frame = 1U; frame <= 10'000U; ++frame) {
        const HostVideoForwardProgressDecision decision = policy.observe({
            .monotonic_time_us = frame,
            .published_frames = frame,
            .fresh_frame_published = true,
            .capture_to_publish_us = 200U,
        });
        assert(decision.failure == HostVideoForwardProgressFailure::none);
        assert(!decision.recovery_required());
    }
}

void test_video_forward_progress_accepts_static_repeat_publication() {
    using namespace vfdual;
    HostVideoForwardProgressPolicy policy({
        .maximum_publish_silence = 1500ms,
        .maximum_fresh_frame_age = 1500ms,
    });

    assert(!policy.observe({
        .monotonic_time_us = 0U,
        .published_frames = 40U,
    }).recovery_required());
    const auto repeated = policy.observe({
        .monotonic_time_us = 2'000'000U,
        .published_frames = 41U,
        .fresh_frame_published = false,
        .capture_to_publish_us = 2'000'000U,
    });
    assert(repeated.failure == HostVideoForwardProgressFailure::none);
}

void test_video_forward_progress_ignores_short_jitter_then_detects_stall() {
    using namespace vfdual;
    HostVideoForwardProgressPolicy policy({
        .maximum_publish_silence = 1500ms,
        .maximum_fresh_frame_age = 1500ms,
    });

    assert(!policy.observe({
        .monotonic_time_us = 1'000U,
        .published_frames = 7U,
    }).recovery_required());
    assert(!policy.observe({
        .monotonic_time_us = 1'500'999U,
        .published_frames = 7U,
    }).recovery_required());

    const auto stalled = policy.observe({
        .monotonic_time_us = 1'501'000U,
        .published_frames = 7U,
    });
    assert(stalled.failure ==
           HostVideoForwardProgressFailure::publish_stalled);
    assert(stalled.no_publish_progress_us == 1'500'000U);
    assert(stalled.recovery_required());
}

void test_video_forward_progress_detects_one_severely_stale_fresh_frame() {
    using namespace vfdual;
    HostVideoForwardProgressPolicy policy({
        .maximum_publish_silence = 1500ms,
        .maximum_fresh_frame_age = 1500ms,
    });

    const auto stale = policy.observe({
        .monotonic_time_us = 2'000'000U,
        .published_frames = 1U,
        .fresh_frame_published = true,
        .capture_to_publish_us = 4'897'453U,
    });
    assert(stale.failure ==
           HostVideoForwardProgressFailure::fresh_frame_stale);
    assert(stale.capture_to_publish_us == 4'897'453U);
    assert(stale.recovery_required());

    policy.reset();
    assert(!policy.observe({
        .monotonic_time_us = 9'000'000U,
        .published_frames = 1U,
    }).recovery_required());
}

void test_video_forward_progress_ignores_intentional_data_plane_close() {
    using namespace vfdual;
    HostVideoForwardProgressPolicy policy({
        .maximum_publish_silence = 1500ms,
        .maximum_fresh_frame_age = 1500ms,
    });

    assert(!policy.observe({
        .monotonic_time_us = 1'000U,
        .published_frames = 5U,
    }).recovery_required());
    assert(!policy.observe({
        .monotonic_time_us = 5'000'000U,
        .published_frames = 5U,
        .publication_expected = false,
    }).recovery_required());
    assert(!policy.observe({
        .monotonic_time_us = 5'100'000U,
        .published_frames = 5U,
    }).recovery_required());
}

void test_cross_adapter_nvenc_bridge_failure_trips_nvenc_breaker() {
    using namespace vfdual;
    HostEncoderRecoveryPolicy policy;

    const HostEncoderFailoverDecision decision = policy.record_failure(
        HostRecoveryCause::video_pipeline,
        HostVideoFailureKind::bridge_failed,
        HostEncoderRuntimePath::nvenc_cross_adapter);

    assert(decision.action == HostEncoderFailoverAction::skip_nvenc);
    assert(decision.breakers.skip_nvenc);
    assert(!decision.breakers.force_software);
    const auto repeated = policy.record_failure(
        HostRecoveryCause::video_pipeline,
        HostVideoFailureKind::bridge_failed,
        HostEncoderRuntimePath::nvenc_cross_adapter);
    assert(repeated.action == HostEncoderFailoverAction::none);
    assert(repeated.breakers.skip_nvenc);
}

void test_same_adapter_async_transfer_failure_falls_back_to_direct_nvenc() {
    using namespace vfdual;
    HostEncoderRecoveryPolicy policy;

    const HostEncoderFailoverDecision decision = policy.record_failure(
        HostRecoveryCause::video_pipeline,
        HostVideoFailureKind::bridge_failed,
        HostEncoderRuntimePath::nvenc_same_adapter_async_shared);

    assert(decision.action == HostEncoderFailoverAction::skip_async_shared);
    assert(decision.breakers.skip_async_shared);
    assert(!decision.breakers.skip_nvenc);
    assert(!decision.breakers.force_software);
    const auto repeated = policy.record_failure(
        HostRecoveryCause::video_pipeline,
        HostVideoFailureKind::bridge_failed,
        HostEncoderRuntimePath::nvenc_same_adapter_async_shared);
    assert(repeated.action == HostEncoderFailoverAction::none);
}

void test_soft_heartbeat_does_not_trip_encoder_breakers() {
    using namespace vfdual;
    HostEncoderRecoveryPolicy policy;
    constexpr bool soft_degradation_recovery_required = false;
    const HostRecoveryCause cause = choose_host_recovery_cause(
        soft_degradation_recovery_required, true);

    const HostEncoderFailoverDecision decision = policy.record_failure(
        cause,
        HostVideoFailureKind::bridge_failed,
        HostEncoderRuntimePath::nvenc_cross_adapter);

    assert(cause == HostRecoveryCause::none);
    assert(decision.action == HostEncoderFailoverAction::none);
    assert(!decision.breakers.skip_nvenc);
    assert(!decision.breakers.force_software);
}

void test_encode_failure_preserves_existing_two_stage_failover() {
    using namespace vfdual;
    HostEncoderRecoveryPolicy policy;

    const auto nvenc = policy.record_failure(
        HostRecoveryCause::video_pipeline,
        HostVideoFailureKind::encode_failed,
        HostEncoderRuntimePath::nvenc_capture_device);
    assert(nvenc.action == HostEncoderFailoverAction::skip_nvenc);
    assert(nvenc.breakers.skip_nvenc);
    assert(!nvenc.breakers.force_software);

    const auto hardware_mft = policy.record_failure(
        HostRecoveryCause::video_pipeline,
        HostVideoFailureKind::encode_failed,
        HostEncoderRuntimePath::windows_hardware);
    assert(hardware_mft.action == HostEncoderFailoverAction::force_software);
    assert(hardware_mft.breakers.skip_nvenc);
    assert(hardware_mft.breakers.force_software);
}

void test_same_adapter_async_encode_failure_skips_all_nvenc() {
    using namespace vfdual;
    HostEncoderRecoveryPolicy policy;

    const auto decision = policy.record_failure(
        HostRecoveryCause::video_pipeline,
        HostVideoFailureKind::encode_failed,
        HostEncoderRuntimePath::nvenc_same_adapter_async_shared);
    assert(decision.action == HostEncoderFailoverAction::skip_nvenc);
    assert(decision.breakers.skip_nvenc);
}

void test_new_host_run_resets_runtime_encoder_breakers() {
    using namespace vfdual;
    HostEncoderRecoveryPolicy first_run;
    static_cast<void>(first_run.record_failure(
        HostRecoveryCause::video_pipeline,
        HostVideoFailureKind::bridge_failed,
        HostEncoderRuntimePath::nvenc_cross_adapter));
    assert(first_run.breakers().skip_nvenc);

    // The policy is owned by HostRuntimeService::run and never persisted.
    HostEncoderRecoveryPolicy restarted_process;
    assert(!restarted_process.breakers().skip_nvenc);
    assert(!restarted_process.breakers().force_software);
}

}  // namespace

int main() {
    test_backoff_is_exponential_and_bounded_without_a_terminal_budget();
    test_sustained_published_frames_reset_only_the_failure_streak();
    test_invalid_zero_configuration_is_normalized_to_safe_minimums();
    test_cat6_recovery_precedes_video_restart();
    test_preferred_transport_upgrade_precedes_link_and_video_recovery();
    test_preferred_cat6_probe_has_single_flight_and_commit_guards();
    test_preferred_probe_failure_log_has_change_and_heartbeat_semantics();
    test_preferred_probe_failure_log_records_every_state_change();
    test_preferred_probe_success_reset_allows_same_failure_immediately();
    test_preferred_probe_reason_excludes_volatile_adapter_inventory();
    test_soft_cat6_degradation_never_escalates_video_recovery();
    test_video_forward_progress_accepts_unbounded_fast_publish_progress();
    test_video_forward_progress_accepts_static_repeat_publication();
    test_video_forward_progress_ignores_short_jitter_then_detects_stall();
    test_video_forward_progress_detects_one_severely_stale_fresh_frame();
    test_video_forward_progress_ignores_intentional_data_plane_close();
    test_cross_adapter_nvenc_bridge_failure_trips_nvenc_breaker();
    test_same_adapter_async_transfer_failure_falls_back_to_direct_nvenc();
    test_soft_heartbeat_does_not_trip_encoder_breakers();
    test_encode_failure_preserves_existing_two_stage_failover();
    test_same_adapter_async_encode_failure_skips_all_nvenc();
    test_new_host_run_resets_runtime_encoder_breakers();
    return 0;
}
