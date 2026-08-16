package com.visionforge.inferencebenchmark;

final class MobileControlHealthSummarySelfTest {
    private MobileControlHealthSummarySelfTest() {}

    static void run() {
        String decoderReport = "configured=1 makcu_bridge{"
                + "processed_frames=912 active_stream_generation=73 "
                + "control_blocker=post_ack_visibility control_blocker_age_us=225000 "
                + "control_blocker_transition_id=19 "
                + "native_delivery_fail_close_requests=4 "
                + "native_stream_lifecycle_close_requests=1 "
                + "stale_stream_generation_suppressed=2 "
                + "output_disabled_suppressed=17 "
                + "candidate_moves=41 no_targets=7 geometry_unsupported_class_rejected=3 "
                + "tracker_tracks_created=5 tracker_tracks_expired=4 "
                + "tracker_ambiguous_center_matches_rejected=6 "
                + "track_id_rebinds=3 rejected_ambiguous_rebinds=2 "
                + "rejected_rebind_geometry=8 rejected_exact_track_geometry=9 "
                + "held_targets=11 target_switches=2 switch_pending_frames=7 "
                + "head_body_projection_continuations=12 "
                + "head_body_projection_recoveries=4 "
                + "maximum_head_body_projection_recovery_pixels=6.25 "
                + "rejected_head_body_projection_geometry=3 "
                + "reacquisition_pending_frames=5 reacquisition_confirmations=1 "
                + "ego_motion_response_timeouts=2 "
                + "maximum_measured_ego_motion_support=2 "
                + "motion_plans=39 "
                + "tracker_control_filter_blends=30 tracker_control_filter_bypasses=4 "
                + "tracker_time_based_velocity_updates=27 "
                + "tracker_maximum_observation_interval_us=31000 "
                + "tracker_maximum_control_innovation_pixels=18.5 "
                + "tracking_only_lock_updates=13 "
                + "switch_confirmation_duration_us=25000 "
                + "lost_target_hold_duration_us=25000 "
                + "native_move_completion_pending_suppressed=9 "
                + "native_move_completion_pending_age_us=37000 "
                + "native_move_completion_deadline_us=250000 "
                + "native_move_completion_timeouts=2 "
                + "native_device_ack_completions=22 native_device_ack_failures=1 "
                + "native_last_device_ack_latency_us=735 "
                + "native_last_device_ack_interval_us=18400 "
                + "native_last_offered_delta_x=-4 native_last_offered_delta_y=3 "
                + "native_offered_absolute_x_counts=182 "
                + "native_offered_absolute_y_counts=97 "
                + "native_maximum_offered_absolute_axis_delta=12 "
                + "native_offered_direction_flips_x=5 "
                + "native_offered_direction_flips_y=2 "
                + "native_last_offer_interval_us=17600 "
                + "makcu_post_completion_visibility_min_us=0 "
                + "post_completion_visibility_armed=1 "
                + "post_completion_visibility_age_us=225000 "
                + "post_completion_visibility_timeouts=1 "
                + "last_detection_count=2 last_max_detection_confidence=0.46 "
                + "tracker_new_track_confidence_threshold=0.5 "
                + "tracker_low_confidence_threshold=0.25 output_requested=1 "
                + "output_enabled=1 maximum_axis_delta=127 "
                + "motion_uncalibrated_maximum_axis_delta=32}";
        String summary = MobileControlHealthSummary.format(decoderReport);
        require(summary.equals(
                "processed_frames=912 active_stream_generation=73 "
                        + "control_blocker=post_ack_visibility blocker_age_us=225000 "
                        + "blocker_transition_id=19 "
                        + "delivery_fail_closes=4 stream_lifecycle_closes=1 "
                        + "stale_generation_suppressed=2 output_disabled_suppressed=17 "
                        + "candidate_moves=41 no_targets=7 unsupported_class=3 tracks_created=5 "
                        + "tracks_expired=4 ambiguous_center_rejected=6 "
                        + "track_id_rebinds=3 ambiguous_rebinds=2 "
                        + "rebind_geometry_rejected=8 exact_track_geometry_rejected=9 "
                        + "held_targets=11 target_switches=2 "
                        + "head_projection_continued=12 head_projection_recovered=4 "
                        + "head_projection_recovery_max_px=6.25 "
                        + "head_projection_rejected=3 "
                        + "switch_pending=7 "
                        + "reacquisition_pending=5 reacquisition_confirmed=1 "
                        + "ego_response_timeouts=2 "
                        + "ego_response_support=2 "
                        + "motion_plans=39 filter_blends=30 filter_bypasses=4 "
                        + "time_velocity_updates=27 max_observation_interval_us=31000 "
                        + "filter_max_innovation_px=18.5 tracking_lock_updates=13 "
                        + "switch_confirm_us=25000 lost_hold_us=25000 "
                        + "pending_suppressed=9 pending_age_us=37000 pending_deadline_us=250000 "
                        + "pending_timeouts=2 ack_completions=22 ack_failures=1 last_ack_us=735 "
                        + "last_ack_interval_us=18400 last_move=-4,3 "
                        + "absolute_move=182,97 maximum_absolute_axis=12 "
                        + "direction_flips=5,2 last_offer_interval_us=17600 "
                        + "visibility_min_us=0 visibility_armed=1 visibility_age_us=225000 "
                        + "visibility_timeouts=1 detections=2 max_confidence=0.46 "
                        + "new_track_threshold=0.5 low_track_threshold=0.25 "
                        + "output_requested=1 output_enabled=1 "
                        + "user_max_axis=127 effective_uncalibrated_max_axis=32"));

        String missing = MobileControlHealthSummary.format(null);
        require(missing.startsWith("processed_frames=na "));
        require(missing.contains("candidate_moves=na"));
        require(missing.contains("effective_uncalibrated_max_axis=na"));

        String prefixed = MobileControlHealthSummary.format(
                "shadow_processed_frames=99 processed_frames=7 "
                        + "shadow_candidate_moves=99 candidate_moves=3 "
                        + "shadow_output_requested=1 output_requested=0");
        require(prefixed.startsWith("processed_frames=7 "));
        require(prefixed.contains(" candidate_moves=3 "));
        require(prefixed.contains(" output_requested=0 "));
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("mobile control health summary contract failed");
    }
}
