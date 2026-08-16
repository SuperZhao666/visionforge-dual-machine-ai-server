package com.visionforge.inferencebenchmark;

/** Extracts a compact, logcat-safe control-chain snapshot from the native decoder report. */
final class MobileControlHealthSummary {
    private static final String MISSING = "na";

    private MobileControlHealthSummary() {}

    static String format(String decoderReport) {
        return "processed_frames=" + value(decoderReport, "processed_frames")
                + " active_stream_generation="
                + value(decoderReport, "active_stream_generation")
                + " control_blocker=" + value(decoderReport, "control_blocker")
                + " blocker_age_us="
                + value(decoderReport, "control_blocker_age_us")
                + " blocker_transition_id="
                + value(decoderReport, "control_blocker_transition_id")
                + " delivery_fail_closes="
                + value(decoderReport, "native_delivery_fail_close_requests")
                + " stream_lifecycle_closes="
                + value(decoderReport, "native_stream_lifecycle_close_requests")
                + " stale_generation_suppressed="
                + value(decoderReport, "stale_stream_generation_suppressed")
                + " output_disabled_suppressed="
                + value(decoderReport, "output_disabled_suppressed")
                + " candidate_moves=" + value(decoderReport, "candidate_moves")
                + " no_targets=" + value(decoderReport, "no_targets")
                + " unsupported_class="
                + value(decoderReport, "geometry_unsupported_class_rejected")
                + " tracks_created=" + value(decoderReport, "tracker_tracks_created")
                + " tracks_expired=" + value(decoderReport, "tracker_tracks_expired")
                + " ambiguous_center_rejected="
                + value(decoderReport, "tracker_ambiguous_center_matches_rejected")
                + " track_id_rebinds=" + value(decoderReport, "track_id_rebinds")
                + " ambiguous_rebinds="
                + value(decoderReport, "rejected_ambiguous_rebinds")
                + " rebind_geometry_rejected="
                + value(decoderReport, "rejected_rebind_geometry")
                + " exact_track_geometry_rejected="
                + value(decoderReport, "rejected_exact_track_geometry")
                + " held_targets=" + value(decoderReport, "held_targets")
                + " target_switches=" + value(decoderReport, "target_switches")
                + " head_projection_continued="
                + value(decoderReport, "head_body_projection_continuations")
                + " head_projection_recovered="
                + value(decoderReport, "head_body_projection_recoveries")
                + " head_projection_recovery_max_px="
                + value(decoderReport, "maximum_head_body_projection_recovery_pixels")
                + " head_projection_rejected="
                + value(decoderReport, "rejected_head_body_projection_geometry")
                + " switch_pending=" + value(decoderReport, "switch_pending_frames")
                + " reacquisition_pending="
                + value(decoderReport, "reacquisition_pending_frames")
                + " reacquisition_confirmed="
                + value(decoderReport, "reacquisition_confirmations")
                + " ego_response_timeouts="
                + value(decoderReport, "ego_motion_response_timeouts")
                + " ego_response_support="
                + value(decoderReport, "maximum_measured_ego_motion_support")
                + " motion_plans=" + value(decoderReport, "motion_plans")
                + " filter_blends="
                + value(decoderReport, "tracker_control_filter_blends")
                + " filter_bypasses="
                + value(decoderReport, "tracker_control_filter_bypasses")
                + " time_velocity_updates="
                + value(decoderReport, "tracker_time_based_velocity_updates")
                + " max_observation_interval_us="
                + value(decoderReport, "tracker_maximum_observation_interval_us")
                + " filter_max_innovation_px="
                + value(decoderReport, "tracker_maximum_control_innovation_pixels")
                + " tracking_lock_updates="
                + value(decoderReport, "tracking_only_lock_updates")
                + " switch_confirm_us="
                + value(decoderReport, "switch_confirmation_duration_us")
                + " lost_hold_us="
                + value(decoderReport, "lost_target_hold_duration_us")
                + " pending_suppressed="
                + value(decoderReport, "native_move_completion_pending_suppressed")
                + " pending_age_us="
                + value(decoderReport, "native_move_completion_pending_age_us")
                + " pending_deadline_us="
                + value(decoderReport, "native_move_completion_deadline_us")
                + " pending_timeouts="
                + value(decoderReport, "native_move_completion_timeouts")
                + " ack_completions="
                + value(decoderReport, "native_device_ack_completions")
                + " ack_failures=" + value(decoderReport, "native_device_ack_failures")
                + " last_ack_us="
                + value(decoderReport, "native_last_device_ack_latency_us")
                + " last_ack_interval_us="
                + value(decoderReport, "native_last_device_ack_interval_us")
                + " last_move=" + value(decoderReport, "native_last_offered_delta_x")
                + "," + value(decoderReport, "native_last_offered_delta_y")
                + " absolute_move="
                + value(decoderReport, "native_offered_absolute_x_counts")
                + "," + value(decoderReport, "native_offered_absolute_y_counts")
                + " maximum_absolute_axis="
                + value(decoderReport, "native_maximum_offered_absolute_axis_delta")
                + " direction_flips="
                + value(decoderReport, "native_offered_direction_flips_x")
                + "," + value(decoderReport, "native_offered_direction_flips_y")
                + " last_offer_interval_us="
                + value(decoderReport, "native_last_offer_interval_us")
                + " visibility_min_us="
                + value(decoderReport, "makcu_post_completion_visibility_min_us")
                + " visibility_armed="
                + value(decoderReport, "post_completion_visibility_armed")
                + " visibility_age_us="
                + value(decoderReport, "post_completion_visibility_age_us")
                + " visibility_timeouts="
                + value(decoderReport, "post_completion_visibility_timeouts")
                + " detections=" + value(decoderReport, "last_detection_count")
                + " max_confidence="
                + value(decoderReport, "last_max_detection_confidence")
                + " new_track_threshold="
                + value(decoderReport, "tracker_new_track_confidence_threshold")
                + " low_track_threshold="
                + value(decoderReport, "tracker_low_confidence_threshold")
                + " output_requested=" + value(decoderReport, "output_requested")
                + " output_enabled=" + value(decoderReport, "output_enabled")
                + " user_max_axis=" + value(decoderReport, "maximum_axis_delta")
                + " effective_uncalibrated_max_axis="
                + value(decoderReport, "motion_uncalibrated_maximum_axis_delta");
    }

    private static String value(String report, String field) {
        return MobileDiagnosticFieldParser.valueOr(report, field, MISSING);
    }
}
