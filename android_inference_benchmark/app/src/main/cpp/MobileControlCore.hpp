#pragma once

#include "MobileMotionPlanner.hpp"
#include "MobileTargetTracker.hpp"
#include "YoloPostprocessor.hpp"
#include "vfdual/model_contract.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace vfdual_android {

enum class AimSource : std::uint8_t {
  none,
  head,
  body_fallback,
  geometric_head,
  selected_class,
};

enum class GeometryRejectReason : std::uint8_t {
  none,
  non_finite,
  invalid_box,
  unsupported_class,
  confidence,
  out_of_bounds,
  border,
  size,
  aspect_ratio,
};

enum class ControlSuppressionReason : std::uint8_t {
  none,
  invalid_time,
  stale_frame,
  non_monotonic_frame,
  no_valid_target,
  detected_not_control_eligible,
  lock_held,
  switch_pending,
  deadzone,
  settle_guard,
  response_guard,
  device_resolution_guard,
  direction_flip,
  motion_invalid,
};

[[nodiscard]] const char* control_suppression_reason_name(
    ControlSuppressionReason reason) noexcept;

struct ControlFrameContext {
  std::uint64_t sequence{};
  std::uint64_t observed_at_us{};
  std::uint64_t now_us{};
};

inline constexpr std::uint64_t kMobileControlMaximumFrameAgeUs = 150'000U;
inline constexpr std::uint64_t kMobileControlMaximumLostTargetHoldUs = 500'000U;
inline constexpr std::uint64_t kMobileControlDefaultLostTrackDurationUs =
    100'000U;

struct MobileControlConfig {
  std::uint32_t body_class_id{vfdual::kDefaultMobileModel.body_class_id};
  std::uint32_t head_class_id{vfdual::kDefaultMobileModel.head_class_id};
  std::uint32_t selected_class_id{vfdual::kDefaultMobileModel.head_class_id};
  bool selected_class_uses_head_box{true};
  bool selected_class_uses_geometric_head{false};
  bool head_body_pairing_enabled{true};
  float head_confidence_threshold{0.25F};
  float body_confidence_threshold{0.25F};
  float model_width{static_cast<float>(vfdual::kDefaultMobileModel.input.width)};
  float model_height{static_cast<float>(vfdual::kDefaultMobileModel.input.height)};
  float model_center_x{static_cast<float>(vfdual::kDefaultMobileModel.input.width) / 2.0F};
  float model_center_y{static_cast<float>(vfdual::kDefaultMobileModel.input.height) / 2.0F};
  std::uint64_t maximum_frame_age_us{kMobileControlMaximumFrameAgeUs};

  bool reject_border_touching{true};
  float border_margin_pixels{1.0F};
  float head_min_width{2.0F};
  float head_max_width{128.0F};
  float head_min_height{2.0F};
  float head_max_height{128.0F};
  float head_min_aspect_ratio{0.30F};
  float head_max_aspect_ratio{2.55F};
  float body_min_width{8.0F};
  float body_max_width{414.0F};
  float body_min_height{26.0F};
  float body_max_height{414.0F};
  float body_min_aspect_ratio{0.10F};
  float body_max_aspect_ratio{1.05F};

  MobileTargetTrackerConfig tracker{
      .lost_track_duration_us = kMobileControlDefaultLostTrackDurationUs,
  };
  float paired_body_min_confidence{0.42F};
  float head_only_min_confidence{0.82F};
  float head_only_max_center_distance_pixels{195.0F};
  float body_fallback_min_confidence{0.62F};
  float body_fallback_max_center_distance_pixels{169.0F};
  // Single-machine parity: confidence keeps weak detections out, while a
  // normalized reticle-distance term prevents a far 0.99 target from beating
  // a nearby credible target during initial acquisition or missing-lock switch.
  float candidate_confidence_weight{1.55F};
  float candidate_center_weight{1.35F};
  float candidate_center_scale_pixels{103.5F};
  float pair_body_expand_width_ratio{0.35F};
  float pair_body_expand_height_ratio{0.10F};
  float pair_head_upper_body_ratio{0.62F};
  float pair_min_head_body_area_ratio{0.002F};
  float pair_max_head_body_area_ratio{0.55F};
  float pair_min_head_body_width_ratio{0.025F};
  float pair_max_head_body_width_ratio{0.85F};
  float pair_min_head_body_height_ratio{0.025F};
  float pair_max_head_body_height_ratio{0.75F};
  float pair_min_body_pixels_below_head{3.0F};

  float body_fallback_y_ratio{0.18F};
  // A geometric head is inferred from a body box.  The body edges remain
  // valid prediction bounds, but they are not a valid "close enough" radius
  // for final aiming.  Keep the control radius tight and model-space based.
  float geometric_head_control_radius_pixels{4.0F};
  float head_anchor_x_ratio{0.50F};
  float head_anchor_y_ratio{0.50F};
  float head_safe_inset_fraction{0.12F};
  float head_safe_inset_min_pixels{0.50F};
  float head_max_anchor_lag_pixels{1.25F};
  float head_max_anchor_lag_fraction{0.18F};

  float lock_match_max_distance_pixels{48.0F};
  float lock_match_min_iou{0.15F};
  float lock_match_min_giou{-0.164F};
  bool track_id_rebind_enabled{true};
  std::uint32_t track_id_rebind_max_candidates{1};
  float track_id_rebind_max_distance_pixels{72.0F};
  float track_id_rebind_min_iou{0.02F};
  float track_id_rebind_min_body_iou{0.18F};
  float track_id_rebind_min_size_ratio{0.55F};
  float track_id_rebind_max_size_ratio{1.80F};
  // Common-frame translation may refine the uncalibrated 1px/count estimate,
  // but never beyond the desktop guard's unknown-environment response range.
  float measured_ego_motion_maximum_px_per_count{8.0F};
  std::uint32_t switch_confirmation_frames{2};
  // Monotonic observation time is authoritative so confirmation does not
  // become shorter merely because the fresh-content FPS is higher.
  std::uint64_t switch_confirmation_duration_us{20'000U};
  // Zero keeps the generic model contract unchanged. Game profiles may add
  // final-control credibility and jump gates for a missing-lock switch.
  float missing_switch_min_confidence{};
  float missing_switch_max_jump_pixels{};
  std::uint32_t lost_frame_hold_count{2};
  // Zero preserves the legacy count-based contract. Game-specific profiles
  // use monotonic time so target persistence cannot vary with fresh FPS.
  std::uint64_t lost_target_hold_duration_us{};

  float velocity_update_alpha{0.45F};
  float maximum_velocity_pixels_per_second{1'200.0F};
  MobileMotionPlannerConfig motion{};
};

/** Applies bounded game-specific motion tuning without changing model I/O. */
void apply_mobile_model_control_tuning(
    const vfdual::MobileModelContract& model,
    MobileControlConfig& config) noexcept;

struct ControlCoreMetrics {
  std::uint64_t rejected_non_finite{};
  std::uint64_t rejected_invalid_box{};
  std::uint64_t rejected_unsupported_class{};
  std::uint64_t rejected_confidence{};
  std::uint64_t rejected_out_of_bounds{};
  std::uint64_t rejected_border{};
  std::uint64_t rejected_size{};
  std::uint64_t rejected_aspect_ratio{};
  std::uint64_t invalid_time_frames{};
  std::uint64_t stale_frames{};
  std::uint64_t non_monotonic_frames{};
  std::uint64_t head_preemptions{};
  std::uint64_t head_body_projection_continuations{};
  std::uint64_t head_body_projection_recoveries{};
  std::uint64_t rejected_head_body_projection_geometry{};
  std::uint64_t switch_pending_frames{};
  std::uint64_t reacquisition_pending_frames{};
  std::uint64_t reacquisition_confirmations{};
  std::uint64_t rejected_missing_switch_confidence{};
  std::uint64_t rejected_missing_switch_jump{};
  std::uint64_t settle_suppressions{};
  std::uint64_t paired_heads{};
  std::uint64_t head_only_acceptances{};
  std::uint64_t rejected_unvalidated_heads{};
  std::uint64_t rejected_body_fallbacks{};
  std::uint64_t detected_not_control_eligible_frames{};
  std::uint64_t motion_invalid_suppressions{};
  std::uint64_t lock_exact_track_matches{};
  std::uint64_t lock_observation_track_matches{};
  std::uint64_t rejected_exact_track_geometry{};
  std::uint64_t lock_geometric_matches{};
  std::uint64_t lock_giou_matches{};
  std::uint64_t track_id_rebinds{};
  std::uint64_t rejected_known_track_rebinds{};
  std::uint64_t rejected_track_id_mismatches{};
  std::uint64_t rejected_ambiguous_rebinds{};
  std::uint64_t rejected_rebind_geometry{};
  std::uint64_t ego_motion_adjustments{};
  std::uint64_t measured_ego_motion_adjustments{};
  std::uint64_t rejected_measured_ego_motion_axes{};
  std::uint64_t ego_motion_response_waits{};
  std::uint64_t ego_motion_response_timeouts{};
  std::uint64_t head_anchor_prediction_limits{};
  std::uint64_t tracking_only_frames{};
  std::uint64_t tracking_only_lock_updates{};
  float last_head_safe_radius_pixels{};
  float maximum_head_anchor_lag_pixels{};
  float maximum_head_body_projection_recovery_pixels{};
  float maximum_ego_motion_shift_pixels{};
  float maximum_ego_motion_prediction_error_pixels{};
  std::uint32_t maximum_measured_ego_motion_support{};
};

struct MobileControlOutput {
  bool has_target{};
  bool held{};
  bool switched{};
  AimSource source{AimSource::none};
  ControlSuppressionReason suppression_reason{ControlSuppressionReason::none};
  float target_x{};
  float target_y{};
  std::int32_t delta_x{};
  std::int32_t delta_y{};
  std::uint64_t lock_id{};
  std::uint64_t track_id{};
  MobileMotionPhase motion_phase{MobileMotionPhase::acquire};
  MotionPlannerSuppressionReason motion_suppression_reason{
      MotionPlannerSuppressionReason::none};
  float predicted_error_x{};
  float predicted_error_y{};
  float target_acceleration_x_pixels_per_second2{};
  float target_acceleration_y_pixels_per_second2{};
  bool response_limited{};
  bool jerk_limited{};
  bool step_limited{};
  bool prediction_limited{};
  bool settle_stopped{};
  float head_safe_radius_pixels{};
  float head_anchor_lag_x_pixels{};
  float head_anchor_lag_y_pixels{};

  [[nodiscard]] bool has_move() const noexcept { return delta_x != 0 || delta_y != 0; }
};

/** Platform-independent Android hot-path control. No JNI, USB, network or host-input dependency. */
class MobileControlCore final {
 public:
  MobileControlCore() = default;
  explicit MobileControlCore(const MobileControlConfig& config);

  [[nodiscard]] bool configure(const MobileControlConfig& config);
  [[nodiscard]] MobileControlOutput process(
      std::span<const YoloDetection> detections, const ControlFrameContext& frame);
  /** Updates detection identity while physical output is waiting for completion. */
  [[nodiscard]] ControlSuppressionReason observe_tracking_only(
      std::span<const YoloDetection> detections,
      const ControlFrameContext& frame) noexcept;
  /** Queues one acknowledged move for resolution against its first visible frame. */
  void apply_visible_ego_motion(
      std::int32_t delta_x, std::int32_t delta_y) noexcept;
  [[nodiscard]] const ControlCoreMetrics& metrics() const noexcept { return metrics_; }
  [[nodiscard]] const MobileTargetTrackerMetrics& tracker_metrics() const noexcept {
    return tracker_.metrics();
  }
  [[nodiscard]] const MobileMotionPlannerMetrics& motion_metrics() const noexcept {
    return motion_planner_.metrics();
  }
  [[nodiscard]] const MobileMotionPlannerConfig& motion_config() const noexcept {
    return motion_planner_.config();
  }
  [[nodiscard]] std::uint64_t switch_confirmation_duration_us() const noexcept {
    return config_.switch_confirmation_duration_us;
  }
  [[nodiscard]] float missing_switch_min_confidence() const noexcept {
    return config_.missing_switch_min_confidence;
  }
  [[nodiscard]] float missing_switch_max_jump_pixels() const noexcept {
    return config_.missing_switch_max_jump_pixels;
  }
  [[nodiscard]] std::uint64_t lost_target_hold_duration_us() const noexcept {
    return config_.lost_target_hold_duration_us;
  }
  [[nodiscard]] std::uint64_t lost_track_duration_us() const noexcept {
    return config_.tracker.lost_track_duration_us;
  }
  [[nodiscard]] float tracker_new_track_confidence_threshold() const noexcept {
    return config_.tracker.new_track_confidence_threshold;
  }
  [[nodiscard]] float tracker_low_confidence_threshold() const noexcept {
    return config_.tracker.low_confidence_threshold;
  }
  [[nodiscard]] const MobileMotionPlannerOutput& motion_snapshot() const noexcept {
    return motion_planner_.last_output();
  }
  void reset() noexcept;

 private:
  struct Candidate {
    YoloDetection detection{};
    YoloDetection paired_body{};
    AimSource source{AimSource::none};
    float target_x{};
    float target_y{};
    float anchor_x{};
    float anchor_y{};
    float safe_radius_pixels{};
    std::uint64_t track_id{};
    // The paired body's track remains the cross-class control anchor, while
    // this id preserves the underlying selected-class observation identity.
    std::uint64_t observation_track_id{};
    bool has_body_pair{};
    bool track_was_known{};
    // True only while the selected head geometry is synthesized from the
    // exact paired-body track during a temporary real-head dropout.
    bool head_from_body_projection{};
  };

  struct PairOption {
    std::size_t head_index{};
    std::size_t body_index{};
    float score{};
  };

  [[nodiscard]] static bool valid_config(const MobileControlConfig& config) noexcept;
  [[nodiscard]] GeometryRejectReason geometry_reject_reason(const YoloDetection& detection) const noexcept;
  void count_geometry_rejection(GeometryRejectReason reason) noexcept;
  [[nodiscard]] bool build_candidates(
      std::span<const YoloDetection> detections,
      std::uint64_t sequence, std::uint64_t observed_at_us);
  [[nodiscard]] Candidate candidate_for(
      const TrackedDetection& detection, AimSource source,
      const TrackedDetection* paired_body = nullptr) const noexcept;
  [[nodiscard]] bool head_body_pair_admissible(
      const YoloDetection& head, const YoloDetection& body) const noexcept;
  [[nodiscard]] float head_body_pair_score(
      const YoloDetection& head, const YoloDetection& body) const noexcept;
  [[nodiscard]] bool head_only_admissible(const TrackedDetection& head) const noexcept;
  [[nodiscard]] bool body_fallback_admissible(const TrackedDetection& body) const noexcept;
  [[nodiscard]] bool better_rank(const Candidate& left, const Candidate& right) const noexcept;
  [[nodiscard]] bool choose_best(Candidate& result) const noexcept;
  [[nodiscard]] bool choose_locked_target_head_upgrade(
      Candidate& result) const noexcept;
  [[nodiscard]] bool choose_locked_head_body_projection(
      Candidate& result) noexcept;
  [[nodiscard]] bool is_head_projection_recovery(
      const Candidate& candidate) const noexcept;
  [[nodiscard]] bool missing_switch_admissible(
      const Candidate& candidate, bool count_rejection) noexcept;
  [[nodiscard]] bool choose_pending_switch(Candidate& result) noexcept;
  [[nodiscard]] bool choose_best_missing_switch(Candidate& result) noexcept;
  [[nodiscard]] bool association_admissible(
      const Candidate& left, const Candidate& right,
      bool* giou_only = nullptr) const noexcept;
  [[nodiscard]] static bool same_candidate_identity(
      const Candidate& left, const Candidate& right) noexcept;
  [[nodiscard]] bool track_id_rebind_admissible(
      const Candidate& candidate, bool* giou_only) const noexcept;
  [[nodiscard]] bool match_locked(Candidate& result) noexcept;
  [[nodiscard]] bool update_pending_switch(
      const Candidate& challenger, std::uint64_t observed_at_us) noexcept;
  void remember_candidate_tracks();
  void accept_candidate(const Candidate& candidate, const ControlFrameContext& frame, bool switched) noexcept;
  void accept_same_identity_head_upgrade(
      const Candidate& candidate,
      const ControlFrameContext& frame) noexcept;
  void accept_head_projection_recovery(
      const Candidate& candidate,
      const ControlFrameContext& frame) noexcept;
  [[nodiscard]] bool refresh_locked_candidate(
      const ControlFrameContext& frame) noexcept;
  [[nodiscard]] MobileControlOutput held_output(ControlSuppressionReason reason) const noexcept;
  [[nodiscard]] MobileControlOutput active_output(
      const ControlFrameContext& frame, bool switched) noexcept;
  [[nodiscard]] static ControlSuppressionReason control_suppression_reason(
      MotionPlannerSuppressionReason reason) noexcept;
  [[nodiscard]] ControlSuppressionReason accept_frame_context(
      const ControlFrameContext& frame) noexcept;
  void reset_motion() noexcept;
  void clear_pending_switch() noexcept;
  [[nodiscard]] bool apply_pending_visible_ego_motion(
      std::uint64_t sequence, std::uint64_t observed_at_us) noexcept;
  [[nodiscard]] std::uint32_t visible_ego_motion_witness_class_id()
      const noexcept;
  [[nodiscard]] std::uint64_t visible_ego_motion_timeout_us() const noexcept;
  void abandon_pending_visible_ego_motion() noexcept;
  void apply_visible_frame_shift(
      float shift_x, float shift_y, bool measured,
      std::uint32_t measured_support) noexcept;

  MobileControlConfig config_{};
  ControlCoreMetrics metrics_{};
  MobileTargetTracker tracker_{};
  MobileMotionPlanner motion_planner_{};
  std::vector<Candidate> candidates_{};
  std::vector<YoloDetection> validated_detections_{};
  std::vector<TrackedDetection> tracked_detections_{};
  std::vector<PairOption> pair_options_{};
  std::vector<std::size_t> paired_body_for_head_{};
  std::vector<std::uint8_t> paired_bodies_{};
  // Tracker ids are positive and monotonically increasing until reset.  One
  // ceiling therefore represents the complete current-lock identity history
  // without a growing hash set or per-track hot-path allocation.
  std::uint64_t known_track_id_ceiling_{};
  Candidate locked_candidate_{};
  Candidate pending_candidate_{};
  float velocity_x_{};
  float velocity_y_{};
  bool has_lock_{};
  bool has_pending_switch_{};
  bool reacquisition_requires_confirmation_{};
  bool has_pending_visible_ego_motion_{};
  bool has_accepted_frame_{};
  std::int32_t pending_visible_delta_x_{};
  std::int32_t pending_visible_delta_y_{};
  std::uint64_t pending_visible_started_at_us_{};
  std::uint32_t pending_switch_frames_{};
  std::uint64_t pending_switch_started_at_us_{};
  std::uint32_t missing_frames_{};
  std::uint64_t last_frame_sequence_{};
  std::uint64_t last_frame_observed_at_us_{};
  std::uint64_t last_frame_now_us_{};
  std::uint64_t last_target_observed_at_us_{};
  std::uint64_t lock_id_{};
};

}  // namespace vfdual_android
