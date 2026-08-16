#include "MobileControlCore.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace vfdual_android {
namespace {

constexpr float kMinimumVisibleResponseFraction = 0.20F;
constexpr std::uint32_t kMinimumCommonFrameShiftSupport = 2U;
constexpr float kPairConfidenceTieBreakScale = 0.01F;

float box_area(const YoloDetection& detection) noexcept {
  return (detection.x2 - detection.x1) * (detection.y2 - detection.y1);
}

float squared_distance(float left_x, float left_y, float right_x, float right_y) noexcept {
  const float delta_x = left_x - right_x;
  const float delta_y = left_y - right_y;
  return delta_x * delta_x + delta_y * delta_y;
}

float intersection_over_union(const YoloDetection& left, const YoloDetection& right) noexcept {
  const float x1 = std::max(left.x1, right.x1);
  const float y1 = std::max(left.y1, right.y1);
  const float x2 = std::min(left.x2, right.x2);
  const float y2 = std::min(left.y2, right.y2);
  const float intersection = std::max(0.0F, x2 - x1) * std::max(0.0F, y2 - y1);
  const float union_area = box_area(left) + box_area(right) - intersection;
  return union_area > 0.0F ? intersection / union_area : 0.0F;
}

float generalized_intersection_over_union(
    const YoloDetection& left, const YoloDetection& right) noexcept {
  const float x1 = std::max(left.x1, right.x1);
  const float y1 = std::max(left.y1, right.y1);
  const float x2 = std::min(left.x2, right.x2);
  const float y2 = std::min(left.y2, right.y2);
  const float intersection =
      std::max(0.0F, x2 - x1) * std::max(0.0F, y2 - y1);
  const float union_area = box_area(left) + box_area(right) - intersection;
  const float enclosing_x1 = std::min(left.x1, right.x1);
  const float enclosing_y1 = std::min(left.y1, right.y1);
  const float enclosing_x2 = std::max(left.x2, right.x2);
  const float enclosing_y2 = std::max(left.y2, right.y2);
  const float enclosing_area =
      (enclosing_x2 - enclosing_x1) * (enclosing_y2 - enclosing_y1);
  if (union_area <= 0.0F || enclosing_area <= 0.0F) return -1.0F;
  const float iou = intersection / union_area;
  return iou - (enclosing_area - union_area) / enclosing_area;
}

bool box_size_compatible(
    const YoloDetection& left, const YoloDetection& right,
    float minimum_ratio, float maximum_ratio) noexcept {
  const float left_width = left.x2 - left.x1;
  const float left_height = left.y2 - left.y1;
  const float right_width = right.x2 - right.x1;
  const float right_height = right.y2 - right.y1;
  const float width_ratio = right_width / std::max(left_width, 1.0e-6F);
  const float height_ratio = right_height / std::max(left_height, 1.0e-6F);
  return width_ratio >= minimum_ratio && width_ratio <= maximum_ratio &&
      height_ratio >= minimum_ratio && height_ratio <= maximum_ratio;
}

float clamp_magnitude(float value, float maximum) noexcept {
  return std::clamp(value, -maximum, maximum);
}

float bounded_measured_ego_axis(
    float measured_shift, float expected_shift, std::int32_t command_delta,
    float maximum_px_per_count, float tolerance, bool& accepted) noexcept {
  accepted = false;
  if (command_delta == 0) return 0.0F;
  const float maximum_shift =
      std::fabs(static_cast<float>(command_delta)) * maximum_px_per_count +
      tolerance;
  const float minimum_shift =
      std::fabs(expected_shift) * kMinimumVisibleResponseFraction;
  if (!std::isfinite(measured_shift) || measured_shift == 0.0F ||
      (measured_shift > 0.0F) != (expected_shift > 0.0F) ||
      std::fabs(measured_shift) < minimum_shift ||
      std::fabs(measured_shift) > maximum_shift) {
    return expected_shift;
  }
  accepted = true;
  return measured_shift;
}

}  // namespace

const char* control_suppression_reason_name(
    ControlSuppressionReason reason) noexcept {
  switch (reason) {
    case ControlSuppressionReason::none: return "none";
    case ControlSuppressionReason::invalid_time: return "invalid_time";
    case ControlSuppressionReason::stale_frame: return "stale_frame";
    case ControlSuppressionReason::non_monotonic_frame:
      return "non_monotonic_frame";
    case ControlSuppressionReason::no_valid_target: return "no_valid_target";
    case ControlSuppressionReason::detected_not_control_eligible:
      return "detected_not_control_eligible";
    case ControlSuppressionReason::lock_held: return "lock_held";
    case ControlSuppressionReason::switch_pending: return "switch_pending";
    case ControlSuppressionReason::deadzone: return "deadzone";
    case ControlSuppressionReason::settle_guard: return "settle_guard";
    case ControlSuppressionReason::response_guard: return "response_guard";
    case ControlSuppressionReason::device_resolution_guard:
      return "device_resolution_guard";
    case ControlSuppressionReason::direction_flip: return "direction_flip";
    case ControlSuppressionReason::motion_invalid: return "motion_invalid";
  }
  return "unknown";
}

MobileControlCore::MobileControlCore(const MobileControlConfig& config) {
  (void)configure(config);
}

bool MobileControlCore::valid_config(const MobileControlConfig& config) noexcept {
  const float values[] = {
      config.head_confidence_threshold, config.body_confidence_threshold,
      config.model_width, config.model_height, config.model_center_x, config.model_center_y,
      config.border_margin_pixels, config.head_min_width, config.head_max_width,
      config.head_min_height, config.head_max_height, config.head_min_aspect_ratio,
      config.head_max_aspect_ratio, config.body_min_width, config.body_max_width,
      config.body_min_height, config.body_max_height, config.body_min_aspect_ratio,
      config.body_max_aspect_ratio, config.paired_body_min_confidence,
      config.head_only_min_confidence, config.head_only_max_center_distance_pixels,
      config.body_fallback_min_confidence, config.body_fallback_max_center_distance_pixels,
      config.candidate_confidence_weight, config.candidate_center_weight,
      config.candidate_center_scale_pixels,
      config.pair_body_expand_width_ratio, config.pair_body_expand_height_ratio,
      config.pair_head_upper_body_ratio, config.pair_min_head_body_area_ratio,
      config.pair_max_head_body_area_ratio, config.pair_min_head_body_width_ratio,
      config.pair_max_head_body_width_ratio, config.pair_min_head_body_height_ratio,
      config.pair_max_head_body_height_ratio, config.pair_min_body_pixels_below_head,
      config.body_fallback_y_ratio, config.head_anchor_x_ratio,
      config.head_anchor_y_ratio, config.head_safe_inset_fraction, config.head_safe_inset_min_pixels,
      config.head_max_anchor_lag_pixels, config.head_max_anchor_lag_fraction,
      config.lock_match_max_distance_pixels, config.lock_match_min_iou,
      config.lock_match_min_giou, config.track_id_rebind_max_distance_pixels,
      config.track_id_rebind_min_iou, config.track_id_rebind_min_body_iou,
      config.track_id_rebind_min_size_ratio, config.track_id_rebind_max_size_ratio,
      config.missing_switch_min_confidence,
      config.missing_switch_max_jump_pixels,
      config.measured_ego_motion_maximum_px_per_count,
      config.velocity_update_alpha, config.maximum_velocity_pixels_per_second,
  };
  if (!std::all_of(std::begin(values), std::end(values), [](float value) { return std::isfinite(value); })) {
    return false;
  }
  const bool head_class_valid =
      config.head_class_id != vfdual::kNoModelClass &&
      config.head_class_id != config.body_class_id;
  const bool selected_head_valid = !config.selected_class_uses_head_box ||
      (head_class_valid && config.selected_class_id == config.head_class_id);
  const bool selected_geometric_valid =
      !config.selected_class_uses_geometric_head ||
      !config.selected_class_uses_head_box;
  return selected_head_valid && selected_geometric_valid &&
      config.maximum_frame_age_us > 0 &&
      config.head_confidence_threshold >= 0.0F && config.head_confidence_threshold <= 1.0F &&
      config.body_confidence_threshold >= 0.0F && config.body_confidence_threshold <= 1.0F &&
      config.model_width > 0.0F && config.model_height > 0.0F &&
      config.model_center_x >= 0.0F && config.model_center_x <= config.model_width &&
      config.model_center_y >= 0.0F && config.model_center_y <= config.model_height &&
      config.border_margin_pixels >= 0.0F && config.border_margin_pixels * 2.0F < config.model_width &&
      config.border_margin_pixels * 2.0F < config.model_height &&
      config.head_min_width > 0.0F && config.head_max_width >= config.head_min_width &&
      config.head_min_height > 0.0F && config.head_max_height >= config.head_min_height &&
      config.head_min_aspect_ratio > 0.0F && config.head_max_aspect_ratio >= config.head_min_aspect_ratio &&
      config.body_min_width > 0.0F && config.body_max_width >= config.body_min_width &&
      config.body_min_height > 0.0F && config.body_max_height >= config.body_min_height &&
      config.body_min_aspect_ratio > 0.0F && config.body_max_aspect_ratio >= config.body_min_aspect_ratio &&
      config.paired_body_min_confidence >= 0.0F && config.paired_body_min_confidence <= 1.0F &&
      config.head_only_min_confidence >= 0.0F && config.head_only_min_confidence <= 1.0F &&
      config.head_only_max_center_distance_pixels >= 0.0F &&
      config.body_fallback_min_confidence >= 0.0F && config.body_fallback_min_confidence <= 1.0F &&
      config.body_fallback_max_center_distance_pixels >= 0.0F &&
      config.candidate_confidence_weight >= 0.0F &&
      config.candidate_confidence_weight <= 10.0F &&
      config.candidate_center_weight >= 0.0F &&
      config.candidate_center_weight <= 10.0F &&
      config.candidate_confidence_weight + config.candidate_center_weight > 0.0F &&
      config.candidate_center_scale_pixels >= 1.0F &&
      config.candidate_center_scale_pixels <= 4'096.0F &&
      config.pair_body_expand_width_ratio >= 0.0F && config.pair_body_expand_height_ratio >= 0.0F &&
      config.pair_head_upper_body_ratio >= 0.0F && config.pair_head_upper_body_ratio <= 1.0F &&
      config.pair_min_head_body_area_ratio >= 0.0F &&
      config.pair_max_head_body_area_ratio >= config.pair_min_head_body_area_ratio &&
      config.pair_min_head_body_width_ratio >= 0.0F &&
      config.pair_max_head_body_width_ratio >= config.pair_min_head_body_width_ratio &&
      config.pair_min_head_body_height_ratio >= 0.0F &&
      config.pair_max_head_body_height_ratio >= config.pair_min_head_body_height_ratio &&
      config.pair_min_body_pixels_below_head >= 0.0F &&
      config.body_fallback_y_ratio >= 0.0F && config.body_fallback_y_ratio <= 1.0F &&
      config.geometric_head_control_radius_pixels > 0.0F &&
      config.geometric_head_control_radius_pixels <=
          std::max(config.model_width, config.model_height) &&
      config.head_anchor_x_ratio >= 0.0F && config.head_anchor_x_ratio <= 1.0F &&
      config.head_anchor_y_ratio >= 0.0F && config.head_anchor_y_ratio <= 1.0F &&
      config.head_safe_inset_fraction >= 0.0F && config.head_safe_inset_fraction <= 0.45F &&
      config.head_safe_inset_min_pixels >= 0.0F &&
      config.head_max_anchor_lag_pixels >= 0.0F &&
      config.head_max_anchor_lag_fraction >= 0.0F &&
      config.head_max_anchor_lag_fraction <= 0.50F &&
      config.lock_match_max_distance_pixels > 0.0F &&
      config.lock_match_min_iou >= 0.0F && config.lock_match_min_iou <= 1.0F &&
      config.lock_match_min_giou >= -1.0F && config.lock_match_min_giou <= 1.0F &&
      config.track_id_rebind_max_candidates > 0 &&
      config.track_id_rebind_max_distance_pixels > 0.0F &&
      config.track_id_rebind_min_iou >= 0.0F &&
      config.track_id_rebind_min_iou <= 1.0F &&
      config.track_id_rebind_min_body_iou >= 0.0F &&
      config.track_id_rebind_min_body_iou <= 1.0F &&
      config.track_id_rebind_min_size_ratio > 0.0F &&
      config.track_id_rebind_max_size_ratio >=
          config.track_id_rebind_min_size_ratio &&
      config.lost_target_hold_duration_us <=
          kMobileControlMaximumLostTargetHoldUs &&
      config.measured_ego_motion_maximum_px_per_count >= 0.10F &&
      config.measured_ego_motion_maximum_px_per_count <= 32.0F &&
      config.switch_confirmation_frames > 0 &&
      config.switch_confirmation_duration_us <= 500'000U &&
      config.missing_switch_min_confidence >= 0.0F &&
      config.missing_switch_min_confidence <= 1.0F &&
      config.missing_switch_max_jump_pixels >= 0.0F &&
      config.missing_switch_max_jump_pixels <=
          std::hypot(config.model_width, config.model_height) &&
      config.velocity_update_alpha >= 0.0F &&
      config.velocity_update_alpha <= 1.0F &&
      config.maximum_velocity_pixels_per_second >= 0.0F;
}

void apply_mobile_model_control_tuning(
    const vfdual::MobileModelContract& model,
    MobileControlConfig& config) noexcept {
  if (model.id ==
      vfdual::GameModelId::counter_strike_2_vombit_416_v8s) {
    // The legacy two-frame hold varied from roughly 10 ms at 200 fresh FPS to
    // 50 ms at 40 FPS. CS2 already exposes a monotonic, user-configurable
    // switch confirmation window; use that same duration for brief full-target
    // dropout so throughput changes cannot alter lock persistence.
    config.lost_target_hold_duration_us =
        config.switch_confirmation_duration_us;
    return;
  }
  if (model.id != vfdual::GameModelId::overwatch2_416_yolov5) return;

  // OW2 currently supplies an enemy-body class and derives the head anchor at
  // 18% of that box.  A 40x100 body box otherwise yields an 18px safe radius
  // and the settle latch stops roughly 9px away from the requested anchor.
  config.geometric_head_control_radius_pixels = 3.0F;
  // Without per-device response calibration, camera motion cannot be safely
  // separated from target velocity.  Fast proportional feedback is stable
  // across MAKCU and Bluetooth HID; speculative velocity lead is not.
  config.motion.prediction_horizon_ms = 0.0F;
  config.motion.uncalibrated_maximum_axis_delta = 32;
  config.motion.maximum_step_counts_per_tick = 24.0F;
  config.motion.maximum_jerk_counts_per_tick2 = 12.0F;
  config.switch_confirmation_frames = 3;
  // Match the desktop missing-lock contract: a retained low-confidence track
  // or a distant crowd member may not become the new lock merely by surviving
  // the temporal confirmation window.
  config.missing_switch_min_confidence = 0.461F;
  config.missing_switch_max_jump_pixels = 57.0F;
  config.lost_frame_hold_count = 4;
  // Four 60 Hz observations expressed as time. This retains the established
  // OW2 dropout tolerance without stretching to 100+ ms when fresh FPS falls.
  config.lost_target_hold_duration_us = 70'000U;
  // Six 60 Hz observations expressed as time keeps tracker identity stable
  // through short effect occlusion without retaining ghosts longer at low FPS.
  config.tracker.lost_track_duration_us = 100'000U;
}

bool MobileControlCore::configure(const MobileControlConfig& config) {
  if (!valid_config(config)) return false;
  MobileTargetTracker configured_tracker;
  if (!configured_tracker.configure(config.tracker)) return false;
  MobileMotionPlannerConfig motion_config = config.motion;
  motion_config.maximum_observation_age_us = std::min(
      motion_config.maximum_observation_age_us, config.maximum_frame_age_us);
  MobileMotionPlanner configured_motion;
  if (!configured_motion.configure(motion_config)) return false;
  config_ = config;
  config_.motion = motion_config;
  tracker_ = configured_tracker;
  motion_planner_ = configured_motion;
  reset();
  return true;
}

void MobileControlCore::apply_visible_ego_motion(
    std::int32_t delta_x, std::int32_t delta_y) noexcept {
  if (!has_lock_ || (delta_x == 0 && delta_y == 0)) return;
  pending_visible_delta_x_ = delta_x;
  pending_visible_delta_y_ = delta_y;
  pending_visible_started_at_us_ = 0U;
  has_pending_visible_ego_motion_ = true;
}

void MobileControlCore::apply_visible_frame_shift(
    float shift_x, float shift_y, bool measured,
    std::uint32_t measured_support) noexcept {
  if (!std::isfinite(shift_x) || !std::isfinite(shift_y)) return;
  const auto shift_detection = [&](YoloDetection& detection) {
    detection.x1 += shift_x;
    detection.x2 += shift_x;
    detection.y1 += shift_y;
    detection.y2 += shift_y;
  };
  const auto shift_candidate = [&](Candidate& candidate) {
    shift_detection(candidate.detection);
    if (candidate.has_body_pair) shift_detection(candidate.paired_body);
    candidate.target_x += shift_x;
    candidate.target_y += shift_y;
    candidate.anchor_x += shift_x;
    candidate.anchor_y += shift_y;
  };

  shift_candidate(locked_candidate_);
  if (has_pending_switch_) shift_candidate(pending_candidate_);
  tracker_.apply_visible_frame_shift(shift_x, shift_y);
  motion_planner_.apply_visible_error_shift(shift_x, shift_y);
  ++metrics_.ego_motion_adjustments;
  if (measured) {
    ++metrics_.measured_ego_motion_adjustments;
    metrics_.maximum_measured_ego_motion_support = std::max(
        metrics_.maximum_measured_ego_motion_support, measured_support);
  }
  metrics_.maximum_ego_motion_shift_pixels = std::max(
      metrics_.maximum_ego_motion_shift_pixels,
      std::hypot(shift_x, shift_y));
}

std::uint64_t MobileControlCore::visible_ego_motion_timeout_us() const noexcept {
  // Once either the selected lock or its tracker identity is no longer valid,
  // waiting for correspondence cannot produce trustworthy evidence. Reuse the
  // existing time contracts so this recovery is independent of fresh FPS.
  std::uint64_t timeout_us = config_.maximum_frame_age_us;
  if (config_.tracker.lost_track_duration_us != 0U) {
    timeout_us = std::min(timeout_us, config_.tracker.lost_track_duration_us);
  }
  if (config_.lost_target_hold_duration_us != 0U) {
    timeout_us = std::min(timeout_us, config_.lost_target_hold_duration_us);
  }
  return timeout_us;
}

void MobileControlCore::abandon_pending_visible_ego_motion() noexcept {
  // The old screen-space lock cannot be reconciled with the acknowledged
  // physical response. Drop target/motion state and require the existing
  // observation-time confirmation before another target may move the camera;
  // otherwise the timeout frame can immediately compound one uncertain move
  // with an unrelated replacement target.
  tracker_.reset();
  known_track_id_ceiling_ = 0U;
  locked_candidate_ = {};
  has_lock_ = false;
  reacquisition_requires_confirmation_ = true;
  missing_frames_ = 0U;
  last_target_observed_at_us_ = 0U;
  velocity_x_ = 0.0F;
  velocity_y_ = 0.0F;
  reset_motion();
  clear_pending_switch();
  pending_visible_delta_x_ = 0;
  pending_visible_delta_y_ = 0;
  pending_visible_started_at_us_ = 0U;
  has_pending_visible_ego_motion_ = false;
  ++metrics_.ego_motion_response_timeouts;
}

bool MobileControlCore::apply_pending_visible_ego_motion(
    std::uint64_t sequence, std::uint64_t observed_at_us) noexcept {
  if (!has_pending_visible_ego_motion_) return false;
  if (pending_visible_started_at_us_ == 0U) {
    pending_visible_started_at_us_ = observed_at_us;
  }
  const float expected_shift_x =
      -static_cast<float>(pending_visible_delta_x_) *
      config_.motion.response_x_px_per_count;
  const float expected_shift_y =
      -static_cast<float>(pending_visible_delta_y_) *
      config_.motion.response_y_px_per_count;
  const MobileVisibleFrameShift resolved =
      tracker_.resolve_visible_frame_shift(
          validated_detections_, sequence,
          expected_shift_x, expected_shift_y, observed_at_us, 1U,
          visible_ego_motion_witness_class_id());
  bool measured_x{};
  bool measured_y{};
  const float bounded_shift_x = resolved.measured
      ? bounded_measured_ego_axis(
            resolved.shift_x, expected_shift_x, pending_visible_delta_x_,
            config_.measured_ego_motion_maximum_px_per_count,
            config_.tracker.control_smoothing_bypass_delta_pixels,
            measured_x)
      : expected_shift_x;
  const float bounded_shift_y = resolved.measured
      ? bounded_measured_ego_axis(
            resolved.shift_y, expected_shift_y, pending_visible_delta_y_,
            config_.measured_ego_motion_maximum_px_per_count,
            config_.tracker.control_smoothing_bypass_delta_pixels,
            measured_y)
      : expected_shift_y;
  // A single target can confirm that an acknowledged response is visible, but
  // its displacement also contains independent target motion.  Absorbing the
  // whole displacement as camera motion erases target velocity and produces a
  // correction jump on the next frame.  Only a common shift supported by at
  // least two targets may replace the conservative response estimate.
  const bool has_common_frame_shift =
      resolved.support >= kMinimumCommonFrameShiftSupport;
  const float applied_shift_x = has_common_frame_shift
      ? bounded_shift_x : expected_shift_x;
  const float applied_shift_y = has_common_frame_shift
      ? bounded_shift_y : expected_shift_y;
  const bool measured = measured_x || measured_y;
  const bool x_confirmed = pending_visible_delta_x_ == 0 || measured_x;
  const bool y_confirmed = pending_visible_delta_y_ == 0 || measured_y;
  if (resolved.measured) {
    metrics_.maximum_ego_motion_prediction_error_pixels = std::max(
        metrics_.maximum_ego_motion_prediction_error_pixels,
        std::hypot(
            resolved.shift_x - expected_shift_x,
            resolved.shift_y - expected_shift_y));
    if (pending_visible_delta_x_ != 0 && !measured_x) {
      ++metrics_.rejected_measured_ego_motion_axes;
    }
    if (pending_visible_delta_y_ != 0 && !measured_y) {
      ++metrics_.rejected_measured_ego_motion_axes;
    }
  }
  if (!resolved.measured || !x_confirmed || !y_confirmed) {
    ++metrics_.ego_motion_response_waits;
    const std::uint64_t timeout_us = visible_ego_motion_timeout_us();
    if (observed_at_us >= pending_visible_started_at_us_ &&
        observed_at_us - pending_visible_started_at_us_ < timeout_us) {
      return true;
    }
    abandon_pending_visible_ego_motion();
    return false;
  }
  apply_visible_frame_shift(
      applied_shift_x, applied_shift_y,
      measured, measured ? resolved.support : 0U);
  pending_visible_delta_x_ = 0;
  pending_visible_delta_y_ = 0;
  pending_visible_started_at_us_ = 0U;
  has_pending_visible_ego_motion_ = false;
  return false;
}

std::uint32_t MobileControlCore::visible_ego_motion_witness_class_id()
    const noexcept {
  if (!config_.selected_class_uses_head_box) {
    return config_.selected_class_id;
  }
  std::size_t selected_class_count{};
  std::size_t body_class_count{};
  for (const YoloDetection& detection : validated_detections_) {
    if (detection.class_id == config_.selected_class_id) {
      ++selected_class_count;
    } else if (detection.class_id == config_.body_class_id) {
      ++body_class_count;
    }
  }
  // One person can expose both head and body tracks.  Use only one class as
  // the camera-motion witness set so that physical identity contributes once;
  // prefer the class with more currently visible people, with head on ties.
  return body_class_count > selected_class_count
      ? config_.body_class_id : config_.selected_class_id;
}

GeometryRejectReason MobileControlCore::geometry_reject_reason(
    const YoloDetection& detection) const noexcept {
  if (!std::isfinite(detection.x1) || !std::isfinite(detection.y1) ||
      !std::isfinite(detection.x2) || !std::isfinite(detection.y2) ||
      !std::isfinite(detection.confidence)) return GeometryRejectReason::non_finite;
  if (detection.x2 <= detection.x1 || detection.y2 <= detection.y1 ||
      detection.confidence < 0.0F || detection.confidence > 1.0F) {
    return GeometryRejectReason::invalid_box;
  }
  const bool is_selected = detection.class_id == config_.selected_class_id;
  const bool is_pairing_body = config_.selected_class_uses_head_box &&
      config_.head_body_pairing_enabled &&
      detection.class_id == config_.body_class_id;
  if (!is_selected && !is_pairing_body) return GeometryRejectReason::unsupported_class;
  const bool is_head = is_selected && config_.selected_class_uses_head_box;
  const float confidence_threshold = is_head
      ? config_.head_confidence_threshold : config_.body_confidence_threshold;
  if (detection.confidence < confidence_threshold) return GeometryRejectReason::confidence;
  if (detection.x1 < 0.0F || detection.y1 < 0.0F ||
      detection.x2 > config_.model_width || detection.y2 > config_.model_height) {
    return GeometryRejectReason::out_of_bounds;
  }
  if (config_.reject_border_touching &&
      (detection.x1 <= config_.border_margin_pixels || detection.y1 <= config_.border_margin_pixels ||
       detection.x2 >= config_.model_width - config_.border_margin_pixels ||
       detection.y2 >= config_.model_height - config_.border_margin_pixels)) {
    return GeometryRejectReason::border;
  }
  const float width = detection.x2 - detection.x1;
  const float height = detection.y2 - detection.y1;
  const float minimum_width = is_head ? config_.head_min_width : config_.body_min_width;
  const float maximum_width = is_head ? config_.head_max_width : config_.body_max_width;
  const float minimum_height = is_head ? config_.head_min_height : config_.body_min_height;
  const float maximum_height = is_head ? config_.head_max_height : config_.body_max_height;
  if (width < minimum_width || width > maximum_width ||
      height < minimum_height || height > maximum_height) return GeometryRejectReason::size;
  const float aspect_ratio = width / height;
  const float minimum_aspect = is_head ? config_.head_min_aspect_ratio : config_.body_min_aspect_ratio;
  const float maximum_aspect = is_head ? config_.head_max_aspect_ratio : config_.body_max_aspect_ratio;
  if (aspect_ratio < minimum_aspect || aspect_ratio > maximum_aspect) {
    return GeometryRejectReason::aspect_ratio;
  }
  return GeometryRejectReason::none;
}

void MobileControlCore::count_geometry_rejection(GeometryRejectReason reason) noexcept {
  switch (reason) {
    case GeometryRejectReason::non_finite: ++metrics_.rejected_non_finite; break;
    case GeometryRejectReason::invalid_box: ++metrics_.rejected_invalid_box; break;
    case GeometryRejectReason::unsupported_class: ++metrics_.rejected_unsupported_class; break;
    case GeometryRejectReason::confidence: ++metrics_.rejected_confidence; break;
    case GeometryRejectReason::out_of_bounds: ++metrics_.rejected_out_of_bounds; break;
    case GeometryRejectReason::border: ++metrics_.rejected_border; break;
    case GeometryRejectReason::size: ++metrics_.rejected_size; break;
    case GeometryRejectReason::aspect_ratio: ++metrics_.rejected_aspect_ratio; break;
    case GeometryRejectReason::none: break;
  }
}

bool MobileControlCore::build_candidates(
    std::span<const YoloDetection> detections, std::uint64_t sequence,
    std::uint64_t observed_at_us) {
  candidates_.clear();
  validated_detections_.clear();
  if (validated_detections_.capacity() < detections.size()) {
    validated_detections_.reserve(detections.size());
  }
  if (candidates_.capacity() < detections.size()) {
    candidates_.reserve(detections.size());
  }
  for (const auto& detection : detections) {
    const GeometryRejectReason reason = geometry_reject_reason(detection);
    if (reason != GeometryRejectReason::none) {
      count_geometry_rejection(reason);
      continue;
    }
    validated_detections_.push_back(detection);
  }

  const bool ego_motion_response_pending =
      apply_pending_visible_ego_motion(sequence, observed_at_us);

  tracker_.update_into(
      validated_detections_, sequence, observed_at_us,
      tracked_detections_);
  const std::span<const TrackedDetection> tracked = tracked_detections_;
  if (!config_.selected_class_uses_head_box) {
    const AimSource source = config_.selected_class_uses_geometric_head
        ? AimSource::geometric_head : AimSource::selected_class;
    for (const TrackedDetection& detection : tracked) {
      if (detection.detection.class_id != config_.selected_class_id) continue;
      if (body_fallback_admissible(detection)) {
        candidates_.push_back(candidate_for(detection, source));
      } else {
        ++metrics_.rejected_body_fallbacks;
      }
    }
    remember_candidate_tracks();
    return ego_motion_response_pending;
  }
  pair_options_.clear();
  for (std::size_t head_index = 0; head_index < tracked.size(); ++head_index) {
    if (!config_.head_body_pairing_enabled ||
        tracked[head_index].detection.class_id != config_.selected_class_id) continue;
    for (std::size_t body_index = 0; body_index < tracked.size(); ++body_index) {
      if (tracked[body_index].detection.class_id != config_.body_class_id) continue;
      if (!head_body_pair_admissible(
              tracked[head_index].detection, tracked[body_index].detection)) continue;
      pair_options_.push_back({
          head_index,
          body_index,
          head_body_pair_score(tracked[head_index].detection, tracked[body_index].detection),
      });
    }
  }
  std::sort(pair_options_.begin(), pair_options_.end(), [](const PairOption& left, const PairOption& right) {
    if (left.score != right.score) return left.score > right.score;
    if (left.head_index != right.head_index) return left.head_index < right.head_index;
    return left.body_index < right.body_index;
  });
  paired_body_for_head_.assign(tracked.size(), tracked.size());
  paired_bodies_.assign(tracked.size(), 0U);
  for (const PairOption& option : pair_options_) {
    if (paired_body_for_head_[option.head_index] != tracked.size() ||
        paired_bodies_[option.body_index]) {
      continue;
    }
    paired_body_for_head_[option.head_index] = option.body_index;
    paired_bodies_[option.body_index] = 1U;
  }

  for (std::size_t index = 0; index < tracked.size(); ++index) {
    const TrackedDetection& detection = tracked[index];
    if (detection.detection.class_id == config_.selected_class_id) {
      const std::size_t body_index = paired_body_for_head_[index];
      if (body_index != tracked.size()) {
        const Candidate paired = candidate_for(detection, AimSource::head, &tracked[body_index]);
        if (paired.track_id != 0) {
          candidates_.push_back(paired);
          ++metrics_.paired_heads;
          continue;
        }
      }
      if (head_only_admissible(detection)) {
        candidates_.push_back(candidate_for(detection, AimSource::head));
        ++metrics_.head_only_acceptances;
      } else {
        ++metrics_.rejected_unvalidated_heads;
      }
      continue;
    }
    if (detection.detection.class_id == config_.body_class_id) {
      if (body_fallback_admissible(detection)) {
        candidates_.push_back(candidate_for(detection, AimSource::body_fallback));
      } else {
        ++metrics_.rejected_body_fallbacks;
      }
    }
  }
  remember_candidate_tracks();
  return ego_motion_response_pending;
}

MobileControlCore::Candidate MobileControlCore::candidate_for(
    const TrackedDetection& tracked, AimSource source,
    const TrackedDetection* paired_body) const noexcept {
  const YoloDetection& detection = tracked.detection;
  Candidate candidate{
      .detection = detection,
      .source = source,
      .track_id = tracked.track_id,
      .observation_track_id = tracked.track_id,
  };
  if (paired_body != nullptr) {
    candidate.paired_body = paired_body->detection;
    // The body track is the cross-class identity anchor; head confidence can
    // legitimately cross the track-creation threshold between adjacent frames.
    candidate.track_id = paired_body->track_id != 0 ? paired_body->track_id : tracked.track_id;
    candidate.has_body_pair = true;
  }
  candidate.track_was_known = candidate.track_id != 0 &&
      candidate.track_id <= known_track_id_ceiling_;
  const float width = detection.x2 - detection.x1;
  const float height = detection.y2 - detection.y1;
  if (source == AimSource::head) {
    const float inset_x = std::min(width * 0.45F,
        std::max(config_.head_safe_inset_min_pixels, width * config_.head_safe_inset_fraction));
    const float inset_y = std::min(height * 0.45F,
        std::max(config_.head_safe_inset_min_pixels, height * config_.head_safe_inset_fraction));
    const float anchor_x = detection.x1 + width * config_.head_anchor_x_ratio;
    const float anchor_y = detection.y1 + height * config_.head_anchor_y_ratio;
    candidate.anchor_x = anchor_x;
    candidate.anchor_y = anchor_y;
    candidate.target_x = std::clamp(anchor_x, detection.x1 + inset_x, detection.x2 - inset_x);
    candidate.target_y = std::clamp(anchor_y, detection.y1 + inset_y, detection.y2 - inset_y);
    candidate.safe_radius_pixels = std::max(0.0F, std::min({
        candidate.target_x - detection.x1,
        detection.x2 - candidate.target_x,
        candidate.target_y - detection.y1,
        detection.y2 - candidate.target_y,
    }));
  } else {
    candidate.target_x = detection.x1 + width * 0.5F;
    candidate.target_y = detection.y1 + height * config_.body_fallback_y_ratio;
    candidate.anchor_x = candidate.target_x;
    candidate.anchor_y = candidate.target_y;
    candidate.safe_radius_pixels = std::max(0.0F, std::min({
        candidate.target_x - detection.x1,
        detection.x2 - candidate.target_x,
        candidate.target_y - detection.y1,
        detection.y2 - candidate.target_y,
    }));
    if (source == AimSource::geometric_head) {
      candidate.safe_radius_pixels = std::min(
          candidate.safe_radius_pixels,
          config_.geometric_head_control_radius_pixels);
    }
  }
  return candidate;
}

bool MobileControlCore::head_body_pair_admissible(
    const YoloDetection& head, const YoloDetection& body) const noexcept {
  if (body.confidence < config_.paired_body_min_confidence) return false;
  const float head_width = head.x2 - head.x1;
  const float head_height = head.y2 - head.y1;
  const float body_width = body.x2 - body.x1;
  const float body_height = body.y2 - body.y1;
  const float head_center_x = (head.x1 + head.x2) * 0.5F;
  const float head_center_y = (head.y1 + head.y2) * 0.5F;
  const float expand_x = body_width * config_.pair_body_expand_width_ratio;
  const float expand_y = body_height * config_.pair_body_expand_height_ratio;
  if (head_center_x < body.x1 - expand_x || head_center_x > body.x2 + expand_x ||
      head_center_y < body.y1 - expand_y || head_center_y > body.y2 + expand_y) return false;
  const float relative_y = (head_center_y - body.y1) / std::max(body_height, 1.0e-6F);
  if (relative_y > config_.pair_head_upper_body_ratio ||
      body.y2 - head_center_y < config_.pair_min_body_pixels_below_head) return false;
  const float area_ratio = (head_width * head_height) /
      std::max(body_width * body_height, 1.0e-6F);
  const float width_ratio = head_width / std::max(body_width, 1.0e-6F);
  const float height_ratio = head_height / std::max(body_height, 1.0e-6F);
  return area_ratio >= config_.pair_min_head_body_area_ratio &&
      area_ratio <= config_.pair_max_head_body_area_ratio &&
      width_ratio >= config_.pair_min_head_body_width_ratio &&
      width_ratio <= config_.pair_max_head_body_width_ratio &&
      height_ratio >= config_.pair_min_head_body_height_ratio &&
      height_ratio <= config_.pair_max_head_body_height_ratio;
}

float MobileControlCore::head_body_pair_score(
    const YoloDetection& head, const YoloDetection& body) const noexcept {
  const float head_center_x = (head.x1 + head.x2) * 0.5F;
  const float head_center_y = (head.y1 + head.y2) * 0.5F;
  const float body_center_x = (body.x1 + body.x2) * 0.5F;
  const float expected_head_y = body.y1 + (body.y2 - body.y1) * 0.18F;
  const float distance = std::sqrt(squared_distance(
      head_center_x, head_center_y, body_center_x, expected_head_y));
  // Geometry is the identity authority.  Confidence has already passed the
  // admissibility gate and may only break an effectively equal-distance tie;
  // otherwise a clear but neighbouring body can steal this head's track id.
  const float confidence_tie_break =
      (head.confidence * 0.55F + body.confidence * 0.45F) *
      kPairConfidenceTieBreakScale;
  return -distance + confidence_tie_break;
}

bool MobileControlCore::head_only_admissible(const TrackedDetection& head) const noexcept {
  if (head.track_id == 0 || head.detection.confidence < config_.head_only_min_confidence) return false;
  const float head_center_x = (head.detection.x1 + head.detection.x2) * 0.5F;
  const float head_center_y = (head.detection.y1 + head.detection.y2) * 0.5F;
  const float maximum_distance_squared = config_.head_only_max_center_distance_pixels *
      config_.head_only_max_center_distance_pixels;
  return squared_distance(
      head_center_x, head_center_y, config_.model_center_x, config_.model_center_y) <=
      maximum_distance_squared;
}

bool MobileControlCore::body_fallback_admissible(const TrackedDetection& body) const noexcept {
  if (body.track_id == 0 || body.detection.confidence < config_.body_fallback_min_confidence) return false;
  const float body_width = body.detection.x2 - body.detection.x1;
  const float body_height = body.detection.y2 - body.detection.y1;
  const float target_x = body.detection.x1 + body_width * 0.5F;
  const float target_y = body.detection.y1 + body_height * config_.body_fallback_y_ratio;
  const float maximum_distance_squared = config_.body_fallback_max_center_distance_pixels *
      config_.body_fallback_max_center_distance_pixels;
  return squared_distance(target_x, target_y, config_.model_center_x, config_.model_center_y) <=
      maximum_distance_squared;
}

bool MobileControlCore::better_rank(const Candidate& left, const Candidate& right) const noexcept {
  if (left.source == AimSource::head && right.source == AimSource::head &&
      left.has_body_pair != right.has_body_pair) return left.has_body_pair;
  const float left_distance = squared_distance(
      left.target_x, left.target_y, config_.model_center_x, config_.model_center_y);
  const float right_distance = squared_distance(
      right.target_x, right.target_y, config_.model_center_x, config_.model_center_y);
  const float inverse_center_scale =
      1.0F / config_.candidate_center_scale_pixels;
  const float left_score =
      left.detection.confidence * config_.candidate_confidence_weight -
      std::sqrt(left_distance) * inverse_center_scale *
          config_.candidate_center_weight;
  const float right_score =
      right.detection.confidence * config_.candidate_confidence_weight -
      std::sqrt(right_distance) * inverse_center_scale *
          config_.candidate_center_weight;
  if (left_score != right_score) return left_score > right_score;
  if (left.detection.confidence != right.detection.confidence) {
    return left.detection.confidence > right.detection.confidence;
  }
  if (left_distance != right_distance) return left_distance < right_distance;
  return box_area(left.detection) > box_area(right.detection);
}

bool MobileControlCore::choose_best(Candidate& result) const noexcept {
  Candidate best_head{};
  Candidate best_body{};
  bool found_head = false;
  bool found_body = false;
  for (const Candidate& candidate : candidates_) {
    bool& found = candidate.source == AimSource::head ? found_head : found_body;
    Candidate& best = candidate.source == AimSource::head ? best_head : best_body;
    if (!found || better_rank(candidate, best)) best = candidate;
    found = true;
  }
  if (found_head) {
    result = best_head;
    return true;
  }
  if (found_body) {
    result = best_body;
    return true;
  }
  return false;
}

bool MobileControlCore::choose_locked_target_head_upgrade(
    Candidate& result) const noexcept {
  if (!has_lock_ ||
      locked_candidate_.source != AimSource::body_fallback ||
      locked_candidate_.track_id == 0U) {
    return false;
  }
  bool found = false;
  for (const Candidate& candidate : candidates_) {
    // A paired head inherits its body track id.  Only that exact identity may
    // bypass normal lock persistence; an unrelated head elsewhere in a crowd
    // must never steal a still-visible body lock in one frame.
    if (candidate.source != AimSource::head ||
        !candidate.has_body_pair ||
        candidate.track_id != locked_candidate_.track_id) {
      continue;
    }
    if (!found || better_rank(candidate, result)) result = candidate;
    found = true;
  }
  return found;
}

bool MobileControlCore::choose_locked_head_body_projection(
    Candidate& result) noexcept {
  if (!has_lock_ || locked_candidate_.source != AimSource::head ||
      !locked_candidate_.has_body_pair ||
      locked_candidate_.track_id == 0U) {
    return false;
  }

  for (const Candidate& candidate : candidates_) {
    if (candidate.source != AimSource::body_fallback ||
        candidate.track_id != locked_candidate_.track_id) {
      continue;
    }

    const YoloDetection& previous_body = locked_candidate_.paired_body;
    const YoloDetection& current_body = candidate.detection;
    if (!box_size_compatible(
            previous_body, current_body,
            config_.track_id_rebind_min_size_ratio,
            config_.track_id_rebind_max_size_ratio)) {
      ++metrics_.rejected_head_body_projection_geometry;
      return false;
    }

    const float previous_center_x =
        (previous_body.x1 + previous_body.x2) * 0.5F;
    const float previous_center_y =
        (previous_body.y1 + previous_body.y2) * 0.5F;
    const float current_center_x =
        (current_body.x1 + current_body.x2) * 0.5F;
    const float current_center_y =
        (current_body.y1 + current_body.y2) * 0.5F;
    const float maximum_distance_squared =
        config_.lock_match_max_distance_pixels *
        config_.lock_match_max_distance_pixels;
    const bool center_match = squared_distance(
        previous_center_x, previous_center_y,
        current_center_x, current_center_y) <= maximum_distance_squared;
    const bool iou_match = intersection_over_union(
        previous_body, current_body) >= config_.lock_match_min_iou;
    const bool giou_match = generalized_intersection_over_union(
        previous_body, current_body) >= config_.lock_match_min_giou;
    if (!center_match && !iou_match && !giou_match) {
      ++metrics_.rejected_head_body_projection_geometry;
      return false;
    }

    const float previous_width = previous_body.x2 - previous_body.x1;
    const float previous_height = previous_body.y2 - previous_body.y1;
    const float scale_x =
        (current_body.x2 - current_body.x1) / previous_width;
    const float scale_y =
        (current_body.y2 - current_body.y1) / previous_height;
    if (!std::isfinite(scale_x) || !std::isfinite(scale_y) ||
        scale_x <= 0.0F || scale_y <= 0.0F) {
      ++metrics_.rejected_head_body_projection_geometry;
      return false;
    }

    const auto project_x = [&](float value) {
      return current_body.x1 +
          (value - previous_body.x1) * scale_x;
    };
    const auto project_y = [&](float value) {
      return current_body.y1 +
          (value - previous_body.y1) * scale_y;
    };
    result = locked_candidate_;
    result.detection.x1 = project_x(locked_candidate_.detection.x1);
    result.detection.x2 = project_x(locked_candidate_.detection.x2);
    result.detection.y1 = project_y(locked_candidate_.detection.y1);
    result.detection.y2 = project_y(locked_candidate_.detection.y2);
    result.target_x = project_x(locked_candidate_.target_x);
    result.target_y = project_y(locked_candidate_.target_y);
    result.anchor_x = project_x(locked_candidate_.anchor_x);
    result.anchor_y = project_y(locked_candidate_.anchor_y);
    result.safe_radius_pixels = locked_candidate_.safe_radius_pixels *
        std::min(scale_x, scale_y);
    result.paired_body = current_body;
    result.track_id = candidate.track_id;
    result.track_was_known = true;
    result.head_from_body_projection = true;
    const bool projected_detection_valid =
        geometry_reject_reason(result.detection) == GeometryRejectReason::none;
    const bool projected_target_valid =
        std::isfinite(result.target_x) && std::isfinite(result.target_y) &&
        result.target_x >= 0.0F && result.target_x <= config_.model_width &&
        result.target_y >= 0.0F && result.target_y <= config_.model_height;
    if (!projected_detection_valid || !projected_target_valid) {
      ++metrics_.rejected_head_body_projection_geometry;
      return false;
    }
    return true;
  }
  return false;
}

bool MobileControlCore::is_head_projection_recovery(
    const Candidate& candidate) const noexcept {
  return has_lock_ && locked_candidate_.head_from_body_projection &&
      locked_candidate_.source == AimSource::head &&
      candidate.source == AimSource::head &&
      !candidate.head_from_body_projection &&
      same_candidate_identity(locked_candidate_, candidate);
}

bool MobileControlCore::missing_switch_admissible(
    const Candidate& candidate, bool count_rejection) noexcept {
  if (candidate.detection.confidence <
      config_.missing_switch_min_confidence) {
    if (count_rejection) ++metrics_.rejected_missing_switch_confidence;
    return false;
  }
  if (config_.missing_switch_max_jump_pixels <= 0.0F) return true;
  const float maximum_jump_squared =
      config_.missing_switch_max_jump_pixels *
      config_.missing_switch_max_jump_pixels;
  if (squared_distance(
          candidate.target_x, candidate.target_y,
          locked_candidate_.target_x, locked_candidate_.target_y) <=
      maximum_jump_squared) {
    return true;
  }
  if (count_rejection) ++metrics_.rejected_missing_switch_jump;
  return false;
}

bool MobileControlCore::choose_pending_switch(Candidate& result) noexcept {
  if (!has_pending_switch_) return false;
  bool found = false;
  for (const Candidate& candidate : candidates_) {
    if (!association_admissible(pending_candidate_, candidate) ||
        !missing_switch_admissible(candidate, false)) {
      continue;
    }
    if (!found || better_rank(candidate, result)) result = candidate;
    found = true;
  }
  return found;
}

bool MobileControlCore::choose_best_missing_switch(Candidate& result) noexcept {
  bool found = false;
  for (const Candidate& candidate : candidates_) {
    if (!missing_switch_admissible(candidate, true)) continue;
    if (!found || better_rank(candidate, result)) result = candidate;
    found = true;
  }
  return found;
}

bool MobileControlCore::association_admissible(
    const Candidate& left, const Candidate& right,
    bool* giou_only) const noexcept {
  if (giou_only != nullptr) *giou_only = false;
  if (left.source != right.source) return false;
  if (left.track_id != 0 && right.track_id != 0) {
    if (left.track_id != right.track_id &&
        !same_candidate_identity(left, right)) return false;
  }
  const float distance_squared = squared_distance(left.target_x, left.target_y, right.target_x, right.target_y);
  const float maximum_distance_squared =
      config_.lock_match_max_distance_pixels * config_.lock_match_max_distance_pixels;
  const float iou =
      intersection_over_union(left.detection, right.detection);
  const float giou =
      generalized_intersection_over_union(left.detection, right.detection);
  const bool distance_match = distance_squared <= maximum_distance_squared;
  const bool iou_match = iou >= config_.lock_match_min_iou;
  const bool giou_match = giou >= config_.lock_match_min_giou;
  if (giou_only != nullptr) {
    *giou_only = giou_match && !distance_match && !iou_match;
  }
  return distance_match || iou_match || giou_match;
}

bool MobileControlCore::same_candidate_identity(
    const Candidate& left, const Candidate& right) noexcept {
  if (left.source != right.source) return false;
  if (left.track_id != 0U && left.track_id == right.track_id) return true;
  // A paired head intentionally borrows the body track as its control anchor.
  // Pair loss/return must not hide the stable head track underneath it.
  return left.source == AimSource::head &&
      left.observation_track_id != 0U &&
      left.observation_track_id == right.observation_track_id;
}

bool MobileControlCore::track_id_rebind_admissible(
    const Candidate& candidate, bool* giou_only) const noexcept {
  if (giou_only != nullptr) *giou_only = false;
  if (!config_.track_id_rebind_enabled ||
      locked_candidate_.source != candidate.source ||
      locked_candidate_.track_id == 0 || candidate.track_id == 0 ||
      locked_candidate_.track_id == candidate.track_id ||
      candidate.track_was_known ||
      candidate.detection.confidence <
          config_.missing_switch_min_confidence) {
    return false;
  }
  const float distance_squared = squared_distance(
      locked_candidate_.target_x, locked_candidate_.target_y,
      candidate.target_x, candidate.target_y);
  const float maximum_distance_squared =
      config_.track_id_rebind_max_distance_pixels *
      config_.track_id_rebind_max_distance_pixels;
  if (distance_squared > maximum_distance_squared) return false;
  if (!box_size_compatible(
          locked_candidate_.detection, candidate.detection,
          config_.track_id_rebind_min_size_ratio,
          config_.track_id_rebind_max_size_ratio)) {
    return false;
  }
  const float iou = intersection_over_union(
      locked_candidate_.detection, candidate.detection);
  const float giou = generalized_intersection_over_union(
      locked_candidate_.detection, candidate.detection);
  bool body_match = false;
  if (locked_candidate_.has_body_pair && candidate.has_body_pair) {
    body_match =
        box_size_compatible(
            locked_candidate_.paired_body, candidate.paired_body,
            config_.track_id_rebind_min_size_ratio,
            config_.track_id_rebind_max_size_ratio) &&
        intersection_over_union(
            locked_candidate_.paired_body, candidate.paired_body) >=
            config_.track_id_rebind_min_body_iou;
  }
  const bool giou_match = giou >= config_.lock_match_min_giou;
  if (giou_only != nullptr) {
    *giou_only =
        giou_match && iou < config_.track_id_rebind_min_iou && !body_match;
  }
  return iou >= config_.track_id_rebind_min_iou || giou_match || body_match;
}

bool MobileControlCore::match_locked(Candidate& result) noexcept {
  bool found = false;
  float best_iou = -1.0F;
  float best_distance = std::numeric_limits<float>::max();
  const auto consider = [&](const Candidate& candidate) {
    const float iou = intersection_over_union(
        locked_candidate_.detection, candidate.detection);
    const float distance = squared_distance(
        locked_candidate_.target_x, locked_candidate_.target_y,
        candidate.target_x, candidate.target_y);
    if (!found || iou > best_iou ||
        (iou == best_iou && distance < best_distance) ||
        (iou == best_iou && distance == best_distance &&
         better_rank(candidate, result))) {
      result = candidate;
      best_iou = iou;
      best_distance = distance;
      found = true;
    }
  };

  if (locked_candidate_.track_id != 0) {
    for (const Candidate& candidate : candidates_) {
      if (candidate.source == locked_candidate_.source &&
          same_candidate_identity(locked_candidate_, candidate)) {
        if (!association_admissible(locked_candidate_, candidate)) {
          ++metrics_.rejected_exact_track_geometry;
          continue;
        }
        consider(candidate);
      }
    }
    if (found) {
      if (result.track_id == locked_candidate_.track_id) {
        ++metrics_.lock_exact_track_matches;
      } else {
        ++metrics_.lock_observation_track_matches;
      }
      return true;
    }
  }

  std::size_t different_track_candidates = 0;
  std::size_t admissible_rebind_candidates = 0;
  Candidate admissible_rebind{};
  bool admissible_rebind_giou_only = false;
  for (const Candidate& candidate : candidates_) {
    if (candidate.source == locked_candidate_.source &&
        locked_candidate_.track_id != 0 && candidate.track_id != 0 &&
        candidate.track_id != locked_candidate_.track_id) {
      ++different_track_candidates;
      bool giou_only = false;
      if (track_id_rebind_admissible(candidate, &giou_only)) {
        ++admissible_rebind_candidates;
        if (admissible_rebind_candidates == 1U) {
          admissible_rebind = candidate;
          admissible_rebind_giou_only = giou_only;
        }
      } else {
        ++metrics_.rejected_track_id_mismatches;
        if (candidate.track_was_known) {
          ++metrics_.rejected_known_track_rebinds;
        } else {
          ++metrics_.rejected_rebind_geometry;
        }
      }
    }
  }
  if (admissible_rebind_candidates >
      config_.track_id_rebind_max_candidates) {
    metrics_.rejected_track_id_mismatches += admissible_rebind_candidates;
    ++metrics_.rejected_ambiguous_rebinds;
    return false;
  }
  if (admissible_rebind_candidates == 1U) {
    result = admissible_rebind;
    ++metrics_.track_id_rebinds;
    if (admissible_rebind_giou_only) ++metrics_.lock_giou_matches;
    return true;
  }
  if (different_track_candidates != 0) {
    return false;
  }

  for (const Candidate& candidate : candidates_) {
    bool giou_only = false;
    if (!association_admissible(
            locked_candidate_, candidate, &giou_only)) continue;
    consider(candidate);
    if (giou_only) ++metrics_.lock_giou_matches;
  }
  if (found) ++metrics_.lock_geometric_matches;
  return found;
}

bool MobileControlCore::update_pending_switch(
    const Candidate& challenger, std::uint64_t observed_at_us) noexcept {
  if (!has_pending_switch_ || !association_admissible(pending_candidate_, challenger)) {
    pending_candidate_ = challenger;
    pending_switch_frames_ = 1;
    pending_switch_started_at_us_ = observed_at_us;
    has_pending_switch_ = true;
  } else {
    pending_candidate_ = challenger;
    ++pending_switch_frames_;
  }
  const bool enough_frames =
      pending_switch_frames_ >= config_.switch_confirmation_frames;
  const bool enough_time = config_.switch_confirmation_duration_us == 0U ||
      (observed_at_us >= pending_switch_started_at_us_ &&
       observed_at_us - pending_switch_started_at_us_ >=
           config_.switch_confirmation_duration_us);
  return enough_frames && enough_time;
}

void MobileControlCore::remember_candidate_tracks() {
  for (const Candidate& candidate : candidates_) {
    known_track_id_ceiling_ = std::max(
        known_track_id_ceiling_, candidate.track_id);
  }
}

void MobileControlCore::accept_candidate(
    const Candidate& candidate, const ControlFrameContext& frame, bool switched) noexcept {
  const bool starts_new_lock = !has_lock_ || switched;
  if (has_lock_ && !switched && last_target_observed_at_us_ != 0 &&
      frame.observed_at_us > last_target_observed_at_us_) {
    const float delta_seconds = static_cast<float>(frame.observed_at_us - last_target_observed_at_us_) / 1'000'000.0F;
    float target_displacement_x = candidate.target_x - locked_candidate_.target_x;
    float target_displacement_y = candidate.target_y - locked_candidate_.target_y;
    const float raw_velocity_x = target_displacement_x / delta_seconds;
    const float raw_velocity_y = target_displacement_y / delta_seconds;
    const float alpha = config_.velocity_update_alpha;
    velocity_x_ = clamp_magnitude(
        velocity_x_ * (1.0F - alpha) + raw_velocity_x * alpha,
        config_.maximum_velocity_pixels_per_second);
    velocity_y_ = clamp_magnitude(
        velocity_y_ * (1.0F - alpha) + raw_velocity_y * alpha,
        config_.maximum_velocity_pixels_per_second);
  } else {
    velocity_x_ = 0.0F;
    velocity_y_ = 0.0F;
    reset_motion();
  }
  if (!has_lock_ || switched) ++lock_id_;
  locked_candidate_ = candidate;
  has_lock_ = true;
  if (starts_new_lock) {
    known_track_id_ceiling_ = 0U;
    remember_candidate_tracks();
  }
  missing_frames_ = 0;
  last_target_observed_at_us_ = frame.observed_at_us;
  reacquisition_requires_confirmation_ = false;
  clear_pending_switch();
}

void MobileControlCore::accept_same_identity_head_upgrade(
    const Candidate& candidate,
    const ControlFrameContext& frame) noexcept {
  // A paired head borrows the already locked body's track id, so this changes
  // only the aim source, not the physical target.  Keep the lock id and motion
  // planner timeline intact.  Also retain the established target velocity:
  // the body-anchor -> head-anchor offset is policy geometry, not an object
  // displacement that should be divided by one frame's elapsed time.
  locked_candidate_ = candidate;
  missing_frames_ = 0U;
  last_target_observed_at_us_ = frame.observed_at_us;
  reacquisition_requires_confirmation_ = false;
  clear_pending_switch();
}

void MobileControlCore::accept_head_projection_recovery(
    const Candidate& candidate,
    const ControlFrameContext& frame) noexcept {
  // The synthetic head and the returning real head are two coordinate
  // estimates for one physical target.  Rebase planner history by their
  // difference, but preserve target velocity until a second real observation
  // measures it.  Dividing this correction by one frame interval otherwise
  // creates a fictitious reversal and an avoidable prediction kick.
  const float correction_x =
      candidate.target_x - locked_candidate_.target_x;
  const float correction_y =
      candidate.target_y - locked_candidate_.target_y;
  motion_planner_.apply_visible_error_shift(correction_x, correction_y);
  ++metrics_.head_body_projection_recoveries;
  metrics_.maximum_head_body_projection_recovery_pixels = std::max(
      metrics_.maximum_head_body_projection_recovery_pixels,
      std::hypot(correction_x, correction_y));
  locked_candidate_ = candidate;
  missing_frames_ = 0U;
  last_target_observed_at_us_ = frame.observed_at_us;
  reacquisition_requires_confirmation_ = false;
  clear_pending_switch();
}

bool MobileControlCore::refresh_locked_candidate(
    const ControlFrameContext& frame) noexcept {
  Candidate candidate{};
  if (choose_locked_target_head_upgrade(candidate)) {
    ++metrics_.head_preemptions;
    accept_same_identity_head_upgrade(candidate, frame);
    return true;
  }
  if (has_lock_ && match_locked(candidate)) {
    if (is_head_projection_recovery(candidate)) {
      accept_head_projection_recovery(candidate, frame);
    } else {
      accept_candidate(candidate, frame, false);
    }
    return true;
  }
  if (has_lock_ && choose_locked_head_body_projection(candidate)) {
    ++metrics_.head_body_projection_continuations;
    accept_candidate(candidate, frame, false);
    return true;
  }
  return false;
}

MobileControlOutput MobileControlCore::held_output(ControlSuppressionReason reason) const noexcept {
  return {
      .has_target = true,
      .held = true,
      .source = locked_candidate_.source,
      .suppression_reason = reason,
      .target_x = locked_candidate_.target_x,
      .target_y = locked_candidate_.target_y,
      .lock_id = lock_id_,
      .track_id = locked_candidate_.track_id,
  };
}

ControlSuppressionReason MobileControlCore::control_suppression_reason(
    MotionPlannerSuppressionReason reason) noexcept {
  switch (reason) {
    case MotionPlannerSuppressionReason::none:
      return ControlSuppressionReason::none;
    case MotionPlannerSuppressionReason::deadzone:
      return ControlSuppressionReason::deadzone;
    case MotionPlannerSuppressionReason::settle_guard:
      return ControlSuppressionReason::settle_guard;
    case MotionPlannerSuppressionReason::response_guard:
      return ControlSuppressionReason::response_guard;
    case MotionPlannerSuppressionReason::subcount_resolution:
      return ControlSuppressionReason::device_resolution_guard;
    case MotionPlannerSuppressionReason::direction_flip:
      return ControlSuppressionReason::direction_flip;
    case MotionPlannerSuppressionReason::invalid_input:
    case MotionPlannerSuppressionReason::invalid_time:
    case MotionPlannerSuppressionReason::stale_observation:
    case MotionPlannerSuppressionReason::non_monotonic_observation:
      return ControlSuppressionReason::motion_invalid;
  }
  return ControlSuppressionReason::motion_invalid;
}

MobileControlOutput MobileControlCore::active_output(
    const ControlFrameContext& frame, bool switched) noexcept {
  const float target_x = locked_candidate_.target_x;
  const float target_y = locked_candidate_.target_y;
  const YoloDetection& box = locked_candidate_.detection;
  float minimum_target_x = box.x1;
  float maximum_target_x = box.x2;
  float minimum_target_y = box.y1;
  float maximum_target_y = box.y2;
  if (locked_candidate_.source == AimSource::head) {
    const float width = box.x2 - box.x1;
    const float height = box.y2 - box.y1;
    const float inset_x = std::min(width * 0.45F,
        std::max(config_.head_safe_inset_min_pixels, width * config_.head_safe_inset_fraction));
    const float inset_y = std::min(height * 0.45F,
        std::max(config_.head_safe_inset_min_pixels, height * config_.head_safe_inset_fraction));
    minimum_target_x += inset_x;
    maximum_target_x -= inset_x;
    minimum_target_y += inset_y;
    maximum_target_y -= inset_y;
    const float maximum_lag_x = std::min(
        config_.head_max_anchor_lag_pixels,
        width * config_.head_max_anchor_lag_fraction);
    const float maximum_lag_y = std::min(
        config_.head_max_anchor_lag_pixels,
        height * config_.head_max_anchor_lag_fraction);
    minimum_target_x = std::max(
        minimum_target_x, locked_candidate_.anchor_x - maximum_lag_x);
    maximum_target_x = std::min(
        maximum_target_x, locked_candidate_.anchor_x + maximum_lag_x);
    minimum_target_y = std::max(
        minimum_target_y, locked_candidate_.anchor_y - maximum_lag_y);
    maximum_target_y = std::min(
        maximum_target_y, locked_candidate_.anchor_y + maximum_lag_y);
    if (minimum_target_x > maximum_target_x) {
      minimum_target_x = maximum_target_x = std::clamp(
          locked_candidate_.anchor_x, box.x1 + inset_x, box.x2 - inset_x);
    }
    if (minimum_target_y > maximum_target_y) {
      minimum_target_y = maximum_target_y = std::clamp(
          locked_candidate_.anchor_y, box.y1 + inset_y, box.y2 - inset_y);
    }
  }
  const float safe_radius = std::max(
      config_.motion.settle_minimum_radius_pixels,
      locked_candidate_.safe_radius_pixels);
  const MobileMotionPlannerOutput motion = motion_planner_.plan({
      .target_id = lock_id_,
      .observation_sequence = frame.sequence,
      .observed_at_us = frame.observed_at_us,
      .now_us = frame.now_us,
      .error_x = target_x - config_.model_center_x,
      .error_y = target_y - config_.model_center_y,
      .target_velocity_x_pixels_per_second = velocity_x_,
      .target_velocity_y_pixels_per_second = velocity_y_,
      .safe_radius_pixels = safe_radius,
      .prediction_bounds_enabled = true,
      .prediction_min_error_x = minimum_target_x - config_.model_center_x,
      .prediction_max_error_x = maximum_target_x - config_.model_center_x,
      .prediction_min_error_y = minimum_target_y - config_.model_center_y,
      .prediction_max_error_y = maximum_target_y - config_.model_center_y,
  });
  MobileControlOutput output{
      .has_target = true,
      .switched = switched,
      .source = locked_candidate_.source,
      .suppression_reason =
          control_suppression_reason(motion.suppression_reason),
      .target_x = target_x,
      .target_y = target_y,
      .delta_x = motion.delta_x,
      .delta_y = motion.delta_y,
      .lock_id = lock_id_,
      .track_id = locked_candidate_.track_id,
      .motion_phase = motion.phase,
      .motion_suppression_reason = motion.suppression_reason,
      .predicted_error_x = motion.predicted_error_x,
      .predicted_error_y = motion.predicted_error_y,
      .target_acceleration_x_pixels_per_second2 =
          motion.target_acceleration_x_pixels_per_second2,
      .target_acceleration_y_pixels_per_second2 =
          motion.target_acceleration_y_pixels_per_second2,
      .response_limited = motion.response_limited,
      .jerk_limited = motion.jerk_limited,
      .step_limited = motion.step_limited,
      .prediction_limited = motion.prediction_limited,
      .settle_stopped = motion.settle_stopped,
      .head_safe_radius_pixels =
          locked_candidate_.source == AimSource::head ||
                  locked_candidate_.source == AimSource::geometric_head
              ? safe_radius
              : 0.0F,
      .head_anchor_lag_x_pixels =
          locked_candidate_.source == AimSource::head ||
                  locked_candidate_.source == AimSource::geometric_head
          ? std::fabs(
                motion.predicted_error_x + config_.model_center_x -
                locked_candidate_.anchor_x)
          : 0.0F,
      .head_anchor_lag_y_pixels =
          locked_candidate_.source == AimSource::head ||
                  locked_candidate_.source == AimSource::geometric_head
          ? std::fabs(
                motion.predicted_error_y + config_.model_center_y -
                locked_candidate_.anchor_y)
          : 0.0F,
  };
  if (locked_candidate_.source == AimSource::head ||
      locked_candidate_.source == AimSource::geometric_head) {
    metrics_.last_head_safe_radius_pixels = safe_radius;
    metrics_.maximum_head_anchor_lag_pixels = std::max({
        metrics_.maximum_head_anchor_lag_pixels,
        output.head_anchor_lag_x_pixels,
        output.head_anchor_lag_y_pixels,
    });
    if (motion.prediction_limited) {
      ++metrics_.head_anchor_prediction_limits;
    }
  }
  if (motion.suppression_reason ==
          MotionPlannerSuppressionReason::settle_guard ||
      motion.suppression_reason ==
          MotionPlannerSuppressionReason::direction_flip) {
    ++metrics_.settle_suppressions;
  } else if (motion.suppression_reason ==
                 MotionPlannerSuppressionReason::invalid_input ||
             motion.suppression_reason ==
                 MotionPlannerSuppressionReason::invalid_time ||
             motion.suppression_reason ==
                 MotionPlannerSuppressionReason::stale_observation ||
             motion.suppression_reason ==
                 MotionPlannerSuppressionReason::non_monotonic_observation) {
    ++metrics_.motion_invalid_suppressions;
  }
  return output;
}

MobileControlOutput MobileControlCore::process(
    std::span<const YoloDetection> detections, const ControlFrameContext& frame) {
  const ControlSuppressionReason frame_reason = accept_frame_context(frame);
  if (frame_reason != ControlSuppressionReason::none) {
    return {.suppression_reason = frame_reason};
  }
  const bool ego_motion_response_pending = build_candidates(
      detections, frame.sequence, frame.observed_at_us);
  if (ego_motion_response_pending) {
    return held_output(ControlSuppressionReason::response_guard);
  }

  if (refresh_locked_candidate(frame)) {
    return active_output(frame, false);
  }
  Candidate candidate{};
  if (has_lock_ &&
      (choose_pending_switch(candidate) ||
       choose_best_missing_switch(candidate))) {
    ++missing_frames_;
    if (update_pending_switch(candidate, frame.observed_at_us)) {
      accept_candidate(candidate, frame, true);
      return active_output(frame, true);
    }
    ++metrics_.switch_pending_frames;
    return held_output(ControlSuppressionReason::switch_pending);
  }
  if (has_lock_) {
    const bool hold_by_time = config_.lost_target_hold_duration_us != 0U;
    const bool within_hold_window = hold_by_time
        ? frame.observed_at_us - last_target_observed_at_us_ <
            config_.lost_target_hold_duration_us
        : missing_frames_ < config_.lost_frame_hold_count;
    if (within_hold_window) {
      clear_pending_switch();
      ++missing_frames_;
      return held_output(ControlSuppressionReason::lock_held);
    }
    // A former lock changes the trust boundary.  Do not let the first far or
    // one-frame detection after expiry fall through to the startup acquisition
    // path and emit an unconfirmed camera yank.  Fresh-frame processing stays
    // uncapped; only stable observation time and identity confirm reacquisition.
    has_lock_ = false;
    reacquisition_requires_confirmation_ = true;
    missing_frames_ = 0;
    last_target_observed_at_us_ = 0;
    reset_motion();
  }
  if (choose_best(candidate)) {
    if (reacquisition_requires_confirmation_) {
      if (update_pending_switch(candidate, frame.observed_at_us)) {
        ++metrics_.reacquisition_confirmations;
        accept_candidate(candidate, frame, true);
        return active_output(frame, true);
      }
      ++metrics_.switch_pending_frames;
      ++metrics_.reacquisition_pending_frames;
      return {.suppression_reason = ControlSuppressionReason::switch_pending};
    }
    accept_candidate(candidate, frame, false);
    return active_output(frame, false);
  }
  clear_pending_switch();
  if (!detections.empty()) {
    ++metrics_.detected_not_control_eligible_frames;
    return {
        .suppression_reason =
            ControlSuppressionReason::detected_not_control_eligible,
    };
  }
  return {.suppression_reason = ControlSuppressionReason::no_valid_target};
}

ControlSuppressionReason MobileControlCore::observe_tracking_only(
    std::span<const YoloDetection> detections,
    const ControlFrameContext& frame) noexcept {
  const ControlSuppressionReason frame_reason = accept_frame_context(frame);
  if (frame_reason != ControlSuppressionReason::none) return frame_reason;
  const bool ego_motion_response_pending = build_candidates(
      detections, frame.sequence, frame.observed_at_us);
  ++metrics_.tracking_only_frames;
  if (ego_motion_response_pending) {
    return ControlSuppressionReason::response_guard;
  }
  if (refresh_locked_candidate(frame)) {
    ++metrics_.tracking_only_lock_updates;
  }
  return ControlSuppressionReason::none;
}

ControlSuppressionReason MobileControlCore::accept_frame_context(
    const ControlFrameContext& frame) noexcept {
  if (frame.sequence == 0 || frame.observed_at_us == 0 || frame.now_us == 0 ||
      frame.now_us < frame.observed_at_us ||
      (has_accepted_frame_ && frame.now_us < last_frame_now_us_)) {
    ++metrics_.invalid_time_frames;
    return ControlSuppressionReason::invalid_time;
  }
  if (frame.now_us - frame.observed_at_us > config_.maximum_frame_age_us) {
    ++metrics_.stale_frames;
    return ControlSuppressionReason::stale_frame;
  }
  if (has_accepted_frame_ &&
      (frame.sequence <= last_frame_sequence_ || frame.observed_at_us <= last_frame_observed_at_us_)) {
    ++metrics_.non_monotonic_frames;
    return ControlSuppressionReason::non_monotonic_frame;
  }
  has_accepted_frame_ = true;
  last_frame_sequence_ = frame.sequence;
  last_frame_observed_at_us_ = frame.observed_at_us;
  last_frame_now_us_ = frame.now_us;
  return ControlSuppressionReason::none;
}

void MobileControlCore::reset_motion() noexcept {
  motion_planner_.reset_motion();
}

void MobileControlCore::clear_pending_switch() noexcept {
  pending_candidate_ = {};
  has_pending_switch_ = false;
  pending_switch_frames_ = 0;
  pending_switch_started_at_us_ = 0;
}

void MobileControlCore::reset() noexcept {
  candidates_.clear();
  validated_detections_.clear();
  tracked_detections_.clear();
  pair_options_.clear();
  paired_body_for_head_.clear();
  paired_bodies_.clear();
  tracker_.reset();
  known_track_id_ceiling_ = 0U;
  locked_candidate_ = {};
  has_lock_ = false;
  reacquisition_requires_confirmation_ = false;
  has_accepted_frame_ = false;
  missing_frames_ = 0;
  last_frame_sequence_ = 0;
  last_frame_observed_at_us_ = 0;
  last_frame_now_us_ = 0;
  last_target_observed_at_us_ = 0;
  velocity_x_ = 0.0F;
  velocity_y_ = 0.0F;
  reset_motion();
  clear_pending_switch();
  pending_visible_delta_x_ = 0;
  pending_visible_delta_y_ = 0;
  pending_visible_started_at_us_ = 0U;
  has_pending_visible_ego_motion_ = false;
}

}  // namespace vfdual_android
