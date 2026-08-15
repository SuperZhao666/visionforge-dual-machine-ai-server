#include "MobileControlCore.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <limits>
#include <span>

namespace {

using vfdual_android::AimSource;
using vfdual_android::ControlFrameContext;
using vfdual_android::ControlSuppressionReason;
using vfdual_android::MobileControlConfig;
using vfdual_android::MobileControlCore;
using vfdual_android::MobileMotionPhase;
using vfdual_android::MobileMotionPlannerConfig;
using vfdual_android::YoloDetection;
using vfdual_android::apply_mobile_model_control_tuning;

YoloDetection box(float center_x, float center_y, float width, float height,
                  float confidence, std::uint32_t class_id) {
  return {center_x - width * 0.5F, center_y - height * 0.5F,
          center_x + width * 0.5F, center_y + height * 0.5F,
          confidence, class_id};
}

ControlFrameContext frame(std::uint64_t sequence, std::uint64_t observed_at_us,
                          std::uint64_t age_us = 0) {
  return {sequence, observed_at_us, observed_at_us + age_us};
}

MobileControlConfig algorithm_test_config() {
  MobileControlConfig config{};
  config.model_width = 320.0F;
  config.model_height = 320.0F;
  config.model_center_x = 160.0F;
  config.model_center_y = 160.0F;
  config.head_max_width = 96.0F;
  config.head_max_height = 96.0F;
  config.body_max_width = 220.0F;
  config.body_max_height = 318.0F;
  config.head_only_max_center_distance_pixels = 150.0F;
  config.body_fallback_max_center_distance_pixels = 130.0F;
  config.switch_confirmation_duration_us = 0U;
  return config;
}

MobileControlConfig cs2_t_head_config() {
  const auto& model = vfdual::kCounterStrike2Vombit416V8s;
  const vfdual::MobileAimTargetContract* target = nullptr;
  for (std::size_t index = 0; index < model.aim_target_count; ++index) {
    if (model.aim_targets[index].token == "t_head") {
      target = &model.aim_targets[index];
      break;
    }
  }
  assert(target != nullptr);

  MobileControlConfig config = algorithm_test_config();
  config.body_class_id = target->body_class_id;
  config.head_class_id = target->head_class_id;
  config.selected_class_id = target->selected_class_id;
  config.selected_class_uses_head_box = target->uses_head_box;
  config.selected_class_uses_geometric_head = target->uses_geometric_head;
  config.head_body_pairing_enabled = target->uses_head_box;
  config.body_fallback_y_ratio = target->target_y_ratio;
  config.model_width = static_cast<float>(model.input.width);
  config.model_height = static_cast<float>(model.input.height);
  config.model_center_x = config.model_width * 0.5F;
  config.model_center_y = config.model_height * 0.5F;
  config.tracker.high_confidence_threshold =
      model.tracking_confidence.high_confidence_threshold;
  config.tracker.low_confidence_threshold =
      model.tracking_confidence.low_confidence_threshold;
  config.tracker.new_track_confidence_threshold =
      model.tracking_confidence.new_track_confidence_threshold;
  config.head_confidence_threshold = 0.0F;
  config.body_confidence_threshold = 0.0F;
  config.paired_body_min_confidence = 0.0F;
  config.head_only_min_confidence = 0.0F;
  config.body_fallback_min_confidence = 0.0F;
  config.head_only_max_center_distance_pixels = config.model_width;
  config.body_fallback_max_center_distance_pixels = config.model_width;
  config.reject_border_touching = false;
  config.switch_confirmation_frames = 4;
  config.motion.prediction_horizon_ms = 0.0F;
  return config;
}

MobileControlConfig overwatch_enemy_body_config() {
  MobileControlConfig config = algorithm_test_config();
  config.head_class_id = vfdual::kNoModelClass;
  config.selected_class_id = 0U;
  config.selected_class_uses_head_box = false;
  config.selected_class_uses_geometric_head = true;
  config.head_body_pairing_enabled = false;
  config.body_fallback_y_ratio = 0.18F;
  config.motion.prediction_horizon_ms = 0.0F;
  return config;
}

MobileControlConfig production_overwatch_enemy_body_config() {
  const auto& model = vfdual::kOverwatch2Yolov5_416;
  MobileControlConfig config = overwatch_enemy_body_config();
  config.model_width = static_cast<float>(model.input.width);
  config.model_height = static_cast<float>(model.input.height);
  config.model_center_x = config.model_width * 0.5F;
  config.model_center_y = config.model_height * 0.5F;
  config.tracker.high_confidence_threshold =
      model.tracking_confidence.high_confidence_threshold;
  config.tracker.low_confidence_threshold =
      model.tracking_confidence.low_confidence_threshold;
  config.tracker.new_track_confidence_threshold =
      model.tracking_confidence.new_track_confidence_threshold;
  config.head_confidence_threshold = 0.0F;
  config.body_confidence_threshold = 0.0F;
  config.paired_body_min_confidence = 0.0F;
  config.head_only_min_confidence = 0.0F;
  config.body_fallback_min_confidence = 0.0F;
  config.body_fallback_max_center_distance_pixels = config.model_width;
  config.reject_border_touching = false;
  config.motion.response_gain = 0.60F;
  config.motion.prediction_horizon_ms =
      MobileMotionPlannerConfig{}.prediction_horizon_ms;
  config.switch_confirmation_duration_us = 45'000U;
  apply_mobile_model_control_tuning(model, config);
  return config;
}

void test_model_production_tuning_is_scoped() {
  MobileControlConfig valorant{};
  apply_mobile_model_control_tuning(
      vfdual::kValorantYellow416V11sNoFlash, valorant);
  assert(valorant.motion.uncalibrated_maximum_axis_delta == 12);
  assert(valorant.motion.maximum_step_counts_per_tick == 12.0F);
  assert(valorant.motion.maximum_jerk_counts_per_tick2 == 6.0F);
  assert(valorant.switch_confirmation_frames == 2);
  assert(valorant.switch_confirmation_duration_us == 20'000U);
  assert(valorant.lost_frame_hold_count == 2);
  assert(valorant.lost_target_hold_duration_us == 0U);
  assert(valorant.tracker.lost_track_duration_us == 100'000U);

  MobileControlConfig counter_strike{};
  counter_strike.switch_confirmation_duration_us = 25'000U;
  apply_mobile_model_control_tuning(
      vfdual::kCounterStrike2Vombit416V8s, counter_strike);
  assert(counter_strike.switch_confirmation_duration_us == 25'000U);
  assert(counter_strike.lost_target_hold_duration_us == 25'000U);
  assert(counter_strike.tracker.lost_track_duration_us == 100'000U);

  MobileControlConfig overwatch{};
  overwatch.switch_confirmation_duration_us = 37'000U;
  apply_mobile_model_control_tuning(vfdual::kOverwatch2Yolov5_416, overwatch);
  assert(overwatch.geometric_head_control_radius_pixels == 3.0F);
  assert(overwatch.motion.prediction_horizon_ms == 0.0F);
  assert(overwatch.motion.uncalibrated_maximum_axis_delta == 32);
  assert(overwatch.motion.maximum_step_counts_per_tick == 24.0F);
  assert(overwatch.motion.maximum_jerk_counts_per_tick2 == 12.0F);
  assert(overwatch.switch_confirmation_frames == 3);
  assert(overwatch.switch_confirmation_duration_us == 37'000U);
  assert(std::fabs(overwatch.missing_switch_min_confidence - 0.461F) < 0.0001F);
  assert(std::fabs(overwatch.missing_switch_max_jump_pixels - 57.0F) < 0.0001F);
  assert(overwatch.lost_frame_hold_count == 4);
  assert(overwatch.lost_target_hold_duration_us == 70'000U);
  assert(overwatch.tracker.lost_track_duration_us == 100'000U);
}

void test_default_production_model_contract() {
  const MobileControlConfig config{};
  assert(config.model_width == 416.0F && config.model_height == 416.0F);
  assert(config.model_center_x == 208.0F && config.model_center_y == 208.0F);
  assert(config.body_class_id == 0U && config.head_class_id == 1U);
  assert(config.head_only_max_center_distance_pixels == 195.0F);
  assert(config.body_fallback_max_center_distance_pixels == 169.0F);
}

void test_head_priority_body_fallback_and_safe_anchor() {
  MobileControlConfig config = algorithm_test_config();
  config.head_anchor_y_ratio = 0.0F;
  config.head_safe_inset_fraction = 0.20F;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);
  const std::array detections{
      box(180.0F, 180.0F, 40.0F, 100.0F, 0.99F, 0U),
      box(120.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto head = core.process(detections, frame(1, 1'000));
  assert(head.has_target && head.source == AimSource::head);
  assert(std::fabs(head.target_x - 120.0F) < 0.001F);
  assert(std::fabs(head.target_y - 94.0F) < 0.001F);

  core.reset();
  const std::array body_only{box(180.0F, 180.0F, 40.0F, 100.0F, 0.99F, 0U)};
  const auto body = core.process(body_only, frame(1, 2'000));
  assert(body.has_target && body.source == AimSource::body_fallback);
  assert(std::fabs(body.target_y - 148.0F) < 0.001F);
}

void test_initial_selection_balances_confidence_with_reticle_distance() {
  MobileControlConfig config = algorithm_test_config();
  config.head_only_min_confidence = 0.80F;
  config.motion.prediction_horizon_ms = 0.0F;
  config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore core(config);

  const std::array crowd{
      box(170.0F, 160.0F, 20.0F, 20.0F, 0.85F, 1U),
      box(270.0F, 160.0F, 20.0F, 20.0F, 0.99F, 1U),
  };
  const auto selected = core.process(crowd, frame(1, 10'000));

  assert(selected.has_target);
  assert(std::fabs(selected.target_x - 170.0F) < 0.001F);
}

void test_parameter_contract_rejects_invalid_anchor_and_rebind_limits() {
  MobileControlCore core(algorithm_test_config());
  MobileControlConfig invalid_anchor = algorithm_test_config();
  invalid_anchor.head_max_anchor_lag_fraction = 0.51F;
  assert(!core.configure(invalid_anchor));

  MobileControlConfig invalid_rebind = algorithm_test_config();
  invalid_rebind.track_id_rebind_max_candidates = 0;
  assert(!core.configure(invalid_rebind));

  MobileControlConfig invalid_switch_confirmation = algorithm_test_config();
  invalid_switch_confirmation.switch_confirmation_duration_us = 500'001U;
  assert(!core.configure(invalid_switch_confirmation));

  MobileControlConfig invalid_lost_target_hold = algorithm_test_config();
  invalid_lost_target_hold.lost_target_hold_duration_us = 500'001U;
  assert(!core.configure(invalid_lost_target_hold));

  MobileControlConfig invalid_measured_response = algorithm_test_config();
  invalid_measured_response.measured_ego_motion_maximum_px_per_count = 32.01F;
  assert(!core.configure(invalid_measured_response));

  MobileControlConfig invalid_candidate_scale = algorithm_test_config();
  invalid_candidate_scale.candidate_center_scale_pixels = 0.0F;
  assert(!core.configure(invalid_candidate_scale));
}

void test_unrelated_head_cannot_preempt_visible_body_lock() {
  MobileControlConfig config = algorithm_test_config();
  config.switch_confirmation_frames = 4;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);
  const std::array body_only{box(100.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U)};
  const auto body = core.process(body_only, frame(1, 10'000));
  const std::array body_and_head{
      box(101.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
      box(250.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto head = core.process(body_and_head, frame(2, 20'000));
  assert(body.source == AimSource::body_fallback);
  assert(head.source == AimSource::body_fallback);
  assert(!head.switched && !head.held);
  assert(head.lock_id == body.lock_id);
  assert(core.metrics().head_preemptions == 0);
}

void test_same_target_paired_head_immediately_upgrades_body_lock() {
  MobileControlConfig config = algorithm_test_config();
  config.switch_confirmation_frames = 4;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);
  const std::array body_only{
      box(180.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U)};
  const auto body = core.process(body_only, frame(1, 10'000));
  const std::array body_and_paired_head{
      box(181.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
      box(181.0F, 145.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto head = core.process(
      body_and_paired_head, frame(2, 20'000));

  assert(body.source == AimSource::body_fallback);
  assert(head.source == AimSource::head && !head.switched && !head.held);
  assert(head.lock_id == body.lock_id);
  assert(head.track_id == body.track_id);
  assert(core.metrics().head_preemptions == 1);
}

void test_same_target_head_upgrade_keeps_pursuit_motion_state() {
  MobileControlConfig config = algorithm_test_config();
  config.switch_confirmation_frames = 4;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);
  const std::array body_only{
      box(260.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U)};

  const auto acquired = core.process(body_only, frame(1, 10'000U));
  static_cast<void>(core.process(body_only, frame(2, 80'000U)));
  const auto pursuing = core.process(body_only, frame(3, 140'000U));
  assert(acquired.has_target && pursuing.has_target);
  assert(pursuing.motion_phase == MobileMotionPhase::pursuit);

  const std::array body_and_paired_head{
      box(261.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
      box(261.0F, 125.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto upgraded = core.process(
      body_and_paired_head, frame(4, 150'000U));

  assert(upgraded.has_target && upgraded.source == AimSource::head);
  assert(!upgraded.switched && !upgraded.held);
  assert(upgraded.lock_id == acquired.lock_id);
  assert(upgraded.track_id == acquired.track_id);
  assert(upgraded.motion_phase == MobileMotionPhase::pursuit);
}

void test_cs2_t_head_contract_rejects_ct_and_preserves_t_identity() {
  MobileControlCore core(cs2_t_head_config());
  const std::array body_only{
      // The unsupported CT target is closer and more confident, so accepting
      // it would expose a faction/class-contract leak immediately.
      box(208.0F, 200.0F, 44.0F, 100.0F, 0.99F, 0U),
      box(280.0F, 200.0F, 44.0F, 100.0F, 0.90F, 2U)};

  const auto body = core.process(body_only, frame(1, 10'000U));
  assert(body.has_target && body.source == AimSource::body_fallback);
  assert(!body.switched);

  const std::array paired_head{
      box(208.0F, 200.0F, 44.0F, 100.0F, 0.99F, 0U),
      box(208.0F, 158.0F, 20.0F, 20.0F, 0.99F, 1U),
      box(280.0F, 200.0F, 44.0F, 100.0F, 0.90F, 2U),
      box(280.0F, 158.0F, 20.0F, 20.0F, 0.88F, 3U)};
  const auto head = core.process(paired_head, frame(2, 20'000U));

  assert(head.has_target && head.source == AimSource::head);
  assert(!head.switched && !head.held);
  assert(head.lock_id == body.lock_id);
  assert(head.track_id == body.track_id);
  assert(core.metrics().rejected_unsupported_class == 3U);
}

void test_paired_head_identity_survives_body_pair_dropout_and_return() {
  MobileControlConfig config = algorithm_test_config();
  config.switch_confirmation_frames = 4;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);

  const std::array paired{
      box(180.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
      box(180.0F, 145.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto acquired = core.process(paired, frame(1, 10'000));
  assert(acquired.has_target && acquired.source == AimSource::head);

  const std::array head_only{
      box(181.0F, 145.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto dropout = core.process(head_only, frame(2, 20'000));
  assert(dropout.has_target && !dropout.held && !dropout.switched);
  assert(dropout.lock_id == acquired.lock_id);

  const std::array paired_again{
      box(182.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
      box(182.0F, 145.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto restored = core.process(paired_again, frame(3, 30'000));
  assert(restored.has_target && !restored.held && !restored.switched);
  assert(restored.lock_id == acquired.lock_id);
  assert(core.metrics().lock_observation_track_matches == 2U);
}

void test_paired_head_dropout_follows_same_body_without_switching_target() {
  MobileControlConfig config = algorithm_test_config();
  config.switch_confirmation_frames = 2;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);

  const std::array paired{
      box(180.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
      box(180.0F, 145.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto acquired = core.process(paired, frame(1, 10'000U));
  assert(acquired.has_target && acquired.source == AimSource::head);

  // A detector can miss the small head box for one fresh frame while the
  // paired body track remains exact and moves normally.  This is still the
  // same physical target: do not enter switch-pending or jump to body centre.
  const std::array body_only{
      box(184.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
  };
  const auto continued = core.process(body_only, frame(2, 20'000U));
  assert(continued.has_target && continued.source == AimSource::head);
  assert(!continued.held && !continued.switched);
  assert(continued.lock_id == acquired.lock_id);
  assert(continued.track_id == acquired.track_id);
  assert(continued.target_x > acquired.target_x);
  assert(std::fabs(continued.target_y - acquired.target_y) < 0.25F);
  assert(core.metrics().head_body_projection_continuations == 1U);
  assert(core.metrics().rejected_head_body_projection_geometry == 0U);
  assert(core.metrics().switch_pending_frames == 0U);

  const std::array paired_again{
      box(188.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
      box(188.0F, 145.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto restored = core.process(paired_again, frame(3, 30'000U));
  assert(restored.has_target && restored.source == AimSource::head);
  assert(!restored.held && !restored.switched);
  assert(restored.lock_id == acquired.lock_id);
  assert(restored.track_id == acquired.track_id);
}

void test_paired_head_projection_survives_multiframe_motion_and_scale() {
  MobileControlConfig config = algorithm_test_config();
  config.switch_confirmation_frames = 2;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);

  const std::array paired{
      box(170.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
      box(170.0F, 145.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto acquired = core.process(paired, frame(1, 10'000U));
  assert(acquired.has_target && acquired.source == AimSource::head);

  struct BodyObservation {
    float center_x;
    float center_y;
    float width;
    float height;
  };
  const std::array body_path{
      BodyObservation{174.0F, 181.0F, 52.0F, 104.0F},
      BodyObservation{180.0F, 182.0F, 55.0F, 108.0F},
      BodyObservation{187.0F, 184.0F, 58.0F, 112.0F},
  };

  std::uint64_t sequence = 2U;
  float previous_target_x = acquired.target_x;
  for (const BodyObservation& observation : body_path) {
    const std::array body_only{box(
        observation.center_x, observation.center_y,
        observation.width, observation.height, 0.99F, 0U)};
    const auto continued = core.process(
        body_only, frame(sequence, sequence * 10'000U));
    const float body_top = observation.center_y - observation.height * 0.5F;
    const float expected_projected_head_y = body_top + observation.height * 0.15F;
    const float body_fallback_y =
        body_top + observation.height * config.body_fallback_y_ratio;

    assert(continued.has_target && continued.source == AimSource::head);
    assert(!continued.held && !continued.switched);
    assert(continued.suppression_reason !=
           ControlSuppressionReason::switch_pending);
    assert(continued.lock_id == acquired.lock_id);
    assert(continued.track_id == acquired.track_id);
    assert(continued.target_x > previous_target_x);
    assert(continued.target_x <= observation.center_x + 0.25F);
    assert(std::fabs(continued.target_x - observation.center_x) < 1.50F);
    assert(std::fabs(continued.target_y - expected_projected_head_y) < 0.25F);
    assert(std::fabs(continued.target_y - body_fallback_y) > 2.0F);
    previous_target_x = continued.target_x;
    ++sequence;
  }

  const std::array paired_again{
      box(187.0F, 184.0F, 58.0F, 112.0F, 0.99F, 0U),
      box(187.0F, 145.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto restored = core.process(
      paired_again, frame(sequence, sequence * 10'000U));
  assert(restored.has_target && restored.source == AimSource::head);
  assert(!restored.held && !restored.switched);
  assert(restored.lock_id == acquired.lock_id);
  assert(restored.track_id == acquired.track_id);
  assert(std::fabs(restored.target_y - 145.0F) < 0.25F);
  assert(core.metrics().head_body_projection_continuations == body_path.size());
  assert(core.metrics().rejected_head_body_projection_geometry == 0U);
  assert(core.metrics().switch_pending_frames == 0U);
}

void test_real_head_recovery_does_not_invent_reverse_velocity() {
  MobileControlConfig config = algorithm_test_config();
  config.tracker.control_smoothing_alpha = 1.0F;
  config.tracker.control_smoothing_bypass_delta_pixels = 1.0F;
  config.velocity_update_alpha = 1.0F;
  config.motion.prediction_horizon_ms = 32.0F;
  config.motion.maximum_prediction_pixels = 22.0F;
  config.motion.acceleration_update_alpha = 1.0F;
  MobileControlCore core(config);

  const std::array paired{
      box(220.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
      box(220.0F, 145.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto acquired = core.process(paired, frame(1, 10'000U));
  assert(acquired.has_target && acquired.source == AimSource::head);

  const std::array body_only{
      box(224.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
  };
  const auto projected = core.process(body_only, frame(2, 20'000U));
  assert(projected.has_target && projected.source == AimSource::head);
  assert(projected.target_x > acquired.target_x);

  // The paired body keeps moving right, while the returning detector head is
  // a valid same-person observation slightly left of the synthetic estimate.
  // Replacing an estimate with real evidence is a coordinate correction, not
  // proof that the target reversed at 1,000 model pixels per second.
  const std::array paired_again{
      box(228.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
      box(214.0F, 145.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto restored = core.process(
      paired_again, frame(3, 30'000U));
  const float observed_error_x = restored.target_x - config.model_center_x;

  assert(restored.has_target && restored.source == AimSource::head);
  assert(!restored.held && !restored.switched);
  assert(restored.lock_id == acquired.lock_id);
  assert(restored.track_id == acquired.track_id);
  assert(restored.target_acceleration_x_pixels_per_second2 >= 0.0F);
  assert(restored.predicted_error_x >= observed_error_x);
  assert(core.metrics().head_body_projection_recoveries == 1U);
  assert(std::fabs(
      core.metrics().maximum_head_body_projection_recovery_pixels - 10.0F) <
      0.001F);
}

void test_paired_head_projection_rejects_implausible_body_jump() {
  MobileControlConfig config = algorithm_test_config();
  // Let the tracker retain its body id across an intentionally implausible
  // observation so this test exercises the stricter control-lock boundary.
  config.tracker.maximum_center_distance_pixels = 300.0F;
  config.switch_confirmation_frames = 4;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);

  const std::array paired{
      box(100.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
      box(100.0F, 145.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto acquired = core.process(paired, frame(1, 10'000U));
  assert(acquired.has_target && acquired.source == AimSource::head);

  const std::array implausible_body{
      box(250.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
  };
  const auto rejected = core.process(
      implausible_body, frame(2, 20'000U));
  assert(rejected.has_target && rejected.held && !rejected.switched);
  assert(rejected.suppression_reason ==
         ControlSuppressionReason::switch_pending);
  assert(rejected.lock_id == acquired.lock_id);
  assert(core.metrics().head_body_projection_continuations == 0U);
  assert(core.metrics().rejected_head_body_projection_geometry == 1U);
}

void test_paired_head_projection_rejects_out_of_bounds_head_box() {
  MobileControlConfig config = algorithm_test_config();
  config.body_fallback_max_center_distance_pixels = 200.0F;
  config.switch_confirmation_frames = 4;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);

  const std::array paired{
      box(160.0F, 70.0F, 50.0F, 80.0F, 0.99F, 0U),
      box(160.0F, 30.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto acquired = core.process(paired, frame(1, 10'000U));
  assert(acquired.has_target && acquired.source == AimSource::head);

  // The body remains a valid exact track, and the projected head target point
  // would still be y=2.  Its full box would span y=-8..12, however, so the
  // synthetic observation must obey the same model bounds as a real head box.
  const std::array edge_body{
      box(160.0F, 42.0F, 50.0F, 80.0F, 0.99F, 0U),
  };
  const auto rejected = core.process(edge_body, frame(2, 20'000U));
  assert(rejected.has_target && rejected.held && !rejected.switched);
  assert(rejected.suppression_reason ==
         ControlSuppressionReason::switch_pending);
  assert(rejected.lock_id == acquired.lock_id);
  assert(core.metrics().head_body_projection_continuations == 0U);
  assert(core.metrics().rejected_head_body_projection_geometry == 1U);
  assert(core.metrics().rejected_out_of_bounds == 0U);
}

void test_cs2_dropout_hold_uses_time_not_fresh_frame_count() {
  MobileControlConfig config = cs2_t_head_config();
  config.switch_confirmation_duration_us = 25'000U;
  apply_mobile_model_control_tuning(
      vfdual::kCounterStrike2Vombit416V8s, config);
  const std::array paired{
      box(208.0F, 220.0F, 44.0F, 100.0F, 0.99F, 2U),
      box(208.0F, 178.0F, 20.0F, 20.0F, 0.90F, 3U),
  };

  const auto verify_timing = [&](std::span<const std::uint64_t> missing_times) {
    MobileControlCore core(config);
    const auto locked = core.process(paired, frame(1U, 10'000U));
    assert(locked.has_target && locked.source == AimSource::head);
    std::uint64_t sequence = 2U;
    for (const std::uint64_t observed_at_us : missing_times) {
      const auto held = core.process({}, frame(sequence++, observed_at_us));
      assert(held.has_target && held.held && !held.has_move());
      assert(held.lock_id == locked.lock_id);
    }
    const auto expired = core.process({}, frame(sequence, 35'000U));
    assert(!expired.has_target && !expired.has_move());
    assert(expired.suppression_reason ==
           ControlSuppressionReason::no_valid_target);
  };

  // Both streams represent the same 25 ms absence.  A frame-count hold drops
  // the high-FPS lock at 15 ms while retaining the low-FPS lock to 25 ms.
  // Production CS2 must instead use the user's monotonic confirmation window.
  constexpr std::array<std::uint64_t, 4> high_fps_missing_times{
      15'000U, 20'000U, 25'000U, 30'000U};
  constexpr std::array<std::uint64_t, 2> low_fps_missing_times{
      20'000U, 30'000U};
  verify_timing(high_fps_missing_times);
  verify_timing(low_fps_missing_times);
}

void test_near_body_owns_head_despite_neighbour_confidence() {
  MobileControlConfig config = algorithm_test_config();
  config.switch_confirmation_frames = 4;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);

  const std::array initial_body{
      box(150.0F, 180.0F, 50.0F, 100.0F, 0.70F, 0U)};
  const auto body = core.process(initial_body, frame(1, 10'000));
  assert(body.has_target && body.source == AimSource::body_fallback);

  // Both bodies geometrically admit the head.  The neighbouring body has much
  // higher confidence, but is 20 pixels away from the head's expected anchor
  // and must not lend its identity to that head.
  const std::array crowded_pair{
      box(150.0F, 180.0F, 50.0F, 100.0F, 0.70F, 0U),
      box(170.0F, 180.0F, 50.0F, 100.0F, 0.99F, 0U),
      box(150.0F, 148.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto head = core.process(crowded_pair, frame(2, 20'000));

  assert(head.has_target && head.source == AimSource::head);
  assert(!head.switched && !head.held);
  assert(head.lock_id == body.lock_id);
  assert(head.track_id == body.track_id);
  assert(core.metrics().head_preemptions == 1U);
}

void test_freshness_and_monotonic_frame_guards() {
  MobileControlConfig config = algorithm_test_config();
  config.maximum_frame_age_us = 50'000;
  MobileControlCore core(config);
  const std::array target{box(200.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U)};
  assert(core.process(target, frame(1, 100'000, 10'000)).has_target);

  const auto stale = core.process(target, frame(2, 120'000, 50'001));
  assert(!stale.has_move() && stale.suppression_reason == ControlSuppressionReason::stale_frame);
  const auto duplicate = core.process(target, frame(1, 130'000));
  assert(!duplicate.has_move() && duplicate.suppression_reason == ControlSuppressionReason::non_monotonic_frame);
  const auto time_backwards = core.process(target, {3, 140'000, 139'999});
  assert(!time_backwards.has_move() && time_backwards.suppression_reason == ControlSuppressionReason::invalid_time);
  assert(core.metrics().stale_frames == 1);
  assert(core.metrics().non_monotonic_frames == 1);
  assert(core.metrics().invalid_time_frames == 1);
}

void test_control_tracker_prediction_uses_elapsed_time_across_sequence_gaps() {
  MobileControlConfig config = algorithm_test_config();
  config.head_body_pairing_enabled = false;
  config.head_only_min_confidence = 0.0F;
  config.tracker.maximum_center_distance_pixels = 6.0F;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);

  const std::array initial{
      box(100.0F, 100.0F, 6.0F, 20.0F, 0.90F, 1U)};
  const auto created = core.process(initial, frame(1U, 100'000U));
  const std::array warmup{
      box(104.0F, 100.0F, 6.0F, 20.0F, 0.90F, 1U)};
  const auto warmed = core.process(warmup, frame(2U, 110'000U));
  const std::array variable_gap{
      box(116.0F, 100.0F, 6.0F, 20.0F, 0.90F, 1U)};
  const auto continued = core.process(
      variable_gap, frame(5U, 140'000U));

  assert(created.has_target && warmed.has_target && continued.has_target);
  assert(warmed.track_id == created.track_id);
  assert(continued.track_id == created.track_id);
  assert(core.tracker_metrics().tracks_created == 1U);
  assert(core.tracker_metrics().time_based_velocity_updates >= 2U);
}

void test_geometry_filter_and_rejection_metrics() {
  MobileControlCore core(algorithm_test_config());
  const std::array detections{
      YoloDetection{0.0F, 80.0F, 20.0F, 100.0F, 0.90F, 1U},
      box(100.0F, 100.0F, 1.0F, 1.0F, 0.90F, 1U),
      box(130.0F, 100.0F, 20.0F, 4.0F, 0.90F, 1U),
      YoloDetection{310.0F, 100.0F, 330.0F, 120.0F, 0.90F, 1U},
      YoloDetection{80.0F, 80.0F, 100.0F, 100.0F,
                    std::numeric_limits<float>::quiet_NaN(), 1U},
      box(200.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto output = core.process(detections, frame(1, 1'000));
  assert(output.has_target && output.target_x == 200.0F);
  const auto& metrics = core.metrics();
  assert(metrics.rejected_border == 1);
  assert(metrics.rejected_size == 1);
  assert(metrics.rejected_aspect_ratio == 1);
  assert(metrics.rejected_out_of_bounds == 1);
  assert(metrics.rejected_non_finite == 1);
}

void test_secondary_validation_pair_and_body_fallback() {
  MobileControlConfig config = algorithm_test_config();
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);
  const std::array weak_head_only{box(160.0F, 90.0F, 20.0F, 20.0F, 0.60F, 1U)};
  const auto rejected_head = core.process(weak_head_only, frame(1, 10'000));
  assert(!rejected_head.has_target);
  assert(core.metrics().rejected_unvalidated_heads == 1);

  core.reset();
  const std::array paired{
      box(160.0F, 150.0F, 50.0F, 100.0F, 0.90F, 0U),
      box(160.0F, 105.0F, 20.0F, 20.0F, 0.60F, 1U),
  };
  const auto accepted_pair = core.process(paired, frame(1, 20'000));
  assert(accepted_pair.has_target && accepted_pair.source == AimSource::head);
  assert(accepted_pair.track_id != 0);
  assert(core.metrics().paired_heads == 1);
  const std::array stronger_head{
      box(161.0F, 150.0F, 50.0F, 100.0F, 0.90F, 0U),
      box(161.0F, 105.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto retained_pair = core.process(stronger_head, frame(2, 30'000));
  assert(!retained_pair.switched && retained_pair.track_id == accepted_pair.track_id);

  core.reset();
  const std::array weak_body{box(160.0F, 170.0F, 40.0F, 100.0F, 0.55F, 0U)};
  const auto rejected_body = core.process(weak_body, frame(1, 40'000));
  assert(!rejected_body.has_target);
  const std::array strong_body{box(160.0F, 170.0F, 40.0F, 100.0F, 0.90F, 0U)};
  const auto accepted_body = core.process(strong_body, frame(2, 50'000));
  assert(accepted_body.has_target && accepted_body.source == AimSource::body_fallback);
  assert(accepted_body.track_id != 0);
}

void test_implausible_pair_does_not_validate_a_weak_head() {
  MobileControlConfig config = algorithm_test_config();
  config.body_fallback_min_confidence = 0.95F;
  MobileControlCore core(config);
  const std::array detections{
      box(260.0F, 180.0F, 40.0F, 100.0F, 0.90F, 0U),
      box(90.0F, 90.0F, 20.0F, 20.0F, 0.60F, 1U),
  };
  const auto output = core.process(detections, frame(1, 10'000));
  assert(!output.has_target);
  assert(core.metrics().rejected_unvalidated_heads == 1);
  assert(core.metrics().rejected_body_fallbacks == 1);
}

void test_track_id_preserves_identity_when_detection_order_and_rank_change() {
  MobileControlConfig config = algorithm_test_config();
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);
  const std::array first{
      box(100.0F, 100.0F, 20.0F, 20.0F, 0.95F, 1U),
      box(220.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto locked = core.process(first, frame(1, 10'000));
  assert(locked.has_target && locked.target_x == 100.0F && locked.track_id != 0);
  const std::array reordered{
      box(218.0F, 100.0F, 20.0F, 20.0F, 0.99F, 1U),
      box(102.0F, 100.0F, 20.0F, 20.0F, 0.85F, 1U),
  };
  const auto retained = core.process(reordered, frame(2, 20'000));
  assert(retained.has_target && !retained.switched);
  assert(retained.track_id == locked.track_id);
  assert(retained.target_x > 100.0F && retained.target_x < 102.0F);
  assert(core.metrics().lock_exact_track_matches == 1);
}

void test_control_target_damps_detector_jitter_without_changing_lock() {
  MobileControlConfig filtered_config = algorithm_test_config();
  filtered_config.motion.prediction_horizon_ms = 0.0F;
  MobileControlConfig raw_config = filtered_config;
  raw_config.tracker.control_smoothing_alpha = 1.0F;
  MobileControlCore filtered(filtered_config);
  MobileControlCore raw(raw_config);

  float filtered_previous = 100.0F;
  float raw_previous = 100.0F;
  float filtered_maximum_step = 0.0F;
  float raw_maximum_step = 0.0F;
  std::uint64_t filtered_lock_id = 0;
  std::uint64_t raw_lock_id = 0;
  for (std::uint64_t sequence = 1; sequence <= 18; ++sequence) {
    const float center_x = sequence == 1
        ? 100.0F : (sequence % 2 == 0 ? 102.0F : 98.0F);
    const std::array detection{
        box(center_x, 100.0F, 20.0F, 20.0F, 0.95F, 1U)};
    const auto filtered_output = filtered.process(
        detection, frame(sequence, 10'000U * sequence));
    const auto raw_output = raw.process(
        detection, frame(sequence, 10'000U * sequence));
    assert(filtered_output.has_target && raw_output.has_target);
    if (sequence == 1) {
      filtered_lock_id = filtered_output.lock_id;
      raw_lock_id = raw_output.lock_id;
    }
    assert(filtered_output.lock_id == filtered_lock_id &&
           raw_output.lock_id == raw_lock_id);
    filtered_maximum_step = std::max(
        filtered_maximum_step,
        std::fabs(filtered_output.target_x - filtered_previous));
    raw_maximum_step = std::max(
        raw_maximum_step,
        std::fabs(raw_output.target_x - raw_previous));
    filtered_previous = filtered_output.target_x;
    raw_previous = raw_output.target_x;
  }

  assert(raw_maximum_step >= 3.99F);
  assert(filtered_maximum_step <= 2.5F);
  assert(filtered_maximum_step < raw_maximum_step);
  assert(filtered.tracker_metrics().control_filter_blends > 0);
  assert(filtered.tracker_metrics().control_filter_bypasses == 0);
}

void test_single_new_track_rebinds_by_giou_without_changing_lock_identity() {
  MobileControlConfig config = algorithm_test_config();
  config.tracker.lost_frame_buffer = 0;
  config.tracker.lost_track_duration_us = 0U;
  config.lost_frame_hold_count = 2;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);
  const std::array initial{box(100.0F, 100.0F, 20.0F, 20.0F, 0.95F, 1U)};
  const auto locked = core.process(initial, frame(1, 10'000));
  assert(locked.track_id != 0);
  assert(core.process({}, frame(2, 20'000)).held);

  // The boxes are close but do not overlap. Their GIoU is still strong enough
  // for a singleton detector-ID rebuild, while ordinary IoU remains zero.
  const std::array rebuilt{box(122.0F, 100.0F, 20.0F, 20.0F, 0.95F, 1U)};
  const auto rebound = core.process(rebuilt, frame(3, 30'000));
  assert(rebound.has_target && !rebound.switched);
  assert(rebound.lock_id == locked.lock_id);
  assert(rebound.track_id != locked.track_id);
  assert(core.metrics().track_id_rebinds == 1);
  assert(core.metrics().lock_giou_matches == 1);
}

void test_unrelated_crowd_target_does_not_make_rebind_ambiguous() {
  MobileControlConfig config = algorithm_test_config();
  config.tracker.lost_frame_buffer = 0;
  config.tracker.lost_track_duration_us = 0U;
  config.lost_frame_hold_count = 2;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);
  const std::array initial{box(100.0F, 100.0F, 20.0F, 20.0F, 0.95F, 1U)};
  const auto locked = core.process(initial, frame(1, 10'000));
  assert(locked.track_id != 0);
  assert(core.process({}, frame(2, 20'000)).held);

  // A team fight can rebuild the locked target's tracker ID while unrelated
  // enemies remain elsewhere in the ROI. Only geometrically plausible
  // replacements are ambiguous; a far target must not force switch-pending.
  const std::array rebuilt_with_crowd{
      box(102.0F, 100.0F, 20.0F, 20.0F, 0.95F, 1U),
      box(280.0F, 100.0F, 20.0F, 20.0F, 0.99F, 1U),
  };
  const auto rebound = core.process(
      rebuilt_with_crowd, frame(3, 30'000));

  assert(rebound.has_target && !rebound.switched && !rebound.held);
  assert(rebound.lock_id == locked.lock_id);
  assert(rebound.track_id != locked.track_id);
  assert(std::fabs(rebound.target_x - 102.0F) < 0.001F);
  assert(core.metrics().track_id_rebinds == 1);
  assert(core.metrics().rejected_ambiguous_rebinds == 0);
  assert(core.metrics().rejected_rebind_geometry == 1);
}

void test_ambiguous_new_tracks_cannot_inherit_the_lock() {
  MobileControlConfig config = algorithm_test_config();
  config.tracker.lost_frame_buffer = 0;
  config.tracker.lost_track_duration_us = 0U;
  config.lost_frame_hold_count = 2;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);
  const std::array initial{box(100.0F, 100.0F, 20.0F, 20.0F, 0.95F, 1U)};
  (void)core.process(initial, frame(1, 10'000));
  (void)core.process({}, frame(2, 20'000));

  const std::array ambiguous{
      box(102.0F, 100.0F, 20.0F, 20.0F, 0.95F, 1U),
      box(127.0F, 100.0F, 20.0F, 20.0F, 0.94F, 1U),
  };
  const auto rejected = core.process(ambiguous, frame(3, 30'000));
  assert(rejected.held);
  assert(rejected.suppression_reason ==
         ControlSuppressionReason::switch_pending);
  assert(core.metrics().rejected_ambiguous_rebinds == 1);
  assert(core.metrics().track_id_rebinds == 0);
}

void test_head_prediction_is_bounded_to_anchor_lag_and_reports_safe_radius() {
  MobileControlConfig config = algorithm_test_config();
  config.head_anchor_x_ratio = 0.20F;
  config.head_safe_inset_fraction = 0.10F;
  config.velocity_update_alpha = 1.0F;
  config.motion.prediction_horizon_ms = 20.0F;
  config.motion.maximum_prediction_pixels = 20.0F;
  MobileControlCore core(config);
  const std::array first{box(110.0F, 100.0F, 20.0F, 20.0F, 0.95F, 1U)};
  const std::array second{box(120.0F, 100.0F, 20.0F, 20.0F, 0.95F, 1U)};
  (void)core.process(first, frame(1, 10'000));
  const auto constrained = core.process(second, frame(2, 20'000));
  assert(constrained.prediction_limited);
  assert(constrained.head_anchor_lag_x_pixels <= 1.2501F);
  assert(std::fabs(constrained.head_safe_radius_pixels - 4.0F) < 0.001F);
  assert(core.metrics().head_anchor_prediction_limits == 1);
  assert(core.metrics().maximum_head_anchor_lag_pixels <= 1.2501F);
}

void test_iou_association_and_confirmed_switch() {
  MobileControlConfig config = algorithm_test_config();
  config.lock_match_max_distance_pixels = 5.0F;
  config.lock_match_min_iou = 0.20F;
  config.switch_confirmation_frames = 2;
  config.motion.prediction_horizon_ms = 0.0F;
  config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore core(config);
  const std::array initial{box(100.0F, 100.0F, 60.0F, 60.0F, 0.90F, 1U)};
  const auto selected = core.process(initial, frame(1, 10'000));
  const std::array overlapping{box(120.0F, 100.0F, 60.0F, 60.0F, 0.60F, 1U)};
  const auto associated = core.process(overlapping, frame(2, 20'000));
  assert(!associated.switched && associated.lock_id == selected.lock_id);

  const std::array challenger{box(250.0F, 100.0F, 20.0F, 20.0F, 0.99F, 1U)};
  const auto pending = core.process(challenger, frame(3, 30'000));
  assert(pending.held && pending.suppression_reason == ControlSuppressionReason::switch_pending);
  const auto switched = core.process(challenger, frame(4, 40'000));
  assert(switched.switched && !switched.held && switched.target_x == 250.0F);
  assert(switched.lock_id == selected.lock_id + 1);
  assert(core.metrics().switch_pending_frames == 1);
}

void test_switch_confirmation_uses_observation_time_without_limiting_fps() {
  MobileControlConfig config = algorithm_test_config();
  config.lock_match_max_distance_pixels = 5.0F;
  config.lock_match_min_iou = 0.20F;
  config.switch_confirmation_frames = 2;
  config.switch_confirmation_duration_us = 40'000U;
  config.motion.prediction_horizon_ms = 0.0F;
  config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore core(config);

  const std::array initial{
      box(100.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U)};
  const auto selected = core.process(initial, frame(1, 10'000));
  const std::array challenger{
      box(250.0F, 100.0F, 20.0F, 20.0F, 0.99F, 1U)};

  assert(core.process(challenger, frame(2, 20'000)).held);
  assert(core.process(challenger, frame(3, 20'100)).held);
  assert(core.process(challenger, frame(4, 20'200)).held);
  const auto switched = core.process(challenger, frame(5, 60'000));
  assert(switched.switched && switched.lock_id == selected.lock_id + 1);
}

void test_switch_confirmation_keeps_one_stable_crowd_challenger() {
  MobileControlConfig config = algorithm_test_config();
  config.lock_match_max_distance_pixels = 5.0F;
  config.lock_match_min_iou = 0.20F;
  config.switch_confirmation_frames = 3;
  config.motion.prediction_horizon_ms = 0.0F;
  config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore core(config);

  const std::array initial{
      box(100.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U)};
  const auto selected = core.process(initial, frame(1, 10'000));

  const std::array first_challenge{
      box(220.0F, 100.0F, 20.0F, 20.0F, 0.95F, 1U),
      box(260.0F, 100.0F, 20.0F, 20.0F, 0.80F, 1U),
  };
  assert(core.process(first_challenge, frame(2, 20'000)).held);

  // Skill effects can make nearby detections trade the highest confidence on
  // every frame. Candidate A remains geometrically and temporally stable, so
  // B's confidence spike must not restart A's confirmation window.
  const std::array second_challenge{
      box(220.0F, 100.0F, 20.0F, 20.0F, 0.85F, 1U),
      box(260.0F, 100.0F, 20.0F, 20.0F, 0.99F, 1U),
  };
  assert(core.process(second_challenge, frame(3, 30'000)).held);
  const std::array third_challenge{
      box(220.0F, 100.0F, 20.0F, 20.0F, 0.99F, 1U),
      box(260.0F, 100.0F, 20.0F, 20.0F, 0.85F, 1U),
  };
  const auto switched = core.process(third_challenge, frame(4, 40'000));

  assert(switched.switched && !switched.held);
  assert(switched.lock_id == selected.lock_id + 1U);
  assert(std::fabs(switched.target_x - 220.0F) < 1.0F);
}

void test_overwatch_missing_switch_rejects_weak_retained_challenger() {
  MobileControlCore core(production_overwatch_enemy_body_config());
  const std::array crowd{
      box(208.0F, 240.0F, 40.0F, 100.0F, 0.95F, 0U),
      box(250.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U),
  };
  const auto selected = core.process(crowd, frame(1, 10'000U));
  assert(selected.has_target && std::fabs(selected.target_x - 208.0F) < 0.001F);

  // The challenger was already tracked, but an effect-obscured 0.30
  // observation must not take a missing lock merely because it retained ID.
  const std::array weak_challenger{
      box(250.0F, 240.0F, 40.0F, 100.0F, 0.30F, 0U)};
  const auto held = core.process(weak_challenger, frame(2, 20'000U));

  assert(held.held && !held.switched);
  assert(held.suppression_reason == ControlSuppressionReason::lock_held);
  assert(core.metrics().rejected_missing_switch_confidence == 1U);
}

void test_overwatch_missing_switch_rejects_distant_challenger() {
  MobileControlCore core(production_overwatch_enemy_body_config());
  const std::array crowd{
      box(208.0F, 240.0F, 40.0F, 100.0F, 0.95F, 0U),
      box(330.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U),
  };
  const auto selected = core.process(crowd, frame(1, 10'000U));
  assert(selected.has_target && std::fabs(selected.target_x - 208.0F) < 0.001F);

  const std::array distant_challenger{
      box(330.0F, 240.0F, 40.0F, 100.0F, 0.99F, 0U)};
  const auto held = core.process(distant_challenger, frame(2, 20'000U));

  assert(held.held && !held.switched);
  assert(held.suppression_reason == ControlSuppressionReason::lock_held);
  assert(core.metrics().rejected_missing_switch_jump == 1U);
}

void test_overwatch_missing_switch_accepts_near_credible_challenger() {
  MobileControlCore core(production_overwatch_enemy_body_config());
  const std::array crowd{
      box(208.0F, 240.0F, 40.0F, 100.0F, 0.95F, 0U),
      box(250.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U),
  };
  const auto selected = core.process(crowd, frame(1, 10'000U));
  assert(selected.has_target && std::fabs(selected.target_x - 208.0F) < 0.001F);

  const std::array near_challenger{
      box(250.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  assert(core.process(near_challenger, frame(2, 20'000U)).held);
  assert(core.process(near_challenger, frame(3, 40'000U)).held);
  const auto switched = core.process(near_challenger, frame(4, 70'000U));

  assert(switched.switched && !switched.held);
  assert(switched.lock_id == selected.lock_id + 1U);
  assert(std::fabs(switched.target_x - 250.0F) < 0.001F);
}

void test_overwatch_pending_switch_cancels_when_confidence_collapses() {
  MobileControlCore core(production_overwatch_enemy_body_config());
  const std::array crowd{
      box(208.0F, 240.0F, 40.0F, 100.0F, 0.95F, 0U),
      box(250.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U),
  };
  const auto selected = core.process(crowd, frame(1, 10'000U));
  const std::array credible{
      box(250.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  assert(core.process(credible, frame(2, 20'000U)).held);

  const std::array obscured{
      box(250.0F, 240.0F, 40.0F, 100.0F, 0.30F, 0U)};
  const auto rejected = core.process(obscured, frame(3, 40'000U));

  assert(rejected.held && !rejected.switched);
  assert(rejected.lock_id == selected.lock_id);
  assert(rejected.suppression_reason ==
         ControlSuppressionReason::lock_held);
  assert(core.metrics().rejected_missing_switch_confidence == 1U);
}

void test_overwatch_pending_switch_cancels_after_excessive_drift() {
  MobileControlCore core(production_overwatch_enemy_body_config());
  const std::array crowd{
      box(208.0F, 240.0F, 40.0F, 100.0F, 0.95F, 0U),
      box(250.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U),
  };
  const auto selected = core.process(crowd, frame(1, 10'000U));
  const std::array near_challenger{
      box(250.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  assert(core.process(near_challenger, frame(2, 20'000U)).held);

  const std::array drifted_challenger{
      box(270.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  const auto rejected = core.process(
      drifted_challenger, frame(3, 40'000U));

  assert(rejected.held && !rejected.switched);
  assert(rejected.lock_id == selected.lock_id);
  assert(rejected.suppression_reason ==
         ControlSuppressionReason::lock_held);
  assert(core.metrics().rejected_missing_switch_jump == 1U);
}

void test_exact_track_id_cannot_bypass_geometry() {
  MobileControlConfig config = algorithm_test_config();
  config.lock_match_max_distance_pixels = 5.0F;
  config.lock_match_min_iou = 0.20F;
  config.switch_confirmation_frames = 2;
  config.motion.prediction_horizon_ms = 0.0F;
  config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore core(config);

  const std::array initial{
      box(100.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U)};
  const auto selected = core.process(initial, frame(1, 10'000));
  const std::array implausible_same_track{
      box(140.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U)};
  const auto pending = core.process(
      implausible_same_track, frame(2, 20'000));

  assert(pending.held);
  assert(pending.lock_id == selected.lock_id);
  assert(pending.suppression_reason ==
         ControlSuppressionReason::switch_pending);
  assert(core.metrics().rejected_exact_track_geometry == 1);

  const auto switched = core.process(
      implausible_same_track, frame(3, 30'000));
  assert(switched.switched && switched.target_x == 140.0F);
  assert(switched.lock_id == selected.lock_id + 1);
}

void test_visible_ego_motion_keeps_same_lock_geometry() {
  MobileControlConfig config = algorithm_test_config();
  config.lock_match_max_distance_pixels = 5.0F;
  config.lock_match_min_iou = 0.90F;
  config.lock_match_min_giou = 0.90F;
  config.motion.prediction_horizon_ms = 0.0F;
  config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore core(config);

  const std::array initial{
      box(250.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U)};
  const auto offered = core.process(initial, frame(1, 10'000));
  assert(offered.delta_x > 5);

  core.apply_visible_ego_motion(offered.delta_x, offered.delta_y);
  const std::array visible{
      box(250.0F - static_cast<float>(offered.delta_x),
          100.0F - static_cast<float>(offered.delta_y),
          20.0F, 20.0F, 0.90F, 1U)};
  const auto continued = core.process(visible, frame(2, 20'000));

  assert(continued.has_target && !continued.switched && !continued.held);
  assert(continued.lock_id == offered.lock_id);
  assert(core.metrics().lock_exact_track_matches == 1);
  assert(core.metrics().rejected_exact_track_geometry == 0);
  assert(core.metrics().ego_motion_adjustments == 1);
  assert(core.metrics().maximum_ego_motion_shift_pixels >=
         static_cast<float>(offered.delta_x));
}

void test_unseen_acknowledged_move_cannot_stack_another_correction() {
  MobileControlConfig config = algorithm_test_config();
  config.head_body_pairing_enabled = false;
  config.head_only_min_confidence = 0.0F;
  config.motion.prediction_horizon_ms = 0.0F;
  config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore core(config);

  const std::array initial{
      box(250.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U)};
  const auto offered = core.process(initial, frame(1, 10'000));
  assert(offered.has_move() && offered.delta_x > 0);
  core.apply_visible_ego_motion(offered.delta_x, offered.delta_y);

  // This frame entered the phone after the ACK but still contains the picture
  // captured before the physical response. It may update tracking, but it may
  // not cause a second packet to stack on the unseen first packet.
  const auto in_flight = core.process(initial, frame(2, 20'000));
  assert(in_flight.held && !in_flight.has_move());
  assert(in_flight.suppression_reason ==
         ControlSuppressionReason::response_guard);
  assert(core.metrics().ego_motion_adjustments == 0U);
  assert(core.metrics().ego_motion_response_waits == 1U);

  const float visible_shift_x =
      -static_cast<float>(offered.delta_x) *
      core.motion_config().response_x_px_per_count;
  const float visible_shift_y =
      -static_cast<float>(offered.delta_y) *
      core.motion_config().response_y_px_per_count;
  const std::array visible{
      box(250.0F + visible_shift_x, 100.0F + visible_shift_y,
          20.0F, 20.0F, 0.90F, 1U)};
  const auto resumed = core.process(visible, frame(3, 30'000));

  assert(resumed.has_target && !resumed.held && !resumed.switched);
  assert(resumed.lock_id == offered.lock_id);
  assert(core.metrics().ego_motion_adjustments == 1U);
  assert(core.metrics().measured_ego_motion_adjustments == 1U);
  assert(core.metrics().maximum_measured_ego_motion_support == 1U);
}

void test_single_target_motion_cannot_scale_the_camera_adjustment() {
  MobileControlConfig config = algorithm_test_config();
  config.head_body_pairing_enabled = false;
  config.head_only_min_confidence = 0.0F;
  config.motion.prediction_horizon_ms = 0.0F;
  config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore core(config);

  const std::array initial{
      box(250.0F, 160.0F, 20.0F, 20.0F, 0.90F, 1U)};
  const auto offered = core.process(initial, frame(1, 10'000));
  assert(offered.delta_x > 0 && offered.delta_y == 0);
  core.apply_visible_ego_motion(offered.delta_x, offered.delta_y);

  const float expected_camera_shift =
      -static_cast<float>(offered.delta_x) *
      core.motion_config().response_x_px_per_count;
  // The target independently moves in the same screen direction as the
  // camera response.  One observation can acknowledge the command, but it
  // cannot prove that the doubled displacement is all camera motion.
  const float visible_center_x = 250.0F + expected_camera_shift * 2.0F;
  const std::array visible{
      box(visible_center_x, 160.0F, 20.0F, 20.0F, 0.90F, 1U)};
  const auto continued = core.process(visible, frame(2, 20'000));

  assert(continued.has_target && !continued.held && !continued.switched);
  assert(continued.lock_id == offered.lock_id);
  assert(std::fabs(continued.target_x - visible_center_x) < 0.001F);
  assert(std::fabs(
      core.metrics().maximum_ego_motion_shift_pixels -
      std::fabs(expected_camera_shift)) < 0.001F);
  assert(core.metrics().maximum_measured_ego_motion_support == 1U);
}

void test_paired_head_and_body_count_as_one_ego_motion_witness() {
  MobileControlConfig config = cs2_t_head_config();
  config.motion.prediction_horizon_ms = 0.0F;
  config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore core(config);

  const std::array initial{
      box(260.0F, 250.0F, 44.0F, 100.0F, 0.99F, 2U),
      box(260.0F, 208.0F, 20.0F, 20.0F, 0.90F, 3U),
  };
  const auto offered = core.process(initial, frame(1, 10'000U));
  assert(offered.has_target && offered.source == AimSource::head);
  assert(offered.delta_x > 0 && offered.delta_y == 0);
  core.apply_visible_ego_motion(offered.delta_x, offered.delta_y);

  const float expected_camera_shift =
      -static_cast<float>(offered.delta_x) *
      core.motion_config().response_x_px_per_count;
  const float visible_shift = expected_camera_shift * 2.0F;
  const std::array visible{
      box(260.0F + visible_shift, 250.0F,
          44.0F, 100.0F, 0.99F, 2U),
      box(260.0F + visible_shift, 208.0F,
          20.0F, 20.0F, 0.90F, 3U),
  };
  const auto continued = core.process(visible, frame(2, 20'000U));

  assert(continued.has_target && !continued.held && !continued.switched);
  assert(continued.lock_id == offered.lock_id);
  assert(std::fabs(
      core.metrics().maximum_ego_motion_shift_pixels -
      std::fabs(expected_camera_shift)) < 0.001F);
  assert(core.metrics().maximum_measured_ego_motion_support == 1U);
}

void test_visible_ego_motion_keeps_nearby_target_tracker_identity_aligned() {
  MobileControlConfig config = algorithm_test_config();
  config.motion.prediction_horizon_ms = 0.0F;
  config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore core(config);

  const std::array initial{
      box(220.0F, 100.0F, 20.0F, 20.0F, 0.95F, 1U),
      box(242.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto offered = core.process(initial, frame(1, 10'000));
  assert(offered.has_target && offered.delta_x > 0);

  core.apply_visible_ego_motion(offered.delta_x, offered.delta_y);
  const float expected_shift_x = -static_cast<float>(offered.delta_x) *
      core.motion_config().response_x_px_per_count;
  const float expected_shift_y = -static_cast<float>(offered.delta_y) *
      core.motion_config().response_y_px_per_count;
  const float visible_shift_x = expected_shift_x * 2.0F;
  const float visible_shift_y = expected_shift_y * 2.0F;
  const std::array visible{
      box(220.0F + visible_shift_x, 100.0F + visible_shift_y,
          20.0F, 20.0F, 0.95F, 1U),
      box(242.0F + visible_shift_x, 100.0F + visible_shift_y,
          20.0F, 20.0F, 0.90F, 1U),
  };
  const auto continued = core.process(visible, frame(2, 20'000));

  assert(continued.has_target && !continued.switched);
  assert(continued.lock_id == offered.lock_id);
  assert(std::fabs(continued.target_x - (220.0F + visible_shift_x)) < 0.001F);
  assert(std::fabs(continued.target_y - (100.0F + visible_shift_y)) < 0.001F);
  assert(core.metrics().measured_ego_motion_adjustments == 1U);
  assert(core.metrics().maximum_measured_ego_motion_support == 2U);
  assert(core.metrics().maximum_ego_motion_prediction_error_pixels > 0.0F);
}

void test_common_motion_opposite_to_command_is_not_trusted_as_ego_motion() {
  MobileControlConfig config = algorithm_test_config();
  config.motion.prediction_horizon_ms = 0.0F;
  config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore core(config);

  const std::array initial{
      box(220.0F, 160.0F, 20.0F, 20.0F, 0.95F, 1U),
      box(242.0F, 160.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto offered = core.process(initial, frame(1, 10'000));
  assert(offered.delta_x > 0 && offered.delta_y == 0);
  core.apply_visible_ego_motion(offered.delta_x, offered.delta_y);

  // Both detections moved with the target group, but in the opposite direction
  // from the acknowledged camera command. It is common motion, not ego motion.
  const std::array opposite_motion{
      box(240.0F, 160.0F, 20.0F, 20.0F, 0.95F, 1U),
      box(262.0F, 160.0F, 20.0F, 20.0F, 0.90F, 1U),
  };
  const auto rejected = core.process(opposite_motion, frame(2, 20'000));

  assert(rejected.held && !rejected.has_move());
  assert(rejected.suppression_reason ==
         ControlSuppressionReason::response_guard);
  assert(core.metrics().ego_motion_adjustments == 0U);
  assert(core.metrics().measured_ego_motion_adjustments == 0U);
  assert(core.metrics().rejected_measured_ego_motion_axes == 1U);
  assert(core.metrics().ego_motion_response_waits == 1U);
  assert(core.metrics().maximum_ego_motion_prediction_error_pixels > 0.0F);
}

void test_unconfirmed_ego_motion_times_out_by_observation_time_without_limiting_fps() {
  const auto verify = [](std::span<const std::uint64_t> waiting_times) {
    MobileControlConfig config = algorithm_test_config();
    config.head_body_pairing_enabled = false;
    config.head_only_min_confidence = 0.0F;
    config.motion.prediction_horizon_ms = 0.0F;
    config.motion.maximum_prediction_pixels = 0.0F;
    config.lost_target_hold_duration_us = 70'000U;
    config.tracker.lost_track_duration_us = 70'000U;
    config.switch_confirmation_duration_us = 25'000U;
    MobileControlCore core(config);

    const std::array initial{
        box(250.0F, 160.0F, 20.0F, 20.0F, 0.90F, 1U)};
    const auto offered = core.process(initial, frame(1, 10'000U));
    assert(offered.has_target && offered.has_move());
    core.apply_visible_ego_motion(offered.delta_x, offered.delta_y);

    std::uint64_t sequence = 2U;
    for (const std::uint64_t observed_at_us : waiting_times) {
      const auto waiting = core.process({}, frame(sequence++, observed_at_us));
      assert(waiting.held && !waiting.has_move());
      assert(waiting.suppression_reason ==
             ControlSuppressionReason::response_guard);
    }

    // The first unmatched visible observation is always at 20 ms. At 90 ms
    // the same 70 ms lock/track lifetime has elapsed at every fresh FPS.
    const auto expired = core.process({}, frame(sequence++, 90'000U));
    assert(!expired.has_target && !expired.has_move() && !expired.held);
    assert(core.metrics().ego_motion_response_timeouts == 1U);

    const std::array replacement{
        box(80.0F, 160.0F, 20.0F, 20.0F, 0.90F, 1U)};
    const auto first_reacquisition = core.process(
        replacement, frame(sequence++, 100'000U));
    assert(!first_reacquisition.has_target &&
           !first_reacquisition.has_move());
    assert(first_reacquisition.suppression_reason ==
           ControlSuppressionReason::switch_pending);
    const auto still_pending = core.process(
        replacement, frame(sequence++, 110'000U));
    assert(!still_pending.has_target && !still_pending.has_move());
    assert(still_pending.suppression_reason ==
           ControlSuppressionReason::switch_pending);
    const auto reacquired = core.process(
        replacement, frame(sequence, 125'000U));
    assert(reacquired.has_target && !reacquired.held);
    assert(reacquired.lock_id == offered.lock_id + 1U);
    assert(core.metrics().reacquisition_pending_frames == 2U);
    assert(core.metrics().reacquisition_confirmations == 1U);
  };

  constexpr std::array<std::uint64_t, 7> high_fps_waits{
      20'000U, 30'000U, 40'000U, 50'000U, 60'000U, 70'000U, 80'000U};
  constexpr std::array<std::uint64_t, 1> low_fps_waits{20'000U};
  verify(high_fps_waits);
  verify(low_fps_waits);
}

void test_lost_frame_hold_never_replays_motion() {
  MobileControlConfig config = algorithm_test_config();
  config.lost_frame_hold_count = 2;
  MobileControlCore core(config);
  const std::array target{box(250.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U)};
  assert(core.process(target, frame(1, 10'000)).has_move());
  const auto held_one = core.process({}, frame(2, 20'000));
  const auto held_two = core.process({}, frame(3, 30'000));
  const auto expired = core.process({}, frame(4, 40'000));
  assert(held_one.held && held_two.held && !held_one.has_move() && !held_two.has_move());
  assert(!expired.has_target && expired.suppression_reason == ControlSuppressionReason::no_valid_target);
}

void test_velocity_prediction_is_limited() {
  MobileControlConfig config = algorithm_test_config();
  config.velocity_update_alpha = 1.0F;
  config.maximum_velocity_pixels_per_second = 2'000.0F;
  config.motion.prediction_horizon_ms = 20.0F;
  config.motion.maximum_prediction_pixels = 8.0F;
  MobileControlCore core(config);
  const std::array first{box(100.0F, 180.0F, 60.0F, 80.0F, 0.90F, 0U)};
  const std::array second{box(110.0F, 180.0F, 60.0F, 80.0F, 0.90F, 0U)};
  (void)core.process(first, frame(1, 10'000));
  const auto predicted = core.process(second, frame(2, 20'000));
  assert(std::fabs(predicted.target_x - 110.0F) < 0.001F);
  assert(std::fabs(predicted.predicted_error_x - (-42.0F)) < 0.001F);
}

void test_pid_limit_anti_windup_residual_and_settle_guard() {
  MobileControlConfig config = algorithm_test_config();
  config.motion.response_gain = 1.0F;
  config.motion.pid_ki = 10.0F;
  config.motion.pid_kd = 0.0F;
  config.motion.maximum_axis_delta = 12;
  config.motion.settle_maximum_axis_delta = 3;
  config.motion.response_upper_x_px_per_count = 1.0F;
  config.motion.response_upper_y_px_per_count = 1.0F;
  config.lock_match_max_distance_pixels = 300.0F;
  config.tracker.maximum_center_distance_pixels = 300.0F;
  config.motion.prediction_horizon_ms = 0.0F;
  config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore core(config);
  const std::array far_right{box(280.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U)};
  assert(core.process(far_right, frame(1, 10'000)).delta_x == 12);
  assert(core.process(far_right, frame(2, 20'000)).delta_x == 12);
  const std::array far_left{box(100.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U)};
  const auto reversed = core.process(far_left, frame(3, 30'000));
  assert(reversed.delta_x == -12);
  assert(reversed.suppression_reason == ControlSuppressionReason::none);
  assert(core.process(far_left, frame(4, 40'000)).delta_x == -12);

  MobileControlConfig residual_config = algorithm_test_config();
  residual_config.motion.response_gain = 0.10F;
  residual_config.motion.deadzone_pixels = 0.0F;
  residual_config.motion.response_upper_x_px_per_count = 1.0F;
  residual_config.motion.response_upper_y_px_per_count = 1.0F;
  residual_config.motion.prediction_horizon_ms = 0.0F;
  residual_config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore residual_core(residual_config);
  const std::array small_error{box(164.0F, 100.0F, 20.0F, 20.0F, 0.90F, 1U)};
  assert(residual_core.process(small_error, frame(1, 10'000)).delta_x == 0);
  assert(residual_core.process(small_error, frame(2, 20'000)).delta_x == 1);

  MobileControlConfig settle_config = algorithm_test_config();
  settle_config.motion.response_gain = 1.0F;
  settle_config.motion.deadzone_pixels = 0.0F;
  settle_config.motion.prediction_horizon_ms = 0.0F;
  settle_config.motion.maximum_prediction_pixels = 0.0F;
  MobileControlCore settle_core(settle_config);
  const std::array right{box(170.0F, 160.0F, 20.0F, 20.0F, 0.90F, 1U)};
  const std::array crossed{box(156.0F, 160.0F, 20.0F, 20.0F, 0.90F, 1U)};
  assert(settle_core.process(right, frame(1, 10'000)).delta_x > 0);
  const auto settled = settle_core.process(crossed, frame(2, 20'000));
  assert(settled.delta_x == 0 && settled.suppression_reason == ControlSuppressionReason::settle_guard);
}

void test_no_target() {
  MobileControlCore core(algorithm_test_config());
  const auto output = core.process(std::span<const YoloDetection>{}, frame(1, 1'000));
  assert(!output.has_target && !output.has_move());
  assert(output.suppression_reason == ControlSuppressionReason::no_valid_target);
}

void test_repeated_target_loss_and_reappearance_never_sticks_control() {
  constexpr std::uint64_t kCycles = 2'048U;
  MobileControlConfig config = algorithm_test_config();
  config.lost_frame_hold_count = 0U;
  config.lost_target_hold_duration_us = 0U;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);
  std::uint64_t sequence = 0U;
  std::uint64_t observed_at_us = 0U;

  for (std::uint64_t cycle = 0U; cycle < kCycles; ++cycle) {
    const float first_x = cycle % 2U == 0U ? 250.0F : 70.0F;
    const float second_x = cycle % 2U == 0U ? 70.0F : 250.0F;
    const std::array first{
        box(first_x, 100.0F, 20.0F, 20.0F, 0.95F, 1U)};
    const auto acquired = core.process(
        first, frame(++sequence, observed_at_us += 10'000U));
    assert(acquired.has_target && acquired.has_move());

    const auto absent = core.process(
        {}, frame(++sequence, observed_at_us += 10'000U));
    assert(!absent.has_target && !absent.has_move());

    const std::array second{
        box(second_x, 100.0F, 20.0F, 20.0F, 0.96F, 1U)};
    const auto pending_or_reacquired = core.process(
        second, frame(++sequence, observed_at_us += 10'000U));
    assert(!pending_or_reacquired.has_move()
           || pending_or_reacquired.has_target);
    const auto reacquired = core.process(
        second, frame(++sequence, observed_at_us += 10'000U));
    assert(reacquired.has_target && reacquired.has_move());
  }
}

void test_overwatch_body_box_can_target_geometric_head() {
  MobileControlConfig config = overwatch_enemy_body_config();
  MobileControlCore core(config);
  const std::array enemy_body{box(180.0F, 180.0F, 40.0F, 100.0F, 0.90F, 0U)};
  const auto output = core.process(enemy_body, frame(1, 1'000));
  assert(output.has_target && output.source == AimSource::geometric_head);
  assert(std::fabs(output.target_y - 148.0F) < 0.001F);
}

void test_overwatch_geometric_head_uses_tight_control_radius() {
  MobileControlCore core(production_overwatch_enemy_body_config());
  // The inferred head anchor is 6px right of centre.  The old body-derived
  // radius was 18px and latched zero here; the 3px control radius must keep
  // correcting toward the geometric head anchor.
  const std::array enemy_body{
      box(214.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  const auto output = core.process(enemy_body, frame(1, 10'000));
  assert(output.source == AimSource::geometric_head);
  assert(std::fabs(output.head_safe_radius_pixels - 3.0F) < 0.001F);
  assert(!output.settle_stopped);
  assert(output.delta_x > 0 && output.delta_y == 0);
}

void test_overwatch_closed_loop_is_fast_stable_and_keeps_identity() {
  MobileControlCore core(production_overwatch_enemy_body_config());
  constexpr float kInitialError = 120.0F;
  constexpr float kT90Error = kInitialError * 0.10F;
  constexpr std::uint64_t kFrameIntervalUs = 16'667U;
  float body_center_x = 208.0F + kInitialError;
  constexpr float kBodyCenterY = 240.0F;
  std::uint64_t lock_id = 0;
  std::uint32_t t90_frame = 0;
  std::uint32_t tail_entry_frame = 0;
  std::uint32_t tail_settled_frame = 0;
  std::uint32_t alternating_packets = 0;
  std::int32_t previous_nonzero_delta = 0;
  float minimum_error = kInitialError;
  float maximum_last_ten_error = 0.0F;

  for (std::uint32_t index = 0; index < 60; ++index) {
    const std::uint64_t sequence = static_cast<std::uint64_t>(index) + 1U;
    const std::uint64_t observed_at_us = 10'000U + index * kFrameIntervalUs;
    const std::array detection{
        box(body_center_x, kBodyCenterY, 40.0F, 100.0F, 0.90F, 0U)};
    const auto output = core.process(detection, frame(sequence, observed_at_us));
    assert(output.has_target && output.source == AimSource::geometric_head);
    if (index == 0) {
      assert(output.delta_x == 32);
      lock_id = output.lock_id;
    } else {
      assert(output.lock_id == lock_id && !output.switched);
    }
    if (output.delta_x != 0) {
      if (previous_nonzero_delta != 0 &&
          (output.delta_x > 0) != (previous_nonzero_delta > 0)) {
        ++alternating_packets;
      }
      previous_nonzero_delta = output.delta_x;
    }

    body_center_x -= static_cast<float>(output.delta_x);
    const float error = body_center_x - 208.0F;
    minimum_error = std::min(minimum_error, error);
    if (t90_frame == 0 && std::fabs(error) <= kT90Error) {
      t90_frame = index + 1;
    }
    if (tail_entry_frame == 0 && std::fabs(error) <= 12.0F) {
      tail_entry_frame = index + 1;
    }
    if (tail_entry_frame != 0 && tail_settled_frame == 0 &&
        std::fabs(error) <= 2.0F) {
      tail_settled_frame = index + 1;
    }
    if (index >= 50) {
      maximum_last_ten_error = std::max(
          maximum_last_ten_error, std::fabs(error));
    }
  }

  assert(t90_frame != 0 && t90_frame <= 9);  // <=150ms at 60Hz.
  assert(tail_entry_frame != 0 && tail_settled_frame != 0);
  assert(tail_settled_frame - tail_entry_frame <= 6);  // <=100ms.
  assert(minimum_error >= -1.0F);
  assert(maximum_last_ten_error <= 2.0F);
  assert(alternating_packets <= 1);
}

struct StepResponseSummary {
  std::uint32_t t90_frame{};
  float minimum_error{120.0F};
  float maximum_steady_error{};
  std::uint32_t direction_flips{};
};

StepResponseSummary simulate_overwatch_uncalibrated_step(float pixels_per_count) {
  MobileControlCore core(production_overwatch_enemy_body_config());
  StepResponseSummary summary{};
  float body_center_x = 328.0F;
  std::int32_t previous_delta{};
  for (std::uint32_t index = 0; index < 80; ++index) {
    const std::array detection{
        box(body_center_x, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
    const auto output = core.process(
        detection, frame(index + 1U, 10'000U + index * 16'667U));
    assert(output.has_target && output.source == AimSource::geometric_head);
    if (previous_delta != 0 && output.delta_x != 0 &&
        (previous_delta > 0) != (output.delta_x > 0)) {
      ++summary.direction_flips;
    }
    if (output.delta_x != 0) previous_delta = output.delta_x;
    if (output.has_move()) {
      // The production bridge arms this only after device completion and
      // applies it when the resulting fresh picture becomes visible.  Keep
      // the closed-loop response simulation on that same identity timeline;
      // otherwise a fast 2 px/count response looks like an unrelated target.
      core.apply_visible_ego_motion(output.delta_x, output.delta_y);
    }
    body_center_x -= static_cast<float>(output.delta_x) * pixels_per_count;
    const float error = body_center_x - 208.0F;
    summary.minimum_error = std::min(summary.minimum_error, error);
    if (summary.t90_frame == 0 && std::fabs(error) <= 12.0F) {
      summary.t90_frame = index + 1U;
    }
    if (index >= 60) {
      summary.maximum_steady_error = std::max(
          summary.maximum_steady_error, std::fabs(error));
    }
  }
  return summary;
}

void test_overwatch_uncalibrated_response_range_is_fast_and_stable() {
  const StepResponseSummary slow = simulate_overwatch_uncalibrated_step(0.5F);
  const StepResponseSummary nominal = simulate_overwatch_uncalibrated_step(1.0F);
  const StepResponseSummary fast = simulate_overwatch_uncalibrated_step(2.0F);
  assert(slow.t90_frame != 0 && slow.t90_frame <= 10);
  assert(nominal.t90_frame != 0 && nominal.t90_frame <= 8);
  assert(fast.t90_frame != 0 && fast.t90_frame <= 8);
  assert(slow.minimum_error >= -4.0F);
  assert(nominal.minimum_error >= -4.0F);
  assert(fast.minimum_error >= -12.0F);
  assert(slow.maximum_steady_error <= 3.0F);
  assert(nominal.maximum_steady_error <= 3.0F);
  assert(fast.maximum_steady_error <= 4.0F);
  assert(slow.direction_flips <= 2 && nominal.direction_flips <= 2 &&
      fast.direction_flips <= 2);
}

void test_overwatch_moving_target_stays_magnetically_bounded() {
  MobileControlCore core(production_overwatch_enemy_body_config());
  constexpr std::uint64_t kFrameIntervalUs = 16'667U;
  float body_center_x = 228.0F;
  constexpr float kBodyCenterY = 240.0F;
  float external_step = 3.0F;  // 180 model pixels/second at 60Hz.
  std::uint64_t lock_id = 0;
  std::array<float, 100> steady_errors{};
  std::size_t steady_count = 0;
  std::uint32_t far_zero_run = 0;
  std::uint32_t maximum_far_zero_run = 0;
  std::uint32_t reversal_response_frame = 0;

  for (std::uint32_t index = 0; index < 120; ++index) {
    const std::uint64_t sequence = static_cast<std::uint64_t>(index) + 1U;
    const std::uint64_t observed_at_us = 20'000U + index * kFrameIntervalUs;
    const float observed_error = body_center_x - 208.0F;
    const std::array detection{
        box(body_center_x, kBodyCenterY, 40.0F, 100.0F, 0.90F, 0U)};
    const auto output = core.process(detection, frame(sequence, observed_at_us));
    assert(output.has_target && output.source == AimSource::geometric_head);
    if (index == 0) lock_id = output.lock_id;
    assert(output.lock_id == lock_id && !output.switched);

    if (std::fabs(observed_error) > 4.0F && output.delta_x == 0) {
      ++far_zero_run;
      maximum_far_zero_run = std::max(maximum_far_zero_run, far_zero_run);
    } else {
      far_zero_run = 0;
    }
    if (index >= 61 && reversal_response_frame == 0 && output.delta_x < 0) {
      reversal_response_frame = index + 1;
    }

    body_center_x -= static_cast<float>(output.delta_x);
    if (index == 59) external_step = -3.0F;
    body_center_x += external_step;
    if (index >= 20) {
      steady_errors[steady_count++] = std::fabs(body_center_x - 208.0F);
    }
  }

  std::sort(steady_errors.begin(), steady_errors.begin() + steady_count);
  const std::size_t p95_index =
      std::min(steady_count - 1, steady_count * 95 / 100);
  assert(steady_errors[p95_index] <= 5.0F);
  assert(maximum_far_zero_run <= 1);
  assert(reversal_response_frame != 0 && reversal_response_frame <= 65);
}

void test_overwatch_four_frame_dropout_holds_lock_without_blind_motion() {
  MobileControlCore core(production_overwatch_enemy_body_config());
  const std::array enemy_body{
      box(260.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  const auto locked = core.process(enemy_body, frame(1, 10'000));
  assert(locked.has_target && locked.lock_id != 0);
  for (std::uint64_t sequence = 2; sequence <= 5; ++sequence) {
    const auto held = core.process(
        {}, frame(sequence, 10'000U + (sequence - 1U) * 16'667U));
    assert(held.held && held.lock_id == locked.lock_id && !held.has_move());
  }
  const auto resumed = core.process(enemy_body, frame(6, 93'335));
  assert(resumed.has_target && !resumed.switched);
  assert(resumed.lock_id == locked.lock_id);
}

void test_overwatch_dropout_hold_uses_time_not_fresh_frame_count() {
  const std::array enemy_body{
      box(260.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  const auto verify_timing = [&](std::span<const std::uint64_t> missing_times) {
    MobileControlCore core(production_overwatch_enemy_body_config());
    const auto locked = core.process(enemy_body, frame(1, 10'000U));
    assert(locked.has_target && locked.lock_id != 0U);
    std::uint64_t sequence = 2U;
    for (const std::uint64_t observed_at_us : missing_times) {
      const auto held = core.process({}, frame(sequence++, observed_at_us));
      assert(held.held && held.lock_id == locked.lock_id && !held.has_move());
    }
    const auto expired = core.process({}, frame(sequence, 80'000U));
    assert(!expired.has_target);
    assert(expired.suppression_reason ==
           ControlSuppressionReason::no_valid_target);
  };

  // Both streams retain the same lock through 65 ms and expire it at 70 ms,
  // regardless of whether fresh observations arrive at 200 or about 40 FPS.
  constexpr std::array<std::uint64_t, 13> high_fps_missing_times{
      15'000U, 20'000U, 25'000U, 30'000U, 35'000U, 40'000U, 45'000U,
      50'000U, 55'000U, 60'000U, 65'000U, 70'000U, 75'000U,
  };
  constexpr std::array<std::uint64_t, 3> low_fps_missing_times{
      35'000U, 60'000U, 75'000U};
  verify_timing(high_fps_missing_times);
  verify_timing(low_fps_missing_times);
}

void test_overwatch_reacquisition_rejects_one_frame_far_target_yank() {
  MobileControlCore core(production_overwatch_enemy_body_config());
  const std::array original{
      box(120.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  const auto locked = core.process(original, frame(1U, 10'000U));
  assert(locked.has_target && locked.lock_id != 0U);

  // Expire the 70 ms OW2 lost-target hold.  A later far observation is not a
  // startup acquisition: a single detector flash must never emit a move.
  const auto expired = core.process({}, frame(2U, 80'000U));
  assert(!expired.has_target && !expired.has_move());
  const std::array far_target{
      box(300.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  const auto one_frame = core.process(far_target, frame(3U, 90'000U));
  assert(!one_frame.has_target && !one_frame.has_move());
  assert(one_frame.suppression_reason ==
         ControlSuppressionReason::switch_pending);
  const auto vanished = core.process({}, frame(4U, 100'000U));
  assert(!vanished.has_target && !vanished.has_move());

  // A real far target becomes eligible only after the same identity survives
  // both the three-observation and 45 ms production confirmation contracts.
  const auto pending_first = core.process(
      far_target, frame(5U, 110'000U));
  const auto pending_second = core.process(
      far_target, frame(6U, 130'000U));
  assert(!pending_first.has_target && !pending_first.has_move());
  assert(!pending_second.has_target && !pending_second.has_move());
  const auto confirmed = core.process(
      far_target, frame(7U, 155'000U));
  assert(confirmed.has_target && confirmed.switched);
  assert(confirmed.lock_id == locked.lock_id + 1U);
  assert(core.metrics().reacquisition_pending_frames == 3U);
  assert(core.metrics().reacquisition_confirmations == 1U);
}

void test_tracking_only_frames_refresh_identity_without_planning_unsent_moves() {
  MobileControlCore core(production_overwatch_enemy_body_config());
  const std::array first{
      box(260.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  const auto initial = core.process(first, frame(1, 10'000));
  assert(initial.has_target && initial.has_move());
  const auto initial_motion = core.motion_snapshot();
  const auto initial_plans = core.motion_metrics().plans;

  const std::array second{
      box(245.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  const std::array third{
      box(240.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  assert(core.observe_tracking_only(second, frame(2, 26'667)) ==
         ControlSuppressionReason::none);
  assert(core.observe_tracking_only(third, frame(3, 43'334)) ==
         ControlSuppressionReason::none);
  assert(core.motion_metrics().plans == initial_plans);
  assert(core.motion_snapshot().delta_x == initial_motion.delta_x);
  assert(core.metrics().tracking_only_frames == 2);
  assert(core.metrics().tracking_only_lock_updates == 2);
  assert(core.tracker_metrics().first_stage_matches >= 2);

  const auto resumed = core.process(third, frame(4, 60'001));
  assert(resumed.has_target && resumed.lock_id == initial.lock_id);
  assert(!resumed.switched && std::fabs(resumed.target_x - 240.0F) <= 0.75F);
  assert(core.motion_metrics().plans == initial_plans + 1);
}

void test_tracking_only_frames_keep_lock_geometry_current_across_ack_wait() {
  MobileControlCore core(production_overwatch_enemy_body_config());
  const std::array initial_detection{
      box(260.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  const auto initial = core.process(
      initial_detection, frame(1, 10'000U));
  assert(initial.has_target && initial.has_move());
  const std::uint64_t initial_plans = core.motion_metrics().plans;

  // While one physical packet is awaiting completion, every observation is
  // still fresh identity evidence.  Each 15 px step is tracker-admissible,
  // but the cumulative 45 px shift is approaching the control lock gate.
  constexpr std::array<float, 3> tracking_centers{245.0F, 230.0F, 215.0F};
  std::uint64_t sequence = 2U;
  std::uint64_t observed_at_us = 26'667U;
  for (const float center_x : tracking_centers) {
    const std::array detection{
        box(center_x, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
    assert(core.observe_tracking_only(
               detection, frame(sequence, observed_at_us)) ==
           ControlSuppressionReason::none);
    ++sequence;
    observed_at_us += 16'667U;
  }
  assert(core.motion_metrics().plans == initial_plans);
  assert(core.metrics().tracking_only_lock_updates ==
         tracking_centers.size());

  // The total motion from the last planned frame is now 60 px, beyond both
  // lock_match_max_distance_pixels=48 and the OW2 missing-switch jump gate=57.
  // The same exact tracker identity must nevertheless resume immediately,
  // because all intermediate fresh observations were continuous.
  const std::array resumed_detection{
      box(200.0F, 240.0F, 40.0F, 100.0F, 0.90F, 0U)};
  const auto resumed = core.process(
      resumed_detection, frame(sequence, observed_at_us));

  assert(resumed.has_target && !resumed.held && !resumed.switched);
  assert(resumed.lock_id == initial.lock_id);
  assert(resumed.track_id == initial.track_id);
  assert(std::fabs(resumed.target_x - 200.0F) <= 0.75F);
  assert(core.motion_metrics().plans == initial_plans + 1U);
}

void test_overwatch_live_confidence_starts_track_from_clean_state() {
  constexpr float kObservedLiveEnemyConfidence = 0.487856F;
  const auto& tracking =
      vfdual::kOverwatch2Yolov5_416.tracking_confidence;
  assert(kObservedLiveEnemyConfidence >= tracking.new_track_confidence_threshold);

  MobileControlCore core(production_overwatch_enemy_body_config());
  const std::array enemy_body{YoloDetection{
      167.231F,
      8.57041F,
      240.281F,
      130.958F,
      kObservedLiveEnemyConfidence,
      0U,
  }};
  const auto output = core.process(enemy_body, frame(1, 1'000));
  assert(output.has_target && output.track_id != 0U);
  assert(output.source == AimSource::geometric_head);
  assert(output.has_move());
}

void test_overwatch_non_enemy_body_class_is_ignored() {
  MobileControlCore core(overwatch_enemy_body_config());
  const std::array non_enemy_body{
      box(180.0F, 180.0F, 40.0F, 100.0F, 0.99F, 1U)};
  const auto rejected = core.process(non_enemy_body, frame(1, 1'000));
  assert(!rejected.has_target);
  assert(rejected.suppression_reason == ControlSuppressionReason::no_valid_target);
  assert(core.metrics().rejected_unsupported_class == 1U);

  const std::array mixed{
      box(110.0F, 180.0F, 40.0F, 100.0F, 0.99F, 1U),
      box(210.0F, 180.0F, 40.0F, 100.0F, 0.90F, 0U),
  };
  const auto selected = core.process(mixed, frame(2, 2'000));
  assert(selected.has_target && selected.source == AimSource::geometric_head);
  assert(std::fabs(selected.target_x - 210.0F) < 0.001F);
  assert(std::fabs(selected.target_y - 148.0F) < 0.001F);
  assert(core.metrics().rejected_unsupported_class == 2U);
}

void test_delta_crosshair_class_can_be_selected_directly() {
  MobileControlConfig config = algorithm_test_config();
  config.selected_class_id = 4U;
  config.selected_class_uses_head_box = false;
  config.selected_class_uses_geometric_head = false;
  config.head_body_pairing_enabled = false;
  config.body_fallback_y_ratio = 0.50F;
  config.motion.prediction_horizon_ms = 0.0F;
  MobileControlCore core(config);
  const std::array crosshair{box(180.0F, 160.0F, 30.0F, 30.0F, 0.90F, 4U)};
  const auto output = core.process(crosshair, frame(1, 1'000));
  assert(output.has_target && output.source == AimSource::selected_class);
  assert(std::fabs(output.target_x - 180.0F) < 0.001F);
  assert(std::fabs(output.target_y - 160.0F) < 0.001F);
}

}  // namespace

int main() {
  test_default_production_model_contract();
  test_model_production_tuning_is_scoped();
  test_head_priority_body_fallback_and_safe_anchor();
  test_initial_selection_balances_confidence_with_reticle_distance();
  test_parameter_contract_rejects_invalid_anchor_and_rebind_limits();
  test_unrelated_head_cannot_preempt_visible_body_lock();
  test_same_target_paired_head_immediately_upgrades_body_lock();
  test_same_target_head_upgrade_keeps_pursuit_motion_state();
  test_cs2_t_head_contract_rejects_ct_and_preserves_t_identity();
  test_paired_head_identity_survives_body_pair_dropout_and_return();
  test_paired_head_dropout_follows_same_body_without_switching_target();
  test_paired_head_projection_survives_multiframe_motion_and_scale();
  test_real_head_recovery_does_not_invent_reverse_velocity();
  test_paired_head_projection_rejects_implausible_body_jump();
  test_paired_head_projection_rejects_out_of_bounds_head_box();
  test_cs2_dropout_hold_uses_time_not_fresh_frame_count();
  test_near_body_owns_head_despite_neighbour_confidence();
  test_freshness_and_monotonic_frame_guards();
  test_control_tracker_prediction_uses_elapsed_time_across_sequence_gaps();
  test_geometry_filter_and_rejection_metrics();
  test_secondary_validation_pair_and_body_fallback();
  test_implausible_pair_does_not_validate_a_weak_head();
  test_track_id_preserves_identity_when_detection_order_and_rank_change();
  test_control_target_damps_detector_jitter_without_changing_lock();
  test_single_new_track_rebinds_by_giou_without_changing_lock_identity();
  test_unrelated_crowd_target_does_not_make_rebind_ambiguous();
  test_ambiguous_new_tracks_cannot_inherit_the_lock();
  test_head_prediction_is_bounded_to_anchor_lag_and_reports_safe_radius();
  test_iou_association_and_confirmed_switch();
  test_switch_confirmation_uses_observation_time_without_limiting_fps();
  test_switch_confirmation_keeps_one_stable_crowd_challenger();
  test_overwatch_missing_switch_rejects_weak_retained_challenger();
  test_overwatch_missing_switch_rejects_distant_challenger();
  test_overwatch_missing_switch_accepts_near_credible_challenger();
  test_overwatch_pending_switch_cancels_when_confidence_collapses();
  test_overwatch_pending_switch_cancels_after_excessive_drift();
  test_exact_track_id_cannot_bypass_geometry();
  test_visible_ego_motion_keeps_same_lock_geometry();
  test_unseen_acknowledged_move_cannot_stack_another_correction();
  test_single_target_motion_cannot_scale_the_camera_adjustment();
  test_paired_head_and_body_count_as_one_ego_motion_witness();
  test_visible_ego_motion_keeps_nearby_target_tracker_identity_aligned();
  test_common_motion_opposite_to_command_is_not_trusted_as_ego_motion();
  test_unconfirmed_ego_motion_times_out_by_observation_time_without_limiting_fps();
  test_lost_frame_hold_never_replays_motion();
  test_velocity_prediction_is_limited();
  test_pid_limit_anti_windup_residual_and_settle_guard();
  test_overwatch_body_box_can_target_geometric_head();
  test_overwatch_geometric_head_uses_tight_control_radius();
  test_overwatch_closed_loop_is_fast_stable_and_keeps_identity();
  test_overwatch_uncalibrated_response_range_is_fast_and_stable();
  test_overwatch_moving_target_stays_magnetically_bounded();
  test_overwatch_four_frame_dropout_holds_lock_without_blind_motion();
  test_overwatch_dropout_hold_uses_time_not_fresh_frame_count();
  test_overwatch_reacquisition_rejects_one_frame_far_target_yank();
  test_tracking_only_frames_refresh_identity_without_planning_unsent_moves();
  test_tracking_only_frames_keep_lock_geometry_current_across_ack_wait();
  test_overwatch_live_confidence_starts_track_from_clean_state();
  test_overwatch_non_enemy_body_class_is_ignored();
  test_delta_crosshair_class_can_be_selected_directly();
  test_no_target();
  test_repeated_target_loss_and_reappearance_never_sticks_control();
  return 0;
}
