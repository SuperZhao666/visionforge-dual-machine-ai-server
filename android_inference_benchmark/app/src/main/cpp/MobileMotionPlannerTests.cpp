#include "MobileMotionPlanner.hpp"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <limits>

namespace {

using vfdual_android::MobileMotionPhase;
using vfdual_android::MobileMotionPlanner;
using vfdual_android::MobileMotionPlannerConfig;
using vfdual_android::MobileMotionPlannerInput;
using vfdual_android::MotionPlannerSuppressionReason;

MobileMotionPlannerInput observation(
    std::uint64_t sequence, std::uint64_t observed_at_us,
    float error_x, float error_y = 0.0F,
    float velocity_x = 0.0F, float velocity_y = 0.0F,
    float safe_radius = 4.0F, std::uint64_t age_us = 0,
    std::uint64_t target_id = 1) {
  return {
      .target_id = target_id,
      .observation_sequence = sequence,
      .observed_at_us = observed_at_us,
      .now_us = observed_at_us + age_us,
      .error_x = error_x,
      .error_y = error_y,
      .target_velocity_x_pixels_per_second = velocity_x,
      .target_velocity_y_pixels_per_second = velocity_y,
      .safe_radius_pixels = safe_radius,
  };
}

MobileMotionPlannerConfig direct_config() {
  MobileMotionPlannerConfig config{};
  config.response_gain = 1.0F;
  config.response_x_px_per_count = 1.0F;
  config.response_y_px_per_count = 1.0F;
  config.response_upper_x_px_per_count = 1.0F;
  config.response_upper_y_px_per_count = 1.0F;
  config.uncalibrated_maximum_axis_delta = 127;
  config.prediction_horizon_ms = 0.0F;
  config.maximum_prediction_pixels = 0.0F;
  config.deadzone_pixels = 0.0F;
  return config;
}

void test_parameter_contract_rejects_non_finite_and_inconsistent_values() {
  MobileMotionPlanner planner;
  assert(planner.configure(MobileMotionPlannerConfig{}));

  MobileMotionPlannerConfig non_finite{};
  non_finite.response_gain =
      std::numeric_limits<float>::quiet_NaN();
  assert(!planner.configure(non_finite));

  MobileMotionPlannerConfig inverted_response{};
  inverted_response.response_x_px_per_count = 2.0F;
  inverted_response.response_upper_x_px_per_count = 1.0F;
  assert(!planner.configure(inverted_response));

  MobileMotionPlannerConfig invalid_jerk{};
  invalid_jerk.maximum_step_counts_per_tick = 2.0F;
  invalid_jerk.maximum_jerk_counts_per_tick2 = 3.0F;
  assert(!planner.configure(invalid_jerk));

  MobileMotionPlannerConfig zero_gain{};
  zero_gain.response_gain = 0.0F;
  assert(!planner.configure(zero_gain));

  MobileMotionPlannerConfig invalid_settle_frequency{};
  invalid_settle_frequency.settle_natural_frequency_rad_s = 0.0F;
  assert(!planner.configure(invalid_settle_frequency));

  MobileMotionPlannerConfig invalid_stop_hysteresis{};
  invalid_stop_hysteresis.settle_stop_exit_response_multiple = 2.1F;
  assert(!planner.configure(invalid_stop_hysteresis));
}

void test_input_freshness_nan_and_monotonic_guards() {
  MobileMotionPlannerConfig config{};
  config.maximum_observation_age_us = 50'000;
  MobileMotionPlanner planner(config);

  auto invalid_target = observation(1, 10'000, 20.0F);
  invalid_target.target_id = 0;
  assert(planner.plan(invalid_target).suppression_reason ==
         MotionPlannerSuppressionReason::invalid_input);

  auto nan_error = observation(1, 10'000, 20.0F);
  nan_error.error_x = std::numeric_limits<float>::quiet_NaN();
  assert(planner.plan(nan_error).suppression_reason ==
         MotionPlannerSuppressionReason::invalid_input);

  auto invalid_time = observation(1, 10'000, 20.0F);
  invalid_time.now_us = 9'999;
  assert(planner.plan(invalid_time).suppression_reason ==
         MotionPlannerSuppressionReason::invalid_time);

  assert(planner.plan(observation(1, 100'000, 20.0F, 0.0F, 0.0F, 0.0F,
                                  4.0F, 50'001))
             .suppression_reason ==
         MotionPlannerSuppressionReason::stale_observation);

  assert(planner.plan(observation(1, 200'000, 20.0F)).phase ==
         MobileMotionPhase::acquire);
  assert(planner.plan(observation(1, 210'000, 20.0F)).suppression_reason ==
         MotionPlannerSuppressionReason::non_monotonic_observation);
  assert(planner.plan(observation(2, 220'000, 20.0F, 0.0F, 0.0F, 0.0F,
                                  4.0F, 0))
             .phase != MobileMotionPhase::settle);

  auto backwards_now = observation(3, 230'000, 20.0F);
  backwards_now.now_us = 219'999;
  assert(planner.plan(backwards_now).suppression_reason ==
         MotionPlannerSuppressionReason::invalid_time);

  const auto& metrics = planner.metrics();
  assert(metrics.invalid_inputs == 2);
  assert(metrics.invalid_times == 2);
  assert(metrics.stale_observations == 1);
  assert(metrics.non_monotonic_observations == 1);
}

void test_phase_hysteresis() {
  MobileMotionPlannerConfig config = direct_config();
  config.pursuit_minimum_lock_ms = 20.0F;
  MobileMotionPlanner planner(config);

  assert(planner.plan(observation(1, 10'000, 20.0F, 0.0F, 0.0F, 0.0F, 4.0F))
             .phase == MobileMotionPhase::acquire);
  assert(planner.plan(observation(2, 40'000, 20.0F, 0.0F, 0.0F, 0.0F, 4.0F))
             .phase == MobileMotionPhase::pursuit);
  assert(planner.plan(observation(3, 50'000, 3.0F, 0.0F, 0.0F, 0.0F, 4.0F))
             .phase == MobileMotionPhase::settle);
  assert(planner.plan(observation(4, 60'000, 5.0F, 0.0F, 0.0F, 0.0F, 4.0F))
             .phase == MobileMotionPhase::settle);
  assert(planner.plan(observation(5, 70'000, 7.0F, 0.0F, 0.0F, 0.0F, 4.0F))
             .phase == MobileMotionPhase::pursuit);
}

void test_response_budget_and_residual_quantization() {
  MobileMotionPlannerConfig guarded = direct_config();
  guarded.response_gain = 1.0F;
  guarded.response_upper_x_px_per_count = 8.0F;
  guarded.response_upper_y_px_per_count = 8.0F;
  guarded.uncalibrated_maximum_axis_delta = 12;
  MobileMotionPlanner guarded_planner(guarded);
  const auto far = guarded_planner.plan(
      observation(1, 10'000, 100.0F, 0.0F, 0.0F, 0.0F, 1.0F));
  assert(far.delta_x == 11);
  assert(far.response_limited);
  assert(far.response_budget_x_counts == 11.0F);

  const auto near = guarded_planner.plan(
      observation(2, 20'000, 4.0F, 0.0F, 0.0F, 0.0F, 1.0F));
  assert(!near.has_move());
  assert(near.suppression_reason ==
         MotionPlannerSuppressionReason::subcount_resolution);
  assert(guarded_planner.metrics().subcount_resolution_suppressions == 1U);

  MobileMotionPlannerConfig residual = direct_config();
  residual.response_gain = 0.10F;
  MobileMotionPlanner residual_planner(residual);
  assert(residual_planner.plan(
             observation(1, 10'000, 4.0F, 0.0F, 0.0F, 0.0F, 1.0F))
             .delta_x == 0);
  assert(residual_planner.plan(
             observation(2, 20'000, 4.0F, 0.0F, 0.0F, 0.0F, 1.0F))
             .delta_x == 1);
}

void test_pursuit_step_and_jerk_limits_are_deterministic() {
  MobileMotionPlannerConfig config = direct_config();
  config.pursuit_minimum_lock_ms = 10.0F;
  config.maximum_step_counts_per_tick = 4.0F;
  config.maximum_jerk_counts_per_tick2 = 2.0F;
  config.direction_change_minimum_error_pixels = 1'000.0F;
  MobileMotionPlanner planner(config);

  const auto acquire = planner.plan(
      observation(1, 10'000, 10.0F, 0.0F, 0.0F, 0.0F, 1.0F));
  assert(acquire.phase == MobileMotionPhase::acquire);
  assert(acquire.delta_x == 9);

  const auto pursuit = planner.plan(
      observation(2, 20'000, 100.0F, 0.0F, 0.0F, 0.0F, 1.0F));
  assert(pursuit.phase == MobileMotionPhase::pursuit);
  assert(pursuit.delta_x == 11);
  assert(pursuit.step_limited && pursuit.jerk_limited);
}

void test_velocity_acceleration_prediction_and_box_bounds() {
  MobileMotionPlannerConfig config = direct_config();
  config.acceleration_update_alpha = 1.0F;
  config.maximum_acceleration_pixels_per_second2 = 10'000.0F;
  config.prediction_horizon_ms = 20.0F;
  config.maximum_prediction_pixels = 100.0F;
  MobileMotionPlanner planner(config);

  const auto first = planner.plan(
      observation(1, 10'000, 20.0F, 0.0F, 0.0F, 0.0F, 1.0F));
  assert(std::fabs(first.predicted_error_x - 20.0F) < 0.001F);

  const auto accelerated = planner.plan(
      observation(2, 20'000, 20.0F, 0.0F, 100.0F, 0.0F, 1.0F));
  assert(std::fabs(
             accelerated.target_acceleration_x_pixels_per_second2 -
             10'000.0F) < 0.01F);
  assert(std::fabs(accelerated.predicted_error_x - 24.0F) < 0.01F);

  auto bounded = observation(
      3, 30'000, 20.0F, 0.0F, 1'000.0F, 0.0F, 1.0F);
  bounded.prediction_bounds_enabled = true;
  bounded.prediction_min_error_x = -30.0F;
  bounded.prediction_max_error_x = 25.0F;
  bounded.prediction_min_error_y = -10.0F;
  bounded.prediction_max_error_y = 10.0F;
  assert(std::fabs(planner.plan(bounded).predicted_error_x - 25.0F) <
         0.001F);
  assert(planner.last_output().prediction_limited);
  assert(planner.metrics().prediction_limited_axes == 1);

  auto invalid_bounds = observation(4, 40'000, 20.0F);
  invalid_bounds.prediction_bounds_enabled = true;
  invalid_bounds.prediction_min_error_x = 1.0F;
  invalid_bounds.prediction_max_error_x = -1.0F;
  assert(planner.plan(invalid_bounds).suppression_reason ==
         MotionPlannerSuppressionReason::invalid_input);
}

void test_direction_flip_reorients_without_dropping_observation() {
  MobileMotionPlannerConfig direction = direct_config();
  direction.direction_change_minimum_error_pixels = 8.0F;
  MobileMotionPlanner direction_planner(direction);
  assert(direction_planner.plan(
             observation(1, 10'000, 20.0F, 0.0F, 0.0F, 0.0F, 1.0F))
             .has_move());
  const auto flipped = direction_planner.plan(
      observation(2, 20'000, -20.0F, 0.0F, 0.0F, 0.0F, 1.0F));
  assert(flipped.delta_x < 0);
  assert(flipped.suppression_reason == MotionPlannerSuppressionReason::none);
  assert(direction_planner.metrics().direction_flip_suppressions == 0);
  assert(direction_planner.metrics().direction_reorientations == 1);

  MobileMotionPlannerConfig settle = direct_config();
  settle.direction_change_minimum_error_pixels = 8.0F;
  MobileMotionPlanner settle_planner(settle);
  assert(settle_planner.plan(
             observation(1, 10'000, 6.0F, 0.0F, 0.0F, 0.0F, 10.0F))
             .delta_x > 0);
  const auto crossed = settle_planner.plan(
      observation(2, 20'000, -4.0F, 0.0F, 0.0F, 0.0F, 10.0F));
  assert(!crossed.has_move());
  assert(crossed.suppression_reason ==
         MotionPlannerSuppressionReason::settle_guard);
}

void test_visible_ego_shift_aligns_retained_error_state() {
  MobileMotionPlanner planner(direct_config());
  assert(planner.plan(
             observation(1, 10'000, 20.0F, 0.0F, 0.0F, 0.0F, 1.0F))
             .delta_x > 0);

  // A completed rightward camera move makes the same target appear 40 pixels
  // left. Align the retained error before accepting that visible frame.
  planner.apply_visible_error_shift(-40.0F, 0.0F);
  const auto visible = planner.plan(
      observation(2, 20'000, -20.0F, 0.0F, 0.0F, 0.0F, 1.0F));
  assert(visible.delta_x < 0);
  assert(visible.suppression_reason == MotionPlannerSuppressionReason::none);
  assert(planner.metrics().direction_reorientations == 0);
}

void test_settle_inner_stop_latch_and_exit_hysteresis() {
  MobileMotionPlannerConfig config = direct_config();
  config.settle_inner_radius_fraction = 0.50F;
  config.settle_inner_radius_response_multiple = 1.25F;
  config.settle_stop_exit_response_multiple = 0.25F;
  MobileMotionPlanner planner(config);

  const auto stopped = planner.plan(
      observation(1, 10'000, 5.0F, 0.0F, 0.0F, 0.0F, 10.0F));
  assert(stopped.phase == MobileMotionPhase::settle);
  assert(stopped.settle_stopped && !stopped.has_move());
  assert(stopped.suppression_reason ==
         MotionPlannerSuppressionReason::settle_guard);

  const auto held = planner.plan(
      observation(2, 20'000, 5.2F, 0.0F, 0.0F, 0.0F, 10.0F));
  assert(held.settle_stopped && !held.has_move());
  const auto released = planner.plan(
      observation(3, 30'000, 5.3F, 0.0F, 0.0F, 0.0F, 10.0F));
  assert(!released.settle_stopped && released.delta_x > 0);
  assert(planner.metrics().settle_stop_latches == 1);
  assert(planner.metrics().settle_stop_holds == 1);
}

void test_critical_settle_pd_brakes_a_closing_target() {
  MobileMotionPlannerConfig config = direct_config();
  config.response_x_px_per_count = 0.1F;
  config.response_y_px_per_count = 0.1F;
  config.response_upper_x_px_per_count = 0.1F;
  config.response_upper_y_px_per_count = 0.1F;
  config.settle_maximum_axis_delta = 127;
  MobileMotionPlanner baseline(config);
  MobileMotionPlanner closing(config);

  (void)baseline.plan(
      observation(1, 10'000, 30.0F, 0.0F, 0.0F, 0.0F, 20.0F));
  (void)closing.plan(
      observation(1, 10'000, 30.0F, 0.0F, 0.0F, 0.0F, 20.0F));
  const auto baseline_packet = baseline.plan(
      observation(2, 20'000, 19.0F, 0.0F, 0.0F, 0.0F, 20.0F));
  const auto closing_packet = closing.plan(
      observation(2, 20'000, 19.0F, 0.0F, -30.0F, 0.0F, 20.0F));
  assert(baseline_packet.delta_x > 0);
  assert(closing_packet.delta_x > 0);
  assert(closing_packet.delta_x < baseline_packet.delta_x);
  assert(closing_packet.response_budget_x_counts <= 127.0F);
}

void test_settle_radial_quantization_preserves_diagonal_progress() {
  MobileMotionPlannerConfig config = direct_config();
  config.settle_inner_radius_fraction = 0.50F;
  config.settle_inner_radius_response_multiple = 1.25F;
  MobileMotionPlanner planner(config);

  const auto diagonal = planner.plan(
      observation(1, 10'000, 3.0F, 3.0F, 0.0F, 0.0F, 5.0F));
  assert(diagonal.phase == MobileMotionPhase::settle);
  assert(!diagonal.settle_stopped);
  assert(diagonal.has_move());
  assert(std::abs(diagonal.delta_x) + std::abs(diagonal.delta_y) == 1);
  assert(diagonal.delta_x >= 0 && diagonal.delta_y >= 0);
  assert(planner.metrics().settle_quantization_rescues == 1);
}

void test_new_target_clears_settle_stop_latch() {
  MobileMotionPlanner planner(direct_config());
  const auto stopped = planner.plan(
      observation(1, 10'000, 5.0F, 0.0F, 0.0F, 0.0F, 10.0F, 0, 7));
  assert(stopped.settle_stopped);
  const auto new_target = planner.plan(
      observation(2, 20'000, 8.0F, 0.0F, 0.0F, 0.0F, 10.0F, 0, 8));
  assert(!new_target.settle_stopped);
  assert(new_target.delta_x > 0);
}

void test_target_change_resets_reversal_and_kinematic_state() {
  MobileMotionPlanner planner(direct_config());
  assert(planner.plan(
             observation(1, 10'000, 20.0F, 0.0F, 0.0F, 0.0F, 1.0F))
             .has_move());
  const auto new_target = planner.plan(
      observation(2, 20'000, -20.0F, 0.0F, 0.0F, 0.0F, 1.0F, 0, 2));
  assert(new_target.phase == MobileMotionPhase::acquire);
  assert(new_target.suppression_reason !=
         MotionPlannerSuppressionReason::direction_flip);
  assert(new_target.delta_x < 0);
}

void test_personal_profile_shapes_only_pursuit_and_remains_bounded() {
  MobileMotionPlannerConfig baseline_config = direct_config();
  baseline_config.maximum_step_counts_per_tick = 127.0F;
  baseline_config.maximum_jerk_counts_per_tick2 = 127.0F;
  MobileMotionPlanner baseline(baseline_config);

  MobileMotionPlannerConfig personal_config = baseline_config;
  personal_config.personal_trajectory_enabled = true;
  personal_config.personal_profile_seed = 0x1234U;
  personal_config.personal_speed_scale = 1.223F;
  personal_config.personal_stability_scale = 1.266F;
  personal_config.personal_variation_scale = 0.679F;
  personal_config.personal_median_duration_ms = 539.848F;
  personal_config.personal_peak_time_fraction = 0.38726F;
  personal_config.personal_bell_correlation = 0.44F;
  personal_config.personal_jitter_amplitude_pixels = 0.85F;
  personal_config.personal_jitter_maximum_pixels = 3.5F;
  personal_config.personal_maximum_extra_counts = 2;
  personal_config.personal_minimum_error_pixels = 24.0F;
  personal_config.personal_speed_envelope = {
      0.17232F, 0.24439F, 0.40611F, 0.65890F,
      0.97757F, 1.00000F, 0.92441F, 0.86369F,
      0.62419F, 0.48713F, 0.37127F, 0.23917F,
      0.19919F, 0.13661F, 0.14717F, 0.21239F};
  personal_config.personal_speed_envelope_count = 16;
  MobileMotionPlanner personal(personal_config);

  const auto first_baseline = baseline.plan(
      observation(1, 10'000, 60.0F, 15.0F));
  const auto first_personal = personal.plan(
      observation(1, 10'000, 60.0F, 15.0F));
  assert(first_baseline.phase == MobileMotionPhase::acquire);
  assert(first_baseline.delta_x == first_personal.delta_x);
  assert(first_baseline.delta_y == first_personal.delta_y);
  assert(!first_personal.personal_trajectory_applied);

  const auto pursuit_baseline = baseline.plan(
      observation(2, 210'000, 60.0F, 15.0F));
  const auto pursuit_personal = personal.plan(
      observation(2, 210'000, 60.0F, 15.0F));
  assert(pursuit_personal.phase == MobileMotionPhase::pursuit);
  assert(pursuit_personal.personal_trajectory_applied);
  assert(std::abs(pursuit_personal.delta_x - pursuit_baseline.delta_x) <= 2);
  assert(std::abs(pursuit_personal.delta_y - pursuit_baseline.delta_y) <= 2);
  assert(pursuit_personal.delta_x >= pursuit_baseline.delta_x);
  assert(personal.metrics().personal_trajectory_plans == 1);
}

}  // namespace

int main() {
  test_parameter_contract_rejects_non_finite_and_inconsistent_values();
  test_input_freshness_nan_and_monotonic_guards();
  test_phase_hysteresis();
  test_response_budget_and_residual_quantization();
  test_pursuit_step_and_jerk_limits_are_deterministic();
  test_velocity_acceleration_prediction_and_box_bounds();
  test_direction_flip_reorients_without_dropping_observation();
  test_visible_ego_shift_aligns_retained_error_state();
  test_settle_inner_stop_latch_and_exit_hysteresis();
  test_critical_settle_pd_brakes_a_closing_target();
  test_settle_radial_quantization_preserves_diagonal_progress();
  test_new_target_clears_settle_stop_latch();
  test_target_change_resets_reversal_and_kinematic_state();
  test_personal_profile_shapes_only_pursuit_and_remains_bounded();
  return 0;
}
