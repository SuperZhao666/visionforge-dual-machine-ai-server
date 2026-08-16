#include "MobileMotionPlanner.hpp"

#include <algorithm>
#include <cmath>
#include <iterator>
#include <limits>

namespace vfdual_android {
namespace {

float clamp_magnitude(float value, float maximum) noexcept {
  return std::clamp(value, -maximum, maximum);
}

bool same_sign_or_zero(float left, float right) noexcept {
  return left == 0.0F || right == 0.0F ||
      std::signbit(left) == std::signbit(right);
}

}  // namespace

const char* mobile_motion_phase_name(MobileMotionPhase phase) noexcept {
  switch (phase) {
    case MobileMotionPhase::acquire: return "acquire";
    case MobileMotionPhase::pursuit: return "pursuit";
    case MobileMotionPhase::settle: return "settle";
  }
  return "unknown";
}

const char* motion_planner_suppression_name(
    MotionPlannerSuppressionReason reason) noexcept {
  switch (reason) {
    case MotionPlannerSuppressionReason::none: return "none";
    case MotionPlannerSuppressionReason::invalid_input: return "invalid_input";
    case MotionPlannerSuppressionReason::invalid_time: return "invalid_time";
    case MotionPlannerSuppressionReason::stale_observation: return "stale_observation";
    case MotionPlannerSuppressionReason::non_monotonic_observation:
      return "non_monotonic_observation";
    case MotionPlannerSuppressionReason::deadzone: return "deadzone";
    case MotionPlannerSuppressionReason::direction_flip: return "direction_flip";
    case MotionPlannerSuppressionReason::response_guard: return "response_guard";
    case MotionPlannerSuppressionReason::subcount_resolution:
      return "subcount_resolution";
    case MotionPlannerSuppressionReason::settle_guard: return "settle_guard";
  }
  return "unknown";
}

MobileMotionPlanner::MobileMotionPlanner(
    const MobileMotionPlannerConfig& config) {
  (void)configure(config);
}

bool MobileMotionPlanner::valid_config(
    const MobileMotionPlannerConfig& config) noexcept {
  const float values[] = {
      config.response_gain,
      config.response_x_px_per_count,
      config.response_y_px_per_count,
      config.response_upper_x_px_per_count,
      config.response_upper_y_px_per_count,
      config.response_step_fraction,
      config.response_settle_fraction,
      config.prediction_horizon_ms,
      config.maximum_prediction_pixels,
      config.maximum_target_velocity_pixels_per_second,
      config.acceleration_update_alpha,
      config.maximum_acceleration_pixels_per_second2,
      config.pursuit_minimum_lock_ms,
      config.settle_enter_radius_fraction,
      config.settle_exit_radius_fraction,
      config.settle_minimum_radius_pixels,
      config.settle_natural_frequency_rad_s,
      config.settle_inner_radius_fraction,
      config.settle_inner_radius_response_multiple,
      config.settle_stop_exit_response_multiple,
      config.pid_ki,
      config.pid_kd,
      config.pid_integral_limit,
      config.pid_derivative_alpha,
      config.pid_minimum_dt_ms,
      config.pid_maximum_dt_ms,
      config.residual_limit,
      config.deadzone_pixels,
      config.maximum_step_counts_per_tick,
      config.maximum_jerk_counts_per_tick2,
      config.direction_change_cosine,
      config.direction_change_minimum_error_pixels,
      config.personal_speed_scale,
      config.personal_stability_scale,
      config.personal_variation_scale,
      config.personal_median_duration_ms,
      config.personal_peak_time_fraction,
      config.personal_bell_correlation,
      config.personal_jitter_amplitude_pixels,
      config.personal_jitter_maximum_pixels,
      config.personal_minimum_error_pixels,
  };
  if (!std::all_of(
          std::begin(values), std::end(values),
          [](float value) { return std::isfinite(value); })) {
    return false;
  }
  return config.maximum_observation_age_us > 0 &&
      config.response_gain > 0.0F && config.response_gain <= 8.0F &&
      config.response_x_px_per_count >= 0.001F &&
      config.response_y_px_per_count >= 0.001F &&
      config.response_upper_x_px_per_count >= config.response_x_px_per_count &&
      config.response_upper_y_px_per_count >= config.response_y_px_per_count &&
      config.response_upper_x_px_per_count <= 32.0F &&
      config.response_upper_y_px_per_count <= 32.0F &&
      config.response_step_fraction > 0.0F &&
      config.response_step_fraction <= 1.0F &&
      config.response_settle_fraction > 0.0F &&
      config.response_settle_fraction <= 1.0F &&
      config.uncalibrated_maximum_axis_delta > 0 &&
      config.uncalibrated_maximum_axis_delta <= config.maximum_axis_delta &&
      config.prediction_horizon_ms >= 0.0F &&
      config.maximum_prediction_pixels >= 0.0F &&
      config.maximum_target_velocity_pixels_per_second >= 0.0F &&
      config.acceleration_update_alpha >= 0.0F &&
      config.acceleration_update_alpha <= 1.0F &&
      config.maximum_acceleration_pixels_per_second2 >= 0.0F &&
      config.pursuit_minimum_lock_ms >= 0.0F &&
      config.settle_enter_radius_fraction > 0.0F &&
      config.settle_exit_radius_fraction >= config.settle_enter_radius_fraction &&
      config.settle_minimum_radius_pixels > 0.0F &&
      config.settle_natural_frequency_rad_s >= 1.0F &&
      config.settle_natural_frequency_rad_s <= 200.0F &&
      config.settle_inner_radius_fraction > 0.0F &&
      config.settle_inner_radius_fraction <= 1.0F &&
      config.settle_inner_radius_response_multiple >= 0.5F &&
      config.settle_inner_radius_response_multiple <= 4.0F &&
      config.settle_stop_exit_response_multiple >= 0.0F &&
      config.settle_stop_exit_response_multiple <= 2.0F &&
      config.pid_ki >= 0.0F && config.pid_kd >= 0.0F &&
      config.pid_integral_limit >= 0.0F &&
      config.pid_derivative_alpha >= 0.0F &&
      config.pid_derivative_alpha <= 1.0F &&
      config.pid_minimum_dt_ms > 0.0F &&
      config.pid_maximum_dt_ms >= config.pid_minimum_dt_ms &&
      config.residual_limit >= 0.0F && config.deadzone_pixels >= 0.0F &&
      config.settle_maximum_axis_delta > 0 &&
      config.settle_maximum_axis_delta <= config.maximum_axis_delta &&
      config.maximum_axis_delta > 0 && config.maximum_axis_delta <= 127 &&
      config.maximum_step_counts_per_tick > 0.0F &&
      config.maximum_step_counts_per_tick <=
          static_cast<float>(config.maximum_axis_delta) &&
      config.maximum_jerk_counts_per_tick2 > 0.0F &&
      config.maximum_jerk_counts_per_tick2 <=
          config.maximum_step_counts_per_tick &&
      config.direction_change_cosine >= -1.0F &&
      config.direction_change_cosine <= 1.0F &&
      config.direction_change_minimum_error_pixels >= 0.0F &&
      config.personal_speed_scale >= 0.5F &&
      config.personal_speed_scale <= 1.5F &&
      config.personal_stability_scale >= 0.5F &&
      config.personal_stability_scale <= 1.5F &&
      config.personal_variation_scale >= 0.5F &&
      config.personal_variation_scale <= 1.5F &&
      config.personal_median_duration_ms >= 120.0F &&
      config.personal_median_duration_ms <= 1'200.0F &&
      config.personal_peak_time_fraction >= 0.1F &&
      config.personal_peak_time_fraction <= 0.9F &&
      config.personal_bell_correlation >= 0.0F &&
      config.personal_bell_correlation <= 1.0F &&
      config.personal_jitter_amplitude_pixels >= 0.0F &&
      config.personal_jitter_amplitude_pixels <= 1.2F &&
      config.personal_jitter_maximum_pixels >= 0.0F &&
      config.personal_jitter_maximum_pixels <= 4.5F &&
      config.personal_maximum_extra_counts >= 0 &&
      config.personal_maximum_extra_counts <= 8 &&
      config.personal_minimum_error_pixels >= 0.0F &&
      config.personal_speed_envelope_count <=
          MobileMotionPlannerConfig::kPersonalEnvelopePoints &&
      (!config.personal_trajectory_enabled ||
       config.personal_speed_envelope_count ==
           MobileMotionPlannerConfig::kPersonalEnvelopePoints) &&
      std::all_of(
          config.personal_speed_envelope.begin(),
          config.personal_speed_envelope.begin() +
              static_cast<std::ptrdiff_t>(config.personal_speed_envelope_count),
          [](float value) {
            return std::isfinite(value) && value >= 0.0F && value <= 2.0F;
          });
}

bool MobileMotionPlanner::configure(
    const MobileMotionPlannerConfig& config) {
  if (!valid_config(config)) return false;
  config_ = config;
  reset_motion();
  return true;
}

void MobileMotionPlanner::reset_packet_state() noexcept {
  x_axis_ = {};
  y_axis_ = {};
  jerk_x_ = {};
  jerk_y_ = {};
}

void MobileMotionPlanner::reset_target(
    std::uint64_t target_id, std::uint64_t now_us) noexcept {
  target_id_ = target_id;
  lock_started_at_us_ = now_us;
  phase_started_at_us_ = now_us;
  phase_ = MobileMotionPhase::acquire;
  previous_velocity_x_ = 0.0F;
  previous_velocity_y_ = 0.0F;
  acceleration_x_ = 0.0F;
  acceleration_y_ = 0.0F;
  previous_error_x_ = 0.0F;
  previous_error_y_ = 0.0F;
  has_previous_error_ = false;
  settle_stopped_ = false;
  personal_noise_state_ = 0.0F;
  personal_rng_state_ = config_.personal_profile_seed ^
      (target_id + 0x9e3779b97f4a7c15ULL);
  if (personal_rng_state_ == 0U) {
    personal_rng_state_ = 0x9e3779b97f4a7c15ULL;
  }
  reset_packet_state();
}

void MobileMotionPlanner::reset_motion() noexcept {
  last_output_ = {};
  target_id_ = 0;
  lock_started_at_us_ = 0;
  phase_started_at_us_ = 0;
  last_observation_sequence_ = 0;
  last_observed_at_us_ = 0;
  last_now_us_ = 0;
  has_observation_ = false;
  reset_target(0, 0);
}

void MobileMotionPlanner::apply_visible_error_shift(
    float shift_x, float shift_y) noexcept {
  if (!std::isfinite(shift_x) || !std::isfinite(shift_y)) return;
  if (has_previous_error_) {
    previous_error_x_ += shift_x;
    previous_error_y_ += shift_y;
  }
  if (x_axis_.initialized) x_axis_.previous_error += shift_x;
  if (y_axis_.initialized) y_axis_.previous_error += shift_y;
  if (target_id_ != 0U) {
    last_output_.predicted_error_x += shift_x;
    last_output_.predicted_error_y += shift_y;
  }
}

MobileMotionPlannerOutput MobileMotionPlanner::suppress(
    MotionPlannerSuppressionReason reason) noexcept {
  last_output_ = {
      .target_acceleration_x_pixels_per_second2 = acceleration_x_,
      .target_acceleration_y_pixels_per_second2 = acceleration_y_,
      .phase = phase_,
      .suppression_reason = reason,
  };
  return last_output_;
}

void MobileMotionPlanner::update_acceleration(
    const MobileMotionPlannerInput& input, bool target_changed) noexcept {
  const float velocity_x = clamp_magnitude(
      input.target_velocity_x_pixels_per_second,
      config_.maximum_target_velocity_pixels_per_second);
  const float velocity_y = clamp_magnitude(
      input.target_velocity_y_pixels_per_second,
      config_.maximum_target_velocity_pixels_per_second);
  if (target_changed || !has_observation_ ||
      input.observed_at_us <= last_observed_at_us_) {
    previous_velocity_x_ = velocity_x;
    previous_velocity_y_ = velocity_y;
    acceleration_x_ = 0.0F;
    acceleration_y_ = 0.0F;
    return;
  }
  const float dt = static_cast<float>(
      input.observed_at_us - last_observed_at_us_) / 1'000'000.0F;
  const float raw_x =
      (velocity_x - previous_velocity_x_) / dt;
  const float raw_y =
      (velocity_y - previous_velocity_y_) / dt;
  const float alpha = config_.acceleration_update_alpha;
  acceleration_x_ = clamp_magnitude(
      acceleration_x_ * (1.0F - alpha) + raw_x * alpha,
      config_.maximum_acceleration_pixels_per_second2);
  acceleration_y_ = clamp_magnitude(
      acceleration_y_ * (1.0F - alpha) + raw_y * alpha,
      config_.maximum_acceleration_pixels_per_second2);
  previous_velocity_x_ = velocity_x;
  previous_velocity_y_ = velocity_y;
}

MobileMotionPhase MobileMotionPlanner::update_phase(
    const MobileMotionPlannerInput& input, float predicted_length,
    float safe_radius) noexcept {
  const float enter_radius = std::max(
      config_.settle_minimum_radius_pixels,
      safe_radius * config_.settle_enter_radius_fraction);
  const float exit_radius = std::max(
      enter_radius, safe_radius * config_.settle_exit_radius_fraction);
  const float lock_age_ms = input.now_us >= lock_started_at_us_
      ? static_cast<float>(input.now_us - lock_started_at_us_) / 1'000.0F
      : 0.0F;
  MobileMotionPhase next = MobileMotionPhase::acquire;
  if (phase_ == MobileMotionPhase::settle &&
      predicted_length <= exit_radius) {
    next = MobileMotionPhase::settle;
  } else if (predicted_length <= enter_radius) {
    next = MobileMotionPhase::settle;
  } else if (lock_age_ms >= config_.pursuit_minimum_lock_ms) {
    next = MobileMotionPhase::pursuit;
  }
  if (next != phase_) {
    phase_ = next;
    phase_started_at_us_ = input.now_us;
    if (phase_ != MobileMotionPhase::settle) settle_stopped_ = false;
  }
  return phase_;
}

bool MobileMotionPlanner::direction_changed(
    const MobileMotionPlannerInput& input, bool target_changed) noexcept {
  const float current_length = std::hypot(input.error_x, input.error_y);
  bool changed = false;
  if (!target_changed && has_previous_error_) {
    const float previous_length =
        std::hypot(previous_error_x_, previous_error_y_);
    if (previous_length >= config_.direction_change_minimum_error_pixels &&
        current_length >= config_.direction_change_minimum_error_pixels) {
      const float cosine =
          (previous_error_x_ * input.error_x +
           previous_error_y_ * input.error_y) /
          std::max(previous_length * current_length,
                   std::numeric_limits<float>::epsilon());
      changed = cosine < config_.direction_change_cosine;
    }
  }
  previous_error_x_ = input.error_x;
  previous_error_y_ = input.error_y;
  has_previous_error_ = true;
  return changed;
}

float MobileMotionPlanner::predicted_axis(
    float error, float velocity, float acceleration,
    float age_seconds) const noexcept {
  const float horizon_seconds =
      age_seconds + config_.prediction_horizon_ms / 1'000.0F;
  const float offset =
      velocity * horizon_seconds +
      0.5F * acceleration * horizon_seconds * horizon_seconds;
  return error + clamp_magnitude(
      offset, config_.maximum_prediction_pixels);
}

float MobileMotionPlanner::response_budget(
    float predicted_error, float response_upper,
    MobileMotionPhase phase) const noexcept {
  const float fraction = phase == MobileMotionPhase::settle
      ? config_.response_settle_fraction
      : config_.response_step_fraction;
  const float geometric_budget =
      std::floor(std::fabs(predicted_error) * fraction / response_upper);
  return std::max(
      0.0F,
      std::min(
          geometric_budget,
          static_cast<float>(config_.uncalibrated_maximum_axis_delta)));
}

std::int32_t MobileMotionPlanner::pid_axis(
    float predicted_error, float response_px_per_count, float budget_counts,
    std::uint64_t now_us, MobileMotionPhase phase, AxisState& state,
    bool& response_limited, bool& settle_limited) noexcept {
  if (std::fabs(predicted_error) <= config_.deadzone_pixels) {
    state = {};
    return 0;
  }
  if (state.initialized &&
      !same_sign_or_zero(predicted_error, state.previous_error) &&
      phase == MobileMotionPhase::settle) {
    state = {};
    settle_limited = true;
    return 0;
  }

  const float minimum_dt = config_.pid_minimum_dt_ms / 1'000.0F;
  const float maximum_dt = config_.pid_maximum_dt_ms / 1'000.0F;
  const float elapsed =
      state.initialized && now_us > state.previous_time_us
      ? static_cast<float>(now_us - state.previous_time_us) / 1'000'000.0F
      : minimum_dt;
  const float dt = std::clamp(elapsed, minimum_dt, maximum_dt);
  const float normalized_error = predicted_error / response_px_per_count;
  const float previous_normalized_error =
      state.previous_error / response_px_per_count;
  const float raw_derivative = state.initialized
      ? (normalized_error - previous_normalized_error) / dt
      : 0.0F;
  state.derivative =
      state.derivative * config_.pid_derivative_alpha +
      raw_derivative * (1.0F - config_.pid_derivative_alpha);

  float proposed_integral = state.integral;
  if (config_.pid_ki > 0.0F) {
    proposed_integral = clamp_magnitude(
        state.integral + normalized_error * dt,
        config_.pid_integral_limit);
  } else {
    proposed_integral = 0.0F;
  }
  const auto pid_value = [&](float integral) {
    return config_.response_gain * normalized_error +
        config_.pid_ki * integral +
        config_.pid_kd * state.derivative;
  };
  const float maximum_output =
      static_cast<float>(config_.maximum_axis_delta);
  float raw_output = pid_value(proposed_integral);
  if (std::fabs(raw_output) <= maximum_output ||
      !same_sign_or_zero(raw_output, normalized_error)) {
    state.integral = proposed_integral;
  } else {
    raw_output = pid_value(state.integral);
  }

  float shaped = clamp_magnitude(raw_output + state.residual, maximum_output);
  const float pre_response_guard = shaped;
  shaped = clamp_magnitude(shaped, budget_counts);
  response_limited = std::fabs(shaped - pre_response_guard) > 1.0e-6F;
  if (phase == MobileMotionPhase::settle) {
    const float before_settle = shaped;
    shaped = clamp_magnitude(
        shaped, static_cast<float>(config_.settle_maximum_axis_delta));
    settle_limited = settle_limited ||
        std::fabs(shaped - before_settle) > 1.0e-6F;
  }
  if (!same_sign_or_zero(shaped, predicted_error)) {
    state = {};
    settle_limited = true;
    return 0;
  }

  const std::int32_t rounded = std::clamp(
      static_cast<std::int32_t>(std::lround(shaped)),
      -config_.maximum_axis_delta, config_.maximum_axis_delta);
  state.residual = clamp_magnitude(
      shaped - static_cast<float>(rounded), config_.residual_limit);
  state.previous_error = predicted_error;
  state.previous_time_us = now_us;
  state.initialized = true;
  return rounded;
}

std::int32_t MobileMotionPlanner::jerk_axis(
    std::int32_t desired, MobileMotionPhase phase, JerkAxisState& state,
    bool& jerk_limited, bool& step_limited) const noexcept {
  if (phase != MobileMotionPhase::pursuit) {
    state.output = static_cast<float>(desired);
    state.acceleration = 0.0F;
    return desired;
  }
  if (desired == 0) {
    state = {};
    return 0;
  }
  const float desired_acceleration =
      clamp_magnitude(
          static_cast<float>(desired) - state.output,
          config_.maximum_step_counts_per_tick);
  step_limited =
      std::fabs(static_cast<float>(desired) - state.output) >
      config_.maximum_step_counts_per_tick + 1.0e-6F;
  const float acceleration_delta =
      clamp_magnitude(
          desired_acceleration - state.acceleration,
          config_.maximum_jerk_counts_per_tick2);
  jerk_limited =
      std::fabs(desired_acceleration - state.acceleration) >
      config_.maximum_jerk_counts_per_tick2 + 1.0e-6F;
  float acceleration = clamp_magnitude(
      state.acceleration + acceleration_delta,
      config_.maximum_step_counts_per_tick);
  float output = state.output + acceleration;
  if ((desired > 0 && output < 0.0F) ||
      (desired < 0 && output > 0.0F)) {
    output = 0.0F;
    acceleration = 0.0F;
  }
  std::int32_t rounded = static_cast<std::int32_t>(std::lround(output));
  if (desired != 0 && std::abs(rounded) > std::abs(desired)) {
    rounded = desired;
    output = static_cast<float>(rounded);
    acceleration = output - state.output;
  }
  if (rounded != 0 && !same_sign_or_zero(
          static_cast<float>(rounded), static_cast<float>(desired))) {
    rounded = 0;
    output = 0.0F;
    acceleration = 0.0F;
  }
  state.output = output;
  state.acceleration = acceleration;
  return rounded;
}

void MobileMotionPlanner::shape_settle_packet(
    const MobileMotionPlannerInput& input, float predicted_error_x,
    float predicted_error_y, float safe_radius, std::int32_t& desired_x,
    std::int32_t& desired_y, bool& settle_limited) noexcept {
  if (phase_ != MobileMotionPhase::settle) {
    settle_stopped_ = false;
    return;
  }
  const float response_max = std::max(
      config_.response_x_px_per_count, config_.response_y_px_per_count);
  const float inner_radius = std::max(
      safe_radius * config_.settle_inner_radius_fraction,
      response_max * config_.settle_inner_radius_response_multiple);
  const float stop_exit_radius = inner_radius +
      response_max * config_.settle_stop_exit_response_multiple;
  const float error_length = std::hypot(predicted_error_x, predicted_error_y);
  if (settle_stopped_) {
    if (error_length <= stop_exit_radius) {
      desired_x = 0;
      desired_y = 0;
      settle_limited = true;
      ++metrics_.settle_stop_holds;
      return;
    }
    settle_stopped_ = false;
  }
  if (error_length <= inner_radius) {
    desired_x = 0;
    desired_y = 0;
    settle_limited = true;
    settle_stopped_ = true;
    ++metrics_.settle_stop_latches;
    return;
  }
  if ((desired_x == 0 && desired_y == 0) ||
      error_length <= std::numeric_limits<float>::epsilon()) {
    return;
  }

  const float radial_velocity =
      (predicted_error_x * input.target_velocity_x_pixels_per_second +
       predicted_error_y * input.target_velocity_y_pixels_per_second) /
      error_length;
  const float critical_speed =
      config_.settle_natural_frequency_rad_s * (error_length - inner_radius);
  const float pd_speed = std::clamp(
      critical_speed + 2.0F * radial_velocity, 0.0F, critical_speed);
  const float packet_x_pixels =
      static_cast<float>(desired_x) * config_.response_x_px_per_count;
  const float packet_y_pixels =
      static_cast<float>(desired_y) * config_.response_y_px_per_count;
  const float packet_length_pixels =
      std::hypot(packet_x_pixels, packet_y_pixels);
  if (packet_length_pixels <= std::numeric_limits<float>::epsilon()) return;

  const float minimum_dt = config_.pid_minimum_dt_ms / 1'000.0F;
  const float maximum_dt = config_.pid_maximum_dt_ms / 1'000.0F;
  const float elapsed = has_observation_ &&
          input.observed_at_us > last_observed_at_us_
      ? static_cast<float>(input.observed_at_us - last_observed_at_us_) /
          1'000'000.0F
      : minimum_dt;
  const float dt = std::clamp(elapsed, minimum_dt, maximum_dt);
  float minimum_active_response = std::numeric_limits<float>::max();
  if (desired_x != 0) {
    minimum_active_response = std::min(
        minimum_active_response, config_.response_x_px_per_count);
  }
  if (desired_y != 0) {
    minimum_active_response = std::min(
        minimum_active_response, config_.response_y_px_per_count);
  }
  const float pd_packet_pixels =
      std::max(minimum_active_response, pd_speed * dt);
  float scale = std::min(1.0F, pd_packet_pixels / packet_length_pixels);
  if (desired_x != 0) {
    scale = std::min(
        scale,
        std::fabs(predicted_error_x) /
            std::max(std::fabs(packet_x_pixels), 1.0e-6F));
  }
  if (desired_y != 0) {
    scale = std::min(
        scale,
        std::fabs(predicted_error_y) /
            std::max(std::fabs(packet_y_pixels), 1.0e-6F));
  }
  const auto truncate_toward_zero = [](float value) {
    return static_cast<std::int32_t>(value);
  };
  std::int32_t shaped_x =
      truncate_toward_zero(static_cast<float>(desired_x) * scale);
  std::int32_t shaped_y =
      truncate_toward_zero(static_cast<float>(desired_y) * scale);
  if (shaped_x == 0 && shaped_y == 0) {
    // Independent truncation can erase a small diagonal packet even though
    // the radial PD contract deliberately reserved one physical count. Keep
    // exactly one admissible axis so a target outside the inner stop radius
    // continues converging instead of waiting for detector noise to kick it.
    constexpr float tolerance = 1.0e-6F;
    const bool x_admissible = desired_x != 0 &&
        config_.response_x_px_per_count <= pd_packet_pixels + tolerance;
    const bool y_admissible = desired_y != 0 &&
        config_.response_y_px_per_count <= pd_packet_pixels + tolerance;
    if (x_admissible || y_admissible) {
      const float scaled_x = std::fabs(
          static_cast<float>(desired_x) * scale);
      const float scaled_y = std::fabs(
          static_cast<float>(desired_y) * scale);
      const bool choose_x = x_admissible &&
          (!y_admissible || scaled_x >= scaled_y);
      if (choose_x) {
        shaped_x = desired_x > 0 ? 1 : -1;
      } else {
        shaped_y = desired_y > 0 ? 1 : -1;
      }
      ++metrics_.settle_quantization_rescues;
    }
  }
  if (shaped_x != desired_x || shaped_y != desired_y) {
    desired_x = shaped_x;
    desired_y = shaped_y;
    settle_limited = true;
    ++metrics_.settle_pd_limited_plans;
  }
}

float MobileMotionPlanner::personal_envelope(float progress) const noexcept {
  if (config_.personal_speed_envelope_count !=
      MobileMotionPlannerConfig::kPersonalEnvelopePoints) {
    return 0.0F;
  }
  const float position = std::clamp(progress, 0.0F, 1.0F) *
      static_cast<float>(MobileMotionPlannerConfig::kPersonalEnvelopePoints - 1);
  const std::size_t left = static_cast<std::size_t>(position);
  const std::size_t right = std::min(
      left + 1, MobileMotionPlannerConfig::kPersonalEnvelopePoints - 1);
  const float fraction = position - static_cast<float>(left);
  return config_.personal_speed_envelope[left] * (1.0F - fraction) +
      config_.personal_speed_envelope[right] * fraction;
}

float MobileMotionPlanner::next_personal_noise() noexcept {
  std::uint64_t value = personal_rng_state_;
  value ^= value >> 12U;
  value ^= value << 25U;
  value ^= value >> 27U;
  personal_rng_state_ = value;
  const std::uint64_t sample = value * 2685821657736338717ULL;
  const float uniform = static_cast<float>(
      (sample >> 40U) & 0x00ff'ffffULL) / 8'388'607.5F - 1.0F;
  const float stability = std::clamp(
      config_.personal_stability_scale, 0.5F, 1.5F);
  const float memory = std::clamp(0.82F + (stability - 1.0F) * 0.10F,
                                  0.72F, 0.90F);
  personal_noise_state_ =
      personal_noise_state_ * memory + uniform * (1.0F - memory);
  return std::clamp(personal_noise_state_, -1.0F, 1.0F);
}

void MobileMotionPlanner::shape_personal_packet(
    const MobileMotionPlannerInput& input, MobileMotionPhase phase,
    float predicted_error_x, float predicted_error_y, float safe_radius,
    std::int32_t& desired_x, std::int32_t& desired_y,
    bool& applied, bool& variation_applied) noexcept {
  applied = false;
  variation_applied = false;
  if (!config_.personal_trajectory_enabled ||
      phase != MobileMotionPhase::pursuit ||
      config_.personal_speed_envelope_count !=
          MobileMotionPlannerConfig::kPersonalEnvelopePoints ||
      (desired_x == 0 && desired_y == 0)) {
    return;
  }
  const float error_length = std::hypot(
      predicted_error_x, predicted_error_y);
  if (error_length < config_.personal_minimum_error_pixels) return;

  const float duration_ms = std::clamp(
      config_.personal_median_duration_ms /
          config_.personal_speed_scale,
      120.0F, 1'200.0F);
  const float elapsed_ms = input.now_us >= lock_started_at_us_
      ? static_cast<float>(input.now_us - lock_started_at_us_) / 1'000.0F
      : 0.0F;
  const float progress = std::clamp(elapsed_ms / duration_ms, 0.0F, 1.0F);
  const auto peak_iterator = std::max_element(
      config_.personal_speed_envelope.begin(),
      config_.personal_speed_envelope.begin() +
          static_cast<std::ptrdiff_t>(
              config_.personal_speed_envelope_count));
  const float envelope_peak_progress = static_cast<float>(
      std::distance(
          config_.personal_speed_envelope.begin(), peak_iterator)) /
      static_cast<float>(
          MobileMotionPlannerConfig::kPersonalEnvelopePoints - 1);
  const float recorded_peak = config_.personal_peak_time_fraction;
  const float envelope_progress = progress <= recorded_peak
      ? progress / std::max(recorded_peak, 0.001F) *
          envelope_peak_progress
      : envelope_peak_progress +
          (progress - recorded_peak) /
              std::max(1.0F - recorded_peak, 0.001F) *
              (1.0F - envelope_peak_progress);
  const float envelope = personal_envelope(envelope_progress);
  const float temporal_window = std::pow(
      std::max(0.0F, std::sin(3.14159265358979323846F * progress)),
      1.35F);
  const float profile_strength = std::clamp(
      0.55F + 0.45F * config_.personal_bell_correlation,
      0.55F, 1.0F);
  const float transport_boost = 1.0F +
      0.16F * envelope * temporal_window * profile_strength *
          config_.personal_speed_scale;

  const float base_x = static_cast<float>(desired_x);
  const float base_y = static_cast<float>(desired_y);
  const float base_length = std::hypot(base_x, base_y);
  if (base_length <= std::numeric_limits<float>::epsilon()) return;
  float shaped_x = base_x * transport_boost;
  float shaped_y = base_y * transport_boost;

  const float response_mean = std::max(
      0.001F,
      (config_.response_x_px_per_count +
       config_.response_y_px_per_count) * 0.5F);
  const float safe_variation_pixels = std::min(
      config_.personal_jitter_maximum_pixels,
      std::max(0.0F, safe_radius) * 0.10F);
  const float requested_variation_counts =
      config_.personal_jitter_amplitude_pixels *
      config_.personal_variation_scale /
      std::max(config_.personal_stability_scale, 0.5F) /
      response_mean;
  const float variation_limit = std::min(
      static_cast<float>(config_.personal_maximum_extra_counts),
      safe_variation_pixels / response_mean);
  const float variation = std::clamp(
      next_personal_noise() * requested_variation_counts,
      -variation_limit, variation_limit);
  if (std::fabs(variation) >= 0.05F) {
    shaped_x += (-base_y / base_length) * variation;
    shaped_y += (base_x / base_length) * variation;
    variation_applied = true;
  }

  const auto bounded_axis = [&](float candidate, std::int32_t base) {
    const std::int32_t extra = config_.personal_maximum_extra_counts;
    std::int32_t rounded = static_cast<std::int32_t>(std::lround(candidate));
    rounded = std::clamp(rounded, base - extra, base + extra);
    if (base != 0 && !same_sign_or_zero(
            static_cast<float>(rounded), static_cast<float>(base))) {
      return base;
    }
    return rounded;
  };
  const std::int32_t candidate_x = bounded_axis(shaped_x, desired_x);
  const std::int32_t candidate_y = bounded_axis(shaped_y, desired_y);
  const float forward_energy =
      static_cast<float>(candidate_x) * base_x +
      static_cast<float>(candidate_y) * base_y;
  const float base_energy = base_x * base_x + base_y * base_y;
  if (forward_energy + 0.001F < base_energy) return;
  applied = candidate_x != desired_x || candidate_y != desired_y;
  desired_x = candidate_x;
  desired_y = candidate_y;
}

void MobileMotionPlanner::accept_observation(
    const MobileMotionPlannerInput& input) noexcept {
  last_observation_sequence_ = input.observation_sequence;
  last_observed_at_us_ = input.observed_at_us;
  last_now_us_ = input.now_us;
  has_observation_ = true;
}

void MobileMotionPlanner::count_phase(MobileMotionPhase phase) noexcept {
  switch (phase) {
    case MobileMotionPhase::acquire: ++metrics_.acquire_plans; break;
    case MobileMotionPhase::pursuit: ++metrics_.pursuit_plans; break;
    case MobileMotionPhase::settle: ++metrics_.settle_plans; break;
  }
}

MobileMotionPlannerOutput MobileMotionPlanner::plan(
    const MobileMotionPlannerInput& input) noexcept {
  ++metrics_.plans;
  const float values[] = {
      input.error_x,
      input.error_y,
      input.target_velocity_x_pixels_per_second,
      input.target_velocity_y_pixels_per_second,
      input.safe_radius_pixels,
  };
  if (input.target_id == 0 || input.observation_sequence == 0 ||
      !std::all_of(
          std::begin(values), std::end(values),
          [](float value) { return std::isfinite(value); }) ||
      input.safe_radius_pixels < 0.0F) {
    ++metrics_.invalid_inputs;
    reset_packet_state();
    return suppress(MotionPlannerSuppressionReason::invalid_input);
  }
  if (input.prediction_bounds_enabled &&
      (!std::isfinite(input.prediction_min_error_x) ||
       !std::isfinite(input.prediction_max_error_x) ||
       !std::isfinite(input.prediction_min_error_y) ||
       !std::isfinite(input.prediction_max_error_y) ||
       input.prediction_min_error_x > input.prediction_max_error_x ||
       input.prediction_min_error_y > input.prediction_max_error_y)) {
    ++metrics_.invalid_inputs;
    reset_packet_state();
    return suppress(MotionPlannerSuppressionReason::invalid_input);
  }
  if (input.observed_at_us == 0 || input.now_us == 0 ||
      input.now_us < input.observed_at_us ||
      (has_observation_ && input.now_us < last_now_us_)) {
    ++metrics_.invalid_times;
    reset_packet_state();
    return suppress(MotionPlannerSuppressionReason::invalid_time);
  }
  if (input.now_us - input.observed_at_us >
      config_.maximum_observation_age_us) {
    ++metrics_.stale_observations;
    reset_packet_state();
    return suppress(MotionPlannerSuppressionReason::stale_observation);
  }
  if (has_observation_ &&
      (input.observation_sequence <= last_observation_sequence_ ||
       input.observed_at_us <= last_observed_at_us_)) {
    ++metrics_.non_monotonic_observations;
    reset_packet_state();
    return suppress(
        MotionPlannerSuppressionReason::non_monotonic_observation);
  }

  const bool target_changed = input.target_id != target_id_;
  if (target_changed) reset_target(input.target_id, input.now_us);
  update_acceleration(input, target_changed);
  const float age_seconds =
      static_cast<float>(input.now_us - input.observed_at_us) / 1'000'000.0F;
  const float velocity_x = clamp_magnitude(
      input.target_velocity_x_pixels_per_second,
      config_.maximum_target_velocity_pixels_per_second);
  const float velocity_y = clamp_magnitude(
      input.target_velocity_y_pixels_per_second,
      config_.maximum_target_velocity_pixels_per_second);
  const float unbounded_predicted_error_x = predicted_axis(
      input.error_x, velocity_x,
      acceleration_x_, age_seconds);
  const float unbounded_predicted_error_y = predicted_axis(
      input.error_y, velocity_y,
      acceleration_y_, age_seconds);
  float predicted_error_x = unbounded_predicted_error_x;
  float predicted_error_y = unbounded_predicted_error_y;
  bool prediction_limited_x = false;
  bool prediction_limited_y = false;
  if (input.prediction_bounds_enabled) {
    predicted_error_x = std::clamp(
        predicted_error_x,
        input.prediction_min_error_x,
        input.prediction_max_error_x);
    predicted_error_y = std::clamp(
        predicted_error_y,
        input.prediction_min_error_y,
        input.prediction_max_error_y);
    prediction_limited_x =
        std::fabs(predicted_error_x - unbounded_predicted_error_x) > 1.0e-6F;
    prediction_limited_y =
        std::fabs(predicted_error_y - unbounded_predicted_error_y) > 1.0e-6F;
    if (prediction_limited_x) ++metrics_.prediction_limited_axes;
    if (prediction_limited_y) ++metrics_.prediction_limited_axes;
  }
  const float predicted_length =
      std::hypot(predicted_error_x, predicted_error_y);
  const float safe_radius = std::max(
      config_.settle_minimum_radius_pixels, input.safe_radius_pixels);
  const MobileMotionPhase phase =
      update_phase(input, predicted_length, safe_radius);
  count_phase(phase);
  const float lock_age_ms = input.now_us >= lock_started_at_us_
      ? static_cast<float>(input.now_us - lock_started_at_us_) / 1'000.0F
      : 0.0F;
  const float phase_age_ms = input.now_us >= phase_started_at_us_
      ? static_cast<float>(input.now_us - phase_started_at_us_) / 1'000.0F
      : 0.0F;

  if (direction_changed(input, target_changed)) {
    // A reversal invalidates accumulated residual and jerk momentum, but the
    // current observation is already fresh evidence. Re-plan it from rest
    // instead of dropping a whole control frame.
    ++metrics_.direction_reorientations;
    reset_packet_state();
    previous_velocity_x_ = velocity_x;
    previous_velocity_y_ = velocity_y;
    acceleration_x_ = 0.0F;
    acceleration_y_ = 0.0F;
  }

  const float budget_x = response_budget(
      predicted_error_x, config_.response_upper_x_px_per_count, phase);
  const float budget_y = response_budget(
      predicted_error_y, config_.response_upper_y_px_per_count, phase);
  bool response_limited_x = false;
  bool response_limited_y = false;
  bool settle_limited_x = false;
  bool settle_limited_y = false;
  std::int32_t desired_x = pid_axis(
      predicted_error_x, config_.response_x_px_per_count, budget_x,
      input.now_us, phase, x_axis_, response_limited_x, settle_limited_x);
  std::int32_t desired_y = pid_axis(
      predicted_error_y, config_.response_y_px_per_count, budget_y,
      input.now_us, phase, y_axis_, response_limited_y, settle_limited_y);
  bool personal_applied = false;
  bool personal_variation_applied = false;
  shape_personal_packet(
      input, phase, predicted_error_x, predicted_error_y, safe_radius,
      desired_x, desired_y, personal_applied, personal_variation_applied);
  if (personal_applied) ++metrics_.personal_trajectory_plans;
  if (personal_variation_applied) {
    ++metrics_.personal_trajectory_variation_packets;
  }
  bool settle_packet_limited = false;
  shape_settle_packet(
      input, predicted_error_x, predicted_error_y, safe_radius,
      desired_x, desired_y, settle_packet_limited);
  settle_limited_x = settle_limited_x || settle_packet_limited;
  settle_limited_y = settle_limited_y || settle_packet_limited;

  bool jerk_limited_x = false;
  bool jerk_limited_y = false;
  bool step_limited_x = false;
  bool step_limited_y = false;
  std::int32_t delta_x = jerk_axis(
      desired_x, phase, jerk_x_, jerk_limited_x, step_limited_x);
  std::int32_t delta_y = jerk_axis(
      desired_y, phase, jerk_y_, jerk_limited_y, step_limited_y);
  const auto apply_final_response_guard =
      [&](std::int32_t delta, float predicted_error, float budget,
          JerkAxisState& jerk_state, bool& response_limited,
          bool& settle_limited) {
        float final_budget = std::min(
            budget, static_cast<float>(config_.maximum_axis_delta));
        if (phase == MobileMotionPhase::settle) {
          const float settle_budget =
              static_cast<float>(config_.settle_maximum_axis_delta);
          settle_limited = settle_limited || final_budget > settle_budget;
          final_budget = std::min(final_budget, settle_budget);
        }
        std::int32_t guarded = std::clamp(
            delta,
            -static_cast<std::int32_t>(final_budget),
            static_cast<std::int32_t>(final_budget));
        if (guarded != 0 &&
            !same_sign_or_zero(
                static_cast<float>(guarded), predicted_error)) {
          guarded = 0;
        }
        if (guarded != delta) {
          response_limited = true;
          jerk_state.output = static_cast<float>(guarded);
          jerk_state.acceleration = 0.0F;
        }
        return guarded;
      };
  delta_x = apply_final_response_guard(
      delta_x, predicted_error_x, budget_x, jerk_x_,
      response_limited_x, settle_limited_x);
  delta_y = apply_final_response_guard(
      delta_y, predicted_error_y, budget_y, jerk_y_,
      response_limited_y, settle_limited_y);
  accept_observation(input);

  if (response_limited_x) ++metrics_.response_limited_axes;
  if (response_limited_y) ++metrics_.response_limited_axes;
  if (jerk_limited_x) ++metrics_.jerk_limited_axes;
  if (jerk_limited_y) ++metrics_.jerk_limited_axes;
  if (step_limited_x) ++metrics_.step_limited_axes;
  if (step_limited_y) ++metrics_.step_limited_axes;

  MotionPlannerSuppressionReason reason =
      MotionPlannerSuppressionReason::none;
  if (delta_x == 0 && delta_y == 0) {
    const bool in_deadzone =
        std::fabs(predicted_error_x) <= config_.deadzone_pixels &&
        std::fabs(predicted_error_y) <= config_.deadzone_pixels;
    if (in_deadzone) {
      reason = MotionPlannerSuppressionReason::deadzone;
      ++metrics_.deadzone_suppressions;
    } else if ((std::fabs(predicted_error_x) <= config_.deadzone_pixels ||
                budget_x < 1.0F) &&
               (std::fabs(predicted_error_y) <= config_.deadzone_pixels ||
                budget_y < 1.0F)) {
      // The target is outside the configured pixel deadzone, but the
      // calibrated worst-case response says that one physical count would
      // exceed the admissible correction on every active axis. This is a
      // device-resolution terminal state, not an unexplained active stall.
      reason = MotionPlannerSuppressionReason::subcount_resolution;
      ++metrics_.subcount_resolution_suppressions;
    } else if (settle_limited_x || settle_limited_y) {
      reason = MotionPlannerSuppressionReason::settle_guard;
      ++metrics_.settle_guard_suppressions;
    } else {
      reason = MotionPlannerSuppressionReason::response_guard;
      ++metrics_.response_guard_suppressions;
    }
  }

  last_output_ = {
      .delta_x = delta_x,
      .delta_y = delta_y,
      .predicted_error_x = predicted_error_x,
      .predicted_error_y = predicted_error_y,
      .target_acceleration_x_pixels_per_second2 = acceleration_x_,
      .target_acceleration_y_pixels_per_second2 = acceleration_y_,
      .response_budget_x_counts = budget_x,
      .response_budget_y_counts = budget_y,
      .lock_age_ms = lock_age_ms,
      .phase_age_ms = phase_age_ms,
      .phase = phase,
      .suppression_reason = reason,
      .response_limited = response_limited_x || response_limited_y,
      .jerk_limited = jerk_limited_x || jerk_limited_y,
      .step_limited = step_limited_x || step_limited_y,
      .prediction_limited = prediction_limited_x || prediction_limited_y,
      .settle_stopped = settle_stopped_,
      .personal_trajectory_applied = personal_applied,
  };
  return last_output_;
}

}  // namespace vfdual_android
