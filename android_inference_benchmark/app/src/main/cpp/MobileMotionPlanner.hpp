#pragma once

#include <array>
#include <cstdint>

namespace vfdual_android {

enum class MobileMotionPhase : std::uint8_t {
  acquire,
  pursuit,
  settle,
};

enum class MotionPlannerSuppressionReason : std::uint8_t {
  none,
  invalid_input,
  invalid_time,
  stale_observation,
  non_monotonic_observation,
  deadzone,
  direction_flip,
  response_guard,
  subcount_resolution,
  settle_guard,
};

/**
 * Pure C++ contract for the motion stage.  Pixel-space observations enter
 * here; bounded MAKCU count deltas leave here.  The planner owns no JNI, USB,
 * network, thread or wall-clock dependency.
 */
struct MobileMotionPlannerConfig {
  static constexpr std::size_t kPersonalEnvelopePoints = 16;

  std::uint64_t maximum_observation_age_us{150'000};

  // Pixel error -> MAKCU count response contract.
  // Defaults mirror the single-machine runtime_controller contract:
  // relative_response starts at 1.0 px/count (its online learner could raise
  // it to 8.0; using the learning ceiling as the static value zeroed the
  // response budget for any residual under ~8.4px and made corrections 8x
  // too weak). gain matches overshoot_error_fraction=0.36, and the fine
  // deadzone matches the original "converge to center" stop semantics.
  float response_gain{0.36F};
  float response_x_px_per_count{1.0F};
  float response_y_px_per_count{1.0F};
  float response_upper_x_px_per_count{1.0F};
  float response_upper_y_px_per_count{1.0F};
  float response_step_fraction{0.95F};
  float response_settle_fraction{0.95F};
  std::int32_t uncalibrated_maximum_axis_delta{12};

  // Bounded target-motion prediction. Mirrors velocity_lead_ms=32 and
  // velocity_lead_max_px=22 from the single-machine controller.
  float prediction_horizon_ms{32.0F};
  float maximum_prediction_pixels{22.0F};
  float maximum_target_velocity_pixels_per_second{1'200.0F};
  float acceleration_update_alpha{0.35F};
  float maximum_acceleration_pixels_per_second2{50'000.0F};

  // Explicit acquire -> pursuit -> settle phase contract.
  float pursuit_minimum_lock_ms{120.0F};
  float settle_enter_radius_fraction{1.0F};
  float settle_exit_radius_fraction{1.35F};
  float settle_minimum_radius_pixels{1.0F};
  float settle_natural_frequency_rad_s{32.0F};
  float settle_inner_radius_fraction{0.50F};
  float settle_inner_radius_response_multiple{1.25F};
  float settle_stop_exit_response_multiple{0.25F};

  // PID, quantization debt and packet-space bounds.
  float pid_ki{0.0F};
  float pid_kd{0.0F};
  float pid_integral_limit{24.0F};
  float pid_derivative_alpha{0.70F};
  float pid_minimum_dt_ms{1.0F};
  float pid_maximum_dt_ms{80.0F};
  float residual_limit{1.0F};
  // Single-machine parity: fine_deadzone=0.2px; 0.5 is the practical floor
  // for integer MAKCU counts.
  float deadzone_pixels{0.5F};
  std::int32_t settle_maximum_axis_delta{3};
  std::int32_t maximum_axis_delta{127};

  // Pursuit-only acceleration/jerk shaping. Acquire remains immediate and
  // settle remains response-budgeted.
  float maximum_step_counts_per_tick{12.0F};
  float maximum_jerk_counts_per_tick2{6.0F};

  // A material error-vector reversal clears stale packet momentum and
  // immediately replans the same fresh observation from rest.
  float direction_change_cosine{0.15F};
  float direction_change_minimum_error_pixels{8.0F};

  // Optional profile-driven shaping ported from the desktop personal
  // trajectory model. It shapes an already-safe pursuit packet; acquire,
  // settle, response, jerk and sign guards remain authoritative.
  bool personal_trajectory_enabled{};
  std::uint64_t personal_profile_seed{};
  float personal_speed_scale{1.0F};
  float personal_stability_scale{1.0F};
  float personal_variation_scale{1.0F};
  float personal_median_duration_ms{480.0F};
  float personal_peak_time_fraction{0.42F};
  float personal_bell_correlation{0.75F};
  float personal_jitter_amplitude_pixels{0.20F};
  float personal_jitter_maximum_pixels{1.0F};
  std::int32_t personal_maximum_extra_counts{2};
  float personal_minimum_error_pixels{24.0F};
  std::array<float, kPersonalEnvelopePoints> personal_speed_envelope{};
  std::size_t personal_speed_envelope_count{};
};

struct MobileMotionPlannerInput {
  std::uint64_t target_id{};
  std::uint64_t observation_sequence{};
  std::uint64_t observed_at_us{};
  std::uint64_t now_us{};
  float error_x{};
  float error_y{};
  float target_velocity_x_pixels_per_second{};
  float target_velocity_y_pixels_per_second{};
  float safe_radius_pixels{};
  bool prediction_bounds_enabled{};
  float prediction_min_error_x{};
  float prediction_max_error_x{};
  float prediction_min_error_y{};
  float prediction_max_error_y{};
};

struct MobileMotionPlannerOutput {
  std::int32_t delta_x{};
  std::int32_t delta_y{};
  float predicted_error_x{};
  float predicted_error_y{};
  float target_acceleration_x_pixels_per_second2{};
  float target_acceleration_y_pixels_per_second2{};
  float response_budget_x_counts{};
  float response_budget_y_counts{};
  float lock_age_ms{};
  float phase_age_ms{};
  MobileMotionPhase phase{MobileMotionPhase::acquire};
  MotionPlannerSuppressionReason suppression_reason{
      MotionPlannerSuppressionReason::none};
  bool response_limited{};
  bool jerk_limited{};
  bool step_limited{};
  bool prediction_limited{};
  bool settle_stopped{};
  bool personal_trajectory_applied{};

  [[nodiscard]] bool has_move() const noexcept {
    return delta_x != 0 || delta_y != 0;
  }
};

struct MobileMotionPlannerMetrics {
  std::uint64_t plans{};
  std::uint64_t invalid_inputs{};
  std::uint64_t invalid_times{};
  std::uint64_t stale_observations{};
  std::uint64_t non_monotonic_observations{};
  std::uint64_t acquire_plans{};
  std::uint64_t pursuit_plans{};
  std::uint64_t settle_plans{};
  std::uint64_t direction_flip_suppressions{};
  std::uint64_t direction_reorientations{};
  std::uint64_t deadzone_suppressions{};
  std::uint64_t response_guard_suppressions{};
  std::uint64_t subcount_resolution_suppressions{};
  std::uint64_t settle_guard_suppressions{};
  std::uint64_t response_limited_axes{};
  std::uint64_t jerk_limited_axes{};
  std::uint64_t step_limited_axes{};
  std::uint64_t prediction_limited_axes{};
  std::uint64_t settle_pd_limited_plans{};
  std::uint64_t settle_quantization_rescues{};
  std::uint64_t settle_stop_latches{};
  std::uint64_t settle_stop_holds{};
  std::uint64_t personal_trajectory_plans{};
  std::uint64_t personal_trajectory_variation_packets{};
};

[[nodiscard]] const char* mobile_motion_phase_name(
    MobileMotionPhase phase) noexcept;
[[nodiscard]] const char* motion_planner_suppression_name(
    MotionPlannerSuppressionReason reason) noexcept;

class MobileMotionPlanner final {
 public:
  MobileMotionPlanner() = default;
  explicit MobileMotionPlanner(const MobileMotionPlannerConfig& config);

  [[nodiscard]] bool configure(const MobileMotionPlannerConfig& config);
  [[nodiscard]] MobileMotionPlannerOutput plan(
      const MobileMotionPlannerInput& input) noexcept;
  [[nodiscard]] const MobileMotionPlannerMetrics& metrics() const noexcept {
    return metrics_;
  }
  [[nodiscard]] const MobileMotionPlannerConfig& config() const noexcept {
    return config_;
  }
  [[nodiscard]] const MobileMotionPlannerOutput& last_output() const noexcept {
    return last_output_;
  }
  /** Aligns retained error state with a physical move visible in the frame. */
  void apply_visible_error_shift(float shift_x, float shift_y) noexcept;
  void reset_motion() noexcept;

 private:
  struct AxisState {
    float integral{};
    float derivative{};
    float previous_error{};
    float residual{};
    std::uint64_t previous_time_us{};
    bool initialized{};
  };

  struct JerkAxisState {
    float output{};
    float acceleration{};
  };

  [[nodiscard]] static bool valid_config(
      const MobileMotionPlannerConfig& config) noexcept;
  [[nodiscard]] MobileMotionPlannerOutput suppress(
      MotionPlannerSuppressionReason reason) noexcept;
  void reset_target(std::uint64_t target_id, std::uint64_t now_us) noexcept;
  void reset_packet_state() noexcept;
  void update_acceleration(
      const MobileMotionPlannerInput& input, bool target_changed) noexcept;
  [[nodiscard]] MobileMotionPhase update_phase(
      const MobileMotionPlannerInput& input, float predicted_length,
      float safe_radius) noexcept;
  [[nodiscard]] bool direction_changed(
      const MobileMotionPlannerInput& input, bool target_changed) noexcept;
  [[nodiscard]] float predicted_axis(
      float error, float velocity, float acceleration,
      float age_seconds) const noexcept;
  [[nodiscard]] float response_budget(
      float predicted_error, float response_upper, MobileMotionPhase phase) const noexcept;
  [[nodiscard]] std::int32_t pid_axis(
      float predicted_error, float response_px_per_count, float budget_counts,
      std::uint64_t now_us, MobileMotionPhase phase, AxisState& state,
      bool& response_limited, bool& settle_limited) noexcept;
  [[nodiscard]] std::int32_t jerk_axis(
      std::int32_t desired, MobileMotionPhase phase, JerkAxisState& state,
      bool& jerk_limited, bool& step_limited) const noexcept;
  void shape_settle_packet(
      const MobileMotionPlannerInput& input, float predicted_error_x,
      float predicted_error_y, float safe_radius, std::int32_t& desired_x,
      std::int32_t& desired_y, bool& settle_limited) noexcept;
  void shape_personal_packet(
      const MobileMotionPlannerInput& input, MobileMotionPhase phase,
      float predicted_error_x, float predicted_error_y, float safe_radius,
      std::int32_t& desired_x, std::int32_t& desired_y,
      bool& applied, bool& variation_applied) noexcept;
  [[nodiscard]] float personal_envelope(float progress) const noexcept;
  [[nodiscard]] float next_personal_noise() noexcept;
  void accept_observation(const MobileMotionPlannerInput& input) noexcept;
  void count_phase(MobileMotionPhase phase) noexcept;

  MobileMotionPlannerConfig config_{};
  MobileMotionPlannerMetrics metrics_{};
  MobileMotionPlannerOutput last_output_{};
  AxisState x_axis_{};
  AxisState y_axis_{};
  JerkAxisState jerk_x_{};
  JerkAxisState jerk_y_{};
  std::uint64_t target_id_{};
  std::uint64_t lock_started_at_us_{};
  std::uint64_t phase_started_at_us_{};
  std::uint64_t last_observation_sequence_{};
  std::uint64_t last_observed_at_us_{};
  std::uint64_t last_now_us_{};
  float previous_velocity_x_{};
  float previous_velocity_y_{};
  float acceleration_x_{};
  float acceleration_y_{};
  float previous_error_x_{};
  float previous_error_y_{};
  bool has_observation_{};
  bool has_previous_error_{};
  bool settle_stopped_{};
  float personal_noise_state_{};
  std::uint64_t personal_rng_state_{0x9e3779b97f4a7c15ULL};
  MobileMotionPhase phase_{MobileMotionPhase::acquire};
};

}  // namespace vfdual_android
