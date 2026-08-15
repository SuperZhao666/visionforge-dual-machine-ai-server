#pragma once

#include "YoloPostprocessor.hpp"
#include "vfdual/model_contract.hpp"

#include <array>
#include <jni.h>
#include <span>
#include <string>

namespace vfdual_android {

struct MakcuControlProfile {
  // Defaults mirror the single-machine controller (overshoot_error_fraction
  // 0.36 per observation, fine_deadzone ~0.2px) instead of the overly
  // conservative first-pass migration values that made tracking feel slow.
  float relative_gain{0.36F};
  float deadzone_pixels{0.5F};
  std::int32_t maximum_axis_delta{127};
  std::uint32_t switch_confirmation_ms{25U};
  bool output_enabled{};
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
  std::array<float, 16> personal_speed_envelope{};
  std::size_t personal_speed_envelope_count{};
  std::string model_token{vfdual::kDefaultMobileModel.token};
  std::uint32_t body_class_id{vfdual::kDefaultMobileModel.body_class_id};
  std::uint32_t head_class_id{vfdual::kDefaultMobileModel.head_class_id};
  std::uint32_t selected_class_id{vfdual::kDefaultMobileModel.head_class_id};
  bool selected_class_uses_head_box{true};
  bool selected_class_uses_geometric_head{};
  float target_y_ratio{0.50F};
};

/**
 * The only native-to-control boundary. It derives a bounded relative move
 * from postprocessed detections and invokes the Android USB-serial adapter.
 * It never opens a socket and never targets the Windows host.
 */
[[nodiscard]] bool bind_makcu_move_bridge(JNIEnv* environment, jclass controller_class);
[[nodiscard]] bool configure_makcu_control_profile(const MakcuControlProfile& profile);
/** Establishes the only stream generation allowed to mutate control state. */
void activate_makcu_stream_generation(std::uint64_t generation) noexcept;
/** Temporarily holds physical output while preserving the user's authorization. */
void suspend_makcu_output_for_recovery(std::uint64_t generation) noexcept;
/** Reopens only the matching recovery generation and only if the user still authorizes output. */
[[nodiscard]] bool resume_makcu_output_after_valid_frame(std::uint64_t generation) noexcept;
/** Closes physical delivery without invalidating the still-active video stream. */
void fail_closed_makcu_delivery() noexcept;
void disable_makcu_output() noexcept;
void publish_makcu_move_for_detections(
    std::span<const YoloDetection> detections, std::uint64_t frame_sequence,
    std::uint64_t stream_generation, bool content_updated,
    std::uint64_t observed_at_us, std::uint64_t now_us);
/** Commits only the matching in-flight command after firmware echo + prompt. */
void report_makcu_move_result(
    std::uint64_t ticket, bool device_acknowledged,
    std::uint64_t acknowledgement_us) noexcept;
/** Commits only the matching move ticket after Android's HID API accepts it. */
[[nodiscard]] bool report_bluetooth_hid_move_accepted(
    std::uint64_t ticket, std::uint64_t api_acceptance_us) noexcept;
[[nodiscard]] std::string makcu_move_bridge_report();

}  // namespace vfdual_android
