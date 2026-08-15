#pragma once

#include "YoloPostprocessor.hpp"

#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace vfdual_android {

inline constexpr std::uint64_t kMobileTargetTrackerMaximumLostDurationUs =
    500'000U;
inline constexpr std::uint32_t kMobileVisibleFrameShiftAnyClass =
    std::numeric_limits<std::uint32_t>::max();

struct MobileTargetTrackerConfig {
  float high_confidence_threshold{0.50F};
  float low_confidence_threshold{0.25F};
  float new_track_confidence_threshold{0.50F};
  float first_stage_iou_threshold{0.20F};
  float second_stage_iou_threshold{0.10F};
  float maximum_center_distance_pixels{52.0F};
  float maximum_size_ratio{2.50F};
  // Smooth only the control-facing geometry. Association continues to use
  // the raw observation so filtering cannot make the tracker lose fast motion.
  float control_smoothing_alpha{0.45F};
  float control_smoothing_bypass_delta_pixels{8.0F};
  std::uint32_t lost_frame_buffer{6};
  // Zero preserves count-based standalone use. Production profiles pass
  // monotonic observation time so retention is independent of fresh FPS.
  std::uint64_t lost_track_duration_us{};
};

struct TrackedDetection {
  YoloDetection detection{};
  std::uint64_t track_id{};
};

struct MobileTargetTrackerMetrics {
  std::uint64_t tracks_created{};
  std::uint64_t first_stage_matches{};
  std::uint64_t second_stage_matches{};
  std::uint64_t center_distance_matches{};
  std::uint64_t ambiguous_center_matches_rejected{};
  std::uint64_t tracks_expired{};
  std::uint64_t control_filter_blends{};
  std::uint64_t control_filter_bypasses{};
  std::uint64_t time_based_velocity_updates{};
  std::uint64_t maximum_observation_interval_us{};
  float maximum_control_innovation_pixels{};
};

struct MobileVisibleFrameShift {
  float shift_x{};
  float shift_y{};
  std::uint32_t support{};
  bool measured{};
};

/**
 * Small class-isolated two-stage tracker for the Android control hot path.
 * It has no JNI, USB, network, clock or allocation ownership outside this object.
 */
class MobileTargetTracker final {
 public:
  MobileTargetTracker() = default;
  explicit MobileTargetTracker(const MobileTargetTrackerConfig& config);

  [[nodiscard]] bool configure(const MobileTargetTrackerConfig& config);
  [[nodiscard]] std::vector<TrackedDetection> update(
      std::span<const YoloDetection> detections, std::uint64_t sequence,
      std::uint64_t observed_at_us = 0U);
  /** Reuses caller-owned result storage for the per-frame control hot path. */
  void update_into(
      std::span<const YoloDetection> detections, std::uint64_t sequence,
      std::uint64_t observed_at_us,
      std::vector<TrackedDetection>& result);
  [[nodiscard]] const MobileTargetTrackerMetrics& metrics() const noexcept { return metrics_; }
  /** Resolves a common camera translation from independent same-class witnesses. */
  [[nodiscard]] MobileVisibleFrameShift resolve_visible_frame_shift(
      std::span<const YoloDetection> detections, std::uint64_t sequence,
      float expected_shift_x, float expected_shift_y,
      std::uint64_t observed_at_us = 0U,
      std::uint32_t minimum_support = 2U,
      std::uint32_t witness_class_id = kMobileVisibleFrameShiftAnyClass);
  /** Aligns every retained track with a completed camera move visible on screen. */
  void apply_visible_frame_shift(float shift_x, float shift_y) noexcept;
  void reset() noexcept;

 private:
  struct Track {
    std::uint64_t id{};
    // Raw detector geometry is the association and velocity authority.
    YoloDetection detection{};
    // Filtered geometry is exposed to target selection and motion planning.
    YoloDetection control_detection{};
    // Pixels/second when time-based retention is enabled; otherwise the
    // standalone compatibility path keeps pixels/sequence semantics.
    float velocity_x{};
    float velocity_y{};
    std::uint64_t last_sequence{};
    std::uint64_t last_observed_at_us{};
    std::uint32_t lost_frames{};
  };

  struct Match {
    std::size_t track_index{};
    std::size_t detection_index{};
    float score{};
    bool center_distance_only{};
  };

  struct VisibleShiftFit {
    float shift_x{};
    float shift_y{};
    float residual{};
    float prior_error{};
    std::uint32_t support{};
  };

  [[nodiscard]] static bool valid_config(const MobileTargetTrackerConfig& config) noexcept;
  [[nodiscard]] YoloDetection predicted_box(
      const Track& track, std::uint64_t sequence,
      std::uint64_t observed_at_us) const noexcept;
  [[nodiscard]] std::span<const Match> associate(
      std::span<const std::size_t> track_indices,
      std::span<const std::size_t> detection_indices,
      std::span<const YoloDetection> detections,
      float iou_threshold, std::uint64_t observed_at_us);
  [[nodiscard]] bool has_closer_same_class_observation(
      const Track& track, const YoloDetection& reference,
      std::size_t candidate_index,
      std::span<const YoloDetection> detections,
      float candidate_distance_squared) const noexcept;
  [[nodiscard]] VisibleShiftFit fit_visible_frame_shift(
      std::span<const YoloDetection> detections, std::uint64_t sequence,
      float candidate_shift_x, float candidate_shift_y,
      float expected_shift_x, float expected_shift_y,
      std::uint64_t observed_at_us,
      std::span<std::uint8_t> used_detections,
      std::uint32_t witness_class_id) const;
  [[nodiscard]] static bool better_visible_shift_fit(
      const VisibleShiftFit& candidate,
      const VisibleShiftFit& current) noexcept;
  void update_control_detection(
      Track& track, const YoloDetection& detection) noexcept;
  void update_track(
      Track& track, const YoloDetection& detection,
      std::uint64_t sequence, std::uint64_t observed_at_us) noexcept;

  MobileTargetTrackerConfig config_{};
  MobileTargetTrackerMetrics metrics_{};
  std::vector<Track> tracks_{};
  std::vector<std::size_t> high_detection_indices_{};
  std::vector<std::size_t> low_detection_indices_{};
  std::vector<std::size_t> track_indices_{};
  std::vector<std::size_t> unmatched_track_indices_{};
  std::vector<std::uint8_t> matched_tracks_{};
  std::vector<std::uint8_t> matched_high_detections_{};
  std::vector<std::uint8_t> association_used_tracks_{};
  std::vector<std::uint8_t> association_used_detections_{};
  std::vector<std::uint8_t> visible_used_detections_{};
  std::vector<Match> possible_matches_{};
  std::vector<Match> matches_{};
  std::uint64_t next_track_id_{1};
  std::uint64_t last_sequence_{};
  std::uint64_t last_observed_at_us_{};
};

}  // namespace vfdual_android
