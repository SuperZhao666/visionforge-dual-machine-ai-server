#include "MobileTargetTracker.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace vfdual_android {
namespace {

float width(const YoloDetection& detection) noexcept {
  return detection.x2 - detection.x1;
}

float height(const YoloDetection& detection) noexcept {
  return detection.y2 - detection.y1;
}

float center_x(const YoloDetection& detection) noexcept {
  return (detection.x1 + detection.x2) * 0.5F;
}

float center_y(const YoloDetection& detection) noexcept {
  return (detection.y1 + detection.y2) * 0.5F;
}

float intersection_over_union(const YoloDetection& left, const YoloDetection& right) noexcept {
  const float x1 = std::max(left.x1, right.x1);
  const float y1 = std::max(left.y1, right.y1);
  const float x2 = std::min(left.x2, right.x2);
  const float y2 = std::min(left.y2, right.y2);
  const float intersection = std::max(0.0F, x2 - x1) * std::max(0.0F, y2 - y1);
  const float left_area = width(left) * height(left);
  const float right_area = width(right) * height(right);
  const float union_area = left_area + right_area - intersection;
  return union_area > 0.0F ? intersection / union_area : 0.0F;
}

float size_ratio(const YoloDetection& left, const YoloDetection& right) noexcept {
  const float width_ratio = std::max(width(left), width(right)) /
      std::max(std::min(width(left), width(right)), 1.0e-6F);
  const float height_ratio = std::max(height(left), height(right)) /
      std::max(std::min(height(left), height(right)), 1.0e-6F);
  return std::max(width_ratio, height_ratio);
}

}  // namespace

MobileTargetTracker::MobileTargetTracker(const MobileTargetTrackerConfig& config) {
  (void)configure(config);
}

bool MobileTargetTracker::valid_config(const MobileTargetTrackerConfig& config) noexcept {
  const float values[] = {
      config.high_confidence_threshold,
      config.low_confidence_threshold,
      config.new_track_confidence_threshold,
      config.first_stage_iou_threshold,
      config.second_stage_iou_threshold,
      config.maximum_center_distance_pixels,
      config.maximum_size_ratio,
      config.control_smoothing_alpha,
      config.control_smoothing_bypass_delta_pixels,
  };
  if (!std::all_of(std::begin(values), std::end(values), [](float value) {
        return std::isfinite(value);
      })) {
    return false;
  }
  return config.low_confidence_threshold >= 0.0F &&
      config.low_confidence_threshold <= config.high_confidence_threshold &&
      config.high_confidence_threshold <= 1.0F &&
      config.new_track_confidence_threshold >= config.high_confidence_threshold &&
      config.new_track_confidence_threshold <= 1.0F &&
      config.first_stage_iou_threshold >= 0.0F && config.first_stage_iou_threshold <= 1.0F &&
      config.second_stage_iou_threshold >= 0.0F &&
      config.second_stage_iou_threshold <= config.first_stage_iou_threshold &&
      config.maximum_center_distance_pixels > 0.0F &&
      config.maximum_size_ratio >= 1.0F &&
      config.control_smoothing_alpha > 0.0F &&
      config.control_smoothing_alpha <= 1.0F &&
      config.control_smoothing_bypass_delta_pixels > 0.0F &&
      config.lost_track_duration_us <=
          kMobileTargetTrackerMaximumLostDurationUs;
}

bool MobileTargetTracker::configure(const MobileTargetTrackerConfig& config) {
  if (!valid_config(config)) return false;
  config_ = config;
  reset();
  return true;
}

MobileVisibleFrameShift MobileTargetTracker::resolve_visible_frame_shift(
    std::span<const YoloDetection> detections, std::uint64_t sequence,
    float expected_shift_x, float expected_shift_y,
    std::uint64_t observed_at_us, std::uint32_t minimum_support,
    std::uint32_t witness_class_id) {
  MobileVisibleFrameShift result{
      .shift_x = expected_shift_x,
      .shift_y = expected_shift_y,
  };
  if (!std::isfinite(expected_shift_x) || !std::isfinite(expected_shift_y) ||
      sequence == 0U || minimum_support == 0U ||
      tracks_.size() < minimum_support ||
      detections.size() < minimum_support) {
    return result;
  }

  VisibleShiftFit best_fit{
      .residual = std::numeric_limits<float>::max(),
      .prior_error = std::numeric_limits<float>::max(),
  };
  visible_used_detections_.assign(detections.size(), 0U);

  for (const Track& seed_track : tracks_) {
    if (seed_track.lost_frames != 0U ||
        (witness_class_id != kMobileVisibleFrameShiftAnyClass &&
         seed_track.detection.class_id != witness_class_id)) {
      continue;
    }
    const YoloDetection seed_reference = predicted_box(
        seed_track, sequence, observed_at_us);
    for (const YoloDetection& seed_detection : detections) {
      if ((witness_class_id != kMobileVisibleFrameShiftAnyClass &&
           seed_detection.class_id != witness_class_id) ||
          seed_track.detection.class_id != seed_detection.class_id ||
          size_ratio(seed_reference, seed_detection) > config_.maximum_size_ratio) {
        continue;
      }
      const float candidate_shift_x =
          center_x(seed_detection) - center_x(seed_reference);
      const float candidate_shift_y =
          center_y(seed_detection) - center_y(seed_reference);
      const VisibleShiftFit fit = fit_visible_frame_shift(
          detections, sequence, candidate_shift_x, candidate_shift_y,
          expected_shift_x, expected_shift_y, observed_at_us,
          visible_used_detections_, witness_class_id);
      if (fit.support >= minimum_support &&
          better_visible_shift_fit(fit, best_fit)) best_fit = fit;
    }
  }
  if (best_fit.support >= minimum_support) {
    result = {
        .shift_x = best_fit.shift_x,
        .shift_y = best_fit.shift_y,
        .support = best_fit.support,
        .measured = true,
    };
  }
  return result;
}

MobileTargetTracker::VisibleShiftFit MobileTargetTracker::fit_visible_frame_shift(
    std::span<const YoloDetection> detections, std::uint64_t sequence,
    float candidate_shift_x, float candidate_shift_y,
    float expected_shift_x, float expected_shift_y,
    std::uint64_t observed_at_us,
    std::span<std::uint8_t> used_detections,
    std::uint32_t witness_class_id) const {
  const float tolerance_squared =
      config_.control_smoothing_bypass_delta_pixels *
      config_.control_smoothing_bypass_delta_pixels;
  VisibleShiftFit fit{};
  std::fill(used_detections.begin(), used_detections.end(), 0U);
  for (const Track& track : tracks_) {
    if (track.lost_frames != 0U ||
        (witness_class_id != kMobileVisibleFrameShiftAnyClass &&
         track.detection.class_id != witness_class_id)) {
      continue;
    }
    const YoloDetection reference = predicted_box(
        track, sequence, observed_at_us);
    std::size_t best_index = detections.size();
    float best_residual = tolerance_squared;
    float best_shift_x{};
    float best_shift_y{};
    for (std::size_t index = 0; index < detections.size(); ++index) {
      const YoloDetection& detection = detections[index];
      if (used_detections[index] ||
          (witness_class_id != kMobileVisibleFrameShiftAnyClass &&
           detection.class_id != witness_class_id) ||
          track.detection.class_id != detection.class_id ||
          size_ratio(reference, detection) > config_.maximum_size_ratio) continue;
      const float shift_x = center_x(detection) - center_x(reference);
      const float shift_y = center_y(detection) - center_y(reference);
      const float residual_x = shift_x - candidate_shift_x;
      const float residual_y = shift_y - candidate_shift_y;
      const float residual = residual_x * residual_x + residual_y * residual_y;
      if (residual <= best_residual) {
        best_index = index;
        best_residual = residual;
        best_shift_x = shift_x;
        best_shift_y = shift_y;
      }
    }
    if (best_index == detections.size()) continue;
    used_detections[best_index] = 1U;
    ++fit.support;
    fit.residual += best_residual;
    fit.shift_x += best_shift_x;
    fit.shift_y += best_shift_y;
  }
  if (fit.support == 0U) return fit;
  fit.shift_x /= static_cast<float>(fit.support);
  fit.shift_y /= static_cast<float>(fit.support);
  const float prior_x = fit.shift_x - expected_shift_x;
  const float prior_y = fit.shift_y - expected_shift_y;
  fit.prior_error = prior_x * prior_x + prior_y * prior_y;
  return fit;
}

bool MobileTargetTracker::better_visible_shift_fit(
    const VisibleShiftFit& candidate,
    const VisibleShiftFit& current) noexcept {
  return candidate.support > current.support ||
      (candidate.support == current.support &&
       candidate.residual < current.residual) ||
      (candidate.support == current.support &&
       candidate.residual == current.residual &&
       candidate.prior_error < current.prior_error);
}

void MobileTargetTracker::apply_visible_frame_shift(
    float shift_x, float shift_y) noexcept {
  if (!std::isfinite(shift_x) || !std::isfinite(shift_y) ||
      (shift_x == 0.0F && shift_y == 0.0F)) {
    return;
  }
  const auto shift_detection = [shift_x, shift_y](YoloDetection& detection) {
    detection.x1 += shift_x;
    detection.x2 += shift_x;
    detection.y1 += shift_y;
    detection.y2 += shift_y;
  };
  for (Track& track : tracks_) {
    shift_detection(track.detection);
    shift_detection(track.control_detection);
  }
}

YoloDetection MobileTargetTracker::predicted_box(
    const Track& track, std::uint64_t sequence,
    std::uint64_t observed_at_us) const noexcept {
  float prediction_interval{};
  if (config_.lost_track_duration_us != 0U &&
      observed_at_us > track.last_observed_at_us) {
    const std::uint64_t elapsed_us = std::min(
        observed_at_us - track.last_observed_at_us,
        config_.lost_track_duration_us);
    prediction_interval = static_cast<float>(elapsed_us) / 1'000'000.0F;
  } else if (config_.lost_track_duration_us == 0U) {
    const std::uint64_t gap = sequence > track.last_sequence
        ? sequence - track.last_sequence : 0U;
    prediction_interval = static_cast<float>(
        std::min<std::uint64_t>(gap, 2U));
  }
  const float shift_x = track.velocity_x * prediction_interval;
  const float shift_y = track.velocity_y * prediction_interval;
  YoloDetection predicted = track.detection;
  predicted.x1 += shift_x;
  predicted.x2 += shift_x;
  predicted.y1 += shift_y;
  predicted.y2 += shift_y;
  return predicted;
}

std::span<const MobileTargetTracker::Match> MobileTargetTracker::associate(
    std::span<const std::size_t> track_indices,
    std::span<const std::size_t> detection_indices,
    std::span<const YoloDetection> detections,
    float iou_threshold, std::uint64_t observed_at_us) {
  possible_matches_.clear();
  const std::size_t maximum_possible_matches =
      track_indices.size() * detection_indices.size();
  if (possible_matches_.capacity() < maximum_possible_matches) {
    possible_matches_.reserve(maximum_possible_matches);
  }
  const float maximum_distance_squared =
      config_.maximum_center_distance_pixels * config_.maximum_center_distance_pixels;
  for (const std::size_t track_index : track_indices) {
    const Track& track = tracks_[track_index];
    const YoloDetection reference = predicted_box(
        track, last_sequence_, observed_at_us);
    for (const std::size_t detection_index : detection_indices) {
      const YoloDetection& detection = detections[detection_index];
      if (track.detection.class_id != detection.class_id) continue;
      if (size_ratio(reference, detection) > config_.maximum_size_ratio) continue;
      const float delta_x = center_x(reference) - center_x(detection);
      const float delta_y = center_y(reference) - center_y(detection);
      const float distance_squared = delta_x * delta_x + delta_y * delta_y;
      const float iou = intersection_over_union(reference, detection);
      const bool center_match = distance_squared <= maximum_distance_squared;
      if (iou < iou_threshold && !center_match) continue;
      if (iou < iou_threshold && has_closer_same_class_observation(
              track, reference, detection_index, detections,
              distance_squared)) {
        ++metrics_.ambiguous_center_matches_rejected;
        continue;
      }
      const float normalized_distance =
          std::sqrt(distance_squared / std::max(maximum_distance_squared, 1.0F));
      const float score = iou * 2.0F + std::max(0.0F, 1.0F - normalized_distance) * 0.5F;
      possible_matches_.push_back({
          track_index, detection_index, score, iou < iou_threshold});
    }
  }
  std::sort(possible_matches_.begin(), possible_matches_.end(), [](const Match& left, const Match& right) {
    if (left.score != right.score) return left.score > right.score;
    if (left.track_index != right.track_index) return left.track_index < right.track_index;
    return left.detection_index < right.detection_index;
  });

  matches_.clear();
  association_used_tracks_.assign(tracks_.size(), 0U);
  association_used_detections_.assign(detections.size(), 0U);
  for (const Match& match : possible_matches_) {
    if (association_used_tracks_[match.track_index] ||
        association_used_detections_[match.detection_index]) {
      continue;
    }
    association_used_tracks_[match.track_index] = 1U;
    association_used_detections_[match.detection_index] = 1U;
    matches_.push_back(match);
  }
  return matches_;
}

bool MobileTargetTracker::has_closer_same_class_observation(
    const Track& track, const YoloDetection& reference,
    std::size_t candidate_index,
    std::span<const YoloDetection> detections,
    float candidate_distance_squared) const noexcept {
  for (std::size_t index = 0; index < detections.size(); ++index) {
    if (index == candidate_index) continue;
    const YoloDetection& observation = detections[index];
    if (observation.class_id != track.detection.class_id ||
        observation.confidence < config_.low_confidence_threshold) {
      continue;
    }
    const float delta_x = center_x(reference) - center_x(observation);
    const float delta_y = center_y(reference) - center_y(observation);
    const float distance_squared = delta_x * delta_x + delta_y * delta_y;
    if (distance_squared < candidate_distance_squared) return true;
  }
  return false;
}

void MobileTargetTracker::update_control_detection(
    Track& track, const YoloDetection& detection) noexcept {
  const YoloDetection& previous = track.control_detection;
  // Only rapid aim-point motion may bypass smoothing.  Detector scale noise
  // can move opposite box edges by many pixels while leaving the target
  // center stationary; treating that as motion forwarded raw size jitter into
  // the head aim point on nearly every other frame in real OW2 sessions.
  const float innovation_x = center_x(detection) - center_x(previous);
  const float innovation_y = center_y(detection) - center_y(previous);
  const float innovation = std::hypot(innovation_x, innovation_y);
  metrics_.maximum_control_innovation_pixels = std::max(
      metrics_.maximum_control_innovation_pixels, innovation);
  if (innovation >= config_.control_smoothing_bypass_delta_pixels) {
    track.control_detection = detection;
    ++metrics_.control_filter_bypasses;
    return;
  }

  const float progress = std::clamp(
      innovation / config_.control_smoothing_bypass_delta_pixels,
      0.0F, 1.0F);
  const float alpha = config_.control_smoothing_alpha +
      (1.0F - config_.control_smoothing_alpha) * progress;
  const float retained = 1.0F - alpha;
  YoloDetection filtered = detection;
  filtered.x1 = previous.x1 * retained + detection.x1 * alpha;
  filtered.y1 = previous.y1 * retained + detection.y1 * alpha;
  filtered.x2 = previous.x2 * retained + detection.x2 * alpha;
  filtered.y2 = previous.y2 * retained + detection.y2 * alpha;
  track.control_detection = filtered;
  ++metrics_.control_filter_blends;
}

void MobileTargetTracker::update_track(
    Track& track, const YoloDetection& detection,
    std::uint64_t sequence, std::uint64_t observed_at_us) noexcept {
  update_control_detection(track, detection);
  float inverse_interval{};
  if (config_.lost_track_duration_us != 0U &&
      observed_at_us > track.last_observed_at_us) {
    const std::uint64_t interval_us =
        observed_at_us - track.last_observed_at_us;
    inverse_interval = 1'000'000.0F / static_cast<float>(interval_us);
    ++metrics_.time_based_velocity_updates;
    metrics_.maximum_observation_interval_us = std::max(
        metrics_.maximum_observation_interval_us, interval_us);
  } else {
    const std::uint64_t gap = sequence > track.last_sequence
        ? sequence - track.last_sequence : 1U;
    inverse_interval = 1.0F / static_cast<float>(gap);
  }
  const float measured_velocity_x =
      (center_x(detection) - center_x(track.detection)) * inverse_interval;
  const float measured_velocity_y =
      (center_y(detection) - center_y(track.detection)) * inverse_interval;
  track.velocity_x = track.velocity_x * 0.45F + measured_velocity_x * 0.55F;
  track.velocity_y = track.velocity_y * 0.45F + measured_velocity_y * 0.55F;
  track.detection = detection;
  track.last_sequence = sequence;
  if (observed_at_us != 0U) track.last_observed_at_us = observed_at_us;
  track.lost_frames = 0;
}

std::vector<TrackedDetection> MobileTargetTracker::update(
    std::span<const YoloDetection> detections, std::uint64_t sequence,
    std::uint64_t observed_at_us) {
  std::vector<TrackedDetection> result;
  update_into(detections, sequence, observed_at_us, result);
  return result;
}

void MobileTargetTracker::update_into(
    std::span<const YoloDetection> detections, std::uint64_t sequence,
    std::uint64_t observed_at_us,
    std::vector<TrackedDetection>& result) {
  result.clear();
  if (result.capacity() < detections.size()) {
    result.reserve(detections.size());
  }
  for (const YoloDetection& detection : detections) result.push_back({detection, 0});
  if (sequence == 0 || (last_sequence_ != 0 && sequence <= last_sequence_) ||
      (config_.lost_track_duration_us != 0U &&
       (observed_at_us == 0U ||
        (last_observed_at_us_ != 0U &&
         observed_at_us <= last_observed_at_us_)))) {
    return;
  }
  last_sequence_ = sequence;
  if (observed_at_us != 0U) last_observed_at_us_ = observed_at_us;

  if (config_.lost_track_duration_us != 0U) {
    const auto old_size = tracks_.size();
    std::erase_if(tracks_, [this, observed_at_us](const Track& track) {
      return observed_at_us - track.last_observed_at_us >
          config_.lost_track_duration_us;
    });
    metrics_.tracks_expired += old_size - tracks_.size();
  }

  high_detection_indices_.clear();
  low_detection_indices_.clear();
  if (high_detection_indices_.capacity() < detections.size()) {
    high_detection_indices_.reserve(detections.size());
    low_detection_indices_.reserve(detections.size());
  }
  for (std::size_t index = 0; index < detections.size(); ++index) {
    const float confidence = detections[index].confidence;
    if (confidence >= config_.high_confidence_threshold) {
      high_detection_indices_.push_back(index);
    } else if (confidence >= config_.low_confidence_threshold) {
      low_detection_indices_.push_back(index);
    }
  }
  track_indices_.resize(tracks_.size());
  for (std::size_t index = 0; index < tracks_.size(); ++index) {
    track_indices_[index] = index;
  }

  matched_tracks_.assign(tracks_.size(), 0U);
  matched_high_detections_.assign(detections.size(), 0U);
  const std::span<const Match> first_matches = associate(
      track_indices_, high_detection_indices_, detections,
      config_.first_stage_iou_threshold, observed_at_us);
  for (const Match& match : first_matches) {
    update_track(
        tracks_[match.track_index], detections[match.detection_index],
        sequence, observed_at_us);
    result[match.detection_index].detection =
        tracks_[match.track_index].control_detection;
    result[match.detection_index].track_id = tracks_[match.track_index].id;
    matched_tracks_[match.track_index] = 1U;
    matched_high_detections_[match.detection_index] = 1U;
    ++metrics_.first_stage_matches;
    if (match.center_distance_only) ++metrics_.center_distance_matches;
  }

  unmatched_track_indices_.clear();
  if (unmatched_track_indices_.capacity() < tracks_.size()) {
    unmatched_track_indices_.reserve(tracks_.size());
  }
  for (std::size_t index = 0; index < tracks_.size(); ++index) {
    if (!matched_tracks_[index]) unmatched_track_indices_.push_back(index);
  }
  const std::span<const Match> second_matches = associate(
      unmatched_track_indices_, low_detection_indices_, detections,
      config_.second_stage_iou_threshold, observed_at_us);
  for (const Match& match : second_matches) {
    update_track(
        tracks_[match.track_index], detections[match.detection_index],
        sequence, observed_at_us);
    result[match.detection_index].detection =
        tracks_[match.track_index].control_detection;
    result[match.detection_index].track_id = tracks_[match.track_index].id;
    matched_tracks_[match.track_index] = 1U;
    ++metrics_.second_stage_matches;
    if (match.center_distance_only) ++metrics_.center_distance_matches;
  }

  for (std::size_t index = 0; index < tracks_.size(); ++index) {
    if (!matched_tracks_[index]) ++tracks_[index].lost_frames;
  }
  for (const std::size_t detection_index : high_detection_indices_) {
    if (matched_high_detections_[detection_index] ||
        detections[detection_index].confidence < config_.new_track_confidence_threshold) {
      continue;
    }
    Track track{
        .id = next_track_id_++,
        .detection = detections[detection_index],
        .control_detection = detections[detection_index],
        .last_sequence = sequence,
        .last_observed_at_us = observed_at_us,
    };
    result[detection_index].track_id = track.id;
    tracks_.push_back(track);
    ++metrics_.tracks_created;
  }

  if (config_.lost_track_duration_us == 0U) {
    const auto old_size = tracks_.size();
    std::erase_if(tracks_, [this](const Track& track) {
      return track.lost_frames > config_.lost_frame_buffer;
    });
    metrics_.tracks_expired += old_size - tracks_.size();
  }
}

void MobileTargetTracker::reset() noexcept {
  tracks_.clear();
  next_track_id_ = 1;
  last_sequence_ = 0;
  last_observed_at_us_ = 0;
}

}  // namespace vfdual_android
