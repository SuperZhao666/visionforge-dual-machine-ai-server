#include "YoloPostprocessor.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace vfdual_android {
namespace {

bool tensor_bytes_match(
    std::size_t actual_bytes, std::uint32_t channels,
    std::uint32_t anchor_count) noexcept {
  if (channels == 0U || anchor_count == 0U) return false;
  const std::uint64_t elements =
      static_cast<std::uint64_t>(channels) * anchor_count;
  const std::uint64_t expected_bytes = elements * sizeof(float);
  return expected_bytes <= static_cast<std::uint64_t>(SIZE_MAX) &&
      actual_bytes == static_cast<std::size_t>(expected_bytes);
}

float read_float(std::span<const std::uint8_t> bytes, std::size_t index) {
  float value{};
  std::memcpy(&value, bytes.data() + index * sizeof(float), sizeof(value));
  return value;
}

float intersection_over_union(const YoloDetection& left, const YoloDetection& right) {
  const float left_x = std::max(left.x1, right.x1);
  const float top_y = std::max(left.y1, right.y1);
  const float right_x = std::min(left.x2, right.x2);
  const float bottom_y = std::min(left.y2, right.y2);
  const float intersection = std::max(0.0F, right_x - left_x) * std::max(0.0F, bottom_y - top_y);
  const float left_area = std::max(0.0F, left.x2 - left.x1) * std::max(0.0F, left.y2 - left.y1);
  const float right_area = std::max(0.0F, right.x2 - right.x1) * std::max(0.0F, right.y2 - right.y1);
  const float union_area = left_area + right_area - intersection;
  return union_area > 0.0F ? intersection / union_area : 0.0F;
}

}  // namespace

bool decode_qnn_split_yolo_output_into(
    std::span<const std::uint8_t> coordinate_bytes, std::span<const std::uint8_t> confidence_bytes,
    const YoloPostprocessConfig& config, const YoloSplitTensorContract& contract,
    std::vector<YoloDetection>& candidates,
    std::vector<YoloDetection>& detections) {
  if (&candidates == &detections) return false;
  candidates.clear();
  detections.clear();
  if (!tensor_bytes_match(coordinate_bytes.size(), 4U, contract.anchor_count) ||
      !tensor_bytes_match(confidence_bytes.size(), contract.class_count,
                          contract.anchor_count) ||
      !std::isfinite(config.confidence_threshold) ||
      !std::isfinite(config.iou_threshold) ||
      config.confidence_threshold < 0.0F || config.confidence_threshold > 1.0F ||
      config.iou_threshold < 0.0F || config.iou_threshold > 1.0F) {
    return false;
  }
  const auto coordinate_at = [&coordinate_bytes, &contract](
                                 std::uint32_t channel,
                                 std::uint32_t anchor) {
    return read_float(
        coordinate_bytes,
        static_cast<std::size_t>(channel) * contract.anchor_count + anchor);
  };
  const auto confidence_at = [&confidence_bytes, &contract](
                                 std::uint32_t channel,
                                 std::uint32_t anchor) {
    return read_float(
        confidence_bytes,
        static_cast<std::size_t>(channel) * contract.anchor_count + anchor);
  };
  const std::size_t maximum_detection_count =
      (std::min)(contract.anchor_count,
                 config.maximum_candidates == 0U
                     ? contract.anchor_count
                     : config.maximum_candidates);
  // The confidence gate can admit every anchor before the top-K reduction.
  // Reserve that actual upper bound once so scene density cannot reintroduce
  // allocator jitter after a quiet warm-up frame.
  candidates.reserve(contract.anchor_count);
  detections.reserve(maximum_detection_count);
  for (std::uint32_t anchor = 0; anchor < contract.anchor_count; ++anchor) {
    std::uint32_t class_id = 0U;
    float confidence = confidence_at(0U, anchor);
    for (std::uint32_t channel = 1U; channel < contract.class_count; ++channel) {
      const float candidate_confidence = confidence_at(channel, anchor);
      if (candidate_confidence > confidence) {
        confidence = candidate_confidence;
        class_id = channel;
      }
    }
    if (confidence < config.confidence_threshold) continue;
    const float width = coordinate_at(2, anchor);
    const float height = coordinate_at(3, anchor);
    const float center_x = coordinate_at(0, anchor);
    const float center_y = coordinate_at(1, anchor);
    if (!std::isfinite(confidence) || !std::isfinite(center_x) || !std::isfinite(center_y) ||
        !std::isfinite(width) || !std::isfinite(height) || width <= 0.0F || height <= 0.0F) continue;
    candidates.push_back({center_x - width * 0.5F, center_y - height * 0.5F,
                          center_x + width * 0.5F, center_y + height * 0.5F,
                          confidence, class_id});
  }
  const auto higher_confidence = [](const YoloDetection& left, const YoloDetection& right) {
    return left.confidence > right.confidence;
  };
  if (config.maximum_candidates != 0 && candidates.size() > config.maximum_candidates) {
    const auto limit = candidates.begin() + static_cast<std::ptrdiff_t>(config.maximum_candidates);
    std::nth_element(candidates.begin(), limit, candidates.end(), higher_confidence);
    candidates.resize(config.maximum_candidates);
  }
  std::sort(candidates.begin(), candidates.end(), higher_confidence);

  for (const auto& candidate : candidates) {
    const bool overlaps_kept = std::any_of(
        detections.begin(), detections.end(),
        [&candidate, &config](const YoloDetection& existing) {
          return existing.class_id == candidate.class_id &&
              intersection_over_union(existing, candidate) > config.iou_threshold;
        });
    if (!overlaps_kept) detections.push_back(candidate);
  }
  return true;
}

std::vector<YoloDetection> decode_qnn_split_yolo_output(
    std::span<const std::uint8_t> coordinate_bytes,
    std::span<const std::uint8_t> confidence_bytes,
    const YoloPostprocessConfig& config,
    const YoloSplitTensorContract& contract) {
  std::vector<YoloDetection> candidates;
  std::vector<YoloDetection> detections;
  (void)decode_qnn_split_yolo_output_into(
      coordinate_bytes, confidence_bytes, config, contract, candidates, detections);
  return detections;
}

std::vector<YoloDetection> decode_qnn_split_yolo_output(
    std::span<const std::uint8_t> coordinate_bytes,
    std::span<const std::uint8_t> confidence_bytes,
    const YoloPostprocessConfig& config) {
  return decode_qnn_split_yolo_output(
      coordinate_bytes, confidence_bytes, config, YoloSplitTensorContract{});
}

}  // namespace vfdual_android
