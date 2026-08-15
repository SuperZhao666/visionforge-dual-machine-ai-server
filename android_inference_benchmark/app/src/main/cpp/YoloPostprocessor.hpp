#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace vfdual_android {

struct YoloDetection {
  float x1{};
  float y1{};
  float x2{};
  float y2{};
  float confidence{};
  std::uint32_t class_id{};
};

struct YoloPostprocessConfig {
  float confidence_threshold{0.25F};
  float iou_threshold{0.45F};
  std::uint32_t maximum_candidates{300};
};

/** Explicit split-output tensor contract owned by the selected model profile. */
struct YoloSplitTensorContract {
  std::uint32_t anchor_count{2100};
  std::uint32_t class_count{2};
};

/**
 * Real-time decode entry point. Both vectors retain their allocations across
 * frames; candidates is private scratch and detections receives the NMS result.
 */
[[nodiscard]] bool decode_qnn_split_yolo_output_into(
    std::span<const std::uint8_t> coordinate_bytes,
    std::span<const std::uint8_t> confidence_bytes,
    const YoloPostprocessConfig& config,
    const YoloSplitTensorContract& contract,
    std::vector<YoloDetection>& candidates,
    std::vector<YoloDetection>& detections);

/** Decodes FP32 coordinates [1,4,A] and confidences [1,C,A]. */
[[nodiscard]] std::vector<YoloDetection> decode_qnn_split_yolo_output(
    std::span<const std::uint8_t> coordinate_bytes,
    std::span<const std::uint8_t> confidence_bytes,
    const YoloPostprocessConfig& config,
    const YoloSplitTensorContract& contract);

/** Backward-compatible Valorant 320 contract: A=2100, C=2. */
[[nodiscard]] std::vector<YoloDetection> decode_qnn_split_yolo_output(
    std::span<const std::uint8_t> coordinate_bytes, std::span<const std::uint8_t> confidence_bytes,
    const YoloPostprocessConfig& config);

}  // namespace vfdual_android
