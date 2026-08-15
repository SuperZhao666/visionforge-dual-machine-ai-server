#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "YoloPostprocessor.hpp"

namespace vfdual_android {

[[nodiscard]] bool prepare_onnxruntime_realtime(
    std::string_view backend_token,
    const std::string& model_path,
    const std::string& model_token);
[[nodiscard]] bool execute_onnxruntime_realtime(
    std::span<const std::uint8_t> rgb_nhwc_u16,
    std::uint64_t* elapsed_us,
    std::uint32_t* graph_status,
    std::uint32_t* detection_count,
    std::vector<YoloDetection>* detections = nullptr);
[[nodiscard]] bool configure_onnxruntime_postprocess(
    float confidence_threshold,
    float iou_threshold);
[[nodiscard]] std::string onnxruntime_realtime_report();
void release_onnxruntime_realtime();

}  // namespace vfdual_android
