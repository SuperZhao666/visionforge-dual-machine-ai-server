#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "YoloPostprocessor.hpp"

namespace vfdual_android {

/** QNN boundary used by the native video pipeline; it accepts the selected graph's NHWC RGB U16 contract only. */
[[nodiscard]] bool prepare_qnn_realtime(
    const std::string& native_library_directory,
    const std::string& skeleton_directory,
    const std::string& model_token);
[[nodiscard]] bool execute_qnn_realtime(
    std::span<const std::uint8_t> rgb_nhwc, std::uint64_t* elapsed_us, std::uint32_t* graph_status,
    std::uint32_t* detection_count, std::vector<YoloDetection>* detections = nullptr);
[[nodiscard]] bool configure_qnn_postprocess(float confidence_threshold, float iou_threshold);
[[nodiscard]] std::string qnn_realtime_report();
void release_qnn_realtime();

/**
 * Stable inference boundary used by the decoder worker. The router keeps QNN
 * first on supported Snapdragon devices and exposes ONNX Runtime NNAPI/CPU as
 * real, executable fallbacks for other Android SoCs.
 */
[[nodiscard]] bool prepare_realtime_inference(
    std::string_view backend_token,
    const std::string& native_library_directory,
    const std::string& vendor_runtime_directory,
    const std::string& portable_model_path,
    const std::string& model_token);
[[nodiscard]] bool execute_realtime_inference(
    std::span<const std::uint8_t> rgb_nhwc_u16,
    std::uint64_t* elapsed_us,
    std::uint32_t* graph_status,
    std::uint32_t* detection_count,
    std::vector<YoloDetection>* detections = nullptr);
[[nodiscard]] bool configure_realtime_postprocess(
    float confidence_threshold,
    float iou_threshold);
[[nodiscard]] std::string realtime_inference_report();
[[nodiscard]] std::string_view realtime_inference_backend_token() noexcept;
void release_realtime_inference();

}  // namespace vfdual_android
