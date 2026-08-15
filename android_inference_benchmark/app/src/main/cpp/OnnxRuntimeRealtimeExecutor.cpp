#include "OnnxRuntimeRealtimeExecutor.hpp"

#include <android/log.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "nnapi_provider_factory.h"
#include "onnxruntime_cxx_api.h"
#include "PortableInferenceFailurePolicy.hpp"
#include "vfdual/model_contract.hpp"

namespace {

constexpr char kTag[] = "VisionForgeOrt";
constexpr std::string_view kNnapiBackend = "onnxruntime_nnapi";
constexpr std::string_view kCpuBackend = "onnxruntime_cpu";
constexpr std::uint32_t kOrtStatusSuccess = 0U;
constexpr std::uint32_t kOrtStatusNotReady = 0x4f520001U;
constexpr std::uint32_t kOrtStatusInvalidInput = 0x4f520002U;
constexpr std::uint32_t kOrtStatusExecutionFailed = 0x4f520003U;
constexpr float kU16ToUnit = 1.0F / 65535.0F;

bool dimensions_match(
    const std::vector<std::int64_t>& actual,
    std::initializer_list<std::int64_t> expected) noexcept {
  return actual.size() == expected.size() &&
      std::equal(actual.begin(), actual.end(), expected.begin());
}

std::span<const std::uint8_t> float_bytes(
    const std::vector<float>& values) noexcept {
  return {
      reinterpret_cast<const std::uint8_t*>(values.data()),
      values.size() * sizeof(float)};
}

bool finite_values(const std::vector<float>& values) noexcept {
  return std::all_of(values.begin(), values.end(), [](float value) {
    return std::isfinite(value);
  });
}

class PortablePermanentInitializationError final
    : public std::runtime_error {
 public:
  PortablePermanentInitializationError(
      vfdual_android::PortableInitializationFailureKind kind,
      std::string detail)
      : std::runtime_error(std::move(detail)), kind_(kind) {}

  [[nodiscard]] vfdual_android::PortableInitializationFailureKind kind()
      const noexcept {
    return kind_;
  }

 private:
  vfdual_android::PortableInitializationFailureKind kind_;
};

vfdual_android::PortableInitializationFailureDecision
classify_ort_initialization_failure(OrtErrorCode error_code) noexcept {
  using Kind = vfdual_android::PortableInitializationFailureKind;
  switch (error_code) {
    case ORT_INVALID_ARGUMENT:
    case ORT_NO_MODEL:
    case ORT_INVALID_PROTOBUF:
    case ORT_MODEL_LOADED:
    case ORT_NOT_IMPLEMENTED:
    case ORT_INVALID_GRAPH:
    case ORT_MODEL_REQUIRES_COMPILATION:
    case ORT_NOT_FOUND:
      return vfdual_android::classify_portable_initialization_failure(
          Kind::onnxruntime_model_or_configuration_invalid);
    case ORT_OK:
    case ORT_FAIL:
    case ORT_NO_SUCHFILE:
    case ORT_ENGINE_ERROR:
    case ORT_RUNTIME_EXCEPTION:
    case ORT_EP_FAIL:
    case ORT_MODEL_LOAD_CANCELED:
    default:
      return vfdual_android::classify_portable_initialization_failure(
          Kind::onnxruntime_initialization_failed);
  }
}

class PortableRuntime final {
 public:
  bool prepare(
      std::string_view backend_token,
      const std::string& model_path,
      std::string_view model_token) {
    std::scoped_lock lock(mutex_);
    release_locked();
    diagnostic_.clear();
    const vfdual::MobileModelContract* requested_model =
        vfdual::find_mobile_model(model_token);
    if (requested_model == nullptr) {
      return fail_locked(
          vfdual_android::classify_portable_initialization_failure(
              vfdual_android::PortableInitializationFailureKind::
                  model_selection_invalid),
          "unsupported model token=" + std::string(model_token));
    }
    if (backend_token != kNnapiBackend && backend_token != kCpuBackend) {
      return fail_locked(
          vfdual_android::classify_portable_initialization_failure(
              vfdual_android::PortableInitializationFailureKind::
                  backend_invalid),
          "unsupported backend token=" + std::string(backend_token));
    }
    if (model_path.empty()) {
      return fail_locked(
          vfdual_android::classify_portable_initialization_failure(
              vfdual_android::PortableInitializationFailureKind::
                  model_path_missing),
          "portable ONNX model path is empty");
    }

    try {
      environment_ = std::make_unique<Ort::Env>(
          ORT_LOGGING_LEVEL_WARNING, "VisionForgePortable");
      Ort::SessionOptions options;
      options.SetExecutionMode(ExecutionMode::ORT_SEQUENTIAL);
      options.SetGraphOptimizationLevel(
          GraphOptimizationLevel::ORT_ENABLE_ALL);
      options.SetLogSeverityLevel(3);
      if (backend_token == kNnapiBackend) {
        Ort::ThrowOnError(
            OrtSessionOptionsAppendExecutionProvider_Nnapi(
                options, NNAPI_FLAG_USE_NONE));
      }
      session_ = std::make_unique<Ort::Session>(
          *environment_, model_path.c_str(), options);
      validate_contract_locked(*requested_model);
      allocate_tensors_locked(*requested_model);
      active_model_ = requested_model;
      backend_token_ = std::string(backend_token);

      // Readiness requires one real graph execution, not merely provider or
      // session construction. 114 is the same letterbox color used by the
      // live YUV preprocessor.
      std::fill(input_floats_.begin(), input_floats_.end(), 114.0F / 255.0F);
      const auto started = std::chrono::steady_clock::now();
      run_graph_locked();
      const auto probe_us = static_cast<std::uint64_t>(
          std::chrono::duration_cast<std::chrono::microseconds>(
              std::chrono::steady_clock::now() - started).count());
      if (!outputs_finite_locked()) {
        throw PortablePermanentInitializationError(
            vfdual_android::PortableInitializationFailureKind::
                probe_non_finite_output,
            "portable probe produced non-finite output");
      }
      ready_ = true;
      std::ostringstream detail;
      detail << "ready=1 backend="
             << (backend_token == kNnapiBackend
                     ? "ONNX Runtime NNAPI" : "ONNX Runtime CPU")
             << " backend_token=" << backend_token
             << " model=" << model_token
             << " input=FP32_NCHW outputs=FP32_split"
             << " probe_execution=success probe_us=" << probe_us
             << " cpu_fallback_allowed="
             << (backend_token == kNnapiBackend ? 1 : 0);
      diagnostic_ = detail.str();
      __android_log_print(
          ANDROID_LOG_INFO, kTag, "%s", diagnostic_.c_str());
      return true;
    } catch (const PortablePermanentInitializationError& failure) {
      return fail_locked(
          vfdual_android::classify_portable_initialization_failure(
              failure.kind()),
          failure.what());
    } catch (const Ort::Exception& failure) {
      return fail_locked(
          classify_ort_initialization_failure(
              failure.GetOrtErrorCode()),
          std::string("Ort::Exception code=")
              + std::to_string(static_cast<int>(failure.GetOrtErrorCode()))
              + " message=" + failure.what());
    } catch (const std::exception& failure) {
      return fail_locked(
          vfdual_android::classify_portable_initialization_failure(
              vfdual_android::PortableInitializationFailureKind::
                  unexpected_initialization_failed),
          failure.what());
    }
  }

  bool execute(
      std::span<const std::uint8_t> input,
      std::uint64_t* elapsed_us,
      std::uint32_t* graph_status,
      std::uint32_t* detection_count,
      std::vector<vfdual_android::YoloDetection>* detections) {
    std::scoped_lock lock(mutex_);
    if (elapsed_us != nullptr) *elapsed_us = 0U;
    if (graph_status != nullptr) *graph_status = kOrtStatusNotReady;
    if (detection_count != nullptr) *detection_count = 0U;
    if (detections != nullptr) detections->clear();
    if (!ready_ || active_model_ == nullptr || session_ == nullptr) {
      return false;
    }
    const std::size_t expected_bytes =
        vfdual::model_input_bytes(active_model_->input);
    if (input.size() != expected_bytes) {
      if (graph_status != nullptr) *graph_status = kOrtStatusInvalidInput;
      return false;
    }

    try {
      convert_nhwc_u16_to_nchw_float_locked(input);
      const auto started = std::chrono::steady_clock::now();
      run_graph_locked();
      if (elapsed_us != nullptr) {
        *elapsed_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started).count());
      }
      if (!outputs_finite_locked()) {
        record_execution_failure_locked(
            vfdual_android::classify_portable_execution_failure(
                vfdual_android::PortableExecutionFailureKind::
                    non_finite_output),
            "portable output contains a non-finite value");
        if (graph_status != nullptr) {
          *graph_status = kOrtStatusExecutionFailed;
        }
        return false;
      }
      auto& decoded = detections == nullptr
          ? postprocess_detections_ : *detections;
      const vfdual_android::YoloSplitTensorContract contract{
          .anchor_count = active_model_->output.anchor_count,
          .class_count = active_model_->output.class_count};
      if (!vfdual_android::decode_qnn_split_yolo_output_into(
              float_bytes(coordinates_), float_bytes(confidences_),
              postprocess_config_, contract,
              postprocess_candidates_, decoded)) {
        if (graph_status != nullptr) {
          *graph_status = kOrtStatusExecutionFailed;
        }
        return false;
      }
      if (detection_count != nullptr) {
        *detection_count = static_cast<std::uint32_t>(decoded.size());
      }
      record_execution_success_locked();
      if (graph_status != nullptr) *graph_status = kOrtStatusSuccess;
      return true;
    } catch (const Ort::Exception& failure) {
      record_execution_failure_locked(
          vfdual_android::classify_portable_execution_failure(
              vfdual_android::PortableExecutionFailureKind::
                  onnxruntime_run_failed),
          failure.what());
      if (graph_status != nullptr) *graph_status = kOrtStatusExecutionFailed;
      __android_log_print(
          ANDROID_LOG_ERROR, kTag, "%s",
          last_execution_failure_.c_str());
      return false;
    }
  }

  bool configure_postprocess(float confidence_threshold, float iou_threshold) {
    std::scoped_lock lock(mutex_);
    if (!std::isfinite(confidence_threshold) ||
        !std::isfinite(iou_threshold) ||
        confidence_threshold < 0.0F || confidence_threshold > 1.0F ||
        iou_threshold < 0.0F || iou_threshold > 1.0F) {
      return false;
    }
    postprocess_config_.confidence_threshold = confidence_threshold;
    postprocess_config_.iou_threshold = iou_threshold;
    return true;
  }

  std::string report() {
    std::scoped_lock lock(mutex_);
    std::ostringstream report;
    report.setf(std::ios::fixed);
    report.precision(2);
    report << "ready=" << (ready_ ? 1 : 0)
           << " backend_token="
           << (backend_token_.empty() ? "none" : backend_token_)
           << " postprocess_confidence="
           << postprocess_config_.confidence_threshold
           << " postprocess_iou=" << postprocess_config_.iou_threshold
           << " execution_failures=" << execution_failures_
           << " consecutive_execution_failures="
           << consecutive_execution_failures_
           << " execution_recoveries=" << execution_recoveries_;
    if (!last_execution_failure_.empty()) {
      report << " last_execution_failure={"
             << last_execution_failure_ << '}';
    }
    report << '\n' << diagnostic_;
    return report.str();
  }

  void release() {
    std::scoped_lock lock(mutex_);
    release_locked();
  }

 private:
  void validate_contract_locked(
      const vfdual::MobileModelContract& model) {
    if (session_->GetInputCount() != 1U ||
        session_->GetOutputCount() != 2U) {
      throw PortablePermanentInitializationError(
          vfdual_android::PortableInitializationFailureKind::
              model_contract_invalid,
          "portable model requires one input and two outputs");
    }
    Ort::AllocatorWithDefaultOptions allocator;
    auto input_name = session_->GetInputNameAllocated(0U, allocator);
    if (input_name.get() == nullptr ||
        std::strcmp(input_name.get(), "images") != 0) {
      throw PortablePermanentInitializationError(
          vfdual_android::PortableInitializationFailureKind::
              model_contract_invalid,
          "portable input name is not images");
    }
    const auto input_info = session_->GetInputTypeInfo(0U)
        .GetTensorTypeAndShapeInfo();
    if (input_info.GetElementType() !=
            ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT ||
        !dimensions_match(
            input_info.GetShape(),
            {1, 3, model.input.height, model.input.width})) {
      throw PortablePermanentInitializationError(
          vfdual_android::PortableInitializationFailureKind::
              model_contract_invalid,
          "portable input is not FP32 NCHW model contract");
    }

    bool coordinates_found = false;
    bool confidences_found = false;
    for (std::size_t index = 0; index < 2U; ++index) {
      auto output_name = session_->GetOutputNameAllocated(index, allocator);
      const auto output_info = session_->GetOutputTypeInfo(index)
          .GetTensorTypeAndShapeInfo();
      if (output_info.GetElementType() !=
          ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT) {
        throw PortablePermanentInitializationError(
            vfdual_android::PortableInitializationFailureKind::
                model_contract_invalid,
            "portable output is not FP32");
      }
      if (output_name.get() != nullptr &&
          std::strcmp(output_name.get(), "output_coordinates") == 0) {
        coordinates_found = dimensions_match(
            output_info.GetShape(),
            {1, 4, model.output.anchor_count});
      } else if (output_name.get() != nullptr &&
                 std::strcmp(output_name.get(),
                             "output_confidences") == 0) {
        confidences_found = dimensions_match(
            output_info.GetShape(),
            {1, model.output.class_count,
             model.output.anchor_count});
      }
    }
    if (!coordinates_found || !confidences_found) {
      throw PortablePermanentInitializationError(
          vfdual_android::PortableInitializationFailureKind::
              model_contract_invalid,
          "portable split output contract is invalid");
    }
  }

  void allocate_tensors_locked(
      const vfdual::MobileModelContract& model) {
    const std::size_t pixels =
        static_cast<std::size_t>(model.input.width) * model.input.height;
    input_floats_.assign(pixels * model.input.channels, 0.0F);
    coordinates_.assign(
        static_cast<std::size_t>(4U) * model.output.anchor_count, 0.0F);
    confidences_.assign(
        static_cast<std::size_t>(model.output.class_count) *
            model.output.anchor_count,
        0.0F);
    memory_info_ = std::make_unique<Ort::MemoryInfo>(
        Ort::MemoryInfo::CreateCpu(
            OrtArenaAllocator, OrtMemTypeDefault));
    const std::array<std::int64_t, 4> input_shape{
        1, 3,
        static_cast<std::int64_t>(model.input.height),
        static_cast<std::int64_t>(model.input.width)};
    input_tensor_ = Ort::Value::CreateTensor<float>(
        *memory_info_, input_floats_.data(), input_floats_.size(),
        input_shape.data(), input_shape.size());

    output_tensors_.clear();
    output_tensors_.reserve(2U);
    const std::array<std::int64_t, 3> coordinate_shape{
        1, 4,
        static_cast<std::int64_t>(model.output.anchor_count)};
    output_tensors_.push_back(Ort::Value::CreateTensor<float>(
        *memory_info_, coordinates_.data(), coordinates_.size(),
        coordinate_shape.data(), coordinate_shape.size()));
    const std::array<std::int64_t, 3> confidence_shape{
        1,
        static_cast<std::int64_t>(model.output.class_count),
        static_cast<std::int64_t>(model.output.anchor_count)};
    output_tensors_.push_back(Ort::Value::CreateTensor<float>(
        *memory_info_, confidences_.data(), confidences_.size(),
        confidence_shape.data(), confidence_shape.size()));
    postprocess_candidates_.reserve(model.output.anchor_count);
    postprocess_detections_.reserve(
        postprocess_config_.maximum_candidates);
  }

  void convert_nhwc_u16_to_nchw_float_locked(
      std::span<const std::uint8_t> input) noexcept {
    const std::size_t pixels = input_floats_.size() / 3U;
    for (std::size_t pixel = 0; pixel < pixels; ++pixel) {
      const std::size_t source = pixel * 6U;
      for (std::size_t channel = 0; channel < 3U; ++channel) {
        const std::size_t offset = source + channel * 2U;
        const std::uint16_t value = static_cast<std::uint16_t>(
            input[offset] |
            (static_cast<std::uint16_t>(input[offset + 1U]) << 8U));
        input_floats_[channel * pixels + pixel] =
            static_cast<float>(value) * kU16ToUnit;
      }
    }
  }

  void run_graph_locked() {
    static constexpr std::array<const char*, 1> kInputNames{"images"};
    static constexpr std::array<const char*, 2> kOutputNames{
        "output_coordinates", "output_confidences"};
    session_->Run(
        Ort::RunOptions{nullptr},
        kInputNames.data(), &input_tensor_, 1U,
        kOutputNames.data(), output_tensors_.data(),
        output_tensors_.size());
  }

  bool outputs_finite_locked() const noexcept {
    return finite_values(coordinates_) && finite_values(confidences_);
  }

  void record_execution_failure_locked(
      vfdual_android::PortableExecutionFailureDecision decision,
      const std::string& detail) {
    ++execution_failures_;
    ++consecutive_execution_failures_;
    last_execution_failure_ = "failure_code="
        + std::string(decision.failure_code)
        + " retryable=" + (decision.retryable ? "true" : "false")
        + " session_retired="
        + (decision.retire_session ? "true" : "false")
        + " detail={" + detail + "}";
    if (decision.retire_session) ready_ = false;
  }

  void record_execution_success_locked() noexcept {
    if (consecutive_execution_failures_ > 0U) {
      ++execution_recoveries_;
      consecutive_execution_failures_ = 0U;
    }
  }

  bool fail_locked(
      vfdual_android::PortableInitializationFailureDecision decision,
      const std::string& detail) {
    diagnostic_ = "ready=0 failure_code="
        + std::string(decision.failure_code)
        + " retryable=" + (decision.retryable ? "true" : "false")
        + " detail={" + detail + "}";
    __android_log_print(
        ANDROID_LOG_ERROR, kTag, "%s", diagnostic_.c_str());
    release_locked(false);
    return false;
  }

  void release_locked(bool clear_diagnostic = true) noexcept {
    ready_ = false;
    active_model_ = nullptr;
    output_tensors_.clear();
    input_tensor_ = Ort::Value{nullptr};
    memory_info_.reset();
    session_.reset();
    environment_.reset();
    input_floats_.clear();
    coordinates_.clear();
    confidences_.clear();
    postprocess_candidates_.clear();
    postprocess_detections_.clear();
    backend_token_.clear();
    if (clear_diagnostic) {
      diagnostic_.clear();
      last_execution_failure_.clear();
      execution_failures_ = 0U;
      consecutive_execution_failures_ = 0U;
      execution_recoveries_ = 0U;
    }
  }

  std::mutex mutex_;
  bool ready_{};
  std::string backend_token_;
  std::string diagnostic_;
  std::string last_execution_failure_;
  std::uint64_t execution_failures_{};
  std::uint64_t consecutive_execution_failures_{};
  std::uint64_t execution_recoveries_{};
  const vfdual::MobileModelContract* active_model_{};
  std::unique_ptr<Ort::Env> environment_;
  std::unique_ptr<Ort::Session> session_;
  std::unique_ptr<Ort::MemoryInfo> memory_info_;
  Ort::Value input_tensor_{nullptr};
  std::vector<Ort::Value> output_tensors_;
  std::vector<float> input_floats_;
  std::vector<float> coordinates_;
  std::vector<float> confidences_;
  std::vector<vfdual_android::YoloDetection> postprocess_candidates_;
  std::vector<vfdual_android::YoloDetection> postprocess_detections_;
  vfdual_android::YoloPostprocessConfig postprocess_config_{};
};

PortableRuntime& runtime() {
  static PortableRuntime instance;
  return instance;
}

}  // namespace

namespace vfdual_android {

bool prepare_onnxruntime_realtime(
    std::string_view backend_token,
    const std::string& model_path,
    const std::string& model_token) {
  return runtime().prepare(backend_token, model_path, model_token);
}

bool execute_onnxruntime_realtime(
    std::span<const std::uint8_t> rgb_nhwc_u16,
    std::uint64_t* elapsed_us,
    std::uint32_t* graph_status,
    std::uint32_t* detection_count,
    std::vector<YoloDetection>* detections) {
  return runtime().execute(
      rgb_nhwc_u16, elapsed_us, graph_status,
      detection_count, detections);
}

bool configure_onnxruntime_postprocess(
    float confidence_threshold,
    float iou_threshold) {
  return runtime().configure_postprocess(
      confidence_threshold, iou_threshold);
}

std::string onnxruntime_realtime_report() {
  return runtime().report();
}

void release_onnxruntime_realtime() {
  runtime().release();
}

}  // namespace vfdual_android
