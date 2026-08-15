#include <android/log.h>
#include <jni.h>
#include <dlfcn.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <numeric>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "QnnRealtimeExecutor.hpp"
#include "MakcuMoveBridge.hpp"
#include "YoloPostprocessor.hpp"

#include "QnnBackend.h"
#include "QnnDevice.h"
#include "QnnGraph.h"
#include "QnnInterface.h"
#include "QnnTensor.h"
#include "QnnTypes.h"
#include "HTP/QnnHtpDevice.h"
#include "HTP/QnnHtpPerfInfrastructure.h"
#include "vfdual/model_contract.hpp"
#include "vfdual/protocol.hpp"

namespace {
constexpr char kTag[] = "VisionForgeQnnHtp";
constexpr int kWarmupRuns = 30;
constexpr int kMeasuredRuns = 300;

void logLine(const std::string& message) {
  __android_log_print(ANDROID_LOG_INFO, kTag, "%s", message.c_str());
}

std::mutex gQnnErrorLogMutex;
std::string gQnnErrorLog;
std::atomic_bool gQnnUnsupportedSnapdragonSeen{false};

void clearQnnErrorLog() {
  std::lock_guard<std::mutex> lock(gQnnErrorLogMutex);
  gQnnErrorLog.clear();
  gQnnUnsupportedSnapdragonSeen.store(false, std::memory_order_release);
}

std::string qnnErrorLogSnapshot() {
  std::lock_guard<std::mutex> lock(gQnnErrorLogMutex);
  return gQnnErrorLog;
}

void captureQnnErrorLog(const char* format, QnnLog_Level_t, uint64_t, va_list arguments) {
  if (format == nullptr) return;
  std::array<char, 2048> buffer{};
  va_list copied;
  va_copy(copied, arguments);
  std::vsnprintf(buffer.data(), buffer.size(), format, copied);
  va_end(copied);
  const std::string message(buffer.data());
  if (message.find("Unsupported SnapdragonModel") != std::string::npos) {
    gQnnUnsupportedSnapdragonSeen.store(true, std::memory_order_release);
  }
  {
    std::lock_guard<std::mutex> lock(gQnnErrorLogMutex);
    if (!gQnnErrorLog.empty()) gQnnErrorLog.push_back('\n');
    gQnnErrorLog += message;
    constexpr std::size_t kMaximumCapturedLogBytes = 8192U;
    if (gQnnErrorLog.size() > kMaximumCapturedLogBytes) {
      gQnnErrorLog.erase(0U, gQnnErrorLog.size() - kMaximumCapturedLogBytes);
    }
  }
  __android_log_print(ANDROID_LOG_ERROR, kTag, "%s", message.c_str());
}

struct GraphInfo {
  Qnn_GraphHandle_t graph;
  char* graphName;
  Qnn_Tensor_t* inputTensors;
  uint32_t numInputTensors;
  Qnn_Tensor_t* outputTensors;
  uint32_t numOutputTensors;
};
using GraphInfoPtr = GraphInfo*;
struct GraphConfigInfo {
  char* graphName;
  const QnnGraph_Config_t** graphConfigs;
};
enum ModelError : int { kModelNoError = 0 };
using ComposeGraphsFn = ModelError (*)(Qnn_BackendHandle_t, QNN_INTERFACE_VER_TYPE,
                                       Qnn_ContextHandle_t, const GraphConfigInfo**, uint32_t,
                                       GraphInfoPtr**, uint32_t*, bool, QnnLog_Callback_t,
                                       QnnLog_Level_t);
using FreeGraphsInfoFn = ModelError (*)(GraphInfoPtr**, uint32_t);
using GetProvidersFn = Qnn_ErrorHandle_t (*)(const QnnInterface_t***, uint32_t*);

size_t dataTypeBytes(Qnn_DataType_t type) {
  switch (type) {
    case QNN_DATATYPE_INT_8: case QNN_DATATYPE_UINT_8: case QNN_DATATYPE_SFIXED_POINT_8:
    case QNN_DATATYPE_UFIXED_POINT_8: return 1;
    case QNN_DATATYPE_INT_16: case QNN_DATATYPE_UINT_16: case QNN_DATATYPE_FLOAT_16:
    case QNN_DATATYPE_SFIXED_POINT_16: case QNN_DATATYPE_UFIXED_POINT_16: return 2;
    case QNN_DATATYPE_INT_32: case QNN_DATATYPE_UINT_32: case QNN_DATATYPE_FLOAT_32:
    case QNN_DATATYPE_SFIXED_POINT_32: case QNN_DATATYPE_UFIXED_POINT_32: return 4;
    case QNN_DATATYPE_INT_64: case QNN_DATATYPE_UINT_64: case QNN_DATATYPE_FLOAT_64: return 8;
    default: return 0;
  }
}

size_t tensorBytes(const Qnn_Tensor_t& tensor) {
  const uint32_t rank = tensor.version == QNN_TENSOR_VERSION_2 ? tensor.v2.rank : tensor.v1.rank;
  const uint32_t* dimensions = tensor.version == QNN_TENSOR_VERSION_2 ? tensor.v2.dimensions : tensor.v1.dimensions;
  if (rank == 0 || dimensions == nullptr) return 0;
  size_t elements = 1;
  for (uint32_t index = 0; index < rank; ++index) elements *= dimensions[index];
  const Qnn_DataType_t dataType = tensor.version == QNN_TENSOR_VERSION_2 ? tensor.v2.dataType : tensor.v1.dataType;
  return elements * dataTypeBytes(dataType);
}

const char* tensorName(const Qnn_Tensor_t& tensor) noexcept {
  return tensor.version == QNN_TENSOR_VERSION_2 ? tensor.v2.name : tensor.v1.name;
}

Qnn_DataType_t tensorDataType(const Qnn_Tensor_t& tensor) noexcept {
  return tensor.version == QNN_TENSOR_VERSION_2 ? tensor.v2.dataType : tensor.v1.dataType;
}

Qnn_QuantizeParams_t tensorQuantizeParams(const Qnn_Tensor_t& tensor) noexcept {
  return tensor.version == QNN_TENSOR_VERSION_2 ? tensor.v2.quantizeParams
                                                 : tensor.v1.quantizeParams;
}

std::span<const uint32_t> tensorDimensions(const Qnn_Tensor_t& tensor) noexcept {
  const uint32_t rank = tensor.version == QNN_TENSOR_VERSION_2 ? tensor.v2.rank : tensor.v1.rank;
  const uint32_t* dimensions =
      tensor.version == QNN_TENSOR_VERSION_2 ? tensor.v2.dimensions : tensor.v1.dimensions;
  return dimensions == nullptr ? std::span<const uint32_t>{}
                               : std::span<const uint32_t>{dimensions, rank};
}

bool tensorMatches(const Qnn_Tensor_t& tensor, std::string_view expectedName,
                   Qnn_DataType_t expectedDataType,
                   std::span<const uint32_t> expectedDimensions) noexcept {
  const char* name = tensorName(tensor);
  const auto dimensions = tensorDimensions(tensor);
  return name != nullptr && expectedName == name && tensorDataType(tensor) == expectedDataType &&
      dimensions.size() == expectedDimensions.size() &&
      std::equal(dimensions.begin(), dimensions.end(), expectedDimensions.begin());
}

bool tensorMatchesScaleOffset(const Qnn_Tensor_t& tensor, float expectedScale,
                              int32_t expectedOffset) noexcept {
  const Qnn_QuantizeParams_t quantization = tensorQuantizeParams(tensor);
  const float tolerance = std::max(1.0e-12F, std::abs(expectedScale) * 1.0e-5F);
  return quantization.encodingDefinition == QNN_DEFINITION_DEFINED &&
      quantization.quantizationEncoding == QNN_QUANTIZATION_ENCODING_SCALE_OFFSET &&
      std::abs(quantization.scaleOffsetEncoding.scale - expectedScale) <= tolerance &&
      quantization.scaleOffsetEncoding.offset == expectedOffset;
}

std::string describeTensor(const Qnn_Tensor_t& tensor) {
  const uint32_t rank = tensor.version == QNN_TENSOR_VERSION_2 ? tensor.v2.rank : tensor.v1.rank;
  const uint32_t* dimensions = tensor.version == QNN_TENSOR_VERSION_2 ? tensor.v2.dimensions : tensor.v1.dimensions;
  const Qnn_DataType_t data_type = tensor.version == QNN_TENSOR_VERSION_2 ? tensor.v2.dataType : tensor.v1.dataType;
  std::ostringstream value;
  value << "name=" << (tensorName(tensor) == nullptr ? "<null>" : tensorName(tensor))
        << " rank=" << rank << " dims=[";
  for (uint32_t index = 0; index < rank; ++index) {
    if (index != 0) value << ',';
    value << (dimensions == nullptr ? 0 : dimensions[index]);
  }
  value << "] data_type=" << static_cast<uint32_t>(data_type) << " bytes=" << tensorBytes(tensor);
  return value.str();
}

void bindClientBuffer(
    Qnn_Tensor_t& tensor, void* data, std::uint32_t bytes) noexcept {
  const Qnn_ClientBuffer_t client_buffer{data, bytes};
  if (tensor.version == QNN_TENSOR_VERSION_2) {
    tensor.v2.clientBuf = client_buffer;
  } else {
    tensor.v1.clientBuf = client_buffer;
  }
}

std::string percentileMs(const std::vector<double>& sorted, double percentile) {
  const size_t index = std::min(sorted.size() - 1,
      static_cast<size_t>(std::ceil(percentile * sorted.size()) - 1));
  std::ostringstream stream;
  stream.setf(std::ios::fixed); stream.precision(2); stream << sorted[index];
  return stream.str();
}

uint64_t bufferFingerprint(const std::vector<uint8_t>& buffer) {
  uint64_t hash = 1469598103934665603ULL;
  for (uint8_t value : buffer) {
    hash ^= value;
    hash *= 1099511628211ULL;
  }
  return hash;
}

uint64_t outputFingerprint(const std::vector<std::vector<uint8_t>>& buffers) {
  uint64_t hash = 1469598103934665603ULL;
  for (const auto& buffer : buffers) {
    hash ^= bufferFingerprint(buffer);
    hash *= 1099511628211ULL;
  }
  return hash;
}

class Runtime {
 public:
  ~Runtime() { releaseResources(); }

  std::string run(const std::string& nativeLibraryDirectory,
                  const std::string& skeletonDirectory,
                  std::string_view modelToken) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialize(nativeLibraryDirectory, skeletonDirectory, modelToken)) return diagnostic_;
    return benchmark();
  }

  std::string inferOne(const std::string& nativeLibraryDirectory,
                       const std::string& skeletonDirectory,
                       std::string_view modelToken,
                       const uint8_t* input,
                       size_t input_bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialize(nativeLibraryDirectory, skeletonDirectory, modelToken)) return diagnostic_;
    if (input == nullptr || input_bytes != inputBuffer_.size()) {
      return "QNN realtime inference rejected: expected " + std::to_string(inputBuffer_.size())
          + " bytes of " + std::to_string(active_model_->input.width) + "x"
          + std::to_string(active_model_->input.height)
          + "x3 U16 NHWC RGB input (scale=1/65535), received " + std::to_string(input_bytes);
    }
    std::memcpy(inputBuffer_.data(), input, inputBuffer_.size());
    const auto started = std::chrono::steady_clock::now();
    const Qnn_ErrorHandle_t status = qnn_.graphExecute(graphs_[0]->graph, &input_, 1, outputTensors_.data(),
                                                        static_cast<uint32_t>(outputTensors_.size()), nullptr, nullptr);
    const auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started).count();
    if (status != QNN_GRAPH_NO_ERROR) return "QNN realtime graphExecute failed status=" + std::to_string(status);
    return "QNN realtime graphExecute=OK; input_bytes=" + std::to_string(input_bytes)
        + "; elapsed_us=" + std::to_string(elapsed_us)
        + "; output_fingerprint=" + std::to_string(outputFingerprint(outputBuffers_));
  }

  bool prepare(const std::string& nativeLibraryDirectory,
               const std::string& skeletonDirectory,
               std::string_view modelToken) {
    std::lock_guard<std::mutex> lock(mutex_);
    return initialize(nativeLibraryDirectory, skeletonDirectory, modelToken);
  }

  void release() {
    std::lock_guard<std::mutex> lock(mutex_);
    releaseResources();
  }

  bool configurePostprocess(float confidence_threshold, float iou_threshold) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!std::isfinite(confidence_threshold) || !std::isfinite(iou_threshold) ||
        confidence_threshold < 0.0F || confidence_threshold > 1.0F ||
        iou_threshold < 0.0F || iou_threshold > 1.0F) return false;
    postprocess_config_.confidence_threshold = confidence_threshold;
    postprocess_config_.iou_threshold = iou_threshold;
    return true;
  }

  std::string report() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream profile;
    profile.setf(std::ios::fixed);
    profile.precision(2);
    profile << "postprocess_confidence=" << postprocess_config_.confidence_threshold
            << " postprocess_iou=" << postprocess_config_.iou_threshold;
    return "ready=" + std::to_string(ready_ ? 1 : 0) + "\n" + profile.str() + "\n" + diagnostic_;
  }

  bool executeRealtime(std::span<const uint8_t> input, uint64_t* elapsed_us, uint32_t* graph_status,
                       uint32_t* detection_count, std::vector<vfdual_android::YoloDetection>* detections) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (graph_status != nullptr) *graph_status = 0xffffffffU;
    if (detection_count != nullptr) *detection_count = 0;
    if (detections != nullptr) detections->clear();
    if (!ready_ || input.size() != inputBuffer_.size()) return false;
    // QnnGraph_execute explicitly permits clientBuf to change between
    // synchronous invocations. Bind the preprocessed frame directly and avoid
    // copying roughly one MiB on every inference.
    bindClientBuffer(
        input_, const_cast<uint8_t*>(input.data()),
        static_cast<std::uint32_t>(input.size()));
    const auto started = std::chrono::steady_clock::now();
    const Qnn_ErrorHandle_t status = qnn_.graphExecute(graphs_[0]->graph, &input_, 1, outputTensors_.data(),
                                                        static_cast<uint32_t>(outputTensors_.size()), nullptr, nullptr);
    bindClientBuffer(
        input_, inputBuffer_.data(),
        static_cast<std::uint32_t>(inputBuffer_.size()));
    if (elapsed_us != nullptr) *elapsed_us = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started).count());
    if (graph_status != nullptr) *graph_status = static_cast<uint32_t>(status);
    if (status != QNN_GRAPH_NO_ERROR) return false;
    if (detection_count != nullptr) {
      const auto tensor_name = [](const Qnn_Tensor_t& tensor) { return tensor.version == QNN_TENSOR_VERSION_2 ? tensor.v2.name : tensor.v1.name; };
      const auto find_buffer = [this, &tensor_name](const char* name) -> const std::vector<uint8_t>* {
        for (std::size_t index = 0; index < outputTensors_.size(); ++index) {
          const char* candidate = tensor_name(outputTensors_[index]);
          if (candidate != nullptr && std::strcmp(candidate, name) == 0) return &outputBuffers_[index];
        }
        return nullptr;
      };
      const auto* coordinates = find_buffer("output_coordinates");
      const auto* confidences = find_buffer("output_confidences");
      if (coordinates != nullptr && confidences != nullptr) {
        const vfdual_android::YoloSplitTensorContract tensor_contract{
            .anchor_count = active_model_->output.anchor_count,
            .class_count = active_model_->output.class_count};
        auto& decoded = detections == nullptr ? postprocess_detections_ : *detections;
        if (!vfdual_android::decode_qnn_split_yolo_output_into(
                *coordinates, *confidences, postprocess_config_, tensor_contract,
                postprocess_candidates_, decoded)) {
          return false;
        }
        *detection_count = static_cast<uint32_t>(decoded.size());
      }
    }
    return true;
  }

 private:
  bool initialize(const std::string& nativeLibraryDirectory,
                  const std::string& skeletonDirectory,
                  std::string_view modelToken) {
    (void)nativeLibraryDirectory;
    const auto* requestedModel = vfdual::find_mobile_model(modelToken);
    if (requestedModel == nullptr) {
      diagnostic_ = "FAILED model selection: unsupported model token=" +
          std::string(modelToken) +
          " failure_code=qnn_model_selection_invalid retryable=false\\n";
      return false;
    }
    if (ready_ && active_model_ == requestedModel) return true;
    if (ready_) releaseResources();
    active_model_ = requestedModel;
    // A generated model wrapper can publish a non-null GraphInfo array before
    // it publishes the graph count.  If composition then fails, that wrapper's
    // exported free routine cannot safely reclaim the partial array.  Do not
    // retry such a poisoned initialization in-process and accumulate leaks;
    // the service/process restart remains the recovery boundary.
    if (initializationPoisoned_) return false;
    // FastRPC uses semicolon, not the POSIX colon convention, to split DSP search paths.
    // Match the qnn-net-run invocation already proven on this exact phone.
    std::string adspPath = skeletonDirectory + ";" + skeletonDirectory + "/";
    setenv("ADSP_LIBRARY_PATH", adspPath.c_str(), 1);
    diagnostic_.clear();
    diagnostic_ += "QNN HTP application audit\\n";
    diagnostic_ += "ADSP_LIBRARY_PATH=" + adspPath + "\\n";
    rpcLibrary_ = dlopen("libcdsprpc.so", RTLD_NOW | RTLD_GLOBAL);
    if (!rpcLibrary_) {
      return failTerminal("dlopen Qualcomm RPC transport",
                          "qnn_rpc_runtime_unavailable", dlerror());
    }
    diagnostic_ += "Qualcomm RPC transport=loaded from vendor public library\\n";
    const std::string backendPath = skeletonDirectory + "/libQnnHtp.so";
    backendLibrary_ = dlopen(backendPath.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!backendLibrary_) {
      return failTerminal("dlopen HTP backend", "qnn_htp_runtime_unavailable", dlerror());
    }
    modelLibrary_ = dlopen(active_model_->qnn_library.data(), RTLD_NOW | RTLD_LOCAL);
    if (!modelLibrary_) {
      return failTerminal("dlopen QNN INT8 model",
                          "qnn_model_runtime_unavailable", dlerror());
    }
    auto getProviders = reinterpret_cast<GetProvidersFn>(dlsym(backendLibrary_, "QnnInterface_getProviders"));
    auto compose = reinterpret_cast<ComposeGraphsFn>(dlsym(modelLibrary_, "QnnModel_composeGraphs"));
    freeGraphsInfo_ =
        reinterpret_cast<FreeGraphsInfoFn>(dlsym(modelLibrary_, "QnnModel_freeGraphsInfo"));
    if (!getProviders || !compose || !freeGraphsInfo_) {
      return failTerminal("resolve QNN ABI", "qnn_runtime_abi_invalid",
                          "required symbol absent");
    }
    const QnnInterface_t** providers = nullptr;
    uint32_t providerCount = 0;
    if (getProviders(&providers, &providerCount) != QNN_SUCCESS || providerCount == 0) {
      return failTerminal("QnnInterface_getProviders",
                          "qnn_runtime_provider_unavailable",
                          "no QNN provider returned");
    }
    qnn_ = providers[0]->QNN_INTERFACE_VER_NAME;
    // Capture error-only backend diagnostics so unsupported Snapdragon models
    // become machine-readable instead of existing only in transient logcat.
    clearQnnErrorLog();
    if (qnn_.logCreate == nullptr ||
        qnn_.logCreate(captureQnnErrorLog, QNN_LOG_LEVEL_ERROR, &logger_) != QNN_LOG_NO_ERROR) {
      return failTerminal("logCreate", "qnn_runtime_logging_unavailable",
                           "unable to configure QNN error-only diagnostics");
    }
    recordPlatformInfo();
    const Qnn_ErrorHandle_t backendStatus =
        qnn_.backendCreate(logger_, nullptr, &backend_);
    if (backendStatus != QNN_BACKEND_NO_ERROR) {
      return failQnnInitialization(
          "backendCreate", backendStatus, "QNN backend initialization failed",
          "qnn_backend_create_failed");
    }
    if (qnn_.deviceCreate) {
      const Qnn_ErrorHandle_t deviceStatus =
          qnn_.deviceCreate(logger_, nullptr, &device_);
      if (deviceStatus != QNN_SUCCESS && deviceStatus != QNN_DEVICE_ERROR_UNSUPPORTED_FEATURE) {
        return failQnnInitialization(
            "deviceCreate", deviceStatus, "HTP device initialization failed",
            "qnn_device_create_failed");
      }
      if (deviceStatus == QNN_DEVICE_ERROR_UNSUPPORTED_FEATURE) {
        diagnostic_ += "deviceCreate=unsupported by this backend; continuing with null device handle\\n";
      }
    }
    const Qnn_ErrorHandle_t contextStatus =
        qnn_.contextCreate(backend_, device_, nullptr, &context_);
    if (contextStatus != QNN_CONTEXT_NO_ERROR) {
      return failQnnInitialization(
          "contextCreate", contextStatus, "HTP context initialization failed",
          "qnn_context_create_failed");
    }
    const bool turbo_plus_enabled = configureTurboPlus();
    const ModelError composeStatus = compose(
        backend_, qnn_, context_, nullptr, 0, &graphs_, &graphCount_, false,
        captureQnnErrorLog,
        QNN_LOG_LEVEL_ERROR);
    if (composeStatus != kModelNoError || graphCount_ != 1) {
      if (graphs_ != nullptr && graphCount_ == 0U) initializationPoisoned_ = true;
      return failQnnInitialization(
          "QnnModel_composeGraphs",
          static_cast<Qnn_ErrorHandle_t>(composeStatus),
          "model graph composition failed", "qnn_model_compose_failed");
    }
    const Qnn_ErrorHandle_t finalizeStatus =
        qnn_.graphFinalize(graphs_[0]->graph, nullptr, nullptr);
    if (finalizeStatus != QNN_GRAPH_NO_ERROR) {
      return failQnnInitialization(
          "graphFinalize", finalizeStatus, "HTP graph finalization failed",
          "qnn_model_finalize_failed");
    }
    if (graphs_[0]->numInputTensors != 1 || graphs_[0]->numOutputTensors != 2) {
      return failTerminal("model tensor contract", "qnn_model_contract_invalid",
                          "expected one input and split coordinate/confidence outputs");
    }
    input_ = graphs_[0]->inputTensors[0];
    outputTensors_.assign(graphs_[0]->outputTensors,
                          graphs_[0]->outputTensors + graphs_[0]->numOutputTensors);

    const std::array<uint32_t, 4> expectedInputDimensions{
        1U,
        active_model_->input.height,
        active_model_->input.width,
        active_model_->input.channels};
    const std::array<uint32_t, 3> expectedCoordinateDimensions{
        1U, 4U, active_model_->output.anchor_count};
    const std::array<uint32_t, 3> expectedConfidenceDimensions{
        1U,
        active_model_->output.class_count,
        active_model_->output.anchor_count};
    constexpr float kExpectedInputScale = 0.0000152590218931F;
    if (!tensorMatches(input_, "images", QNN_DATATYPE_UFIXED_POINT_16,
                       expectedInputDimensions) ||
        !tensorMatchesScaleOffset(input_, kExpectedInputScale, 0)) {
      const std::string detail = "unexpected input: " + describeTensor(input_);
      return failTerminal("model tensor contract", "qnn_model_contract_invalid",
                          detail.c_str());
    }
    const Qnn_Tensor_t* coordinateTensor = nullptr;
    const Qnn_Tensor_t* confidenceTensor = nullptr;
    for (const Qnn_Tensor_t& tensor : outputTensors_) {
      if (tensorName(tensor) != nullptr &&
          std::strcmp(tensorName(tensor), "output_coordinates") == 0) {
        coordinateTensor = &tensor;
      } else if (tensorName(tensor) != nullptr &&
                 std::strcmp(tensorName(tensor), "output_confidences") == 0) {
        confidenceTensor = &tensor;
      }
    }
    if (coordinateTensor == nullptr ||
        !tensorMatches(*coordinateTensor, "output_coordinates", QNN_DATATYPE_FLOAT_32,
                       expectedCoordinateDimensions)) {
      const std::string detail = coordinateTensor == nullptr
          ? "output_coordinates absent"
          : "unexpected output_coordinates: " + describeTensor(*coordinateTensor);
      return failTerminal("model tensor contract", "qnn_model_contract_invalid",
                          detail.c_str());
    }
    if (confidenceTensor == nullptr ||
        !tensorMatches(*confidenceTensor, "output_confidences", QNN_DATATYPE_FLOAT_32,
                       expectedConfidenceDimensions)) {
      const std::string detail = confidenceTensor == nullptr
          ? "output_confidences absent"
          : "unexpected output_confidences: " + describeTensor(*confidenceTensor);
      return failTerminal("model tensor contract", "qnn_model_contract_invalid",
                          detail.c_str());
    }

    inputBuffer_.resize(tensorBytes(input_));
    outputBuffers_.resize(outputTensors_.size());
    size_t totalOutputBytes = 0;
    for (size_t index = 0; index < outputTensors_.size(); ++index) {
      outputBuffers_[index].resize(tensorBytes(outputTensors_[index]));
      totalOutputBytes += outputBuffers_[index].size();
    }
    if (inputBuffer_.empty() || totalOutputBytes == 0) {
      return failTerminal("tensor allocation", "qnn_model_contract_invalid",
                          "unsupported tensor data type or dimensions");
    }
    for (size_t index = 0; index < inputBuffer_.size(); ++index) inputBuffer_[index] = static_cast<uint8_t>(index % 251);
    bindClientBuffer(
        input_, inputBuffer_.data(),
        static_cast<std::uint32_t>(inputBuffer_.size()));
    for (size_t index = 0; index < outputTensors_.size(); ++index) {
      bindClientBuffer(
          outputTensors_[index], outputBuffers_[index].data(),
          static_cast<std::uint32_t>(outputBuffers_[index].size()));
      logLine("QNN output tensor[" + std::to_string(index) + "] " + describeTensor(outputTensors_[index]));
    }
    diagnostic_ += "backend=QNN HTP; model=" +
        std::string(active_model_->token) +
        "; precision=W8A16; outputs=FP32 split; graph=1\\n";
    diagnostic_ += turbo_plus_enabled
        ? "HTP performance vote=DCVS v3 Turbo+ (bus/core), sleep disabled, RPC control latency=100us\\n"
        : "HTP performance vote=device default (optional Turbo+ vote unavailable); inference remains enabled\\n";
    diagnostic_ += "input bytes=" + std::to_string(inputBuffer_.size()) + "; output bytes=" + std::to_string(totalOutputBytes) + " (coordinates + confidences)\\n";
    ready_ = true;
    return true;
  }

  void recordPlatformInfo() {
    if (qnn_.deviceGetPlatformInfo == nullptr ||
        qnn_.deviceFreePlatformInfo == nullptr) {
      diagnostic_ += "HTP platform info=provider API unavailable\\n";
      return;
    }
    const QnnDevice_PlatformInfo_t* platform = nullptr;
    const Qnn_ErrorHandle_t status =
        qnn_.deviceGetPlatformInfo(logger_, &platform);
    if (status != QNN_SUCCESS || platform == nullptr) {
      diagnostic_ += "HTP platform info=query failed status=" +
          std::to_string(status) + "\\n";
      return;
    }
    bool described = false;
    if (platform->version == QNN_DEVICE_PLATFORM_INFO_VERSION_1) {
      for (uint32_t index = 0; index < platform->v1.numHwDevices; ++index) {
        const QnnDevice_HardwareDeviceInfo_t& device =
            platform->v1.hwDevices[index];
        if (device.version != QNN_DEVICE_HARDWARE_DEVICE_INFO_VERSION_1 ||
            device.v1.deviceInfoExtension == nullptr) {
          continue;
        }
        const auto* htp = reinterpret_cast<
            const QnnHtpDevice_DeviceInfoExtension_t*>(
            device.v1.deviceInfoExtension);
        if (htp->devType != QNN_HTP_DEVICE_TYPE_ON_CHIP) continue;
        diagnostic_ += "HTP platform device_id=" +
            std::to_string(device.v1.deviceId) +
            " soc_model=" + std::to_string(htp->onChipDevice.socModel) +
            " htp_arch=v" +
            std::to_string(static_cast<uint32_t>(htp->onChipDevice.arch)) +
            " vtcm_mb=" + std::to_string(htp->onChipDevice.vtcmSize) +
            " cores=" + std::to_string(device.v1.numCores) + "\\n";
        described = true;
      }
    }
    if (!described) {
      diagnostic_ += "HTP platform info=no on-chip device reported\\n";
    }
    qnn_.deviceFreePlatformInfo(logger_, platform);
  }

  bool configureTurboPlus() {
    if (!qnn_.deviceGetInfrastructure) {
      return performanceVoteFallback("deviceGetInfrastructure", "HTP performance infrastructure unavailable");
    }
    QnnDevice_Infrastructure_t infrastructure = nullptr;
    if (qnn_.deviceGetInfrastructure(&infrastructure) != QNN_SUCCESS || !infrastructure) {
      return performanceVoteFallback("deviceGetInfrastructure", "cannot obtain HTP performance infrastructure");
    }
    auto* htp = reinterpret_cast<QnnHtpDevice_Infrastructure_t*>(infrastructure);
    if (!htp->perfInfra.createPowerConfigId || !htp->perfInfra.setPowerConfig) {
      return performanceVoteFallback("HTP performance infrastructure", "power configuration functions unavailable");
    }
    if (htp->perfInfra.createPowerConfigId(0, 0, &powerConfigId_) != QNN_SUCCESS) {
      return performanceVoteFallback("createPowerConfigId", "cannot create HTP performance vote");
    }
    powerConfigCreated_ = true;
    perfInfrastructure_ = &htp->perfInfra;
    QnnHtpPerfInfrastructure_PowerConfig_t config{};
    config.option = QNN_HTP_PERF_INFRASTRUCTURE_POWER_CONFIGOPTION_DCVS_V3;
    config.dcvsV3Config.dcvsEnable = 1; config.dcvsV3Config.setDcvsEnable = 1;
    config.dcvsV3Config.contextId = powerConfigId_;
    config.dcvsV3Config.powerMode = QNN_HTP_PERF_INFRASTRUCTURE_POWERMODE_PERFORMANCE_MODE;
    config.dcvsV3Config.setSleepDisable = 1;
    config.dcvsV3Config.sleepDisable = 1;
    config.dcvsV3Config.setSleepLatency = 1;
    config.dcvsV3Config.sleepLatency = 40;
    config.dcvsV3Config.setBusParams = 1;
    config.dcvsV3Config.busVoltageCornerMin = DCVS_VOLTAGE_VCORNER_TURBO_PLUS;
    config.dcvsV3Config.busVoltageCornerTarget = DCVS_VOLTAGE_VCORNER_TURBO_PLUS;
    config.dcvsV3Config.busVoltageCornerMax = DCVS_VOLTAGE_VCORNER_TURBO_PLUS;
    config.dcvsV3Config.setCoreParams = 1;
    config.dcvsV3Config.coreVoltageCornerMin = DCVS_VOLTAGE_VCORNER_TURBO_PLUS;
    config.dcvsV3Config.coreVoltageCornerTarget = DCVS_VOLTAGE_VCORNER_TURBO_PLUS;
    config.dcvsV3Config.coreVoltageCornerMax = DCVS_VOLTAGE_VCORNER_TURBO_PLUS;
    QnnHtpPerfInfrastructure_PowerConfig_t rpcControlLatency{};
    rpcControlLatency.option = QNN_HTP_PERF_INFRASTRUCTURE_POWER_CONFIGOPTION_RPC_CONTROL_LATENCY;
    rpcControlLatency.rpcControlLatencyConfig = 100;
    const QnnHtpPerfInfrastructure_PowerConfig_t* configs[] = {&config, &rpcControlLatency, nullptr};
    if (perfInfrastructure_->setPowerConfig(powerConfigId_, configs) != QNN_SUCCESS) {
      return performanceVoteFallback("setPowerConfig", "Turbo+ HTP performance vote rejected");
    }
    return true;
  }

  std::string benchmark() {
    auto execute = [&]() -> bool {
      return qnn_.graphExecute(graphs_[0]->graph, &input_, 1, outputTensors_.data(),
                               static_cast<uint32_t>(outputTensors_.size()), nullptr, nullptr) == QNN_GRAPH_NO_ERROR;
    };
    for (int index = 0; index < kWarmupRuns; ++index) if (!execute()) return failReport("warmup graphExecute failed");
    std::vector<double> samples; samples.reserve(kMeasuredRuns);
    std::unordered_set<uint64_t> outputFingerprints;
    for (int index = 0; index < kMeasuredRuns; ++index) {
      inputBuffer_[0] = static_cast<uint8_t>(index);
      const auto started = std::chrono::steady_clock::now();
      if (!execute()) return failReport("measured graphExecute failed");
      const auto elapsed = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
      samples.push_back(elapsed);
      outputFingerprints.insert(outputFingerprint(outputBuffers_));
    }
    std::sort(samples.begin(), samples.end());
    const double mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
    std::ostringstream report; report.setf(std::ios::fixed); report.precision(2);
    report << "Backend: QNN HTP (native JNI)\\nModel: "
           << active_model_->qnn_library << "\\n"
           << "Pure graphExecute (" << kMeasuredRuns << " runs, warmup " << kWarmupRuns << "): \\n"
           << "Mean: " << mean << " ms / " << 1000.0 / mean << " FPS\\n"
           << "Median: " << percentileMs(samples, 0.50) << " ms / " << 1000.0 / std::stod(percentileMs(samples, 0.50)) << " FPS\\n"
           << "P95: " << percentileMs(samples, 0.95) << " ms / " << 1000.0 / std::stod(percentileMs(samples, 0.95)) << " FPS\\n\\n"
           << diagnostic_ << "Result: graphExecute completed through QNN HTP backend. This is App-native QNN evidence, not NNAPI delegation.";
    report << "\\nOutput fingerprints across varying inputs: " << outputFingerprints.size() << "/" << kMeasuredRuns;
    return report.str();
  }

  void releaseResources() noexcept {
    ready_ = false;
    if (perfInfrastructure_ != nullptr && powerConfigCreated_ &&
        perfInfrastructure_->destroyPowerConfigId != nullptr) {
      (void)perfInfrastructure_->destroyPowerConfigId(powerConfigId_);
    }
    perfInfrastructure_ = nullptr;
    powerConfigId_ = 0U;
    powerConfigCreated_ = false;
    if (graphs_ != nullptr && graphCount_ > 0U && freeGraphsInfo_ != nullptr) {
      (void)freeGraphsInfo_(&graphs_, graphCount_);
    }
    graphs_ = nullptr;
    graphCount_ = 0U;
    if (context_ != nullptr && qnn_.contextFree != nullptr) {
      (void)qnn_.contextFree(context_, nullptr);
    }
    context_ = nullptr;
    if (device_ != nullptr && qnn_.deviceFree != nullptr) (void)qnn_.deviceFree(device_);
    device_ = nullptr;
    if (backend_ != nullptr && qnn_.backendFree != nullptr) (void)qnn_.backendFree(backend_);
    backend_ = nullptr;
    if (logger_ != nullptr && qnn_.logFree != nullptr) (void)qnn_.logFree(logger_);
    logger_ = nullptr;
    qnn_ = {};
    freeGraphsInfo_ = nullptr;
    input_ = QNN_TENSOR_INIT;
    inputBuffer_.clear();
    outputTensors_.clear();
    outputBuffers_.clear();
    if (modelLibrary_ != nullptr) dlclose(modelLibrary_);
    if (backendLibrary_ != nullptr) dlclose(backendLibrary_);
    if (rpcLibrary_ != nullptr) dlclose(rpcLibrary_);
    modelLibrary_ = nullptr;
    backendLibrary_ = nullptr;
    rpcLibrary_ = nullptr;
    active_model_ = nullptr;
  }

  bool failQnnInitialization(const char* stage, Qnn_ErrorHandle_t status,
                             const char* detail, const char* failureCode) {
    const std::string backendLog = qnnErrorLogSnapshot();
    const bool unsupportedSnapdragon =
        status == QNN_BACKEND_ERROR_UNSUPPORTED_PLATFORM ||
        gQnnUnsupportedSnapdragonSeen.load(std::memory_order_acquire);
    std::ostringstream failure;
    failure << (detail ? detail : "QNN initialization failed")
            << " backend_status=" << static_cast<unsigned long long>(status)
            << " failure_code="
            << (unsupportedSnapdragon
                    ? "qnn_htp_unsupported_snapdragon_model"
                    : failureCode)
            << " retryable=false";
    if (!backendLog.empty()) failure << " backend_log={" << backendLog << "}";
    const std::string failureDetail = failure.str();
    return fail(stage, failureDetail.c_str());
  }

  bool failTerminal(const char* stage, const char* failureCode, const char* detail) {
    std::ostringstream failure;
    failure << (detail ? detail : "QNN permanent initialization failure")
            << " failure_code="
            << (failureCode ? failureCode : "qnn_permanent_initialization_failure")
            << " retryable=false";
    const std::string failureDetail = failure.str();
    return fail(stage, failureDetail.c_str());
  }

  bool fail(const char* stage, const char* detail) {
    diagnostic_ += std::string("FAILED ") + stage + ": " +
        (detail ? detail : "unknown") + "\\n";
    logLine(diagnostic_);
    releaseResources();
    return false;
  }
  bool performanceVoteFallback(const char* stage, const char* detail) {
    diagnostic_ += std::string("OPTIONAL HTP PERFORMANCE VOTE UNAVAILABLE ") + stage + ": " +
        (detail ? detail : "unknown") + "\\n";
    logLine(diagnostic_);
    return false;
  }
  std::string failReport(const char* detail) { diagnostic_ += std::string("FAILED ") + detail + "\\n"; return diagnostic_; }
  std::mutex mutex_; bool ready_ = false; bool initializationPoisoned_ = false; std::string diagnostic_; void* rpcLibrary_ = nullptr; void* backendLibrary_ = nullptr; void* modelLibrary_ = nullptr; FreeGraphsInfoFn freeGraphsInfo_ = nullptr;
  const vfdual::MobileModelContract* active_model_ = nullptr;
  QNN_INTERFACE_VER_TYPE qnn_{}; Qnn_LogHandle_t logger_ = nullptr; Qnn_BackendHandle_t backend_ = nullptr; Qnn_DeviceHandle_t device_ = nullptr; Qnn_ContextHandle_t context_ = nullptr;
  GraphInfoPtr* graphs_ = nullptr; uint32_t graphCount_ = 0; Qnn_Tensor_t input_ = QNN_TENSOR_INIT;
  std::vector<Qnn_Tensor_t> outputTensors_; std::vector<uint8_t> inputBuffer_; std::vector<std::vector<uint8_t>> outputBuffers_;
  std::vector<vfdual_android::YoloDetection> postprocess_candidates_;
  std::vector<vfdual_android::YoloDetection> postprocess_detections_;
  vfdual_android::YoloPostprocessConfig postprocess_config_{
      .confidence_threshold = vfdual::kDefaultMobileModel.default_confidence,
      .iou_threshold = vfdual::kDefaultMobileModel.nms_iou};
  QnnHtpDevice_PerfInfrastructure_t* perfInfrastructure_ = nullptr; uint32_t powerConfigId_ = 0; bool powerConfigCreated_ = false;
};
Runtime& runtime() { static Runtime instance; return instance; }
std::string fromJString(JNIEnv* environment, jstring value) { const char* raw = environment->GetStringUTFChars(value, nullptr); std::string result(raw ? raw : ""); if (raw) environment->ReleaseStringUTFChars(value, raw); return result; }
}  // namespace

namespace vfdual_android {
bool prepare_qnn_realtime(const std::string& native_library_directory,
                          const std::string& skeleton_directory,
                          const std::string& model_token) {
  return runtime().prepare(native_library_directory, skeleton_directory, model_token);
}

bool execute_qnn_realtime(std::span<const std::uint8_t> rgb_nhwc, std::uint64_t* elapsed_us, std::uint32_t* graph_status,
                          std::uint32_t* detection_count, std::vector<YoloDetection>* detections) {
  return runtime().executeRealtime(rgb_nhwc, elapsed_us, graph_status, detection_count, detections);
}
bool configure_qnn_postprocess(float confidence_threshold, float iou_threshold) {
  return runtime().configurePostprocess(confidence_threshold, iou_threshold);
}

std::string qnn_realtime_report() {
  return runtime().report();
}

void release_qnn_realtime() {
  runtime().release();
}
}  // namespace vfdual_android

extern "C" JNIEXPORT jstring JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_runBenchmark(JNIEnv* environment, jclass,
                                                                   jstring nativeLibraryDirectory,
                                                                   jstring skeletonDirectory,
                                                                   jstring modelToken) {
  const std::string report = runtime().run(
      fromJString(environment, nativeLibraryDirectory),
      fromJString(environment, skeletonDirectory),
      fromJString(environment, modelToken));
  return environment->NewStringUTF(report.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_runDualTransportSelfTest(JNIEnv* environment, jclass) {
  const vfdual::VideoFragment source{0x20260721U, 1, 2, {std::byte{1}, std::byte{2}, std::byte{3}}};
  const auto wire = vfdual::encode_video_packet(source);
  vfdual::VideoFragment decoded;
  const bool ok = !wire.empty() && vfdual::decode_video_packet(wire, decoded)
      && decoded.frame_id == source.frame_id && decoded.fragment_index == source.fragment_index
      && decoded.fragment_count == source.fragment_count && decoded.access_unit_part == source.access_unit_part;
  const std::string report = ok
      ? "Dual-machine C++ protocol self-test: PASS (v5.0 12-byte UDP fragment ABI)."
      : "Dual-machine C++ protocol self-test: FAIL";
  return environment->NewStringUTF(report.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_runRealtimeQnnInput(
    JNIEnv* environment, jclass, jstring nativeLibraryDirectory, jstring skeletonDirectory,
    jstring modelToken, jbyteArray input) {
  if (input == nullptr) return environment->NewStringUTF("QNN realtime inference rejected: input is null");
  const jsize input_size = environment->GetArrayLength(input);
  jboolean copied = JNI_FALSE;
  const auto* raw = reinterpret_cast<const uint8_t*>(environment->GetByteArrayElements(input, &copied));
  const std::string report = runtime().inferOne(fromJString(environment, nativeLibraryDirectory),
                                                fromJString(environment, skeletonDirectory),
                                                fromJString(environment, modelToken), raw,
                                                static_cast<size_t>(input_size));
  if (raw != nullptr) environment->ReleaseByteArrayElements(input, const_cast<jbyte*>(reinterpret_cast<const jbyte*>(raw)), JNI_ABORT);
  return environment->NewStringUTF(report.c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_prepareNativeQnnRealtime(
    JNIEnv* environment, jclass, jstring nativeLibraryDirectory, jstring skeletonDirectory,
    jstring modelToken) {
  return vfdual_android::prepare_qnn_realtime(fromJString(environment, nativeLibraryDirectory),
                                              fromJString(environment, skeletonDirectory),
                                              fromJString(environment, modelToken)) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_prepareNativeInferenceRealtime(
    JNIEnv* environment, jclass, jstring backendToken,
    jstring nativeLibraryDirectory, jstring vendorRuntimeDirectory,
    jstring portableModelPath, jstring modelToken) {
  return vfdual_android::prepare_realtime_inference(
      fromJString(environment, backendToken),
      fromJString(environment, nativeLibraryDirectory),
      fromJString(environment, vendorRuntimeDirectory),
      fromJString(environment, portableModelPath),
      fromJString(environment, modelToken)) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_releaseNativeInferenceRealtime(
    JNIEnv*, jclass) {
  vfdual_android::release_realtime_inference();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_getNativeQnnRealtimeReport(JNIEnv* environment, jclass) {
  const std::string report = vfdual_android::realtime_inference_report();
  return environment->NewStringUTF(report.c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_bindNativeMakcuMoveBridge(
    JNIEnv* environment, jclass, jclass controller_class) {
  return controller_class != nullptr &&
      vfdual_android::bind_makcu_move_bridge(environment, controller_class)
      ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_configureNativeMakcuControl(
    JNIEnv* environment, jclass, jfloat gain, jfloat deadzone_pixels,
    jint maximum_axis_delta, jint switch_confirmation_ms,
    jboolean output_enabled,
    jboolean personal_trajectory_enabled, jlong personal_profile_seed,
    jfloat personal_speed_scale, jfloat personal_stability_scale,
    jfloat personal_variation_scale, jfloat personal_median_duration_ms,
    jfloat personal_peak_time_fraction, jfloat personal_bell_correlation,
    jfloat personal_jitter_amplitude_pixels,
    jfloat personal_jitter_maximum_pixels,
    jint personal_maximum_extra_counts,
    jfloat personal_minimum_error_pixels,
    jfloatArray personal_speed_envelope,
    jstring model_token,
    jint body_class_id,
    jint head_class_id,
    jint selected_class_id,
    jboolean selected_class_uses_head_box,
    jboolean selected_class_uses_geometric_head,
    jfloat target_y_ratio) {
  vfdual_android::MakcuControlProfile profile{};
  profile.relative_gain = gain;
  profile.deadzone_pixels = deadzone_pixels;
  profile.maximum_axis_delta =
      static_cast<std::int32_t>(maximum_axis_delta);
  profile.switch_confirmation_ms = switch_confirmation_ms < 0
      ? 0U : static_cast<std::uint32_t>(switch_confirmation_ms);
  profile.output_enabled = output_enabled == JNI_TRUE;
  profile.personal_trajectory_enabled =
      personal_trajectory_enabled == JNI_TRUE;
  profile.personal_profile_seed =
      static_cast<std::uint64_t>(personal_profile_seed);
  profile.personal_speed_scale = personal_speed_scale;
  profile.personal_stability_scale = personal_stability_scale;
  profile.personal_variation_scale = personal_variation_scale;
  profile.personal_median_duration_ms = personal_median_duration_ms;
  profile.personal_peak_time_fraction = personal_peak_time_fraction;
  profile.personal_bell_correlation = personal_bell_correlation;
  profile.personal_jitter_amplitude_pixels =
      personal_jitter_amplitude_pixels;
  profile.personal_jitter_maximum_pixels =
      personal_jitter_maximum_pixels;
  profile.personal_maximum_extra_counts =
      static_cast<std::int32_t>(personal_maximum_extra_counts);
  profile.personal_minimum_error_pixels =
      personal_minimum_error_pixels;
  profile.model_token = model_token == nullptr
      ? std::string{} : fromJString(environment, model_token);
  profile.body_class_id = static_cast<std::uint32_t>(body_class_id);
  profile.head_class_id = head_class_id < 0
      ? vfdual::kNoModelClass : static_cast<std::uint32_t>(head_class_id);
  profile.selected_class_id = static_cast<std::uint32_t>(selected_class_id);
  profile.selected_class_uses_head_box =
      selected_class_uses_head_box == JNI_TRUE;
  profile.selected_class_uses_geometric_head =
      selected_class_uses_geometric_head == JNI_TRUE;
  profile.target_y_ratio = target_y_ratio;
  if (personal_speed_envelope != nullptr) {
    const jsize count = environment->GetArrayLength(
        personal_speed_envelope);
    if (!environment->ExceptionCheck() && count >= 0 &&
        count <= static_cast<jsize>(
            profile.personal_speed_envelope.size())) {
      environment->GetFloatArrayRegion(
          personal_speed_envelope, 0, count,
          profile.personal_speed_envelope.data());
      if (!environment->ExceptionCheck()) {
        profile.personal_speed_envelope_count =
            static_cast<std::size_t>(count);
      }
    }
  }
  if (environment->ExceptionCheck()) {
    environment->ExceptionClear();
    // Profile marshalling failed, but the decoder and its stream generation
    // are still alive.  Fail the physical delivery gate without turning this
    // transient JNI/configuration error into a permanent stale-generation
    // lockout for every later frame from the same stream.
    vfdual_android::fail_closed_makcu_delivery();
    return JNI_FALSE;
  }
  return vfdual_android::configure_makcu_control_profile(profile) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_failClosedNativeMakcuOutput(
    JNIEnv*, jclass) {
  vfdual_android::fail_closed_makcu_delivery();
}

extern "C" JNIEXPORT void JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_reportNativeMakcuMoveResult(
    JNIEnv*, jclass, jlong ticket, jboolean device_acknowledged,
    jlong acknowledgement_us) {
  vfdual_android::report_makcu_move_result(
      static_cast<std::uint64_t>(ticket),
      device_acknowledged == JNI_TRUE,
      acknowledgement_us > 0
          ? static_cast<std::uint64_t>(acknowledgement_us)
          : 0U);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_reportNativeBluetoothHidMoveAccepted(
    JNIEnv*, jclass, jlong ticket, jlong api_acceptance_us) {
  return vfdual_android::report_bluetooth_hid_move_accepted(
      static_cast<std::uint64_t>(ticket),
      api_acceptance_us > 0
          ? static_cast<std::uint64_t>(api_acceptance_us)
          : 0U) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_configureNativeQnnPostprocess(
    JNIEnv*, jclass, jfloat confidence_threshold, jfloat iou_threshold) {
  return vfdual_android::configure_realtime_postprocess(
      confidence_threshold, iou_threshold) ? JNI_TRUE : JNI_FALSE;
}
