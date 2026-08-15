#include "QnnRealtimeExecutor.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "OnnxRuntimeRealtimeExecutor.hpp"
#include "vfdual/model_contract.hpp"

namespace {

enum class ActiveBackend : std::uint8_t {
  none,
  qnn_htp,
  onnxruntime_nnapi,
  onnxruntime_cpu,
};

constexpr std::string_view kQnnToken = "qnn_htp";
constexpr std::string_view kNnapiToken = "onnxruntime_nnapi";
constexpr std::string_view kCpuToken = "onnxruntime_cpu";

std::atomic<ActiveBackend> g_active_backend{ActiveBackend::none};
std::mutex g_router_report_mutex;
std::string g_router_report{"ready=0 backend_token=none"};

void set_router_report(std::string report) {
  std::scoped_lock lock(g_router_report_mutex);
  g_router_report = std::move(report);
}

std::string router_report() {
  std::scoped_lock lock(g_router_report_mutex);
  return g_router_report;
}

ActiveBackend parse_backend(std::string_view token) noexcept {
  if (token == kQnnToken) return ActiveBackend::qnn_htp;
  if (token == kNnapiToken) return ActiveBackend::onnxruntime_nnapi;
  if (token == kCpuToken) return ActiveBackend::onnxruntime_cpu;
  return ActiveBackend::none;
}

std::string_view backend_token(ActiveBackend backend) noexcept {
  switch (backend) {
    case ActiveBackend::qnn_htp: return kQnnToken;
    case ActiveBackend::onnxruntime_nnapi: return kNnapiToken;
    case ActiveBackend::onnxruntime_cpu: return kCpuToken;
    case ActiveBackend::none:
    default: return "none";
  }
}

void release_all_backends() {
  g_active_backend.store(ActiveBackend::none, std::memory_order_release);
  vfdual_android::release_qnn_realtime();
  vfdual_android::release_onnxruntime_realtime();
}

}  // namespace

namespace vfdual_android {

bool prepare_realtime_inference(
    std::string_view backend_token_value,
    const std::string& native_library_directory,
    const std::string& vendor_runtime_directory,
    const std::string& portable_model_path,
    const std::string& model_token) {
  const ActiveBackend requested = parse_backend(backend_token_value);
  release_all_backends();
  if (requested == ActiveBackend::none) {
    set_router_report(
        "ready=0 failure_code=inference_backend_invalid retryable=false");
    return false;
  }

  bool prepared = false;
  if (requested == ActiveBackend::qnn_htp) {
    prepared = prepare_qnn_realtime(
        native_library_directory, vendor_runtime_directory, model_token);
    if (prepared) {
      const vfdual::MobileModelContract* model =
          vfdual::find_mobile_model(model_token);
      if (model == nullptr) {
        prepared = false;
      } else {
        // byte=114 encodes U16 value 114*257 because both little-endian
        // bytes are identical. This executes the exact selected QNN graph.
        std::vector<std::uint8_t> probe(
            vfdual::model_input_bytes(model->input), 114U);
        std::uint64_t elapsed_us{};
        std::uint32_t graph_status{0xffffffffU};
        prepared = execute_qnn_realtime(
            probe, &elapsed_us, &graph_status, nullptr, nullptr);
        std::ostringstream report;
        report << "backend_token=" << kQnnToken
               << " probe_execution="
               << (prepared ? "success" : "failed")
               << " probe_us=" << elapsed_us
               << " probe_status=" << graph_status << '\n'
               << qnn_realtime_report();
        set_router_report(report.str());
      }
    } else {
      set_router_report("backend_token=" + std::string(kQnnToken)
          + " probe_execution=not_run\n" + qnn_realtime_report());
    }
  } else {
    prepared = prepare_onnxruntime_realtime(
        backend_token_value, portable_model_path, model_token);
    set_router_report(onnxruntime_realtime_report());
  }

  if (!prepared) {
    release_all_backends();
    return false;
  }
  g_active_backend.store(requested, std::memory_order_release);
  return true;
}

bool execute_realtime_inference(
    std::span<const std::uint8_t> rgb_nhwc_u16,
    std::uint64_t* elapsed_us,
    std::uint32_t* graph_status,
    std::uint32_t* detection_count,
    std::vector<YoloDetection>* detections) {
  switch (g_active_backend.load(std::memory_order_acquire)) {
    case ActiveBackend::qnn_htp:
      return execute_qnn_realtime(
          rgb_nhwc_u16, elapsed_us, graph_status,
          detection_count, detections);
    case ActiveBackend::onnxruntime_nnapi:
    case ActiveBackend::onnxruntime_cpu:
      return execute_onnxruntime_realtime(
          rgb_nhwc_u16, elapsed_us, graph_status,
          detection_count, detections);
    case ActiveBackend::none:
    default:
      if (elapsed_us != nullptr) *elapsed_us = 0U;
      if (graph_status != nullptr) *graph_status = 0xffffffffU;
      if (detection_count != nullptr) *detection_count = 0U;
      if (detections != nullptr) detections->clear();
      return false;
  }
}

bool configure_realtime_postprocess(
    float confidence_threshold,
    float iou_threshold) {
  switch (g_active_backend.load(std::memory_order_acquire)) {
    case ActiveBackend::qnn_htp:
      return configure_qnn_postprocess(
          confidence_threshold, iou_threshold);
    case ActiveBackend::onnxruntime_nnapi:
    case ActiveBackend::onnxruntime_cpu:
      return configure_onnxruntime_postprocess(
          confidence_threshold, iou_threshold);
    case ActiveBackend::none:
    default:
      // Control profiles are also configured while the data plane is armed.
      // Validate and stage both backends so the later selected runtime inherits
      // the same thresholds without loosening the fail-closed output gate.
      return configure_qnn_postprocess(
                 confidence_threshold, iou_threshold) &&
          configure_onnxruntime_postprocess(
                 confidence_threshold, iou_threshold);
  }
}

std::string realtime_inference_report() {
  const ActiveBackend active =
      g_active_backend.load(std::memory_order_acquire);
  if (active == ActiveBackend::qnn_htp) {
    return router_report() + '\n' + qnn_realtime_report();
  }
  if (active == ActiveBackend::onnxruntime_nnapi ||
      active == ActiveBackend::onnxruntime_cpu) {
    return onnxruntime_realtime_report();
  }
  return router_report();
}

std::string_view realtime_inference_backend_token() noexcept {
  return backend_token(
      g_active_backend.load(std::memory_order_acquire));
}

void release_realtime_inference() {
  release_all_backends();
  set_router_report("ready=0 backend_token=none");
}

}  // namespace vfdual_android
