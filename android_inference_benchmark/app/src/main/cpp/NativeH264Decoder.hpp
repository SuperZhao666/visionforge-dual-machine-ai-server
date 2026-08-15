#pragma once

#include <jni.h>
#include <media/NdkMediaCodec.h>

#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <deque>
#include <atomic>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "DecoderInputDropMetrics.hpp"
#include "FixedMetricRing.hpp"
#include "InferenceGenerationPolicy.hpp"
#include "YoloPostprocessor.hpp"
#include "vfdual/image_preprocessor.hpp"

struct ANativeWindow;

namespace vfdual_android {

/** Surface decoder consumer. Network code only sees submit(), never MediaCodec state. */
class NativeH264Decoder final {
public:
  static constexpr std::uint64_t kStreamRestartTimeoutUs = 250'000U;

  struct StreamRestartCompletion final {
    std::uint64_t generation{};
    bool succeeded{};
    std::uint64_t elapsed_us{};
  };

  [[nodiscard]] bool configure(JNIEnv* environment, jobject surface, std::int32_t width, std::int32_t height);
  [[nodiscard]] bool configure_for_inference(std::int32_t width, std::int32_t height);
  void bind_java_decoder(JNIEnv* environment, jobject decoder);
  [[nodiscard]] bool submit(
      std::span<const std::byte> access_unit, std::uint64_t presentation_us,
      std::uint32_t frame_id, std::uint64_t control_sequence,
      bool content_updated);
  [[nodiscard]] bool process_java_yuv420(
      const vfdual::Yuv420PlaneView& y_plane, const vfdual::Yuv420PlaneView& u_plane,
      const vfdual::Yuv420PlaneView& v_plane, std::int32_t image_width,
      std::int32_t image_height, std::int32_t crop_left, std::int32_t crop_top,
      std::int32_t crop_right, std::int32_t crop_bottom,
      std::int64_t presentation_time_us);
  void update_java_decoder_format(
      std::string codec_name, std::int32_t color_format, std::int32_t color_standard,
      std::int32_t color_range, std::int32_t width, std::int32_t height);
  [[nodiscard]] bool has_fatal_decoder_failure() const;
  void discard_java_decoded_output(
      std::int64_t presentation_time_us, std::string reason, bool fatal);
  void discard_java_compressed_access_unit(
      std::int64_t presentation_time_us, std::string reason, bool fatal);
  /** Recreates only MediaCodec; QNN and the bound UDP socket stay live. */
  [[nodiscard]] bool restart_after_stream_discontinuity();
  void complete_stream_restart(
      std::uint64_t generation, bool succeeded, std::uint64_t elapsed_us,
      std::string diagnostic);
  /** Consumes the current-generation completion edge exactly once. */
  [[nodiscard]] std::optional<StreamRestartCompletion> take_stream_restart_completion();
  [[nodiscard]] bool has_stream_restart_timed_out();
  /** Fails closed before a full pipeline rebuild, without touching Java inline. */
  void mark_stream_discontinuity();
  void stop();
  [[nodiscard]] std::string report() const;
  /**
   * Enables a bounded, explicitly requested offline trace. It is intentionally disabled by
   * default so the real-time control path never serializes per-frame detection data.
   */
  void begin_detection_trace(std::size_t maximum_frames);
  [[nodiscard]] std::string detection_trace_csv() const;
  [[nodiscard]] std::string pipeline_metrics_csv() const;
  ~NativeH264Decoder();

private:
  void output_loop();
  void inference_loop();
  void process_output_locked(std::size_t output_index, const AMediaCodecBufferInfo& output);
  [[nodiscard]] JavaAccessUnitOfferResult submit_to_java_locked(
      std::span<const std::byte> access_unit, std::uint64_t presentation_us, bool sync_frame);
  [[nodiscard]] std::string java_input_health_report_locked() const;
  void update_output_format_locked();

  struct PendingFrame {
    std::int64_t presentation_us{};
    std::uint32_t frame_id{};
    std::uint64_t control_sequence{};
    bool content_updated{};
    std::uint64_t stream_generation{};
  };

  struct DetectionTraceFrame {
    std::uint32_t frame_id{};
    std::vector<YoloDetection> detections;
  };

  struct PendingInferenceFrame {
    std::vector<std::uint8_t> input;
    std::uint32_t frame_id{};
    std::uint64_t control_sequence{};
    bool content_updated{};
    std::uint64_t stream_generation{};
    std::uint64_t observed_at_us{};
    std::uint64_t preprocess_us{};
    std::uint64_t decode_queue_us{};
  };

  struct PipelineMetric {
    std::uint32_t frame_id{};
    std::uint64_t decode_queue_us{};
    std::uint64_t preprocess_us{};
    std::uint64_t qnn_us{};
    std::uint32_t detections{};
    std::uint32_t qnn_status{};
  };

  struct QnnSuccessCommit final {
    bool committed{};
    std::optional<std::uint64_t> resume_generation;
    std::uint64_t execution_count{};
  };

  static constexpr std::size_t kLatencySampleCapacity = 300U;
  static constexpr std::size_t kPipelineMetricCapacity = 600U;

  [[nodiscard]] std::optional<PendingFrame> take_pending_frame_for_output_locked(std::int64_t presentation_us);
  void append_detection_trace_locked(std::uint32_t frame_id);
  /** mutex_ must be held; restart/failure state is part of the generation contract. */
  [[nodiscard]] bool is_current_stream_generation_locked(
      std::uint64_t generation) const noexcept;
  /** Atomically rejects a late old-generation failure or commits current state. */
  [[nodiscard]] std::optional<std::uint64_t> commit_qnn_failure(
      std::uint64_t generation, std::uint32_t graph_status,
      std::uint64_t failed_at_us);
  /** Atomically publishes metrics/detections only for the active generation. */
  [[nodiscard]] QnnSuccessCommit commit_qnn_success(
      const PendingInferenceFrame& frame, std::uint64_t qnn_us,
      std::uint32_t graph_status, std::uint32_t detection_count,
      std::uint64_t inference_total_us, std::uint64_t completed_at_us,
      std::vector<YoloDetection>& detections);
  /** inference_mutex_ must be held; preserves every reusable input allocation. */
  void recycle_pending_inference_frames_locked();

  mutable std::mutex mutex_;
  /** Serializes Java output-buffer use with stop/reconfigure, not UDP state access. */
  std::mutex java_output_callback_mutex_;
  std::thread output_worker_;
  std::atomic_bool output_worker_running_{false};
  std::thread inference_worker_;
  std::atomic_bool inference_worker_running_{false};
  std::mutex inference_mutex_;
  std::condition_variable inference_condition_;
  AMediaCodec* codec_{};
  ANativeWindow* output_window_{};
  bool output_window_owned_{};
  JavaVM* java_vm_{};
  jobject java_decoder_object_{};
  jmethodID java_offer_access_unit_method_{};
  jmethodID java_has_fatal_failure_method_{};
  jmethodID java_fatal_diagnostic_method_{};
  jmethodID java_restart_after_discontinuity_method_{};
  jmethodID java_input_health_report_method_{};
  bool java_image_decoder_mode_{};
  bool java_decoder_failed_{};
  std::string java_decoder_name_{"unconfigured"};
  std::string java_decoder_failure_{};
  std::vector<std::uint8_t> model_input_;
  std::deque<PendingInferenceFrame> pending_inference_frames_;
  std::vector<std::vector<std::uint8_t>> free_model_inputs_;
  std::int32_t output_color_format_{};
  std::int32_t output_color_standard_{1};
  std::int32_t output_color_range_{2};
  std::int32_t decoded_width_{};
  std::int32_t decoded_height_{};
  std::int32_t output_stride_{};
  std::int32_t output_slice_height_{};
  std::int32_t output_crop_left_{};
  std::int32_t output_crop_top_{};
  std::int32_t output_crop_right_{};
  std::int32_t output_crop_bottom_{};
  std::int32_t image_crop_left_{};
  std::int32_t image_crop_top_{};
  std::int32_t image_crop_right_{};
  std::int32_t image_crop_bottom_{};
  std::int32_t image_y_row_stride_{};
  std::int32_t image_u_row_stride_{};
  std::int32_t image_v_row_stride_{};
  std::int32_t image_y_pixel_stride_{};
  std::int32_t image_u_pixel_stride_{};
  std::int32_t image_v_pixel_stride_{};
  std::uint64_t acquired_images_{};
  std::uint64_t image_layout_failures_{};
  std::uint64_t rejected_output_images_{};
  std::uint64_t queued_access_units_{};
  std::uint64_t sync_access_units_{};
  std::uint64_t rendered_frames_{};
  std::uint64_t fresh_content_outputs_{};
  std::uint64_t repeated_content_outputs_{};
  std::uint64_t stale_decoded_outputs_{};
  std::uint64_t superseded_preprocessed_frames_{};
  std::atomic_uint64_t stale_pre_inference_frames_{};
  std::atomic_uint64_t inference_queue_high_watermark_{};
  std::atomic_uint64_t maximum_pre_inference_frame_age_us_{};
  std::uint64_t stale_generation_inference_suppressions_{};
  std::uint64_t stale_generation_result_suppressions_{};
  std::uint64_t stale_generation_control_suppressions_{};
  std::uint64_t repeated_content_inferences_{};
  std::uint64_t repeated_content_inference_suppressions_{};
  std::uint64_t repeated_content_control_suppressions_{};
  std::uint64_t dropped_access_units_{};
  DecoderInputDropMetrics input_drop_metrics_{};
  std::uint64_t qnn_executions_{};
  std::uint64_t qnn_failures_{};
  std::uint64_t consecutive_qnn_failures_{};
  std::uint64_t last_qnn_success_monotonic_us_{};
  std::uint64_t last_qnn_failure_monotonic_us_{};
  std::uint64_t preprocess_failures_{};
  std::uint64_t stream_restarts_{};
  std::uint64_t stream_restart_failures_{};
  std::uint64_t last_stream_restart_us_{};
  std::uint64_t last_stream_restart_request_us_{};
  std::uint64_t stream_restart_generation_{};
  std::uint64_t stream_restart_started_us_{};
  bool stream_restart_in_progress_{};
  std::optional<StreamRestartCompletion> pending_stream_restart_completion_;
  std::optional<std::uint64_t> pending_makcu_resume_generation_;
  FixedMetricRing<std::uint64_t, kLatencySampleCapacity> preprocess_samples_us_;
  FixedMetricRing<std::uint64_t, kLatencySampleCapacity> qnn_samples_us_;
  FixedMetricRing<std::uint64_t, kLatencySampleCapacity> inference_total_samples_us_;
  FixedMetricRing<std::uint64_t, kLatencySampleCapacity> decode_queue_samples_us_;
  std::uint64_t last_preprocess_us_{};
  std::uint64_t last_qnn_us_{};
  std::uint64_t last_inference_total_us_{};
  std::uint32_t last_input_nal_type_mask_{};
  std::uint32_t last_detection_count_{};
  std::vector<YoloDetection> last_detections_;
  std::uint32_t last_qnn_status_{0xffffffffU};
  std::deque<PendingFrame> pending_frames_;
  bool detection_trace_enabled_{};
  std::size_t detection_trace_maximum_frames_{};
  std::vector<DetectionTraceFrame> detection_trace_frames_;
  FixedMetricRing<PipelineMetric, kPipelineMetricCapacity> pipeline_metrics_;
};

NativeH264Decoder& decoder();

}  // namespace vfdual_android
