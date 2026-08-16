#include "NativeH264Decoder.hpp"

#include <android/log.h>
#include <android/native_window_jni.h>
#include <media/NdkMediaCodec.h>
#include <media/NdkMediaFormat.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <cstring>
#include <mutex>
#include <sstream>

#include "QnnRealtimeExecutor.hpp"
#include "MakcuMoveBridge.hpp"
#include "MakcuOutputGate.hpp"
#include "MobileControlCore.hpp"
#include "vfdual/h264_access_unit.hpp"
#include "vfdual/image_preprocessor.hpp"

namespace vfdual_android {
namespace {
constexpr std::int32_t kColorFormatYuv420Flexible = 0x7f420888;
constexpr std::int32_t kColorStandardBt709 = 1;
constexpr std::int32_t kColorStandardBt601Pal = 2;
constexpr std::int32_t kColorStandardBt601Ntsc = 4;
constexpr std::int32_t kColorRangeLimited = 2;
constexpr std::int32_t kMaximumDecodedWidth = 3840;
constexpr std::int32_t kMaximumDecodedHeight = 2160;
// Match the single-machine latest-frame slot: one frame may execute while only
// the newest eligible decoded observation waits.  More pending frames add
// latency after a scheduler hiccup without increasing single-worker throughput.
constexpr std::size_t kInferenceQueueCapacity = 1;
constexpr std::size_t kModelInputBytes =
    vfdual::model_input_bytes(vfdual::kDefaultMobileModel.input);
constexpr std::int64_t kInputPollTimeoutUs = 1'000;
constexpr std::int64_t kOutputWorkerPollTimeoutUs = 1'000;

JNIEnv* current_thread_environment(JavaVM* vm) {
  if (vm == nullptr) return nullptr;
  struct ThreadAttachment final {
    JavaVM* vm{};
    JNIEnv* environment{};
    bool attached{};
    ~ThreadAttachment() {
      if (attached && vm != nullptr) vm->DetachCurrentThread();
    }
  };
  thread_local ThreadAttachment attachment;
  if (attachment.vm == vm && attachment.environment != nullptr) return attachment.environment;
  JNIEnv* environment{};
  if (vm->GetEnv(reinterpret_cast<void**>(&environment), JNI_VERSION_1_6) == JNI_OK) {
    attachment = {vm, environment, false};
    return environment;
  }
  if (vm->AttachCurrentThread(&environment, nullptr) != JNI_OK) return nullptr;
  attachment.vm = vm;
  attachment.environment = environment;
  attachment.attached = true;
  return environment;
}

template <std::size_t Capacity>
void record_latency(
    FixedMetricRing<std::uint64_t, Capacity>& samples,
    std::uint64_t value) noexcept {
  (void)samples.push(value);
}

template <std::size_t Capacity>
std::string percentile_summary(
    const FixedMetricRing<std::uint64_t, Capacity>& samples) {
  if (samples.empty()) return "n=0";
  std::array<std::uint64_t, Capacity> sorted{};
  for (std::size_t index = 0; index < samples.size(); ++index) {
    sorted[index] = samples.oldest_at(index);
  }
  std::sort(sorted.begin(), sorted.begin() + samples.size());
  const auto percentile = [&sorted, sample_count = samples.size()](
                              std::size_t numerator) {
    return sorted[(sample_count - 1U) * numerator / 100U];
  };
  return "n=" + std::to_string(samples.size()) + " p50_us=" + std::to_string(percentile(50)) +
         " p95_us=" + std::to_string(percentile(95)) +
         " p99_us=" + std::to_string(percentile(99));
}

}
bool NativeH264Decoder::configure(JNIEnv* environment, jobject surface, std::int32_t width, std::int32_t height) {
  if (surface == nullptr || width <= 0 || height <= 0) return false;
  stop();
  std::scoped_lock lock(mutex_);
  output_window_ = ANativeWindow_fromSurface(environment, surface);
  if (output_window_ == nullptr) return false;
  output_window_owned_ = true;
  codec_ = AMediaCodec_createDecoderByType("video/avc");
  if (codec_ == nullptr) { ANativeWindow_release(output_window_); output_window_ = nullptr; return false; }
  AMediaFormat* format = AMediaFormat_new();
  AMediaFormat_setString(format, AMEDIAFORMAT_KEY_MIME, "video/avc");
  AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_WIDTH, width);
  AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_HEIGHT, height);
  // The host captures the active desktop, while the model always consumes a
  // model-shaped image. Permit MediaCodec to adapt to the H.264 SPS
  // source size instead of treating the model input dimensions as video size.
  AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_MAX_WIDTH, kMaximumDecodedWidth);
  AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_MAX_HEIGHT, kMaximumDecodedHeight);
  const media_status_t configured = AMediaCodec_configure(codec_, format, output_window_, nullptr, 0);
  AMediaFormat_delete(format);
  if (configured != AMEDIA_OK || AMediaCodec_start(codec_) != AMEDIA_OK) {
    AMediaCodec_delete(codec_); codec_ = nullptr;
    ANativeWindow_release(output_window_); output_window_ = nullptr;
    return false;
  }
  queued_access_units_ = 0; rendered_frames_ = 0; stale_decoded_outputs_ = 0;
  dropped_access_units_ = 0;
  input_drop_metrics_.reset();
  output_worker_running_ = true;
  output_worker_ = std::thread(&NativeH264Decoder::output_loop, this);
  return true;
}

bool NativeH264Decoder::configure_for_inference(std::int32_t width, std::int32_t height) {
  if (width <= 0 || height <= 0) return false;
  stop();
  std::scoped_lock lock(mutex_);
  if (java_vm_ == nullptr || java_decoder_object_ == nullptr ||
      java_offer_access_unit_method_ == nullptr) {
    __android_log_print(
        ANDROID_LOG_ERROR, "VisionForgeDual", "Java Image.Plane decoder bridge is not bound");
    return false;
  }
  model_input_.resize(kModelInputBytes);
  java_image_decoder_mode_ = true;
  java_decoder_failed_ = false;
  java_decoder_failure_.clear();
  output_color_format_ = kColorFormatYuv420Flexible;
  output_color_standard_ = kColorStandardBt709;
  output_color_range_ = kColorRangeLimited;
  decoded_width_ = width;
  decoded_height_ = height;
  output_stride_ = width;
  output_slice_height_ = height;
  output_crop_left_ = output_crop_top_ = 0;
  output_crop_right_ = width;
  output_crop_bottom_ = height;
  image_crop_left_ = image_crop_top_ = 0;
  image_crop_right_ = image_crop_bottom_ = 0;
  image_y_row_stride_ = image_u_row_stride_ = image_v_row_stride_ = 0;
  image_y_pixel_stride_ = image_u_pixel_stride_ = image_v_pixel_stride_ = 0;
  acquired_images_ = image_layout_failures_ = rejected_output_images_ = 0;
  queued_access_units_ = sync_access_units_ = rendered_frames_ =
      fresh_content_outputs_ = repeated_content_outputs_ = stale_decoded_outputs_ =
      superseded_preprocessed_frames_ =
      stale_generation_inference_suppressions_ =
      stale_generation_result_suppressions_ =
      stale_generation_control_suppressions_ =
      repeated_content_inferences_ = repeated_content_inference_suppressions_ =
      repeated_content_control_suppressions_ =
      dropped_access_units_ = qnn_executions_ = qnn_failures_ = preprocess_failures_ = 0;
  consecutive_qnn_failures_ = 0;
  stale_pre_inference_frames_.store(0, std::memory_order_relaxed);
  inference_queue_high_watermark_.store(0, std::memory_order_relaxed);
  maximum_pre_inference_frame_age_us_.store(0, std::memory_order_relaxed);
  last_qnn_success_monotonic_us_ = last_qnn_failure_monotonic_us_ = 0;
  input_drop_metrics_.reset();
  stream_restarts_ = stream_restart_failures_ = last_stream_restart_us_ = 0;
  last_stream_restart_request_us_ = stream_restart_started_us_ = 0;
  ++stream_restart_generation_;
  activate_makcu_stream_generation(stream_restart_generation_);
  stream_restart_in_progress_ = false;
  pending_stream_restart_completion_.reset();
  pending_makcu_resume_generation_.reset();
  java_decoder_name_ = "starting";
  last_detection_count_ = 0;
  last_detections_.clear();
  pending_frames_.clear();
  last_qnn_status_ = 0xffffffffU;
  last_input_nal_type_mask_ = 0;
  preprocess_samples_us_.clear(); qnn_samples_us_.clear();
  inference_total_samples_us_.clear(); decode_queue_samples_us_.clear();
  pipeline_metrics_.clear();
  pending_inference_frames_.clear();
  free_model_inputs_.clear();
  free_model_inputs_.resize(kInferenceQueueCapacity + 1);
  for (auto& input : free_model_inputs_) input.resize(kModelInputBytes);
  inference_worker_running_ = true;
  inference_worker_ = std::thread(&NativeH264Decoder::inference_loop, this);
  return true;
}

void NativeH264Decoder::bind_java_decoder(JNIEnv* environment, jobject decoder) {
  if (environment == nullptr || decoder == nullptr) return;
  std::scoped_lock lock(mutex_);
  JavaVM* vm{};
  if (environment->GetJavaVM(&vm) != JNI_OK || vm == nullptr) return;
  if (java_decoder_object_ != nullptr) environment->DeleteGlobalRef(java_decoder_object_);
  java_decoder_object_ = environment->NewGlobalRef(decoder);
  jclass decoder_class = environment->GetObjectClass(decoder);
  java_offer_access_unit_method_ = decoder_class == nullptr
      ? nullptr
      : environment->GetMethodID(
            decoder_class, "offerAccessUnit", "(Ljava/nio/ByteBuffer;IJZ)I");
  java_has_fatal_failure_method_ = decoder_class == nullptr
      ? nullptr
      : environment->GetMethodID(decoder_class, "hasFatalFailure", "()Z");
  java_fatal_diagnostic_method_ = decoder_class == nullptr
      ? nullptr
      : environment->GetMethodID(decoder_class, "fatalDiagnostic", "()Ljava/lang/String;");
  java_restart_after_discontinuity_method_ = decoder_class == nullptr
      ? nullptr
      : environment->GetMethodID(
            decoder_class, "requestStreamRestart", "(IIJ)Z");
  java_input_health_report_method_ = decoder_class == nullptr
      ? nullptr
      : environment->GetMethodID(decoder_class, "inputHealthReport", "()Ljava/lang/String;");
  if (decoder_class != nullptr) environment->DeleteLocalRef(decoder_class);
  java_vm_ = vm;
  if (environment->ExceptionCheck()) {
    environment->ExceptionDescribe();
    environment->ExceptionClear();
    java_offer_access_unit_method_ = nullptr;
    java_has_fatal_failure_method_ = nullptr;
    java_fatal_diagnostic_method_ = nullptr;
    java_restart_after_discontinuity_method_ = nullptr;
    java_input_health_report_method_ = nullptr;
  }
}

bool NativeH264Decoder::submit(
    std::span<const std::byte> access_unit, std::uint64_t presentation_us,
    std::uint32_t frame_id, std::uint64_t control_sequence,
    bool content_updated) {
  std::unique_lock lock(mutex_);
  if (access_unit.empty()) return false;
  if (java_image_decoder_mode_) {
    if (java_decoder_failed_) {
      ++dropped_access_units_;
      ++input_drop_metrics_.not_running;
      return false;
    }
    last_input_nal_type_mask_ = vfdual::h264_annex_b_nal_type_mask(access_unit);
    const bool sync_frame = (last_input_nal_type_mask_ & (1U << 5U)) != 0U ||
        vfdual::h264_avcc_contains_idr(access_unit);
    const bool produces_decoded_frame =
        (last_input_nal_type_mask_ & ((1U << 1U) | (1U << 5U))) != 0U;
    if (produces_decoded_frame) {
      pending_frames_.push_back({
          static_cast<std::int64_t>(presentation_us), frame_id, control_sequence,
          content_updated, stream_restart_generation_});
    }
    // Do not hold the decoder state lock across Java MediaCodec. The output
    // thread calls back into process_java_yuv420 and must not be starved by a
    // high-rate input producer.
    lock.unlock();
    const auto offer_result = submit_to_java_locked(access_unit, presentation_us, sync_frame);
    lock.lock();
    if (offer_result != JavaAccessUnitOfferResult::accepted) {
      if (produces_decoded_frame) {
        const auto rejected = std::find_if(
            pending_frames_.rbegin(), pending_frames_.rend(),
            [presentation_us](const PendingFrame& pending) {
              return pending.presentation_us == static_cast<std::int64_t>(presentation_us);
            });
        if (rejected != pending_frames_.rend()) {
          pending_frames_.erase(std::next(rejected).base());
        }
      }
      ++dropped_access_units_;
      input_drop_metrics_.record_offer(offer_result);
      return false;
    }
    ++queued_access_units_;
    if (sync_frame) ++sync_access_units_;
    return true;
  }
  if (codec_ == nullptr) {
    ++dropped_access_units_;
    ++input_drop_metrics_.not_running;
    return false;
  }
  // The output worker owns decode-output, preprocessing and QNN. Keep the UDP
  // receive path bounded so a slow consumer cannot starve socket reassembly.
  const ssize_t index = AMediaCodec_dequeueInputBuffer(codec_, kInputPollTimeoutUs);
  if (index < 0) {
    ++dropped_access_units_;
    ++input_drop_metrics_.no_input_buffer;
    return false;
  }
  size_t capacity{};
  std::uint8_t* destination = AMediaCodec_getInputBuffer(codec_, static_cast<size_t>(index), &capacity);
  if (destination == nullptr || access_unit.size() > capacity) {
    ++dropped_access_units_;
    ++input_drop_metrics_.buffer_capacity;
    return false;
  }
  std::memcpy(destination, access_unit.data(), access_unit.size());
  last_input_nal_type_mask_ = vfdual::h264_annex_b_nal_type_mask(access_unit);
  const bool sync_frame = vfdual::h264_access_unit_contains_idr(access_unit);
  const std::uint32_t flags = sync_frame ? AMEDIACODEC_BUFFER_FLAG_KEY_FRAME : 0U;
  if (AMediaCodec_queueInputBuffer(codec_, static_cast<size_t>(index), 0, access_unit.size(), presentation_us, flags) != AMEDIA_OK) {
    ++dropped_access_units_;
    ++input_drop_metrics_.codec_exception;
    return false;
  }
  pending_frames_.push_back({
      static_cast<std::int64_t>(presentation_us), frame_id, control_sequence,
      content_updated, stream_restart_generation_});
  ++queued_access_units_;
  if (sync_frame) ++sync_access_units_;
  return true;
}

JavaAccessUnitOfferResult NativeH264Decoder::submit_to_java_locked(
    std::span<const std::byte> access_unit, std::uint64_t presentation_us, bool sync_frame) {
  JNIEnv* environment = current_thread_environment(java_vm_);
  if (environment == nullptr || java_decoder_object_ == nullptr ||
      java_offer_access_unit_method_ == nullptr || access_unit.size() > INT32_MAX) {
    return JavaAccessUnitOfferResult::bridge_failure;
  }
  jobject buffer = environment->NewDirectByteBuffer(
      const_cast<std::byte*>(access_unit.data()), static_cast<jlong>(access_unit.size()));
  if (buffer == nullptr) return JavaAccessUnitOfferResult::bridge_failure;
  const jint result_code = environment->CallIntMethod(
      java_decoder_object_, java_offer_access_unit_method_, buffer,
      static_cast<jint>(access_unit.size()), static_cast<jlong>(presentation_us),
      sync_frame ? JNI_TRUE : JNI_FALSE);
  environment->DeleteLocalRef(buffer);
  if (environment->ExceptionCheck()) {
    environment->ExceptionDescribe();
    environment->ExceptionClear();
    __android_log_print(
        ANDROID_LOG_ERROR, "VisionForgeDual", "Java decoder access-unit callback failed");
    return JavaAccessUnitOfferResult::bridge_failure;
  }
  bool fatal_failure = false;
  std::string fatal_diagnostic;
  if (result_code != static_cast<jint>(JavaAccessUnitOfferResult::accepted) &&
      java_has_fatal_failure_method_ != nullptr &&
      environment->CallBooleanMethod(
          java_decoder_object_, java_has_fatal_failure_method_) == JNI_TRUE) {
    fatal_failure = true;
    if (java_fatal_diagnostic_method_ != nullptr) {
      auto* diagnostic = static_cast<jstring>(environment->CallObjectMethod(
          java_decoder_object_, java_fatal_diagnostic_method_));
      if (diagnostic != nullptr) {
        const char* utf = environment->GetStringUTFChars(diagnostic, nullptr);
        if (utf != nullptr) {
          fatal_diagnostic = utf;
          environment->ReleaseStringUTFChars(diagnostic, utf);
        }
        environment->DeleteLocalRef(diagnostic);
      }
    }
  }
  if (environment->ExceptionCheck()) {
    environment->ExceptionDescribe();
    environment->ExceptionClear();
  }
  if (fatal_failure) {
    std::scoped_lock lock(mutex_);
    java_decoder_failed_ = true;
    java_decoder_failure_ = fatal_diagnostic.empty() ? "unknown" : std::move(fatal_diagnostic);
  }
  if (result_code < static_cast<jint>(JavaAccessUnitOfferResult::accepted) ||
      result_code > static_cast<jint>(JavaAccessUnitOfferResult::reference_recovery)) {
    return JavaAccessUnitOfferResult::bridge_failure;
  }
  return static_cast<JavaAccessUnitOfferResult>(result_code);
}

void NativeH264Decoder::output_loop() {
  while (output_worker_running_) {
    AMediaCodec* active_codec{};
    {
      std::scoped_lock lock(mutex_);
      active_codec = codec_;
    }
    if (active_codec == nullptr) break;

    AMediaCodecBufferInfo output{};
    const ssize_t output_index = AMediaCodec_dequeueOutputBuffer(
        active_codec, &output, kOutputWorkerPollTimeoutUs);
    if (output_index == AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED) {
      std::scoped_lock lock(mutex_);
      update_output_format_locked();
      continue;
    }
    if (output_index < 0) continue;

    {
      std::scoped_lock lock(mutex_);
      process_output_locked(static_cast<std::size_t>(output_index), output);
    }
    AMediaCodec_releaseOutputBuffer(
        active_codec, static_cast<std::size_t>(output_index), output_window_ != nullptr);
  }
}

void NativeH264Decoder::inference_loop() {
  std::vector<YoloDetection> detections;
  const auto recycle_input = [this](std::vector<std::uint8_t>& input) {
    std::scoped_lock inference_lock(inference_mutex_);
    free_model_inputs_.push_back(std::move(input));
  };
  while (true) {
    PendingInferenceFrame frame{};
    {
      std::unique_lock lock(inference_mutex_);
      inference_condition_.wait(lock, [this] {
        return !inference_worker_running_.load(std::memory_order_acquire) ||
            !pending_inference_frames_.empty();
      });
      if (!inference_worker_running_.load(std::memory_order_acquire) &&
          pending_inference_frames_.empty()) {
        break;
      }
      frame = std::move(pending_inference_frames_.front());
      pending_inference_frames_.pop_front();
    }
    if (!inference_worker_running_.load(std::memory_order_acquire)) {
      recycle_input(frame.input);
      break;
    }

    bool current_before_inference{};
    {
      std::scoped_lock lock(mutex_);
      current_before_inference =
          is_current_stream_generation_locked(frame.stream_generation);
      if (!current_before_inference) {
        ++stale_generation_inference_suppressions_;
      }
    }
    if (!current_before_inference) {
      recycle_input(frame.input);
      continue;
    }

    const auto inference_started = std::chrono::steady_clock::now();
    const auto inference_started_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            inference_started.time_since_epoch()).count());
    const bool invalid_or_stale =
        inference_started_us < frame.observed_at_us ||
        inference_started_us - frame.observed_at_us >
            kMobileControlMaximumFrameAgeUs;
    if (inference_started_us >= frame.observed_at_us) {
      const std::uint64_t age_us = inference_started_us - frame.observed_at_us;
      maximum_pre_inference_frame_age_us_.store(
          std::max(maximum_pre_inference_frame_age_us_.load(
                       std::memory_order_relaxed),
                   age_us),
          std::memory_order_relaxed);
    }
    if (invalid_or_stale) {
      stale_pre_inference_frames_.fetch_add(1, std::memory_order_relaxed);
      recycle_input(frame.input);
      continue;
    }

    std::uint64_t qnn_us{};
    std::uint32_t graph_status{0xffffffffU};
    std::uint32_t detection_count{};
    detections.clear();
    const bool succeeded = vfdual_android::execute_realtime_inference(
        frame.input, &qnn_us, &graph_status, &detection_count, &detections);
    const auto inference_total_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - inference_started).count());
    if (!inference_worker_running_.load(std::memory_order_acquire)) {
      recycle_input(frame.input);
      break;
    }
    const auto completed_at_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    if (!succeeded) {
      const auto failure_count = commit_qnn_failure(
          frame.stream_generation, graph_status, completed_at_us);
      if (failure_count.has_value()) {
        __android_log_print(
            ANDROID_LOG_ERROR, "VisionForgeDual",
            "inference failure backend=%.*s count=%llu status=%u",
            static_cast<int>(realtime_inference_backend_token().size()),
            realtime_inference_backend_token().data(),
            static_cast<unsigned long long>(*failure_count), graph_status);
      }
      recycle_input(frame.input);
      continue;
    }

    const QnnSuccessCommit commit = commit_qnn_success(
        frame, qnn_us, graph_status, detection_count, inference_total_us,
        completed_at_us, detections);
    if (!commit.committed) {
      recycle_input(frame.input);
      continue;
    }
    if (commit.resume_generation.has_value()) {
      const bool resumed =
          resume_makcu_output_after_valid_frame(*commit.resume_generation);
      __android_log_print(
          ANDROID_LOG_INFO, "VisionForgeDual",
          "MAKCU recovery hold released=%d generation=%llu after_valid_qnn_frame=1",
          resumed ? 1 : 0,
          static_cast<unsigned long long>(*commit.resume_generation));
    }
    if (control_frame_is_actionable(commit.committed, frame.content_updated)) {
      // commit_qnn_success swaps the new result into last_detections_.  Only
      // this worker writes that vector, while readers hold mutex_.  The stream
      // generation is revalidated under Makcu's existing publish lock so a
      // restart between this commit and physical control cannot mutate state.
      publish_makcu_move_for_detections(
          last_detections_, frame.control_sequence, frame.stream_generation,
          frame.content_updated, frame.observed_at_us, completed_at_us);
    }
    if (commit.execution_count <= 3U || commit.execution_count % 30U == 0U) {
      __android_log_print(
          ANDROID_LOG_INFO, "VisionForgeDual",
          "inference success backend=%.*s count=%llu elapsed_us=%llu detections=%u",
          static_cast<int>(realtime_inference_backend_token().size()),
          realtime_inference_backend_token().data(),
          static_cast<unsigned long long>(commit.execution_count),
          static_cast<unsigned long long>(qnn_us), detection_count);
    }
    recycle_input(frame.input);
  }
}

std::optional<std::uint64_t> NativeH264Decoder::commit_qnn_failure(
    std::uint64_t generation, std::uint32_t graph_status,
    std::uint64_t failed_at_us) {
  std::scoped_lock lock(mutex_);
  if (!is_current_stream_generation_locked(generation)) {
    ++stale_generation_result_suppressions_;
    return std::nullopt;
  }
  ++qnn_failures_;
  ++consecutive_qnn_failures_;
  last_qnn_failure_monotonic_us_ = failed_at_us;
  last_qnn_status_ = graph_status;
  return qnn_failures_;
}

NativeH264Decoder::QnnSuccessCommit NativeH264Decoder::commit_qnn_success(
    const PendingInferenceFrame& frame, std::uint64_t qnn_us,
    std::uint32_t graph_status, std::uint32_t detection_count,
    std::uint64_t inference_total_us, std::uint64_t completed_at_us,
    std::vector<YoloDetection>& detections) {
  std::scoped_lock lock(mutex_);
  if (!is_current_stream_generation_locked(frame.stream_generation)) {
    ++stale_generation_result_suppressions_;
    ++stale_generation_control_suppressions_;
    return {};
  }

  QnnSuccessCommit commit{
      .committed = true,
      .resume_generation = std::nullopt,
      .execution_count = 0U};
  if (frame.content_updated && pending_makcu_resume_generation_.has_value() &&
      *pending_makcu_resume_generation_ == frame.stream_generation) {
    commit.resume_generation = pending_makcu_resume_generation_;
    pending_makcu_resume_generation_.reset();
  }
  ++qnn_executions_;
  consecutive_qnn_failures_ = 0;
  last_qnn_success_monotonic_us_ = completed_at_us;
  last_qnn_us_ = qnn_us;
  last_inference_total_us_ = inference_total_us;
  last_qnn_status_ = graph_status;
  last_detection_count_ = detection_count;
  last_detections_.swap(detections);
  record_latency(qnn_samples_us_, qnn_us);
  record_latency(inference_total_samples_us_, inference_total_us);
  (void)pipeline_metrics_.push({
      frame.frame_id, frame.decode_queue_us, frame.preprocess_us, qnn_us,
      last_detection_count_, last_qnn_status_});
  append_detection_trace_locked(frame.frame_id);
  if (!frame.content_updated) ++repeated_content_inferences_;
  commit.execution_count = qnn_executions_;
  return commit;
}

void NativeH264Decoder::process_output_locked(
    std::size_t, const AMediaCodecBufferInfo&) {
  ++rendered_frames_;
}

std::optional<NativeH264Decoder::PendingFrame> NativeH264Decoder::take_pending_frame_for_output_locked(std::int64_t presentation_us) {
  const auto match = std::find_if(pending_frames_.begin(), pending_frames_.end(),
      [presentation_us](const PendingFrame& pending) { return pending.presentation_us == presentation_us; });
  if (match == pending_frames_.end()) return std::nullopt;
  const PendingFrame pending = *match;
  pending_frames_.erase(match);
  return pending;
}

void NativeH264Decoder::append_detection_trace_locked(std::uint32_t frame_id) {
  if (!detection_trace_enabled_ || frame_id == 0 || detection_trace_frames_.size() >= detection_trace_maximum_frames_) return;
  detection_trace_frames_.push_back({frame_id, last_detections_});
}

void NativeH264Decoder::update_output_format_locked() {
  AMediaFormat* format = AMediaCodec_getOutputFormat(codec_);
  if (format == nullptr) return;
  AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_COLOR_FORMAT, &output_color_format_);
  AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_COLOR_STANDARD, &output_color_standard_);
  AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_COLOR_RANGE, &output_color_range_);
  AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_WIDTH, &decoded_width_);
  AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_HEIGHT, &decoded_height_);
  __android_log_print(
      ANDROID_LOG_INFO, "VisionForgeDual",
      "surface decoder format actual=%#x standard=%d range=%d size=%dx%d",
      output_color_format_, output_color_standard_, output_color_range_,
      decoded_width_, decoded_height_);
  AMediaFormat_delete(format);
}

bool NativeH264Decoder::process_java_yuv420(
    const vfdual::Yuv420PlaneView& y_plane, const vfdual::Yuv420PlaneView& u_plane,
    const vfdual::Yuv420PlaneView& v_plane, std::int32_t image_width,
    std::int32_t image_height, std::int32_t crop_left, std::int32_t crop_top,
    std::int32_t crop_right, std::int32_t crop_bottom,
    std::int64_t presentation_time_us) {
  std::scoped_lock callback_lock(java_output_callback_mutex_);
  std::unique_lock lock(mutex_);
  if (!java_image_decoder_mode_ ||
      !inference_worker_running_.load(std::memory_order_acquire)) {
    ++stale_decoded_outputs_;
    return false;
  }
  const auto pending_metadata = take_pending_frame_for_output_locked(presentation_time_us);
  if (!pending_metadata.has_value()) {
    ++stale_decoded_outputs_;
    return false;
  }
  ++acquired_images_;
  ++rendered_frames_;
  if (!pending_metadata->content_updated) {
    ++repeated_content_outputs_;
    ++repeated_content_inference_suppressions_;
    ++repeated_content_control_suppressions_;
    return true;
  }
  ++fresh_content_outputs_;

  const bool supported_standard = output_color_standard_ == kColorStandardBt709 ||
      output_color_standard_ == kColorStandardBt601Pal ||
      output_color_standard_ == kColorStandardBt601Ntsc;
  if (!supported_standard || output_color_range_ != kColorRangeLimited) {
    ++preprocess_failures_;
    java_decoder_failed_ = true;
    java_decoder_failure_ = "unsupported_colorimetry_standard=" +
        std::to_string(output_color_standard_) + "_range=" +
        std::to_string(output_color_range_);
    __android_log_print(
        ANDROID_LOG_ERROR, "VisionForgeDual", "%s", java_decoder_failure_.c_str());
    return false;
  }

  vfdual::Yuv420ImageView yuv;
  const bool layout_valid = image_width > 0 && image_height > 0 && crop_left >= 0 &&
      crop_top >= 0 && crop_right > crop_left && crop_bottom > crop_top &&
      vfdual::make_yuv420_image_view(
          y_plane, u_plane, v_plane,
          static_cast<std::uint32_t>(image_width), static_cast<std::uint32_t>(image_height),
          {static_cast<std::uint32_t>(crop_left), static_cast<std::uint32_t>(crop_top),
           static_cast<std::uint32_t>(crop_right), static_cast<std::uint32_t>(crop_bottom)}, yuv);
  if (!layout_valid) {
    ++image_layout_failures_;
    ++preprocess_failures_;
    __android_log_print(
        ANDROID_LOG_ERROR, "VisionForgeDual",
        "Java Image.Plane layout rejected image=%dx%d crop=%d,%d,%d,%d "
        "row=%u/%u/%u pixel=%u/%u/%u failures=%llu",
        image_width, image_height, crop_left, crop_top, crop_right, crop_bottom,
        y_plane.row_stride, u_plane.row_stride, v_plane.row_stride,
        y_plane.pixel_stride, u_plane.pixel_stride, v_plane.pixel_stride,
        static_cast<unsigned long long>(image_layout_failures_));
    return false;
  }
  if (image_y_row_stride_ != static_cast<std::int32_t>(y_plane.row_stride) ||
      image_u_row_stride_ != static_cast<std::int32_t>(u_plane.row_stride) ||
      image_v_row_stride_ != static_cast<std::int32_t>(v_plane.row_stride) ||
      image_y_pixel_stride_ != static_cast<std::int32_t>(y_plane.pixel_stride) ||
      image_u_pixel_stride_ != static_cast<std::int32_t>(u_plane.pixel_stride) ||
      image_v_pixel_stride_ != static_cast<std::int32_t>(v_plane.pixel_stride) ||
      image_crop_left_ != crop_left || image_crop_top_ != crop_top ||
      image_crop_right_ != crop_right || image_crop_bottom_ != crop_bottom) {
    image_y_row_stride_ = static_cast<std::int32_t>(y_plane.row_stride);
    image_u_row_stride_ = static_cast<std::int32_t>(u_plane.row_stride);
    image_v_row_stride_ = static_cast<std::int32_t>(v_plane.row_stride);
    image_y_pixel_stride_ = static_cast<std::int32_t>(y_plane.pixel_stride);
    image_u_pixel_stride_ = static_cast<std::int32_t>(u_plane.pixel_stride);
    image_v_pixel_stride_ = static_cast<std::int32_t>(v_plane.pixel_stride);
    image_crop_left_ = crop_left; image_crop_top_ = crop_top;
    image_crop_right_ = crop_right; image_crop_bottom_ = crop_bottom;
    __android_log_print(
        ANDROID_LOG_INFO, "VisionForgeDual",
        "Java Image.Plane layout verified image=%dx%d crop=%d,%d,%d,%d "
        "row=%u/%u/%u pixel=%u/%u/%u",
        image_width, image_height, crop_left, crop_top, crop_right, crop_bottom,
        y_plane.row_stride, u_plane.row_stride, v_plane.row_stride,
        y_plane.pixel_stride, u_plane.pixel_stride, v_plane.pixel_stride);
  }
  const auto now_us = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count());
  const auto presentation_us = static_cast<std::uint64_t>(presentation_time_us);
  const std::uint64_t decode_queue_us = now_us >= presentation_us ? now_us - presentation_us : 0U;
  record_latency(decode_queue_samples_us_, decode_queue_us);
  const auto matrix = output_color_standard_ == kColorStandardBt601Pal ||
          output_color_standard_ == kColorStandardBt601Ntsc
      ? vfdual::YuvColorMatrix::bt601_limited
      : vfdual::YuvColorMatrix::bt709_limited;
  if (!inference_worker_running_.load(std::memory_order_acquire)) {
    ++stale_decoded_outputs_;
    return false;
  }
  lock.unlock();
  const auto preprocess_started = std::chrono::steady_clock::now();
  vfdual::LetterboxTransform transform;
  const bool preprocessed = vfdual::preprocess_yuv420_to_model_rgb(
      yuv, matrix, vfdual::kDefaultMobileModel.input, model_input_, transform);
  const auto preprocess_us = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now() - preprocess_started).count());
  lock.lock();
  if (!preprocessed) {
    ++preprocess_failures_;
    __android_log_print(ANDROID_LOG_ERROR, "VisionForgeDual", "preprocess failed rendered=%llu", static_cast<unsigned long long>(rendered_frames_));
    return false;
  }
  if (!inference_worker_running_.load(std::memory_order_acquire) ||
      !is_current_stream_generation_locked(pending_metadata->stream_generation)) {
    ++stale_decoded_outputs_;
    return true;
  }
  last_preprocess_us_ = preprocess_us;
  record_latency(preprocess_samples_us_, last_preprocess_us_);
  {
    std::scoped_lock inference_lock(inference_mutex_);
    if (!inference_worker_running_.load(std::memory_order_acquire)) {
      ++stale_decoded_outputs_;
      return false;
    }
    PendingInferenceFrame inference_frame{};
    inference_frame.input.swap(model_input_);
    if (pending_inference_frames_.size() >= kInferenceQueueCapacity ||
        free_model_inputs_.empty()) {
      if (pending_inference_frames_.empty()) {
        model_input_.swap(inference_frame.input);
        ++preprocess_failures_;
        return false;
      }
      if (!content_frame_can_supersede(
              pending_inference_frames_.front().content_updated,
              pending_metadata->content_updated)) {
        // Keep the already queued real observation. The repeat remains useful
        // only when inference capacity is available; it cannot erase a control
        // opportunity from the queue.
        model_input_.swap(inference_frame.input);
        ++superseded_preprocessed_frames_;
        return true;
      }
      model_input_.swap(pending_inference_frames_.front().input);
      pending_inference_frames_.pop_front();
      ++superseded_preprocessed_frames_;
    } else {
      model_input_.swap(free_model_inputs_.back());
      free_model_inputs_.pop_back();
    }
    inference_frame.frame_id = pending_metadata->frame_id;
    inference_frame.control_sequence = pending_metadata->control_sequence;
    inference_frame.content_updated = pending_metadata->content_updated;
    inference_frame.stream_generation = pending_metadata->stream_generation;
    inference_frame.observed_at_us = presentation_us;
    inference_frame.preprocess_us = last_preprocess_us_;
    inference_frame.decode_queue_us = decode_queue_us;
    pending_inference_frames_.push_back(std::move(inference_frame));
    inference_queue_high_watermark_.store(
        std::max(
            inference_queue_high_watermark_.load(std::memory_order_relaxed),
            static_cast<std::uint64_t>(pending_inference_frames_.size())),
        std::memory_order_relaxed);
  }
  inference_condition_.notify_one();
  return true;
}

void NativeH264Decoder::update_java_decoder_format(
    std::string codec_name, std::int32_t color_format, std::int32_t color_standard,
    std::int32_t color_range, std::int32_t width, std::int32_t height) {
  std::scoped_lock lock(mutex_);
  java_decoder_name_ = std::move(codec_name);
  output_color_format_ = color_format;
  output_color_standard_ = color_standard;
  output_color_range_ = color_range;
  if (width > 0) decoded_width_ = width;
  if (height > 0) decoded_height_ = height;
}

bool NativeH264Decoder::has_fatal_decoder_failure() const {
  std::scoped_lock lock(mutex_);
  return java_decoder_failed_;
}

void NativeH264Decoder::discard_java_decoded_output(
    std::int64_t presentation_time_us, std::string reason, bool fatal) {
  std::scoped_lock lock(mutex_);
  (void)take_pending_frame_for_output_locked(presentation_time_us);
  ++rejected_output_images_;
  if (fatal) {
    java_decoder_failed_ = true;
    java_decoder_failure_ = reason;
  }
  if (rejected_output_images_ <= 3U ||
      (rejected_output_images_ & (rejected_output_images_ - 1U)) == 0U) {
    __android_log_print(
        fatal ? ANDROID_LOG_ERROR : ANDROID_LOG_WARN, "VisionForgeDual",
        "Java decoded output rejected count=%llu fatal=%d reason=%s",
        static_cast<unsigned long long>(rejected_output_images_), fatal,
        reason.c_str());
  }
}

void NativeH264Decoder::discard_java_compressed_access_unit(
    std::int64_t presentation_time_us, std::string reason, bool fatal) {
  std::scoped_lock lock(mutex_);
  (void)take_pending_frame_for_output_locked(presentation_time_us);
  ++dropped_access_units_;
  input_drop_metrics_.record_async(reason);
  if (fatal) {
    java_decoder_failed_ = true;
    java_decoder_failure_ = reason;
  }
  const auto reason_total = input_drop_metrics_.total();
  if (reason_total <= 3U || (reason_total & (reason_total - 1U)) == 0U) {
    __android_log_print(
        fatal ? ANDROID_LOG_ERROR : ANDROID_LOG_WARN, "VisionForgeDual",
        "Java compressed access unit dropped count=%llu fatal=%d reason=%s",
        static_cast<unsigned long long>(reason_total), fatal, reason.c_str());
  }
}

bool NativeH264Decoder::restart_after_stream_discontinuity() {
  JavaVM* java_vm{};
  jobject decoder_object{};
  jmethodID restart_method{};
  std::int32_t width{};
  std::int32_t height{};
  std::uint64_t generation{};
  {
    std::scoped_lock lock(mutex_);
    // Multiple Host epoch changes may arrive while Java is recreating
    // MediaCodec.  The receiver keeps only the newest candidate epoch; native
    // therefore coalesces every overlapping request into the one in-flight
    // restart instead of treating Java's busy response as fatal.
    if (stream_restart_in_progress_) return true;
    java_vm = java_vm_;
    decoder_object = java_decoder_object_;
    restart_method = java_restart_after_discontinuity_method_;
    width = decoded_width_;
    height = decoded_height_;
    java_decoder_failed_ = false;
    java_decoder_failure_ = "stream_source_changed_restart_in_progress";
    generation = ++stream_restart_generation_;
    stream_restart_started_us_ = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    stream_restart_in_progress_ = true;
    pending_stream_restart_completion_.reset();
    pending_makcu_resume_generation_.reset();
    pending_frames_.clear();
    suspend_makcu_output_for_recovery(generation);
  }
  {
    std::scoped_lock inference_lock(inference_mutex_);
    recycle_pending_inference_frames_locked();
  }
  if (java_vm == nullptr || decoder_object == nullptr || restart_method == nullptr ||
      width <= 0 || height <= 0) {
    std::scoped_lock lock(mutex_);
    ++stream_restart_failures_;
    stream_restart_in_progress_ = false;
    disable_makcu_output();
    java_decoder_failure_ = "stream_source_changed_restart_bridge_unavailable";
    return false;
  }
  JNIEnv* environment = current_thread_environment(java_vm);
  if (environment == nullptr) {
    std::scoped_lock lock(mutex_);
    ++stream_restart_failures_;
    stream_restart_in_progress_ = false;
    disable_makcu_output();
    java_decoder_failure_ = "stream_source_changed_restart_jni_unavailable";
    return false;
  }
  const auto started = std::chrono::steady_clock::now();
  const jboolean restarted = environment->CallBooleanMethod(
      decoder_object, restart_method, static_cast<jint>(width), static_cast<jint>(height),
      static_cast<jlong>(generation));
  bool callback_failed = false;
  if (environment->ExceptionCheck()) {
    environment->ExceptionDescribe();
    environment->ExceptionClear();
    callback_failed = true;
  }
  const auto elapsed_us = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now() - started).count());
  const bool scheduled = restarted == JNI_TRUE && !callback_failed;
  {
    std::scoped_lock lock(mutex_);
    last_stream_restart_request_us_ = elapsed_us;
    if (!scheduled) {
      ++stream_restart_failures_;
      stream_restart_in_progress_ = false;
      java_decoder_failed_ = true;
      java_decoder_failure_ = "stream_source_changed_restart_schedule_failed";
      pending_makcu_resume_generation_.reset();
      disable_makcu_output();
    }
  }
  __android_log_print(
      scheduled ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, "VisionForgeDual",
      "stream decoder restart scheduled=%d generation=%llu request_us=%llu output_enabled=0",
      scheduled ? 1 : 0, static_cast<unsigned long long>(generation),
      static_cast<unsigned long long>(elapsed_us));
  return scheduled;
}

void NativeH264Decoder::complete_stream_restart(
    std::uint64_t generation, bool succeeded, std::uint64_t elapsed_us,
    std::string diagnostic) {
  std::scoped_lock lock(mutex_);
  if (generation != stream_restart_generation_ || !stream_restart_in_progress_) {
    __android_log_print(
        ANDROID_LOG_WARN, "VisionForgeDual",
        "ignored stale stream restart completion generation=%llu active=%llu",
        static_cast<unsigned long long>(generation),
        static_cast<unsigned long long>(stream_restart_generation_));
    return;
  }
  stream_restart_in_progress_ = false;
  last_stream_restart_us_ = elapsed_us;
  pending_stream_restart_completion_ = StreamRestartCompletion{
      generation, succeeded, elapsed_us};
  if (succeeded) {
    ++stream_restarts_;
    java_decoder_failed_ = false;
    java_decoder_failure_.clear();
    pending_makcu_resume_generation_ = generation;
  } else {
    ++stream_restart_failures_;
    java_decoder_failed_ = true;
    java_decoder_failure_ = diagnostic.empty()
        ? "stream_source_changed_restart_failed" : std::move(diagnostic);
    pending_makcu_resume_generation_.reset();
    disable_makcu_output();
  }
  __android_log_print(
      succeeded ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, "VisionForgeDual",
      "stream decoder restart completed=%d generation=%llu elapsed_us=%llu",
      succeeded ? 1 : 0, static_cast<unsigned long long>(generation),
      static_cast<unsigned long long>(elapsed_us));
}

std::optional<NativeH264Decoder::StreamRestartCompletion>
NativeH264Decoder::take_stream_restart_completion() {
  std::scoped_lock lock(mutex_);
  auto completion = pending_stream_restart_completion_;
  pending_stream_restart_completion_.reset();
  return completion;
}

bool NativeH264Decoder::has_stream_restart_timed_out() {
  std::scoped_lock lock(mutex_);
  if (!stream_restart_in_progress_ || stream_restart_started_us_ == 0U) return false;
  const auto now_us = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
  if (now_us < stream_restart_started_us_ ||
      now_us - stream_restart_started_us_ < kStreamRestartTimeoutUs) return false;
  stream_restart_in_progress_ = false;
  pending_stream_restart_completion_.reset();
  pending_makcu_resume_generation_.reset();
  ++stream_restart_generation_;
  ++stream_restart_failures_;
  java_decoder_failed_ = true;
  java_decoder_failure_ = "stream_source_changed_restart_timeout_250ms";
  disable_makcu_output();
  __android_log_print(
      ANDROID_LOG_ERROR, "VisionForgeDual",
      "stream decoder restart timeout elapsed_us=%llu; full recovery required",
      static_cast<unsigned long long>(now_us - stream_restart_started_us_));
  return true;
}

void NativeH264Decoder::mark_stream_discontinuity() {
  disable_makcu_output();
  {
    std::scoped_lock inference_lock(inference_mutex_);
    recycle_pending_inference_frames_locked();
  }
  std::scoped_lock lock(mutex_);
  ++stream_restart_generation_;
  stream_restart_in_progress_ = false;
  pending_stream_restart_completion_.reset();
  pending_makcu_resume_generation_.reset();
  pending_frames_.clear();
  java_decoder_failed_ = true;
  java_decoder_failure_ = "stream_network_source_changed_full_recovery_required";
}

void NativeH264Decoder::stop() {
  disable_makcu_output();
  output_worker_running_ = false;
  inference_worker_running_ = false;
  {
    std::scoped_lock inference_lock(inference_mutex_);
    recycle_pending_inference_frames_locked();
  }
  inference_condition_.notify_all();
  if (output_worker_.joinable()) output_worker_.join();
  if (inference_worker_.joinable()) inference_worker_.join();
  std::scoped_lock callback_lock(java_output_callback_mutex_);
  std::scoped_lock lock(mutex_);
  ++stream_restart_generation_;
  stream_restart_in_progress_ = false;
  pending_stream_restart_completion_.reset();
  pending_makcu_resume_generation_.reset();
  if (codec_ != nullptr) { AMediaCodec_stop(codec_); AMediaCodec_delete(codec_); codec_ = nullptr; }
  if (output_window_ != nullptr && output_window_owned_) {
    ANativeWindow_release(output_window_);
    output_window_ = nullptr;
  }
  output_window_owned_ = false;
  java_image_decoder_mode_ = false;
  pending_frames_.clear();
}

void NativeH264Decoder::recycle_pending_inference_frames_locked() {
  while (!pending_inference_frames_.empty()) {
    free_model_inputs_.push_back(std::move(pending_inference_frames_.front().input));
    pending_inference_frames_.pop_front();
  }
}

bool NativeH264Decoder::is_current_stream_generation_locked(
    std::uint64_t generation) const noexcept {
  return inference_result_can_commit(
      generation, stream_restart_generation_, stream_restart_in_progress_,
      java_decoder_failed_);
}

void NativeH264Decoder::begin_detection_trace(std::size_t maximum_frames) {
  std::scoped_lock lock(mutex_);
  detection_trace_frames_.clear();
  detection_trace_maximum_frames_ = maximum_frames;
  detection_trace_enabled_ = maximum_frames != 0;
}

std::string NativeH264Decoder::detection_trace_csv() const {
  std::scoped_lock lock(mutex_);
  std::ostringstream value;
  value << "frame_id,class_id,confidence,x1,y1,x2,y2\n";
  for (const auto& frame : detection_trace_frames_) {
    if (frame.detections.empty()) {
      value << frame.frame_id << ",-1,0,0,0,0,0\n";
      continue;
    }
    for (const auto& detection : frame.detections) {
      value << frame.frame_id << ',' << detection.class_id << ',' << detection.confidence << ','
            << detection.x1 << ',' << detection.y1 << ',' << detection.x2 << ',' << detection.y2 << '\n';
    }
  }
  return value.str();
}

std::string NativeH264Decoder::pipeline_metrics_csv() const {
  std::scoped_lock lock(mutex_);
  std::ostringstream value;
  value << "frame_id,decode_queue_us,preprocess_us,qnn_us,detection_count,qnn_status\n";
  for (std::size_t index = 0; index < pipeline_metrics_.size(); ++index) {
    const auto& sample = pipeline_metrics_.oldest_at(index);
    value << sample.frame_id << ',' << sample.decode_queue_us << ',' << sample.preprocess_us << ',' << sample.qnn_us << ','
          << sample.detections << ',' << sample.qnn_status << '\n';
  }
  return value.str();
}

std::string NativeH264Decoder::java_input_health_report_locked() const {
  JNIEnv* environment = current_thread_environment(java_vm_);
  if (environment == nullptr || java_decoder_object_ == nullptr ||
      java_input_health_report_method_ == nullptr) {
    return "unavailable";
  }
  auto* report = static_cast<jstring>(environment->CallObjectMethod(
      java_decoder_object_, java_input_health_report_method_));
  if (environment->ExceptionCheck()) {
    environment->ExceptionClear();
    return "jni_exception";
  }
  if (report == nullptr) return "unavailable";
  const char* utf = environment->GetStringUTFChars(report, nullptr);
  std::string value = utf == nullptr ? "unavailable" : utf;
  if (utf != nullptr) environment->ReleaseStringUTFChars(report, utf);
  environment->DeleteLocalRef(report);
  return value;
}

std::string NativeH264Decoder::report() const {
  std::scoped_lock lock(mutex_);
  const auto now_us = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
  const auto qnn_success_age_ms = last_qnn_success_monotonic_us_ == 0 ||
          now_us < last_qnn_success_monotonic_us_
      ? -1LL
      : static_cast<long long>((now_us - last_qnn_success_monotonic_us_) / 1'000U);
  const auto qnn_failure_age_ms = last_qnn_failure_monotonic_us_ == 0 ||
          now_us < last_qnn_failure_monotonic_us_
      ? -1LL
      : static_cast<long long>((now_us - last_qnn_failure_monotonic_us_) / 1'000U);
  std::ostringstream value;
  value << "configured=" << ((codec_ != nullptr || java_image_decoder_mode_) &&
        !java_decoder_failed_ && !stream_restart_in_progress_)
        << " queued_access_units=" << queued_access_units_
        << " sync_access_units=" << sync_access_units_
        << " pending_access_units=" << pending_frames_.size()
        << " last_input_nal_type_mask=" << last_input_nal_type_mask_
        << " decoded_size=" << decoded_width_ << 'x' << decoded_height_
        << " output_path=" << (java_image_decoder_mode_ ? "java_getOutputImage" : "surface")
        << " decoder_name=" << java_decoder_name_
        << " decoder_failed=" << java_decoder_failed_
        << " decoder_failure=" << (java_decoder_failure_.empty() ? "none" : java_decoder_failure_)
        << " stream_restarts=" << stream_restarts_
        << " stream_restart_failures=" << stream_restart_failures_
        << " stream_restart_in_progress=" << stream_restart_in_progress_
        << " last_stream_restart_us=" << last_stream_restart_us_
        << " last_stream_restart_request_us=" << last_stream_restart_request_us_
        << " requested_color_format=" << kColorFormatYuv420Flexible
        << " output_color_format=" << output_color_format_
        << " color_standard=" << output_color_standard_ << " color_range=" << output_color_range_
        << " image_row_stride=" << image_y_row_stride_ << '/' << image_u_row_stride_ << '/'
        << image_v_row_stride_ << " image_pixel_stride=" << image_y_pixel_stride_ << '/'
        << image_u_pixel_stride_ << '/' << image_v_pixel_stride_
        << " image_crop=" << image_crop_left_ << '/' << image_crop_top_ << '/'
        << image_crop_right_ << '/' << image_crop_bottom_
        << " image_layout_failures=" << image_layout_failures_
        << " rejected_output_images=" << rejected_output_images_
         << " acquired_images=" << acquired_images_
         << " rendered_frames=" << rendered_frames_
         << " fresh_content_outputs=" << fresh_content_outputs_
         << " repeated_content_outputs=" << repeated_content_outputs_
         << " stale_decoded_outputs=" << stale_decoded_outputs_
        << " superseded_preprocessed_frames=" << superseded_preprocessed_frames_
        << " inference_queue_capacity=" << kInferenceQueueCapacity
        << " inference_queue_high_watermark="
        << inference_queue_high_watermark_.load(std::memory_order_relaxed)
        << " stale_pre_inference_frames="
        << stale_pre_inference_frames_.load(std::memory_order_relaxed)
        << " maximum_pre_inference_frame_age_us="
        << maximum_pre_inference_frame_age_us_.load(std::memory_order_relaxed)
        << " stale_generation_inference_suppressions="
        << stale_generation_inference_suppressions_
        << " stale_generation_result_suppressions="
        << stale_generation_result_suppressions_
         << " stale_generation_control_suppressions="
         << stale_generation_control_suppressions_
         << " repeated_content_inferences=" << repeated_content_inferences_
         << " repeated_content_inference_suppressions="
         << repeated_content_inference_suppressions_
         << " repeated_content_control_suppressions="
         << repeated_content_control_suppressions_
        << " dropped_access_units=" << dropped_access_units_
        << " input_drop_no_buffer=" << input_drop_metrics_.no_input_buffer
        << " input_drop_stale_before_codec="
        << input_drop_metrics_.stale_before_codec
        << " input_drop_queue_capacity=" << input_drop_metrics_.queue_capacity
        << " input_drop_buffer_capacity=" << input_drop_metrics_.buffer_capacity
        << " input_drop_codec_exception=" << input_drop_metrics_.codec_exception
        << " input_drop_state_exception=" << input_drop_metrics_.state_exception
        << " input_drop_restart=" << input_drop_metrics_.restart
        << " input_drop_reference_recovery=" << input_drop_metrics_.reference_recovery
        << " input_drop_not_running=" << input_drop_metrics_.not_running
        << " input_drop_invalid=" << input_drop_metrics_.invalid
        << " input_drop_bridge_failure=" << input_drop_metrics_.bridge_failure
        << " input_drop_fatal_flush=" << input_drop_metrics_.fatal_flush
        << " input_drop_recovery_flush=" << input_drop_metrics_.recovery_flush
        << " input_drop_other=" << input_drop_metrics_.other
         << " inference_backend=" << realtime_inference_backend_token()
         << " qnn_executions=" << qnn_executions_ << " qnn_failures=" << qnn_failures_
        << " consecutive_qnn_failures=" << consecutive_qnn_failures_
        << " last_qnn_success_age_ms=" << qnn_success_age_ms
        << " last_qnn_failure_age_ms=" << qnn_failure_age_ms
        << " preprocess_failures=" << preprocess_failures_ << " last_detection_count=" << last_detection_count_
        << " last_qnn_status=" << last_qnn_status_ << " preprocess{" << percentile_summary(preprocess_samples_us_)
        << " last_us=" << last_preprocess_us_ << "} qnn{" << percentile_summary(qnn_samples_us_)
        << " last_us=" << last_qnn_us_ << "} inference_total{"
        << percentile_summary(inference_total_samples_us_)
        << " last_us=" << last_inference_total_us_ << "} decode_queue{"
        << percentile_summary(decode_queue_samples_us_) << "}"
        << " input_health={" << java_input_health_report_locked() << "}";
  value << " last_detections=[";
  constexpr std::size_t kReportDetectionLimit = 5;
  for (std::size_t index = 0; index < std::min(last_detections_.size(), kReportDetectionLimit); ++index) {
    const auto& detection = last_detections_[index];
    if (index != 0) value << ',';
    value << "{class=" << detection.class_id << ",confidence=" << detection.confidence
          << ",xyxy=" << detection.x1 << '/' << detection.y1 << '/' << detection.x2 << '/' << detection.y2 << '}';
  }
  if (last_detections_.size() > kReportDetectionLimit) value << ",...";
  value << ']';
  value << " makcu_bridge{" << makcu_move_bridge_report() << '}';
  return value.str();
}

NativeH264Decoder::~NativeH264Decoder() { stop(); }
NativeH264Decoder& decoder() { static NativeH264Decoder instance; return instance; }
}  // namespace vfdual_android

extern "C" JNIEXPORT jboolean JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_configureNativeH264Decoder(
    JNIEnv* environment, jclass, jobject surface, jint width, jint height) {
  return vfdual_android::decoder().configure(environment, surface, width, height) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_stopNativeH264Decoder(JNIEnv*, jclass) {
  vfdual_android::decoder().stop();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_configureNativeH264InferenceDecoder(JNIEnv*, jclass, jint width, jint height) {
  return vfdual_android::decoder().configure_for_inference(width, height) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_bindNativeH264AccessUnitBridge(
    JNIEnv* environment, jclass, jobject decoder) {
  vfdual_android::decoder().bind_java_decoder(environment, decoder);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_offerNativeDecodedYuv420(
    JNIEnv* environment, jclass,
    jobject y_buffer, jint y_offset, jint y_remaining, jint y_row_stride, jint y_pixel_stride,
    jobject u_buffer, jint u_offset, jint u_remaining, jint u_row_stride, jint u_pixel_stride,
    jobject v_buffer, jint v_offset, jint v_remaining, jint v_row_stride, jint v_pixel_stride,
    jint image_width, jint image_height, jint crop_left, jint crop_top,
    jint crop_right, jint crop_bottom, jlong presentation_time_us) {
  const auto plane = [environment](
      jobject buffer, jint offset, jint remaining, jint row_stride,
      jint pixel_stride, vfdual::Yuv420PlaneView& output) {
    const jlong capacity = buffer == nullptr ? -1 : environment->GetDirectBufferCapacity(buffer);
    auto* address = buffer == nullptr
        ? nullptr
        : static_cast<std::uint8_t*>(environment->GetDirectBufferAddress(buffer));
    if (address == nullptr || capacity < 0 || offset < 0 || remaining <= 0 ||
        row_stride <= 0 || pixel_stride <= 0 ||
        static_cast<jlong>(offset) + remaining > capacity) {
      return false;
    }
    output = {
        address + offset, static_cast<std::size_t>(remaining),
        static_cast<std::uint32_t>(row_stride), static_cast<std::uint32_t>(pixel_stride)};
    return true;
  };
  vfdual::Yuv420PlaneView y_plane;
  vfdual::Yuv420PlaneView u_plane;
  vfdual::Yuv420PlaneView v_plane;
  const bool valid = plane(y_buffer, y_offset, y_remaining, y_row_stride, y_pixel_stride, y_plane) &&
      plane(u_buffer, u_offset, u_remaining, u_row_stride, u_pixel_stride, u_plane) &&
      plane(v_buffer, v_offset, v_remaining, v_row_stride, v_pixel_stride, v_plane);
  return valid && vfdual_android::decoder().process_java_yuv420(
      y_plane, u_plane, v_plane, image_width, image_height,
      crop_left, crop_top, crop_right, crop_bottom, presentation_time_us)
      ? JNI_TRUE
      : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_discardNativeDecodedOutput(
    JNIEnv* environment, jclass, jlong presentation_time_us, jstring reason, jboolean fatal) {
  const char* utf = reason == nullptr ? nullptr : environment->GetStringUTFChars(reason, nullptr);
  std::string value = utf == nullptr ? "unknown" : utf;
  if (utf != nullptr) environment->ReleaseStringUTFChars(reason, utf);
  vfdual_android::decoder().discard_java_decoded_output(
      presentation_time_us, std::move(value), fatal == JNI_TRUE);
}

extern "C" JNIEXPORT void JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_discardNativeCompressedAccessUnit(
    JNIEnv* environment, jclass, jlong presentation_time_us, jstring reason, jboolean fatal) {
  const char* utf = reason == nullptr ? nullptr : environment->GetStringUTFChars(reason, nullptr);
  std::string value = utf == nullptr ? "unknown" : utf;
  if (utf != nullptr) environment->ReleaseStringUTFChars(reason, utf);
  vfdual_android::decoder().discard_java_compressed_access_unit(
      presentation_time_us, std::move(value), fatal == JNI_TRUE);
}

extern "C" JNIEXPORT void JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_updateNativeH264JavaDecoderFormat(
    JNIEnv* environment, jclass, jstring codec_name, jint color_format,
    jint color_standard, jint color_range, jint width, jint height) {
  const char* utf = codec_name == nullptr ? nullptr : environment->GetStringUTFChars(codec_name, nullptr);
  std::string name = utf == nullptr ? "unknown" : utf;
  if (utf != nullptr) environment->ReleaseStringUTFChars(codec_name, utf);
  vfdual_android::decoder().update_java_decoder_format(
      std::move(name), color_format, color_standard, color_range, width, height);
}

extern "C" JNIEXPORT void JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_completeNativeH264StreamRestart(
    JNIEnv* environment, jclass, jlong generation, jboolean succeeded,
    jlong elapsed_us, jstring diagnostic) {
  std::string detail;
  if (environment != nullptr && diagnostic != nullptr) {
    const char* utf = environment->GetStringUTFChars(diagnostic, nullptr);
    if (utf != nullptr) {
      detail = utf;
      environment->ReleaseStringUTFChars(diagnostic, utf);
    }
  }
  vfdual_android::decoder().complete_stream_restart(
      static_cast<std::uint64_t>(generation), succeeded == JNI_TRUE,
      elapsed_us < 0 ? 0U : static_cast<std::uint64_t>(elapsed_us), std::move(detail));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_getNativeH264DecoderReport(JNIEnv* environment, jclass) {
  const std::string value = vfdual_android::decoder().report();
  return environment->NewStringUTF(value.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_getNativePipelineMetricsCsv(JNIEnv* environment, jclass) {
  const std::string value = vfdual_android::decoder().pipeline_metrics_csv();
  return environment->NewStringUTF(value.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_beginNativeH264DetectionTrace(JNIEnv*, jclass, jint maximum_frames) {
  vfdual_android::decoder().begin_detection_trace(maximum_frames > 0 ? static_cast<std::size_t>(maximum_frames) : 0U);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_getNativeH264DetectionTraceCsv(JNIEnv* environment, jclass) {
  const std::string value = vfdual_android::decoder().detection_trace_csv();
  return environment->NewStringUTF(value.c_str());
}
