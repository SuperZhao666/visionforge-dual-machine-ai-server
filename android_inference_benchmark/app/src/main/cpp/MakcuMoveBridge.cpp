#include "MakcuMoveBridge.hpp"

#include "MobileControlCore.hpp"
#include "MakcuOutputGate.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <mutex>
#include <sstream>

namespace vfdual_android {
namespace {
constexpr float kMinimumRelativeGain = 0.01F;
constexpr float kMaximumRelativeGain = 2.00F;
constexpr float kMaximumDeadzonePixels = 64.0F;
constexpr std::int32_t kMinimumAxisDelta = 1;
constexpr std::int32_t kMaximumAxisDelta = 127;
constexpr std::uint32_t kMinimumSwitchConfirmationMs = 10U;
constexpr std::uint32_t kMaximumSwitchConfirmationMs = 100U;
constexpr std::uint64_t kMaximumMoveCompletionAgeUs = 100'000U;

std::mutex g_bridge_mutex;
std::mutex g_control_mutex;
std::mutex g_publish_mutex;
JavaVM* g_vm{};
jclass g_controller_class{};
jmethodID g_offer_move{};
jmethodID g_suspend_delivery{};
jmethodID g_resume_delivery{};
jmethodID g_fail_closed_delivery{};
MobileControlCore g_control_core{};
std::atomic_uint64_t g_processed_frames{};
std::atomic_uint64_t g_candidates{};
MakcuStreamGenerationGate g_stream_generation_gate{};
std::atomic_uint64_t g_stale_stream_generation_suppressed{};
std::atomic_uint64_t g_delivery_fail_close_requests{};
std::atomic_uint64_t g_stream_lifecycle_close_requests{};
std::atomic_uint64_t g_output_disabled_suppressed{};
std::atomic_uint64_t g_java_offer_acceptances{};
std::atomic_uint64_t g_java_offer_rejections{};
std::atomic_uint64_t g_deadzone_suppressed{};
std::atomic_uint64_t g_held_targets{};
std::atomic_uint64_t g_target_switches{};
std::atomic_uint64_t g_no_targets{};
std::atomic_uint64_t g_java_dispatch_failures{};
std::atomic_uint64_t g_move_completion_pending_suppressed{};
std::atomic_uint64_t g_device_ack_completions{};
std::atomic_uint64_t g_device_ack_failures{};
std::atomic_uint64_t g_move_completion_timeouts{};
std::atomic_uint64_t g_stale_device_feedback{};
std::atomic_uint64_t g_last_device_ack_us{};
std::atomic_uint64_t g_last_device_ack_at_us{};
std::atomic_uint64_t g_last_device_ack_interval_us{};
std::atomic_uint64_t g_bluetooth_hid_api_acceptances{};
std::atomic_uint64_t g_stale_bluetooth_hid_api_acceptances{};
std::atomic_uint64_t g_last_bluetooth_hid_api_acceptance_us{};
std::atomic_uint64_t g_post_completion_visibility_suppressed{};
std::atomic<std::int32_t> g_last_offered_delta_x{};
std::atomic<std::int32_t> g_last_offered_delta_y{};
std::atomic<std::int32_t> g_last_nonzero_offered_direction_x{};
std::atomic<std::int32_t> g_last_nonzero_offered_direction_y{};
std::atomic_uint64_t g_offered_absolute_x_counts{};
std::atomic_uint64_t g_offered_absolute_y_counts{};
std::atomic_uint64_t g_maximum_offered_absolute_axis_delta{};
std::atomic_uint64_t g_offered_direction_flips_x{};
std::atomic_uint64_t g_offered_direction_flips_y{};
std::atomic_uint64_t g_last_offer_at_us{};
std::atomic_uint64_t g_last_offer_interval_us{};
std::atomic<float> g_relative_gain{0.36F};
std::atomic<float> g_deadzone_pixels{0.5F};
std::atomic<std::int32_t> g_maximum_axis_delta{kMaximumAxisDelta};
std::atomic_bool g_java_bridge_ready{};
MakcuOutputGate g_output_gate{};
MakcuMoveCommitGate g_move_commit_gate{};
MakcuMoveVisibilityGate g_move_visibility_gate{};

enum class JavaDeliveryCall {
  suspend,
  resume,
  fail_closed,
};

std::uint64_t monotonic_microseconds() noexcept {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::uint64_t absolute_counts(std::int32_t delta) noexcept {
  const std::int64_t widened = delta;
  return static_cast<std::uint64_t>(widened < 0 ? -widened : widened);
}

void update_maximum(
    std::atomic_uint64_t& destination, std::uint64_t candidate) noexcept {
  std::uint64_t current = destination.load(std::memory_order_relaxed);
  while (current < candidate &&
         !destination.compare_exchange_weak(
             current, candidate, std::memory_order_relaxed)) {
  }
}

void observe_interval(
    std::uint64_t observed_at_us, std::atomic_uint64_t& previous_at_us,
    std::atomic_uint64_t& latest_interval_us) noexcept {
  const std::uint64_t previous =
      previous_at_us.exchange(observed_at_us, std::memory_order_relaxed);
  if (previous != 0U && observed_at_us >= previous) {
    latest_interval_us.store(
        observed_at_us - previous, std::memory_order_relaxed);
  }
}

void observe_axis_direction(
    std::int32_t delta, std::atomic<std::int32_t>& previous_direction,
    std::atomic_uint64_t& direction_flips) noexcept {
  const std::int32_t direction = delta > 0 ? 1 : delta < 0 ? -1 : 0;
  if (direction == 0) return;
  const std::int32_t previous =
      previous_direction.exchange(direction, std::memory_order_relaxed);
  if (previous != 0 && previous != direction) {
    direction_flips.fetch_add(1U, std::memory_order_relaxed);
  }
}

void observe_accepted_move(std::int32_t delta_x, std::int32_t delta_y) noexcept {
  const std::uint64_t absolute_x = absolute_counts(delta_x);
  const std::uint64_t absolute_y = absolute_counts(delta_y);
  g_last_offered_delta_x.store(delta_x, std::memory_order_relaxed);
  g_last_offered_delta_y.store(delta_y, std::memory_order_relaxed);
  g_offered_absolute_x_counts.fetch_add(absolute_x, std::memory_order_relaxed);
  g_offered_absolute_y_counts.fetch_add(absolute_y, std::memory_order_relaxed);
  update_maximum(
      g_maximum_offered_absolute_axis_delta,
      std::max(absolute_x, absolute_y));
  observe_axis_direction(
      delta_x, g_last_nonzero_offered_direction_x,
      g_offered_direction_flips_x);
  observe_axis_direction(
      delta_y, g_last_nonzero_offered_direction_y,
      g_offered_direction_flips_y);
  observe_interval(
      monotonic_microseconds(), g_last_offer_at_us,
      g_last_offer_interval_us);
}

void observe_matching_device_ack() noexcept {
  observe_interval(
      monotonic_microseconds(), g_last_device_ack_at_us,
      g_last_device_ack_interval_us);
}

void reset_move_telemetry_continuity() noexcept {
  g_last_offered_delta_x.store(0, std::memory_order_relaxed);
  g_last_offered_delta_y.store(0, std::memory_order_relaxed);
  g_last_nonzero_offered_direction_x.store(0, std::memory_order_relaxed);
  g_last_nonzero_offered_direction_y.store(0, std::memory_order_relaxed);
  g_last_offer_at_us.store(0U, std::memory_order_relaxed);
  g_last_offer_interval_us.store(0U, std::memory_order_relaxed);
  g_last_device_ack_at_us.store(0U, std::memory_order_relaxed);
  g_last_device_ack_interval_us.store(0U, std::memory_order_relaxed);
}

void clear_jni_exception(JNIEnv* environment) noexcept {
  if (environment != nullptr && environment->ExceptionCheck()) {
    environment->ExceptionDescribe();
    environment->ExceptionClear();
  }
}

void clear_binding_locked(JNIEnv* environment) noexcept {
  if (g_controller_class != nullptr && environment != nullptr) {
    environment->DeleteGlobalRef(g_controller_class);
  }
  g_vm = nullptr;
  g_controller_class = nullptr;
  g_offer_move = nullptr;
  g_suspend_delivery = nullptr;
  g_resume_delivery = nullptr;
  g_fail_closed_delivery = nullptr;
  g_java_bridge_ready.store(false, std::memory_order_release);
}

jmethodID delivery_method_locked(JavaDeliveryCall call) noexcept {
  switch (call) {
    case JavaDeliveryCall::suspend: return g_suspend_delivery;
    case JavaDeliveryCall::resume: return g_resume_delivery;
    case JavaDeliveryCall::fail_closed: return g_fail_closed_delivery;
  }
  return nullptr;
}

bool invoke_java_delivery_gate(JavaDeliveryCall call, std::uint64_t generation = 0U) noexcept {
  JavaVM* vm{};
  {
    std::scoped_lock lock(g_bridge_mutex);
    if (!g_java_bridge_ready.load(std::memory_order_acquire) || g_vm == nullptr) return false;
    vm = g_vm;
  }

  JNIEnv* environment{};
  bool attached = false;
  const jint environment_status = vm->GetEnv(
      reinterpret_cast<void**>(&environment), JNI_VERSION_1_6);
  if (environment_status == JNI_EDETACHED) {
    if (vm->AttachCurrentThread(&environment, nullptr) != JNI_OK) return false;
    attached = true;
  } else if (environment_status != JNI_OK || environment == nullptr) {
    return false;
  }

  jclass controller_class{};
  jmethodID method{};
  {
    std::scoped_lock lock(g_bridge_mutex);
    if (g_java_bridge_ready.load(std::memory_order_acquire) && vm == g_vm &&
        g_controller_class != nullptr) {
      method = delivery_method_locked(call);
      controller_class = static_cast<jclass>(environment->NewGlobalRef(g_controller_class));
    }
  }
  if (environment->ExceptionCheck() || controller_class == nullptr || method == nullptr) {
    clear_jni_exception(environment);
    if (controller_class != nullptr) environment->DeleteGlobalRef(controller_class);
    if (attached) vm->DetachCurrentThread();
    return false;
  }

  const jboolean accepted = call == JavaDeliveryCall::fail_closed
      ? environment->CallStaticBooleanMethod(controller_class, method)
      : environment->CallStaticBooleanMethod(
          controller_class, method, static_cast<jlong>(generation));
  const bool call_succeeded = !environment->ExceptionCheck() && accepted == JNI_TRUE;
  clear_jni_exception(environment);
  environment->DeleteGlobalRef(controller_class);
  if (attached) vm->DetachCurrentThread();
  return call_succeeded;
}

void fail_closed_native_state(MakcuStreamCloseScope scope) noexcept {
  g_stream_generation_gate.fail_closed(scope);
  if (scope == MakcuStreamCloseScope::delivery_failure) {
    ++g_delivery_fail_close_requests;
  } else {
    ++g_stream_lifecycle_close_requests;
  }
  g_output_gate.fail_closed();
  g_move_commit_gate.fail_closed();
  g_move_visibility_gate.fail_closed();
  {
    std::scoped_lock lock(g_control_mutex);
    g_control_core.reset();
  }
  reset_move_telemetry_continuity();
}

void fail_closed_bridge(
    MakcuStreamCloseScope scope =
        MakcuStreamCloseScope::delivery_failure) noexcept {
  fail_closed_native_state(scope);
  static_cast<void>(invoke_java_delivery_gate(JavaDeliveryCall::fail_closed));
}

bool complete_matching_move(
    std::uint64_t ticket, std::atomic_uint64_t& stale_counter,
    std::uint64_t minimum_visibility_us) noexcept {
  const std::uint64_t acknowledged_at_us = monotonic_microseconds();
  const MakcuMoveCompletion completion = g_move_commit_gate.complete_with(
      ticket, [&](std::uint64_t source_sequence) noexcept {
        g_move_visibility_gate.arm(
            source_sequence, acknowledged_at_us, minimum_visibility_us);
      });
  if (!completion.matched) {
    ++stale_counter;
    return false;
  }
  return true;
}
}  // namespace

bool bind_makcu_move_bridge(JNIEnv* environment, jclass controller_class) {
  fail_closed_bridge();
  g_java_bridge_ready.store(false, std::memory_order_release);
  if (environment == nullptr || controller_class == nullptr || environment->ExceptionCheck()) {
    clear_jni_exception(environment);
    return false;
  }

  JavaVM* candidate_vm{};
  if (environment->GetJavaVM(&candidate_vm) != JNI_OK || candidate_vm == nullptr) {
    std::scoped_lock lock(g_bridge_mutex);
    clear_binding_locked(environment);
    return false;
  }
  jclass candidate_class = static_cast<jclass>(environment->NewGlobalRef(controller_class));
  if (candidate_class == nullptr || environment->ExceptionCheck()) {
    clear_jni_exception(environment);
    if (candidate_class != nullptr) environment->DeleteGlobalRef(candidate_class);
    std::scoped_lock lock(g_bridge_mutex);
    clear_binding_locked(environment);
    return false;
  }

  const jmethodID candidate_offer =
      environment->GetStaticMethodID(candidate_class, "offerNativeMove", "(IIJ)Z");
  const jmethodID candidate_suspend = environment->ExceptionCheck() ? nullptr
      : environment->GetStaticMethodID(
          candidate_class, "suspendNativeDeliveryForRecovery", "(J)Z");
  const jmethodID candidate_resume = environment->ExceptionCheck() ? nullptr
      : environment->GetStaticMethodID(
          candidate_class, "resumeNativeDeliveryAfterRecovery", "(J)Z");
  const jmethodID candidate_fail_closed = environment->ExceptionCheck() ? nullptr
      : environment->GetStaticMethodID(candidate_class, "failClosedNativeDelivery", "()Z");
  if (environment->ExceptionCheck() || candidate_offer == nullptr || candidate_suspend == nullptr ||
      candidate_resume == nullptr || candidate_fail_closed == nullptr) {
    clear_jni_exception(environment);
    environment->DeleteGlobalRef(candidate_class);
    std::scoped_lock lock(g_bridge_mutex);
    clear_binding_locked(environment);
    return false;
  }

  {
    std::scoped_lock lock(g_bridge_mutex);
    clear_binding_locked(environment);
    g_vm = candidate_vm;
    g_controller_class = candidate_class;
    g_offer_move = candidate_offer;
    g_suspend_delivery = candidate_suspend;
    g_resume_delivery = candidate_resume;
    g_fail_closed_delivery = candidate_fail_closed;
    g_java_bridge_ready.store(true, std::memory_order_release);
  }
  return true;
}

bool configure_makcu_control_profile(const MakcuControlProfile& profile) {
  // A profile generation must not cross an observation/offer transaction.
  // Java closes and drains physical delivery before calling the disabled and
  // enabled phases, while this lock prevents a rejected old offer from
  // fail-closing or resetting the newly configured native generation.
  std::scoped_lock publish_lock(g_publish_mutex);
  const vfdual::MobileModelContract* model =
      vfdual::find_mobile_model(profile.model_token);
  const bool target_policy_valid = model != nullptr &&
      std::isfinite(profile.target_y_ratio) &&
      vfdual::matches_mobile_aim_target_contract(
          *model, profile.body_class_id, profile.head_class_id,
          profile.selected_class_id, profile.selected_class_uses_head_box,
          profile.selected_class_uses_geometric_head,
          profile.target_y_ratio);
  const bool personal_scalars_valid =
      std::isfinite(profile.personal_speed_scale) &&
      std::isfinite(profile.personal_stability_scale) &&
      std::isfinite(profile.personal_variation_scale) &&
      std::isfinite(profile.personal_median_duration_ms) &&
      std::isfinite(profile.personal_peak_time_fraction) &&
      std::isfinite(profile.personal_bell_correlation) &&
      std::isfinite(profile.personal_jitter_amplitude_pixels) &&
      std::isfinite(profile.personal_jitter_maximum_pixels) &&
      std::isfinite(profile.personal_minimum_error_pixels);
  const bool personal_envelope_valid =
      profile.personal_speed_envelope_count <=
          profile.personal_speed_envelope.size() &&
      std::all_of(
          profile.personal_speed_envelope.begin(),
          profile.personal_speed_envelope.begin() +
              static_cast<std::ptrdiff_t>(
                  profile.personal_speed_envelope_count),
          [](float value) {
            return std::isfinite(value) && value >= 0.0F && value <= 2.0F;
          });
  if (!std::isfinite(profile.relative_gain) || !std::isfinite(profile.deadzone_pixels) ||
      profile.relative_gain < kMinimumRelativeGain || profile.relative_gain > kMaximumRelativeGain ||
      profile.deadzone_pixels < 0.0F || profile.deadzone_pixels > kMaximumDeadzonePixels ||
      profile.maximum_axis_delta < kMinimumAxisDelta ||
      profile.maximum_axis_delta > kMaximumAxisDelta ||
      profile.switch_confirmation_ms < kMinimumSwitchConfirmationMs ||
      profile.switch_confirmation_ms > kMaximumSwitchConfirmationMs) {
    fail_closed_bridge();
    return false;
  }
  if (!target_policy_valid || !personal_scalars_valid || !personal_envelope_valid ||
      (profile.personal_trajectory_enabled &&
       profile.personal_speed_envelope_count !=
           profile.personal_speed_envelope.size())) {
    fail_closed_bridge();
    return false;
  }
  if (profile.output_enabled && !g_java_bridge_ready.load(std::memory_order_acquire)) {
    fail_closed_bridge();
    return false;
  }
  if (profile.output_enabled && g_output_gate.recovery_suspended()) return false;
  if (!profile.output_enabled) {
    static_cast<void>(g_output_gate.set_user_requested(false));
  }
  MobileControlConfig control_config{};
  control_config.body_class_id = profile.body_class_id;
  control_config.head_class_id = profile.head_class_id;
  control_config.selected_class_id = profile.selected_class_id;
  control_config.model_width = static_cast<float>(model->input.width);
  control_config.model_height = static_cast<float>(model->input.height);
  control_config.model_center_x = control_config.model_width * 0.5F;
  control_config.model_center_y = control_config.model_height * 0.5F;
  control_config.tracker.high_confidence_threshold =
      model->tracking_confidence.high_confidence_threshold;
  control_config.tracker.low_confidence_threshold =
      model->tracking_confidence.low_confidence_threshold;
  control_config.tracker.new_track_confidence_threshold =
      model->tracking_confidence.new_track_confidence_threshold;
  control_config.selected_class_uses_head_box =
      profile.selected_class_uses_head_box;
  control_config.selected_class_uses_geometric_head =
      profile.selected_class_uses_geometric_head;
  control_config.head_body_pairing_enabled =
      profile.selected_class_uses_head_box;
  control_config.body_fallback_y_ratio = profile.target_y_ratio;
  control_config.head_confidence_threshold = 0.0F;
  control_config.body_confidence_threshold = 0.0F;
  control_config.paired_body_min_confidence = 0.0F;
  control_config.head_only_min_confidence = 0.0F;
  control_config.body_fallback_min_confidence = 0.0F;
  control_config.head_only_max_center_distance_pixels =
      control_config.model_width;
  control_config.body_fallback_max_center_distance_pixels =
      control_config.model_width;
  control_config.reject_border_touching = false;
  if (!profile.selected_class_uses_head_box) {
    control_config.body_min_width = 2.0F;
    control_config.body_min_height = 2.0F;
    control_config.body_max_width = control_config.model_width;
    control_config.body_max_height = control_config.model_height;
    control_config.body_min_aspect_ratio = 0.02F;
    control_config.body_max_aspect_ratio = 50.0F;
  }
  control_config.motion.response_gain = profile.relative_gain;
  control_config.motion.deadzone_pixels = profile.deadzone_pixels;
  control_config.motion.maximum_axis_delta = profile.maximum_axis_delta;
  control_config.switch_confirmation_duration_us =
      static_cast<std::uint64_t>(profile.switch_confirmation_ms) * 1'000U;
  // User/profile timing is authoritative. Model tuning may derive dependent
  // time contracts (CS2 lost-target hold) but must not replace this value.
  apply_mobile_model_control_tuning(*model, control_config);
  control_config.motion.uncalibrated_maximum_axis_delta = std::min(
      control_config.motion.uncalibrated_maximum_axis_delta,
      profile.maximum_axis_delta);
  control_config.motion.maximum_step_counts_per_tick = std::min(
      control_config.motion.maximum_step_counts_per_tick,
      static_cast<float>(profile.maximum_axis_delta));
  control_config.motion.maximum_jerk_counts_per_tick2 = std::min(
      control_config.motion.maximum_jerk_counts_per_tick2,
      control_config.motion.maximum_step_counts_per_tick);
  control_config.motion.settle_maximum_axis_delta =
      std::min(
          control_config.motion.settle_maximum_axis_delta,
          profile.maximum_axis_delta);
  control_config.motion.personal_trajectory_enabled =
      profile.personal_trajectory_enabled;
  control_config.motion.personal_profile_seed =
      profile.personal_profile_seed;
  control_config.motion.personal_speed_scale =
      profile.personal_speed_scale;
  control_config.motion.personal_stability_scale =
      profile.personal_stability_scale;
  control_config.motion.personal_variation_scale =
      profile.personal_variation_scale;
  control_config.motion.personal_median_duration_ms =
      profile.personal_median_duration_ms;
  control_config.motion.personal_peak_time_fraction =
      profile.personal_peak_time_fraction;
  control_config.motion.personal_bell_correlation =
      profile.personal_bell_correlation;
  control_config.motion.personal_jitter_amplitude_pixels =
      profile.personal_jitter_amplitude_pixels;
  control_config.motion.personal_jitter_maximum_pixels =
      profile.personal_jitter_maximum_pixels;
  control_config.motion.personal_maximum_extra_counts =
      profile.personal_maximum_extra_counts;
  control_config.motion.personal_minimum_error_pixels =
      profile.personal_minimum_error_pixels;
  control_config.motion.personal_speed_envelope =
      profile.personal_speed_envelope;
  control_config.motion.personal_speed_envelope_count =
      profile.personal_speed_envelope_count;
  bool control_configured{};
  {
    std::scoped_lock lock(g_control_mutex);
    control_configured = g_control_core.configure(control_config);
  }
  if (!control_configured) {
    fail_closed_bridge();
    return false;
  }
  g_relative_gain.store(profile.relative_gain, std::memory_order_relaxed);
  g_deadzone_pixels.store(profile.deadzone_pixels, std::memory_order_relaxed);
  g_maximum_axis_delta.store(profile.maximum_axis_delta, std::memory_order_relaxed);
  if (!profile.output_enabled) {
    g_move_commit_gate.fail_closed();
    g_move_visibility_gate.fail_closed();
  }
  if (!g_output_gate.set_user_requested(profile.output_enabled)) return false;
  return true;
}

void activate_makcu_stream_generation(std::uint64_t generation) noexcept {
  std::scoped_lock publish_lock(g_publish_mutex);
  g_stream_generation_gate.activate(generation);
}

void suspend_makcu_output_for_recovery(std::uint64_t generation) noexcept {
  // Linearize generation rollover with the complete observation/control
  // transaction. A result that passed the decoder check immediately before
  // recovery cannot repopulate the freshly reset tracker afterward.
  std::scoped_lock publish_lock(g_publish_mutex);
  g_stream_generation_gate.activate(generation);
  g_output_gate.suspend_for_recovery(generation);
  // Java suspension first closes its offer gate and waits for transport I/O
  // already in progress. Keep the exact native ticket valid during that wait
  // so a legitimate final ACK cannot be misclassified as stale and cancel an
  // otherwise recoverable decoder restart.
  const bool java_suspended =
      invoke_java_delivery_gate(JavaDeliveryCall::suspend, generation);
  g_move_commit_gate.fail_closed();
  g_move_visibility_gate.fail_closed();
  {
    std::scoped_lock lock(g_control_mutex);
    g_control_core.reset();
  }
  if (!java_suspended ||
      !g_output_gate.recovery_suspended_for(generation)) fail_closed_bridge();
}

bool resume_makcu_output_after_valid_frame(std::uint64_t generation) noexcept {
  const MakcuRecoveryCompletion completion =
      g_output_gate.complete_after_valid_frame(generation);
  if (!completion.matched) return false;
  const bool java_output_enabled =
      invoke_java_delivery_gate(JavaDeliveryCall::resume, generation);
  if (completion.output_enabled && java_output_enabled) return true;
  fail_closed_bridge();
  return false;
}

void fail_closed_makcu_delivery() noexcept {
  fail_closed_bridge();
}

void disable_makcu_output() noexcept {
  std::scoped_lock publish_lock(g_publish_mutex);
  fail_closed_bridge(MakcuStreamCloseScope::stream_lifecycle);
}

void publish_makcu_move_for_detections(
    std::span<const YoloDetection> detections, std::uint64_t frame_sequence,
  std::uint64_t stream_generation, bool content_updated,
  std::uint64_t observed_at_us, std::uint64_t now_us) {
  std::scoped_lock publish_lock(g_publish_mutex);
  if (!g_stream_generation_gate.accepts(stream_generation)) {
    ++g_stale_stream_generation_suppressed;
    return;
  }
  ++g_processed_frames;
  if (g_move_commit_gate.expire_if_older(
          now_us, kMaximumMoveCompletionAgeUs)) {
    ++g_move_completion_timeouts;
    fail_closed_bridge();
    return;
  }
  if (g_move_commit_gate.pending()) {
    {
      std::scoped_lock lock(g_control_mutex);
      static_cast<void>(g_control_core.observe_tracking_only(
          detections, {frame_sequence, observed_at_us, now_us}));
    }
    ++g_move_completion_pending_suppressed;
    return;
  }
  bool completed_move_became_visible = false;
  if (!g_move_visibility_gate.consume_if_visible(
          frame_sequence, observed_at_us, content_updated,
          &completed_move_became_visible)) {
    {
      std::scoped_lock lock(g_control_mutex);
      static_cast<void>(g_control_core.observe_tracking_only(
          detections, {frame_sequence, observed_at_us, now_us}));
    }
    ++g_post_completion_visibility_suppressed;
    return;
  }

  MobileControlOutput output{};
  {
    std::scoped_lock lock(g_control_mutex);
    if (completed_move_became_visible) {
      g_control_core.apply_visible_ego_motion(
          g_last_offered_delta_x.load(std::memory_order_relaxed),
          g_last_offered_delta_y.load(std::memory_order_relaxed));
    }
    output = g_control_core.process(detections, {frame_sequence, observed_at_us, now_us});
  }
  if (!output.has_target) ++g_no_targets;
  if (output.held) ++g_held_targets;
  if (output.switched) ++g_target_switches;
  if (!output.has_move()) {
    ++g_deadzone_suppressed;
    return;
  }
  ++g_candidates;
  if (!g_output_gate.output_enabled()) {
    ++g_output_disabled_suppressed;
    return;
  }
  const std::uint64_t ticket =
      g_move_commit_gate.begin(now_us, frame_sequence);
  if (ticket == 0U) {
    ++g_move_completion_pending_suppressed;
    std::scoped_lock lock(g_control_mutex);
    g_control_core.reset();
    return;
  }

  bool java_offer_accepted = false;
  bool java_dispatch_completed = false;
  bool offer_authorized = false;
  offer_authorized = g_output_gate.execute_if_enabled([&] {
    std::scoped_lock lock(g_bridge_mutex);
    if (!g_java_bridge_ready.load(std::memory_order_acquire) || g_vm == nullptr ||
        g_controller_class == nullptr || g_offer_move == nullptr) {
      ++g_java_dispatch_failures;
      return;
    }
    JNIEnv* environment{};
    bool attached = false;
    const jint environment_status = g_vm->GetEnv(
        reinterpret_cast<void**>(&environment), JNI_VERSION_1_6);
    if (environment_status == JNI_EDETACHED) {
      if (g_vm->AttachCurrentThread(&environment, nullptr) != JNI_OK) {
        ++g_java_dispatch_failures;
        return;
      }
      attached = true;
    } else if (environment_status != JNI_OK || environment == nullptr) {
      ++g_java_dispatch_failures;
      return;
    }
    const jboolean accepted = environment->CallStaticBooleanMethod(
        g_controller_class, g_offer_move, output.delta_x, output.delta_y,
        static_cast<jlong>(ticket));
    if (environment->ExceptionCheck()) {
      environment->ExceptionClear();
      ++g_java_dispatch_failures;
    } else {
      java_dispatch_completed = true;
      java_offer_accepted = accepted == JNI_TRUE;
      if (java_offer_accepted) ++g_java_offer_acceptances;
      else ++g_java_offer_rejections;
    }
    if (attached) g_vm->DetachCurrentThread();
  });
  if (offer_authorized && java_dispatch_completed && java_offer_accepted) {
    observe_accepted_move(output.delta_x, output.delta_y);
    return;
  }

  static_cast<void>(g_move_commit_gate.complete(ticket));
  {
    std::scoped_lock lock(g_control_mutex);
    g_control_core.reset();
  }
  if (!offer_authorized) {
    ++g_output_disabled_suppressed;
    return;
  }
  fail_closed_bridge();
}

void report_makcu_move_result(
    std::uint64_t ticket, bool device_acknowledged,
    std::uint64_t acknowledgement_us) noexcept {
  if (!device_acknowledged) {
    // Claim the exact ticket and close native authorization before pending is
    // cleared. Do not acquire g_publish_mutex here: the serial reader may hold
    // serialIoLock while decoder recovery owns the publish lock and waits for
    // that same I/O to finish.
    const MakcuMoveCompletion completion = g_move_commit_gate.complete_with(
        ticket, [](std::uint64_t) noexcept {
          g_output_gate.revoke_immediately();
        });
    const MakcuMoveFeedbackAction action = classify_makcu_move_feedback(
        completion.matched, false);
    if (action == MakcuMoveFeedbackAction::ignore_stale) {
      ++g_stale_device_feedback;
      return;
    }
    ++g_device_ack_failures;
    fail_closed_bridge();
    return;
  }
  if (!complete_matching_move(
          ticket, g_stale_device_feedback,
          kPostAcknowledgementAdditionalDelayUs)) {
    return;
  }
  observe_matching_device_ack();
  ++g_device_ack_completions;
  g_last_device_ack_us.store(acknowledgement_us, std::memory_order_relaxed);
}

bool report_bluetooth_hid_move_accepted(
    std::uint64_t ticket, std::uint64_t api_acceptance_us) noexcept {
  if (!complete_matching_move(
          ticket, g_stale_bluetooth_hid_api_acceptances,
          kPostAcknowledgementAdditionalDelayUs)) {
    return false;
  }
  ++g_bluetooth_hid_api_acceptances;
  g_last_bluetooth_hid_api_acceptance_us.store(
      api_acceptance_us, std::memory_order_relaxed);
  return true;
}

std::string makcu_move_bridge_report() {
  ControlCoreMetrics control_metrics{};
  MobileTargetTrackerMetrics tracker_metrics{};
  MobileMotionPlannerMetrics motion_metrics{};
  MobileMotionPlannerConfig motion_config{};
  MobileMotionPlannerOutput motion_snapshot{};
  std::uint64_t switch_confirmation_duration_us{};
  float missing_switch_min_confidence{};
  float missing_switch_max_jump_pixels{};
  std::uint64_t lost_target_hold_duration_us{};
  std::uint64_t lost_track_duration_us{};
  {
    std::scoped_lock lock(g_control_mutex);
    control_metrics = g_control_core.metrics();
    tracker_metrics = g_control_core.tracker_metrics();
    motion_metrics = g_control_core.motion_metrics();
    motion_config = g_control_core.motion_config();
    motion_snapshot = g_control_core.motion_snapshot();
    switch_confirmation_duration_us =
        g_control_core.switch_confirmation_duration_us();
    missing_switch_min_confidence =
        g_control_core.missing_switch_min_confidence();
    missing_switch_max_jump_pixels =
        g_control_core.missing_switch_max_jump_pixels();
    lost_target_hold_duration_us =
        g_control_core.lost_target_hold_duration_us();
    lost_track_duration_us = g_control_core.lost_track_duration_us();
  }
  std::ostringstream value;
  value << "processing_enabled=1"
        << " processed_frames=" << g_processed_frames.load()
        << " active_stream_generation="
        << g_stream_generation_gate.active()
        << " native_delivery_fail_close_requests="
        << g_delivery_fail_close_requests.load()
        << " native_stream_lifecycle_close_requests="
        << g_stream_lifecycle_close_requests.load()
        << " stale_stream_generation_suppressed="
        << g_stale_stream_generation_suppressed.load()
        << " candidate_moves=" << g_candidates.load()
        << " java_offer_acceptances=" << g_java_offer_acceptances.load()
        << " java_offer_rejections=" << g_java_offer_rejections.load()
        << " native_move_completion_pending=" << g_move_commit_gate.pending()
        << " native_move_completion_pending_ticket="
        << g_move_commit_gate.pending_ticket()
        << " native_move_completion_pending_suppressed="
        << g_move_completion_pending_suppressed.load()
        << " native_move_completion_timeouts="
        << g_move_completion_timeouts.load()
        << " native_device_ack_completions="
        << g_device_ack_completions.load()
        << " native_device_ack_failures=" << g_device_ack_failures.load()
        << " stale_device_feedback=" << g_stale_device_feedback.load()
        << " native_last_device_ack_latency_us=" << g_last_device_ack_us.load()
        << " native_last_device_ack_interval_us="
        << g_last_device_ack_interval_us.load()
        << " native_last_offered_delta_x=" << g_last_offered_delta_x.load()
        << " native_last_offered_delta_y=" << g_last_offered_delta_y.load()
        << " native_offered_absolute_x_counts="
        << g_offered_absolute_x_counts.load()
        << " native_offered_absolute_y_counts="
        << g_offered_absolute_y_counts.load()
        << " native_maximum_offered_absolute_axis_delta="
        << g_maximum_offered_absolute_axis_delta.load()
        << " native_offered_direction_flips_x="
        << g_offered_direction_flips_x.load()
        << " native_offered_direction_flips_y="
        << g_offered_direction_flips_y.load()
        << " native_last_offer_interval_us="
        << g_last_offer_interval_us.load()
        << " native_bluetooth_hid_api_acceptances="
        << g_bluetooth_hid_api_acceptances.load()
        << " stale_bluetooth_hid_api_acceptances="
        << g_stale_bluetooth_hid_api_acceptances.load()
        << " native_last_bluetooth_hid_api_acceptance_latency_us="
        << g_last_bluetooth_hid_api_acceptance_us.load()
        << " bluetooth_hid_api_acceptance_semantics="
           "android_hid_stack_accepted_not_host_or_physical_ack"
        << " post_completion_visibility_armed="
        << g_move_visibility_gate.armed()
        << " makcu_post_completion_visibility_min_us="
        << kPostAcknowledgementAdditionalDelayUs
        << " bluetooth_hid_post_completion_visibility_min_us="
        << kPostAcknowledgementAdditionalDelayUs
        << " post_completion_visibility_suppressed="
        << g_post_completion_visibility_suppressed.load()
        << " java_bridge_ready=" << g_java_bridge_ready.load()
        << " output_disabled_suppressed=" << g_output_disabled_suppressed.load()
        << " output_requested=" << g_output_gate.user_requested()
        << " output_recovery_suspended=" << g_output_gate.recovery_suspended()
        << " output_enabled=" << g_output_gate.output_enabled()
        << " relative_gain=" << g_relative_gain.load()
        << " deadzone_pixels=" << g_deadzone_pixels.load()
        << " maximum_axis_delta=" << g_maximum_axis_delta.load()
        << " switch_confirmation_duration_us="
        << switch_confirmation_duration_us
        << " missing_switch_min_confidence="
        << missing_switch_min_confidence
        << " missing_switch_max_jump_pixels="
        << missing_switch_max_jump_pixels
        << " lost_target_hold_duration_us="
        << lost_target_hold_duration_us
        << " tracker_lost_duration_us=" << lost_track_duration_us
        << " deadzone_suppressed=" << g_deadzone_suppressed.load()
        << " held_targets=" << g_held_targets.load()
        << " target_switches=" << g_target_switches.load()
        << " no_targets=" << g_no_targets.load()
        << " stale_frames=" << control_metrics.stale_frames
        << " non_monotonic_frames=" << control_metrics.non_monotonic_frames
        << " invalid_time_frames=" << control_metrics.invalid_time_frames
        << " geometry_non_finite_rejected=" << control_metrics.rejected_non_finite
        << " geometry_invalid_box_rejected=" << control_metrics.rejected_invalid_box
        << " geometry_unsupported_class_rejected=" << control_metrics.rejected_unsupported_class
        << " geometry_confidence_rejected=" << control_metrics.rejected_confidence
        << " geometry_out_of_bounds_rejected=" << control_metrics.rejected_out_of_bounds
        << " geometry_border_rejected=" << control_metrics.rejected_border
        << " geometry_size_rejected=" << control_metrics.rejected_size
        << " geometry_aspect_rejected=" << control_metrics.rejected_aspect_ratio
        << " head_preemptions=" << control_metrics.head_preemptions
        << " head_body_projection_continuations="
        << control_metrics.head_body_projection_continuations
        << " head_body_projection_recoveries="
        << control_metrics.head_body_projection_recoveries
        << " maximum_head_body_projection_recovery_pixels="
        << control_metrics.maximum_head_body_projection_recovery_pixels
        << " rejected_head_body_projection_geometry="
        << control_metrics.rejected_head_body_projection_geometry
        << " switch_pending_frames=" << control_metrics.switch_pending_frames
        << " reacquisition_pending_frames="
        << control_metrics.reacquisition_pending_frames
        << " reacquisition_confirmations="
        << control_metrics.reacquisition_confirmations
        << " rejected_missing_switch_confidence="
        << control_metrics.rejected_missing_switch_confidence
        << " rejected_missing_switch_jump="
        << control_metrics.rejected_missing_switch_jump
        << " lock_exact_track_matches="
        << control_metrics.lock_exact_track_matches
        << " lock_observation_track_matches="
        << control_metrics.lock_observation_track_matches
        << " lock_geometric_matches="
        << control_metrics.lock_geometric_matches
        << " lock_giou_matches="
        << control_metrics.lock_giou_matches
        << " rejected_exact_track_geometry="
        << control_metrics.rejected_exact_track_geometry
        << " ego_motion_adjustments="
        << control_metrics.ego_motion_adjustments
        << " measured_ego_motion_adjustments="
        << control_metrics.measured_ego_motion_adjustments
        << " rejected_measured_ego_motion_axes="
        << control_metrics.rejected_measured_ego_motion_axes
        << " ego_motion_response_waits="
        << control_metrics.ego_motion_response_waits
        << " ego_motion_response_timeouts="
        << control_metrics.ego_motion_response_timeouts
        << " maximum_ego_motion_shift_pixels="
        << control_metrics.maximum_ego_motion_shift_pixels
        << " maximum_ego_motion_prediction_error_pixels="
        << control_metrics.maximum_ego_motion_prediction_error_pixels
        << " maximum_measured_ego_motion_support="
        << control_metrics.maximum_measured_ego_motion_support
        << " track_id_rebinds=" << control_metrics.track_id_rebinds
        << " rejected_known_track_rebinds="
        << control_metrics.rejected_known_track_rebinds
        << " rejected_track_id_mismatches="
        << control_metrics.rejected_track_id_mismatches
        << " rejected_ambiguous_rebinds="
        << control_metrics.rejected_ambiguous_rebinds
        << " rejected_rebind_geometry="
        << control_metrics.rejected_rebind_geometry
        << " tracking_only_frames=" << control_metrics.tracking_only_frames
        << " tracking_only_lock_updates="
        << control_metrics.tracking_only_lock_updates
        << " settle_suppressions=" << control_metrics.settle_suppressions
        << " motion_invalid_suppressions="
        << control_metrics.motion_invalid_suppressions
        << " motion_plans=" << motion_metrics.plans
        << " motion_phase=" << mobile_motion_phase_name(motion_snapshot.phase)
        << " motion_suppression="
        << motion_planner_suppression_name(
               motion_snapshot.suppression_reason)
        << " motion_predicted_error_x="
        << motion_snapshot.predicted_error_x
        << " motion_predicted_error_y="
        << motion_snapshot.predicted_error_y
        << " motion_acceleration_x="
        << motion_snapshot.target_acceleration_x_pixels_per_second2
        << " motion_acceleration_y="
        << motion_snapshot.target_acceleration_y_pixels_per_second2
        << " motion_response_budget_x="
        << motion_snapshot.response_budget_x_counts
        << " motion_response_budget_y="
        << motion_snapshot.response_budget_y_counts
        << " motion_lock_age_ms=" << motion_snapshot.lock_age_ms
        << " motion_phase_age_ms=" << motion_snapshot.phase_age_ms
        << " motion_response_x_px_per_count="
        << motion_config.response_x_px_per_count
        << " motion_response_y_px_per_count="
        << motion_config.response_y_px_per_count
        << " motion_response_upper_x_px_per_count="
        << motion_config.response_upper_x_px_per_count
        << " motion_response_upper_y_px_per_count="
        << motion_config.response_upper_y_px_per_count
        << " motion_response_limited="
        << motion_snapshot.response_limited
        << " motion_jerk_limited=" << motion_snapshot.jerk_limited
        << " motion_step_limited=" << motion_snapshot.step_limited
        << " motion_settle_stopped=" << motion_snapshot.settle_stopped
        << " motion_uncalibrated_maximum_axis_delta="
        << motion_config.uncalibrated_maximum_axis_delta
        << " motion_maximum_step_counts_per_tick="
        << motion_config.maximum_step_counts_per_tick
        << " motion_maximum_jerk_counts_per_tick2="
        << motion_config.maximum_jerk_counts_per_tick2
        << " personal_trajectory_enabled="
        << motion_config.personal_trajectory_enabled
        << " personal_trajectory_applied="
        << motion_snapshot.personal_trajectory_applied
        << " personal_speed_scale="
        << motion_config.personal_speed_scale
        << " personal_stability_scale="
        << motion_config.personal_stability_scale
        << " personal_variation_scale="
        << motion_config.personal_variation_scale
        << " personal_envelope_points="
        << motion_config.personal_speed_envelope_count
        << " personal_trajectory_plans="
        << motion_metrics.personal_trajectory_plans
        << " personal_variation_packets="
        << motion_metrics.personal_trajectory_variation_packets
        << " motion_invalid_inputs=" << motion_metrics.invalid_inputs
        << " motion_invalid_times=" << motion_metrics.invalid_times
        << " motion_stale_observations="
        << motion_metrics.stale_observations
        << " motion_non_monotonic_observations="
        << motion_metrics.non_monotonic_observations
        << " motion_direction_flip_suppressions="
        << motion_metrics.direction_flip_suppressions
        << " motion_direction_reorientations="
        << motion_metrics.direction_reorientations
        << " motion_response_guard_suppressions="
        << motion_metrics.response_guard_suppressions
        << " motion_settle_guard_suppressions="
        << motion_metrics.settle_guard_suppressions
        << " motion_settle_quantization_rescues="
        << motion_metrics.settle_quantization_rescues
        << " motion_settle_stop_latches="
        << motion_metrics.settle_stop_latches
        << " motion_settle_stop_holds="
        << motion_metrics.settle_stop_holds
        << " motion_response_limited_axes="
        << motion_metrics.response_limited_axes
        << " motion_jerk_limited_axes="
        << motion_metrics.jerk_limited_axes
        << " motion_step_limited_axes="
        << motion_metrics.step_limited_axes
        << " paired_heads=" << control_metrics.paired_heads
        << " head_only_acceptances=" << control_metrics.head_only_acceptances
        << " unvalidated_heads_rejected=" << control_metrics.rejected_unvalidated_heads
        << " body_fallbacks_rejected=" << control_metrics.rejected_body_fallbacks
        << " tracker_tracks_created=" << tracker_metrics.tracks_created
        << " tracker_first_stage_matches=" << tracker_metrics.first_stage_matches
        << " tracker_second_stage_matches=" << tracker_metrics.second_stage_matches
        << " tracker_center_matches=" << tracker_metrics.center_distance_matches
        << " tracker_ambiguous_center_matches_rejected="
        << tracker_metrics.ambiguous_center_matches_rejected
        << " tracker_tracks_expired=" << tracker_metrics.tracks_expired
        << " tracker_control_filter_blends="
        << tracker_metrics.control_filter_blends
        << " tracker_control_filter_bypasses="
        << tracker_metrics.control_filter_bypasses
        << " tracker_time_based_velocity_updates="
        << tracker_metrics.time_based_velocity_updates
        << " tracker_maximum_observation_interval_us="
        << tracker_metrics.maximum_observation_interval_us
        << " tracker_maximum_control_innovation_pixels="
        << tracker_metrics.maximum_control_innovation_pixels
        << " java_dispatch_failures=" << g_java_dispatch_failures.load();
  return value.str();
}

}  // namespace vfdual_android
