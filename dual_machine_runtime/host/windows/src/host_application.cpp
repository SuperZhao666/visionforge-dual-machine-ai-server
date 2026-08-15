#include "vfdual/host_application.hpp"
#include "vfdual/host_published_frame_accounting.hpp"

#include <chrono>

namespace vfdual {

HostApplication::HostApplication() = default;
HostApplication::~HostApplication() { stop(); }

bool HostApplication::start(const HostRuntimeConfig& config) {
  stop();
  last_encoder_diagnostics_ = {};
  last_start_stage_ = HostApplicationStartStage::video_initialize;
  last_error_ = 0;
  has_encoder_diagnostics_ = false;
  auto video = std::make_unique<DesktopVideoAgent>();
  if (!video->initialize(config.video)) {
    last_encoder_diagnostics_ = video->encoder_diagnostics();
    has_encoder_diagnostics_ = true;
    last_error_ = last_encoder_diagnostics_.last_failure_status != 0
        ? last_encoder_diagnostics_.last_failure_status : 1;
    return false;
  }
  last_encoder_diagnostics_ = video->encoder_diagnostics();
  has_encoder_diagnostics_ = true;

  last_start_stage_ = HostApplicationStartStage::idr_listener_start;
  if (!idr_requests_.start(
          kWiredIdrPort,
          config.video.local_host,
          config.video.phone_host)) {
    last_error_ = static_cast<std::int32_t>(idr_requests_.last_socket_error());
    video->reset();
    return false;
  }

  last_start_stage_ = HostApplicationStartStage::mouse_button_publisher_start;
  if (!mouse_button_publisher_.start(
          config.video.local_host,
          config.video.phone_host)) {
    last_error_ = static_cast<std::int32_t>(
        mouse_button_publisher_.stats().last_socket_error);
    idr_requests_.stop();
    video->reset();
    return false;
  }

  last_start_stage_ = HostApplicationStartStage::metrics_csv_open;
  if (!metrics_csv_.open(
          config.metrics_csv_path, config.metrics_interval_frames)) {
    last_error_ = metrics_csv_.last_error();
    // Keep a failed start transactional: in particular, do not retain the
    // UDP 5001 listener when a later metrics-file step fails.
    mouse_button_publisher_.stop();
    idr_requests_.stop();
    metrics_csv_.close();
    video->reset();
    return false;
  }
  config_ = config;
  video_agent_ = std::move(video);
  stats_ = {};
  last_error_ = 0;
  last_start_stage_ = HostApplicationStartStage::complete;
  started_ = true;
  return true;
}

bool HostApplication::publish_next() {
  if (!started_ || !video_agent_) return false;
  if (idr_requests_.poll_request()) video_agent_->request_idr();
  const DesktopVideoStepMetrics operational = video_agent_->publish_next();
  metrics_csv_.append(operational);
  stats_.last_video_step = operational;
  stats_.mouse_button_publisher = mouse_button_publisher_.stats();
  bool healthy = is_healthy_host_video_status(operational.status);
  stats_.published_frames = reconcile_published_frames(
      stats_.published_frames, operational);
  if (operational.status == DesktopVideoStepStatus::capture_timeout) {
    ++stats_.capture_timeouts;
  } else if (operational.status == DesktopVideoStepStatus::capture_pointer_only) {
    ++stats_.pointer_only_skips;
  } else if (operational.status == DesktopVideoStepStatus::capture_outside_region) {
    ++stats_.outside_region_skips;
  } else if (operational.status == DesktopVideoStepStatus::staging_busy) {
    ++stats_.staging_busy_drops;
  }

  DesktopVideoStepMetrics completion{};
  while (video_agent_->try_pop_completed(completion)) {
    metrics_csv_.append(completion);
    stats_.published_frames = reconcile_published_frames(
        stats_.published_frames, completion);
    const bool completion_healthy =
        is_healthy_host_video_status(completion.status);
    if (healthy) stats_.last_video_step = completion;
    healthy = healthy && completion_healthy;
  }
  return healthy;
}

void HostApplication::stop() noexcept {
  mouse_button_publisher_.stop();
  if (video_agent_) video_agent_->reset();
  video_agent_.reset();
  idr_requests_.stop();
  metrics_csv_.close();
  stats_ = {};
  started_ = false;
}

const HostApplicationStats& HostApplication::stats() const noexcept { return stats_; }
const DesktopVideoEncoderDiagnostics*
HostApplication::encoder_diagnostics() const noexcept {
  if (video_agent_) return &video_agent_->encoder_diagnostics();
  return has_encoder_diagnostics_ ? &last_encoder_diagnostics_ : nullptr;
}
HostApplicationStartStage HostApplication::last_start_stage() const noexcept {
  return last_start_stage_;
}
std::int32_t HostApplication::last_error() const noexcept { return last_error_; }

}  // namespace vfdual
