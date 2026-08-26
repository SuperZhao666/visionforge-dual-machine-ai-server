#include "vfdual/host_application.hpp"
#include "vfdual/host_published_frame_accounting.hpp"

#include <array>
#include <chrono>

namespace vfdual {

HostApplication::HostApplication() = default;
HostApplication::~HostApplication() { stop(); }

bool HostApplication::start(
    const HostRuntimeConfig& config,
    std::shared_ptr<HostAuthenticatedDataPlaneSessionV2>
        authenticated_session) {
  stop();
  last_encoder_diagnostics_ = {};
  last_start_stage_ = HostApplicationStartStage::video_initialize;
  last_error_ = 0;
  has_encoder_diagnostics_ = false;
  if (!authenticated_session) {
    last_error_ = 1;
    return false;
  }
  HostRuntimeConfig secured_config = config;
  secured_config.video.authenticated_data_plane_session =
      authenticated_session;
  auto video = std::make_unique<DesktopVideoAgent>();
  if (!video->initialize(secured_config.video)) {
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
          secured_config.video.local_host,
          secured_config.video.phone_host,
          secured_config.video.data_plane_permit,
          authenticated_session)) {
    last_error_ = static_cast<std::int32_t>(idr_requests_.last_socket_error());
    video->reset();
    return false;
  }

  last_start_stage_ = HostApplicationStartStage::mouse_button_publisher_start;
  if (!mouse_button_publisher_.start(
          secured_config.video.local_host,
          secured_config.video.phone_host,
          secured_config.video.data_plane_permit,
          authenticated_session)) {
    last_error_ = static_cast<std::int32_t>(
        mouse_button_publisher_.stats().last_socket_error);
    idr_requests_.stop();
    video->reset();
    return false;
  }

  last_start_stage_ = HostApplicationStartStage::authenticated_presence_start;
  if (!presence_socket_.bind_to(secured_config.video.local_host, 0U) ||
      !presence_socket_.connect_to(
          secured_config.video.phone_host,
          kWiredAuthenticatedPresencePort)) {
    last_error_ = static_cast<std::int32_t>(presence_socket_.last_error());
    presence_socket_.close();
    mouse_button_publisher_.stop();
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
  config_ = std::move(secured_config);
  authenticated_session_ = std::move(authenticated_session);
  last_presence_publish_us_ = 0U;
  video_agent_ = std::move(video);
  stats_ = {};
  last_error_ = 0;
  last_start_stage_ = HostApplicationStartStage::complete;
  started_ = true;
  return true;
}

bool HostApplication::publish_next() {
  if (!started_ || !video_agent_) return false;
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const std::uint64_t now_us = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(now).count());
  if (last_presence_publish_us_ == 0U ||
      now_us - last_presence_publish_us_ >= 250'000U) {
    std::array<std::byte, 8U> payload{};
    for (std::size_t index = 0U; index < payload.size(); ++index) {
      payload[index] = std::byte{static_cast<std::uint8_t>(
          now_us >> ((payload.size() - 1U - index) * 8U))};
    }
    PacketSealResult sealed = authenticated_session_
        ? authenticated_session_->seal_presence(payload)
        : PacketSealResult{};
    bool authorized = false;
    try {
      authorized = config_.video.data_plane_permit &&
          config_.video.data_plane_permit();
    } catch (...) {
      authorized = false;
    }
    if (sealed.status != PacketSealStatus::sealed || !authorized ||
        !presence_socket_.send(sealed.datagram)) {
      return false;
    }
    last_presence_publish_us_ = now_us;
  }
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
  presence_socket_.close();
  if (video_agent_) video_agent_->reset();
  video_agent_.reset();
  idr_requests_.stop();
  metrics_csv_.close();
  stats_ = {};
  authenticated_session_.reset();
  last_presence_publish_us_ = 0U;
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
