#pragma once

#include "vfdual/host_mouse_button_publisher.hpp"
#include "vfdual/host_runtime_config.hpp"
#include "vfdual/idr_request_listener.hpp"
#include "vfdual/streamer_metrics_csv.hpp"

#include <atomic>
#include <cstdint>
#include <memory>

namespace vfdual {

[[nodiscard]] constexpr bool is_healthy_host_video_status(
    DesktopVideoStepStatus status) noexcept {
  switch (status) {
    case DesktopVideoStepStatus::frame_published:
    case DesktopVideoStepStatus::data_plane_closed:
    case DesktopVideoStepStatus::frame_queued:
    case DesktopVideoStepStatus::capture_timeout:
    case DesktopVideoStepStatus::capture_pointer_only:
    case DesktopVideoStepStatus::capture_outside_region:
    case DesktopVideoStepStatus::staging_busy:
      return true;
    case DesktopVideoStepStatus::capture_access_lost:
    case DesktopVideoStepStatus::capture_device_removed:
    case DesktopVideoStepStatus::capture_failed:
    case DesktopVideoStepStatus::bridge_failed:
    case DesktopVideoStepStatus::encode_failed:
    case DesktopVideoStepStatus::publish_failed:
      return false;
  }
  return false;
}

enum class HostApplicationStartStage : std::uint8_t {
  none,
  video_initialize,
  idr_listener_start,
  mouse_button_publisher_start,
  authenticated_presence_start,
  metrics_csv_open,
  complete,
};

struct HostApplicationStats {
  std::uint64_t published_frames{};
  std::uint64_t capture_timeouts{};
  std::uint64_t pointer_only_skips{};
  std::uint64_t outside_region_skips{};
  std::uint64_t staging_busy_drops{};
  HostMouseButtonPublisherStats mouse_button_publisher{};
  DesktopVideoStepMetrics last_video_step{};
};

/**
 * Lifetime coordinator for the Windows real-time host application.
 *
 * It owns the PC-side video path and the read-only physical button publisher.
 * Movement output remains phone-owned through the selected MAKCU or Bluetooth
 * HID backend.
 */
class HostApplication final {
public:
  HostApplication();
  ~HostApplication();
  HostApplication(const HostApplication&) = delete;
  HostApplication& operator=(const HostApplication&) = delete;

  [[nodiscard]] bool start(
      const HostRuntimeConfig& config,
      std::shared_ptr<HostAuthenticatedDataPlaneSessionV2>
          authenticated_session = {});
  [[nodiscard]] bool publish_next();
  void stop() noexcept;

  [[nodiscard]] const HostApplicationStats& stats() const noexcept;
  [[nodiscard]] const DesktopVideoEncoderDiagnostics* encoder_diagnostics() const noexcept;
  [[nodiscard]] HostApplicationStartStage last_start_stage() const noexcept;
  [[nodiscard]] std::int32_t last_error() const noexcept;

private:
  std::unique_ptr<DesktopVideoAgent> video_agent_;
  HostRuntimeConfig config_{};
  HostApplicationStats stats_{};
  DesktopVideoEncoderDiagnostics last_encoder_diagnostics_{};
  HostApplicationStartStage last_start_stage_{HostApplicationStartStage::none};
  std::int32_t last_error_{};
  bool has_encoder_diagnostics_{};
  bool started_{};
  IdrRequestListener idr_requests_;
  HostMouseButtonPublisher mouse_button_publisher_;
  UdpSocket presence_socket_;
  std::shared_ptr<HostAuthenticatedDataPlaneSessionV2>
      authenticated_session_;
  std::uint64_t last_presence_publish_us_{};
  StreamerMetricsCsv metrics_csv_;
};

}  // namespace vfdual
