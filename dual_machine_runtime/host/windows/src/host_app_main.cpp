#include "vfdual/host_application.hpp"
#include "vfdual/host_runtime_config.hpp"

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {
std::atomic_bool g_stop_requested{};

void request_stop(int) { g_stop_requested = true; }

void print_usage() {
  std::cerr << "Usage: VisionForgeStreamer --config <path> [--frames <count>] [--stop-event <name>]\n"
            << "This process owns only capture, H.264 encoding and UDP video transmission.\n";
}

bool parse_frames(const char* text, std::uint64_t& value) {
  char* end{};
  value = std::strtoull(text, &end, 10);
  return end != text && *end == '\0';
}

void print_metrics(const vfdual::HostApplicationStats& stats) {
  const auto& step = stats.last_video_step;
  std::cout << "event=host_metrics published_frames=" << stats.published_frames
            << " capture_timeouts=" << stats.capture_timeouts
            << " last_status=" << static_cast<int>(step.status)
            << " frame=" << step.frame_id
            << " capture_us=" << step.capture_us
            << " bridge_us=" << step.bridge_us
            << " encode_us=" << step.encode_us
            << " publish_us=" << step.publish_us
            << " access_unit_bytes=" << step.access_unit_bytes
            << " datagrams=" << step.datagrams_sent << '\n';
}
}  // namespace

int main(int argc, char** argv) {
  std::string config_path;
  std::string stop_event_name;
  std::uint64_t requested_frames{};  // Zero means run until Ctrl+C.
  for (int index = 1; index < argc; ++index) {
    const std::string option = argv[index];
    if (option == "--config" && index + 1 < argc) config_path = argv[++index];
    else if (option == "--frames" && index + 1 < argc && parse_frames(argv[++index], requested_frames)) {}
    else if (option == "--stop-event" && index + 1 < argc) stop_event_name = argv[++index];
    else { print_usage(); return 2; }
  }
  if (config_path.empty()) { print_usage(); return 2; }

  HANDLE stop_event{};
  if (!stop_event_name.empty()) {
    stop_event = OpenEventA(SYNCHRONIZE, FALSE, stop_event_name.c_str());
    if (stop_event == nullptr) {
      std::cerr << "event=host_stop_event_invalid native_error=" << GetLastError() << '\n';
      return 2;
    }
  }

  vfdual::HostRuntimeConfig config;
  std::string config_error;
  if (!vfdual::load_host_runtime_config(config_path, config, config_error)) {
    std::cerr << "event=host_config_invalid error=" << config_error << '\n';
    return 2;
  }
  // This standalone diagnostic process has no authenticated Secure-v2 owner.
  // It may prepare capture/encoder resources but is never a video authority.
  config.video.data_plane_permit = []() noexcept { return false; };
  std::signal(SIGINT, request_stop);
  std::signal(SIGTERM, request_stop);
  vfdual::HostApplication application;
  if (!application.start(config)) {
    std::cerr << "event=host_start_failed native_error=" << application.last_error() << '\n';
    return 1;
  }
  std::cout << "event=host_started phone=" << config.video.phone_host
            << " video_port=" << config.video.phone_port
            << " resolution=" << config.video.encoder.width << 'x' << config.video.encoder.height
            << " fps=" << config.video.encoder.frames_per_second << '\n';

  std::uint64_t attempts{};
  while (!g_stop_requested && (stop_event == nullptr || WaitForSingleObject(stop_event, 0) != WAIT_OBJECT_0) &&
         (requested_frames == 0 || attempts < requested_frames)) {
    ++attempts;
    if (!application.publish_next() &&
        application.stats().last_video_step.status !=
            vfdual::DesktopVideoStepStatus::capture_timeout &&
        application.stats().last_video_step.status !=
            vfdual::DesktopVideoStepStatus::data_plane_closed) {
      std::cerr << "event=host_video_failed status=" << static_cast<int>(application.stats().last_video_step.status)
                << " native_error=" << application.stats().last_video_step.native_status << '\n';
      application.stop();
      return 1;
    }
    if (application.stats().published_frames != 0 &&
        application.stats().published_frames % config.metrics_interval_frames == 0) print_metrics(application.stats());
  }
  print_metrics(application.stats());
  application.stop();
  if (stop_event != nullptr) CloseHandle(stop_event);
  std::cout << "event=host_stopped\n";
  return 0;
}
