#include "vfdual/host_published_frame_accounting.hpp"
#include "vfdual/host_application.hpp"

#include <cstdio>
#include <cstdlib>

namespace {

void require(bool condition, const char* expression, int line) {
  if (condition) return;
  std::fprintf(stderr, "CHECK failed: %s (line %d)\n", expression, line);
  std::exit(EXIT_FAILURE);
}

#define VFDUAL_TEST_REQUIRE(expression) \
  require(static_cast<bool>(expression), #expression, __LINE__)

}  // namespace

int main() {
  VFDUAL_TEST_REQUIRE(vfdual::is_healthy_host_video_status(
      vfdual::DesktopVideoStepStatus::data_plane_closed));
  VFDUAL_TEST_REQUIRE(vfdual::is_healthy_host_video_status(
      vfdual::DesktopVideoStepStatus::frame_published));
  VFDUAL_TEST_REQUIRE(!vfdual::is_healthy_host_video_status(
      vfdual::DesktopVideoStepStatus::bridge_failed));
  VFDUAL_TEST_REQUIRE(vfdual::desktop_video_status_for_hybrid_failure(
      vfdual::HybridGpuFatalStage::worker_texture) ==
      vfdual::DesktopVideoStepStatus::bridge_failed);
  VFDUAL_TEST_REQUIRE(vfdual::desktop_video_status_for_hybrid_failure(
      vfdual::HybridGpuFatalStage::encode) ==
      vfdual::DesktopVideoStepStatus::encode_failed);
  vfdual::DesktopVideoStepMetrics serial{};
  serial.status = vfdual::DesktopVideoStepStatus::frame_published;
  VFDUAL_TEST_REQUIRE(vfdual::reconcile_published_frames(7U, serial) == 8U);
  serial.status = vfdual::DesktopVideoStepStatus::capture_timeout;
  VFDUAL_TEST_REQUIRE(vfdual::reconcile_published_frames(8U, serial) == 8U);

  vfdual::DesktopVideoStepMetrics asynchronous{};
  asynchronous.asynchronous_pipeline = true;
  asynchronous.status = vfdual::DesktopVideoStepStatus::frame_queued;
  asynchronous.hybrid_published = 72U;
  VFDUAL_TEST_REQUIRE(
      vfdual::reconcile_published_frames(8U, asynchronous) == 72U);

  // A stale completion record must never regress the authoritative count.
  asynchronous.status = vfdual::DesktopVideoStepStatus::frame_published;
  asynchronous.hybrid_published = 64U;
  asynchronous.hybrid_completion_metrics_dropped = 9U;
  VFDUAL_TEST_REQUIRE(
      vfdual::reconcile_published_frames(72U, asynchronous) == 72U);
  return EXIT_SUCCESS;
}
