#include "MobileControlCore.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <new>

namespace {

std::atomic<bool> g_count_allocations{false};
std::atomic<std::size_t> g_allocation_count{0U};

vfdual_android::YoloDetection box(
    float center_x, float center_y, float width, float height,
    float confidence, std::uint32_t class_id) {
  return {
      center_x - width * 0.5F,
      center_y - height * 0.5F,
      center_x + width * 0.5F,
      center_y + height * 0.5F,
      confidence,
      class_id,
  };
}

}  // namespace

void* operator new(std::size_t size) {
  if (g_count_allocations.load(std::memory_order_relaxed)) {
    g_allocation_count.fetch_add(1U, std::memory_order_relaxed);
  }
  if (void* allocation = std::malloc(size == 0U ? 1U : size)) {
    return allocation;
  }
  throw std::bad_alloc{};
}

void* operator new[](std::size_t size) {
  return ::operator new(size);
}

void operator delete(void* allocation) noexcept {
  std::free(allocation);
}

void operator delete[](void* allocation) noexcept {
  std::free(allocation);
}

void operator delete(void* allocation, std::size_t) noexcept {
  std::free(allocation);
}

void operator delete[](void* allocation, std::size_t) noexcept {
  std::free(allocation);
}

int main() {
  vfdual_android::MobileControlConfig config{};
  config.motion.prediction_horizon_ms = 0.0F;
  // Force a fresh monotonically increasing track id on every observation.
  // Identity history must remain allocation-free and bounded even when a
  // detector repeatedly loses and recreates the same physical target.
  config.tracker.lost_track_duration_us = 1U;
  vfdual_android::MobileControlCore core(config);
  const std::array detections{
      box(260.0F, 140.0F, 24.0F, 24.0F, 0.95F,
          config.head_class_id),
      box(260.0F, 220.0F, 80.0F, 180.0F, 0.95F,
          config.body_class_id),
  };

  std::uint64_t sequence = 1U;
  std::uint64_t observed_at_us = 100'000U;
  for (int index = 0; index < 16; ++index) {
    const auto output = core.process(
        detections, {sequence++, observed_at_us, observed_at_us});
    assert(output.has_target);
    observed_at_us += 6'667U;
  }

  g_allocation_count.store(0U, std::memory_order_relaxed);
  g_count_allocations.store(true, std::memory_order_relaxed);
  constexpr int kMeasuredFrames = 200;
  for (int index = 0; index < kMeasuredFrames; ++index) {
    const auto output = core.process(
        detections, {sequence++, observed_at_us, observed_at_us});
    assert(output.has_target);
    observed_at_us += 6'667U;
  }
  g_count_allocations.store(false, std::memory_order_relaxed);

  assert(g_allocation_count.load(std::memory_order_relaxed) == 0U);
  assert(core.tracker_metrics().tracks_created >=
         static_cast<std::uint64_t>(kMeasuredFrames));
  return 0;
}
