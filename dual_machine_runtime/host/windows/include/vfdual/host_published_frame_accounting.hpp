#pragma once

#include "vfdual/desktop_video_agent.hpp"

#include <cstdint>

namespace vfdual {

/**
 * Reconciles host publish statistics with the transport's authoritative count.
 *
 * Serial paths report one completed frame at a time. The asynchronous path
 * reports a monotonic worker counter because its bounded diagnostic ring may
 * intentionally discard old metric records without discarding UDP packets.
 */
[[nodiscard]] inline std::uint64_t reconcile_published_frames(
    std::uint64_t current,
    const DesktopVideoStepMetrics& metrics) noexcept {
  if (metrics.asynchronous_pipeline) {
    return metrics.hybrid_published > current
        ? metrics.hybrid_published
        : current;
  }
  return current +
      (metrics.status == DesktopVideoStepStatus::frame_published ? 1U : 0U);
}

}  // namespace vfdual
