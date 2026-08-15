#pragma once

#include <cstdint>

namespace vfdual_android {

/**
 * A QNN result belongs to the active stream only while all generation guards
 * still match at the exact state-commit boundary.  Checking only before QNN is
 * insufficient because an HTP execution may finish after decoder recovery.
 */
[[nodiscard]] constexpr bool inference_result_can_commit(
    std::uint64_t frame_generation, std::uint64_t active_generation,
    bool restart_in_progress, bool decoder_failed) noexcept {
  return frame_generation != 0U && frame_generation == active_generation &&
      !restart_in_progress && !decoder_failed;
}

}  // namespace vfdual_android
