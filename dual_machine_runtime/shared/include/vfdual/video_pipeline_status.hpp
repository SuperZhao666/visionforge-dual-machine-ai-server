#pragma once

#include "vfdual/protocol.hpp"

#include <cstdint>
#include <optional>

namespace vfdual {

enum class VideoPipelinePhase : std::uint8_t {
  stopped,
  starting,
  waiting_for_idr,
  streaming,
  recovering,
  blocked,
  failed,
};

enum class VideoPipelineBlocker : std::uint8_t {
  none,
  authorization,
  capture,
  encoder,
  transport,
  reassembly,
  decoder,
  inference,
  control_output,
};

struct VideoPipelineStatus final {
  VideoPipelinePhase phase{VideoPipelinePhase::stopped};
  VideoPipelineBlocker blocker{VideoPipelineBlocker::none};
  std::uint64_t transition_id{};
  std::uint64_t changed_at_us{};
  std::optional<VideoFrameIdentity> last_complete_frame;
  std::optional<VideoFrameIdentity> last_decoded_frame;

  [[nodiscard]] constexpr bool control_may_open() const noexcept {
    return phase == VideoPipelinePhase::streaming &&
        blocker == VideoPipelineBlocker::none &&
        last_complete_frame.has_value() && last_decoded_frame.has_value() &&
        *last_complete_frame == *last_decoded_frame;
  }
};

class VideoPipelineStateMachine final {
 public:
  [[nodiscard]] const VideoPipelineStatus& status() const noexcept {
    return status_;
  }

  void transition(
      VideoPipelinePhase phase,
      VideoPipelineBlocker blocker,
      std::uint64_t now_us) noexcept {
    if (phase == status_.phase && blocker == status_.blocker) return;
    status_.phase = phase;
    status_.blocker = blocker;
    status_.changed_at_us = now_us;
    ++status_.transition_id;
  }

  void record_complete_frame(VideoFrameIdentity identity) noexcept {
    if (identity.valid()) status_.last_complete_frame = identity;
  }

  void record_decoded_frame(VideoFrameIdentity identity) noexcept {
    if (identity.valid()) status_.last_decoded_frame = identity;
  }

 private:
  VideoPipelineStatus status_{};
};

}  // namespace vfdual
