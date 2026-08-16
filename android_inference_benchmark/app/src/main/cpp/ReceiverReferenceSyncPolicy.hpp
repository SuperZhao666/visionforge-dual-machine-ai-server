#pragma once

#include <cstdint>
#include <optional>

#include "vfdual/protocol.hpp"

namespace vfdual_android {

enum class ReceiverReferenceDecision : std::uint8_t {
  admit,
  reject_awaiting_idr,
  reject_sequence_gap,
};

/**
 * Protects MediaCodec's predictive H.264 reference chain independently of
 * render/inference frame dropping. No rate policy exists here: every
 * consecutive access unit is admitted as soon as it is reassembled.
 */
class ReceiverReferenceSyncPolicy final {
public:
  [[nodiscard]] ReceiverReferenceDecision evaluate(
      std::uint32_t logical_frame_sequence, bool is_idr) const noexcept {
    if (is_idr) return ReceiverReferenceDecision::admit;
    if (awaiting_idr_) {
      return ReceiverReferenceDecision::reject_awaiting_idr;
    }
    std::uint32_t expected{};
    if (!last_accepted_sequence_.has_value() ||
        !vfdual::advance_video_frame_sequence(
            *last_accepted_sequence_, expected) ||
        logical_frame_sequence != expected) {
      return ReceiverReferenceDecision::reject_sequence_gap;
    }
    return ReceiverReferenceDecision::admit;
  }

  void record_submit(
      std::uint32_t logical_frame_sequence, bool accepted) noexcept {
    if (!accepted) {
      require_idr();
      return;
    }
    awaiting_idr_ = false;
    last_accepted_sequence_ = logical_frame_sequence;
  }

  void require_idr() noexcept {
    awaiting_idr_ = true;
    last_accepted_sequence_.reset();
  }

  void reset() noexcept { require_idr(); }

  [[nodiscard]] bool awaiting_idr() const noexcept { return awaiting_idr_; }

private:
  bool awaiting_idr_{true};
  std::optional<std::uint32_t> last_accepted_sequence_;
};

}  // namespace vfdual_android
