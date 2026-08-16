#pragma once

#include "vfdual/protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>

namespace vfdual_android {

struct DecodedFrameMetadata final {
  vfdual::VideoFrameIdentity identity{};
  std::uint64_t decoder_generation{};
  std::uint64_t decoded_at_us{};
  bool real_content{};
};

/**
 * Bounded metadata bridge between asynchronous MediaCodec callbacks and the
 * control gate. Old generations and repeated-content frames can never become
 * the freshness proof for a newly issued control ticket.
 */
class DecodedFrameMetadataLedger final {
 public:
  explicit DecodedFrameMetadataLedger(std::size_t capacity = 64U) noexcept
      : capacity_(capacity == 0U ? 1U : capacity) {}

  void begin_generation(std::uint64_t generation) noexcept {
    if (generation <= generation_) return;
    generation_ = generation;
    entries_.clear();
  }

  [[nodiscard]] bool record(DecodedFrameMetadata metadata) noexcept {
    if (!metadata.identity.valid() ||
        metadata.decoder_generation != generation_) {
      return false;
    }
    if (!entries_.empty() &&
        entries_.back().identity.stream_epoch == metadata.identity.stream_epoch &&
        metadata.identity.frame_sequence <=
            entries_.back().identity.frame_sequence) {
      return false;
    }
    entries_.push_back(metadata);
    while (entries_.size() > capacity_) entries_.pop_front();
    return true;
  }

  [[nodiscard]] std::optional<DecodedFrameMetadata> latest_real() const noexcept {
    for (auto iterator = entries_.rbegin(); iterator != entries_.rend(); ++iterator) {
      if (iterator->real_content) return *iterator;
    }
    return std::nullopt;
  }

  [[nodiscard]] bool visible_after(
      vfdual::VideoFrameIdentity required,
      std::uint64_t issued_at_us) const noexcept {
    for (auto iterator = entries_.rbegin(); iterator != entries_.rend(); ++iterator) {
      if (!iterator->real_content || iterator->decoded_at_us < issued_at_us) continue;
      if (iterator->identity.stream_epoch != required.stream_epoch) continue;
      return iterator->identity.frame_sequence >= required.frame_sequence;
    }
    return false;
  }

  [[nodiscard]] std::uint64_t generation() const noexcept { return generation_; }
  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }

 private:
  std::size_t capacity_{};
  std::uint64_t generation_{};
  std::deque<DecodedFrameMetadata> entries_;
};

}  // namespace vfdual_android
