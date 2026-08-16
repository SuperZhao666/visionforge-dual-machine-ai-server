#pragma once

#include "vfdual/protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace vfdual {

enum class ReceiverEpochDecision : std::uint8_t {
  active,
  candidate,
  retired,
  invalid,
};

/**
 * Receiver-side monotonic epoch gate.
 *
 * <p>The constructor keeps the historic retired-capacity parameter for source
 * compatibility, but the implementation no longer stores a bounded ring.  A
 * bounded ring eventually forgets the oldest session and can let an extremely
 * late UDP packet reclaim the receiver.  The protocol already requires every
 * Host stream epoch to increase, so one monotonic {@code retired_through_}
 * watermark rejects every old session permanently with constant memory.</p>
 *
 * <p>A future epoch remains a candidate until a complete real IDR has passed
 * reassembly and decoder restart.  A lower epoch can never replace a newer
 * candidate, and rejecting a candidate permanently retires it.</p>
 */
class ReceiverEpochSession final {
 public:
  explicit ReceiverEpochSession(std::size_t retired_capacity = 8U) noexcept {
    static_cast<void>(retired_capacity);
  }

  [[nodiscard]] ReceiverEpochDecision observe(
      std::uint64_t stream_epoch) noexcept {
    if (!valid_video_stream_epoch(stream_epoch)) {
      return ReceiverEpochDecision::invalid;
    }
    if (active_epoch_ == stream_epoch) return ReceiverEpochDecision::active;
    if (is_retired(stream_epoch)) return ReceiverEpochDecision::retired;

    if (candidate_epoch_.has_value()) {
      if (*candidate_epoch_ == stream_epoch) {
        return ReceiverEpochDecision::candidate;
      }
      if (stream_epoch < *candidate_epoch_) {
        return ReceiverEpochDecision::retired;
      }
      retire_through(*candidate_epoch_);
    } else if (active_epoch_.has_value() && stream_epoch < *active_epoch_) {
      return ReceiverEpochDecision::retired;
    } else if (!active_epoch_.has_value() && stream_epoch > 1U) {
      // The Host reserves epochs from a persistent monotonic store.  Once a
      // receiver has seen N as its first candidate, every value below N is an
      // already-consumed generation and can be retired immediately.
      retire_through(stream_epoch - 1U);
    }

    candidate_epoch_ = stream_epoch;
    return ReceiverEpochDecision::candidate;
  }

  [[nodiscard]] bool commit_candidate(
      std::uint64_t stream_epoch,
      bool complete_real_idr) noexcept {
    if (!complete_real_idr || candidate_epoch_ != stream_epoch ||
        is_retired(stream_epoch) ||
        (active_epoch_.has_value() && stream_epoch <= *active_epoch_)) {
      return false;
    }
    if (active_epoch_.has_value()) retire_through(*active_epoch_);
    active_epoch_ = stream_epoch;
    candidate_epoch_.reset();
    return true;
  }

  void reject_candidate(std::uint64_t stream_epoch) noexcept {
    if (candidate_epoch_ == stream_epoch) {
      retire_through(stream_epoch);
      candidate_epoch_.reset();
    }
  }

  [[nodiscard]] std::optional<std::uint64_t> active_epoch() const noexcept {
    return active_epoch_;
  }

  [[nodiscard]] std::optional<std::uint64_t> candidate_epoch() const noexcept {
    return candidate_epoch_;
  }

  [[nodiscard]] std::optional<std::uint64_t> retired_through() const noexcept {
    return retired_through_;
  }

  [[nodiscard]] bool is_retired(std::uint64_t stream_epoch) const noexcept {
    return retired_through_.has_value() && stream_epoch <= *retired_through_;
  }

 private:
  void retire_through(std::uint64_t stream_epoch) noexcept {
    if (!valid_video_stream_epoch(stream_epoch)) return;
    if (!retired_through_.has_value() || stream_epoch > *retired_through_) {
      retired_through_ = stream_epoch;
    }
  }

  std::optional<std::uint64_t> active_epoch_;
  std::optional<std::uint64_t> candidate_epoch_;
  std::optional<std::uint64_t> retired_through_;
};

}  // namespace vfdual
