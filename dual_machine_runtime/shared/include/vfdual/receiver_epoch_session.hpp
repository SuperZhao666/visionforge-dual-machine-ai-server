#pragma once

#include "vfdual/protocol.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>

namespace vfdual {

enum class ReceiverEpochDecision : std::uint8_t {
  active,
  candidate,
  retired,
  invalid,
};

/**
 * Separates candidate epoch discovery from commit. A future Host session does
 * not become active merely because one UDP fragment arrived.
 */
class ReceiverEpochSession final {
 public:
  explicit ReceiverEpochSession(std::size_t retired_capacity = 8U) noexcept
      : retired_capacity_(std::max<std::size_t>(1U, retired_capacity)) {}

  [[nodiscard]] ReceiverEpochDecision observe(
      std::uint64_t stream_epoch) noexcept {
    if (stream_epoch == 0U || stream_epoch > kVideoStreamEpochMax) {
      return ReceiverEpochDecision::invalid;
    }
    if (active_epoch_ == stream_epoch) return ReceiverEpochDecision::active;
    if (is_retired(stream_epoch)) return ReceiverEpochDecision::retired;
    if (candidate_epoch_.has_value() && *candidate_epoch_ != stream_epoch) {
      remember_retired(*candidate_epoch_);
    }
    candidate_epoch_ = stream_epoch;
    return ReceiverEpochDecision::candidate;
  }

  [[nodiscard]] bool commit_candidate(
      std::uint64_t stream_epoch,
      bool complete_real_idr) noexcept {
    if (!complete_real_idr || candidate_epoch_ != stream_epoch ||
        is_retired(stream_epoch)) {
      return false;
    }
    if (active_epoch_.has_value()) remember_retired(*active_epoch_);
    active_epoch_ = stream_epoch;
    candidate_epoch_.reset();
    return true;
  }

  void reject_candidate(std::uint64_t stream_epoch) noexcept {
    if (candidate_epoch_ == stream_epoch) {
      remember_retired(stream_epoch);
      candidate_epoch_.reset();
    }
  }

  [[nodiscard]] std::optional<std::uint64_t> active_epoch() const noexcept {
    return active_epoch_;
  }

  [[nodiscard]] std::optional<std::uint64_t> candidate_epoch() const noexcept {
    return candidate_epoch_;
  }

  [[nodiscard]] bool is_retired(std::uint64_t stream_epoch) const noexcept {
    return std::find(retired_.begin(), retired_.end(), stream_epoch) !=
        retired_.end();
  }

 private:
  void remember_retired(std::uint64_t stream_epoch) noexcept {
    if (is_retired(stream_epoch)) return;
    retired_.push_back(stream_epoch);
    while (retired_.size() > retired_capacity_) retired_.pop_front();
  }

  std::size_t retired_capacity_{};
  std::optional<std::uint64_t> active_epoch_;
  std::optional<std::uint64_t> candidate_epoch_;
  std::deque<std::uint64_t> retired_;
};

}  // namespace vfdual
