#include "vfdual/video_transport_contract.hpp"

namespace vfdual {

VideoEpochCoordinator::VideoEpochCoordinator(std::size_t retired_capacity) noexcept {
  // Retained only for source/configuration compatibility. Constant-memory
  // monotonic retirement is independent of a history capacity.
  static_cast<void>(retired_capacity);
}

VideoEpochObservation VideoEpochCoordinator::observe(
    std::uint64_t stream_epoch) noexcept {
  if (!valid_video_stream_epoch(stream_epoch)) {
    return VideoEpochObservation::invalid;
  }
  if (active_epoch_ == stream_epoch) return VideoEpochObservation::active;
  if (is_retired(stream_epoch)) return VideoEpochObservation::retired;

  if (candidate_epoch_.has_value()) {
    if (*candidate_epoch_ == stream_epoch) {
      return VideoEpochObservation::candidate;
    }
    if (stream_epoch < *candidate_epoch_) {
      return VideoEpochObservation::retired;
    }
    retire(*candidate_epoch_);
    candidate_epoch_ = stream_epoch;
    return VideoEpochObservation::candidate_replaced;
  }

  if (active_epoch_.has_value() && stream_epoch < *active_epoch_) {
    return VideoEpochObservation::retired;
  }
  if (!active_epoch_.has_value() && stream_epoch > 1U) {
    retire(stream_epoch - 1U);
  }
  candidate_epoch_ = stream_epoch;
  return VideoEpochObservation::candidate;
}

bool VideoEpochCoordinator::commit_candidate(
    std::uint64_t stream_epoch) noexcept {
  if (!candidate_epoch_.has_value() || *candidate_epoch_ != stream_epoch ||
      is_retired(stream_epoch) ||
      (active_epoch_.has_value() && stream_epoch <= *active_epoch_)) {
    return false;
  }
  if (active_epoch_.has_value()) retire(*active_epoch_);
  active_epoch_ = stream_epoch;
  candidate_epoch_.reset();
  return true;
}

void VideoEpochCoordinator::reject_candidate(
    std::uint64_t stream_epoch) noexcept {
  if (candidate_epoch_ == stream_epoch) {
    retire(stream_epoch);
    candidate_epoch_.reset();
  }
}

void VideoEpochCoordinator::reset() noexcept {
  // Full trust-boundary reset. Ordinary decoder/runtime recovery must keep the
  // coordinator instance alive so retired epochs remain permanently blocked.
  active_epoch_.reset();
  candidate_epoch_.reset();
  retired_through_.reset();
  retirement_advances_ = 0U;
}

std::optional<std::uint64_t> VideoEpochCoordinator::active_epoch() const noexcept {
  return active_epoch_;
}

std::optional<std::uint64_t> VideoEpochCoordinator::candidate_epoch() const noexcept {
  return candidate_epoch_;
}

std::optional<std::uint64_t> VideoEpochCoordinator::retired_through() const noexcept {
  return retired_through_;
}

bool VideoEpochCoordinator::is_retired(std::uint64_t stream_epoch) const noexcept {
  return retired_through_.has_value() && stream_epoch <= *retired_through_;
}

std::size_t VideoEpochCoordinator::retired_count() const noexcept {
  return retirement_advances_;
}

void VideoEpochCoordinator::retire(std::uint64_t stream_epoch) noexcept {
  if (!valid_video_stream_epoch(stream_epoch)) return;
  if (!retired_through_.has_value() || stream_epoch > *retired_through_) {
    retired_through_ = stream_epoch;
    ++retirement_advances_;
  }
}

}  // namespace vfdual
