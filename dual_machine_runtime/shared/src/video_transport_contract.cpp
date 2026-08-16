#include "vfdual/video_transport_contract.hpp"

#include <algorithm>

namespace vfdual {

VideoEpochCoordinator::VideoEpochCoordinator(std::size_t retired_capacity) noexcept
    : retired_capacity_((std::max)(std::size_t{1U}, retired_capacity)) {}

VideoEpochObservation VideoEpochCoordinator::observe(
    std::uint64_t stream_epoch) noexcept {
  if (!valid_video_stream_epoch(stream_epoch)) {
    return VideoEpochObservation::invalid;
  }
  if (active_epoch_ == stream_epoch) return VideoEpochObservation::active;
  if (is_retired(stream_epoch)) return VideoEpochObservation::retired;
  if (candidate_epoch_ == stream_epoch) return VideoEpochObservation::candidate;

  const bool replaced = candidate_epoch_.has_value();
  if (candidate_epoch_.has_value()) retire(*candidate_epoch_);
  candidate_epoch_ = stream_epoch;
  return replaced ? VideoEpochObservation::candidate_replaced
                  : VideoEpochObservation::candidate;
}

bool VideoEpochCoordinator::commit_candidate(
    std::uint64_t stream_epoch) noexcept {
  if (!candidate_epoch_.has_value() || *candidate_epoch_ != stream_epoch ||
      is_retired(stream_epoch)) {
    return false;
  }
  if (active_epoch_.has_value() && *active_epoch_ != stream_epoch) {
    retire(*active_epoch_);
  }
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
  active_epoch_.reset();
  candidate_epoch_.reset();
  retired_epochs_.clear();
}

std::optional<std::uint64_t> VideoEpochCoordinator::active_epoch() const noexcept {
  return active_epoch_;
}

std::optional<std::uint64_t> VideoEpochCoordinator::candidate_epoch() const noexcept {
  return candidate_epoch_;
}

bool VideoEpochCoordinator::is_retired(std::uint64_t stream_epoch) const noexcept {
  return std::find(retired_epochs_.begin(), retired_epochs_.end(), stream_epoch) !=
      retired_epochs_.end();
}

std::size_t VideoEpochCoordinator::retired_count() const noexcept {
  return retired_epochs_.size();
}

void VideoEpochCoordinator::retire(std::uint64_t stream_epoch) noexcept {
  if (!valid_video_stream_epoch(stream_epoch) || is_retired(stream_epoch)) return;
  retired_epochs_.push_back(stream_epoch);
  while (retired_epochs_.size() > retired_capacity_) retired_epochs_.pop_front();
}

}  // namespace vfdual
