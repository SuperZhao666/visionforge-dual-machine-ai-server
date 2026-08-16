#include "ReceiverRecoveryPolicy.hpp"

#include <algorithm>

namespace vfdual_android {
namespace {
constexpr std::uint64_t kIncompleteStreamStallUs = 150'000;
constexpr std::uint64_t kSilentStreamStallUs = 300'000;
constexpr std::uint64_t kMinimumIdrRequestIntervalUs = 500'000;
constexpr std::uint64_t kMaximumIdrRequestIntervalUs = 5'000'000;
constexpr std::uint32_t kMaximumConsecutiveIdleIdrRequests = 4;
}

bool ReceiverRecoveryPolicy::observe_fragment(std::uint64_t now_us, bool fresh_content_accepted,
                                              bool source_changed,
                                              bool reassembly_expired) noexcept {
  consecutive_idle_idr_requests_ = 0U;
  if (first_fragment_us_ == 0U) first_fragment_us_ = now_us;
  last_fragment_us_ = now_us;
  if (fresh_content_accepted) {
    last_completed_us_ = now_us;
    last_idr_request_us_ = 0U;
    consecutive_idr_requests_ = 0U;
  }
  const std::uint64_t progress_reference = last_completed_us_ == 0U
      ? first_fragment_us_ : last_completed_us_;
  const bool stalled = now_us >= progress_reference &&
      now_us - progress_reference >= kIncompleteStreamStallUs;
  return (source_changed || reassembly_expired || stalled) && request_due(now_us);
}

bool ReceiverRecoveryPolicy::observe_idle(std::uint64_t now_us, bool sender_known) noexcept {
  if (!sender_known || last_fragment_us_ == 0U || now_us < last_fragment_us_ ||
      consecutive_idle_idr_requests_ >= kMaximumConsecutiveIdleIdrRequests) {
    return false;
  }
  return now_us - last_fragment_us_ >= kSilentStreamStallUs && request_due(now_us);
}

void ReceiverRecoveryPolicy::mark_idr_requested(std::uint64_t now_us) noexcept {
  last_idr_request_us_ = now_us;
  ++consecutive_idr_requests_;
}

void ReceiverRecoveryPolicy::mark_idle_idr_requested(std::uint64_t now_us) noexcept {
  mark_idr_requested(now_us);
  ++consecutive_idle_idr_requests_;
}

void ReceiverRecoveryPolicy::reset() noexcept {
  first_fragment_us_ = 0U;
  last_fragment_us_ = 0U;
  last_completed_us_ = 0U;
  last_idr_request_us_ = 0U;
  consecutive_idr_requests_ = 0U;
  consecutive_idle_idr_requests_ = 0U;
}

bool ReceiverRecoveryPolicy::request_due(std::uint64_t now_us) const noexcept {
  const std::uint32_t shift = consecutive_idr_requests_ == 0U
      ? 0U : std::min(consecutive_idr_requests_ - 1U, 4U);
  const std::uint64_t interval = std::min(
      kMinimumIdrRequestIntervalUs << shift, kMaximumIdrRequestIntervalUs);
  return last_idr_request_us_ == 0U ||
      (now_us >= last_idr_request_us_ &&
       now_us - last_idr_request_us_ >= interval);
}

}  // namespace vfdual_android
