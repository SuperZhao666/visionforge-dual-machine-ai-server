#include "vfdual/host_outbound_rate_tracker.hpp"

namespace vfdual {
namespace {
constexpr std::uint64_t kSamplingWindowMilliseconds = 1'000U;
}

std::optional<double> HostOutboundRateTracker::observe(
    std::uint64_t published_frames, std::uint64_t monotonic_milliseconds) noexcept {
    if (!has_baseline_ || published_frames < baseline_published_frames_ ||
        monotonic_milliseconds < baseline_monotonic_milliseconds_) {
        baseline_published_frames_ = published_frames;
        baseline_monotonic_milliseconds_ = monotonic_milliseconds;
        has_baseline_ = true;
        last_rate_frames_per_second_.reset();
        return std::nullopt;
    }
    const std::uint64_t elapsed = monotonic_milliseconds - baseline_monotonic_milliseconds_;
    if (elapsed < kSamplingWindowMilliseconds) return last_rate_frames_per_second_;
    const std::uint64_t published_delta = published_frames - baseline_published_frames_;
    last_rate_frames_per_second_ = 1'000.0 * static_cast<double>(published_delta) / static_cast<double>(elapsed);
    baseline_published_frames_ = published_frames;
    baseline_monotonic_milliseconds_ = monotonic_milliseconds;
    return last_rate_frames_per_second_;
}

void HostOutboundRateTracker::reset() noexcept {
    baseline_published_frames_ = 0;
    baseline_monotonic_milliseconds_ = 0;
    last_rate_frames_per_second_.reset();
    has_baseline_ = false;
}

}  // namespace vfdual
