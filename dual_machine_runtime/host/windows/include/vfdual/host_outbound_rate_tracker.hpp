#pragma once

#include <cstdint>
#include <optional>

namespace vfdual {

/**
 * Presentation-only rate sampler for published host video frames.
 *
 * It intentionally has no scheduler interaction: the host continues to
 * publish every available new frame.  The GUI reads this class only to show a
 * stable, time-windowed observed output rate.
 */
class HostOutboundRateTracker final {
public:
    [[nodiscard]] std::optional<double> observe(
        std::uint64_t published_frames, std::uint64_t monotonic_milliseconds) noexcept;
    void reset() noexcept;

private:
    std::uint64_t baseline_published_frames_{};
    std::uint64_t baseline_monotonic_milliseconds_{};
    std::optional<double> last_rate_frames_per_second_;
    bool has_baseline_{};
};

}  // namespace vfdual
