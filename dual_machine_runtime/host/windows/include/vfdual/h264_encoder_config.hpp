#pragma once

#include <cstdint>

namespace vfdual {

/** Used only when Windows cannot report the selected display refresh rate. */
inline constexpr std::uint32_t kFallbackEncoderTimingHintFramesPerSecond = 60U;

/**
 * Derives codec timestamps and idle-repeat timing from the real display source.
 * Deliberately has no upper clamp: fresh capture frames remain event-driven and
 * a high-refresh display must not be folded back to an arbitrary software FPS.
 */
[[nodiscard]] constexpr std::uint32_t encoder_timing_hint_for_display_refresh(
    std::uint32_t display_refresh_hz) noexcept {
    return display_refresh_hz == 0U
        ? kFallbackEncoderTimingHintFramesPerSecond
        : display_refresh_hz;
}

/** Codec-neutral H.264 timing and picture contract. */
struct H264EncoderConfig {
    std::uint32_t width{};
    std::uint32_t height{};
    /** Bitstream timing hint; never a capture or publication scheduler. */
    std::uint32_t frames_per_second{60};
    std::uint32_t keyframe_interval_frames{60};
};

}  // namespace vfdual
