#pragma once

#include <cstdint>

namespace vfdual {

struct FrameScaleExtent final {
    std::uint32_t width{};
    std::uint32_t height{};
};

/** Fits a source extent inside a target without floating-point edge drift. */
[[nodiscard]] constexpr FrameScaleExtent fit_frame_extent(
    std::uint32_t source_width, std::uint32_t source_height,
    std::uint32_t target_width, std::uint32_t target_height) noexcept {
    if (source_width == 0U || source_height == 0U ||
        target_width == 0U || target_height == 0U) {
        return {};
    }
    if (static_cast<std::uint64_t>(source_width) * target_height >=
        static_cast<std::uint64_t>(source_height) * target_width) {
        const std::uint64_t scaled =
            static_cast<std::uint64_t>(source_height) * target_width /
            source_width;
        return {target_width, static_cast<std::uint32_t>(scaled == 0U ? 1U : scaled)};
    }
    const std::uint64_t scaled =
        static_cast<std::uint64_t>(source_width) * target_height /
        source_height;
    return {static_cast<std::uint32_t>(scaled == 0U ? 1U : scaled), target_height};
}

}  // namespace vfdual
