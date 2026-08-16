#pragma once

#include <cstdint>
#include <limits>
#include <optional>

namespace vfdual::host::domain {

/** Signed virtual-desktop bounds. Windows monitors may live left/above the primary display. */
struct DesktopSpace final {
    std::int32_t left{};
    std::int32_t top{};
    std::int32_t right{};
    std::int32_t bottom{};

    [[nodiscard]] constexpr bool valid() const noexcept {
        return right > left && bottom > top;
    }
};

/**
 * Pure capture-region value object.
 *
 * <p>Creation validates positive size, checked coordinate addition and full
 * containment in the selected desktop space. Platform capture objects never
 * leak into the application or UI layers.</p>
 */
class CaptureRegion final {
public:
    [[nodiscard]] static constexpr std::optional<CaptureRegion> create(
        std::int32_t left, std::int32_t top,
        std::uint32_t width, std::uint32_t height,
        DesktopSpace desktop) noexcept {
        if (!desktop.valid() || width == 0U || height == 0U) return std::nullopt;
        const auto right64 = static_cast<std::int64_t>(left) + width;
        const auto bottom64 = static_cast<std::int64_t>(top) + height;
        if (right64 > (std::numeric_limits<std::int32_t>::max)() ||
            bottom64 > (std::numeric_limits<std::int32_t>::max)()) {
            return std::nullopt;
        }
        const auto right = static_cast<std::int32_t>(right64);
        const auto bottom = static_cast<std::int32_t>(bottom64);
        if (left < desktop.left || top < desktop.top ||
            right > desktop.right || bottom > desktop.bottom) {
            return std::nullopt;
        }
        return CaptureRegion(left, top, width, height);
    }

    [[nodiscard]] constexpr std::int32_t left() const noexcept { return left_; }
    [[nodiscard]] constexpr std::int32_t top() const noexcept { return top_; }
    [[nodiscard]] constexpr std::uint32_t width() const noexcept { return width_; }
    [[nodiscard]] constexpr std::uint32_t height() const noexcept { return height_; }
    [[nodiscard]] constexpr std::int32_t right() const noexcept {
        return static_cast<std::int32_t>(static_cast<std::int64_t>(left_) + width_);
    }
    [[nodiscard]] constexpr std::int32_t bottom() const noexcept {
        return static_cast<std::int32_t>(static_cast<std::int64_t>(top_) + height_);
    }

private:
    constexpr CaptureRegion(
        std::int32_t left, std::int32_t top,
        std::uint32_t width, std::uint32_t height) noexcept
        : left_(left), top_(top), width_(width), height_(height) {}

    std::int32_t left_{};
    std::int32_t top_{};
    std::uint32_t width_{};
    std::uint32_t height_{};
};

}  // namespace vfdual::host::domain
