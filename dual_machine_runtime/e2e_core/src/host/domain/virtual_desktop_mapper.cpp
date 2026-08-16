#include "vf/host/domain/virtual_desktop_mapper.hpp"

#include <algorithm>
#include <cstdint>
#include <stdexcept>

namespace vf::host::domain {
namespace {

constexpr std::int64_t kNormalizedMax = 65'535;

bool point_in_rect(DesktopPoint point, std::int32_t left, std::int32_t top,
                   std::int32_t width, std::int32_t height) noexcept {
    if (width <= 0 || height <= 0) {
        return false;
    }
    const auto right = static_cast<std::int64_t>(left) + width;
    const auto bottom = static_cast<std::int64_t>(top) + height;
    return point.x >= left && point.y >= top &&
        static_cast<std::int64_t>(point.x) < right &&
        static_cast<std::int64_t>(point.y) < bottom;
}

std::uint16_t normalize_axis(std::int32_t value, std::int32_t origin, std::int32_t length) noexcept {
    if (length <= 1) {
        return 0;
    }
    const auto offset = static_cast<std::int64_t>(value) - origin;
    const auto numerator = offset * kNormalizedMax + (length - 1) / 2;
    return static_cast<std::uint16_t>(numerator / (length - 1));
}

std::int32_t denormalize_axis(std::uint16_t value, std::int32_t origin, std::int32_t length) noexcept {
    if (length <= 1) {
        return origin;
    }
    const auto numerator = static_cast<std::int64_t>(value) * (length - 1) + kNormalizedMax / 2;
    return static_cast<std::int32_t>(static_cast<std::int64_t>(origin) + numerator / kNormalizedMax);
}

std::int32_t map_axis(std::int32_t value, std::int32_t view_origin, std::int32_t view_length,
                      std::int32_t capture_origin, std::int32_t capture_length) noexcept {
    if (view_length <= 1 || capture_length <= 1) {
        return capture_origin;
    }
    const auto offset = static_cast<std::int64_t>(value) - view_origin;
    const auto numerator = offset * (capture_length - 1) + (view_length - 1) / 2;
    return static_cast<std::int32_t>(static_cast<std::int64_t>(capture_origin) +
                                     numerator / (view_length - 1));
}

}  // namespace

VirtualDesktopMapper::VirtualDesktopMapper(DesktopBounds desktop) : desktop_(desktop) {
    if (desktop_.width <= 0 || desktop_.height <= 0) {
        throw std::invalid_argument("virtual desktop dimensions must be positive");
    }
}

std::optional<NormalizedPoint> VirtualDesktopMapper::normalize(DesktopPoint point) const noexcept {
    if (!point_in_rect(point, desktop_.left, desktop_.top, desktop_.width, desktop_.height)) {
        return std::nullopt;
    }
    return NormalizedPoint{
        .x = normalize_axis(point.x, desktop_.left, desktop_.width),
        .y = normalize_axis(point.y, desktop_.top, desktop_.height),
    };
}

DesktopPoint VirtualDesktopMapper::denormalize(NormalizedPoint point) const noexcept {
    return {
        .x = denormalize_axis(point.x, desktop_.left, desktop_.width),
        .y = denormalize_axis(point.y, desktop_.top, desktop_.height),
    };
}

std::optional<DesktopPoint> VirtualDesktopMapper::viewport_to_desktop(
    DesktopPoint app_point,
    RenderedViewport rendered_video,
    CaptureRegion capture_region) const noexcept {
    if (!capture_region.valid_within(desktop_) ||
        !point_in_rect(app_point, rendered_video.left, rendered_video.top,
                       rendered_video.width, rendered_video.height)) {
        return std::nullopt;
    }
    DesktopPoint mapped{
        .x = map_axis(app_point.x, rendered_video.left, rendered_video.width,
                      capture_region.left, capture_region.width),
        .y = map_axis(app_point.y, rendered_video.top, rendered_video.height,
                      capture_region.top, capture_region.height),
    };
    if (!point_in_rect(mapped, capture_region.left, capture_region.top,
                       capture_region.width, capture_region.height)) {
        return std::nullopt;
    }
    return mapped;
}

}  // namespace vf::host::domain
