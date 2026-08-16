#pragma once

#include "vf/host_pipeline.hpp"

#include <cstdint>
#include <optional>

namespace vf::host::domain {

struct DesktopPoint {
    std::int32_t x{};
    std::int32_t y{};
    friend bool operator==(const DesktopPoint&, const DesktopPoint&) = default;
};

struct NormalizedPoint {
    std::uint16_t x{};
    std::uint16_t y{};
    friend bool operator==(const NormalizedPoint&, const NormalizedPoint&) = default;
};

/** APP 画布内真正显示视频的矩形；排除黑边后才能把触控位置映射到 Host。 */
struct RenderedViewport {
    std::int32_t left{};
    std::int32_t top{};
    std::int32_t width{};
    std::int32_t height{};
};

/**
 * 处理 Windows 虚拟桌面的负坐标、多显示器边界以及 0..65535 绝对 HID 坐标。
 * 所有乘法先提升到 64 位，避免 4K/多屏场景的 int32 溢出。
 */
class VirtualDesktopMapper {
public:
    explicit VirtualDesktopMapper(DesktopBounds desktop);

    [[nodiscard]] std::optional<NormalizedPoint> normalize(DesktopPoint point) const noexcept;
    [[nodiscard]] DesktopPoint denormalize(NormalizedPoint point) const noexcept;

    [[nodiscard]] std::optional<DesktopPoint> viewport_to_desktop(
        DesktopPoint app_point,
        RenderedViewport rendered_video,
        CaptureRegion capture_region) const noexcept;

    [[nodiscard]] const DesktopBounds& desktop() const noexcept { return desktop_; }

private:
    DesktopBounds desktop_;
};

}  // namespace vf::host::domain
