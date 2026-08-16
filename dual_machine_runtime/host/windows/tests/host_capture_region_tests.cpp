#include "vfdual/host/domain/capture_region.hpp"

#include <cassert>
#include <cstdint>
#include <limits>

int main() {
    using vfdual::host::domain::CaptureRegion;
    using vfdual::host::domain::DesktopSpace;

    constexpr DesktopSpace virtual_desktop{-1920, -1080, 3840, 2160};
    const auto left_monitor = CaptureRegion::create(-1920, 0, 1920, 1080, virtual_desktop);
    assert(left_monitor.has_value());
    assert(left_monitor->left() == -1920 && left_monitor->right() == 0);

    assert(!CaptureRegion::create(-1921, 0, 1920, 1080, virtual_desktop));
    assert(!CaptureRegion::create(0, 0, 0, 1080, virtual_desktop));
    assert(!CaptureRegion::create(
        (std::numeric_limits<std::int32_t>::max)() - 2, 0, 10, 10,
        DesktopSpace{0, 0, (std::numeric_limits<std::int32_t>::max)(), 100}));
    assert(!CaptureRegion::create(0, 0, 10, 10, DesktopSpace{}));
    return 0;
}
