#include "vfdual/host_window_layout.hpp"

#include <algorithm>
#include <cmath>

namespace vfdual {
namespace {

double fitting_scale(int client_width, int client_height) noexcept {
    const double width_scale = static_cast<double>((std::max)(1, client_width)) /
                               kHostLogicalClientWidth;
    const double height_scale = static_cast<double>((std::max)(1, client_height)) /
                                kHostLogicalClientHeight;
    return (std::min)({width_scale, height_scale, kHostMaximumLayoutScale});
}

}  // namespace

HostClientSize host_minimum_readable_client_size() noexcept {
    return HostClientSize{
        static_cast<int>(std::ceil(kHostLogicalClientWidth * kHostMinimumReadableScale)),
        static_cast<int>(std::ceil(kHostLogicalClientHeight * kHostMinimumReadableScale)),
    };
}

HostWindowLayout host_window_layout_for_client(int client_width, int client_height) noexcept {
    const int safe_width = (std::max)(1, client_width);
    const int safe_height = (std::max)(1, client_height);
    const double scale = fitting_scale(safe_width, safe_height);
    return HostWindowLayout{
        scale,
        static_cast<int>(std::lround((safe_width - kHostLogicalClientWidth * scale) / 2.0)),
        static_cast<int>(std::lround((safe_height - kHostLogicalClientHeight * scale) / 2.0)),
    };
}

HostClientSize host_initial_client_size(
    int maximum_client_width, int maximum_client_height, unsigned int dpi) noexcept {
    const double requested_scale = static_cast<double>(dpi == 0U ? 96U : dpi) / 96.0;
    const double scale = (std::min)(requested_scale,
                                    fitting_scale(maximum_client_width, maximum_client_height));
    return HostClientSize{
        static_cast<int>(std::lround(kHostLogicalClientWidth * scale)),
        static_cast<int>(std::lround(kHostLogicalClientHeight * scale)),
    };
}

}  // namespace vfdual
