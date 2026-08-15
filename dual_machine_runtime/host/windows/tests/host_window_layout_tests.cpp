#include "vfdual/host_window_layout.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed: %s (%s:%d)\n", expression, file, line);
    std::exit(EXIT_FAILURE);
}

#define VFDUAL_TEST_REQUIRE(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

bool near(double left, double right) noexcept {
    return std::abs(left - right) < 0.0001;
}

void require_layout_fits(int width, int height) {
    const auto layout = vfdual::host_window_layout_for_client(width, height);
    const int right = layout.offset_x + static_cast<int>(
        std::lround(vfdual::kHostLogicalClientWidth * layout.scale));
    const int bottom = layout.offset_y + static_cast<int>(
        std::lround(vfdual::kHostLogicalClientHeight * layout.scale));
    VFDUAL_TEST_REQUIRE(layout.offset_x >= 0);
    VFDUAL_TEST_REQUIRE(layout.offset_y >= 0);
    VFDUAL_TEST_REQUIRE(right <= width);
    VFDUAL_TEST_REQUIRE(bottom <= height);
}

int right(const vfdual::HostLogicalRect& rectangle) noexcept {
    return rectangle.x + rectangle.width;
}

int scaled_width(const vfdual::HostLogicalRect& rectangle, double scale) noexcept {
    return static_cast<int>(std::lround(rectangle.width * scale));
}

}  // namespace

int main() {
    const auto minimum = vfdual::host_minimum_readable_client_size();
    VFDUAL_TEST_REQUIRE(minimum.width == 893);
    VFDUAL_TEST_REQUIRE(minimum.height == 620);

    const unsigned int dpis[] = {96U, 120U, 144U, 192U};
    const double expected_scales[] = {1.0, 1.25, 1.5, 2.0};
    for (int index = 0; index < 4; ++index) {
        const auto initial = vfdual::host_initial_client_size(4000, 3000, dpis[index]);
        VFDUAL_TEST_REQUIRE(initial.width == static_cast<int>(
            std::lround(vfdual::kHostLogicalClientWidth * expected_scales[index])));
        VFDUAL_TEST_REQUIRE(initial.height == static_cast<int>(
            std::lround(vfdual::kHostLogicalClientHeight * expected_scales[index])));
        const auto layout = vfdual::host_window_layout_for_client(initial.width, initial.height);
        VFDUAL_TEST_REQUIRE(near(layout.scale, expected_scales[index]));
        require_layout_fits(initial.width, initial.height);
    }

    const auto readable = vfdual::host_window_layout_for_client(minimum.width, minimum.height);
    VFDUAL_TEST_REQUIRE(readable.scale >= vfdual::kHostMinimumReadableScale);
    require_layout_fits(minimum.width, minimum.height);

    for (const unsigned int dpi : dpis) {
        const auto constrained = vfdual::host_initial_client_size(800, 500, dpi);
        VFDUAL_TEST_REQUIRE(constrained.width <= 800);
        VFDUAL_TEST_REQUIRE(constrained.height <= 500);
        VFDUAL_TEST_REQUIRE(constrained.width == 721);
        VFDUAL_TEST_REQUIRE(constrained.height == 500);
    }

    const auto small = vfdual::host_window_layout_for_client(640, 400);
    VFDUAL_TEST_REQUIRE(small.scale < vfdual::kHostMinimumReadableScale);
    require_layout_fits(640, 400);
    require_layout_fits(1, 1);

    // The status dot is parent-drawn. It must remain outside the child STATIC
    // rectangle or WS_CLIPCHILDREN will clip it from the finished header.
    VFDUAL_TEST_REQUIRE(right(vfdual::kHostHeaderStatusDot) <=
                         vfdual::kHostHeaderStatusText.x);

    // The compact output/probe/P95 columns must remain disjoint even at the
    // minimum readable scale. This guards the former "-- FPS / probe" overlap.
    VFDUAL_TEST_REQUIRE(right(vfdual::kHostSummaryOutputValue) + 12 <=
                         vfdual::kHostSummaryProbeValue.x);
    VFDUAL_TEST_REQUIRE(right(vfdual::kHostSummaryProbeValue) + 12 <=
                         vfdual::kHostSummaryP95Value.x);
    VFDUAL_TEST_REQUIRE(right(vfdual::kHostSummaryP95Value) <= 1196);
    VFDUAL_TEST_REQUIRE(scaled_width(
        vfdual::kHostSummaryOutputValue, vfdual::kHostMinimumReadableScale) >= 86);
    VFDUAL_TEST_REQUIRE(scaled_width(
        vfdual::kHostSummaryProbeValue, vfdual::kHostMinimumReadableScale) >= 86);
    VFDUAL_TEST_REQUIRE(scaled_width(
        vfdual::kHostSummaryP95Value, vfdual::kHostMinimumReadableScale) >= 115);
    return 0;
}
