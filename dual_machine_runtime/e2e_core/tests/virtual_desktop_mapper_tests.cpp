#include "test_support.hpp"
#include "vf/host/domain/virtual_desktop_mapper.hpp"

#include <exception>
#include <iostream>

namespace {
using vf::CaptureRegion;
using vf::DesktopBounds;
using vf::host::domain::DesktopPoint;
using vf::host::domain::NormalizedPoint;
using vf::host::domain::RenderedViewport;
using vf::host::domain::VirtualDesktopMapper;
using vf::test::expect;

void run() {
    const DesktopBounds desktop{-1920, -1080, 5760, 2160};
    VirtualDesktopMapper mapper(desktop);

    expect(mapper.normalize({-1920, -1080}) == NormalizedPoint{0, 0},
           "negative virtual-desktop origin did not normalize to zero");
    expect(mapper.normalize({3839, 1079}) == NormalizedPoint{65535, 65535},
           "virtual-desktop inclusive endpoint did not normalize to HID maximum");
    expect(!mapper.normalize({3840, 1080}), "point outside virtual desktop was accepted");

    const auto roundtrip = mapper.denormalize(*mapper.normalize({-100, 500}));
    expect(roundtrip.x == -100 && roundtrip.y == 500,
           "HID normalization roundtrip drifted by more than integer rounding contract");

    const CaptureRegion capture{-1920, 0, 1920, 1080};
    const RenderedViewport viewport{100, 200, 960, 540};
    expect(mapper.viewport_to_desktop({100, 200}, viewport, capture) ==
               DesktopPoint{-1920, 0},
           "viewport top-left did not map to capture top-left");
    expect(mapper.viewport_to_desktop({1059, 739}, viewport, capture) ==
               DesktopPoint{-1, 1079},
           "viewport bottom-right did not map to capture bottom-right");
    expect(!mapper.viewport_to_desktop({99, 200}, viewport, capture),
           "black-bar/outside point was mapped into desktop control coordinates");
}
}  // namespace

int main() {
    try {
        run();
        std::cout << "VIRTUAL_DESKTOP_MAPPER_TESTS_OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "VIRTUAL_DESKTOP_MAPPER_TESTS_FAILED: " << error.what() << '\n';
        return 1;
    }
}
