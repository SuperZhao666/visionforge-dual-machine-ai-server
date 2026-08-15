#include "vfdual/dxgi_frame_semantics.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>

namespace {

using vfdual::DesktopChangeRect;
using vfdual::DesktopFrameSemantic;
using vfdual::DesktopFrameSemanticInput;
using vfdual::DesktopMetadataState;
using vfdual::DesktopMoveChange;

constexpr DesktopChangeRect kRegion{100, 100, 420, 420};

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) {
        return;
    }
    std::fprintf(stderr, "CHECK failed: %s (%s:%d)\n", expression, file, line);
    std::exit(EXIT_FAILURE);
}

#define VFDUAL_TEST_REQUIRE(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

void pointer_only_is_not_an_image_update() {
    const auto decision = vfdual::decide_desktop_frame_semantic(
        DesktopFrameSemanticInput{0, 4, kRegion});
    VFDUAL_TEST_REQUIRE(decision.semantic == DesktopFrameSemantic::pointer_only);
    VFDUAL_TEST_REQUIRE(decision.missed_present_frames == 0);
}

void dirty_rect_intersection_is_an_image_update() {
    const std::array dirty{DesktopChangeRect{419, 200, 500, 300}};
    const auto decision = vfdual::decide_desktop_frame_semantic(DesktopFrameSemanticInput{
        123, 1, kRegion, DesktopMetadataState::reliable, dirty, {}});
    VFDUAL_TEST_REQUIRE(decision.semantic == DesktopFrameSemantic::image_update);
}

void dirty_rect_outside_region_is_skipped() {
    const std::array dirty{DesktopChangeRect{500, 500, 600, 600}};
    const auto decision = vfdual::decide_desktop_frame_semantic(DesktopFrameSemanticInput{
        123, 1, kRegion, DesktopMetadataState::reliable, dirty, {}});
    VFDUAL_TEST_REQUIRE(decision.semantic == DesktopFrameSemantic::outside_region);
}

void move_source_or_destination_intersection_is_an_image_update() {
    const std::array source_intersects{DesktopMoveChange{
        DesktopChangeRect{200, 200, 250, 250}, DesktopChangeRect{500, 500, 550, 550}}};
    auto decision = vfdual::decide_desktop_frame_semantic(DesktopFrameSemanticInput{
        123, 1, kRegion, DesktopMetadataState::reliable, {}, source_intersects});
    VFDUAL_TEST_REQUIRE(decision.semantic == DesktopFrameSemantic::image_update);

    const std::array destination_intersects{DesktopMoveChange{
        DesktopChangeRect{500, 500, 550, 550}, DesktopChangeRect{200, 200, 250, 250}}};
    decision = vfdual::decide_desktop_frame_semantic(DesktopFrameSemanticInput{
        123, 1, kRegion, DesktopMetadataState::reliable, {}, destination_intersects});
    VFDUAL_TEST_REQUIRE(decision.semantic == DesktopFrameSemantic::image_update);
}

void move_fully_outside_region_is_skipped() {
    const std::array moves{DesktopMoveChange{
        DesktopChangeRect{500, 500, 550, 550}, DesktopChangeRect{600, 600, 650, 650}}};
    const auto decision = vfdual::decide_desktop_frame_semantic(DesktopFrameSemanticInput{
        123, 1, kRegion, DesktopMetadataState::reliable, {}, moves});
    VFDUAL_TEST_REQUIRE(decision.semantic == DesktopFrameSemantic::outside_region);
}

void unknown_or_empty_metadata_fails_open() {
    auto decision = vfdual::decide_desktop_frame_semantic(
        DesktopFrameSemanticInput{123, 1, kRegion, DesktopMetadataState::unavailable});
    VFDUAL_TEST_REQUIRE(decision.semantic == DesktopFrameSemantic::image_update);

    decision = vfdual::decide_desktop_frame_semantic(
        DesktopFrameSemanticInput{123, 1, kRegion, DesktopMetadataState::reliable});
    VFDUAL_TEST_REQUIRE(decision.semantic == DesktopFrameSemantic::image_update);
}

void accumulated_frames_report_missed_presents() {
    const auto decision = vfdual::decide_desktop_frame_semantic(
        DesktopFrameSemanticInput{123, 5, kRegion});
    VFDUAL_TEST_REQUIRE(decision.semantic == DesktopFrameSemantic::image_update);
    VFDUAL_TEST_REQUIRE(decision.missed_present_frames == 4);
}

void static_refresh_uses_display_timing_without_capping_real_presents() {
    VFDUAL_TEST_REQUIRE(
        vfdual::static_frame_refresh_interval_us(144U) == 6'945U);
    VFDUAL_TEST_REQUIRE(
        vfdual::static_frame_refresh_interval_us(60U) == 16'667U);
    VFDUAL_TEST_REQUIRE(
        vfdual::static_frame_capture_wait_ms(100'000U, 100'000U, 144U, 16U) ==
        7U);
    VFDUAL_TEST_REQUIRE(
        vfdual::static_frame_capture_wait_ms(106'000U, 100'000U, 144U, 16U) ==
        1U);

    // Reproduces the static-desktop boundary: after one submitted image, a
    // DXGI timeout at the display-derived deadline must become repeat-eligible.
    VFDUAL_TEST_REQUIRE(
        !vfdual::static_frame_refresh_due(106'944U, 100'000U, 144U));
    VFDUAL_TEST_REQUIRE(
        vfdual::static_frame_refresh_due(106'945U, 100'000U, 144U));
    VFDUAL_TEST_REQUIRE(
        vfdual::static_frame_capture_wait_ms(106'945U, 100'000U, 144U, 16U) ==
        0U);

    // No retained source frame means no synthetic output can be scheduled.
    VFDUAL_TEST_REQUIRE(
        !vfdual::static_frame_refresh_due(1'000'000U, 0U, 144U));
    VFDUAL_TEST_REQUIRE(
        vfdual::static_frame_capture_wait_ms(1'000'000U, 0U, 144U, 16U) ==
        16U);

    // A new ROI image whose first hybrid submit was busy remains a content
    // update when retried from the retained texture. Only later retries are
    // synthetic repeats after that generation was accepted.
    VFDUAL_TEST_REQUIRE(
        !vfdual::retained_frame_repeats_submitted_content(true, 2U, 1U));
    VFDUAL_TEST_REQUIRE(
        vfdual::retained_frame_repeats_submitted_content(true, 2U, 2U));
    VFDUAL_TEST_REQUIRE(
        !vfdual::retained_frame_repeats_submitted_content(false, 2U, 2U));
    VFDUAL_TEST_REQUIRE(
        !vfdual::repeated_frame_can_supersede_mailbox(false, true));
    VFDUAL_TEST_REQUIRE(
        vfdual::repeated_frame_can_supersede_mailbox(true, true));
    VFDUAL_TEST_REQUIRE(
        vfdual::repeated_frame_can_supersede_mailbox(false, false));

    // CPU-readback hybrid mode already owns idle repeats on the encoder
    // worker. Only synchronous and same-adapter shared paths repeat here.
    VFDUAL_TEST_REQUIRE(
        vfdual::capture_stage_owns_idle_repeat(false, false));
    VFDUAL_TEST_REQUIRE(
        vfdual::capture_stage_owns_idle_repeat(true, true));
    VFDUAL_TEST_REQUIRE(
        !vfdual::capture_stage_owns_idle_repeat(true, false));

    // A phone IDR1 request must yield a real VFRG recovery seed even while the
    // desktop is static. Ordinary static refreshes remain VFRR.
    VFDUAL_TEST_REQUIRE(
        vfdual::wire_frame_repeats_content(true, false));
    VFDUAL_TEST_REQUIRE(
        !vfdual::wire_frame_repeats_content(true, true));
    VFDUAL_TEST_REQUIRE(
        !vfdual::wire_frame_repeats_content(false, false));
    VFDUAL_TEST_REQUIRE(
        !vfdual::wire_frame_repeats_content(false, true));
}

}  // namespace

int main() {
    pointer_only_is_not_an_image_update();
    dirty_rect_intersection_is_an_image_update();
    dirty_rect_outside_region_is_skipped();
    move_source_or_destination_intersection_is_an_image_update();
    move_fully_outside_region_is_skipped();
    unknown_or_empty_metadata_fails_open();
    accumulated_frames_report_missed_presents();
    static_refresh_uses_display_timing_without_capping_real_presents();
    return 0;
}
