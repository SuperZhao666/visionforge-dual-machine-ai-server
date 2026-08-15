#include "vfdual/host_display_catalog.hpp"
#include "vfdual/frame_scaling_policy.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
    std::exit(EXIT_FAILURE);
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

namespace {

vfdual::HostDisplayWindowCandidate visible_window(
    vfdual::HostDesktopRect rect, std::uint32_t z_order, bool borderless) {
    vfdual::HostDisplayWindowCandidate candidate{};
    candidate.window_rect = rect;
    candidate.client_rect = rect;
    candidate.z_order = z_order;
    candidate.has_client_rect = true;
    candidate.is_visible = true;
    candidate.is_borderless = borderless;
    return candidate;
}

}  // namespace

int main() {
    const auto wide_odd = vfdual::fit_frame_extent(23U, 1U, 416U, 416U);
    CHECK(wide_odd.width == 416U && wide_odd.height == 18U);
    const auto tall_odd = vfdual::fit_frame_extent(1U, 23U, 416U, 416U);
    CHECK(tall_odd.width == 18U && tall_odd.height == 416U);
    const auto tiny_scale = vfdual::fit_frame_extent(240U, 200U, 416U, 416U);
    CHECK(tiny_scale.width == 416U && tiny_scale.height == 346U);
    const auto almost_square = vfdual::fit_frame_extent(415U, 413U, 416U, 416U);
    CHECK(almost_square.width == 416U && almost_square.height == 413U);
    CHECK(vfdual::fit_frame_extent(0U, 200U, 416U, 416U).width == 0U);

    const std::vector<vfdual::HostDisplayOutput> outputs{
        {0, 0, L"\\\\.\\DISPLAY1", 1920, 1080, 60, false},
        {1, 0, L"\\\\.\\DISPLAY2", 2560, 1440, 144, true},
    };
    const auto* primary = vfdual::select_preferred_display_output(outputs);
    CHECK(primary != nullptr && primary->device_name == L"\\\\.\\DISPLAY2");
    const auto* retained = vfdual::select_matching_or_preferred_display_output(outputs, "\\\\.\\DISPLAY1");
    CHECK(retained != nullptr && retained->device_name == L"\\\\.\\DISPLAY1");
    const auto* changed_primary = vfdual::select_matching_or_preferred_display_output(outputs, "\\\\.\\DISPLAY9");
    CHECK(changed_primary != nullptr && changed_primary->device_name == L"\\\\.\\DISPLAY2");

    const std::vector<vfdual::HostDisplayOutput> fallback{{0, 0, L"\\\\.\\DISPLAY3", 1280, 720, 60, false}};
    const auto* fallback_output = vfdual::select_preferred_display_output(fallback);
    CHECK(fallback_output != nullptr && fallback_output->device_name == L"\\\\.\\DISPLAY3");
    CHECK(vfdual::select_preferred_display_output({}) == nullptr);
    const auto* fallback_retained = vfdual::select_matching_or_preferred_display_output(
        fallback, "\\\\.\\DISPLAY3");
    CHECK(fallback_retained != nullptr && fallback_retained->device_name == L"\\\\.\\DISPLAY3");

    const std::vector<vfdual::HostDisplayOutput> dual_outputs{
        {0, 0, L"\\\\.\\DISPLAY1", 1920, 1080, 144, true, 0, 0, 1920, 1080},
        {1, 0, L"\\\\.\\DISPLAY2", 2560, 1440, 144, false, 1920, 0, 4480, 1440},
    };
    auto host_gui = visible_window({0, 0, 1920, 1080}, 0, false);
    host_gui.belongs_to_host_process = true;
    const auto game_fullscreen = visible_window({1920, 0, 4480, 1440}, 1, true);
    const auto browser_behind = visible_window({0, 0, 1920, 1080}, 2, false);
    const auto game_selection = vfdual::select_host_display_output(
        dual_outputs, {host_gui, game_fullscreen, browser_behind});
    CHECK(game_selection.output != nullptr);
    CHECK(game_selection.output->device_name == L"\\\\.\\DISPLAY2");
    CHECK(game_selection.reason == vfdual::HostDisplaySelectionReason::external_window_fullscreen);
    CHECK(game_selection.score.candidate_z_order == 1);
    CHECK(game_selection.score.output_coverage_per_mille == 1000);
    CHECK(game_selection.score.window_coverage_per_mille == 1000);

    // Among equally full-screen external windows, EnumWindows Z order is the
    // deterministic tie breaker after the Host GUI itself has been excluded.
    const auto topmost_game = visible_window({1920, 0, 4480, 1440}, 3, true);
    const auto lower_primary_window = visible_window({0, 0, 1920, 1080}, 4, false);
    const auto z_order_selection = vfdual::select_host_display_output(
        dual_outputs, {topmost_game, lower_primary_window});
    CHECK(z_order_selection.output != nullptr);
    CHECK(z_order_selection.output->device_name == L"\\\\.\\DISPLAY2");

    const auto large_borderless = visible_window({2000, 100, 4400, 1300}, 1, true);
    const auto borderless_selection = vfdual::select_host_display_output(
        dual_outputs, {large_borderless});
    CHECK(borderless_selection.output != nullptr);
    CHECK(borderless_selection.output->device_name == L"\\\\.\\DISPLAY2");
    CHECK(borderless_selection.reason == vfdual::HostDisplaySelectionReason::external_window_borderless);
    CHECK(borderless_selection.score.output_coverage_per_mille >= 600);

    auto bordered_maximized = visible_window({1920, 0, 4480, 1440}, 0, false);
    const auto bordered_maximized_fallback = vfdual::select_host_display_output(
        dual_outputs, {bordered_maximized});
    CHECK(bordered_maximized_fallback.output != nullptr &&
           bordered_maximized_fallback.output->is_system_primary);
    CHECK(bordered_maximized_fallback.reason ==
           vfdual::HostDisplaySelectionReason::system_primary);

    const auto bordered_near_fullscreen =
        visible_window({1984, 0, 4416, 1440}, 0, false);
    const auto bordered_near_fullscreen_fallback = vfdual::select_host_display_output(
        dual_outputs, {bordered_near_fullscreen});
    CHECK(bordered_near_fullscreen_fallback.output != nullptr &&
           bordered_near_fullscreen_fallback.output->is_system_primary);

    const auto game_over_maximized_editor = vfdual::select_host_display_output(
        dual_outputs, {bordered_maximized, game_fullscreen});
    CHECK(game_over_maximized_editor.output != nullptr);
    CHECK(game_over_maximized_editor.output->device_name == L"\\\\.\\DISPLAY2");
    CHECK(game_over_maximized_editor.reason ==
           vfdual::HostDisplaySelectionReason::external_window_fullscreen);

    auto bordered_partial = large_borderless;
    bordered_partial.is_borderless = false;
    const auto partial_fallback = vfdual::select_host_display_output(
        dual_outputs, {bordered_partial});
    CHECK(partial_fallback.output != nullptr && partial_fallback.output->is_system_primary);
    CHECK(partial_fallback.reason == vfdual::HostDisplaySelectionReason::system_primary);

    auto invisible = game_fullscreen;
    invisible.is_visible = false;
    auto minimized = game_fullscreen;
    minimized.is_minimized = true;
    auto cloaked = game_fullscreen;
    cloaked.is_cloaked = true;
    auto tool = game_fullscreen;
    tool.is_tool_window = true;
    auto shell = game_fullscreen;
    shell.belongs_to_shell_process = true;
    const auto filtered_fallback = vfdual::select_host_display_output(
        dual_outputs, {invisible, minimized, cloaked, tool, host_gui, shell});
    CHECK(filtered_fallback.output != nullptr && filtered_fallback.output->is_system_primary);
    CHECK(filtered_fallback.reason == vfdual::HostDisplaySelectionReason::system_primary);

    const std::vector<vfdual::HostDisplayOutput> no_primary_outputs{
        {2, 1, L"\\\\.\\DISPLAY7", 1280, 720, 60, false, 0, 0, 1280, 720},
    };
    const auto first_output_fallback = vfdual::select_host_display_output(no_primary_outputs, {});
    CHECK(first_output_fallback.output != nullptr);
    CHECK(first_output_fallback.reason == vfdual::HostDisplaySelectionReason::first_attached_output);
    const auto no_output = vfdual::select_host_display_output({}, {game_fullscreen});
    CHECK(no_output.output == nullptr);
    CHECK(no_output.reason == vfdual::HostDisplaySelectionReason::no_attached_output);
    CHECK(std::string{vfdual::host_display_selection_reason_name(game_selection.reason)} ==
           "external_window_fullscreen");

    const vfdual::HostDisplayOutput full_hd{
        0, 0, L"\\\\.\\DISPLAY1", 1920, 1080, 144, true, 0, 0, 1920, 1080};
    const auto full_hd_geometry = vfdual::choose_centered_ai_capture_geometry(full_hd);
    CHECK(full_hd_geometry.source_width == 1920 && full_hd_geometry.source_height == 1080);
    CHECK(full_hd_geometry.local_roi_x == 752 && full_hd_geometry.local_roi_y == 332);
    CHECK(full_hd_geometry.local_roi_width == vfdual::kAiCaptureEdge &&
          full_hd_geometry.local_roi_height == vfdual::kAiCaptureEdge);
    CHECK(full_hd_geometry.roi_rect.left == 752 && full_hd_geometry.roi_rect.top == 332);
    CHECK(full_hd_geometry.roi_rect.right == 1168 && full_hd_geometry.roi_rect.bottom == 748);
    CHECK(full_hd_geometry.encoder_width == vfdual::kAiCaptureEdge &&
          full_hd_geometry.encoder_height == vfdual::kAiCaptureEdge);
    CHECK(full_hd_geometry.fallback_reason == vfdual::HostCaptureFallbackReason::none);

    const vfdual::HostDisplayOutput negative_2k{
        1, 0, L"\\\\.\\DISPLAY2", 2560, 1440, 165, false, -2560, 0, 0, 1440};
    const auto negative_geometry = vfdual::choose_centered_ai_capture_geometry(negative_2k);
    CHECK(negative_geometry.local_roi_x == 1072 && negative_geometry.local_roi_y == 512);
    CHECK(negative_geometry.roi_rect.left == -1488 && negative_geometry.roi_rect.right == -1072);

    const vfdual::HostDisplayOutput ultra_hd{
        2, 0, L"\\\\.\\DISPLAY3", 3840, 2160, 120, false, 1920, -1080, 5760, 1080};
    const auto ultra_hd_geometry = vfdual::choose_centered_ai_capture_geometry(ultra_hd);
    CHECK(ultra_hd_geometry.local_roi_x == 1712 && ultra_hd_geometry.local_roi_y == 872);
    CHECK(ultra_hd_geometry.roi_rect.left == 3632 && ultra_hd_geometry.roi_rect.top == -208);

    const vfdual::HostDisplayOutput tiny{
        3, 0, L"\\\\.\\DISPLAY4", 240, 200, 60, false, 0, 0, 240, 200};
    const auto tiny_geometry = vfdual::choose_centered_ai_capture_geometry(tiny);
    CHECK(tiny_geometry.local_roi_x == 0 && tiny_geometry.local_roi_y == 0);
    CHECK(tiny_geometry.local_roi_width == 240 && tiny_geometry.local_roi_height == 200);
    CHECK(tiny_geometry.encoder_width == vfdual::kAiCaptureEdge &&
          tiny_geometry.encoder_height == vfdual::kAiCaptureEdge);
    CHECK(tiny_geometry.fallback_reason == vfdual::HostCaptureFallbackReason::source_smaller_than_encoder);
    return 0;
}
