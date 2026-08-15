#include "vfdual/host_display_catalog.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dwmapi.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include <algorithm>
#include <limits>

namespace vfdual {
namespace {

constexpr std::uint32_t kNvidiaVendorId = 0x10DE;
constexpr std::uint32_t kCoverageScale = 1000U;
constexpr std::uint32_t kMajorityOutputCoverage = 600U;
constexpr std::uint32_t kNearFullscreenCoverage = 900U;
constexpr std::uint32_t kMostlyOnOneOutputCoverage = 900U;

bool is_system_primary_output(const DXGI_OUTPUT_DESC& description) noexcept {
    const HMONITOR primary_monitor = MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTONULL);
    if (primary_monitor == nullptr) return false;
    MONITORINFOEXW monitor_info{};
    monitor_info.cbSize = sizeof(monitor_info);
    return GetMonitorInfoW(primary_monitor, &monitor_info) != FALSE
           && lstrcmpiW(monitor_info.szDevice, description.DeviceName) == 0;
}

bool has_valid_extent(const HostDesktopRect& rect) noexcept {
    return rect.right > rect.left && rect.bottom > rect.top;
}

std::uint64_t rect_area(const HostDesktopRect& rect) noexcept {
    if (!has_valid_extent(rect)) return 0;
    return static_cast<std::uint64_t>(static_cast<std::int64_t>(rect.right) - rect.left) *
        static_cast<std::uint64_t>(static_cast<std::int64_t>(rect.bottom) - rect.top);
}

std::uint64_t overlap_area(const HostDesktopRect& left, const HostDesktopRect& right) noexcept {
    const std::int64_t width = (std::max)(std::int64_t{0},
        static_cast<std::int64_t>((std::min)(left.right, right.right)) -
            (std::max)(left.left, right.left));
    const std::int64_t height = (std::max)(std::int64_t{0},
        static_cast<std::int64_t>((std::min)(left.bottom, right.bottom)) -
            (std::max)(left.top, right.top));
    return static_cast<std::uint64_t>(width) * static_cast<std::uint64_t>(height);
}

std::uint32_t coverage_per_mille(std::uint64_t overlap, std::uint64_t area) noexcept {
    if (area == 0) return 0;
    return static_cast<std::uint32_t>((std::min)(
        static_cast<std::uint64_t>(kCoverageScale), overlap * kCoverageScale / area));
}

HostDesktopRect output_rect(const HostDisplayOutput& output) noexcept {
    return HostDesktopRect{output.desktop_left, output.desktop_top,
                           output.desktop_right, output.desktop_bottom};
}

struct WindowEnumerationContext {
    std::vector<HostDisplayWindowCandidate>* candidates{};
    DWORD host_process_id{};
    DWORD shell_process_id{};
    std::uint32_t z_order{};
};

BOOL CALLBACK enumerate_window(HWND window, LPARAM parameter) {
    auto& context = *reinterpret_cast<WindowEnumerationContext*>(parameter);
    HostDisplayWindowCandidate candidate{};
    candidate.z_order = context.z_order++;
    candidate.is_visible = IsWindowVisible(window) != FALSE;
    candidate.is_minimized = IsIconic(window) != FALSE;
    DWORD process_id{};
    GetWindowThreadProcessId(window, &process_id);
    candidate.belongs_to_host_process = process_id == context.host_process_id;
    candidate.belongs_to_shell_process = context.shell_process_id != 0 &&
        process_id == context.shell_process_id;
    const LONG_PTR extended_style = GetWindowLongPtrW(window, GWL_EXSTYLE);
    const LONG_PTR style = GetWindowLongPtrW(window, GWL_STYLE);
    candidate.is_tool_window = (extended_style & WS_EX_TOOLWINDOW) != 0;
    candidate.is_borderless = (style & (WS_CAPTION | WS_THICKFRAME)) == 0;
    DWORD cloaked{};
    candidate.is_cloaked = SUCCEEDED(DwmGetWindowAttribute(
        window, DWMWA_CLOAKED, &cloaked, sizeof(cloaked))) && cloaked != 0;

    RECT window_rect{};
    if (FAILED(DwmGetWindowAttribute(window, DWMWA_EXTENDED_FRAME_BOUNDS,
                                     &window_rect, sizeof(window_rect)))) {
        GetWindowRect(window, &window_rect);
    }
    candidate.window_rect = HostDesktopRect{
        window_rect.left, window_rect.top, window_rect.right, window_rect.bottom};

    RECT client_rect{};
    POINT client_top_left{};
    if (GetClientRect(window, &client_rect) != FALSE &&
        ClientToScreen(window, &client_top_left) != FALSE) {
        candidate.client_rect = HostDesktopRect{
            client_top_left.x, client_top_left.y,
            client_top_left.x + client_rect.right,
            client_top_left.y + client_rect.bottom};
        candidate.has_client_rect = has_valid_extent(candidate.client_rect);
    }
    context.candidates->push_back(candidate);
    return TRUE;
}

bool is_eligible_window(const HostDisplayWindowCandidate& candidate) noexcept {
    return candidate.is_visible && !candidate.is_minimized && !candidate.is_cloaked &&
        !candidate.is_tool_window && !candidate.belongs_to_host_process &&
        !candidate.belongs_to_shell_process &&
        (has_valid_extent(candidate.window_rect) ||
         (candidate.has_client_rect && has_valid_extent(candidate.client_rect)));
}

bool has_better_score(const HostDisplaySelectionScore& candidate,
                      const HostDisplayOutput& candidate_output,
                      const HostDisplaySelectionScore& current,
                      const HostDisplayOutput& current_output) noexcept {
    if (candidate.is_fullscreen != current.is_fullscreen) return candidate.is_fullscreen;
    if (candidate.candidate_z_order != current.candidate_z_order) {
        return candidate.candidate_z_order < current.candidate_z_order;
    }
    if (candidate.output_coverage_per_mille != current.output_coverage_per_mille) {
        return candidate.output_coverage_per_mille > current.output_coverage_per_mille;
    }
    if (candidate.window_coverage_per_mille != current.window_coverage_per_mille) {
        return candidate.window_coverage_per_mille > current.window_coverage_per_mille;
    }
    if (candidate.is_borderless != current.is_borderless) return candidate.is_borderless;
    if (candidate_output.is_system_primary != current_output.is_system_primary) {
        return candidate_output.is_system_primary;
    }
    if (candidate_output.adapter_index != current_output.adapter_index) {
        return candidate_output.adapter_index < current_output.adapter_index;
    }
    if (candidate_output.output_index != current_output.output_index) {
        return candidate_output.output_index < current_output.output_index;
    }
    return candidate_output.device_name < current_output.device_name;
}

}  // namespace

std::vector<HostDisplayOutput> enumerate_host_display_outputs() {
    Microsoft::WRL::ComPtr<IDXGIFactory1> factory;
    if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&factory)))) return {};
    std::vector<HostDisplayOutput> outputs;
    for (std::uint32_t adapter_index = 0;; ++adapter_index) {
        Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter;
        if (factory->EnumAdapters1(adapter_index, &adapter) == DXGI_ERROR_NOT_FOUND) break;
        if (adapter == nullptr) continue;
        DXGI_ADAPTER_DESC1 adapter_description{};
        if (FAILED(adapter->GetDesc1(&adapter_description))) continue;
        for (std::uint32_t output_index = 0;; ++output_index) {
            Microsoft::WRL::ComPtr<IDXGIOutput> output;
            if (adapter->EnumOutputs(output_index, &output) == DXGI_ERROR_NOT_FOUND) break;
            if (output == nullptr) continue;
            DXGI_OUTPUT_DESC description{};
            if (FAILED(output->GetDesc(&description)) || !description.AttachedToDesktop) continue;
            DEVMODEW mode{};
            mode.dmSize = sizeof(mode);
            const std::uint32_t refresh_hz = EnumDisplaySettingsW(description.DeviceName, ENUM_CURRENT_SETTINGS, &mode)
                ? mode.dmDisplayFrequency : 60U;
            const auto width = static_cast<std::uint32_t>(description.DesktopCoordinates.right - description.DesktopCoordinates.left);
            const auto height = static_cast<std::uint32_t>(description.DesktopCoordinates.bottom - description.DesktopCoordinates.top);
            const bool is_system_primary = is_system_primary_output(description);
            const auto existing = std::find_if(outputs.begin(), outputs.end(), [&description](const HostDisplayOutput& item) {
                return item.device_name == description.DeviceName;
            });
            if (existing == outputs.end()) {
                outputs.push_back(HostDisplayOutput{adapter_index, output_index, description.DeviceName, width, height,
                                                    refresh_hz, is_system_primary,
                                                    description.DesktopCoordinates.left,
                                                    description.DesktopCoordinates.top,
                                                    description.DesktopCoordinates.right,
                                                    description.DesktopCoordinates.bottom});
            } else if (adapter_description.VendorId == kNvidiaVendorId) {
                // Hybrid laptops expose one physical panel through both adapters.
                // Prefer NVIDIA so Desktop Duplication and NVENC stay on one GPU path.
                *existing = HostDisplayOutput{adapter_index, output_index, description.DeviceName, width, height,
                                              refresh_hz, is_system_primary,
                                              description.DesktopCoordinates.left,
                                              description.DesktopCoordinates.top,
                                              description.DesktopCoordinates.right,
                                              description.DesktopCoordinates.bottom};
            }
        }
    }
    return outputs;
}

std::vector<HostDisplayWindowCandidate> enumerate_host_display_window_candidates() {
    std::vector<HostDisplayWindowCandidate> candidates;
    DWORD shell_process_id{};
    GetWindowThreadProcessId(GetShellWindow(), &shell_process_id);
    WindowEnumerationContext context{
        &candidates, GetCurrentProcessId(), shell_process_id, 0};
    EnumWindows(enumerate_window, reinterpret_cast<LPARAM>(&context));
    return candidates;
}

HostDisplaySelection select_host_display_output(
    const std::vector<HostDisplayOutput>& outputs,
    const std::vector<HostDisplayWindowCandidate>& candidates) noexcept {
    HostDisplaySelection selection{};
    for (const auto& candidate : candidates) {
        if (!is_eligible_window(candidate)) continue;
        for (const auto& output : outputs) {
            const HostDesktopRect display_rect = output_rect(output);
            const std::uint64_t display_area = rect_area(display_rect);
            if (display_area == 0) continue;

            HostDesktopRect candidate_rect = candidate.window_rect;
            std::uint64_t candidate_overlap = overlap_area(candidate_rect, display_rect);
            if (candidate.has_client_rect) {
                const std::uint64_t client_overlap = overlap_area(candidate.client_rect, display_rect);
                if (client_overlap > candidate_overlap) {
                    candidate_rect = candidate.client_rect;
                    candidate_overlap = client_overlap;
                }
            }
            const std::uint64_t candidate_area = rect_area(candidate_rect);
            const std::uint32_t output_coverage = coverage_per_mille(candidate_overlap, display_area);
            const std::uint32_t window_coverage = coverage_per_mille(candidate_overlap, candidate_area);
            // A normal maximized browser/editor can cover almost the complete
            // monitor.  Geometry alone must therefore not promote a framed
            // window above the actual borderless game surface.
            const bool is_fullscreen = candidate.is_borderless &&
                output_coverage >= kNearFullscreenCoverage;
            const bool is_large_borderless = candidate.is_borderless &&
                output_coverage >= kMajorityOutputCoverage;
            if (window_coverage < kMostlyOnOneOutputCoverage ||
                (!is_fullscreen && !is_large_borderless)) continue;

            const HostDisplaySelectionScore score{
                candidate.z_order, output_coverage, window_coverage,
                is_fullscreen, candidate.is_borderless};
            if (selection.output == nullptr ||
                has_better_score(score, output, selection.score, *selection.output)) {
                selection.output = &output;
                selection.reason = is_fullscreen
                    ? HostDisplaySelectionReason::external_window_fullscreen
                    : HostDisplaySelectionReason::external_window_borderless;
                selection.score = score;
            }
        }
    }
    if (selection.output != nullptr) return selection;

    selection.output = select_preferred_display_output(outputs);
    if (selection.output == nullptr) {
        selection.reason = HostDisplaySelectionReason::no_attached_output;
    } else {
        selection.reason = selection.output->is_system_primary
            ? HostDisplaySelectionReason::system_primary
            : HostDisplaySelectionReason::first_attached_output;
    }
    return selection;
}

const HostDisplayOutput* select_preferred_display_output(const std::vector<HostDisplayOutput>& outputs) noexcept {
    const auto primary = std::find_if(outputs.begin(), outputs.end(), [](const HostDisplayOutput& output) {
        return output.is_system_primary;
    });
    return primary != outputs.end() ? &*primary : (outputs.empty() ? nullptr : &outputs.front());
}

const HostDisplayOutput* select_matching_or_preferred_display_output(
    const std::vector<HostDisplayOutput>& outputs, std::string_view device_id) noexcept {
    const auto matching = std::find_if(outputs.begin(), outputs.end(), [device_id](const HostDisplayOutput& output) {
        if (output.device_name.size() != device_id.size()) return false;
        for (std::size_t index = 0; index < output.device_name.size(); ++index) {
            const wchar_t character = output.device_name[index];
            if (character < 0 || character > 0x7f ||
                static_cast<char>(character) != device_id[index]) return false;
        }
        return true;
    });
    return matching != outputs.end() ? &*matching : select_preferred_display_output(outputs);
}

HostCaptureGeometry choose_centered_ai_capture_geometry(const HostDisplayOutput& output) noexcept {
    HostCaptureGeometry geometry{};
    geometry.encoder_width = kAiCaptureEdge;
    geometry.encoder_height = kAiCaptureEdge;

    const std::int64_t rect_width = static_cast<std::int64_t>(output.desktop_right) - output.desktop_left;
    const std::int64_t rect_height = static_cast<std::int64_t>(output.desktop_bottom) - output.desktop_top;
    const bool has_valid_rect = rect_width > 0 && rect_height > 0 &&
        rect_width <= (std::numeric_limits<std::uint32_t>::max)() &&
        rect_height <= (std::numeric_limits<std::uint32_t>::max)();
    geometry.source_width = has_valid_rect ? static_cast<std::uint32_t>(rect_width) : output.width;
    geometry.source_height = has_valid_rect ? static_cast<std::uint32_t>(rect_height) : output.height;
    geometry.display_rect = has_valid_rect
        ? HostDesktopRect{output.desktop_left, output.desktop_top, output.desktop_right, output.desktop_bottom}
        : HostDesktopRect{output.desktop_left, output.desktop_top,
                          output.desktop_left + static_cast<std::int32_t>(output.width),
                          output.desktop_top + static_cast<std::int32_t>(output.height)};
    if (geometry.source_width == 0 || geometry.source_height == 0) {
        geometry.fallback_reason = HostCaptureFallbackReason::invalid_display_extent;
        return geometry;
    }

    geometry.local_roi_width = (std::min)(kAiCaptureEdge, geometry.source_width);
    geometry.local_roi_height = (std::min)(kAiCaptureEdge, geometry.source_height);
    geometry.local_roi_x = (geometry.source_width - geometry.local_roi_width) / 2U;
    geometry.local_roi_y = (geometry.source_height - geometry.local_roi_height) / 2U;
    geometry.roi_rect = HostDesktopRect{
        geometry.display_rect.left + static_cast<std::int32_t>(geometry.local_roi_x),
        geometry.display_rect.top + static_cast<std::int32_t>(geometry.local_roi_y),
        geometry.display_rect.left + static_cast<std::int32_t>(geometry.local_roi_x + geometry.local_roi_width),
        geometry.display_rect.top + static_cast<std::int32_t>(geometry.local_roi_y + geometry.local_roi_height),
    };
    geometry.fallback_reason = geometry.local_roi_width == kAiCaptureEdge &&
                                       geometry.local_roi_height == kAiCaptureEdge
        ? HostCaptureFallbackReason::none
        : HostCaptureFallbackReason::source_smaller_than_encoder;
    return geometry;
}

const char* host_capture_fallback_reason_name(HostCaptureFallbackReason reason) noexcept {
    switch (reason) {
        case HostCaptureFallbackReason::none: return "none";
        case HostCaptureFallbackReason::source_smaller_than_encoder: return "source_smaller_than_encoder";
        case HostCaptureFallbackReason::invalid_display_extent: return "invalid_display_extent";
    }
    return "invalid_display_extent";
}

const char* host_display_selection_reason_name(HostDisplaySelectionReason reason) noexcept {
    switch (reason) {
        case HostDisplaySelectionReason::external_window_fullscreen: return "external_window_fullscreen";
        case HostDisplaySelectionReason::external_window_borderless: return "external_window_borderless";
        case HostDisplaySelectionReason::system_primary: return "system_primary";
        case HostDisplaySelectionReason::first_attached_output: return "first_attached_output";
        case HostDisplaySelectionReason::no_attached_output: return "no_attached_output";
    }
    return "no_attached_output";
}

}  // namespace vfdual
