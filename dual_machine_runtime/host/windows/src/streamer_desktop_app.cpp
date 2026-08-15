#include "vfdual/streamer_desktop_app.hpp"

#include "vfdual/host_cat6_bootstrap.hpp"
#include "vfdual/host_cat6_session.hpp"
#include "vfdual/host_direct_link_provisioner.hpp"
#include "vfdual/host_release_version.hpp"
#include "vfdual/host_window_layout.hpp"
#include "vfdual/h264_encoder_config.hpp"
#include "vfdual/model_contract.hpp"
#include "../streamer_ui_resources.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dwmapi.h>
#include <shellapi.h>

#ifdef small
#undef small
#endif

#include <algorithm>
#include <cmath>
#include <cwchar>
#include <exception>
#include <filesystem>
#include <iomanip>
#include <memory>
#include <new>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace vfdual {
namespace {

constexpr wchar_t kWindowClassName[] = L"VisionForgeStreamerDesktopWindow";
constexpr UINT_PTR kRefreshTimerId = 1;
// Retries a failed start only in --acceptance-autostart runs so a transient
// bootstrap failure (for example the machine-identity tool rewriting the
// adapter mid-bootstrap) does not abort the whole acceptance attempt.
constexpr UINT_PTR kAutostartRetryTimerId = 2;
constexpr int kStartButtonId = 1001;
constexpr int kStopButtonId = 1002;
constexpr int kDiagnosticsButtonId = 1003;
constexpr int kSettingsButtonId = 1004;
constexpr int kClearEventsButtonId = 1005;
constexpr int kRefreshDisplaysButtonId = 1009;
constexpr int kRefreshMobileButtonId = 1010;
constexpr int kCloseSettingsButtonId = 1011;
constexpr UINT kStartupCompletedMessage = WM_APP + 1;
constexpr UINT kMobileRefreshCompletedMessage = WM_APP + 2;
constexpr UINT kAcceptanceAutostartMessage = WM_APP + 3;
constexpr auto kWirelessLanDiscoveryTimeout = std::chrono::seconds(8);

void schedule_autostart_retry(HWND window, bool acceptance_autostart) {
    // A failed or not-yet-possible acceptance start retries on its own
    // cadence: the machine-identity tool's second rewrite wave and transient
    // display enumeration gaps land during the first bootstrap on this
    // machine, and only a later attempt can succeed. Never use a modal
    // MessageBox in autostart mode -- the machine is unattended.
    if (!acceptance_autostart) return;
    SetTimer(window, kAutostartRetryTimerId, 3000, nullptr);
}

void safe_join_thread(std::thread& thread) noexcept {
    // Message-loop teardown must never let a std::thread::join error escape:
    // during E-system acceptance #6 a stale thread state turned WM_CLOSE into
    // std::terminate.
    try {
        if (thread.joinable()) thread.join();
    } catch (...) {
    }
}
// Obsidian Aurora visual system: near-black obsidian base plus electric violet accent.
// Semantic colors: soft violet healthy, lava amber warning, coral error, slate idle.
constexpr COLORREF kWindowBackground = RGB(0x0B, 0x0E, 0x13);
constexpr COLORREF kWindowBackgroundDeep = RGB(0x11, 0x16, 0x24);
constexpr COLORREF kPanelBackground = RGB(0x14, 0x19, 0x24);
constexpr COLORREF kPanelOutline = RGB(0x23, 0x2B, 0x3A);
constexpr COLORREF kRowBackground = RGB(0x1A, 0x21, 0x30);
constexpr COLORREF kRowOutline = RGB(0x26, 0x2F, 0x42);
constexpr COLORREF kSummaryBackground = RGB(0x1E, 0x1A, 0x33);
constexpr COLORREF kSummaryOutline = RGB(0x46, 0x3A, 0x6B);
constexpr COLORREF kAccent = RGB(0x8B, 0x5C, 0xF6);
constexpr COLORREF kAccentHover = RGB(0xA7, 0x8B, 0xFA);
constexpr COLORREF kAccentPressed = RGB(0x6D, 0x45, 0xD8);
constexpr COLORREF kCaptureAccent = RGB(0xC4, 0xB5, 0xFD);
constexpr COLORREF kEncodeAccent = RGB(0xA7, 0x8B, 0xFA);
constexpr COLORREF kPublishAccent = RGB(0x8B, 0x5C, 0xF6);
constexpr COLORREF kLinkAccent = RGB(0xE8, 0x79, 0xF9);
constexpr COLORREF kText = RGB(0xE6, 0xEA, 0xF2);
constexpr COLORREF kMutedText = RGB(0x8A, 0x93, 0xA6);
constexpr COLORREF kButtonSecondary = RGB(0x1D, 0x25, 0x33);
constexpr COLORREF kButtonSecondaryPressed = RGB(0x26, 0x31, 0x46);
constexpr COLORREF kButtonDisabled = RGB(0x25, 0x2D, 0x3B);
constexpr COLORREF kStateIdle = RGB(0x64, 0x74, 0x8B);
constexpr COLORREF kStateDiscovering = kAccent;
constexpr COLORREF kStateHealthy = RGB(0xA7, 0x8B, 0xFA);
constexpr COLORREF kStateWarning = RGB(0xF5, 0x9E, 0x0B);
constexpr COLORREF kStateFailure = RGB(0xFB, 0x71, 0x85);
constexpr int kGradientBandCount = 64;
// The parent owns the card/background artwork while the live values are child
// STATIC controls.  Excluding child rectangles prevents an unrelated parent
// paint from briefly covering them before they repaint.
constexpr DWORD kWindowStyle = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;

struct StartupResult final {
    std::uint64_t generation{};
    bool started{};
    std::string error;
};

struct MobileRefreshResult final {
    std::uint64_t generation{};
    std::optional<Cat6SessionSnapshot> mobile;
};

std::string describe_background_exception(
    std::string_view operation, const std::exception& exception) {
    std::string detail{operation};
    detail += " failed in background thread: ";
    detail += exception.what();
    return detail;
}

std::string describe_unknown_background_exception(std::string_view operation) {
    std::string detail{operation};
    detail += " failed in background thread with an unknown exception";
    return detail;
}

void post_startup_completed_result(
    HWND window, std::uint64_t generation, bool started, std::string error) noexcept {
    auto* result = new (std::nothrow) StartupResult{
        generation, started, std::move(error)};
    if (result == nullptr) return;
    if (!PostMessageW(
            window, kStartupCompletedMessage, 0,
            reinterpret_cast<LPARAM>(result))) {
        delete result;
    }
}

void post_mobile_refresh_completed_result(
    HWND window, std::uint64_t generation,
    std::optional<Cat6SessionSnapshot> mobile) noexcept {
    auto* result = new (std::nothrow) MobileRefreshResult{
        generation, std::move(mobile)};
    if (result == nullptr) return;
    if (!PostMessageW(
            window, kMobileRefreshCompletedMessage, 0,
            reinterpret_cast<LPARAM>(result))) {
        delete result;
    }
}

struct InitialWindowBounds final {
    int x{};
    int y{};
    int width{};
    int height{};
};

constexpr RECT logical_rect(int x, int y, int width, int height) noexcept {
    return RECT{x, y, x + width, y + height};
}

constexpr RECT logical_rect(HostLogicalRect bounds) noexcept {
    return logical_rect(bounds.x, bounds.y, bounds.width, bounds.height);
}

std::wstring format_microseconds(std::uint64_t value) {
    wchar_t text[32]{};
    swprintf_s(text, L"%.2f ms", static_cast<double>(value) / 1000.0);
    return text;
}

std::wstring format_decimal(double value, const wchar_t* suffix = L"") {
    std::wostringstream formatter;
    formatter << std::fixed << std::setprecision(1) << value << suffix;
    return formatter.str();
}

COLORREF host_ui_phase_color(HostUiPhase phase) noexcept {
    switch (phase) {
        case HostUiPhase::idle: return kStateIdle;
        case HostUiPhase::discovering: return kStateDiscovering;
        case HostUiPhase::streaming: return kStateHealthy;
        case HostUiPhase::mobile_stale:
        case HostUiPhase::recovering: return kStateWarning;
        case HostUiPhase::failed: return kStateFailure;
    }
    return kStateIdle;
}

std::wstring widen_ascii(std::string_view value) {
    std::wstring result;
    result.reserve(value.size());
    for (const unsigned char character : value) {
        result.push_back(character < 0x80U ? static_cast<wchar_t>(character) : L'?');
    }
    return result;
}

std::wstring friendly_host_failure(std::string_view error) {
    if (error.find("ambiguous_same_name_rule") != std::string_view::npos) {
        return L"\u68c0\u6d4b\u5230\u51b2\u7a81\u7684\u65e7\u7248 Windows \u9632\u706b\u5899\u89c4\u5219";
    }
    if (error.find("wireless_firewall_status=failed") !=
            std::string_view::npos ||
        error.find("failure_stage=firewall") != std::string_view::npos ||
        error.find("CAT6 firewall provisioning failed") !=
            std::string_view::npos) {
        return L"Windows \u9632\u706b\u5899\u6700\u5c0f\u653e\u884c\u89c4\u5219\u914d\u7f6e\u5931\u8d25";
    }
    if (error.find("Automatic wireless-LAN UDP fallback was unavailable") !=
            std::string_view::npos ||
        error.find("wireless_discovery={") != std::string_view::npos) {
        return L"\u65e0\u7ebf\u5c40\u57df\u7f51\u672a\u53d1\u73b0 VF Mobile";
    }
    if (error.find("Host DHCP received zero packets") != std::string_view::npos ||
        error.find("not exposing an app-usable IPv4") != std::string_view::npos) {
        return L"\u624b\u673a\u6709\u7ebf\u7f51\u672a\u83b7\u5f97 10.57.23.2/24 IPv4";
    }
    if (error.find("failure_stage=mobile_ready_timeout") != std::string_view::npos ||
        error.find("heartbeat") != std::string_view::npos) {
        return L"\u672a\u6536\u5230\u624b\u673a CAT6 \u5fc3\u8df3";
    }
    if (error.find("failure_stage=dhcp") != std::string_view::npos ||
        error.find("CAT6 DHCP bootstrap failed") != std::string_view::npos) {
        return L"CAT6 DHCP \u542f\u52a8\u5931\u8d25";
    }
    if (error.find("direct-link") != std::string_view::npos ||
        error.find("wired") != std::string_view::npos) {
        return L"CAT6 \u6709\u7ebf\u63a5\u53e3\u81ea\u52a8\u914d\u7f6e\u5931\u8d25";
    }
    if (error.find("display") != std::string_view::npos ||
        error.find("DXGI") != std::string_view::npos) {
        return L"\u684c\u9762\u6355\u83b7\u521d\u59cb\u5316\u5931\u8d25";
    }
    if (error.find("H.264") != std::string_view::npos ||
        error.find("UDP") != std::string_view::npos) {
        return L"\u7f16\u7801\u6216 CAT6 \u53d1\u9001\u521d\u59cb\u5316\u5931\u8d25";
    }
    return L"\u4e3b\u673a\u4f20\u8f93\u542f\u52a8\u5931\u8d25";
}

bool set_window_text_if_changed(HWND control, std::wstring_view text) {
    if (control == nullptr) return false;
    const int length = GetWindowTextLengthW(control);
    std::wstring current(static_cast<std::size_t>((std::max)(0, length)) + 1U, L'\0');
    const int copied = GetWindowTextW(
        control, current.data(), static_cast<int>(current.size()));
    current.resize(static_cast<std::size_t>((std::max)(0, copied)));
    if (current == text) return false;
    const std::wstring replacement{text};
    SetWindowTextW(control, replacement.c_str());
    return true;
}

const wchar_t* encoder_vendor_name(std::int32_t vendor) noexcept {
    switch (vendor) {
        case 1: return L"Microsoft";
        case 2: return L"NVIDIA";
        case 3: return L"AMD";
        case 4: return L"Intel";
        default: return L"Unknown";
    }
}

std::wstring describe_encoder_state(const HostStreamMetrics& metrics) {
    if (metrics.encoder_backend == 1) {
        if (!metrics.encoder_same_adapter) {
            return L"NVIDIA NVENC (H.264)  |  \u8de8\u5361\u786c\u4ef6\u7f16\u7801";
        }
        return L"NVIDIA NVENC (H.264)  |  \u786c\u4ef6\u7f16\u7801";
    }
    if (metrics.encoder_backend == 2) {
        return std::wstring{encoder_vendor_name(metrics.encoder_vendor)} +
            L" Media Foundation (H.264)  |  \u786c\u4ef6\u7f16\u7801";
    }
    if (metrics.encoder_backend == 3) {
        return L"Microsoft Media Foundation (H.264)  |  CPU \u8f6f\u4ef6\u7f16\u7801";
    }
    return L"\u7f16\u7801\u5668\u672a\u5c31\u7eea";
}

std::wstring format_metric(const wchar_t* label, const wchar_t* detail,
                           const std::optional<HostUiMetricTriple>& metric,
                           const wchar_t* suffix) {
    std::wstring text = std::wstring{label} + L"\r\n" + detail + L"\r\n";
    if (!metric.has_value()) return text + L"\u5f53\u524d  --     P50  --     P95  --";
    return text + L"\u5f53\u524d  " + format_decimal(metric->current, suffix) +
           L"     P50  " + format_decimal(metric->p50, suffix) +
           L"     P95  " + format_decimal(metric->p95, suffix);
}

bool is_wireless_lan_transport(std::string_view transport) noexcept {
    return transport == kWirelessLanUdpTransportName;
}

std::wstring describe_link(std::string_view transport) {
    if (is_wireless_lan_transport(transport)) {
        return L"\u65e0\u7ebf\u5c40\u57df\u7f51 UDP";
    }
    if (transport == kCat6TransportName) {
        return L"CAT6 \u70b9\u5bf9\u70b9\u6709\u7ebf";
    }
    return L"\u672a\u77e5\u4f20\u8f93\u94fe\u8def";
}

const wchar_t* display_selection_reason_text(HostDisplaySelectionReason reason) noexcept {
    switch (reason) {
        case HostDisplaySelectionReason::external_window_fullscreen: return L"\u5168\u5c4f\u5916\u90e8\u7a97\u53e3";
        case HostDisplaySelectionReason::external_window_borderless: return L"\u65e0\u8fb9\u6846\u5916\u90e8\u7a97\u53e3";
        case HostDisplaySelectionReason::system_primary: return L"\u7cfb\u7edf\u4e3b\u5c4f\u56de\u9000";
        case HostDisplaySelectionReason::first_attached_output: return L"\u9996\u4e2a\u6709\u6548\u8f93\u51fa\u56de\u9000";
        case HostDisplaySelectionReason::no_attached_output: return L"\u65e0\u6709\u6548\u8f93\u51fa";
    }
    return L"\u65e0\u6709\u6548\u8f93\u51fa";
}

std::wstring describe_display(const HostDisplayOutput& output) {
    return output.device_name + L"  |  " +
           std::to_wstring(output.width) + L"\u00d7" + std::to_wstring(output.height) +
           L"  |  " + std::to_wstring((std::max)(1U, output.refresh_hz)) + L" Hz";
}

std::string narrow_display_id(const std::wstring& device_name) {
    std::string value;
    value.reserve(device_name.size());
    for (const wchar_t character : device_name) {
        value.push_back(character >= 0 && character <= 0x7f ? static_cast<char>(character) : '?');
    }
    return value;
}

InitialWindowBounds choose_initial_window_bounds() noexcept {
    RECT work_area{};
    if (!SystemParametersInfoW(SPI_GETWORKAREA, 0, &work_area, 0)) {
        work_area = RECT{0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)};
    }
    const UINT dpi = (std::max)(96U, GetDpiForSystem());
    const int work_width = work_area.right - work_area.left;
    const int work_height = work_area.bottom - work_area.top;
    RECT non_client{};
    if (!AdjustWindowRectExForDpi(&non_client, kWindowStyle, FALSE, 0, dpi)) {
        AdjustWindowRectEx(&non_client, kWindowStyle, FALSE, 0);
    }
    const int non_client_width = non_client.right - non_client.left;
    const int non_client_height = non_client.bottom - non_client.top;
    const HostClientSize client = host_initial_client_size(
        (std::max)(1, work_width - 48 - non_client_width),
        (std::max)(1, work_height - 72 - non_client_height), dpi);

    RECT outer{0, 0, client.width, client.height};
    if (!AdjustWindowRectExForDpi(&outer, kWindowStyle, FALSE, 0, dpi)) {
        AdjustWindowRectEx(&outer, kWindowStyle, FALSE, 0);
    }
    const int width = outer.right - outer.left;
    const int height = outer.bottom - outer.top;
    return InitialWindowBounds{work_area.left + (work_width - width) / 2,
                               work_area.top + (work_height - height) / 2, width, height};
}

COLORREF lerp_color(COLORREF from, COLORREF to, double t) noexcept {
    const auto channel = [t](int a, int b) {
        return static_cast<int>(std::lround(a + (b - a) * t));
    };
    return RGB(channel(GetRValue(from), GetRValue(to)),
               channel(GetGValue(from), GetGValue(to)),
               channel(GetBValue(from), GetBValue(to)));
}

// Cached vertical background gradient bands used by WM_PAINT and STATIC
// controls. Keep this source comment ASCII-only because this target may be
// compiled under the system code page on Chinese Windows.
HBRUSH gradient_band_brush(int band) {
    static HBRUSH band_brushes[kGradientBandCount]{};
    band = (std::max)(0, (std::min)(kGradientBandCount - 1, band));
    if (band_brushes[band] == nullptr) {
        band_brushes[band] = CreateSolidBrush(lerp_color(
            kWindowBackground, kWindowBackgroundDeep,
            (band + 0.5) / static_cast<double>(kGradientBandCount)));
    }
    return band_brushes[band];
}

int gradient_band_for_y(int y, int client_height) noexcept {
    return static_cast<int>(static_cast<long long>(y) * kGradientBandCount /
                            (std::max)(1, client_height));
}

void fill_window_gradient(HDC context, const RECT& client) {
    const int height = (std::max)(1L, client.bottom - client.top);
    for (int band = 0; band < kGradientBandCount; ++band) {
        const RECT strip{client.left,
                         client.top + static_cast<LONG>(static_cast<long long>(band) * height / kGradientBandCount),
                         client.right,
                         client.top + static_cast<LONG>(static_cast<long long>(band + 1) * height / kGradientBandCount)};
        FillRect(context, &strip, gradient_band_brush(band));
    }
}

// Header divider: one bright line plus a soft glow fading into the background.
void draw_aurora_divider(HDC context, int x0, int x1, int y, double scale) {
    constexpr int kSegments = 48;
    const int thickness = (std::max)(1, static_cast<int>(std::lround(1.0 * scale)));
    for (int pass = 0; pass < 2; ++pass) {
        const int offset = pass == 0 ? 0 : thickness * 2;
        for (int segment = 0; segment < kSegments; ++segment) {
            const double t = (segment + 0.5) / kSegments;
            COLORREF color = lerp_color(kAccent, kWindowBackground, t * t);
            if (pass == 1) color = lerp_color(color, kWindowBackground, 0.62);
            HBRUSH brush = CreateSolidBrush(color);
            const RECT strip{x0 + (x1 - x0) * segment / kSegments, y + offset,
                             x0 + (x1 - x0) * (segment + 1) / kSegments, y + offset + thickness};
            FillRect(context, &strip, brush);
            DeleteObject(brush);
        }
    }
}

// Status dot: a solid core plus a soft glow fading into the background.
void draw_status_dot(HDC context, const RECT& area, COLORREF color, double scale) {
    const int glow = (std::max)(2, static_cast<int>(std::lround(4.0 * scale)));
    HBRUSH glow_brush = CreateSolidBrush(lerp_color(color, kWindowBackground, 0.72));
    HGDIOBJ old_brush = SelectObject(context, glow_brush);
    HPEN glow_pen = CreatePen(PS_SOLID, 1, lerp_color(color, kWindowBackground, 0.72));
    HGDIOBJ old_pen = SelectObject(context, glow_pen);
    Ellipse(context, area.left - glow, area.top - glow, area.right + glow, area.bottom + glow);
    SelectObject(context, old_pen);
    SelectObject(context, old_brush);
    DeleteObject(glow_pen);
    DeleteObject(glow_brush);
    HBRUSH core_brush = CreateSolidBrush(color);
    old_brush = SelectObject(context, core_brush);
    HPEN core_pen = CreatePen(PS_SOLID, 1, color);
    old_pen = SelectObject(context, core_pen);
    Ellipse(context, area.left, area.top, area.right, area.bottom);
    SelectObject(context, old_pen);
    SelectObject(context, old_brush);
    DeleteObject(core_pen);
    DeleteObject(core_brush);
}

// Rounded vertical gradient fill: clips to the panel's rounded rect and
// paints interpolated bands so the surface reads as lit from above.
void fill_rounded_gradient(HDC context, const RECT& area, COLORREF top, COLORREF bottom,
                           double scale, double logical_radius) {
    const int radius = (std::max)(8, static_cast<int>(std::lround(logical_radius * scale)));
    HRGN region = CreateRoundRectRgn(area.left, area.top, area.right, area.bottom, radius, radius);
    if (region == nullptr) return;
    SelectClipRgn(context, region);
    constexpr int kBands = 40;
    const int height = (std::max)(1L, area.bottom - area.top);
    for (int band = 0; band < kBands; ++band) {
        HBRUSH brush = CreateSolidBrush(
            lerp_color(top, bottom, (band + 0.5) / static_cast<double>(kBands)));
        const RECT strip{area.left,
                         area.top + static_cast<LONG>(static_cast<long long>(band) * height / kBands),
                         area.right,
                         area.top + static_cast<LONG>(static_cast<long long>(band + 1) * height / kBands)};
        FillRect(context, &strip, brush);
        DeleteObject(brush);
    }
    SelectClipRgn(context, nullptr);
    DeleteObject(region);
}

void draw_panel(HDC context, const RECT& area, double scale) {
    // Aurora surface: light violet-grey crown falling into the panel base.
    fill_rounded_gradient(context, area, RGB(0x18, 0x1F, 0x2C), kPanelBackground, scale, 12.0);
    HPEN border = CreatePen(PS_SOLID, 1, kPanelOutline);
    HGDIOBJ old_pen = SelectObject(context, border);
    HGDIOBJ old_brush = SelectObject(context, GetStockObject(HOLLOW_BRUSH));
    const int radius = (std::max)(8, static_cast<int>(std::lround(12.0 * scale)));
    RoundRect(context, area.left, area.top, area.right, area.bottom, radius, radius);
    // Top inner highlight: one soft bright row under the crown edge.
    HPEN highlight = CreatePen(PS_SOLID, 1, RGB(0x30, 0x3A, 0x4E));
    SelectObject(context, highlight);
    const int inset = (std::max)(2, static_cast<int>(std::lround(3.0 * scale)));
    MoveToEx(context, area.left + radius, area.top + inset, nullptr);
    LineTo(context, area.right - radius, area.top + inset);
    SelectObject(context, old_pen);
    SelectObject(context, old_brush);
    DeleteObject(highlight);
    DeleteObject(border);
}

void draw_rounded_surface(HDC context, const RECT& area, double scale, COLORREF fill_color,
                          COLORREF outline_color, double logical_radius) {
    HBRUSH fill = CreateSolidBrush(fill_color);
    HPEN border = CreatePen(PS_SOLID, 1, outline_color);
    HGDIOBJ old_brush = SelectObject(context, fill);
    HGDIOBJ old_pen = SelectObject(context, border);
    const int radius = (std::max)(8, static_cast<int>(std::lround(logical_radius * scale)));
    RoundRect(context, area.left, area.top, area.right, area.bottom, radius, radius);
    SelectObject(context, old_brush);
    SelectObject(context, old_pen);
    DeleteObject(border);
    DeleteObject(fill);
}

void draw_row(HDC context, const RECT& area, double scale) {
    fill_rounded_gradient(context, area, RGB(0x1E, 0x26, 0x36), kRowBackground, scale, 10.0);
    HPEN border = CreatePen(PS_SOLID, 1, kRowOutline);
    HGDIOBJ old_pen = SelectObject(context, border);
    HGDIOBJ old_brush = SelectObject(context, GetStockObject(HOLLOW_BRUSH));
    const int radius = (std::max)(8, static_cast<int>(std::lround(10.0 * scale)));
    RoundRect(context, area.left, area.top, area.right, area.bottom, radius, radius);
    SelectObject(context, old_pen);
    SelectObject(context, old_brush);
    DeleteObject(border);
}

void draw_icon_tile(HDC context, HICON icon, const RECT& area, double scale, COLORREF background) {
    fill_rounded_gradient(context, area, lerp_color(background, kText, 0.10), background,
                          scale, 10.0);
    HPEN border = CreatePen(PS_SOLID, 1, lerp_color(background, kText, 0.16));
    HGDIOBJ old_pen = SelectObject(context, border);
    HGDIOBJ old_brush = SelectObject(context, GetStockObject(HOLLOW_BRUSH));
    const int radius = (std::max)(8, static_cast<int>(std::lround(10.0 * scale)));
    RoundRect(context, area.left, area.top, area.right, area.bottom, radius, radius);
    SelectObject(context, old_pen);
    SelectObject(context, old_brush);
    DeleteObject(border);
    if (icon == nullptr) return;
    const int size = (std::max)(14, static_cast<int>(std::lround(22.0 * scale)));
    const int x = area.left + ((area.right - area.left) - size) / 2;
    const int y = area.top + ((area.bottom - area.top) - size) / 2;
    DrawIconEx(context, x, y, icon, size, size, 0, nullptr, DI_NORMAL);
}

void draw_icon_circle(HDC context, HICON icon, int center_x, int center_y, int logical_size,
                      double scale, COLORREF outline) {
    const int size = static_cast<int>(std::lround(logical_size * scale));
    const int radius = size / 2;
    const COLORREF fill_color = outline == kStateHealthy ? RGB(0x26, 0x20, 0x4A) : RGB(0x1A, 0x21, 0x30);
    HBRUSH fill = CreateSolidBrush(fill_color);
    HPEN border = CreatePen(PS_SOLID, (std::max)(1, static_cast<int>(std::lround(2.0 * scale))), outline);
    HGDIOBJ old_brush = SelectObject(context, fill);
    HGDIOBJ old_pen = SelectObject(context, border);
    Ellipse(context, center_x - radius, center_y - radius, center_x + radius, center_y + radius);
    SelectObject(context, old_brush);
    SelectObject(context, old_pen);
    DeleteObject(border);
    DeleteObject(fill);
    if (icon == nullptr) return;
    const int icon_size = static_cast<int>(std::lround(24.0 * scale));
    DrawIconEx(context, center_x - icon_size / 2, center_y - icon_size / 2,
               icon, icon_size, icon_size, 0, nullptr, DI_NORMAL);
}

void draw_owner_button(const DRAWITEMSTRUCT& item, bool primary, double scale, HBRUSH background,
                       HICON leading_icon = nullptr, HICON trailing_icon = nullptr,
                       bool flat = false) {
    const bool enabled = (item.itemState & ODS_DISABLED) == 0;
    const bool pressed = (item.itemState & ODS_SELECTED) != 0;
    FillRect(item.hDC, &item.rcItem, background);
    COLORREF fill_color = !enabled ? kButtonDisabled : (primary ? kAccent : kButtonSecondary);
    if (pressed && enabled) fill_color = primary ? kAccentPressed : kButtonSecondaryPressed;
    if (primary && enabled && !flat) {
        // Aurora CTA: soft outer glow ring, vertical violet gradient, bright rim.
        const int radius = (std::max)(8, static_cast<int>(std::lround(10.0 * scale)));
        const int glow = (std::max)(2, static_cast<int>(std::lround(3.0 * scale)));
        HPEN glow_pen = CreatePen(PS_SOLID, glow, lerp_color(kAccent, kWindowBackground, 0.62));
        HGDIOBJ old_pen = SelectObject(item.hDC, glow_pen);
        HGDIOBJ old_brush = SelectObject(item.hDC, GetStockObject(HOLLOW_BRUSH));
        RoundRect(item.hDC, item.rcItem.left - 1, item.rcItem.top - 1,
                  item.rcItem.right + 1, item.rcItem.bottom + 1, radius, radius);
        SelectObject(item.hDC, old_pen);
        SelectObject(item.hDC, old_brush);
        DeleteObject(glow_pen);
        fill_rounded_gradient(item.hDC, item.rcItem,
                              pressed ? kAccent : kAccentHover,
                              pressed ? kAccentPressed : kAccent, scale, 10.0);
        HPEN rim = CreatePen(PS_SOLID, 1, kAccentHover);
        old_pen = SelectObject(item.hDC, rim);
        old_brush = SelectObject(item.hDC, GetStockObject(HOLLOW_BRUSH));
        RoundRect(item.hDC, item.rcItem.left, item.rcItem.top, item.rcItem.right,
                  item.rcItem.bottom, radius, radius);
        SelectObject(item.hDC, old_pen);
        SelectObject(item.hDC, old_brush);
        DeleteObject(rim);
    } else if (!flat || pressed) {
        HBRUSH fill = CreateSolidBrush(fill_color);
        HPEN border = CreatePen(PS_SOLID, 1, primary && enabled ? kAccentHover : kPanelOutline);
        HGDIOBJ old_brush = SelectObject(item.hDC, fill);
        HGDIOBJ old_pen = SelectObject(item.hDC, border);
        const int radius = (std::max)(8, static_cast<int>(std::lround(10.0 * scale)));
        RoundRect(item.hDC, item.rcItem.left, item.rcItem.top, item.rcItem.right,
                  item.rcItem.bottom, radius, radius);
        SelectObject(item.hDC, old_brush);
        SelectObject(item.hDC, old_pen);
        DeleteObject(border);
        DeleteObject(fill);
    }
    SetBkMode(item.hDC, TRANSPARENT);
    SetTextColor(item.hDC, !enabled ? kStateIdle : (primary ? RGB(255, 255, 255) : kText));
    wchar_t text[64]{};
    GetWindowTextW(item.hwndItem, text, 64);
    HFONT font = reinterpret_cast<HFONT>(SendMessageW(item.hwndItem, WM_GETFONT, 0, 0));
    HGDIOBJ old_font = font == nullptr ? nullptr : SelectObject(item.hDC, font);
    RECT text_area = item.rcItem;
    const int icon_size = (std::max)(14, static_cast<int>(std::lround(20.0 * scale)));
    const int icon_gap = (std::max)(6, static_cast<int>(std::lround(9.0 * scale)));
    SIZE text_size{};
    GetTextExtentPoint32W(item.hDC, text, static_cast<int>(wcslen(text)), &text_size);
    if (leading_icon != nullptr) {
        const int content_width = icon_size + icon_gap + text_size.cx;
        const int icon_x = item.rcItem.left + ((item.rcItem.right - item.rcItem.left) - content_width) / 2;
        const int icon_y = item.rcItem.top + ((item.rcItem.bottom - item.rcItem.top) - icon_size) / 2;
        DrawIconEx(item.hDC, icon_x, icon_y, leading_icon, icon_size, icon_size, 0, nullptr, DI_NORMAL);
        text_area.left = icon_x + icon_size + icon_gap;
        text_area.right = text_area.left + text_size.cx;
    }
    if (trailing_icon != nullptr) {
        const int icon_x = item.rcItem.right - icon_size - static_cast<int>(std::lround(14.0 * scale));
        const int icon_y = item.rcItem.top + ((item.rcItem.bottom - item.rcItem.top) - icon_size) / 2;
        DrawIconEx(item.hDC, icon_x, icon_y, trailing_icon, icon_size, icon_size, 0, nullptr, DI_NORMAL);
    }
    DrawTextW(item.hDC, text, -1, &text_area, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    if (old_font != nullptr) SelectObject(item.hDC, old_font);
    if ((item.itemState & ODS_FOCUS) != 0) {
        RECT focus = item.rcItem;
        const int inset = (std::max)(3, static_cast<int>(std::lround(4.0 * scale)));
        InflateRect(&focus, -inset, -inset);
        DrawFocusRect(item.hDC, &focus);
    }
}

}  // namespace

StreamerDesktopApp::~StreamerDesktopApp() noexcept {
    shutdown_background_runtime();
}

void StreamerDesktopApp::shutdown_background_runtime() noexcept {
    if (background_shutdown_done_) return;
    background_shutdown_done_ = true;
    cancel_mobile_refresh_probe();
    ++startup_generation_;
    runtime_service_.request_stop();
    runtime_service_.stop();
    safe_join_thread(startup_thread_);
    isolated_dhcp_server_.stop();
    runtime_service_.restore_direct_link_on_clean_shutdown();
}

int StreamerDesktopApp::run(HINSTANCE instance, bool acceptance_autostart) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.hInstance = instance;
    window_class.lpszClassName = kWindowClassName;
    window_class.lpfnWndProc = window_proc;
    window_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    window_class.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_VF_APP));
    window_class.hIconSm = window_class.hIcon;
    RegisterClassExW(&window_class);

    const InitialWindowBounds bounds = choose_initial_window_bounds();
    HWND window = CreateWindowExW(0, kWindowClassName, L"VF Host", kWindowStyle,
                                  bounds.x, bounds.y, bounds.width, bounds.height,
                                  nullptr, nullptr, instance, this);
    if (window == nullptr) return 1;
    const BOOL use_dark_title_bar = TRUE;
    constexpr DWORD kUseImmersiveDarkMode = 20;
    DwmSetWindowAttribute(window, kUseImmersiveDarkMode, &use_dark_title_bar,
                          sizeof(use_dark_title_bar));
    constexpr DWORD kWindowCornerPreference = 33;
    constexpr DWORD kRoundWindowCorners = 2;
    DwmSetWindowAttribute(window, kWindowCornerPreference, &kRoundWindowCorners,
                          sizeof(kRoundWindowCorners));
    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);
    initialize_display_selection();
    if (acceptance_autostart) {
        acceptance_autostart_ = true;
        // Release-only acceptance hook: exercise the same WM_COMMAND path as
        // the visible button after an interactive desktop has been created.
        const BOOL posted = PostMessageW(window, kAcceptanceAutostartMessage, 0, 0);
        log_host_runtime_event(
            "host_gui_acceptance_autostart_posted",
            std::string{"posted="} + (posted ? "1" : "0") +
                " win32_error=" + std::to_string(posted ? 0U : GetLastError()));
    }
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}

LRESULT CALLBACK StreamerDesktopApp::window_proc(HWND window, UINT message, WPARAM w_param, LPARAM l_param) {
    if (message == WM_NCCREATE) {
        const auto* creation = reinterpret_cast<const CREATESTRUCTW*>(l_param);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(creation->lpCreateParams));
    }
    auto* application = reinterpret_cast<StreamerDesktopApp*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    return application == nullptr ? DefWindowProcW(window, message, w_param, l_param)
                                  : application->handle_message(window, message, w_param, l_param);
}

LRESULT StreamerDesktopApp::handle_message(HWND window, UINT message, WPARAM w_param, LPARAM l_param) {
    switch (message) {
        case WM_CREATE:
            window_ = window;
            create_controls(window);
            layout_controls();
            return 0;
        case WM_SIZE:
            layout_controls();
            InvalidateRect(window, nullptr, FALSE);
            return 0;
        case WM_GETMINMAXINFO: {
            auto* limits = reinterpret_cast<MINMAXINFO*>(l_param);
            const HostClientSize minimum_client = host_minimum_readable_client_size();
            RECT minimum_outer{0, 0, minimum_client.width, minimum_client.height};
            const UINT dpi = (std::max)(96U, GetDpiForWindow(window));
            if (!AdjustWindowRectExForDpi(&minimum_outer, kWindowStyle, FALSE, 0, dpi)) {
                AdjustWindowRectEx(&minimum_outer, kWindowStyle, FALSE, 0);
            }
            limits->ptMinTrackSize.x = minimum_outer.right - minimum_outer.left;
            limits->ptMinTrackSize.y = minimum_outer.bottom - minimum_outer.top;
            return 0;
        }
        case WM_DPICHANGED: {
            const auto* suggested = reinterpret_cast<const RECT*>(l_param);
            SetWindowPos(window, nullptr, suggested->left, suggested->top,
                         suggested->right - suggested->left, suggested->bottom - suggested->top,
                         SWP_NOACTIVATE | SWP_NOZORDER);
            layout_controls();
            return 0;
        }
        case WM_PAINT: {
            PAINTSTRUCT paint{};
            HDC target_context = BeginPaint(window, &paint);
            RECT client{};
            GetClientRect(window, &client);
            HDC buffer_context = CreateCompatibleDC(target_context);
            HBITMAP buffer_bitmap = CreateCompatibleBitmap(
                target_context, (std::max)(1L, client.right - client.left),
                (std::max)(1L, client.bottom - client.top));
            HGDIOBJ old_buffer_bitmap = nullptr;
            HDC context = target_context;
            if (buffer_context != nullptr && buffer_bitmap != nullptr) {
                old_buffer_bitmap = SelectObject(buffer_context, buffer_bitmap);
                context = buffer_context;
            }
            fill_window_gradient(context, client);
            const COLORREF phase_color = host_ui_phase_color(ui_phase_);
            const auto icon = [this](IconRole role) {
                return icons_[static_cast<std::size_t>(role)];
            };
            const RECT header_line = transform_rect(RECT{24, 66, kHostLogicalClientWidth - 24, 66});
            draw_aurora_divider(context, header_line.left, header_line.right, header_line.top,
                                layout_scale_);

            const RECT status_dot = transform_rect(logical_rect(kHostHeaderStatusDot));
            draw_status_dot(context, status_dot, phase_color, layout_scale_);

            draw_panel(context, transform_rect(RECT{24, 82, 638, 592}), layout_scale_);
            draw_panel(context, transform_rect(RECT{650, 82, 1216, 592}), layout_scale_);
            draw_panel(context, transform_rect(RECT{24, 606, 638, 808}), layout_scale_);
            draw_panel(context, transform_rect(RECT{650, 606, 1216, 808}), layout_scale_);

            draw_icon_tile(context, icon(IconRole::display), transform_rect(RECT{54, 232, 96, 274}),
                           layout_scale_, RGB(0x26, 0x20, 0x4A));
            draw_icon_tile(context, icon(IconRole::encoder), transform_rect(RECT{54, 298, 96, 340}),
                           layout_scale_, RGB(0x22, 0x1E, 0x46));
            draw_icon_tile(context, icon(IconRole::phone), transform_rect(RECT{54, 364, 96, 406}),
                           layout_scale_, RGB(0x24, 0x1F, 0x48));
            draw_icon_tile(context, icon(IconRole::link), transform_rect(RECT{54, 430, 96, 472}),
                           layout_scale_, RGB(0x20, 0x1C, 0x42));
            for (const int center_y : {253, 319, 385, 451}) {
                const RECT marker = transform_rect(RECT{582, center_y - 10, 602, center_y + 10});
                if (ui_phase_ == HostUiPhase::streaming) {
                    DrawIconEx(context, marker.left, marker.top, icon(IconRole::check),
                               marker.right - marker.left, marker.bottom - marker.top,
                               0, nullptr, DI_NORMAL);
                } else {
                    HBRUSH marker_brush = CreateSolidBrush(phase_color);
                    HGDIOBJ old_marker_brush = SelectObject(context, marker_brush);
                    HPEN marker_pen = CreatePen(PS_SOLID, 1, phase_color);
                    HGDIOBJ old_marker_pen = SelectObject(context, marker_pen);
                    const int inset = (std::max)(3, static_cast<int>(std::lround(5.0 * layout_scale_)));
                    Ellipse(context, marker.left + inset, marker.top + inset,
                            marker.right - inset, marker.bottom - inset);
                    SelectObject(context, old_marker_pen);
                    SelectObject(context, old_marker_brush);
                    DeleteObject(marker_pen);
                    DeleteObject(marker_brush);
                }
            }

            const int metric_rows[] = {140, 224, 308, 392};
            const COLORREF metric_tile_colors[] = {
                RGB(0x2C, 0x24, 0x52), RGB(0x28, 0x21, 0x50), RGB(0x25, 0x1F, 0x4E), RGB(0x34, 0x24, 0x56)};
            const IconRole metric_icons[] = {
                IconRole::capture, IconRole::video, IconRole::send, IconRole::link};
            for (int index = 0; index < 4; ++index) {
                const int y = metric_rows[index];
                draw_row(context, transform_rect(RECT{666, y, 1196, y + 68}), layout_scale_);
                draw_icon_tile(context, icon(metric_icons[index]), transform_rect(RECT{680, y + 13, 722, y + 55}),
                               layout_scale_, metric_tile_colors[index]);
            }
            draw_rounded_surface(context, transform_rect(RECT{666, 480, 1196, 560}), layout_scale_,
                                 kSummaryBackground, kSummaryOutline, 10.0);
            draw_icon_tile(context, icon(IconRole::pulse), transform_rect(RECT{684, 500, 722, 538}),
                           layout_scale_, RGB(0x2A, 0x21, 0x50));
            const RECT lock_icon = transform_rect(RECT{176, 555, 190, 569});
            DrawIconEx(context, lock_icon.left, lock_icon.top, icon(IconRole::lock),
                       lock_icon.right - lock_icon.left, lock_icon.bottom - lock_icon.top,
                       0, nullptr, DI_NORMAL);

            HPEN route_pen = CreatePen(PS_SOLID,
                                       (std::max)(1, static_cast<int>(std::lround(3.0 * layout_scale_))),
                                       phase_color);
            HGDIOBJ old_pen = SelectObject(context, route_pen);
            const RECT route = transform_rect(RECT{112, 684, 550, 684});
            MoveToEx(context, route.left, route.top, nullptr);
            LineTo(context, route.right, route.bottom);
            SelectObject(context, old_pen);
            DeleteObject(route_pen);
            draw_rounded_surface(context, transform_rect(RECT{196, 672, 276, 698}), layout_scale_,
                                 kPanelBackground, kPanelOutline, 6.0);
            draw_rounded_surface(context, transform_rect(RECT{415, 672, 495, 698}), layout_scale_,
                                 kPanelBackground, kPanelOutline, 6.0);
            for (const auto [center_x, role] : {std::pair{112, IconRole::display},
                                                std::pair{331, IconRole::link},
                                                std::pair{550, IconRole::phone}}) {
                const RECT center = transform_rect(RECT{center_x, 684, center_x, 684});
                draw_icon_circle(context, icon(role), center.left, center.top, 48,
                                 layout_scale_, phase_color);
            }
            if (!settings_panel_visible_) {
                const int visible_event_count = static_cast<int>((std::min)(recent_events_.size(), std::size_t{5}));
                for (int row = 0; row < visible_event_count; ++row) {
                    const RECT event_icon = transform_rect(RECT{670, 662 + row * 24, 686, 678 + row * 24});
                    DrawIconEx(context, event_icon.left, event_icon.top, icon(IconRole::check),
                               event_icon.right - event_icon.left, event_icon.bottom - event_icon.top,
                               0, nullptr, DI_NORMAL);
                }
            }
            if (context == buffer_context) {
                BitBlt(target_context, 0, 0, client.right - client.left,
                       client.bottom - client.top, buffer_context, 0, 0, SRCCOPY);
                SelectObject(buffer_context, old_buffer_bitmap);
            }
            if (buffer_bitmap != nullptr) DeleteObject(buffer_bitmap);
            if (buffer_context != nullptr) DeleteDC(buffer_context);
            EndPaint(window, &paint);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(w_param) == kStartButtonId) start_streamer(window);
            if (LOWORD(w_param) == kStopButtonId) stop_streamer();
            if (LOWORD(w_param) == kDiagnosticsButtonId) open_diagnostics();
            if (LOWORD(w_param) == kSettingsButtonId) set_settings_panel_visible(!settings_panel_visible_);
            if (LOWORD(w_param) == kCloseSettingsButtonId) set_settings_panel_visible(false);
            if (LOWORD(w_param) == kRefreshDisplaysButtonId) refresh_display_selection();
            if (LOWORD(w_param) == kRefreshMobileButtonId) refresh_mobile_device();
            if (LOWORD(w_param) == kClearEventsButtonId) {
                recent_events_.clear();
                update_event_text();
            }
            return 0;
        case kAcceptanceAutostartMessage:
            log_host_runtime_event("host_gui_acceptance_autostart_received");
            start_streamer(window);
            return 0;
        case kMobileRefreshCompletedMessage: {
            const std::unique_ptr<MobileRefreshResult> result(reinterpret_cast<MobileRefreshResult*>(l_param));
            if (result == nullptr) return 0;
            const bool generation_matches = result->generation == mobile_refresh_generation_;
            safe_join_thread(mobile_refresh_thread_);
            mark_mobile_refresh_idle();
            EnableWindow(refresh_mobile_button_, TRUE);
            if (!generation_matches) {
                if (start_after_mobile_refresh_cancel_) {
                    start_after_mobile_refresh_cancel_ = false;
                    append_event(L"空闲端点检测已取消：继续正式启动传输");
                    start_streamer(window);
                    return 0;
                }
                set_ui_phase(HostUiPhase::idle);
                update_action_state(runtime_service_.is_running(), false);
                set_status(L"手机端点检测已取消。");
                return 0;
            }
            start_after_mobile_refresh_cancel_ = false;
            set_ui_phase(HostUiPhase::idle);
            if (!result->mobile.has_value()) {
                mobile_reachable_ = false;
                apply_idle_ui_state(HostIdleEndpointState::unreachable);
                set_status(L"端点检测完成：主机未在传输，且未收到手机链路响应。");
                append_event(L"端点检测完成：手机未响应");
            } else {
                mobile_reachable_ = true;
                apply_idle_ui_state(HostIdleEndpointState::reachable);
                set_status(L"主机传输已停止；手机传输端点已就绪，可继续启动。");
                append_event(L"端点检测完成：VF Mobile 已响应");
            }
            return 0;
        }
        case kStartupCompletedMessage: {
            const std::unique_ptr<StartupResult> result(reinterpret_cast<StartupResult*>(l_param));
            if (result == nullptr) return 0;
            if (result->generation != startup_generation_) {
                safe_join_thread(startup_thread_);
                starting_ = false;
                set_ui_phase(HostUiPhase::idle);
                clear_runtime_metrics();
                update_action_state(false, false);
                SetWindowTextW(ready_state_text_, L"端点检测已取消");
                SetWindowTextW(ready_detail_text_, L"等待重新开始");
                SetWindowTextW(phone_state_text_, L"VF Mobile\u00b7 \u7b49\u5f85\u54cd\u5e94");
                set_status(L"启动已取消，手机端点等待已结束。");
                append_event(L"启动已取消：手机端点检测已停止");
                return 0;
            }
            if (!starting_) return 0;
            starting_ = false;
            safe_join_thread(startup_thread_);
            if (!result->started) {
                retry_not_before_ =
                    std::chrono::steady_clock::now() + std::chrono::seconds(2);
                schedule_autostart_retry(window_, acceptance_autostart_);
                set_ui_phase(HostUiPhase::failed);
                clear_runtime_metrics();
                update_action_state(false, false);
                const std::wstring summary = friendly_host_failure(result->error);
                const std::wstring technical = widen_ascii(result->error);
                SetWindowTextW(mobile_state_text_, summary.c_str());
                SetWindowTextW(ready_state_text_, L"\u4e3b\u673a\u4f20\u8f93\u672a\u542f\u52a8");
                SetWindowTextW(ready_detail_text_, summary.c_str());
                SetWindowTextW(phone_state_text_, L"VF Mobile\u00b7 \u72b6\u6001\u672a\u5224\u5b9a");
                set_status(summary + (technical.empty() ? L"" : L"\u3002\u6280\u672f\u539f\u56e0\uff1a" + technical));
                append_event(L"\u542f\u52a8\u5931\u8d25\uff1a" + summary);
                return 0;
            }
            was_running_ = true;
            retry_not_before_ = {};
            mobile_reachable_ = true;
            set_ui_phase(HostUiPhase::streaming);
            update_action_state(true, false);
            SetWindowTextW(mobile_state_text_, L"VF Mobile \u94fe\u8def\u5df2\u54cd\u5e94");
            SetWindowTextW(ready_state_text_, L"\u624b\u673a\u94fe\u8def\u5df2\u54cd\u5e94\uff0c\u4e3b\u673a\u6b63\u5728\u53d1\u9001");
            SetWindowTextW(ready_detail_text_, L"\u624b\u673a\u94fe\u8def\u63a2\u9488\u5728\u7ebf\u00b7 \u4e3b\u673a UDP \u6b63\u5728\u53d1\u9001\u00b7 \u624b\u673a\u89c6\u9891\u63a5\u6536\u72b6\u6001\u5f85\u786e\u8ba4");
            SetWindowTextW(phone_state_text_, L"VF Mobile\u00b7 \u94fe\u8def\u5df2\u54cd\u5e94");
            set_status(L"\u4e3b\u673a\u53d1\u9001\u5df2\u542f\u52a8\uff1a\u753b\u9762\u662f\u5426\u5df2\u63a5\u6536\u4e0e\u6e32\u67d3\uff0c\u4ee5\u624b\u673a\u7aef\u72b6\u6001\u4e3a\u51c6\u3002");
            append_event(L"\u4e3b\u673a\u53d1\u9001\u5df2\u542f\u52a8\uff1a\u624b\u673a\u94fe\u8def\u63a2\u9488\u5df2\u54cd\u5e94");
            return 0;
        }
        case WM_TIMER:
            if (w_param == kRefreshTimerId) refresh_status();
            if (w_param == kAutostartRetryTimerId) {
                KillTimer(window, kAutostartRetryTimerId);
                if (acceptance_autostart_ && !starting_ &&
                    !runtime_service_.is_running()) {
                    start_streamer(window);
                }
            }
            return 0;
        case WM_DRAWITEM: {
            const auto* item = reinterpret_cast<const DRAWITEMSTRUCT*>(l_param);
            if (item->CtlID != kStartButtonId && item->CtlID != kStopButtonId &&
                item->CtlID != kDiagnosticsButtonId && item->CtlID != kSettingsButtonId &&
                item->CtlID != kClearEventsButtonId &&
                item->CtlID != kRefreshDisplaysButtonId &&
                item->CtlID != kRefreshMobileButtonId &&
                item->CtlID != kCloseSettingsButtonId) break;
            const auto icon = [this](IconRole role) {
                return icons_[static_cast<std::size_t>(role)];
            };
            const bool is_primary = item->CtlID == kStartButtonId;
            const bool is_header_action = item->CtlID == kDiagnosticsButtonId ||
                                          item->CtlID == kSettingsButtonId;
            HICON leading = nullptr;
            HICON trailing = nullptr;
            if (item->CtlID == kStartButtonId) leading = icon(IconRole::play);
            if (item->CtlID == kSettingsButtonId) leading = icon(IconRole::settings);
            if (item->CtlID == kClearEventsButtonId) leading = icon(IconRole::trash);
            if (item->CtlID == kDiagnosticsButtonId) trailing = icon(IconRole::chevron);
            draw_owner_button(*item, is_primary, layout_scale_,
                               is_header_action ? background_brush_ : panel_background_brush_,
                               leading, trailing, item->CtlID == kSettingsButtonId);
            return TRUE;
        }
        case WM_ERASEBKGND: {
            // WM_PAINT renders the parent surface through a memory DC. Avoid a
            // second full-window erase that made resize/settings transitions flash.
            return 1;
        }
        case WM_CTLCOLORSTATIC:
            SetTextColor(reinterpret_cast<HDC>(w_param), kText);
            SetBkMode(reinterpret_cast<HDC>(w_param), TRANSPARENT);
            for (const ControlPlacement& placement : control_placements_) {
                if (placement.handle == reinterpret_cast<HWND>(l_param)) {
                    COLORREF color = kText;
                    switch (placement.text_role) {
                        case TextRole::primary: color = kText; break;
                        case TextRole::muted: color = kMutedText; break;
                        case TextRole::positive: color = kStateHealthy; break;
                        case TextRole::capture: color = kCaptureAccent; break;
                        case TextRole::encode: color = kEncodeAccent; break;
                        case TextRole::publish: color = kPublishAccent; break;
                        case TextRole::link: color = kLinkAccent; break;
                    }
                    SetTextColor(reinterpret_cast<HDC>(w_param), color);
                    switch (placement.surface_role) {
                        case SurfaceRole::window: {
                            // The window background is a vertical gradient: pick
                            // the band brush at the control center so the STATIC
                            // background matches the gradient underneath it.
                            RECT control_rect{};
                            GetWindowRect(placement.handle, &control_rect);
                            MapWindowPoints(nullptr, window_,
                                            reinterpret_cast<POINT*>(&control_rect), 2);
                            RECT client_rect{};
                            GetClientRect(window_, &client_rect);
                            const int center_y = static_cast<int>(
                                (control_rect.top + control_rect.bottom) / 2 - client_rect.top);
                            return reinterpret_cast<LRESULT>(gradient_band_brush(
                                gradient_band_for_y(center_y,
                                                    static_cast<int>(client_rect.bottom - client_rect.top))));
                        }
                        case SurfaceRole::panel:
                        case SurfaceRole::transparent:
                            return reinterpret_cast<LRESULT>(panel_background_brush_);
                        case SurfaceRole::row:
                            return reinterpret_cast<LRESULT>(row_background_brush_);
                        case SurfaceRole::summary:
                            return reinterpret_cast<LRESULT>(summary_background_brush_);
                    }
                }
            }
            return reinterpret_cast<LRESULT>(background_brush_);
        case WM_CLOSE:
            shutdown_background_runtime();
            DestroyWindow(window);
            return 0;
        case WM_ENDSESSION:
            if (w_param != FALSE) shutdown_background_runtime();
            return 0;
        case WM_DESTROY:
            KillTimer(window, kRefreshTimerId);
            KillTimer(window, kAutostartRetryTimerId);
            DeleteObject(regular_font_);
            DeleteObject(title_font_);
            DeleteObject(caption_font_);
            DeleteObject(small_font_);
            DeleteObject(section_font_);
            DeleteObject(hero_font_);
            DeleteObject(metric_font_);
            DeleteObject(background_brush_);
            DeleteObject(panel_background_brush_);
            DeleteObject(row_background_brush_);
            DeleteObject(summary_background_brush_);
            release_ui_icons();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(window, message, w_param, l_param);
}

void StreamerDesktopApp::create_controls(HWND window) {
    background_brush_ = CreateSolidBrush(kWindowBackground);
    panel_background_brush_ = CreateSolidBrush(kPanelBackground);
    row_background_brush_ = CreateSolidBrush(kRowBackground);
    summary_background_brush_ = CreateSolidBrush(kSummaryBackground);
    load_ui_icons();
    recreate_fonts(1.0);
    const HostIdleUiText initial_idle =
        host_idle_ui_text(HostIdleEndpointState::not_checked);
    add_static(window, L"VF  HOST", logical_rect(24, 21, 280, 30), FontRole::caption,
               SurfaceRole::window, TextRole::positive);
    ready_state_text_ = add_static(window, initial_idle.ready_state.data(),
                                   logical_rect(kHostHeaderStatusText), FontRole::caption,
                                   SurfaceRole::window, TextRole::primary, SS_LEFT);
    ready_detail_text_ = add_static(window, initial_idle.ready_detail.data(),
                                    logical_rect(580, 39, 300, 20), FontRole::small,
                                     SurfaceRole::window, TextRole::muted, SS_LEFT);
    settings_button_ = add_button(window, L"\u8bbe\u7f6e", kSettingsButtonId,
                                  logical_rect(978, 14, 80, 42));
    diagnostics_button_ = add_button(window, L"\u8bca\u65ad\u4e0e\u65e5\u5fd7", kDiagnosticsButtonId,
                                     logical_rect(1068, 14, 148, 42));

    add_static(window, L"自动发现手机端点，零配置使用", logical_rect(54, 108, 330, 24),
               FontRole::caption, SurfaceRole::transparent, TextRole::positive);
    mobile_state_text_ = add_static(window, initial_idle.hero.data(),
                                    logical_rect(54, 143, 530, 48), FontRole::hero,
                                    SurfaceRole::transparent);
    add_static(window, L"自动选屏与编码，仅发送桌面画面；主机不参与控制。",
               logical_rect(54, 196, 530, 30), FontRole::small,
               SurfaceRole::transparent, TextRole::muted);

    add_static(window, L"\u7cfb\u7edf\u4e3b\u5c4f\uff08\u5df2\u81ea\u52a8\u9009\u62e9\uff09", logical_rect(112, 230, 430, 22),
               FontRole::caption, SurfaceRole::transparent);
    display_state_text_ = add_static(window, L"\u6b63\u5728\u8bc6\u522b Windows \u6d3b\u52a8\u663e\u793a\u5668",
                                     logical_rect(112, 254, 470, 20), FontRole::small,
                                     SurfaceRole::transparent, TextRole::muted);
    add_static(window, L"\u7f16\u7801\u5668\uff08\u81ea\u52a8\u9009\u62e9\uff09", logical_rect(112, 296, 430, 22),
               FontRole::caption, SurfaceRole::transparent);
    encoder_state_text_ = add_static(window, initial_idle.encoder.data(),
                                     logical_rect(112, 320, 445, 20), FontRole::small,
                                     SurfaceRole::transparent, TextRole::muted);
    add_static(window, L"手机（自动端点检测）", logical_rect(112, 362, 430, 22),
               FontRole::caption, SurfaceRole::transparent);
    phone_state_text_ = add_static(window, initial_idle.phone.data(),
                                   logical_rect(112, 386, 445, 20), FontRole::small,
                                   SurfaceRole::transparent, TextRole::muted);
    add_static(window, L"\u5f53\u524d\u94fe\u8def", logical_rect(112, 428, 430, 22),
               FontRole::caption, SurfaceRole::transparent);
    link_state_text_ = add_static(window, initial_idle.link.data(),
                                  logical_rect(112, 452, 445, 20), FontRole::small,
                                  SurfaceRole::transparent, TextRole::muted);
    start_button_ = add_button(window, L"\u5f00\u59cb\u4f20\u8f93", kStartButtonId,
                               logical_rect(46, 488, 570, 56));
    stop_button_ = add_button(window, L"\u505c\u6b62\u4f20\u8f93", kStopButtonId,
                              logical_rect(46, 488, 570, 56));
    update_action_state(false, false);
    add_static(window, L"\u70b9\u51fb\u5f00\u59cb\u540e\u4ec5\u4f20\u8f93\u89c6\u9891\uff0c\u4e0d\u53d1\u9001\u4efb\u4f55\u63a7\u5236\u6307\u4ee4",
               logical_rect(198, 552, 360, 20), FontRole::small,
               SurfaceRole::transparent, TextRole::muted);

    add_static(window, L"\u5b9e\u65f6\u6307\u6807", logical_rect(666, 102, 220, 28), FontRole::section,
               SurfaceRole::transparent);
    add_static(window, L"\u8d8a\u4f4e\u8d8a\u597d / \u8d8a\u9ad8\u8d8a\u597d", logical_rect(802, 105, 190, 22), FontRole::small,
               SurfaceRole::transparent, TextRole::muted);
    add_static(window, L"\u5b9e\u6d4b\u901f\u7387\u00b7 \u65e0\u56fa\u5b9a\u4e0a\u9650", logical_rect(997, 103, 190, 24),
               FontRole::caption, SurfaceRole::transparent, TextRole::positive);
    capture_metric_ = add_metric_row(window, 140, L"\u6355\u83b7", L"DXGI \u91c7\u96c6\u5ef6\u8fdf (ms)", TextRole::capture);
    encode_metric_ = add_metric_row(window, 224, L"\u7f16\u7801", L"H.264 \u7f16\u7801\u5ef6\u8fdf (ms)", TextRole::encode);
    publish_metric_ = add_metric_row(window, 308, L"\u53d1\u9001", L"UDP \u53d1\u5e03\u5ef6\u8fdf (ms)", TextRole::publish);
    link_metric_ = add_metric_row(window, 392, L"\u94fe\u8def", L"\u7f51\u7edc\u5f80\u8fd4\u5ef6\u8fdf (ms)", TextRole::link);
    add_static(window, L"\u5f53\u524d\u5b9e\u6d4b\u8f93\u51fa", logical_rect(kHostSummaryOutputLabel), FontRole::small,
               SurfaceRole::summary, TextRole::muted);
    output_rate_value_ = add_static(window, L"-- FPS", logical_rect(kHostSummaryOutputValue), FontRole::metric,
                                    SurfaceRole::summary, TextRole::positive);
    add_static(window, L"P95 \u8f93\u51fa\u901f\u7387", logical_rect(kHostSummaryP95Label), FontRole::small,
               SurfaceRole::summary, TextRole::muted);
    output_rate_p95_value_ = add_static(window, L"-- FPS", logical_rect(kHostSummaryP95Value), FontRole::metric,
                                        SurfaceRole::summary);
    bandwidth_text_ = add_static(window, L"\u63a2\u9488 -- Mbps", logical_rect(kHostSummaryProbeValue), FontRole::small,
                                 SurfaceRole::summary, TextRole::muted);
    add_static(window, L"\u5b9e\u6d4b\u901f\u7387\u4f1a\u968f\u753b\u9762\u590d\u6742\u5ea6\u3001\u5206\u8fa8\u7387\u548c\u7f51\u7edc\u72b6\u51b5\u52a8\u6001\u53d8\u5316\u3002",
               logical_rect(738, 538, 410, 18), FontRole::small,
               SurfaceRole::summary, TextRole::muted);

    add_static(window, L"\u4f20\u8f93\u94fe\u8def\u72b6\u6001", logical_rect(48, 624, 260, 28), FontRole::section,
               SurfaceRole::transparent);
    add_static(window, L"\u4e3b\u673a", logical_rect(57, 716, 110, 20), FontRole::caption,
               SurfaceRole::transparent, TextRole::primary, SS_CENTER);
    add_static(window, L"链路", logical_rect(276, 716, 110, 20), FontRole::caption,
               SurfaceRole::transparent, TextRole::primary, SS_CENTER);
    add_static(window, L"\u624b\u673a", logical_rect(495, 716, 110, 20), FontRole::caption,
               SurfaceRole::transparent, TextRole::primary, SS_CENTER);
    add_static(window, L"\u91c7\u96c6 \u00b7 \u7f16\u7801", logical_rect(47, 739, 130, 18), FontRole::small,
               SurfaceRole::transparent, TextRole::muted, SS_CENTER);
    add_static(window, L"\u4f20\u8f93\u94fe\u8def", logical_rect(266, 739, 130, 18), FontRole::small,
               SurfaceRole::transparent, TextRole::muted, SS_CENTER);
    add_static(window, L"\u63a5\u6536 \u00b7 \u63a8\u7406", logical_rect(485, 739, 130, 18), FontRole::small,
               SurfaceRole::transparent, TextRole::muted, SS_CENTER);
    topology_host_state_text_ = add_static(window, initial_idle.topology_host.data(), logical_rect(57, 761, 110, 18),
        FontRole::small, SurfaceRole::transparent, TextRole::positive, SS_CENTER);
    topology_link_state_text_ = add_static(window, initial_idle.topology_link.data(), logical_rect(276, 761, 110, 18),
        FontRole::small, SurfaceRole::transparent, TextRole::muted, SS_CENTER);
    topology_mobile_state_text_ = add_static(window, initial_idle.topology_mobile.data(), logical_rect(495, 761, 110, 18),
        FontRole::small, SurfaceRole::transparent, TextRole::muted, SS_CENTER);
    route_capture_latency_text_ = add_static(window, L"-- ms", logical_rect(196, 676, 80, 18),
        FontRole::small, SurfaceRole::transparent, TextRole::muted, SS_CENTER);
    route_network_latency_text_ = add_static(window, L"-- ms", logical_rect(415, 676, 80, 18),
        FontRole::small, SurfaceRole::transparent, TextRole::muted, SS_CENTER);
    status_text_ = add_static(window, L"等待手机端点响应后开始传输。",
                              logical_rect(48, 780, 540, 26), FontRole::small,
                              SurfaceRole::transparent, TextRole::muted);

    events_title_text_ = add_static(window, L"\u6700\u8fd1\u4e8b\u4ef6 (0)", logical_rect(670, 624, 220, 28),
                                    FontRole::section, SurfaceRole::transparent);
    clear_events_button_ = add_button(window, L"\u6e05\u7a7a", kClearEventsButtonId,
                                      logical_rect(1102, 619, 88, 34));
    events_text_ = add_static(window, L"", logical_rect(698, 661, 484, 124), FontRole::small,
                              SurfaceRole::transparent, TextRole::muted);
    event_panel_controls_ = {events_title_text_, clear_events_button_, events_text_};

    settings_title_text_ = add_static(window, L"设置与手机连接", logical_rect(670, 624, 300, 28),
                                      FontRole::section, SurfaceRole::transparent);
    settings_description_text_ = add_static(window,
        L"Host 只采集、编码并推送屏幕画面；授权、计费和保护全部由安卓端完成。\r\n"
        L"Host 不保存卡密、不验票、不持有租约。",
        logical_rect(670, 654, 520, 42), FontRole::small, SurfaceRole::transparent, TextRole::muted);
    settings_contract_text_ = add_static(window, L"CAT6 有线优先 · 不可用时自动回退无线局域网 UDP",
        logical_rect(670, 700, 520, 22), FontRole::caption, SurfaceRole::transparent,
        TextRole::positive);
    refresh_displays_button_ = add_button(window, L"\u5237\u65b0\u663e\u793a\u5668", kRefreshDisplaysButtonId,
                                          logical_rect(670, 730, 132, 34));
    refresh_mobile_button_ = add_button(window, L"\u5b9a\u5411\u68c0\u6d4b", kRefreshMobileButtonId,
                                        logical_rect(810, 730, 120, 34));
    close_settings_button_ = add_button(window, L"\u5b8c\u6210", kCloseSettingsButtonId,
                                        logical_rect(1090, 730, 100, 34));
    settings_panel_controls_ = {settings_title_text_, settings_description_text_, settings_contract_text_,
        refresh_displays_button_, refresh_mobile_button_, close_settings_button_};
    set_settings_panel_visible(false);
    std::wstring version_label{L"VF Host   v"};
    version_label.append(kHostReleaseVersion.data(), kHostReleaseVersion.size());
    add_static(window, version_label.c_str(), logical_rect(24, 832, 260, 20), FontRole::small,
               SurfaceRole::window, TextRole::muted);
    add_static(window, L"\u4e3b\u673a\u4ec5\u505a\u672c\u5730\u5c4f\u5e55\u91c7\u96c6\u3001\u7f16\u7801\u4e0e\u53d1\u9001\uff0c\u4e0d\u63a5\u6536\u6216\u6267\u884c\u4efb\u4f55\u63a7\u5236\u6307\u4ee4\u3002",
               logical_rect(365, 832, 700, 20), FontRole::small,
               SurfaceRole::window, TextRole::muted);
    append_event(L"\u5e94\u7528\u5df2\u5c31\u7eea\uff1a\u63a7\u5236\u94fe\u8def\u4e0d\u5b58\u5728\u4e8e\u4e3b\u673a\u7aef");
}

void StreamerDesktopApp::initialize_display_selection() {
    display_outputs_ = enumerate_host_display_outputs();
    const auto display_selection = select_host_display_output(
        display_outputs_, enumerate_host_display_window_candidates());
    const HostDisplayOutput* preferred_display = display_selection.output;
    if (display_outputs_.size() == 1 && preferred_display != nullptr) {
        SetWindowTextW(display_state_text_, describe_display(*preferred_display).c_str());
    } else if (display_outputs_.empty()) {
        SetWindowTextW(display_state_text_, L"\u672a\u627e\u5230\u53ef\u7528 DXGI \u6355\u83b7\u7684\u6d3b\u52a8\u663e\u793a\u5668\u3002");
    } else if (preferred_display != nullptr) {
        SetWindowTextW(display_state_text_, describe_display(*preferred_display).c_str());
    }
    if (preferred_display != nullptr) {
        append_event(std::wstring{L"\u663e\u793a\u5668\u81ea\u52a8\u9009\u62e9\uff1a"} +
                     display_selection_reason_text(display_selection.reason));
        log_host_runtime_event(
            "host_gui_display_selection_initialized",
            "display_count=" + std::to_string(display_outputs_.size()) +
                " selection_reason=" +
                host_display_selection_reason_name(display_selection.reason));
    } else {
        log_host_runtime_event(
            "host_gui_display_selection_initialized",
            "display_count=0 selection_reason=no_attached_output");
    }
}

HWND StreamerDesktopApp::add_static(HWND parent, const wchar_t* text, RECT logical_bounds,
                                    FontRole font_role, SurfaceRole surface_role, TextRole text_role,
                                    DWORD static_style) {
    HWND control = CreateWindowExW(0, L"STATIC", text,
                                   WS_CHILD | WS_VISIBLE | SS_NOPREFIX | static_style,
                                   0, 0, 1, 1, parent, nullptr, GetModuleHandleW(nullptr), nullptr);
    HFONT font = regular_font_;
    switch (font_role) {
        case FontRole::small: font = small_font_; break;
        case FontRole::caption: font = caption_font_; break;
        case FontRole::regular: font = regular_font_; break;
        case FontRole::section: font = section_font_; break;
        case FontRole::title: font = title_font_; break;
        case FontRole::hero: font = hero_font_; break;
        case FontRole::metric: font = metric_font_; break;
    }
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    control_placements_.push_back(ControlPlacement{control, logical_bounds, font_role, surface_role, text_role});
    return control;
}

HWND StreamerDesktopApp::add_button(HWND parent, const wchar_t* text, int id, RECT logical_bounds) {
    HWND control = CreateWindowExW(0, L"BUTTON", text,
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                                   0, 0, 1, 1, parent,
                                   reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                                   GetModuleHandleW(nullptr), nullptr);
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(regular_font_), TRUE);
    control_placements_.push_back(
        ControlPlacement{control, logical_bounds, FontRole::regular, SurfaceRole::window, TextRole::primary});
    return control;
}

StreamerDesktopApp::MetricControls StreamerDesktopApp::add_metric_row(
        HWND window, int logical_y, const wchar_t* title, const wchar_t* detail, TextRole accent) {
    add_static(window, title, logical_rect(736, logical_y + 11, 180, 22), FontRole::caption,
               SurfaceRole::row);
    add_static(window, detail, logical_rect(736, logical_y + 35, 223, 20), FontRole::small,
               SurfaceRole::row, TextRole::muted);
    add_static(window, L"\u5f53\u524d", logical_rect(968, logical_y + 11, 64, 18), FontRole::small,
               SurfaceRole::row, TextRole::muted);
    add_static(window, L"P50", logical_rect(1052, logical_y + 11, 54, 18), FontRole::small,
               SurfaceRole::row, TextRole::muted);
    add_static(window, L"P95", logical_rect(1122, logical_y + 11, 54, 18), FontRole::small,
               SurfaceRole::row, TextRole::muted);
    MetricControls controls{};
    controls.current = add_static(window, L"--", logical_rect(968, logical_y + 33, 72, 26), FontRole::metric,
                                  SurfaceRole::row, accent);
    controls.p50 = add_static(window, L"--", logical_rect(1052, logical_y + 33, 62, 26), FontRole::metric,
                              SurfaceRole::row, accent);
    controls.p95 = add_static(window, L"--", logical_rect(1122, logical_y + 33, 62, 26), FontRole::metric,
                              SurfaceRole::row, accent);
    return controls;
}

void StreamerDesktopApp::load_ui_icons() {
    const int resource_ids[] = {
        IDI_VF_APP, IDI_VF_DISPLAY, IDI_VF_ENCODER, IDI_VF_PHONE, IDI_VF_LINK,
        IDI_VF_CAPTURE, IDI_VF_VIDEO, IDI_VF_SEND, IDI_VF_NETWORK, IDI_VF_PULSE,
        IDI_VF_ROUTER, IDI_VF_PLAY, IDI_VF_SETTINGS, IDI_VF_CHEVRON, IDI_VF_CHECK,
        IDI_VF_TRASH, IDI_VF_LOCK};
    HINSTANCE instance = GetModuleHandleW(nullptr);
    for (std::size_t index = 0; index < icons_.size(); ++index) {
        icons_[index] = reinterpret_cast<HICON>(LoadImageW(
            instance, MAKEINTRESOURCEW(resource_ids[index]), IMAGE_ICON, 64, 64, LR_DEFAULTCOLOR));
    }
}

void StreamerDesktopApp::release_ui_icons() noexcept {
    for (HICON& icon : icons_) {
        if (icon != nullptr) DestroyIcon(icon);
        icon = nullptr;
    }
}

void StreamerDesktopApp::layout_controls() {
    if (window_ == nullptr) return;
    RECT client{};
    GetClientRect(window_, &client);
    const int width = (std::max)(1L, client.right - client.left);
    const int height = (std::max)(1L, client.bottom - client.top);
    const HostWindowLayout layout = host_window_layout_for_client(width, height);
    const double scale = layout.scale;
    layout_offset_x_ = layout.offset_x;
    layout_offset_y_ = layout.offset_y;
    if (std::abs(scale - layout_scale_) > 0.01) recreate_fonts(scale);
    layout_scale_ = scale;
    HDWP deferred = BeginDeferWindowPos(static_cast<int>(control_placements_.size()));
    for (const ControlPlacement& placement : control_placements_) {
        const RECT bounds = transform_rect(placement.logical_bounds);
        if (deferred != nullptr) {
            deferred = DeferWindowPos(
                deferred, placement.handle, nullptr, bounds.left, bounds.top,
                bounds.right - bounds.left, bounds.bottom - bounds.top,
                SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOOWNERZORDER);
        } else {
            SetWindowPos(placement.handle, nullptr, bounds.left, bounds.top,
                         bounds.right - bounds.left, bounds.bottom - bounds.top,
                         SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOOWNERZORDER);
        }
    }
    if (deferred != nullptr) EndDeferWindowPos(deferred);
    RedrawWindow(window_, nullptr, nullptr,
                 RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_NOERASE);
}

void StreamerDesktopApp::recreate_fonts(double scale) {
    const int small_height = -(std::max)(11, static_cast<int>(std::lround(13.0 * scale)));
    const int caption_height = -(std::max)(12, static_cast<int>(std::lround(14.0 * scale)));
    const int regular_height = -(std::max)(13, static_cast<int>(std::lround(15.0 * scale)));
    const int section_height = -(std::max)(15, static_cast<int>(std::lround(17.0 * scale)));
    const int title_height = -(std::max)(20, static_cast<int>(std::lround(25.0 * scale)));
    const int hero_height = -(std::max)(28, static_cast<int>(std::lround(38.0 * scale)));
    const int metric_height = -(std::max)(18, static_cast<int>(std::lround(22.0 * scale)));
    HFONT new_small = CreateFontW(small_height, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI Variable Text");
    HFONT new_caption = CreateFontW(caption_height, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI Variable Text");
    HFONT new_regular = CreateFontW(regular_height, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI Variable Text");
    HFONT new_title = CreateFontW(title_height, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI Variable Display");
    HFONT new_section = CreateFontW(section_height, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI Variable Text");
    HFONT new_hero = CreateFontW(hero_height, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI Variable Display");
    HFONT new_metric = CreateFontW(metric_height, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                   DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                   CLEARTYPE_QUALITY, FF_MODERN | FIXED_PITCH, L"Consolas");
    for (const ControlPlacement& placement : control_placements_) {
        HFONT font = new_regular;
        switch (placement.font_role) {
            case FontRole::small: font = new_small; break;
            case FontRole::caption: font = new_caption; break;
            case FontRole::regular: font = new_regular; break;
            case FontRole::section: font = new_section; break;
            case FontRole::title: font = new_title; break;
            case FontRole::hero: font = new_hero; break;
            case FontRole::metric: font = new_metric; break;
        }
        SendMessageW(placement.handle, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }
    if (small_font_ != nullptr) DeleteObject(small_font_);
    if (caption_font_ != nullptr) DeleteObject(caption_font_);
    if (regular_font_ != nullptr) DeleteObject(regular_font_);
    if (section_font_ != nullptr) DeleteObject(section_font_);
    if (title_font_ != nullptr) DeleteObject(title_font_);
    if (hero_font_ != nullptr) DeleteObject(hero_font_);
    if (metric_font_ != nullptr) DeleteObject(metric_font_);
    small_font_ = new_small;
    caption_font_ = new_caption;
    regular_font_ = new_regular;
    section_font_ = new_section;
    title_font_ = new_title;
    hero_font_ = new_hero;
    metric_font_ = new_metric;
}

RECT StreamerDesktopApp::transform_rect(RECT logical_bounds) const noexcept {
    return RECT{layout_offset_x_ + static_cast<LONG>(std::lround(logical_bounds.left * layout_scale_)),
                layout_offset_y_ + static_cast<LONG>(std::lround(logical_bounds.top * layout_scale_)),
                layout_offset_x_ + static_cast<LONG>(std::lround(logical_bounds.right * layout_scale_)),
                layout_offset_y_ + static_cast<LONG>(std::lround(logical_bounds.bottom * layout_scale_))};
}

void StreamerDesktopApp::set_settings_panel_visible(bool visible) {
    settings_panel_visible_ = visible;
    for (HWND control : event_panel_controls_) {
        if (control != nullptr) ShowWindow(control, visible ? SW_HIDE : SW_SHOW);
    }
    for (HWND control : settings_panel_controls_) {
        if (control != nullptr) ShowWindow(control, visible ? SW_SHOW : SW_HIDE);
    }
    if (settings_button_ != nullptr) {
        SetWindowTextW(settings_button_, visible ? L"\u8fd4\u56de" : L"\u8bbe\u7f6e");
    }
    if (window_ != nullptr) InvalidateRect(window_, nullptr, FALSE);
}

void StreamerDesktopApp::refresh_display_selection() {
    if (starting_ || runtime_service_.is_running()) {
        set_status(L"\u4f20\u8f93\u671f\u95f4\u663e\u793a\u5668\u7531\u8fd0\u884c\u65f6\u6301\u7eed\u6821\u9a8c\uff1b\u505c\u6b62\u540e\u53ef\u624b\u52a8\u5237\u65b0\u3002");
        return;
    }
    display_outputs_ = enumerate_host_display_outputs();
    const auto selection = select_host_display_output(
        display_outputs_, enumerate_host_display_window_candidates());
    const HostDisplayOutput* preferred = selection.output;
    if (preferred == nullptr) {
        SetWindowTextW(display_state_text_, L"\u672a\u627e\u5230\u53ef\u7528 DXGI \u6355\u83b7\u7684\u6d3b\u52a8\u663e\u793a\u5668\u3002");
        set_status(L"\u663e\u793a\u5668\u5237\u65b0\u5b8c\u6210\uff1a\u672a\u627e\u5230\u53ef\u6355\u83b7\u7684 Windows \u6d3b\u52a8\u663e\u793a\u5668\u3002");
        append_event(L"\u663e\u793a\u5668\u5237\u65b0\u5931\u8d25\uff1a\u65e0\u53ef\u6355\u83b7\u8f93\u51fa");
        return;
    }
    SetWindowTextW(display_state_text_, describe_display(*preferred).c_str());
    set_status(std::wstring{L"\u663e\u793a\u5668\u5237\u65b0\u5b8c\u6210\uff1a"} +
               display_selection_reason_text(selection.reason) + L"\u5df2\u5c31\u7eea\u3002");
    append_event(std::wstring{L"\u663e\u793a\u5668\u5df2\u5237\u65b0\uff1a"} +
                 display_selection_reason_text(selection.reason));
}

void StreamerDesktopApp::refresh_mobile_device() {
    reap_completed_mobile_refresh_thread("refresh_mobile_device_enter");
    if (mobile_refresh_running() || starting_ || runtime_service_.is_running()) {
        set_status(L"\u5f53\u524d\u6b63\u5728\u68c0\u6d4b\u6216\u4f20\u8f93\uff0c\u65e0\u9700\u91cd\u590d\u68c0\u6d4b\u624b\u673a\u7aef\u70b9\u3002");
        return;
    }
    if (mobile_refresh_thread_.joinable()) {
        mobile_refresh_stop_source_.request_stop();
        safe_join_thread(mobile_refresh_thread_);
    }
    mobile_refresh_stop_source_ = std::stop_source{};
    mobile_refresh_finished_.store(false, std::memory_order_release);
    mobile_refresh_state_ = MobileRefreshState::running;
    set_ui_phase(HostUiPhase::discovering);
    clear_runtime_metrics();
    EnableWindow(refresh_mobile_button_, FALSE);
    SetWindowTextW(ready_state_text_, L"正在自动检测手机端点");
    SetWindowTextW(ready_detail_text_, L"CAT6 优先 · 无线局域网自动回退");
    SetWindowTextW(mobile_state_text_, L"正在检测 VF Mobile");
    SetWindowTextW(encoder_state_text_,
                   host_idle_ui_text(HostIdleEndpointState::not_checked).encoder.data());
    SetWindowTextW(phone_state_text_, L"VF Mobile·端点检测中");
    SetWindowTextW(link_state_text_, L"正在检测 CAT6 与无线局域网链路");
    SetWindowTextW(topology_host_state_text_, L"\u5f85\u542f\u52a8");
    SetWindowTextW(topology_link_state_text_, L"\u68c0\u6d4b\u4e2d");
    SetWindowTextW(topology_mobile_state_text_, L"\u7b49\u5f85\u54cd\u5e94");
    SetWindowTextW(route_capture_latency_text_, L"-- ms");
    SetWindowTextW(route_network_latency_text_, L"-- ms");
    set_status(L"正在检查手机端点；此操作不会开始捕获或传输。");
    append_event(L"已开始按 CAT6 优先顺序检测手机端点");
    const std::uint64_t generation = ++mobile_refresh_generation_;
    const std::stop_token stop_token = mobile_refresh_stop_source_.get_token();
    try {
        mobile_refresh_thread_ = std::thread([
            window = window_, generation, dhcp_server = &isolated_dhcp_server_,
            stop_token, finished = &mobile_refresh_finished_] {
            try {
                const auto bootstrap = bootstrap_host_cat6_link(
                    kHostCat6MobileReadyTimeout, dhcp_server, stop_token);
                std::optional<Cat6SessionSnapshot> mobile = bootstrap.mobile;
                if (!mobile.has_value() && !stop_token.stop_requested()) {
                    const HostFirewallProvisioningResult firewall =
                        ensure_host_firewall_rules_automatically();
                    if (host_firewall_is_ready(firewall.status)) {
                        mobile = measure_wireless_lan_mobile_session(
                            kWirelessLanDiscoveryTimeout, stop_token);
                    }
                }
                finished->store(true, std::memory_order_release);
                post_mobile_refresh_completed_result(window, generation, std::move(mobile));
            } catch (...) {
                finished->store(true, std::memory_order_release);
                post_mobile_refresh_completed_result(window, generation, std::nullopt);
            }
        });
    } catch (const std::exception& exception) {
        mark_mobile_refresh_idle();
        EnableWindow(refresh_mobile_button_, TRUE);
        set_ui_phase(HostUiPhase::failed);
        const std::wstring message = widen_ascii(
            describe_background_exception("mobile transport refresh thread start", exception));
        set_status(message);
        append_event(L"\u624b\u673a\u4f20\u8f93\u7aef\u70b9\u68c0\u6d4b\u542f\u52a8\u5931\u8d25\uff1a" + message);
    } catch (...) {
        mark_mobile_refresh_idle();
        EnableWindow(refresh_mobile_button_, TRUE);
        set_ui_phase(HostUiPhase::failed);
        const std::wstring message = widen_ascii(
            describe_unknown_background_exception("mobile transport refresh thread start"));
        set_status(message);
        append_event(L"\u624b\u673a\u4f20\u8f93\u7aef\u70b9\u68c0\u6d4b\u542f\u52a8\u5931\u8d25\uff1a" + message);
    }
}

void StreamerDesktopApp::cancel_mobile_refresh_probe() noexcept {
    if (!mobile_refresh_running() && !mobile_refresh_thread_.joinable()) {
        mark_mobile_refresh_idle();
        return;
    }
    start_after_mobile_refresh_cancel_ = false;
    ++mobile_refresh_generation_;
    mobile_refresh_stop_source_.request_stop();
    safe_join_thread(mobile_refresh_thread_);
    mark_mobile_refresh_idle();
}

void StreamerDesktopApp::apply_idle_ui_state(HostIdleEndpointState endpoint_state) {
    const HostIdleUiText text = host_idle_ui_text(endpoint_state);
    set_window_text_if_changed(ready_state_text_, text.ready_state);
    set_window_text_if_changed(ready_detail_text_, text.ready_detail);
    set_window_text_if_changed(mobile_state_text_, text.hero);
    set_window_text_if_changed(encoder_state_text_, text.encoder);
    set_window_text_if_changed(phone_state_text_, text.phone);
    set_window_text_if_changed(link_state_text_, text.link);
    set_window_text_if_changed(topology_host_state_text_, text.topology_host);
    set_window_text_if_changed(topology_link_state_text_, text.topology_link);
    set_window_text_if_changed(topology_mobile_state_text_, text.topology_mobile);
    clear_runtime_metrics();
}

void StreamerDesktopApp::clear_runtime_metrics() {
    ui_telemetry_.reset();
    const auto clear_metric = [](const MetricControls& controls) {
        set_window_text_if_changed(controls.current, L"--");
        set_window_text_if_changed(controls.p50, L"--");
        set_window_text_if_changed(controls.p95, L"--");
    };
    clear_metric(capture_metric_);
    clear_metric(encode_metric_);
    clear_metric(publish_metric_);
    clear_metric(link_metric_);
    set_window_text_if_changed(output_rate_value_, L"-- FPS");
    set_window_text_if_changed(output_rate_p95_value_, L"-- FPS");
    set_window_text_if_changed(bandwidth_text_, L"\u63a2\u9488 -- Mbps");
    set_window_text_if_changed(route_capture_latency_text_, L"-- ms");
    set_window_text_if_changed(route_network_latency_text_, L"-- ms");
}

bool StreamerDesktopApp::mobile_refresh_running() const noexcept {
    return mobile_refresh_state_ == MobileRefreshState::running &&
        mobile_refresh_thread_.joinable();
}

void StreamerDesktopApp::mark_mobile_refresh_idle() noexcept {
    mobile_refresh_state_ = MobileRefreshState::idle;
    mobile_refresh_finished_.store(true, std::memory_order_release);
    mobile_refresh_stop_source_ = std::stop_source{};
    if (refresh_mobile_button_ != nullptr) EnableWindow(refresh_mobile_button_, TRUE);
}

bool StreamerDesktopApp::reap_completed_mobile_refresh_thread(const char* context) noexcept {
    const bool joinable = mobile_refresh_thread_.joinable();
    const bool finished = mobile_refresh_finished_.load(std::memory_order_acquire);
    const bool valid_state = mobile_refresh_state_ == MobileRefreshState::idle ||
        mobile_refresh_state_ == MobileRefreshState::running;
    const bool stale_running_state =
        mobile_refresh_state_ == MobileRefreshState::running && !joinable;
    const bool stale_finished_flag = !joinable && !finished;
    const bool completed_joinable_thread = joinable && finished;
    if (!completed_joinable_thread && valid_state && !stale_running_state &&
        !stale_finished_flag) {
        return false;
    }

    std::ostringstream detail;
    detail << "context=" << (context == nullptr ? "unknown" : context)
           << " state_raw=" << static_cast<int>(mobile_refresh_state_)
           << " joinable=" << joinable
           << " finished=" << finished
           << " pending_start=" << start_after_mobile_refresh_cancel_;
    log_host_runtime_event("host_gui_mobile_refresh_state_repaired", detail.str());

    if (completed_joinable_thread) safe_join_thread(mobile_refresh_thread_);
    mark_mobile_refresh_idle();
    return true;
}

bool StreamerDesktopApp::repair_stale_startup_state(const char* context) noexcept {
    if (!starting_ || startup_thread_.joinable() || runtime_service_.is_running()) {
        return false;
    }
    std::ostringstream detail;
    detail << "context=" << (context == nullptr ? "unknown" : context)
           << " starting=" << starting_
           << " startup_joinable=" << startup_thread_.joinable()
           << " runtime_running=" << runtime_service_.is_running();
    log_host_runtime_event("host_gui_startup_state_repaired", detail.str());
    starting_ = false;
    update_action_state(false, false);
    return true;
}

void StreamerDesktopApp::start_streamer(HWND window) {
    repair_stale_startup_state("start_streamer_enter");
    reap_completed_mobile_refresh_thread("start_streamer_enter");
    {
        std::ostringstream detail;
        detail << "starting=" << starting_
               << " runtime_running=" << runtime_service_.is_running()
               << " mobile_refresh_state=" << static_cast<int>(mobile_refresh_state_)
               << " mobile_refresh_joinable=" << mobile_refresh_thread_.joinable()
               << " mobile_refresh_finished="
               << mobile_refresh_finished_.load(std::memory_order_acquire)
               << " acceptance_autostart=" << acceptance_autostart_;
        log_host_runtime_event("host_gui_start_streamer_entered", detail.str());
    }
    if (starting_ || runtime_service_.is_running()) {
        log_host_runtime_event(
            "host_gui_start_streamer_skipped",
            "reason=already_starting_or_running");
        return;
    }
    if (mobile_refresh_thread_.joinable() || mobile_refresh_state_ == MobileRefreshState::running) {
        start_after_mobile_refresh_cancel_ = true;
        ++mobile_refresh_generation_;
        mobile_refresh_stop_source_.request_stop();
        update_action_state(false, true);
        EnableWindow(refresh_mobile_button_, FALSE);
        set_status(L"\u6b63\u5728\u53d6\u6d88\u7a7a\u95f2 CAT6 \u7aef\u70b9\u68c0\u6d4b\uff0c\u968f\u540e\u5f00\u59cb\u6b63\u5f0f\u4f20\u8f93\u3002");
        append_event(L"\u542f\u52a8\u4f20\u8f93\uff1a\u6b63\u5728\u5f02\u6b65\u505c\u6b62\u7a7a\u95f2 CAT6 \u68c0\u6d4b\uff0c\u907f\u514d UI \u7ebf\u7a0b\u963b\u585e");
        log_host_runtime_event(
            "host_gui_start_streamer_deferred",
            "reason=mobile_refresh_running");
        schedule_autostart_retry(window, acceptance_autostart_);
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    if (retry_not_before_ != std::chrono::steady_clock::time_point{} &&
        now < retry_not_before_) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            retry_not_before_ - now);
        set_status(
            L"\u4e0a\u4e00\u6b21\u542f\u52a8\u521a\u521a\u7ed3\u675f\uff1b"
            L"\u4e3a\u907f\u514d\u91cd\u590d\u5e76\u53d1\u914d\u7f6e\uff0c"
            L"\u8bf7\u7b49\u5f85 " +
            std::to_wstring((remaining.count() + 999) / 1000) +
            L" \u79d2\u540e\u91cd\u8bd5\u3002");
        log_host_runtime_event(
            "host_gui_start_streamer_skipped",
            "reason=retry_backoff remaining_ms=" + std::to_string(remaining.count()));
        return;
    }
    // Displays can be attached, removed or promoted to primary while the GUI
    // is open. Re-enumerate at the action boundary instead of using startup data.
    display_outputs_ = enumerate_host_display_outputs();
    if (display_outputs_.empty()) {
        log_host_runtime_event(
            "host_gui_start_streamer_skipped",
            "reason=no_display_outputs");
        if (acceptance_autostart_) {
            append_event(L"\u542f\u52a8\u6682\u4e0d\u53ef\u7528\uff1a\u672a\u627e\u5230\u6d3b\u52a8\u663e\u793a\u5668\uff0c\u5c06\u81ea\u52a8\u91cd\u8bd5");
            schedule_autostart_retry(window, acceptance_autostart_);
        } else {
            MessageBoxW(window, L"\u672a\u627e\u5230\u53ef\u6355\u83b7\u7684 Windows \u6d3b\u52a8\u663e\u793a\u5668\u3002", L"VF Host", MB_OK | MB_ICONERROR);
        }
        return;
    }
    const auto selection = select_host_display_output(
        display_outputs_, enumerate_host_display_window_candidates());
    const HostDisplayOutput* preferred_display = selection.output;
    if (preferred_display == nullptr) {
        log_host_runtime_event(
            "host_gui_start_streamer_skipped",
            "reason=no_preferred_display display_count=" +
                std::to_string(display_outputs_.size()));
        if (acceptance_autostart_) {
            append_event(L"\u542f\u52a8\u6682\u4e0d\u53ef\u7528\uff1a\u663e\u793a\u5668\u9009\u62e9\u4e3a\u7a7a\uff0c\u5c06\u81ea\u52a8\u91cd\u8bd5");
            schedule_autostart_retry(window, acceptance_autostart_);
        }
        return;
    }
    const HostDisplayOutput& display = *preferred_display;
    const HostCaptureGeometry geometry = choose_centered_ai_capture_geometry(display);
    if (geometry.fallback_reason == HostCaptureFallbackReason::invalid_display_extent) {
        log_host_runtime_event(
            "host_gui_start_streamer_skipped",
            "reason=invalid_display_extent display_id=" + narrow_display_id(display.device_name));
        if (acceptance_autostart_) {
            append_event(L"\u542f\u52a8\u6682\u4e0d\u53ef\u7528\uff1a\u663e\u793a\u5668\u684c\u9762\u8303\u56f4\u65e0\u6548\uff0c\u5c06\u81ea\u52a8\u91cd\u8bd5");
            schedule_autostart_retry(window, acceptance_autostart_);
        } else {
            MessageBoxW(window, L"\u81ea\u52a8\u9009\u4e2d\u7684\u663e\u793a\u5668\u6ca1\u6709\u6709\u6548\u684c\u9762\u8303\u56f4\u3002", L"VF Host", MB_OK | MB_ICONERROR);
        }
        return;
    }
    HostStreamSettings settings{};
    settings.adapter_index = display.adapter_index;
    settings.output_index = display.output_index;
    settings.width = geometry.encoder_width;
    settings.height = geometry.encoder_height;
    settings.capture_region = DesktopCaptureRegion{
        geometry.local_roi_x, geometry.local_roi_y,
        geometry.local_roi_width, geometry.local_roi_height};
    settings.display_id = narrow_display_id(display.device_name);
    settings.display_left = geometry.display_rect.left;
    settings.display_top = geometry.display_rect.top;
    settings.display_right = geometry.display_rect.right;
    settings.display_bottom = geometry.display_rect.bottom;
    settings.roi_left = geometry.roi_rect.left;
    settings.roi_top = geometry.roi_rect.top;
    settings.roi_right = geometry.roi_rect.right;
    settings.roi_bottom = geometry.roi_rect.bottom;
    settings.source_width = geometry.source_width;
    settings.source_height = geometry.source_height;
    settings.fallback_reason = host_capture_fallback_reason_name(geometry.fallback_reason);
    settings.display_selection_reason = host_display_selection_reason_name(selection.reason);
    settings.encoder_timing_fps =
        encoder_timing_hint_for_display_refresh(display.refresh_hz);
    {
        std::ostringstream detail;
        detail << "display_count=" << display_outputs_.size()
               << " selection_reason=" << settings.display_selection_reason
               << " display_id=" << settings.display_id
               << " refresh_hz=" << display.refresh_hz
               << " roi=" << settings.capture_region.x << ','
               << settings.capture_region.y << ','
               << settings.capture_region.width << 'x'
               << settings.capture_region.height;
        log_host_runtime_event("host_gui_start_streamer_selected", detail.str());
    }
    log_host_runtime_event(
        "host_gui_startup_thread_join_prepare",
        std::string{"startup_joinable="} + (startup_thread_.joinable() ? "1" : "0"));
    safe_join_thread(startup_thread_);
    log_host_runtime_event("host_gui_startup_thread_joined");
    starting_ = true;
    last_event_frame_ = 0U;
    last_recovery_count_ = 0U;
    last_mobile_ipv4_.clear();
    last_transport_.clear();
    last_runtime_display_id_ = settings.display_id;
    const std::uint64_t generation = ++startup_generation_;
    try {
        log_host_runtime_event(
            "host_gui_startup_thread_launching",
            "generation=" + std::to_string(generation));
        startup_thread_ = std::thread([this, settings, generation, window] {
            std::string error;
            bool started = false;
            try {
                started = runtime_service_.start(settings, error);
            } catch (const std::exception& exception) {
                error = describe_background_exception(
                    "Host runtime start", exception);
            } catch (...) {
                error = describe_unknown_background_exception("Host runtime start");
            }
            post_startup_completed_result(
                window, generation, started, std::move(error));
        });
        log_host_runtime_event(
            "host_gui_startup_thread_created",
            std::string{"startup_joinable="} + (startup_thread_.joinable() ? "1" : "0"));
    } catch (const std::exception& exception) {
        starting_ = false;
        set_ui_phase(HostUiPhase::failed);
        update_action_state(false, false);
        const std::string detail =
            describe_background_exception("Host startup thread start", exception);
        const std::wstring message = friendly_host_failure(detail);
        set_status(message + L"\u3002\u6280\u672f\u539f\u56e0\uff1a" + widen_ascii(detail));
        append_event(L"\u542f\u52a8\u5931\u8d25\uff1a" + message);
        return;
    } catch (...) {
        starting_ = false;
        set_ui_phase(HostUiPhase::failed);
        update_action_state(false, false);
        const std::string detail =
            describe_unknown_background_exception("Host startup thread start");
        const std::wstring message = friendly_host_failure(detail);
        set_status(message + L"\u3002\u6280\u672f\u539f\u56e0\uff1a" + widen_ascii(detail));
        append_event(L"\u542f\u52a8\u5931\u8d25\uff1a" + message);
        return;
    }
    set_ui_phase(HostUiPhase::discovering);
    clear_runtime_metrics();
    update_action_state(false, true);
    SetWindowTextW(mobile_state_text_, L"\u6b63\u5728\u5b9a\u5411\u68c0\u6d4b VF Mobile...");
    SetWindowTextW(ready_state_text_, L"正在配置手机传输链路");
    SetWindowTextW(ready_detail_text_, L"CAT6 优先 · 无线局域网自动回退");
    SetWindowTextW(phone_state_text_, L"VF Mobile·正在等待手机端点响应");
    SetWindowTextW(display_state_text_, describe_display(display).c_str());
    set_status(L"正在异步检测手机传输端点。此时可以点击“停止”取消。");
    append_event(L"正在启动：检测手机传输端点");
    append_event(std::wstring{L"\u663e\u793a\u5668\u9009\u62e9\u4f9d\u636e\uff1a"} +
                 display_selection_reason_text(selection.reason));
}

void StreamerDesktopApp::stop_streamer() {
    const bool had_active_runtime = starting_ || was_running_ || runtime_service_.is_running();
    if (start_after_mobile_refresh_cancel_) {
        start_after_mobile_refresh_cancel_ = false;
        ++mobile_refresh_generation_;
        mobile_refresh_stop_source_.request_stop();
        update_action_state(false, false);
        set_status(L"已取消等待中的正式启动。");
        append_event(L"启动已取消：空闲端点检测取消后不再自动开始传输");
        return;
    }
    if (starting_) {
        ++startup_generation_;
        runtime_service_.request_stop();
        EnableWindow(stop_button_, FALSE);
        set_status(L"\u6b63\u5728\u53d6\u6d88\u4f20\u8f93\u94fe\u8def\u542f\u52a8\u7b49\u5f85...");
        append_event(L"\u5df2\u8bf7\u6c42\u53d6\u6d88\uff1a\u6b63\u5728\u505c\u6b62\u624b\u673a\u7aef\u70b9\u68c0\u6d4b");
        return;
    }
    ++startup_generation_;
    runtime_service_.stop();
    runtime_service_.restore_direct_link_on_clean_shutdown();
    safe_join_thread(startup_thread_);
    starting_ = false;
    was_running_ = false;
    set_ui_phase(HostUiPhase::idle);
    clear_runtime_metrics();
    update_action_state(false, false);
    if (status_text_ != nullptr) set_status(L"\u4f20\u8f93\u5df2\u505c\u6b62\uff08\u64cd\u4f5c\u5458\u8bf7\u6c42\uff09\u3002\u4e3b\u673a\u4e0d\u4fdd\u7559\u63a7\u5236\u901a\u9053\u6216\u540e\u53f0\u8f93\u5165\u903b\u8f91\u3002");
    if (mobile_state_text_ != nullptr) SetWindowTextW(mobile_state_text_, L"\u4e3b\u673a\u4f20\u8f93\u5df2\u505c\u6b62");
    if (ready_state_text_ != nullptr) SetWindowTextW(ready_state_text_, L"\u4f20\u8f93\u5df2\u505c\u6b62");
    if (ready_detail_text_ != nullptr) SetWindowTextW(ready_detail_text_, L"\u64cd\u4f5c\u5458\u505c\u6b62\u00b7\u4f20\u8f93\u94fe\u8def\u540e\u53f0\u5df2\u5173\u95ed");
    if (phone_state_text_ != nullptr) SetWindowTextW(phone_state_text_, L"VF Mobile\u00b7 \u672a\u68c0\u6d4b");
    if (link_state_text_ != nullptr) SetWindowTextW(link_state_text_, L"\u81ea\u52a8\u4f20\u8f93\u94fe\u8def\u00b7 \u5df2\u505c\u6b62");
    if (topology_link_state_text_ != nullptr) SetWindowTextW(topology_link_state_text_, L"\u5df2\u505c\u6b62");
    if (topology_mobile_state_text_ != nullptr) SetWindowTextW(topology_mobile_state_text_, L"\u672a\u68c0\u6d4b");
    if (had_active_runtime) {
        append_event(L"\u4f20\u8f93\u5df2\u505c\u6b62\uff08\u64cd\u4f5c\u5458\u8bf7\u6c42\uff09\uff1a\u4f20\u8f93\u94fe\u8def\u540e\u53f0\u5df2\u5173\u95ed");
    }
}

void StreamerDesktopApp::refresh_status() {
    if (!runtime_service_.is_running()) {
        if (was_running_) {
            was_running_ = false;
            runtime_service_.restore_direct_link_on_clean_shutdown();
            set_ui_phase(HostUiPhase::failed);
            clear_runtime_metrics();
            update_action_state(false, false);
            const std::string error = runtime_service_.last_error();
            const std::wstring summary = friendly_host_failure(error);
            const std::wstring technical = widen_ascii(error);
            SetWindowTextW(mobile_state_text_, L"\u4e3b\u673a\u4f20\u8f93\u5f02\u5e38\u505c\u6b62");
            SetWindowTextW(ready_state_text_, L"\u4e3b\u673a\u4f20\u8f93\u5f02\u5e38\u505c\u6b62");
            SetWindowTextW(ready_detail_text_, summary.c_str());
            SetWindowTextW(phone_state_text_, mobile_reachable_
                ? L"VF Mobile\u00b7 \u4e0a\u6b21\u5fc3\u8df3\u6b63\u5e38"
                : L"VF Mobile\u00b7 \u5fc3\u8df3\u5df2\u8d85\u65f6");
            SetWindowTextW(topology_link_state_text_, L"\u4e3b\u673a\u5df2\u505c\u6b62");
            SetWindowTextW(topology_mobile_state_text_, mobile_reachable_
                ? L"\u4e0a\u6b21\u53ef\u8fbe" : L"\u5fc3\u8df3\u8d85\u65f6");
            SetWindowTextW(route_capture_latency_text_, L"-- ms");
            SetWindowTextW(route_network_latency_text_, L"-- ms");
            set_status(summary + (technical.empty() ? L"" : L"\u3002\u6280\u672f\u539f\u56e0\uff1a" + technical));
            append_event(L"\u4e3b\u673a\u4f20\u8f93\u5f02\u5e38\u505c\u6b62\uff1a" + summary);
        }
        return;
    }
    const auto metrics = runtime_service_.last_metrics();
    if (!metrics.has_value()) return;
    const bool mobile_state_changed = mobile_reachable_ != metrics->mobile_reachable;
    mobile_reachable_ = metrics->mobile_reachable;
    set_ui_phase(mobile_reachable_ ? HostUiPhase::streaming : HostUiPhase::mobile_stale);
    const std::uint64_t host_path_us = metrics->capture_to_publish_us != 0U
        ? metrics->capture_to_publish_us
        : metrics->capture_us + metrics->readback_wait_us + metrics->readback_copy_us +
            metrics->bridge_us + metrics->upload_us + metrics->encode_us + metrics->publish_us;
    const HostUiTelemetrySnapshot telemetry = ui_telemetry_.observe(*metrics, GetTickCount64());
    const auto set_metric_values = [](const MetricControls& controls,
                                      const std::optional<HostUiMetricTriple>& metric) {
        if (!metric.has_value()) {
            set_window_text_if_changed(controls.current, L"--");
            set_window_text_if_changed(controls.p50, L"--");
            set_window_text_if_changed(controls.p95, L"--");
            return;
        }
        set_window_text_if_changed(controls.current, format_decimal(metric->current));
        set_window_text_if_changed(controls.p50, format_decimal(metric->p50));
        set_window_text_if_changed(controls.p95, format_decimal(metric->p95));
    };
    set_metric_values(capture_metric_, telemetry.capture_ms);
    set_metric_values(encode_metric_, telemetry.encode_ms);
    set_metric_values(publish_metric_, telemetry.publish_ms);
    set_metric_values(link_metric_, mobile_reachable_
        ? telemetry.link_rtt_ms : std::optional<HostUiMetricTriple>{});
    std::wstring rate_text = L"--";
    if (telemetry.output_fps.has_value()) {
        rate_text = format_decimal(telemetry.output_fps->current);
        set_window_text_if_changed(output_rate_value_, rate_text + L" FPS");
        set_window_text_if_changed(
            output_rate_p95_value_, format_decimal(telemetry.output_fps->p95) + L" FPS");
        // This value is derived from the selected transport's fixed-size probe.
        // It is not the video access-unit bitrate and must not be presented as
        // link capacity or encoder bandwidth.
        set_window_text_if_changed(bandwidth_text_, mobile_reachable_
            ? L"\u63a2\u9488 " + format_decimal(metrics->throughput_mbps, L" Mbps")
            : L"\u624b\u673a\u5fc3\u8df3\u8d85\u65f6\u00b7 \u4e3b\u673a\u4ecd\u5728\u53d1\u9001");
    }
    const bool wireless_lan = is_wireless_lan_transport(metrics->transport);
    const std::wstring link_description = describe_link(metrics->transport);
    set_window_text_if_changed(link_state_text_, mobile_reachable_
        ? link_description + L"\u00b7 RTT " + format_decimal(metrics->rtt_ms, L" ms")
        : link_description + L"\u00b7 \u624b\u673a\u5fc3\u8df3\u8d85\u65f6 " +
            format_decimal(static_cast<double>(metrics->mobile_last_success_age_ms) / 1000.0, L" s"));
    set_window_text_if_changed(encoder_state_text_, describe_encoder_state(*metrics));
    if (!metrics->mobile_ipv4.empty() && mobile_reachable_) {
        set_window_text_if_changed(
            phone_state_text_,
            L"VF Mobile\u00b7 " +
                std::wstring(metrics->mobile_ipv4.begin(), metrics->mobile_ipv4.end()));
    } else if (!mobile_reachable_) {
        set_window_text_if_changed(phone_state_text_,
            L"VF Mobile\u00b7 \u5fc3\u8df3\u8d85\u65f6\uff0c\u7b49\u5f85\u81ea\u52a8\u6062\u590d");
    }
    set_window_text_if_changed(topology_host_state_text_, L"\u6b63\u5e38");
    set_window_text_if_changed(topology_link_state_text_, mobile_reachable_
        ? L"\u4e3b\u673a\u53d1\u9001\u4e2d" : L"\u7b49\u5f85\u6062\u590d");
    set_window_text_if_changed(topology_mobile_state_text_, mobile_reachable_
        ? L"\u94fe\u8def\u5df2\u54cd\u5e94" : L"\u5fc3\u8df3\u8d85\u65f6");
    if (telemetry.encode_ms.has_value()) {
        set_window_text_if_changed(
            route_capture_latency_text_,
            format_decimal(telemetry.encode_ms->current, L" ms"));
    }
    set_window_text_if_changed(route_network_latency_text_, mobile_reachable_
        ? format_decimal(metrics->rtt_ms, L" ms") : L"-- ms");
    set_window_text_if_changed(ready_state_text_, mobile_reachable_
        ? (wireless_lan
            ? L"\u65e0\u7ebf\u5c40\u57df\u7f51\u94fe\u8def\u5df2\u5c31\u7eea\uff0c\u4e3b\u673a\u6b63\u5728\u53d1\u9001"
            : L"CAT6 \u94fe\u8def\u5df2\u5c31\u7eea\uff0c\u4e3b\u673a\u6b63\u5728\u53d1\u9001")
        : L"\u4e3b\u673a\u4ecd\u5728\u53d1\u9001\uff0c\u624b\u673a\u5fc3\u8df3\u8d85\u65f6");
    set_window_text_if_changed(ready_detail_text_, mobile_reachable_
        ? L"\u624b\u673a\u94fe\u8def\u63a2\u9488\u5728\u7ebf\u00b7 \u4e3b\u673a UDP \u6b63\u5728\u53d1\u9001\u00b7 \u624b\u673a\u89c6\u9891\u63a5\u6536\u72b6\u6001\u5f85\u786e\u8ba4"
        : L"\u4e0d\u505c\u6b62\u4e3b\u673a\u7ba1\u7ebf\u00b7 \u7b49\u5f85\u4f20\u8f93\u94fe\u8def\u81ea\u52a8\u6062\u590d");
    if (metrics->mobile_ipv4 != last_mobile_ipv4_
            || metrics->transport != last_transport_) {
        last_mobile_ipv4_ = metrics->mobile_ipv4;
        last_transport_ = metrics->transport;
        append_event(L"\u53d1\u9001\u94fe\u8def\u5df2\u9009\u5b9a\uff1a" + link_description);
    }
    if (mobile_state_changed) {
        append_event(mobile_reachable_
            ? L"\u624b\u673a\u94fe\u8def\u5fc3\u8df3\u5df2\u81ea\u52a8\u6062\u590d"
            : L"\u624b\u673a\u94fe\u8def\u5fc3\u8df3\u8d85\u65f6\uff1a\u4e3b\u673a\u4fdd\u6301\u53d1\u9001\u5e76\u7b49\u5f85\u6062\u590d");
    }
    if (metrics->recovery_count > last_recovery_count_) {
        last_recovery_count_ = metrics->recovery_count;
        append_event(L"\u94fe\u8def\u6062\u590d\u5b8c\u6210\uff1a\u7d2f\u8ba1 " + std::to_wstring(last_recovery_count_) + L" \u6b21");
    }
    if (!metrics->display_id.empty() &&
        metrics->display_id != last_runtime_display_id_) {
        last_runtime_display_id_ = metrics->display_id;
        const std::wstring display_id{
            metrics->display_id.begin(), metrics->display_id.end()};
        set_window_text_if_changed(
            display_state_text_, L"\u8fd0\u884c\u65f6\u5df2\u5207\u6362  " + display_id +
                L"  |  \u4e2d\u5fc3 ROI " +
                std::to_wstring(kDefaultMobileModel.input.width) + L" x " +
                std::to_wstring(kDefaultMobileModel.input.height));
        append_event(L"\u663e\u793a\u8f93\u51fa\u5df2\u81ea\u52a8\u6062\u590d\u5230\uff1a" + display_id);
    }
    if (metrics->published_frames >= last_event_frame_ + 300U) {
        last_event_frame_ = metrics->published_frames;
        append_event(L"\u4e3b\u673a\u6301\u7eed\u53d1\u9001\uff1a\u672c\u673a\u5df2\u63d0\u4ea4 " + std::to_wstring(metrics->published_frames) + L" \u5e27");
    }
    // The topology card has a single status line. Keep it scannable and leave
    // the full timing breakdown in structured host_cat6_quality logs.
    set_status((mobile_reachable_
                   ? L"\u4e3b\u673a\u6301\u7eed\u53d1\u9001\uff08\u624b\u673a\u94fe\u8def\u63a2\u9488\u6709\u54cd\u5e94\uff09"
                   : L"\u4e3b\u673a\u6301\u7eed\u53d1\u9001\uff0c\u624b\u673a\u5fc3\u8df3\u8d85\u65f6") +
               std::wstring{L"  \u00b7  \u4e3b\u673a\u7aef\u5230\u7aef "} + format_microseconds(host_path_us) +
               L"  \u00b7  \u8f93\u51fa " + rate_text + L" FPS" +
               L"  \u00b7  \u672c\u673a\u5df2\u63d0\u4ea4 " + std::to_wstring(metrics->published_frames) + L" \u5e27");
}

void StreamerDesktopApp::set_status(const std::wstring& text) {
    set_window_text_if_changed(status_text_, text);
}

void StreamerDesktopApp::set_ui_phase(HostUiPhase phase) {
    if (ui_phase_ == phase) return;
    ui_phase_ = phase;
    if (window_ == nullptr) return;
    if (host_ui_phase_requires_polling(phase)) {
        SetTimer(window_, kRefreshTimerId, 400, nullptr);
    } else {
        KillTimer(window_, kRefreshTimerId);
    }
    InvalidateRect(window_, nullptr, FALSE);
}

void StreamerDesktopApp::update_action_state(bool running, bool starting) {
    if (start_button_ == nullptr || stop_button_ == nullptr) return;
    ShowWindow(start_button_, running || starting ? SW_HIDE : SW_SHOW);
    ShowWindow(stop_button_, running || starting ? SW_SHOW : SW_HIDE);
    EnableWindow(start_button_, !running && !starting);
    EnableWindow(stop_button_, running || starting);
}

void StreamerDesktopApp::append_event(const std::wstring& event) {
    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t prefix[16]{};
    swprintf_s(prefix, L"%02u:%02u:%02u  ", time.wHour, time.wMinute, time.wSecond);
    recent_events_.push_front(std::wstring{prefix} + event);
    while (recent_events_.size() > 5U) recent_events_.pop_back();
    update_event_text();
}

void StreamerDesktopApp::update_event_text() {
    if (events_text_ == nullptr) return;
    std::wstring text;
    for (const std::wstring& event : recent_events_) {
        if (!text.empty()) text += L"\r\n";
        text += event;
    }
    bool changed = set_window_text_if_changed(events_text_, text);
    if (events_title_text_ != nullptr) {
        const std::wstring title = L"\u6700\u8fd1\u4e8b\u4ef6 (" + std::to_wstring(recent_events_.size()) + L")";
        changed = set_window_text_if_changed(events_title_text_, title) || changed;
    }
    if (changed && window_ != nullptr) {
        // Check icons are drawn by the parent, so invalidate only their small
        // event-panel strip.  Live metric refreshes never invalidate the parent.
        const RECT event_icons = transform_rect(RECT{650, 646, 700, 800});
        InvalidateRect(window_, &event_icons, FALSE);
    }
}

void StreamerDesktopApp::open_diagnostics() const {
    wchar_t local_app_data[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data, MAX_PATH) == 0U) {
        MessageBoxW(window_, L"\u65e0\u6cd5\u89e3\u6790\u672c\u673a\u8bca\u65ad\u76ee\u5f55\u3002", L"VF Host", MB_OK | MB_ICONERROR);
        return;
    }
    const std::filesystem::path diagnostics =
        std::filesystem::path{local_app_data} / L"VisionForge" / L"DualMachine";
    std::error_code error;
    std::filesystem::create_directories(diagnostics, error);
    const auto result = reinterpret_cast<INT_PTR>(
        ShellExecuteW(window_, L"open", diagnostics.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
    if (result <= 32) {
        MessageBoxW(window_, diagnostics.c_str(), L"VF Host \u8bca\u65ad\u76ee\u5f55", MB_OK | MB_ICONINFORMATION);
    }
}

}  // namespace vfdual
