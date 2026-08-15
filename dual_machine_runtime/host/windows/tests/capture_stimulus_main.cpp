#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>

#include <d3d11.h>
#include <dxgi.h>
#include <wrl/client.h>

#include "vfdual/model_contract.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using Microsoft::WRL::ComPtr;
constexpr wchar_t kWindowClassName[] = L"VisionForgeCaptureStimulus";
constexpr wchar_t kWindowTitle[] = L"VF Capture Stimulus";
static_assert(
    vfdual::kDefaultMobileModel.input.width == vfdual::kDefaultMobileModel.input.height,
    "Capture stimulus requires a square AI model input.");
constexpr std::uint32_t kRoiEdge = vfdual::kDefaultMobileModel.input.width;
constexpr std::uint32_t kDefaultDurationSeconds = 60U;
constexpr std::uint32_t kDefaultRawFps = 144U;
// Raw frames are tightly packed top-down rows in BGRA byte order.
constexpr std::size_t kRawFrameBytes =
    static_cast<std::size_t>(kRoiEdge) * kRoiEdge * 4U;

enum class ExitCode : int {
    success = 0,
    display_too_small = 2,
    window_class_registration_failed = 3,
    window_creation_failed = 4,
    d3d_initialization_failed = 5,
    back_buffer_initialization_failed = 6,
    present_failed = 7,
    invalid_arguments = 8,
    raw_file_open_failed = 9,
    raw_file_size_invalid = 10,
    raw_file_read_failed = 11,
};

struct CommandLineOptions {
    std::uint32_t duration_seconds{kDefaultDurationSeconds};
    std::optional<std::filesystem::path> raw_bgra_path;
    std::uint32_t raw_fps{kDefaultRawFps};
};

struct ParseOptionsResult {
    CommandLineOptions options;
    std::wstring error;
};

enum class RawFileStatus {
    ready,
    open_failed,
    invalid_size,
    read_failed,
};

LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_CLOSE) {
        DestroyWindow(window);
        return 0;
    }
    if (message == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    if (message == WM_KEYDOWN && wparam == VK_ESCAPE) {
        DestroyWindow(window);
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

bool parse_bounded_unsigned(
    std::wstring_view value, std::uint32_t minimum, std::uint32_t maximum,
    std::uint32_t& destination) noexcept {
    if (value.empty()) return false;
    std::uint32_t parsed{};
    for (const wchar_t character : value) {
        if (character < L'0' || character > L'9') return false;
        const std::uint32_t digit = static_cast<std::uint32_t>(character - L'0');
        if (parsed > (maximum - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    if (parsed < minimum || parsed > maximum) return false;
    destination = parsed;
    return true;
}

ParseOptionsResult parse_options() {
    ParseOptionsResult result{};
    int argument_count{};
    wchar_t** arguments = CommandLineToArgvW(GetCommandLineW(), &argument_count);
    if (arguments == nullptr) {
        result.error = L"CommandLineToArgvW failed";
        return result;
    }

    bool duration_seen{};
    bool raw_path_seen{};
    bool raw_fps_seen{};
    for (int index = 1; index < argument_count && result.error.empty(); ++index) {
        const std::wstring_view option{arguments[index]};
        if (option == L"--duration-seconds") {
            if (duration_seen || index + 1 >= argument_count ||
                !parse_bounded_unsigned(
                    arguments[++index], 1U, 3'600U,
                    result.options.duration_seconds)) {
                result.error = L"--duration-seconds requires one value in 1..3600";
            }
            duration_seen = true;
            continue;
        }
        if (option == L"--raw-bgra") {
            if (raw_path_seen || index + 1 >= argument_count ||
                std::wstring_view{arguments[index + 1]}.empty()) {
                result.error = L"--raw-bgra requires one non-empty file path";
            } else {
                result.options.raw_bgra_path = std::filesystem::path{arguments[++index]};
            }
            raw_path_seen = true;
            continue;
        }
        if (option == L"--raw-fps") {
            if (raw_fps_seen || index + 1 >= argument_count ||
                !parse_bounded_unsigned(
                    arguments[++index], 1U, 240U, result.options.raw_fps)) {
                result.error = L"--raw-fps requires one value in 1..240";
            }
            raw_fps_seen = true;
            continue;
        }
        result.error = L"Unknown argument: ";
        result.error.append(option);
    }
    LocalFree(arguments);
    if (result.error.empty() && raw_fps_seen && !result.options.raw_bgra_path.has_value()) {
        result.error = L"--raw-fps requires --raw-bgra";
    }
    return result;
}

int report_error(ExitCode code, std::wstring_view detail) {
    std::wstring message = L"Error code ";
    message.append(std::to_wstring(static_cast<int>(code)));
    message.append(L": ");
    message.append(detail);
    MessageBoxW(nullptr, message.c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
    return static_cast<int>(code);
}

class RawBgraFrameReader final {
public:
    [[nodiscard]] RawFileStatus open(const std::filesystem::path& path) {
        stream_.open(path, std::ios::binary | std::ios::ate);
        if (!stream_) return RawFileStatus::open_failed;

        const std::streamoff file_size = stream_.tellg();
        if (file_size < 0) return RawFileStatus::read_failed;
        const auto frame_bytes = static_cast<std::streamoff>(kRawFrameBytes);
        if (file_size == 0 || file_size % frame_bytes != 0) {
            return RawFileStatus::invalid_size;
        }
        frame_count_ = static_cast<std::uint64_t>(file_size / frame_bytes);
        stream_.seekg(0, std::ios::beg);
        return stream_ ? RawFileStatus::ready : RawFileStatus::read_failed;
    }

    [[nodiscard]] bool read_next(std::vector<std::uint32_t>& destination) {
        if (next_frame_index_ == frame_count_) {
            stream_.clear();
            stream_.seekg(0, std::ios::beg);
            next_frame_index_ = 0U;
        }
        stream_.read(
            reinterpret_cast<char*>(destination.data()),
            static_cast<std::streamsize>(kRawFrameBytes));
        if (stream_.gcount() != static_cast<std::streamsize>(kRawFrameBytes)) return false;
        ++next_frame_index_;
        return true;
    }

private:
    std::ifstream stream_;
    std::uint64_t frame_count_{};
    std::uint64_t next_frame_index_{};
};

class FrameScheduler final {
    using Clock = std::chrono::steady_clock;
    using HundredNanoseconds = std::chrono::duration<std::int64_t, std::ratio<1, 10'000'000>>;

public:
    explicit FrameScheduler(std::uint32_t frames_per_second)
        : interval_(std::chrono::duration_cast<Clock::duration>(
              std::chrono::duration<double>(1.0 / frames_per_second))),
          next_frame_at_(Clock::now()),
          timer_(CreateWaitableTimerExW(
              nullptr, nullptr, 0x00000002U /* CREATE_WAITABLE_TIMER_HIGH_RESOLUTION */,
              TIMER_ALL_ACCESS)) {}

    ~FrameScheduler() {
        if (timer_ != nullptr) CloseHandle(timer_);
    }

    FrameScheduler(const FrameScheduler&) = delete;
    FrameScheduler& operator=(const FrameScheduler&) = delete;

    [[nodiscard]] bool wait_for_next(Clock::time_point deadline) {
        if (next_frame_at_ >= deadline) return false;
        auto now = Clock::now();
        if (now < next_frame_at_) {
            const auto remaining = next_frame_at_ - now;
            const std::int64_t ticks = std::max<std::int64_t>(
                1, std::chrono::duration_cast<HundredNanoseconds>(remaining).count());
            LARGE_INTEGER due_time{};
            due_time.QuadPart = -ticks;
            if (timer_ == nullptr ||
                !SetWaitableTimer(timer_, &due_time, 0, nullptr, nullptr, FALSE) ||
                WaitForSingleObject(timer_, INFINITE) != WAIT_OBJECT_0) {
                std::this_thread::sleep_until(next_frame_at_);
            }
            now = Clock::now();
        }
        if (now >= deadline) return false;
        next_frame_at_ += interval_;
        if (next_frame_at_ <= now) {
            const auto skipped_intervals = (now - next_frame_at_) / interval_ + 1;
            next_frame_at_ += interval_ * skipped_intervals;
        }
        return true;
    }

private:
    Clock::duration interval_;
    Clock::time_point next_frame_at_;
    HANDLE timer_{};
};

RECT primary_monitor_rect() noexcept {
    MONITORINFO monitor_info{};
    monitor_info.cbSize = sizeof(monitor_info);
    const HMONITOR monitor = MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY);
    return GetMonitorInfoW(monitor, &monitor_info) ? monitor_info.rcMonitor : RECT{0, 0, 1920, 1080};
}

void render_unique_roi(std::vector<std::uint32_t>& pixels, std::uint64_t frame_index) {
    const std::uint32_t phase = static_cast<std::uint32_t>(frame_index);
    for (std::uint32_t y = 0; y < kRoiEdge; ++y) {
        for (std::uint32_t x = 0; x < kRoiEdge; ++x) {
            const std::uint32_t checker = ((x / 8U) ^ (y / 8U) ^ phase) & 1U;
            const std::uint8_t red = static_cast<std::uint8_t>((x + phase * 3U) & 0xffU);
            const std::uint8_t green = static_cast<std::uint8_t>((y + phase * 5U) & 0xffU);
            const std::uint8_t blue = checker != 0U ? 0xf0U : static_cast<std::uint8_t>(phase & 0xffU);
            pixels[static_cast<std::size_t>(y) * kRoiEdge + x] =
                0xff000000U | (static_cast<std::uint32_t>(red) << 16U) |
                (static_cast<std::uint32_t>(green) << 8U) | blue;
        }
    }

    // The first 32 columns carry an explicit little-endian frame counter.
    // A future acceptance reader can recover uniqueness without OCR.
    for (std::uint32_t bit = 0; bit < 32U; ++bit) {
        const std::uint32_t color = ((phase >> bit) & 1U) != 0U
            ? 0xffffffffU : 0xff000000U;
        for (std::uint32_t y = 0; y < 16U; ++y) {
            pixels[static_cast<std::size_t>(y) * kRoiEdge + bit] = color;
        }
    }
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    const ParseOptionsResult parsed = parse_options();
    if (!parsed.error.empty()) {
        return report_error(ExitCode::invalid_arguments, parsed.error);
    }
    const CommandLineOptions& options = parsed.options;
    const bool raw_mode = options.raw_bgra_path.has_value();
    RawBgraFrameReader raw_frames;
    if (raw_mode) {
        const RawFileStatus raw_status = raw_frames.open(*options.raw_bgra_path);
        if (raw_status == RawFileStatus::open_failed) {
            return report_error(
                ExitCode::raw_file_open_failed, L"Unable to open the BGRA raw file");
        }
        if (raw_status == RawFileStatus::invalid_size) {
            return report_error(
                ExitCode::raw_file_size_invalid,
                L"Raw file must contain one or more complete model-input BGRA frames");
        }
        if (raw_status == RawFileStatus::read_failed) {
            return report_error(
                ExitCode::raw_file_read_failed, L"Unable to seek to the first raw frame");
        }
    }
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    const RECT monitor = primary_monitor_rect();
    const int width = monitor.right - monitor.left;
    const int height = monitor.bottom - monitor.top;
    if (width < static_cast<int>(kRoiEdge) || height < static_cast<int>(kRoiEdge)) {
        return static_cast<int>(ExitCode::display_too_small);
    }

    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.hInstance = instance;
    window_class.lpfnWndProc = window_proc;
    window_class.lpszClassName = kWindowClassName;
    window_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    if (RegisterClassExW(&window_class) == 0U) {
        return static_cast<int>(ExitCode::window_class_registration_failed);
    }

    const HWND window = CreateWindowExW(
        WS_EX_APPWINDOW | WS_EX_TOPMOST, kWindowClassName, kWindowTitle,
        WS_POPUP | WS_VISIBLE,
        monitor.left, monitor.top, width, height, nullptr, nullptr, instance, nullptr);
    if (window == nullptr) return static_cast<int>(ExitCode::window_creation_failed);
    SetWindowPos(
        window, HWND_TOPMOST, monitor.left, monitor.top, width, height,
        SWP_SHOWWINDOW | SWP_NOOWNERZORDER);
    ShowWindow(window, SW_SHOW);
    SetForegroundWindow(window);

    DXGI_SWAP_CHAIN_DESC swap_chain_description{};
    swap_chain_description.BufferDesc.Width = static_cast<UINT>(width);
    swap_chain_description.BufferDesc.Height = static_cast<UINT>(height);
    swap_chain_description.BufferDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    swap_chain_description.SampleDesc.Count = 1U;
    swap_chain_description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swap_chain_description.BufferCount = 2U;
    swap_chain_description.OutputWindow = window;
    swap_chain_description.Windowed = TRUE;
    // Modern flip presentation avoids the legacy blt-model copy and gives
    // Desktop Duplication a deterministic display-paced source.
    swap_chain_description.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IDXGISwapChain> swap_chain;
    D3D_FEATURE_LEVEL selected{};
    const std::array levels{D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
    const HRESULT device_result = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
        levels.data(), static_cast<UINT>(levels.size()), D3D11_SDK_VERSION,
        &swap_chain_description, &swap_chain, &device, &selected, &context);
    if (FAILED(device_result)) return static_cast<int>(ExitCode::d3d_initialization_failed);

    ComPtr<ID3D11Texture2D> back_buffer;
    if (FAILED(swap_chain->GetBuffer(0U, IID_PPV_ARGS(&back_buffer)))) {
        return static_cast<int>(ExitCode::back_buffer_initialization_failed);
    }
    ComPtr<ID3D11RenderTargetView> back_buffer_view;
    if (FAILED(device->CreateRenderTargetView(
            back_buffer.Get(), nullptr, &back_buffer_view))) {
        return static_cast<int>(ExitCode::back_buffer_initialization_failed);
    }
    std::vector<std::uint32_t> pixels(static_cast<std::size_t>(kRoiEdge) * kRoiEdge);
    const UINT roi_left = static_cast<UINT>((width - static_cast<int>(kRoiEdge)) / 2);
    const UINT roi_top = static_cast<UINT>((height - static_cast<int>(kRoiEdge)) / 2);
    const D3D11_BOX roi_box{
        roi_left, roi_top, 0U, roi_left + kRoiEdge, roi_top + kRoiEdge, 1U};

    const auto started_at = std::chrono::steady_clock::now();
    std::optional<FrameScheduler> raw_scheduler;
    if (raw_mode) raw_scheduler.emplace(options.raw_fps);
    const auto deadline = started_at +
        std::chrono::seconds(options.duration_seconds);
    auto next_title_update = started_at + std::chrono::seconds(1);
    std::uint64_t frame_index{};
    bool running = true;
    while (running && std::chrono::steady_clock::now() < deadline) {
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0U, 0U, PM_REMOVE)) {
            if (message.message == WM_QUIT) {
                running = false;
                break;
            }
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        if (!running) break;
        if (raw_mode) {
            if (!raw_frames.read_next(pixels)) {
                return report_error(
                    ExitCode::raw_file_read_failed, L"Unable to read the next raw frame");
            }
            if (!raw_scheduler->wait_for_next(deadline)) break;
            ++frame_index;
        } else {
            render_unique_roi(pixels, frame_index++);
        }
        constexpr float background[]{0.018F, 0.024F, 0.038F, 1.0F};
        context->ClearRenderTargetView(back_buffer_view.Get(), background);
        context->UpdateSubresource(
            back_buffer.Get(), 0U, &roi_box, pixels.data(), kRoiEdge * 4U, 0U);
        // Raw playback already has an absolute scheduler.  Waiting for another
        // vblank here makes non-divisor rates (for example 120 FPS on 144 Hz)
        // miss the next refresh and collapse to roughly half-rate.  Submit raw
        // frames immediately; Desktop Duplication still cannot observe more
        // updates than the physical output.  Preserve the legacy generated
        // stimulus' display-paced behaviour.
        const UINT sync_interval = raw_mode ? 0U : 1U;
        const HRESULT present_result = swap_chain->Present(sync_interval, 0U);
        if (FAILED(present_result)) return static_cast<int>(ExitCode::present_failed);
        const auto now = std::chrono::steady_clock::now();
        if (now >= next_title_update) {
            const double elapsed_seconds =
                std::chrono::duration<double>(now - started_at).count();
            const auto measured_fps = static_cast<std::uint32_t>(
                static_cast<double>(frame_index) / elapsed_seconds + 0.5);
            const std::wstring source = raw_mode
                ? L"raw=" + std::to_wstring(options.raw_fps) + L" FPS | measured="
                : L"source=";
            const std::wstring title = std::wstring{kWindowTitle} + L" | " + source +
                std::to_wstring(measured_fps) + L" FPS | frames=" + std::to_wstring(frame_index);
            SetWindowTextW(window, title.c_str());
            next_title_update = now + std::chrono::seconds(1);
        }
    }
    DestroyWindow(window);
    return static_cast<int>(ExitCode::success);
}
