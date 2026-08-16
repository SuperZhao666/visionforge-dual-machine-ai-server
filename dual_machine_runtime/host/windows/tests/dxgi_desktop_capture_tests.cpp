#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <dxgi.h>

#include "vfdual/dxgi_desktop_capture.hpp"
#include "vfdual/host_display_catalog.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>

namespace {

int verify_wait_timeout_hresult(vfdual::DxgiDesktopCapture& capture) {
    vfdual::CapturedDesktopFrame ignored_frame{};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    while (std::chrono::steady_clock::now() < deadline) {
        const vfdual::CaptureStatus status = capture.acquire_next(ignored_frame, 0U);
        if (status == vfdual::CaptureStatus::timeout) {
            const auto expected = static_cast<std::int32_t>(DXGI_ERROR_WAIT_TIMEOUT);
            if (capture.last_hresult() != expected) {
                std::cerr << "DXGI timeout diagnostic mismatch expected=" << expected
                          << " actual=" << capture.last_hresult() << '\n';
                return 1;
            }
            return 0;
        }
        if (status != vfdual::CaptureStatus::frame_ready &&
            status != vfdual::CaptureStatus::pointer_only_skipped &&
            status != vfdual::CaptureStatus::outside_region_skipped) {
            std::cerr << "DXGI no-wait drain failed status=" << static_cast<int>(status)
                      << " HRESULT=" << capture.last_hresult() << '\n';
            return 1;
        }
    }
    std::cerr << "SKIP: active desktop never reached a no-wait DXGI timeout\n";
    return 77;
}

}  // namespace

int main() {
    constexpr std::uint32_t kCaptureEdge = vfdual::kAiCaptureEdge;
    const auto outputs = vfdual::enumerate_host_display_outputs();
    const auto* output = vfdual::select_preferred_display_output(outputs);
    if (output == nullptr || output->width < kCaptureEdge || output->height < kCaptureEdge) {
        std::cerr << "SKIP: no active output can provide the model input capture region\n";
        return 77;
    }
    const vfdual::DesktopCaptureRegion region{
        static_cast<std::int32_t>((output->width - kCaptureEdge) / 2U),
        static_cast<std::int32_t>((output->height - kCaptureEdge) / 2U),
        kCaptureEdge,
        kCaptureEdge,
    };
    vfdual::DxgiDesktopCapture capture;
    const auto initialized = capture.initialize(output->adapter_index, output->output_index, region);
    if (initialized != vfdual::CaptureStatus::frame_ready) {
        std::cerr << "DXGI initialization failed HRESULT=" << capture.last_hresult() << '\n';
        return 1;
    }
    vfdual::CapturedDesktopFrame frame;
    auto status = vfdual::CaptureStatus::timeout;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        status = capture.acquire_next(frame, 500);
        if (status == vfdual::CaptureStatus::frame_ready) break;
        if (status != vfdual::CaptureStatus::timeout &&
            status != vfdual::CaptureStatus::pointer_only_skipped &&
            status != vfdual::CaptureStatus::outside_region_skipped) {
            std::cerr << "DXGI frame acquisition failed status=" << static_cast<int>(status)
                      << " HRESULT=" << capture.last_hresult() << '\n';
            return 1;
        }
    }
    if (status != vfdual::CaptureStatus::frame_ready) {
        std::cerr << "SKIP: selected desktop output did not present a dynamic frame\n";
        return 77;
    }
    if (frame.texture == nullptr || frame.width != kCaptureEdge || frame.height != kCaptureEdge) {
        std::cerr << "DXGI frame contract mismatch status=" << static_cast<int>(status)
                  << " HRESULT=" << capture.last_hresult() << '\n';
        return 1;
    }
    const int timeout_contract_result = verify_wait_timeout_hresult(capture);
    if (timeout_contract_result != 0) return timeout_contract_result;
    std::cout << "DXGI capture OK " << frame.width << 'x' << frame.height << " qpc=" << frame.capture_qpc << '\n';
    return 0;
}
