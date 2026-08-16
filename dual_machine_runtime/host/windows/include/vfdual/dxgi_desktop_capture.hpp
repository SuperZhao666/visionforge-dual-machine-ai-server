#pragma once

#include <cstdint>
#include <memory>

struct ID3D11Device;
struct ID3D11DeviceContext;
struct ID3D11Texture2D;
struct IDXGIOutputDuplication;

namespace vfdual {

enum class CaptureStatus {
    frame_ready,
    timeout,
    pointer_only_skipped,
    outside_region_skipped,
    access_lost,
    device_removed,
    initialization_failed,
    failed,
};

/**
 * Region in the selected output's local coordinate space.
 *
 * Coordinates are signed on purpose: Windows virtual desktops permit outputs
 * to live left of or above the primary display.  DXGI copy coordinates are
 * converted to unsigned only after range and overflow validation.
 */
struct DesktopCaptureRegion {
    std::int32_t x{};
    std::int32_t y{};
    std::uint32_t width{};
    std::uint32_t height{};
};

struct CapturedDesktopFrame {
    ID3D11Texture2D* texture{};
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint64_t capture_qpc{};
    std::uint64_t last_present_qpc{};
    std::uint32_t accumulated_frames{};
    std::uint32_t missed_present_frames{};
    std::uint64_t content_sequence{};
    bool repeated_content{};
};

struct DesktopCaptureStatistics {
    std::uint64_t pointer_only_skips{};
    std::uint64_t outside_region_skips{};
    std::uint64_t missed_present_frames{};
    std::uint64_t static_content_repeats{};
};

/** DXGI Desktop Duplication capture source. The returned texture remains valid until the next capture call. */
class DxgiDesktopCapture final {
public:
    DxgiDesktopCapture() noexcept;
    ~DxgiDesktopCapture();
    DxgiDesktopCapture(const DxgiDesktopCapture&) = delete;
    DxgiDesktopCapture& operator=(const DxgiDesktopCapture&) = delete;

    [[nodiscard]] CaptureStatus initialize(
        std::uint32_t adapter_index = 0, std::uint32_t output_index = 0,
        DesktopCaptureRegion region = {}) noexcept;
    [[nodiscard]] CaptureStatus acquire_next(CapturedDesktopFrame& destination, std::uint32_t timeout_ms) noexcept;
    /** Returns the retained ROI snapshot without claiming a new desktop present. */
    [[nodiscard]] bool repeat_last(CapturedDesktopFrame& destination) noexcept;
    void reset() noexcept;
    [[nodiscard]] std::int32_t last_hresult() const noexcept;
    [[nodiscard]] ID3D11Device* native_device() const noexcept;
    [[nodiscard]] ID3D11DeviceContext* native_context() const noexcept;
    [[nodiscard]] DesktopCaptureStatistics statistics_snapshot() const noexcept;

private:
    struct State;
    std::unique_ptr<State> state_;
    std::int32_t last_hresult_{};
};

}  // namespace vfdual
