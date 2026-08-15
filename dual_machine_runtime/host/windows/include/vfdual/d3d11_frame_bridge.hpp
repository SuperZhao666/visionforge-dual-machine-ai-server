#pragma once

#include <cstdint>
#include <memory>

struct ID3D11Device;
struct ID3D11DeviceContext;
struct ID3D11Texture2D;

namespace vfdual {

enum class FrameBridgeMode {
    zero_copy,
    gpu_scale_cpu_upload,
    cpu_staging_upload,
    gpu_scale_zero_copy,
    cross_adapter_shared_texture,
    hybrid_async_readback_upload,
    same_adapter_async_shared_texture,
};

enum class FrameEncoderDevicePreference { nvidia, capture_source };

struct BridgedFrame {
    ID3D11Texture2D* texture{};
    FrameBridgeMode mode{FrameBridgeMode::cpu_staging_upload};
    std::int32_t hresult{};
};

/**
 * Makes a captured BGRA texture consumable by NVENC.
 *
 * It also owns the source-to-encoder letterbox contract. Exact-size NVIDIA
 * textures are handed through directly. Exact-size hybrid-GPU paths first try
 * an NT-handle shared texture synchronized by a keyed mutex, avoiding a CPU
 * readback. Drivers that cannot share across adapters retain the CPU staging
 * fallback. Resized inputs use the source-GPU video processor before handoff.
 */
class D3D11FrameBridge final {
public:
    D3D11FrameBridge() noexcept;
    ~D3D11FrameBridge();
    D3D11FrameBridge(const D3D11FrameBridge&) = delete;
    D3D11FrameBridge& operator=(const D3D11FrameBridge&) = delete;

    [[nodiscard]] bool initialize(
        ID3D11Device* source_device, ID3D11DeviceContext* source_context,
        std::uint32_t target_width, std::uint32_t target_height,
        std::uint32_t presentation_timing_fps,
        FrameEncoderDevicePreference preference = FrameEncoderDevicePreference::nvidia) noexcept;
    [[nodiscard]] BridgedFrame bridge(ID3D11Texture2D* source_texture) noexcept;
    void reset() noexcept;

    [[nodiscard]] ID3D11Device* encoder_device() const noexcept;
    [[nodiscard]] bool uses_capture_device() const noexcept;
    [[nodiscard]] FrameBridgeMode mode() const noexcept;
    [[nodiscard]] std::int32_t last_hresult() const noexcept;

private:
    struct State;
    std::unique_ptr<State> state_;
};

}  // namespace vfdual
