#pragma once

#include <cstdint>

struct ID3D11Device;
struct ID3D11Texture2D;

namespace vfdual {

struct NvencSessionProbeResult {
    bool function_table_loaded{};
    bool session_opened{};
    std::int32_t nvenc_status{};
    std::uint32_t runtime_api_version{};
};

/** Creates and destroys a direct-D3D encoder session. It does not encode a frame. */
[[nodiscard]] NvencSessionProbeResult probe_nvenc_d3d11_session(ID3D11Device* device) noexcept;
/** Opens an NVENC D3D11 session and registers one BGRA texture without encoding it. */
[[nodiscard]] NvencSessionProbeResult probe_nvenc_d3d11_texture_registration(
    ID3D11Device* device, ID3D11Texture2D* texture, std::uint32_t width, std::uint32_t height) noexcept;

}  // namespace vfdual
