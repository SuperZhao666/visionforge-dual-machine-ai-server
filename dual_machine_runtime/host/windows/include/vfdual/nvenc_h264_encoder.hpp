#pragma once

#include "vfdual/h264_encoder_config.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

struct ID3D11Device;
struct ID3D11Texture2D;

namespace vfdual {

struct NvencEncodeResult {
    bool success{};
    bool keyframe{};
    std::int32_t nvenc_status{};
    std::uint32_t bytes{};
    enum class Stage : std::int32_t {
        none,
        validate_input,
        unregister_resource,
        register_resource,
        map_resource,
        encode_picture,
        lock_bitstream,
        copy_bitstream,
        complete,
    } stage{Stage::none};
};

/**
 * Persistent direct-D3D11 NVENC H.264 encoder.
 *
 * It owns the NVENC session and bitstream buffer. The caller owns the D3D11
 * device. The encoder retains up to three successfully registered textures
 * until reset or destruction. This class deliberately produces only H.264
 * access units and does not know about capture, networking, or application
 * policy.
 */
class NvencH264Encoder final {
public:
    NvencH264Encoder() noexcept;
    ~NvencH264Encoder();
    NvencH264Encoder(const NvencH264Encoder&) = delete;
    NvencH264Encoder& operator=(const NvencH264Encoder&) = delete;

    [[nodiscard]] bool initialize(ID3D11Device* device, const H264EncoderConfig& config) noexcept;
    [[nodiscard]] NvencEncodeResult encode(ID3D11Texture2D* texture, bool force_keyframe = false) noexcept;
    void reset() noexcept;

    [[nodiscard]] bool is_ready() const noexcept;
    [[nodiscard]] std::int32_t last_nvenc_status() const noexcept;
    [[nodiscard]] std::span<const std::byte> access_unit() const noexcept;

private:
    struct State;
    std::unique_ptr<State> state_;
};

}  // namespace vfdual
