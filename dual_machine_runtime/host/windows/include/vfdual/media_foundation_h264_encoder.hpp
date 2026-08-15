#pragma once

#include "vfdual/h264_encoder_config.hpp"
#include "vfdual/host_encoder_policy.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

struct ID3D11Device;
struct ID3D11Texture2D;

namespace vfdual {

enum class MediaFoundationEncoderMode { hardware, software };

struct MediaFoundationHardwareProbeResult {
    GraphicsAdapterVendor adapter_vendor{GraphicsAdapterVendor::unknown};
    std::uint32_t adapter_vendor_id{};
    std::uint32_t adapter_luid_low{};
    std::int32_t adapter_luid_high{};
    std::uint32_t matching_hardware_transforms{};
    std::int32_t hresult{};
    bool activation_succeeded{};
    std::string transform_name;
    std::string transform_clsid;
};

/** Enumerates only H.264 hardware MFTs associated with the supplied D3D11 adapter LUID. */
[[nodiscard]] MediaFoundationHardwareProbeResult probe_media_foundation_h264_hardware(
    ID3D11Device* device) noexcept;

/** Returns the physical adapter vendor behind a D3D11 device. */
[[nodiscard]] GraphicsAdapterVendor graphics_adapter_vendor(ID3D11Device* device) noexcept;

struct MediaFoundationEncodeResult {
    enum class Stage : std::int32_t {
        none,
        validate_input,
        texture_readback,
        color_conversion,
        submit_input,
        receive_output,
        normalize_annex_b,
        complete,
    };

    bool success{};
    bool keyframe{};
    std::int32_t hresult{};
    std::uint32_t bytes{};
    Stage stage{Stage::none};
};

/**
 * Windows-native H.264 encoder with separately proven hardware and software modes.
 *
 * The encoder accepts a BGRA D3D11 texture, performs a bounded readback and
 * NV12 conversion. Hardware mode uses only an adapter-LUID-filtered hardware
 * MFT; software mode uses the built-in Microsoft H.264 MFT. Hardware mode is
 * currently not zero-copy because conversion uses a bounded CPU readback.
 */
class MediaFoundationH264Encoder final {
public:
    MediaFoundationH264Encoder() noexcept;
    ~MediaFoundationH264Encoder();
    MediaFoundationH264Encoder(const MediaFoundationH264Encoder&) = delete;
    MediaFoundationH264Encoder& operator=(const MediaFoundationH264Encoder&) = delete;

    [[nodiscard]] bool initialize(
        ID3D11Device* device, const H264EncoderConfig& config,
        MediaFoundationEncoderMode mode = MediaFoundationEncoderMode::software) noexcept;
    [[nodiscard]] MediaFoundationEncodeResult encode(
        ID3D11Texture2D* texture, bool force_keyframe = false) noexcept;
    void reset() noexcept;

    [[nodiscard]] bool is_ready() const noexcept;
    [[nodiscard]] bool is_hardware() const noexcept;
    [[nodiscard]] GraphicsAdapterVendor adapter_vendor() const noexcept;
    [[nodiscard]] std::uint32_t adapter_vendor_id() const noexcept;
    [[nodiscard]] std::uint32_t adapter_luid_low() const noexcept;
    [[nodiscard]] std::int32_t adapter_luid_high() const noexcept;
    [[nodiscard]] std::uint32_t matching_hardware_transforms() const noexcept;
    [[nodiscard]] std::string_view transform_name() const noexcept;
    [[nodiscard]] std::string_view transform_clsid() const noexcept;
    [[nodiscard]] std::uint32_t effective_frames_per_second() const noexcept;
    [[nodiscard]] std::int32_t last_hresult() const noexcept;
    [[nodiscard]] std::span<const std::byte> access_unit() const noexcept;

private:
    struct State;
    std::unique_ptr<State> state_;
};

}  // namespace vfdual
