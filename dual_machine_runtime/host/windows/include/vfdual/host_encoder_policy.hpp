#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace vfdual {

enum class GraphicsAdapterVendor {
    unknown,
    microsoft,
    nvidia,
    amd,
    intel,
};

enum class H264EncoderPreference {
    automatic,
    automatic_without_async_shared,
    nvenc,
    media_foundation,
    software,
};
enum class H264EncoderBackend { none, nvenc, windows_hardware, software_cpu };

enum class HostEncoderCandidate {
    nvenc_same_adapter_async_shared,
    nvenc_capture_device,
    nvenc_cross_adapter,
    windows_hardware_capture_device,
    software_cpu,
};

struct HostEncoderCandidateList {
    std::array<HostEncoderCandidate, 4> values{};
    std::size_t size{};
};

/** The bounded asynchronous paths copy model-sized textures without scaling. */
[[nodiscard]] constexpr bool host_async_pipeline_supports_capture_extent(
    std::uint32_t capture_width, std::uint32_t capture_height,
    std::uint32_t encoder_width, std::uint32_t encoder_height) noexcept {
    return capture_width != 0U && capture_height != 0U &&
        capture_width == encoder_width && capture_height == encoder_height;
}

/** Pure startup policy. Availability is proven while each candidate initializes. */
[[nodiscard]] constexpr HostEncoderCandidateList choose_host_encoder_candidates(
    H264EncoderPreference preference, GraphicsAdapterVendor capture_vendor) noexcept {
    if (preference == H264EncoderPreference::nvenc) {
        // An explicit NVENC request preserves its historical direct/zero-copy
        // meaning on NVIDIA. Non-NVIDIA capture must use the transfer path.
        return capture_vendor == GraphicsAdapterVendor::nvidia
            ? HostEncoderCandidateList{{
                  HostEncoderCandidate::nvenc_capture_device,
              }, 1}
            : HostEncoderCandidateList{{
                  HostEncoderCandidate::nvenc_cross_adapter,
              }, 1};
    }
    if (preference == H264EncoderPreference::software) {
        return HostEncoderCandidateList{{HostEncoderCandidate::software_cpu}, 1};
    }
    if (preference == H264EncoderPreference::media_foundation) {
        return HostEncoderCandidateList{{
            HostEncoderCandidate::windows_hardware_capture_device,
            HostEncoderCandidate::software_cpu,
        }, 2};
    }
    if (capture_vendor == GraphicsAdapterVendor::nvidia &&
        preference != H264EncoderPreference::automatic_without_async_shared) {
        return HostEncoderCandidateList{{
            HostEncoderCandidate::nvenc_same_adapter_async_shared,
            HostEncoderCandidate::nvenc_capture_device,
            HostEncoderCandidate::windows_hardware_capture_device,
            HostEncoderCandidate::software_cpu,
        }, 4};
    }
    if (capture_vendor == GraphicsAdapterVendor::nvidia) {
        return HostEncoderCandidateList{{
            HostEncoderCandidate::nvenc_capture_device,
            HostEncoderCandidate::windows_hardware_capture_device,
            HostEncoderCandidate::software_cpu,
        }, 3};
    }
    return HostEncoderCandidateList{{
        HostEncoderCandidate::nvenc_cross_adapter,
        HostEncoderCandidate::windows_hardware_capture_device,
        HostEncoderCandidate::software_cpu,
    }, 3};
}

}  // namespace vfdual
