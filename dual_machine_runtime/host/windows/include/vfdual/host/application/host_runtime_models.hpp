#pragma once

#include "vfdual/host/domain/capture_region.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace vfdual::host::application {

/** Stable application request; contains no DXGI, D3D11, socket or encoder types. */
struct HostStartRequest final {
    std::string local_host{"10.57.23.1"};
    std::string phone_host;
    std::string transport{"cat6"};
    std::uint32_t adapter_index{};
    std::uint32_t output_index{};
    std::uint32_t width{};
    std::uint32_t height{};
    std::optional<domain::CaptureRegion> capture_region;
    std::string display_id;
    std::int32_t display_left{};
    std::int32_t display_top{};
    std::int32_t display_right{};
    std::int32_t display_bottom{};
    std::int32_t roi_left{};
    std::int32_t roi_top{};
    std::int32_t roi_right{};
    std::int32_t roi_bottom{};
    std::uint32_t source_width{};
    std::uint32_t source_height{};
    std::string fallback_reason{"none"};
    std::string display_selection_reason{"system_primary"};
    std::uint32_t encoder_timing_fps{};
};

/** Stable UI read model translated from infrastructure-owned runtime metrics. */
struct HostRuntimeReadModel final {
    std::uint64_t stream_epoch{};
    std::uint64_t source_sequence{};
    std::uint64_t frame_sequence{};
    std::uint64_t capture_us{};
    std::uint64_t readback_wait_us{};
    std::uint64_t readback_copy_us{};
    std::uint64_t bridge_us{};
    std::uint64_t upload_us{};
    std::uint64_t encode_us{};
    std::uint64_t publish_us{};
    std::uint64_t capture_to_publish_us{};
    std::uint64_t published_frames{};
    std::int32_t encoder_backend{};
    std::int32_t encoder_vendor{};
    bool encoder_same_adapter{};
    std::uint32_t recovery_count{};
    std::string display_id;
    std::string transport;
    std::string mobile_ipv4;
    bool mobile_reachable{};
    std::uint64_t mobile_last_success_age_ms{};
    double rtt_ms{};
    double throughput_mbps{};
};

}  // namespace vfdual::host::application
