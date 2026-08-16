#pragma once

#include "vfdual/protocol.hpp"

#include <cstddef>
#include <span>
#include <vector>

namespace vfdual {

/** Splits one encoded H.264 access unit into bounded v6.0 UDP fragments. */
[[nodiscard]] std::vector<VideoFragment> fragment_access_unit(
    VideoFrameIdentity identity,
    std::span<const std::byte> access_unit,
    bool repeated_content = false,
    std::size_t max_payload_bytes = kVideoPacketPayloadBytes);

}  // namespace vfdual
