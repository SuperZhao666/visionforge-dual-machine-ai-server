#pragma once

#include "vfdual/protocol.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace vfdual {

/** Splits one encoded H.264 access unit into v5.0 UDP payloads of at most 1400 bytes. */
[[nodiscard]] std::vector<VideoFragment> fragment_access_unit(
    std::uint32_t frame_id,
    std::span<const std::byte> access_unit,
    std::size_t max_payload_bytes = kVideoPacketPayloadBytes);

}  // namespace vfdual
