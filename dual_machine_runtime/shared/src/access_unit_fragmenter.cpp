#include "vfdual/access_unit_fragmenter.hpp"

#include <algorithm>

namespace vfdual {
std::vector<VideoFragment> fragment_access_unit(
    std::uint32_t frame_id,
    std::span<const std::byte> access_unit,
    std::size_t max_payload_bytes) {
    if (access_unit.empty() || access_unit.size() > kMaxAccessUnitBytes ||
        max_payload_bytes == 0 ||
        max_payload_bytes > kVideoPacketPayloadBytes) {
        return {};
    }
    const auto fragment_count = (access_unit.size() + max_payload_bytes - 1) / max_payload_bytes;
    if (fragment_count > kMaxVideoFragmentsPerAccessUnit) return {};
    std::vector<VideoFragment> fragments;
    fragments.reserve(fragment_count);
    for (std::size_t offset = 0, index = 0; offset < access_unit.size(); offset += max_payload_bytes, ++index) {
        const auto bytes = std::min(max_payload_bytes, access_unit.size() - offset);
        fragments.push_back(VideoFragment{
            frame_id,
            static_cast<std::uint16_t>(index),
            static_cast<std::uint16_t>(fragment_count),
            std::vector<std::byte>(access_unit.begin() + static_cast<std::ptrdiff_t>(offset), access_unit.begin() + static_cast<std::ptrdiff_t>(offset + bytes)),
        });
    }
    return fragments;
}
}  // namespace vfdual
