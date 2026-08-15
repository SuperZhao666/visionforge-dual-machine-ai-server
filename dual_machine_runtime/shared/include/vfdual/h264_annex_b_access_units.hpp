#pragma once

#include <cstddef>
#include <span>
#include <vector>

namespace vfdual {

/**
 * Splits a complete Annex-B H.264 elementary stream into decoder-ready access
 * units.  It is deliberately a transport diagnostic helper: it does not
 * transcode, inspect pixels, or participate in the real-time host capture
 * path.  Each returned access unit retains its original start codes.
 */
[[nodiscard]] std::vector<std::vector<std::byte>> split_h264_annex_b_access_units(
    std::span<const std::byte> elementary_stream);

}  // namespace vfdual
