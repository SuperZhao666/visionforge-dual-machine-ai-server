#pragma once

#include "vf/wire_protocol.hpp"

#include <cstdint>

namespace vf::host::domain {

/** Host/APP 视频帧的全局有效身份；epoch 单调前进，sequence 仅在 epoch 内递增。 */
struct FrameIdentity {
    std::uint64_t stream_epoch{};
    std::uint32_t frame_sequence{};

    [[nodiscard]] bool valid() const noexcept {
        return stream_epoch > 0 && stream_epoch <= kMaxStreamEpoch;
    }

    [[nodiscard]] bool newer_than(const FrameIdentity& other) const noexcept {
        return stream_epoch > other.stream_epoch ||
            (stream_epoch == other.stream_epoch && frame_sequence > other.frame_sequence);
    }

    friend bool operator==(const FrameIdentity&, const FrameIdentity&) = default;
};

}  // namespace vf::host::domain
