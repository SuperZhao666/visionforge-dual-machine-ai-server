#pragma once

#include "vf/wire_protocol.hpp"

#include "vf/host/domain/frame_identity.hpp"

#include <chrono>
#include <cstdint>
#include <optional>

namespace vf::host::domain {

/**
 * 解码后帧的事实记录。content_fingerprint 是上层计算出的轻量内容指纹；它不承担
 * 密码学用途，只用于识别“序号相同但内容不同”的协议冲突。
 */
struct DecodedFrameMetadata {
    FrameIdentity identity{};
    std::uint64_t content_fingerprint{};
    bool is_idr{};
    bool is_repeat{};
    bool content_updated{};
    std::chrono::steady_clock::time_point decoded_at{};
};

enum class FrameDisposition {
    Fresh,
    EpochAdvanced,
    EpochRequiresIdr,
    Duplicate,
    SequenceConflict,
    StaleSequence,
    RetiredEpoch,
    NotFresh,
    Invalid,
};

struct FrameLedgerResult {
    FrameDisposition disposition{FrameDisposition::Invalid};
    bool accepted_for_inference{};
    bool epoch_changed{};
};

/**
 * 单调帧元数据账本。
 *
 * 核心不变量：
 * 1. stream_epoch 只能前进，旧 epoch 永远不能凭延迟 UDP 包重新夺回接收器；
 * 2. 同一 epoch 内 frame_sequence 只能前进；
 * 3. repeat 或 content_updated=false 只更新“看见过”的事实，不会伪装成新鲜推理输入；
 * 4. 相同身份但不同内容指纹属于冲突，必须 fail-closed。
 */
class DecodedFrameMetadataLedger {
public:
    [[nodiscard]] FrameLedgerResult observe(const DecodedFrameMetadata& metadata) noexcept;

    [[nodiscard]] std::optional<std::uint64_t> current_epoch() const noexcept {
        return current_epoch_;
    }
    [[nodiscard]] std::optional<std::uint32_t> last_observed_sequence() const noexcept {
        return last_observed_sequence_;
    }
    [[nodiscard]] std::optional<DecodedFrameMetadata> last_fresh_frame() const noexcept {
        return last_fresh_frame_;
    }
    [[nodiscard]] std::uint64_t transition_id() const noexcept { return transition_id_; }

private:
    std::optional<std::uint64_t> current_epoch_;
    std::optional<std::uint32_t> last_observed_sequence_;
    std::optional<DecodedFrameMetadata> last_observed_frame_;
    std::optional<DecodedFrameMetadata> last_fresh_frame_;
    std::uint64_t transition_id_{};
};

}  // namespace vf::host::domain
