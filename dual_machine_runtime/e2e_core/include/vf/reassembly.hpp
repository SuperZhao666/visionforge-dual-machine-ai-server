#pragma once

#include "vf/wire_protocol.hpp"

#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace vf {

struct ReassemblyConfig {
    std::size_t max_inflight_frames{16};
    std::size_t max_total_bytes{8U * 1024U * 1024U};
    std::size_t max_access_unit_bytes{2U * 1024U * 1024U};
    std::chrono::milliseconds frame_timeout{500};
    // 仅为旧配置文件兼容保留；实际安全语义使用单调 epoch 高水位，不再依赖有限退休环。
    std::size_t retired_epoch_capacity{8};
};

enum class IngestCode {
    Accepted,
    Complete,
    Duplicate,
    Conflict,
    Invalid,
    RetiredEpoch,
    ResourceLimit,
    CandidateRejected,
    GapDetected,
    Repeat,
};

struct IngestResult {
    IngestCode code{IngestCode::Invalid};
    std::uint64_t stream_epoch{};
    std::uint32_t frame_sequence{};
    std::vector<std::uint8_t> access_unit{};
    // true 表示这是尚未获得接收会话所有权的新 epoch。调用方验证完整 IDR 后
    // 必须立即 commit_candidate_epoch()；验证失败则 reject_candidate_epoch()。
    bool requires_epoch_commit{};
};

/**
 * 有界访问单元重组器。
 *
 * <p>旧 epoch 永久由单调高水位拒绝。新 epoch 先在单一候选槽中组装，只有上层确认
 * 完整新鲜 IDR 后才提交，因此单个高 epoch 半帧、冲突帧或 malformed 完整帧不能
 * 退休健康会话。活动 epoch 的半帧超时或资源淘汰会显式返回 GapDetected/
 * ResourceLimit；候选失败只回收候选，不破坏当前预测链。</p>
 */
class AccessUnitReassembler {
public:
    using TimePoint = std::chrono::steady_clock::time_point;

    explicit AccessUnitReassembler(ReassemblyConfig config = {});
    [[nodiscard]] IngestResult ingest(
        const WireHeader& header,
        std::span<const std::uint8_t> payload,
        TimePoint now);

    /** 只允许提交刚刚完整返回、且仍高于当前高水位的候选 epoch。 */
    [[nodiscard]] bool commit_candidate_epoch(std::uint64_t epoch) noexcept;
    /** 上层判定候选访问单元不是有效 IDR 时，丢弃该候选而不影响当前会话。 */
    void reject_candidate_epoch(std::uint64_t epoch) noexcept;

    void expire(TimePoint now);
    void discard_inflight() noexcept;

    [[nodiscard]] std::optional<std::uint64_t> current_epoch() const noexcept { return current_epoch_; }
    [[nodiscard]] std::optional<std::uint64_t> candidate_epoch() const noexcept {
        return candidate_epoch_;
    }
    [[nodiscard]] std::size_t inflight_count() const noexcept { return frames_.size(); }
    [[nodiscard]] std::size_t inflight_bytes() const noexcept { return total_bytes_; }
    [[nodiscard]] bool is_retired(std::uint64_t epoch) const noexcept;

private:
    struct FrameKey {
        std::uint64_t epoch{};
        std::uint32_t sequence{};
        friend auto operator<=>(const FrameKey&, const FrameKey&) = default;
    };

    struct Frame {
        std::uint16_t fragment_count{};
        std::vector<std::optional<std::vector<std::uint8_t>>> fragments;
        std::uint16_t received_fragments{};
        std::size_t bytes{};
        TimePoint created_at{};
    };

    [[nodiscard]] bool is_candidate(std::uint64_t epoch) const noexcept;
    [[nodiscard]] bool has_frames_for_epoch(std::uint64_t epoch) const noexcept;
    [[nodiscard]] bool select_candidate_epoch(std::uint64_t epoch) noexcept;
    void erase_frame(const FrameKey& key) noexcept;
    void erase_epoch(std::uint64_t epoch) noexcept;
    void erase_noncurrent_epochs() noexcept;
    void erase_older_epochs(std::uint64_t epoch) noexcept;
    [[nodiscard]] IngestResult resource_failure(const WireHeader& header, bool candidate) noexcept;
    [[nodiscard]] IngestResult candidate_failure(const WireHeader& header) noexcept;

    ReassemblyConfig config_;
    std::optional<std::uint64_t> current_epoch_;
    std::optional<std::uint64_t> candidate_epoch_;
    bool candidate_ready_{};
    std::map<FrameKey, Frame> frames_;
    std::size_t total_bytes_{};
    bool gap_detected_{};
};

}  // namespace vf
