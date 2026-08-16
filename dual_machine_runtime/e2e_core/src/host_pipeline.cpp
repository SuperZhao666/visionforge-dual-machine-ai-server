#include "vf/host_pipeline.hpp"

#include <cstdint>
#include <limits>

namespace vf {

bool CaptureRegion::valid_within(const DesktopBounds& desktop) const noexcept {
    if (width <= 0 || height <= 0 || desktop.width <= 0 || desktop.height <= 0) {
        return false;
    }
    const auto right = static_cast<std::int64_t>(left) + width;
    const auto bottom = static_cast<std::int64_t>(top) + height;
    const auto desktop_right = static_cast<std::int64_t>(desktop.left) + desktop.width;
    const auto desktop_bottom = static_cast<std::int64_t>(desktop.top) + desktop.height;
    return left >= desktop.left && top >= desktop.top && right <= desktop_right &&
           bottom <= desktop_bottom && right > left && bottom > top;
}

bool IdrDeliveryTracker::identity_is_newer(
    std::uint64_t stream_epoch,
    std::uint32_t frame_sequence,
    const std::optional<std::uint64_t>& other_epoch,
    const std::optional<std::uint32_t>& other_sequence) noexcept {
    if (!other_epoch || !other_sequence) {
        return true;
    }
    return stream_epoch > *other_epoch ||
        (stream_epoch == *other_epoch && frame_sequence > *other_sequence);
}

bool IdrDeliveryTracker::identity_is_same(
    std::uint64_t stream_epoch,
    std::uint32_t frame_sequence,
    const std::optional<std::uint64_t>& other_epoch,
    const std::optional<std::uint32_t>& other_sequence) noexcept {
    return other_epoch && other_sequence && stream_epoch == *other_epoch &&
        frame_sequence == *other_sequence;
}

void IdrDeliveryTracker::on_access_unit(
    std::uint64_t stream_epoch,
    std::uint32_t frame_sequence,
    bool is_idr,
    const PublishSummary& summary) noexcept {
    if (!is_idr) {
        return;
    }
    if (stream_epoch == 0 || stream_epoch > kMaxStreamEpoch) {
        idr_requested_ = true;
        return;
    }

    const bool newer_attempt = identity_is_newer(
        stream_epoch, frame_sequence,
        latest_observed_idr_epoch_, latest_observed_idr_sequence_);
    const bool same_attempt = identity_is_same(
        stream_epoch, frame_sequence,
        latest_observed_idr_epoch_, latest_observed_idr_sequence_);
    if (!newer_attempt && !same_attempt) {
        // 一个较旧 IDR 的迟到成功或失败，都不能覆盖后来 IDR 的真实终态。
        return;
    }
    if (newer_attempt) {
        latest_observed_idr_epoch_ = stream_epoch;
        latest_observed_idr_sequence_ = frame_sequence;
    }

    if (!summary.complete()) {
        idr_requested_ = true;
        return;
    }
    if (!identity_is_newer(
            stream_epoch, frame_sequence,
            last_delivered_epoch_, last_delivered_sequence_)) {
        // 同一已确认 IDR 的重复回调，尤其是在外部重新发起 IDR 请求后，不能把
        // 新请求错误清除，也不能制造重复交付计数。
        return;
    }

    last_delivered_epoch_ = stream_epoch;
    last_delivered_sequence_ = frame_sequence;
    idr_requested_ = false;
    if (delivered_idr_count_ != std::numeric_limits<std::uint64_t>::max()) {
        ++delivered_idr_count_;
    }
}

}  // namespace vf
