#include "vf/host/domain/decoded_frame_metadata_ledger.hpp"

#include <limits>

namespace vf::host::domain {

FrameLedgerResult DecodedFrameMetadataLedger::observe(
    const DecodedFrameMetadata& metadata) noexcept {
    if (!metadata.identity.valid()) {
        return {.disposition = FrameDisposition::Invalid};
    }

    if (current_epoch_ && metadata.identity.stream_epoch < *current_epoch_) {
        return {.disposition = FrameDisposition::RetiredEpoch};
    }

    const bool new_epoch = !current_epoch_ || metadata.identity.stream_epoch > *current_epoch_;
    if (new_epoch && (metadata.is_repeat || !metadata.content_updated || !metadata.is_idr)) {
        // 只有真正解码出的新鲜 IDR 能建立一个新 epoch。重复帧、未更新画面或 P/B 帧
        // 都不能凭更大的 epoch 清空当前高水位。
        return {.disposition = FrameDisposition::EpochRequiresIdr};
    }

    bool epoch_changed = false;
    if (new_epoch) {
        current_epoch_ = metadata.identity.stream_epoch;
        last_observed_sequence_.reset();
        last_observed_frame_.reset();
        last_fresh_frame_.reset();
        if (transition_id_ != std::numeric_limits<std::uint64_t>::max()) {
            ++transition_id_;
        }
        epoch_changed = true;
    }

    if (last_observed_sequence_) {
        if (metadata.identity.frame_sequence < *last_observed_sequence_) {
            return {.disposition = FrameDisposition::StaleSequence,
                    .epoch_changed = epoch_changed};
        }
        if (metadata.identity.frame_sequence == *last_observed_sequence_) {
            if (last_observed_frame_ &&
                (metadata.content_fingerprint != last_observed_frame_->content_fingerprint ||
                 metadata.is_idr != last_observed_frame_->is_idr ||
                 metadata.is_repeat != last_observed_frame_->is_repeat ||
                 metadata.content_updated != last_observed_frame_->content_updated)) {
                // 同一帧身份的语义字段也必须完全一致。否则一端可能把它当 repeat，
                // 另一端却当成新鲜 IDR，属于必须立即关闭链路的协议冲突。
                return {.disposition = FrameDisposition::SequenceConflict,
                        .epoch_changed = epoch_changed};
            }
            return {.disposition = FrameDisposition::Duplicate,
                    .epoch_changed = epoch_changed};
        }
    }

    last_observed_sequence_ = metadata.identity.frame_sequence;
    last_observed_frame_ = metadata;

    if (metadata.is_repeat || !metadata.content_updated) {
        return {.disposition = FrameDisposition::NotFresh,
                .accepted_for_inference = false,
                .epoch_changed = epoch_changed};
    }

    last_fresh_frame_ = metadata;
    return {.disposition = epoch_changed ? FrameDisposition::EpochAdvanced
                                         : FrameDisposition::Fresh,
            .accepted_for_inference = true,
            .epoch_changed = epoch_changed};
}

}  // namespace vf::host::domain
