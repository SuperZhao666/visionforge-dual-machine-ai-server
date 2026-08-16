#include "vf/reassembly.hpp"

#include <algorithm>
#include <stdexcept>

namespace vf {

AccessUnitReassembler::AccessUnitReassembler(ReassemblyConfig config) : config_(config) {
    if (config_.max_inflight_frames == 0 || config_.max_total_bytes == 0 ||
        config_.max_access_unit_bytes == 0 || config_.retired_epoch_capacity == 0 ||
        config_.frame_timeout <= std::chrono::milliseconds::zero() ||
        config_.max_access_unit_bytes > config_.max_total_bytes) {
        throw std::invalid_argument("reassembly limits must be positive and internally consistent");
    }
}

bool AccessUnitReassembler::is_retired(std::uint64_t epoch) const noexcept {
    return current_epoch_.has_value() && epoch < *current_epoch_;
}

bool AccessUnitReassembler::is_candidate(std::uint64_t epoch) const noexcept {
    return !current_epoch_ || epoch > *current_epoch_;
}

bool AccessUnitReassembler::has_frames_for_epoch(std::uint64_t epoch) const noexcept {
    return std::any_of(frames_.begin(), frames_.end(), [epoch](const auto& entry) {
        return entry.first.epoch == epoch;
    });
}

bool AccessUnitReassembler::select_candidate_epoch(std::uint64_t epoch) noexcept {
    if (!candidate_epoch_) {
        candidate_epoch_ = epoch;
        candidate_ready_ = false;
        return true;
    }
    if (*candidate_epoch_ == epoch) {
        return !candidate_ready_;
    }
    if (candidate_ready_ || epoch < *candidate_epoch_) {
        return false;
    }

    // 尚未完成的旧候选可被更高 epoch 取代；低 epoch 或待确认完整候选不得被抢占。
    const auto superseded = *candidate_epoch_;
    erase_epoch(superseded);
    candidate_epoch_ = epoch;
    candidate_ready_ = false;
    return true;
}

void AccessUnitReassembler::erase_frame(const FrameKey& key) noexcept {
    const auto it = frames_.find(key);
    if (it == frames_.end()) {
        return;
    }
    total_bytes_ -= it->second.bytes;
    frames_.erase(it);
}

void AccessUnitReassembler::erase_epoch(std::uint64_t epoch) noexcept {
    for (auto it = frames_.begin(); it != frames_.end();) {
        if (it->first.epoch == epoch) {
            total_bytes_ -= it->second.bytes;
            it = frames_.erase(it);
        } else {
            ++it;
        }
    }
    if (candidate_epoch_ == epoch) {
        candidate_epoch_.reset();
        candidate_ready_ = false;
    }
}

void AccessUnitReassembler::erase_noncurrent_epochs() noexcept {
    for (auto it = frames_.begin(); it != frames_.end();) {
        if (!current_epoch_ || it->first.epoch != *current_epoch_) {
            total_bytes_ -= it->second.bytes;
            it = frames_.erase(it);
        } else {
            ++it;
        }
    }
    candidate_epoch_.reset();
    candidate_ready_ = false;
}

void AccessUnitReassembler::erase_older_epochs(std::uint64_t epoch) noexcept {
    for (auto it = frames_.begin(); it != frames_.end();) {
        if (it->first.epoch < epoch) {
            total_bytes_ -= it->second.bytes;
            it = frames_.erase(it);
        } else {
            ++it;
        }
    }
}

void AccessUnitReassembler::discard_inflight() noexcept {
    frames_.clear();
    total_bytes_ = 0;
    candidate_epoch_.reset();
    candidate_ready_ = false;
}

void AccessUnitReassembler::expire(TimePoint now) {
    for (auto it = frames_.begin(); it != frames_.end();) {
        const bool expired = now >= it->second.created_at &&
            now - it->second.created_at >= config_.frame_timeout;
        if (!expired) {
            ++it;
            continue;
        }
        // 候选 epoch 尚未拥有预测链；其半帧超时只丢弃候选，不得破坏健康当前流。
        if (current_epoch_ && it->first.epoch == *current_epoch_) {
            gap_detected_ = true;
        }
        total_bytes_ -= it->second.bytes;
        it = frames_.erase(it);
    }
    if (candidate_epoch_ && !candidate_ready_ && !has_frames_for_epoch(*candidate_epoch_)) {
        candidate_epoch_.reset();
    }
}

IngestResult AccessUnitReassembler::candidate_failure(const WireHeader& header) noexcept {
    reject_candidate_epoch(header.stream_epoch);
    return {.code = IngestCode::CandidateRejected,
            .stream_epoch = header.stream_epoch,
            .frame_sequence = header.frame_sequence};
}

IngestResult AccessUnitReassembler::resource_failure(
    const WireHeader& header,
    bool candidate) noexcept {
    if (candidate) {
        return candidate_failure(header);
    }
    discard_inflight();
    return {.code = IngestCode::ResourceLimit,
            .stream_epoch = header.stream_epoch,
            .frame_sequence = header.frame_sequence};
}

IngestResult AccessUnitReassembler::ingest(
    const WireHeader& header,
    std::span<const std::uint8_t> payload,
    TimePoint now) {
    if (!header.valid()) {
        return {.code = IngestCode::Invalid};
    }

    expire(now);
    if (is_retired(header.stream_epoch)) {
        return {.code = IngestCode::RetiredEpoch, .stream_epoch = header.stream_epoch,
                .frame_sequence = header.frame_sequence};
    }
    if (gap_detected_ && current_epoch_ && header.stream_epoch == *current_epoch_) {
        gap_detected_ = false;
        discard_inflight();
        return {.code = IngestCode::GapDetected, .stream_epoch = header.stream_epoch,
                .frame_sequence = header.frame_sequence};
    }

    // REPEAT 只描述当前已提交会话的“画面未更新”，绝不能创建候选或推进高水位。
    if (header.kind == PacketKind::Repeat) {
        if (!payload.empty() || !current_epoch_ || *current_epoch_ != header.stream_epoch) {
            return {.code = IngestCode::Invalid, .stream_epoch = header.stream_epoch,
                    .frame_sequence = header.frame_sequence};
        }
        return {.code = IngestCode::Repeat, .stream_epoch = header.stream_epoch,
                .frame_sequence = header.frame_sequence};
    }
    if (payload.empty() || payload.size() > config_.max_access_unit_bytes) {
        return {.code = IngestCode::Invalid, .stream_epoch = header.stream_epoch,
                .frame_sequence = header.frame_sequence};
    }

    const bool candidate = is_candidate(header.stream_epoch);
    if (candidate && !select_candidate_epoch(header.stream_epoch)) {
        return {.code = IngestCode::CandidateRejected,
                .stream_epoch = header.stream_epoch,
                .frame_sequence = header.frame_sequence};
    }

    const FrameKey key{header.stream_epoch, header.frame_sequence};
    auto it = frames_.find(key);
    if (it == frames_.end()) {
        if (frames_.size() >= config_.max_inflight_frames) {
            if (!candidate) {
                erase_noncurrent_epochs();
            }
            if (frames_.size() >= config_.max_inflight_frames) {
                return resource_failure(header, candidate);
            }
        }
        Frame frame{
            .fragment_count = header.fragment_count,
            .fragments = std::vector<std::optional<std::vector<std::uint8_t>>>(header.fragment_count),
            .bytes = 0,
            .created_at = now,
        };
        it = frames_.emplace(key, std::move(frame)).first;
    } else if (it->second.fragment_count != header.fragment_count) {
        if (candidate) {
            return candidate_failure(header);
        }
        erase_frame(key);
        return {.code = IngestCode::Conflict, .stream_epoch = header.stream_epoch,
                .frame_sequence = header.frame_sequence};
    }
    Frame& frame = it->second;

    auto& slot = frame.fragments[header.fragment_index];
    if (slot) {
        if (slot->size() == payload.size() && std::equal(slot->begin(), slot->end(), payload.begin())) {
            return {.code = IngestCode::Duplicate, .stream_epoch = header.stream_epoch,
                    .frame_sequence = header.frame_sequence};
        }
        if (candidate) {
            return candidate_failure(header);
        }
        erase_frame(key);
        return {.code = IngestCode::Conflict, .stream_epoch = header.stream_epoch,
                .frame_sequence = header.frame_sequence};
    }

    if (!candidate && payload.size() > config_.max_total_bytes - total_bytes_) {
        erase_noncurrent_epochs();
    }
    if (payload.size() > config_.max_access_unit_bytes - frame.bytes ||
        payload.size() > config_.max_total_bytes - total_bytes_) {
        return resource_failure(header, candidate);
    }

    slot = std::vector<std::uint8_t>(payload.begin(), payload.end());
    frame.bytes += payload.size();
    total_bytes_ += payload.size();

    const bool complete = std::all_of(frame.fragments.begin(), frame.fragments.end(),
                                      [](const auto& part) { return part.has_value(); });
    if (!complete) {
        return {.code = IngestCode::Accepted, .stream_epoch = header.stream_epoch,
                .frame_sequence = header.frame_sequence};
    }

    std::vector<std::uint8_t> access_unit;
    access_unit.reserve(frame.bytes);
    for (const auto& fragment : frame.fragments) {
        access_unit.insert(access_unit.end(), fragment->begin(), fragment->end());
    }
    erase_frame(key);
    if (candidate) {
        candidate_ready_ = true;
    }
    return {.code = IngestCode::Complete,
            .stream_epoch = header.stream_epoch,
            .frame_sequence = header.frame_sequence,
            .access_unit = std::move(access_unit),
            .requires_epoch_commit = candidate};
}

bool AccessUnitReassembler::commit_candidate_epoch(std::uint64_t epoch) noexcept {
    if (!candidate_epoch_ || *candidate_epoch_ != epoch || !candidate_ready_ ||
        (current_epoch_ && epoch <= *current_epoch_)) {
        return false;
    }
    current_epoch_ = epoch;
    candidate_epoch_.reset();
    candidate_ready_ = false;
    erase_older_epochs(epoch);
    gap_detected_ = false;
    return true;
}

void AccessUnitReassembler::reject_candidate_epoch(std::uint64_t epoch) noexcept {
    if (!candidate_epoch_ || *candidate_epoch_ != epoch) {
        return;
    }
    erase_epoch(epoch);
}

}  // namespace vf
