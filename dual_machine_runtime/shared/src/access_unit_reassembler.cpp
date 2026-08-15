#include "vfdual/access_unit_reassembler.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace vfdual {
AccessUnitReassembler::AccessUnitReassembler(std::size_t max_inflight_frames) noexcept
    : max_inflight_frames_(std::max<std::size_t>(1, max_inflight_frames)) {}

std::optional<CompletedAccessUnit> AccessUnitReassembler::push(
    VideoFragment fragment, std::uint64_t now_us) {
    if (fragment.fragment_count == 0 ||
        fragment.fragment_count > kMaxVideoFragmentsPerAccessUnit ||
        fragment.fragment_index >= fragment.fragment_count ||
        fragment.access_unit_part.empty() ||
        fragment.access_unit_part.size() > kVideoPacketPayloadBytes) {
        return std::nullopt;
    }
    const std::uint32_t logical_sequence =
        video_logical_frame_sequence(fragment.frame_id);
    if (last_delivered_sequence_.has_value() &&
        !video_logical_frame_sequence_is_newer(
            logical_sequence, *last_delivered_sequence_)) {
        // Late UDP duplicates must not create a second incomplete AU that
        // expires later and falsely breaks a healthy reference chain.
        return pop_completed();
    }
    auto [iterator, inserted] = pending_.try_emplace(fragment.frame_id);
    auto& pending = iterator->second;
    if (inserted) {
        pending.expected_fragments = fragment.fragment_count;
        pending.first_seen_us = now_us;
        pending.arrival_order = next_arrival_order_++;
        pending.received.assign(fragment.fragment_count, false);
        pending.parts.resize(fragment.fragment_count);
    }
    if (pending.expected_fragments != fragment.fragment_count) {
        pending_.erase(iterator);
        ++incomplete_access_unit_losses_;
        return std::nullopt;
    }
    if (!pending.received[fragment.fragment_index]) {
        const std::size_t part_size = fragment.access_unit_part.size();
        if (pending.total_bytes > kMaxAccessUnitBytes - part_size) {
            pending_.erase(iterator);
            ++incomplete_access_unit_losses_;
            return std::nullopt;
        }
        pending.received[fragment.fragment_index] = true;
        pending.parts[fragment.fragment_index] =
            std::move(fragment.access_unit_part);
        pending.total_bytes += part_size;
        ++pending.received_fragments;
    }
    while (pending_.size() > max_inflight_frames_) discard_oldest();
    return pop_completed();
}

std::optional<CompletedAccessUnit> AccessUnitReassembler::pop_completed() {
    if (pending_.empty()) return std::nullopt;
    auto oldest = pending_.end();
    if (last_delivered_sequence_.has_value()) {
        const std::uint32_t expected = next_video_logical_frame_sequence(
            *last_delivered_sequence_);
        oldest = std::find_if(
            pending_.begin(), pending_.end(), [expected](const auto& candidate) {
                return video_logical_frame_sequence(candidate.first) == expected;
            });
        if (oldest == pending_.end()) return std::nullopt;
    } else {
        oldest = std::min_element(
            pending_.begin(), pending_.end(), [](const auto& left, const auto& right) {
                return left.second.arrival_order < right.second.arrival_order;
            });
    }
    if (oldest->second.received_fragments != oldest->second.expected_fragments) {
        return std::nullopt;
    }
    CompletedAccessUnit completed{oldest->first, {}};
    completed.bytes.reserve(oldest->second.total_bytes);
    for (const auto& part : oldest->second.parts) {
        completed.bytes.insert(completed.bytes.end(), part.begin(), part.end());
    }
    last_delivered_sequence_ = video_logical_frame_sequence(oldest->first);
    pending_.erase(oldest);
    return completed;
}

std::size_t AccessUnitReassembler::discard_expired(
    std::uint64_t now_us, std::uint64_t ttl_us) noexcept {
    std::size_t discarded{};
    for (auto iterator = pending_.begin(); iterator != pending_.end();) {
        const bool expired = now_us >= iterator->second.first_seen_us && now_us - iterator->second.first_seen_us > ttl_us;
        if (!expired) {
            ++iterator;
            continue;
        }
        iterator = pending_.erase(iterator);
        ++discarded;
    }
    incomplete_access_unit_losses_ += discarded;
    return discarded;
}

std::size_t AccessUnitReassembler::inflight_frame_count() const noexcept { return pending_.size(); }

std::uint64_t AccessUnitReassembler::incomplete_access_unit_losses() const noexcept {
    return incomplete_access_unit_losses_;
}

void AccessUnitReassembler::discard_oldest() noexcept {
    if (pending_.empty()) return;
    const auto oldest = std::min_element(pending_.begin(), pending_.end(), [](const auto& left, const auto& right) {
        return left.second.arrival_order < right.second.arrival_order;
    });
    pending_.erase(oldest);
    ++incomplete_access_unit_losses_;
}
}  // namespace vfdual
