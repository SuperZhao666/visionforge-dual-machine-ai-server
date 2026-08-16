#include "vfdual/access_unit_reassembler.hpp"

#include <algorithm>
#include <utility>

namespace vfdual {
AccessUnitReassembler::AccessUnitReassembler(
    std::size_t max_inflight_frames,
    std::size_t max_inflight_bytes,
    std::size_t retired_epoch_capacity) noexcept
    : max_inflight_frames_(std::max<std::size_t>(1U, max_inflight_frames)),
      max_inflight_bytes_(std::max<std::size_t>(
          kVideoPacketPayloadBytes, max_inflight_bytes)) {
  // Kept only for source/configuration compatibility. The retired session set
  // is represented by one monotonic high-water mark, not a bounded ring.
  static_cast<void>(retired_epoch_capacity);
}

bool AccessUnitReassembler::activate_epoch(
    std::uint64_t stream_epoch,
    std::optional<std::uint32_t> last_delivered_sequence) noexcept {
  if (!valid_video_stream_epoch(stream_epoch) ||
      is_retired_epoch(stream_epoch) ||
      (active_epoch_.has_value() && stream_epoch < *active_epoch_)) {
    return false;
  }
  if (active_epoch_ == stream_epoch) {
    if (last_delivered_sequence.has_value() &&
        !last_delivered_sequence_.has_value() && pending_.empty()) {
      last_delivered_sequence_ = last_delivered_sequence;
    }
    return true;
  }
  if (active_epoch_.has_value()) {
    remember_retired_epoch(*active_epoch_);
  } else if (stream_epoch > 1U) {
    remember_retired_epoch(stream_epoch - 1U);
  }
  clear_pending(true);
  active_epoch_ = stream_epoch;
  last_delivered_sequence_ = last_delivered_sequence;
  return true;
}

std::optional<std::uint64_t> AccessUnitReassembler::active_epoch() const noexcept {
  return active_epoch_;
}

bool AccessUnitReassembler::is_retired_epoch(
    std::uint64_t stream_epoch) const noexcept {
  return retired_through_.has_value() && stream_epoch <= *retired_through_;
}

std::optional<std::uint64_t> AccessUnitReassembler::retired_through() const noexcept {
  return retired_through_;
}

std::optional<CompletedAccessUnit> AccessUnitReassembler::push(
    VideoFragment fragment, std::uint64_t now_us) {
  const std::span<const std::byte> payload(fragment.access_unit_part);
  return push_payload(
      fragment.identity, fragment.repeated_content,
      fragment.fragment_index, fragment.fragment_count,
      payload, &fragment.access_unit_part,
      /*allocation_free_duplicate_path=*/false, now_us);
}

std::optional<CompletedAccessUnit> AccessUnitReassembler::push_view(
    VideoFragmentView fragment, std::uint64_t now_us) {
  return push_payload(
      fragment.identity, fragment.repeated_content,
      fragment.fragment_index, fragment.fragment_count,
      fragment.access_unit_part, nullptr,
      /*allocation_free_duplicate_path=*/true, now_us);
}

std::optional<CompletedAccessUnit> AccessUnitReassembler::push_payload(
    VideoFrameIdentity identity,
    bool repeated_content,
    std::uint16_t fragment_index,
    std::uint16_t fragment_count,
    std::span<const std::byte> payload,
    std::vector<std::byte>* owned_payload,
    bool allocation_free_duplicate_path,
    std::uint64_t now_us) {
  if (!identity.valid() || fragment_count == 0U ||
      fragment_count > kMaxVideoFragmentsPerAccessUnit ||
      fragment_index >= fragment_count || payload.empty() ||
      payload.size() > kVideoPacketPayloadBytes) {
    return std::nullopt;
  }

  if (!active_epoch_.has_value()) {
    if (!activate_epoch(identity.stream_epoch)) return std::nullopt;
  }
  if (identity.stream_epoch != *active_epoch_) {
    ++foreign_or_retired_epoch_drops_;
    return pop_completed();
  }

  const std::uint32_t sequence = identity.frame_sequence;
  if (last_delivered_sequence_.has_value() &&
      !video_frame_sequence_is_newer(sequence, *last_delivered_sequence_)) {
    // A late duplicate must not create a new incomplete candidate whose later
    // expiry would incorrectly invalidate the healthy H.264 reference chain.
    if (allocation_free_duplicate_path) {
      duplicate_payload_bytes_avoided_ += payload.size();
    }
    return pop_completed();
  }

  auto [iterator, inserted] = pending_.try_emplace(sequence);
  PendingFrame& pending = iterator->second;
  if (inserted) {
    pending.repeated_content = repeated_content;
    pending.expected_fragments = fragment_count;
    pending.first_seen_us = now_us;
    pending.arrival_order = next_arrival_order_++;
    pending.received.assign(fragment_count, false);
    pending.parts.resize(fragment_count);
  }

  if (pending.expected_fragments != fragment_count ||
      pending.repeated_content != repeated_content) {
    erase_pending(iterator, true);
    ++conflicting_duplicate_losses_;
    return std::nullopt;
  }

  const std::size_t index = fragment_index;
  if (pending.received[index]) {
    const auto& stored = pending.parts[index];
    const bool identical = stored.size() == payload.size() &&
        std::equal(stored.begin(), stored.end(), payload.begin());
    if (!identical) {
      erase_pending(iterator, true);
      ++conflicting_duplicate_losses_;
      return std::nullopt;
    }
    if (allocation_free_duplicate_path) {
      duplicate_payload_bytes_avoided_ += payload.size();
    }
    return pop_completed();
  }

  const std::size_t part_size = payload.size();
  if (part_size > kMaxAccessUnitBytes ||
      pending.total_bytes > kMaxAccessUnitBytes - part_size ||
      part_size > max_inflight_bytes_ ||
      inflight_bytes_ > max_inflight_bytes_ - part_size) {
    erase_pending(iterator, true);
    return std::nullopt;
  }

  pending.received[index] = true;
  if (owned_payload != nullptr) {
    pending.parts[index] = std::move(*owned_payload);
    payload_bytes_moved_ += part_size;
  } else {
    pending.parts[index].assign(payload.begin(), payload.end());
    payload_bytes_copied_ += part_size;
  }
  pending.total_bytes += part_size;
  inflight_bytes_ += part_size;
  ++pending.received_fragments;

  while (pending_.size() > max_inflight_frames_ ||
         inflight_bytes_ > max_inflight_bytes_) {
    discard_oldest();
  }
  return pop_completed();
}

std::optional<CompletedAccessUnit> AccessUnitReassembler::pop_completed() {
  if (!active_epoch_.has_value() || pending_.empty()) return std::nullopt;

  auto selected = pending_.end();
  if (last_delivered_sequence_.has_value()) {
    std::uint32_t expected{};
    if (!advance_video_frame_sequence(*last_delivered_sequence_, expected)) {
      return std::nullopt;
    }
    selected = pending_.find(expected);
    if (selected == pending_.end()) return std::nullopt;
  } else {
    selected = std::min_element(
        pending_.begin(), pending_.end(),
        [](const auto& left, const auto& right) {
          return left.second.arrival_order < right.second.arrival_order;
        });
  }

  if (selected->second.received_fragments !=
      selected->second.expected_fragments) {
    return std::nullopt;
  }

  CompletedAccessUnit completed{
      VideoFrameIdentity{*active_epoch_, selected->first},
      selected->second.repeated_content,
      {}};
  completed.bytes.reserve(selected->second.total_bytes);
  for (const auto& part : selected->second.parts) {
    completed.bytes.insert(completed.bytes.end(), part.begin(), part.end());
  }
  last_delivered_sequence_ = selected->first;
  erase_pending(selected, false);
  return completed;
}

std::size_t AccessUnitReassembler::discard_expired(
    std::uint64_t now_us, std::uint64_t ttl_us) noexcept {
  std::size_t discarded{};
  for (auto iterator = pending_.begin(); iterator != pending_.end();) {
    const bool expired = now_us >= iterator->second.first_seen_us &&
        now_us - iterator->second.first_seen_us > ttl_us;
    if (!expired) {
      ++iterator;
      continue;
    }
    auto victim = iterator++;
    erase_pending(victim, true);
    ++discarded;
  }
  return discarded;
}

std::size_t AccessUnitReassembler::inflight_frame_count() const noexcept {
  return pending_.size();
}

std::size_t AccessUnitReassembler::inflight_byte_count() const noexcept {
  return inflight_bytes_;
}

std::uint64_t AccessUnitReassembler::incomplete_access_unit_losses() const noexcept {
  return incomplete_access_unit_losses_;
}

std::uint64_t AccessUnitReassembler::conflicting_duplicate_losses() const noexcept {
  return conflicting_duplicate_losses_;
}

std::uint64_t AccessUnitReassembler::foreign_or_retired_epoch_drops() const noexcept {
  return foreign_or_retired_epoch_drops_;
}

std::uint64_t AccessUnitReassembler::payload_bytes_copied() const noexcept {
  return payload_bytes_copied_;
}

std::uint64_t AccessUnitReassembler::payload_bytes_moved() const noexcept {
  return payload_bytes_moved_;
}

std::uint64_t AccessUnitReassembler::duplicate_payload_bytes_avoided() const noexcept {
  return duplicate_payload_bytes_avoided_;
}

void AccessUnitReassembler::clear_pending(bool count_as_loss) noexcept {
  if (count_as_loss) incomplete_access_unit_losses_ += pending_.size();
  pending_.clear();
  inflight_bytes_ = 0U;
}

void AccessUnitReassembler::erase_pending(
    std::unordered_map<std::uint32_t, PendingFrame>::iterator iterator,
    bool count_as_loss) noexcept {
  if (iterator == pending_.end()) return;
  inflight_bytes_ -= std::min(inflight_bytes_, iterator->second.total_bytes);
  pending_.erase(iterator);
  if (count_as_loss) ++incomplete_access_unit_losses_;
}

void AccessUnitReassembler::discard_oldest() noexcept {
  if (pending_.empty()) return;
  const auto oldest = std::min_element(
      pending_.begin(), pending_.end(),
      [](const auto& left, const auto& right) {
        return left.second.arrival_order < right.second.arrival_order;
      });
  erase_pending(oldest, true);
}

void AccessUnitReassembler::remember_retired_epoch(
    std::uint64_t stream_epoch) noexcept {
  if (!valid_video_stream_epoch(stream_epoch)) return;
  if (!retired_through_.has_value() || stream_epoch > *retired_through_) {
    retired_through_ = stream_epoch;
  }
}
}  // namespace vfdual
