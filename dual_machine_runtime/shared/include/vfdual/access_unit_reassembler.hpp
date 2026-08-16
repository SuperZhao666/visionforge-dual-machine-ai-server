#pragma once

#include "vfdual/protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

namespace vfdual {

struct CompletedAccessUnit final {
  VideoFrameIdentity identity{};
  bool repeated_content{};
  std::vector<std::byte> bytes;
};

/**
 * Single-epoch, decode-order-preserving UDP reassembler.
 *
 * Epoch admission is explicit: callers activate an epoch only after their
 * preflight/session policy has accepted it. This prevents one fragment from a
 * future or retired Host session from silently displacing a healthy stream.
 */
class AccessUnitReassembler final {
 public:
  explicit AccessUnitReassembler(
      std::size_t max_inflight_frames = 8U,
      std::size_t max_inflight_bytes = 8U * kMaxAccessUnitBytes,
      std::size_t retired_epoch_capacity = 8U) noexcept;

  /**
   * Activates an epoch and retires the previous one.
   *
   * When an IDR was admitted by an external preflight gate instead of through
   * this reassembler, `last_delivered_sequence` seeds the decode-order cursor
   * so the first prediction frame cannot overtake an earlier in-flight frame.
   * The optional seed is accepted only while establishing a fresh/empty epoch.
   */
  [[nodiscard]] bool activate_epoch(
      std::uint64_t stream_epoch,
      std::optional<std::uint32_t> last_delivered_sequence = std::nullopt) noexcept;

  [[nodiscard]] std::optional<std::uint64_t> active_epoch() const noexcept;
  [[nodiscard]] bool is_retired_epoch(std::uint64_t stream_epoch) const noexcept;
  [[nodiscard]] std::optional<std::uint64_t> retired_through() const noexcept;

  /** Takes fragment ownership so the receiver performs no second payload copy. */
  [[nodiscard]] std::optional<CompletedAccessUnit> push(
      VideoFragment fragment, std::uint64_t now_us);

  /**
   * Accepts a caller-owned datagram view.  New fragments are copied exactly
   * once into bounded reassembly storage; identical duplicates are compared in
   * place and allocate nothing.
   */
  [[nodiscard]] std::optional<CompletedAccessUnit> push_view(
      VideoFragmentView fragment, std::uint64_t now_us);

  /** Drains another complete AU only after every preceding sequence is drained. */
  [[nodiscard]] std::optional<CompletedAccessUnit> pop_completed();

  [[nodiscard]] std::size_t discard_expired(
      std::uint64_t now_us, std::uint64_t ttl_us = 50'000U) noexcept;

  [[nodiscard]] std::size_t inflight_frame_count() const noexcept;
  [[nodiscard]] std::size_t inflight_byte_count() const noexcept;
  [[nodiscard]] std::uint64_t incomplete_access_unit_losses() const noexcept;
  [[nodiscard]] std::uint64_t conflicting_duplicate_losses() const noexcept;
  [[nodiscard]] std::uint64_t foreign_or_retired_epoch_drops() const noexcept;
  [[nodiscard]] std::uint64_t payload_bytes_copied() const noexcept;
  [[nodiscard]] std::uint64_t payload_bytes_moved() const noexcept;
  [[nodiscard]] std::uint64_t duplicate_payload_bytes_avoided() const noexcept;

 private:
  struct PendingFrame final {
    bool repeated_content{};
    std::uint16_t expected_fragments{};
    std::uint16_t received_fragments{};
    std::size_t total_bytes{};
    std::uint64_t first_seen_us{};
    std::uint64_t arrival_order{};
    std::vector<bool> received;
    std::vector<std::vector<std::byte>> parts;
  };

  void clear_pending(bool count_as_loss) noexcept;
  void erase_pending(
      std::unordered_map<std::uint32_t, PendingFrame>::iterator iterator,
      bool count_as_loss) noexcept;
  void discard_oldest() noexcept;
  void remember_retired_epoch(std::uint64_t stream_epoch) noexcept;
  [[nodiscard]] std::optional<CompletedAccessUnit> push_payload(
      VideoFrameIdentity identity,
      bool repeated_content,
      std::uint16_t fragment_index,
      std::uint16_t fragment_count,
      std::span<const std::byte> payload,
      std::vector<std::byte>* owned_payload,
      bool allocation_free_duplicate_path,
      std::uint64_t now_us);

  std::size_t max_inflight_frames_{};
  std::size_t max_inflight_bytes_{};
  std::size_t inflight_bytes_{};
  std::uint64_t next_arrival_order_{};
  std::uint64_t incomplete_access_unit_losses_{};
  std::uint64_t conflicting_duplicate_losses_{};
  std::uint64_t foreign_or_retired_epoch_drops_{};
  std::uint64_t payload_bytes_copied_{};
  std::uint64_t payload_bytes_moved_{};
  std::uint64_t duplicate_payload_bytes_avoided_{};
  std::optional<std::uint64_t> active_epoch_;
  std::optional<std::uint64_t> retired_through_;
  std::optional<std::uint32_t> last_delivered_sequence_;
  std::unordered_map<std::uint32_t, PendingFrame> pending_;
};

}  // namespace vfdual
