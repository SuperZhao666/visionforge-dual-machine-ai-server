#pragma once

#include "vfdual/protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>

namespace vfdual {

/** Stable, cross-platform invariants shared by Host, Android native, and Java. */
struct VideoTransportContract final {
  static constexpr std::uint32_t normal_magic = kVideoPacketMagic;
  static constexpr std::uint32_t repeated_magic = kVideoRepeatedPacketMagic;
  static constexpr std::size_t header_bytes = kVideoPacketHeaderBytes;
  static constexpr std::size_t payload_bytes = kVideoPacketPayloadBytes;
  static constexpr std::size_t maximum_access_unit_bytes = kMaxAccessUnitBytes;
  static constexpr std::size_t maximum_fragments =
      kMaxVideoFragmentsPerAccessUnit;
};

[[nodiscard]] constexpr bool valid_video_fragment_metadata(
    VideoFrameIdentity identity,
    std::uint16_t fragment_index,
    std::uint16_t fragment_count,
    std::size_t payload_size) noexcept {
  return identity.valid() && fragment_count != 0U &&
      fragment_count <= kMaxVideoFragmentsPerAccessUnit &&
      fragment_index < fragment_count && payload_size != 0U &&
      payload_size <= kVideoPacketPayloadBytes;
}


enum class VideoEpochObservation : std::uint8_t {
  invalid,
  active,
  candidate,
  candidate_replaced,
  retired,
};

/**
 * Owns the receiver-side stream-session transition.
 *
 * A new epoch starts as a candidate.  It becomes active only after the caller
 * has reassembled and validated a complete IDR and the decoder restart gate
 * has accepted it.  Active and rejected candidates are remembered in a
 * bounded retired ring so late UDP traffic can never reclaim the session.
 */
class VideoEpochCoordinator final {
 public:
  explicit VideoEpochCoordinator(std::size_t retired_capacity = 8U) noexcept;

  [[nodiscard]] VideoEpochObservation observe(
      std::uint64_t stream_epoch) noexcept;
  [[nodiscard]] bool commit_candidate(std::uint64_t stream_epoch) noexcept;
  void reject_candidate(std::uint64_t stream_epoch) noexcept;
  void reset() noexcept;

  [[nodiscard]] std::optional<std::uint64_t> active_epoch() const noexcept;
  [[nodiscard]] std::optional<std::uint64_t> candidate_epoch() const noexcept;
  [[nodiscard]] bool is_retired(std::uint64_t stream_epoch) const noexcept;
  [[nodiscard]] std::size_t retired_count() const noexcept;

 private:
  void retire(std::uint64_t stream_epoch) noexcept;

  std::size_t retired_capacity_{};
  std::optional<std::uint64_t> active_epoch_;
  std::optional<std::uint64_t> candidate_epoch_;
  std::deque<std::uint64_t> retired_epochs_;
};

/**
 * Produces a valid positive 63-bit epoch from two independently changing Host
 * values. Zero is remapped because it is reserved for "no active stream".
 */
[[nodiscard]] constexpr std::uint64_t derive_video_stream_epoch(
    std::uint64_t process_nonce,
    std::uint64_t monotonic_boot_us) noexcept {
  std::uint64_t value = process_nonce ^
      (monotonic_boot_us + 0x9e37'79b9'7f4a'7c15ULL +
       (process_nonce << 6U) + (process_nonce >> 2U));
  value &= kVideoStreamEpochMax;
  return value == 0U ? 1U : value;
}

}  // namespace vfdual
