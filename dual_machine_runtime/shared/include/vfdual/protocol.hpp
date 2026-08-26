#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

namespace vfdual {

/**
 * VisionForge video wire contract v6.0.
 *
 * Every datagram starts with one fixed 20-byte, network-byte-order header:
 *
 *   [magic:u32][stream_epoch:u64][frame_sequence:u32]
 *   [fragment_index:u16][fragment_count:u16]
 *
 * A frame is identified by the complete (stream_epoch, frame_sequence) tuple.
 * The epoch changes whenever a Host stream is rebuilt, so sequence zero in a
 * new session can never be confused with a late packet from an old session.
 */
constexpr std::uint32_t kVideoPacketMagic = 0x56463247U;          // "VF2G"
constexpr std::uint32_t kVideoRepeatedPacketMagic = 0x56463252U;  // "VF2R"
constexpr std::uint64_t kVideoStreamEpochMax = 0x7fff'ffff'ffff'ffffULL;
constexpr std::size_t kVideoPacketHeaderBytes = 20U;
// VFP2 is the inner video fragment.  1344 + the 20-byte VFP2 header fits in
// one 1364-byte VFA2 plaintext, whose authenticated outer datagram is 1412.
constexpr std::size_t kVideoPacketPayloadBytes = 1344U;
constexpr std::size_t kMaxDatagramBytes =
    kVideoPacketHeaderBytes + kVideoPacketPayloadBytes;
constexpr std::size_t kMaxAccessUnitBytes = 2U * 1024U * 1024U;
constexpr std::size_t kMaxVideoFragmentsPerAccessUnit =
    (kMaxAccessUnitBytes + kVideoPacketPayloadBytes - 1U) /
    kVideoPacketPayloadBytes;

[[nodiscard]] constexpr bool valid_video_stream_epoch(
    std::uint64_t value) noexcept {
  return value != 0U && value <= kVideoStreamEpochMax;
}

struct VideoFrameIdentity final {
  std::uint64_t stream_epoch{};
  std::uint32_t frame_sequence{};

  [[nodiscard]] constexpr bool valid() const noexcept {
    return valid_video_stream_epoch(stream_epoch);
  }

  friend constexpr bool operator==(
      const VideoFrameIdentity&, const VideoFrameIdentity&) noexcept = default;
};

struct VideoFrameIdentityHash final {
  [[nodiscard]] std::size_t operator()(
      const VideoFrameIdentity& value) const noexcept {
    const std::uint64_t mixed = value.stream_epoch ^
        (static_cast<std::uint64_t>(value.frame_sequence) << 32U) ^
        static_cast<std::uint64_t>(value.frame_sequence);
    return std::hash<std::uint64_t>{}(mixed);
  }
};

struct VideoFragment final {
  VideoFrameIdentity identity{};
  bool repeated_content{};
  std::uint16_t fragment_index{};
  std::uint16_t fragment_count{};
  std::vector<std::byte> access_unit_part;
};

/**
 * Allocation-free view over one received video datagram.
 *
 * The payload span remains valid only while the caller-owned datagram buffer
 * is alive.  The Android receiver decodes into this view and immediately gives
 * it to the bounded reassembler.  That lets an identical duplicate be checked
 * before allocating another payload vector, which matters on a high-rate UDP
 * path where duplicates and reordering are expected rather than exceptional.
 */
struct VideoFragmentView final {
  VideoFrameIdentity identity{};
  bool repeated_content{};
  std::uint16_t fragment_index{};
  std::uint16_t fragment_count{};
  std::span<const std::byte> access_unit_part{};
};

/**
 * Advances a frame sequence without wraparound.
 *
 * Returning false at UINT32_MAX forces the Host to rotate stream_epoch rather
 * than silently reusing an identity that a receiver may already have retired.
 */
[[nodiscard]] constexpr bool advance_video_frame_sequence(
    std::uint32_t current, std::uint32_t& next) noexcept {
  if (current == UINT32_MAX) return false;
  next = current + 1U;
  return true;
}

[[nodiscard]] constexpr bool video_frame_sequence_is_newer(
    std::uint32_t candidate, std::uint32_t reference) noexcept {
  return candidate > reference;
}

/**
 * Allocation-free production encoder. Returns the encoded byte count, or zero
 * when the identity, fragment metadata, payload, or destination is invalid.
 */
[[nodiscard]] std::size_t encode_video_packet_into(
    VideoFrameIdentity identity,
    bool repeated_content,
    std::uint16_t fragment_index,
    std::uint16_t fragment_count,
    std::span<const std::byte> access_unit_part,
    std::span<std::byte> destination) noexcept;

[[nodiscard]] std::vector<std::byte> encode_video_packet(
    const VideoFragment& fragment);

/** Parses header and payload as a caller-owned, allocation-free view. */
[[nodiscard]] bool decode_video_packet_view(
    std::span<const std::byte> datagram,
    VideoFragmentView& destination) noexcept;

/** Backward-compatible owning decoder; delegates validation to the view codec. */
[[nodiscard]] bool decode_video_packet(
    std::span<const std::byte> datagram,
    VideoFragment& destination) noexcept;

}  // namespace vfdual
