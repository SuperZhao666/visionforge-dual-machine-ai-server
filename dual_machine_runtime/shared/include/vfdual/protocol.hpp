#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace vfdual {

/**
 * v5.1-compatible wire contract:
 * [magic:u32][frame_id:u32][frag_idx:u16][frag_cnt:u16].
 *
 * Normal frames retain the v5.0 magic. Repeated-content frames use a distinct
 * magic and the high frame-id bit, so an older receiver safely rejects only
 * synthetic repeats instead of misclassifying them as control observations.
 * The high bit is not part of the logical sequence.
 */
constexpr std::uint32_t kVideoPacketMagic = 0x56465247U;  // "VFRG"
constexpr std::uint32_t kVideoRepeatedPacketMagic = 0x56465252U;  // "VFRR"
constexpr std::uint32_t kVideoRepeatedContentFlag = 0x8000'0000U;
constexpr std::uint32_t kVideoFrameSequenceMask = 0x7fff'ffffU;
constexpr std::uint32_t kVideoFrameSequenceHalfRange = 0x4000'0000U;
constexpr std::size_t kVideoPacketHeaderBytes = 12;
constexpr std::size_t kVideoPacketPayloadBytes = 1400;
constexpr std::size_t kMaxDatagramBytes = kVideoPacketHeaderBytes + kVideoPacketPayloadBytes;
constexpr std::size_t kMaxAccessUnitBytes = 2 * 1024 * 1024;
constexpr std::size_t kMaxVideoFragmentsPerAccessUnit =
    (kMaxAccessUnitBytes + kVideoPacketPayloadBytes - 1U) /
    kVideoPacketPayloadBytes;

struct VideoFragment {
    std::uint32_t frame_id{};
    std::uint16_t fragment_index{};
    std::uint16_t fragment_count{};
    std::vector<std::byte> access_unit_part;
};

[[nodiscard]] constexpr std::uint32_t make_video_wire_frame_id(
    std::uint32_t logical_sequence, bool repeated_content) noexcept {
  return (logical_sequence & kVideoFrameSequenceMask) |
      (repeated_content ? kVideoRepeatedContentFlag : 0U);
}

[[nodiscard]] constexpr std::uint32_t video_logical_frame_sequence(
    std::uint32_t wire_frame_id) noexcept {
  return wire_frame_id & kVideoFrameSequenceMask;
}

[[nodiscard]] constexpr bool video_repeats_content(
    std::uint32_t wire_frame_id) noexcept {
  return (wire_frame_id & kVideoRepeatedContentFlag) != 0U;
}

/**
 * Advances the unsigned logical sequence inside the 31-bit wire domain.
 *
 * Keeping the producer counter in that domain makes the host metric and the
 * receiver-visible sequence identical even after a very long-running stream.
 */
[[nodiscard]] constexpr std::uint32_t next_video_logical_frame_sequence(
    std::uint32_t logical_sequence) noexcept {
  return (logical_sequence + 1U) & kVideoFrameSequenceMask;
}

/** RFC-1982-style ordering for the 31-bit video sequence number. */
[[nodiscard]] constexpr bool video_logical_frame_sequence_is_newer(
    std::uint32_t candidate, std::uint32_t reference) noexcept {
  const std::uint32_t distance =
      (candidate - reference) & kVideoFrameSequenceMask;
  return distance != 0U && distance < kVideoFrameSequenceHalfRange;
}

/**
 * Serializes one v5.0 UDP datagram into caller-owned storage.
 *
 * This allocation-free overload is the production hot-path contract. It
 * returns the encoded byte count, or zero when any field/storage is invalid.
 */
[[nodiscard]] std::size_t encode_video_packet_into(
    std::uint32_t frame_id,
    std::uint16_t fragment_index,
    std::uint16_t fragment_count,
    std::span<const std::byte> access_unit_part,
    std::span<std::byte> destination) noexcept;

/** Serializes exactly one UDP datagram according to the fixed v5.0 header. */
[[nodiscard]] std::vector<std::byte> encode_video_packet(const VideoFragment& fragment);
[[nodiscard]] bool decode_video_packet(std::span<const std::byte> datagram, VideoFragment& destination) noexcept;

}  // namespace vfdual
