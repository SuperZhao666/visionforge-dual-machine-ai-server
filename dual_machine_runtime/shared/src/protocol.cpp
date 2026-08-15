#include "vfdual/protocol.hpp"

#include <algorithm>

namespace vfdual {
namespace {
void store_u16(std::span<std::byte> output, std::size_t offset, std::uint16_t value) noexcept {
  output[offset] = std::byte(value >> 8);
  output[offset + 1U] = std::byte(value);
}

void store_u32(std::span<std::byte> output, std::size_t offset, std::uint32_t value) noexcept {
  for (int shift = 24; shift >= 0; shift -= 8) {
    output[offset++] = std::byte(value >> shift);
  }
}

std::uint16_t get_u16(std::span<const std::byte> input, std::size_t offset) {
  return (std::to_integer<std::uint16_t>(input[offset]) << 8) |
      std::to_integer<std::uint16_t>(input[offset + 1]);
}

std::uint32_t get_u32(std::span<const std::byte> input, std::size_t offset) {
  std::uint32_t value{};
  for (std::size_t index{}; index < 4; ++index) {
    value = (value << 8) | std::to_integer<std::uint8_t>(input[offset + index]);
  }
  return value;
}
}  // namespace

std::size_t encode_video_packet_into(
    std::uint32_t frame_id,
    std::uint16_t fragment_index,
    std::uint16_t fragment_count,
    std::span<const std::byte> access_unit_part,
    std::span<std::byte> destination) noexcept {
  if (fragment_count == 0U ||
      fragment_count > kMaxVideoFragmentsPerAccessUnit ||
      fragment_index >= fragment_count ||
      access_unit_part.empty() || access_unit_part.size() > kVideoPacketPayloadBytes ||
      destination.size() < kVideoPacketHeaderBytes + access_unit_part.size()) {
    return 0U;
  }
  store_u32(
      destination, 0U,
      video_repeats_content(frame_id)
          ? kVideoRepeatedPacketMagic
          : kVideoPacketMagic);
  store_u32(destination, 4U, frame_id);
  store_u16(destination, 8U, fragment_index);
  store_u16(destination, 10U, fragment_count);
  std::copy(access_unit_part.begin(), access_unit_part.end(),
            destination.begin() + static_cast<std::ptrdiff_t>(kVideoPacketHeaderBytes));
  return kVideoPacketHeaderBytes + access_unit_part.size();
}

std::vector<std::byte> encode_video_packet(const VideoFragment& fragment) {
  std::vector<std::byte> packet(kVideoPacketHeaderBytes + fragment.access_unit_part.size());
  const std::size_t encoded = encode_video_packet_into(
      fragment.frame_id, fragment.fragment_index, fragment.fragment_count,
      fragment.access_unit_part, packet);
  if (encoded == 0U) return {};
  packet.resize(encoded);
  return packet;
}

bool decode_video_packet(std::span<const std::byte> datagram, VideoFragment& destination) noexcept {
  if (datagram.size() <= kVideoPacketHeaderBytes ||
      datagram.size() > kMaxDatagramBytes) {
    return false;
  }
  const std::uint32_t magic = get_u32(datagram, 0);
  if (magic != kVideoPacketMagic && magic != kVideoRepeatedPacketMagic) {
    return false;
  }
  const auto count = get_u16(datagram, 10);
  const auto index = get_u16(datagram, 8);
  if (count == 0 || count > kMaxVideoFragmentsPerAccessUnit ||
      index >= count) return false;
  const std::uint32_t wire_frame_id = get_u32(datagram, 4);
  destination.frame_id =
      video_logical_frame_sequence(wire_frame_id) |
      (magic == kVideoRepeatedPacketMagic ? kVideoRepeatedContentFlag : 0U);
  destination.fragment_index = index;
  destination.fragment_count = count;
  destination.access_unit_part.assign(datagram.begin() + kVideoPacketHeaderBytes, datagram.end());
  return true;
}
}  // namespace vfdual
