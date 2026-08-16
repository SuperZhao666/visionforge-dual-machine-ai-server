#include "vfdual/protocol.hpp"

#include <algorithm>

namespace vfdual {
namespace {
void store_u16(
    std::span<std::byte> output, std::size_t offset,
    std::uint16_t value) noexcept {
  output[offset] = std::byte(value >> 8U);
  output[offset + 1U] = std::byte(value);
}

void store_u32(
    std::span<std::byte> output, std::size_t offset,
    std::uint32_t value) noexcept {
  for (int shift = 24; shift >= 0; shift -= 8) {
    output[offset++] = std::byte(value >> shift);
  }
}

void store_u64(
    std::span<std::byte> output, std::size_t offset,
    std::uint64_t value) noexcept {
  for (int shift = 56; shift >= 0; shift -= 8) {
    output[offset++] = std::byte(value >> shift);
  }
}

[[nodiscard]] std::uint16_t get_u16(
    std::span<const std::byte> input, std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      (std::to_integer<std::uint16_t>(input[offset]) << 8U) |
      std::to_integer<std::uint16_t>(input[offset + 1U]));
}

[[nodiscard]] std::uint32_t get_u32(
    std::span<const std::byte> input, std::size_t offset) noexcept {
  std::uint32_t value{};
  for (std::size_t index{}; index < 4U; ++index) {
    value = (value << 8U) |
        std::to_integer<std::uint8_t>(input[offset + index]);
  }
  return value;
}

[[nodiscard]] std::uint64_t get_u64(
    std::span<const std::byte> input, std::size_t offset) noexcept {
  std::uint64_t value{};
  for (std::size_t index{}; index < 8U; ++index) {
    value = (value << 8U) |
        std::to_integer<std::uint8_t>(input[offset + index]);
  }
  return value;
}
}  // namespace

std::size_t encode_video_packet_into(
    VideoFrameIdentity identity,
    bool repeated_content,
    std::uint16_t fragment_index,
    std::uint16_t fragment_count,
    std::span<const std::byte> access_unit_part,
    std::span<std::byte> destination) noexcept {
  if (!identity.valid() || fragment_count == 0U ||
      fragment_count > kMaxVideoFragmentsPerAccessUnit ||
      fragment_index >= fragment_count || access_unit_part.empty() ||
      access_unit_part.size() > kVideoPacketPayloadBytes ||
      destination.size() < kVideoPacketHeaderBytes + access_unit_part.size()) {
    return 0U;
  }

  store_u32(destination, 0U,
      repeated_content ? kVideoRepeatedPacketMagic : kVideoPacketMagic);
  store_u64(destination, 4U, identity.stream_epoch);
  store_u32(destination, 12U, identity.frame_sequence);
  store_u16(destination, 16U, fragment_index);
  store_u16(destination, 18U, fragment_count);
  std::copy(
      access_unit_part.begin(), access_unit_part.end(),
      destination.begin() +
          static_cast<std::ptrdiff_t>(kVideoPacketHeaderBytes));
  return kVideoPacketHeaderBytes + access_unit_part.size();
}

std::vector<std::byte> encode_video_packet(const VideoFragment& fragment) {
  std::vector<std::byte> packet(
      kVideoPacketHeaderBytes + fragment.access_unit_part.size());
  const std::size_t encoded = encode_video_packet_into(
      fragment.identity, fragment.repeated_content,
      fragment.fragment_index, fragment.fragment_count,
      fragment.access_unit_part, packet);
  if (encoded == 0U) return {};
  packet.resize(encoded);
  return packet;
}

bool decode_video_packet_view(
    std::span<const std::byte> datagram,
    VideoFragmentView& destination) noexcept {
  if (datagram.size() <= kVideoPacketHeaderBytes ||
      datagram.size() > kMaxDatagramBytes) {
    return false;
  }

  const std::uint32_t magic = get_u32(datagram, 0U);
  if (magic != kVideoPacketMagic &&
      magic != kVideoRepeatedPacketMagic) {
    return false;
  }

  const VideoFrameIdentity identity{
      get_u64(datagram, 4U), get_u32(datagram, 12U)};
  const std::uint16_t index = get_u16(datagram, 16U);
  const std::uint16_t count = get_u16(datagram, 18U);
  if (!identity.valid() || count == 0U ||
      count > kMaxVideoFragmentsPerAccessUnit || index >= count) {
    return false;
  }

  destination.identity = identity;
  destination.repeated_content = magic == kVideoRepeatedPacketMagic;
  destination.fragment_index = index;
  destination.fragment_count = count;
  destination.access_unit_part = datagram.subspan(kVideoPacketHeaderBytes);
  return true;
}

bool decode_video_packet(
    std::span<const std::byte> datagram,
    VideoFragment& destination) noexcept {
  VideoFragmentView view{};
  if (!decode_video_packet_view(datagram, view)) {
    return false;
  }
  destination.identity = view.identity;
  destination.repeated_content = view.repeated_content;
  destination.fragment_index = view.fragment_index;
  destination.fragment_count = view.fragment_count;
  destination.access_unit_part.assign(
      view.access_unit_part.begin(), view.access_unit_part.end());
  return true;
}
}  // namespace vfdual
