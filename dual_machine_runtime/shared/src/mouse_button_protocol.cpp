#include "vfdual/mouse_button_protocol.hpp"

namespace vfdual {
namespace {

void store_u32(
    std::span<std::byte> output,
    std::size_t offset,
    std::uint32_t value) noexcept {
  for (int shift = 24; shift >= 0; shift -= 8) {
    output[offset++] = std::byte(value >> shift);
  }
}

std::uint32_t load_u32(
    std::span<const std::byte> input,
    std::size_t offset) noexcept {
  std::uint32_t value{};
  for (std::size_t index{}; index < 4U; ++index) {
    value = (value << 8U) |
        std::to_integer<std::uint8_t>(input[offset + index]);
  }
  return value;
}

}  // namespace

std::size_t encode_mouse_button_state_packet(
    const MouseButtonStatePacket& packet,
    std::span<std::byte> destination) noexcept {
  if (destination.size() < kMouseButtonPacketBytes || packet.session_id == 0U ||
      (packet.button_mask & ~kMouseButtonValidMask) != 0U) {
    return 0U;
  }
  store_u32(destination, 0U, kMouseButtonPacketMagic);
  destination[4U] = std::byte{kMouseButtonPacketVersion};
  destination[5U] = std::byte{packet.button_mask};
  destination[6U] = std::byte{};
  destination[7U] = std::byte{};
  store_u32(destination, 8U, packet.session_id);
  store_u32(destination, 12U, packet.sequence);
  return kMouseButtonPacketBytes;
}

bool decode_mouse_button_state_packet(
    std::span<const std::byte> datagram,
    MouseButtonStatePacket& destination) noexcept {
  if (datagram.size() != kMouseButtonPacketBytes ||
      load_u32(datagram, 0U) != kMouseButtonPacketMagic ||
      std::to_integer<std::uint8_t>(datagram[4U]) !=
          kMouseButtonPacketVersion ||
      datagram[6U] != std::byte{} || datagram[7U] != std::byte{}) {
    return false;
  }
  const std::uint8_t button_mask =
      std::to_integer<std::uint8_t>(datagram[5U]);
  const std::uint32_t session_id = load_u32(datagram, 8U);
  if (session_id == 0U || (button_mask & ~kMouseButtonValidMask) != 0U) {
    return false;
  }
  destination = MouseButtonStatePacket{
      button_mask,
      session_id,
      load_u32(datagram, 12U),
  };
  return true;
}

}  // namespace vfdual
