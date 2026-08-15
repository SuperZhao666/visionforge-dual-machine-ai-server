#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace vfdual {

/** Fixed host-to-phone physical mouse button snapshot carried over CAT6. */
inline constexpr std::uint32_t kMouseButtonPacketMagic = 0x56464d42U;  // "VFMB"
inline constexpr std::uint8_t kMouseButtonPacketVersion = 1U;
inline constexpr std::uint8_t kMouseButtonValidMask = 0x1fU;
inline constexpr std::size_t kMouseButtonPacketBytes = 16U;

struct MouseButtonStatePacket {
  std::uint8_t button_mask{};
  std::uint32_t session_id{};
  std::uint32_t sequence{};
};

/** Encodes one allocation-free, network-byte-order mouse button snapshot. */
[[nodiscard]] std::size_t encode_mouse_button_state_packet(
    const MouseButtonStatePacket& packet,
    std::span<std::byte> destination) noexcept;

/** Strictly decodes one complete snapshot; malformed datagrams are rejected. */
[[nodiscard]] bool decode_mouse_button_state_packet(
    std::span<const std::byte> datagram,
    MouseButtonStatePacket& destination) noexcept;

}  // namespace vfdual
