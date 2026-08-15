#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace vfdual {

[[nodiscard]] inline std::uint32_t h264_annex_b_nal_type_mask(
    std::span<const std::byte> access_unit) noexcept {
  std::uint32_t mask{};
  for (std::size_t index{}; index + 3U < access_unit.size(); ++index) {
    const bool four_byte_start = index + 4U < access_unit.size() &&
        access_unit[index] == std::byte{0} &&
        access_unit[index + 1U] == std::byte{0} &&
        access_unit[index + 2U] == std::byte{0} &&
        access_unit[index + 3U] == std::byte{1};
    const bool three_byte_start = !four_byte_start &&
        access_unit[index] == std::byte{0} &&
        access_unit[index + 1U] == std::byte{0} &&
        access_unit[index + 2U] == std::byte{1};
    if (!four_byte_start && !three_byte_start) continue;
    const std::size_t nal_index = index + (four_byte_start ? 4U : 3U);
    if (nal_index >= access_unit.size()) continue;
    const std::uint8_t nal_type =
        std::to_integer<std::uint8_t>(access_unit[nal_index]) & 0x1fU;
    mask |= 1U << nal_type;
  }
  return mask;
}

[[nodiscard]] inline bool h264_avcc_contains_idr(
    std::span<const std::byte> access_unit) noexcept {
  for (std::size_t offset{}; offset + 4U <= access_unit.size();) {
    const std::uint32_t length =
        (std::to_integer<std::uint8_t>(access_unit[offset]) << 24U) |
        (std::to_integer<std::uint8_t>(access_unit[offset + 1U]) << 16U) |
        (std::to_integer<std::uint8_t>(access_unit[offset + 2U]) << 8U) |
        std::to_integer<std::uint8_t>(access_unit[offset + 3U]);
    offset += 4U;
    if (length == 0U || length > access_unit.size() - offset) return false;
    if ((std::to_integer<std::uint8_t>(access_unit[offset]) & 0x1fU) == 5U) {
      return true;
    }
    offset += length;
  }
  return false;
}

[[nodiscard]] inline bool h264_access_unit_contains_idr(
    std::span<const std::byte> access_unit) noexcept {
  return (h264_annex_b_nal_type_mask(access_unit) & (1U << 5U)) != 0U ||
      h264_avcc_contains_idr(access_unit);
}

}  // namespace vfdual
