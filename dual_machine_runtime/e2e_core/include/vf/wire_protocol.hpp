#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string_view>

namespace vf {

inline constexpr std::size_t kWireHeaderSize = 20;
inline constexpr std::array<std::uint8_t, 4> kDataMagic{'V', 'F', '2', 'G'};
inline constexpr std::array<std::uint8_t, 4> kRepeatMagic{'V', 'F', '2', 'R'};
inline constexpr std::size_t kVideoPayloadBytes = 1344;
inline constexpr std::size_t kMaxAccessUnitBytes = 2U * 1024U * 1024U;
inline constexpr std::uint16_t kMaxFragments = static_cast<std::uint16_t>(
    (kMaxAccessUnitBytes + kVideoPayloadBytes - 1U) / kVideoPayloadBytes);
// Java 端使用正 long 表示 epoch；跨语言契约因此限制在有符号 63 位正整数。
inline constexpr std::uint64_t kMaxStreamEpoch =
    static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());

enum class PacketKind { Data, Repeat };

struct WireHeader {
    PacketKind kind{};
    std::uint64_t stream_epoch{};
    std::uint32_t frame_sequence{};
    std::uint16_t fragment_index{};
    std::uint16_t fragment_count{};

    [[nodiscard]] bool valid() const noexcept;
    friend bool operator==(const WireHeader&, const WireHeader&) = default;
};

[[nodiscard]] std::optional<WireHeader> parse_wire_header(std::span<const std::uint8_t> bytes) noexcept;
[[nodiscard]] std::array<std::uint8_t, kWireHeaderSize> serialize_wire_header(const WireHeader& header);
[[nodiscard]] std::string_view packet_kind_name(PacketKind kind) noexcept;

}  // namespace vf
