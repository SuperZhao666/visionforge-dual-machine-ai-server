#include "vf/wire_protocol.hpp"

#include <algorithm>
#include <stdexcept>

namespace vf {
namespace {

std::uint16_t read_u16(std::span<const std::uint8_t> bytes, std::size_t offset) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1]));
}

std::uint32_t read_u32(std::span<const std::uint8_t> bytes, std::size_t offset) noexcept {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        value = (value << 8U) | bytes[offset + i];
    }
    return value;
}

std::uint64_t read_u64(std::span<const std::uint8_t> bytes, std::size_t offset) noexcept {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value = (value << 8U) | bytes[offset + i];
    }
    return value;
}

void write_u16(std::span<std::uint8_t> bytes, std::size_t offset, std::uint16_t value) noexcept {
    bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 1] = static_cast<std::uint8_t>(value);
}

void write_u32(std::span<std::uint8_t> bytes, std::size_t offset, std::uint32_t value) noexcept {
    for (int i = 3; i >= 0; --i) {
        bytes[offset + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(value);
        value >>= 8U;
    }
}

void write_u64(std::span<std::uint8_t> bytes, std::size_t offset, std::uint64_t value) noexcept {
    for (int i = 7; i >= 0; --i) {
        bytes[offset + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(value);
        value >>= 8U;
    }
}

}  // namespace

bool WireHeader::valid() const noexcept {
    if (stream_epoch == 0 || stream_epoch > kMaxStreamEpoch || fragment_count == 0 ||
        fragment_count > kMaxFragments) {
        return false;
    }
    if (fragment_index >= fragment_count) {
        return false;
    }
    if (kind == PacketKind::Repeat && (fragment_index != 0 || fragment_count != 1)) {
        return false;
    }
    return true;
}

std::optional<WireHeader> parse_wire_header(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < kWireHeaderSize) {
        return std::nullopt;
    }
    PacketKind kind{};
    if (std::equal(kDataMagic.begin(), kDataMagic.end(), bytes.begin())) {
        kind = PacketKind::Data;
    } else if (std::equal(kRepeatMagic.begin(), kRepeatMagic.end(), bytes.begin())) {
        kind = PacketKind::Repeat;
    } else {
        return std::nullopt;
    }
    WireHeader header{
        .kind = kind,
        .stream_epoch = read_u64(bytes, 4),
        .frame_sequence = read_u32(bytes, 12),
        .fragment_index = read_u16(bytes, 16),
        .fragment_count = read_u16(bytes, 18),
    };
    return header.valid() ? std::optional<WireHeader>{header} : std::nullopt;
}

std::array<std::uint8_t, kWireHeaderSize> serialize_wire_header(const WireHeader& header) {
    if (!header.valid()) {
        throw std::invalid_argument("invalid wire header");
    }
    std::array<std::uint8_t, kWireHeaderSize> bytes{};
    const auto& magic = header.kind == PacketKind::Data ? kDataMagic : kRepeatMagic;
    std::copy(magic.begin(), magic.end(), bytes.begin());
    write_u64(bytes, 4, header.stream_epoch);
    write_u32(bytes, 12, header.frame_sequence);
    write_u16(bytes, 16, header.fragment_index);
    write_u16(bytes, 18, header.fragment_count);
    return bytes;
}

std::string_view packet_kind_name(PacketKind kind) noexcept {
    return kind == PacketKind::Data ? "data" : "repeat";
}

}  // namespace vf
