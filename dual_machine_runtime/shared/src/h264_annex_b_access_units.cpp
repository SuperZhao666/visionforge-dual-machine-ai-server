#include "vfdual/h264_annex_b_access_units.hpp"

#include <cstdint>

namespace vfdual {
namespace {

struct NalRange {
    std::size_t start{};
    std::size_t payload_start{};
    std::size_t end{};
};

[[nodiscard]] bool is_start_code(std::span<const std::byte> bytes, std::size_t offset, std::size_t* size) {
    if (offset + 3U <= bytes.size() && bytes[offset] == std::byte{0} &&
        bytes[offset + 1U] == std::byte{0} && bytes[offset + 2U] == std::byte{1}) {
        *size = 3U;
        return true;
    }
    if (offset + 4U <= bytes.size() && bytes[offset] == std::byte{0} &&
        bytes[offset + 1U] == std::byte{0} && bytes[offset + 2U] == std::byte{0} &&
        bytes[offset + 3U] == std::byte{1}) {
        *size = 4U;
        return true;
    }
    return false;
}

[[nodiscard]] std::vector<NalRange> find_nals(std::span<const std::byte> bytes) {
    std::vector<NalRange> nals;
    for (std::size_t offset{}; offset + 3U <= bytes.size();) {
        std::size_t start_code_size{};
        if (!is_start_code(bytes, offset, &start_code_size)) {
            ++offset;
            continue;
        }
        const std::size_t start = offset;
        const std::size_t payload_start = offset + start_code_size;
        offset = payload_start;
        while (offset + 3U <= bytes.size()) {
            if (is_start_code(bytes, offset, &start_code_size)) break;
            ++offset;
        }
        // The final NAL can be shorter than the three-byte look-ahead used to
        // find the next start code.  It still belongs to the stream; without
        // this EOF normalization a valid final picture would be discarded.
        if (offset + 3U > bytes.size()) offset = bytes.size();
        nals.push_back({start, payload_start, offset});
    }
    return nals;
}

[[nodiscard]] std::vector<std::uint8_t> rbsp_after_nal_header(std::span<const std::byte> nal_payload) {
    std::vector<std::uint8_t> bytes;
    if (nal_payload.size() <= 1U) return bytes;
    bytes.reserve(nal_payload.size() - 1U);
    std::uint32_t zero_count{};
    for (std::size_t index = 1U; index < nal_payload.size(); ++index) {
        const auto value = std::to_integer<std::uint8_t>(nal_payload[index]);
        if (zero_count >= 2U && value == 3U) {
            zero_count = 0;
            continue;
        }
        bytes.push_back(value);
        zero_count = value == 0U ? zero_count + 1U : 0U;
    }
    return bytes;
}

[[nodiscard]] bool first_mb_is_zero(std::span<const std::byte> nal_payload) {
    const auto rbsp = rbsp_after_nal_header(nal_payload);
    if (rbsp.empty()) return false;
    std::size_t bit_offset{};
    const auto read_bit = [&rbsp, &bit_offset](bool* value) {
        if (bit_offset >= rbsp.size() * 8U) return false;
        *value = ((rbsp[bit_offset / 8U] >> (7U - (bit_offset % 8U))) & 1U) != 0U;
        ++bit_offset;
        return true;
    };
    std::size_t leading_zeroes{};
    bool bit{};
    while (true) {
        if (!read_bit(&bit)) return false;
        if (bit) break;
        ++leading_zeroes;
        if (leading_zeroes > 31U) return false;
    }
    std::uint32_t suffix{};
    for (std::size_t index{}; index < leading_zeroes; ++index) {
        if (!read_bit(&bit)) return false;
        suffix = (suffix << 1U) | (bit ? 1U : 0U);
    }
    const std::uint64_t first_mb = ((std::uint64_t{1} << leading_zeroes) - 1U) + suffix;
    return first_mb == 0U;
}

void append_range(std::vector<std::byte>& destination, std::span<const std::byte> bytes, const NalRange& range) {
    destination.insert(destination.end(), bytes.begin() + static_cast<std::ptrdiff_t>(range.start),
                       bytes.begin() + static_cast<std::ptrdiff_t>(range.end));
}

}  // namespace

std::vector<std::vector<std::byte>> split_h264_annex_b_access_units(std::span<const std::byte> elementary_stream) {
    std::vector<std::vector<std::byte>> access_units;
    std::vector<std::byte> pending_prefix;
    std::vector<std::byte> current;
    bool current_has_vcl{};

    for (const auto& range : find_nals(elementary_stream)) {
        if (range.payload_start >= range.end) continue;
        const auto nal_payload = elementary_stream.subspan(range.payload_start, range.end - range.payload_start);
        const auto nal_type = std::to_integer<std::uint8_t>(nal_payload.front()) & 0x1fU;
        const bool is_vcl = nal_type >= 1U && nal_type <= 5U;
        const bool starts_picture = is_vcl && first_mb_is_zero(nal_payload);
        if (is_vcl && current_has_vcl && starts_picture) {
            access_units.push_back(std::move(current));
            current.clear();
            current_has_vcl = false;
        }
        if (is_vcl) {
            if (!current_has_vcl && !pending_prefix.empty()) {
                current.insert(current.end(), pending_prefix.begin(), pending_prefix.end());
                pending_prefix.clear();
            }
            append_range(current, elementary_stream, range);
            current_has_vcl = true;
        } else if (current_has_vcl) {
            append_range(pending_prefix, elementary_stream, range);
        } else {
            append_range(pending_prefix, elementary_stream, range);
        }
    }
    if (current_has_vcl) access_units.push_back(std::move(current));
    return access_units;
}

}  // namespace vfdual
