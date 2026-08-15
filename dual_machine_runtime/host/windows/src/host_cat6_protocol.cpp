#include "vfdual/host_cat6_protocol.hpp"

#include <algorithm>
#include <charconv>

namespace vfdual {
namespace {
constexpr std::string_view kReadyPrefix{"VF_CAT6_READY_V1|"};
constexpr std::string_view kProbePrefix{"VF_CAT6_PROBE_V1|"};
constexpr std::string_view kProbeAckPrefix{"VF_CAT6_PROBE_ACK_V1|"};

bool valid_ipv4(std::string_view value) noexcept {
    std::size_t start = 0;
    for (int part = 0; part < 4; ++part) {
        const std::size_t end = part == 3 ? value.size() : value.find('.', start);
        if (end == std::string_view::npos || end == start) return false;
        unsigned number{};
        const auto parsed = std::from_chars(value.data() + start, value.data() + end, number);
        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + end || number > 255U) return false;
        start = end + 1U;
    }
    return start == value.size() + 1U;
}

std::optional<std::uint32_t> parse_token(std::string_view value) noexcept {
    if (value.empty()) return std::nullopt;
    std::uint32_t token{};
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), token);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) return std::nullopt;
    return token;
}
}  // namespace

std::optional<Cat6ReadyMessage> parse_cat6_ready_message(std::string_view datagram) {
    if (!datagram.starts_with(kReadyPrefix)) return std::nullopt;
    datagram.remove_prefix(kReadyPrefix.size());
    const std::size_t address_end = datagram.find('|');
    if (address_end == std::string_view::npos) return std::nullopt;
    const std::string_view address = datagram.substr(0, address_end);
    const std::string_view sequence_text = datagram.substr(address_end + 1U);
    const auto sequence = parse_token(sequence_text);
    if (!sequence || !valid_ipv4(address)) return std::nullopt;
    return Cat6ReadyMessage{std::string(address), *sequence};
}

std::vector<char> build_cat6_probe(std::uint32_t token, std::size_t bytes) {
    const std::string header = std::string(kProbePrefix) + std::to_string(token) + '|';
    if (bytes < header.size()) return {};
    std::vector<char> datagram(bytes, '\0');
    std::copy(header.begin(), header.end(), datagram.begin());
    return datagram;
}

std::optional<std::uint32_t> parse_cat6_probe_ack(std::span<const char> datagram) {
    if (datagram.empty()) return std::nullopt;
    const auto terminator = std::find(datagram.begin(), datagram.end(), '\0');
    std::string_view value(datagram.data(), static_cast<std::size_t>(terminator - datagram.begin()));
    if (!value.starts_with(kProbeAckPrefix)) return std::nullopt;
    value.remove_prefix(kProbeAckPrefix.size());
    if (!value.empty() && value.back() == '|') value.remove_suffix(1U);
    return parse_token(value);
}

}  // namespace vfdual
