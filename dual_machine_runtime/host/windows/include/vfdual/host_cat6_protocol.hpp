#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vfdual {

struct Cat6ReadyMessage {
    std::string ipv4;
    std::uint32_t sequence{};
};

/** Parses VF_CAT6_READY_V1|10.57.23.2|42 without accepting trailing fields. */
[[nodiscard]] std::optional<Cat6ReadyMessage> parse_cat6_ready_message(
    std::string_view datagram);

/** Creates a fixed-size unicast probe for CAT6 reachability and RTT measurement. */
[[nodiscard]] std::vector<char> build_cat6_probe(std::uint32_t token, std::size_t bytes);

/** Returns the token from a zero-padded VF_CAT6_PROBE_ACK_V1 response. */
[[nodiscard]] std::optional<std::uint32_t> parse_cat6_probe_ack(std::span<const char> datagram);

}  // namespace vfdual
