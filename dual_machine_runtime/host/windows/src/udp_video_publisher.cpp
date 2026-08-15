#include "vfdual/udp_video_publisher.hpp"

#include "vfdual/protocol.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace vfdual {
bool UdpVideoPublisher::connect_to(
    std::string_view host, std::uint16_t port, std::uint16_t local_port,
    std::string_view local_host,
    const VideoDataPlanePermitSource& permit_source) noexcept {
    reset();
    if (!permit_source) return false;
    try {
        permit_source_ = permit_source;
    } catch (...) {
        permit_source_ = {};
        return false;
    }
    if ((!local_host.empty() || local_port != 0U) &&
        !socket_.bind_to(local_host, local_port)) {
        reset();
        return false;
    }
    if (!socket_.connect_to(host, port)) {
        reset();
        return false;
    }
    return true;
}

void UdpVideoPublisher::reset() noexcept {
    socket_.close();
    permit_source_ = {};
}

VideoPublishResult UdpVideoPublisher::publish(
    std::uint32_t frame_id, std::span<const std::byte> access_unit,
    std::uint64_t monotonic_us, bool repeated_content) noexcept {
    static_cast<void>(monotonic_us);
    VideoPublishResult result{};
    if (access_unit.empty() || access_unit.size() > kMaxAccessUnitBytes) {
        result.stage = VideoPublishResult::Stage::validate_input;
        return result;
    }
    const std::size_t fragment_count_size =
        (access_unit.size() + kVideoPacketPayloadBytes - 1U) /
        kVideoPacketPayloadBytes;
    if (fragment_count_size == 0U ||
        fragment_count_size > (std::numeric_limits<std::uint16_t>::max)()) {
        result.stage = VideoPublishResult::Stage::validate_input;
        return result;
    }
    if (!authorization_permits_send()) {
        result.stage = VideoPublishResult::Stage::authorization_check;
        return result;
    }
    const auto fragment_count = static_cast<std::uint16_t>(fragment_count_size);
    const std::uint32_t wire_frame_id =
        make_video_wire_frame_id(frame_id, repeated_content);
    std::array<std::byte, kMaxDatagramBytes> datagram{};
    for (std::size_t offset = 0U, index = 0U; offset < access_unit.size();
         offset += kVideoPacketPayloadBytes, ++index) {
        const std::size_t payload_size = (std::min)(
            kVideoPacketPayloadBytes, access_unit.size() - offset);
        const std::span<const std::byte> payload = access_unit.subspan(offset, payload_size);
        const std::size_t datagram_size = encode_video_packet_into(
            wire_frame_id, static_cast<std::uint16_t>(index), fragment_count,
            payload, datagram);
        if (datagram_size == 0U) {
            result.stage = VideoPublishResult::Stage::encode_datagram;
            return result;
        }
        // Recheck at the actual send boundary so a lease expiry or channel
        // loss cannot leak the tail of a large access unit.
        if (!authorization_permits_send()) {
            result.stage = VideoPublishResult::Stage::authorization_check;
            return result;
        }
        if (!socket_.send(std::span<const std::byte>{datagram.data(), datagram_size})) {
            result.stage = VideoPublishResult::Stage::socket_send;
            return result;
        }
        ++result.fragments_sent;
        result.bytes_sent += static_cast<std::uint32_t>(datagram_size);
    }
    result.success = true;
    result.stage = VideoPublishResult::Stage::complete;
    return result;
}

bool UdpVideoPublisher::authorization_permits_send() const noexcept {
    if (!permit_source_) return false;
    try {
        return permit_source_();
    } catch (...) {
        return false;
    }
}

std::uint32_t UdpVideoPublisher::last_socket_error() const noexcept { return socket_.last_error(); }
std::uint16_t UdpVideoPublisher::local_port() const noexcept { return socket_.local_port(); }
}  // namespace vfdual
