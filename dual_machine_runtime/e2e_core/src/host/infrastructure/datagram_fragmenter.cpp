#include "vf/host/infrastructure/datagram_fragmenter.hpp"

#include "vf/video_transport_contract.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace vf::host::infrastructure {

DatagramFragmenter::DatagramFragmenter(FragmentationConfig config) : config_(config) {
    if (config_.max_datagram_bytes <= kWireHeaderSize ||
        config_.max_datagram_bytes > kMaximumUdpDatagramBytes ||
        config_.max_fragments == 0 || config_.max_fragments > kMaxFragments ||
        config_.max_access_unit_bytes == 0 ||
        config_.max_access_unit_bytes > payload_capacity() * config_.max_fragments) {
        throw std::invalid_argument("invalid or cross-end-inconsistent fragmentation limits");
    }
}

std::vector<std::vector<std::uint8_t>> DatagramFragmenter::fragment(
    host::domain::FrameIdentity identity,
    std::span<const std::uint8_t> access_unit) const {
    if (!identity.valid() || access_unit.empty()) {
        throw std::invalid_argument("frame identity and access unit must be valid");
    }
    if (access_unit.size() > config_.max_access_unit_bytes) {
        throw std::length_error("access unit exceeds the shared receiver limit");
    }
    const auto capacity = payload_capacity();
    const auto fragment_count_size = ((access_unit.size() - 1U) / capacity) + 1U;
    if (fragment_count_size == 0 || fragment_count_size > config_.max_fragments ||
        fragment_count_size > std::numeric_limits<std::uint16_t>::max()) {
        throw std::length_error("access unit exceeds bounded fragmentation capacity");
    }
    const auto fragment_count = static_cast<std::uint16_t>(fragment_count_size);
    std::vector<std::vector<std::uint8_t>> datagrams;
    datagrams.reserve(fragment_count);
    for (std::uint16_t index = 0; index < fragment_count; ++index) {
        const auto offset = static_cast<std::size_t>(index) * capacity;
        const auto payload_bytes = std::min(capacity, access_unit.size() - offset);
        const WireHeader header{
            .kind = PacketKind::Data,
            .stream_epoch = identity.stream_epoch,
            .frame_sequence = identity.frame_sequence,
            .fragment_index = index,
            .fragment_count = fragment_count,
        };
        if (transport::validate(header) != transport::ContractViolation::None) {
            throw std::logic_error("fragmenter produced an invalid wire header");
        }
        const auto encoded = serialize_wire_header(header);
        std::vector<std::uint8_t> datagram;
        datagram.reserve(kWireHeaderSize + payload_bytes);
        datagram.insert(datagram.end(), encoded.begin(), encoded.end());
        datagram.insert(datagram.end(), access_unit.begin() + static_cast<std::ptrdiff_t>(offset),
                        access_unit.begin() + static_cast<std::ptrdiff_t>(offset + payload_bytes));
        datagrams.push_back(std::move(datagram));
    }
    return datagrams;
}

std::vector<std::uint8_t> DatagramFragmenter::repeat(
    host::domain::FrameIdentity identity) const {
    if (!identity.valid()) {
        throw std::invalid_argument("repeat identity must be valid");
    }
    const WireHeader header{
        .kind = PacketKind::Repeat,
        .stream_epoch = identity.stream_epoch,
        .frame_sequence = identity.frame_sequence,
        .fragment_index = 0,
        .fragment_count = 1,
    };
    const auto encoded = serialize_wire_header(header);
    return {encoded.begin(), encoded.end()};
}

}  // namespace vf::host::infrastructure
