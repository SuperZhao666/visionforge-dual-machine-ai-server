#include "vfdual/isolated_dhcp_protocol.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace vfdual {
namespace {

constexpr std::size_t kBootpFixedBytes = 236;
constexpr std::array<std::uint8_t, 4> kDhcpCookie{99, 130, 83, 99};
constexpr std::uint8_t kOptionPadding = 0;
constexpr std::uint8_t kOptionSubnetMask = 1;
constexpr std::uint8_t kOptionRequestedAddress = 50;
constexpr std::uint8_t kOptionLeaseTime = 51;
constexpr std::uint8_t kOptionMessageType = 53;
constexpr std::uint8_t kOptionServerIdentifier = 54;
constexpr std::uint8_t kOptionRenewalTime = 58;
constexpr std::uint8_t kOptionRebindingTime = 59;
constexpr std::uint8_t kOptionEnd = 255;
constexpr std::uint8_t kDhcpDiscover = 1;
constexpr std::uint8_t kDhcpOffer = 2;
constexpr std::uint8_t kDhcpRequest = 3;
constexpr std::uint8_t kDhcpAck = 5;
constexpr std::uint32_t kLeaseSeconds = 86'400;

struct ParsedRequest final {
    bool valid{};
    std::uint8_t message_type{};
    std::uint32_t xid{};
    std::uint32_t client_address{};
    std::uint32_t requested_address{};
    std::uint32_t server_identifier{};
    std::array<std::uint8_t, 6> client_mac{};
};

void append_option(std::vector<std::uint8_t>& packet, std::uint8_t code,
                   std::span<const std::uint8_t> value) {
    packet.push_back(code);
    packet.push_back(static_cast<std::uint8_t>(value.size()));
    packet.insert(packet.end(), value.begin(), value.end());
}

void append_u32_option(std::vector<std::uint8_t>& packet, std::uint8_t code,
                       std::uint32_t network_value) {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&network_value);
    append_option(packet, code, std::span<const std::uint8_t>(bytes, sizeof(network_value)));
}

std::uint32_t host_to_network_u32(std::uint32_t value) noexcept {
    return ((value & 0x000000ffU) << 24U) | ((value & 0x0000ff00U) << 8U) |
           ((value & 0x00ff0000U) >> 8U) | ((value & 0xff000000U) >> 24U);
}

ParsedRequest parse_request(std::span<const std::uint8_t> packet) noexcept {
    ParsedRequest parsed{};
    if (packet.size() < kBootpFixedBytes + kDhcpCookie.size() || packet[0] != 1 ||
        packet[1] != 1 || packet[2] != 6 ||
        !std::equal(kDhcpCookie.begin(), kDhcpCookie.end(), packet.begin() + kBootpFixedBytes)) {
        return parsed;
    }
    std::memcpy(&parsed.xid, packet.data() + 4, 4);
    std::memcpy(&parsed.client_address, packet.data() + 12, 4);
    std::copy_n(packet.begin() + 28, parsed.client_mac.size(), parsed.client_mac.begin());
    const bool all_zero_mac = std::all_of(
        parsed.client_mac.begin(), parsed.client_mac.end(), [](std::uint8_t byte) { return byte == 0; });
    const bool all_ff_mac = std::all_of(
        parsed.client_mac.begin(), parsed.client_mac.end(), [](std::uint8_t byte) { return byte == 0xff; });
    if (all_zero_mac || all_ff_mac) return parsed;
    std::size_t cursor = kBootpFixedBytes + kDhcpCookie.size();
    while (cursor < packet.size()) {
        const std::uint8_t code = packet[cursor++];
        if (code == kOptionEnd) break;
        if (code == kOptionPadding) continue;
        if (cursor >= packet.size()) return {};
        const std::size_t length = packet[cursor++];
        if (length > packet.size() - cursor) return {};
        if (code == kOptionMessageType && length == 1) parsed.message_type = packet[cursor];
        if (code == kOptionRequestedAddress && length == 4) {
            std::memcpy(&parsed.requested_address, packet.data() + cursor, 4);
        }
        if (code == kOptionServerIdentifier && length == 4) {
            std::memcpy(&parsed.server_identifier, packet.data() + cursor, 4);
        }
        cursor += length;
    }
    parsed.valid = parsed.message_type == kDhcpDiscover || parsed.message_type == kDhcpRequest;
    return parsed;
}

std::vector<std::uint8_t> build_reply(
    std::span<const std::uint8_t> request, std::uint8_t message_type,
    const IsolatedDhcpProtocolConfig& config) {
    std::vector<std::uint8_t> reply(kBootpFixedBytes, 0);
    reply[0] = 2;
    reply[1] = request[1];
    reply[2] = request[2];
    reply[3] = request[3];
    std::copy_n(request.begin() + 4, 4, reply.begin() + 4);
    reply[10] = 0x80;
    std::memcpy(reply.data() + 16, &config.lease_address_network_order, 4);
    std::memcpy(reply.data() + 20, &config.server_address_network_order, 4);
    std::copy_n(request.begin() + 28, 16, reply.begin() + 28);
    reply.insert(reply.end(), kDhcpCookie.begin(), kDhcpCookie.end());
    append_option(reply, kOptionMessageType, std::span<const std::uint8_t>(&message_type, 1));
    append_u32_option(reply, kOptionServerIdentifier, config.server_address_network_order);
    append_u32_option(reply, kOptionSubnetMask, config.subnet_mask_network_order);
    append_u32_option(reply, kOptionLeaseTime, host_to_network_u32(kLeaseSeconds));
    append_u32_option(reply, kOptionRenewalTime, host_to_network_u32(kLeaseSeconds / 2));
    append_u32_option(reply, kOptionRebindingTime, host_to_network_u32((kLeaseSeconds * 7) / 8));
    reply.push_back(kOptionEnd);
    if (reply.size() < 300) reply.resize(300, 0);
    return reply;
}

}  // namespace

IsolatedDhcpProtocol::IsolatedDhcpProtocol(IsolatedDhcpProtocolConfig config) noexcept
    : config_(config) {
    const auto server = config_.server_address_network_order;
    const auto lease = config_.lease_address_network_order;
    const auto mask = config_.subnet_mask_network_order;
    valid_ = server != 0 && lease != 0 && mask != 0 && server != lease &&
             (server & mask) == (lease & mask);
}

bool IsolatedDhcpProtocol::valid() const noexcept { return valid_; }

std::uint64_t IsolatedDhcpProtocol::rejected_packets() const noexcept {
    return rejected_packets_;
}

IsolatedDhcpDecision IsolatedDhcpProtocol::process(
    std::span<const std::uint8_t> request) noexcept {
    IsolatedDhcpDecision decision{};
    const ParsedRequest parsed = parse_request(request);
    decision.request_message_type = parsed.message_type;
    decision.transaction_id = parsed.xid;
    decision.client_mac = parsed.client_mac;
    const auto reject = [&](IsolatedDhcpRejectReason reason) {
        ++rejected_packets_;
        decision.reject_reason = reason;
        return decision;
    };
    if (!valid_) return reject(IsolatedDhcpRejectReason::invalid_configuration);
    if (!parsed.valid) return reject(IsolatedDhcpRejectReason::malformed_request);
    if (config_.has_excluded_client_mac &&
        parsed.client_mac == config_.excluded_client_mac) {
        return reject(IsolatedDhcpRejectReason::local_interface_client);
    }

    if (parsed.message_type == kDhcpDiscover) {
        if ((has_offer_ || has_lease_) && parsed.client_mac != client_mac_) {
            return reject(has_lease_
                ? IsolatedDhcpRejectReason::lease_owned_by_other_client
                : IsolatedDhcpRejectReason::client_mismatch);
        }
        decision.response_message_type = kDhcpOffer;
    } else {
        if (!has_offer_ && !has_lease_) {
            return reject(IsolatedDhcpRejectReason::request_without_offer);
        }
        if (parsed.client_mac != client_mac_) {
            return reject(IsolatedDhcpRejectReason::client_mismatch);
        }
        if (parsed.server_identifier != 0 &&
            parsed.server_identifier != config_.server_address_network_order) {
            return reject(IsolatedDhcpRejectReason::server_identifier_mismatch);
        }
        if (parsed.requested_address != 0 &&
            parsed.requested_address != config_.lease_address_network_order) {
            return reject(IsolatedDhcpRejectReason::requested_address_mismatch);
        }
        if (parsed.client_address != 0 &&
            parsed.client_address != config_.lease_address_network_order) {
            return reject(IsolatedDhcpRejectReason::client_address_mismatch);
        }
        const bool selecting_request = parsed.server_identifier != 0 || parsed.requested_address != 0;
        if (!has_lease_ && (!selecting_request || parsed.xid != offered_xid_)) {
            return reject(IsolatedDhcpRejectReason::transaction_mismatch);
        }
        decision.response_message_type = kDhcpAck;
    }
    decision.accepted = true;
    decision.reply = build_reply(request, decision.response_message_type, config_);
    return decision;
}

void IsolatedDhcpProtocol::commit_sent_response(
    const IsolatedDhcpDecision& decision) noexcept {
    if (!decision.accepted) return;
    if (decision.response_message_type == kDhcpOffer) {
        has_offer_ = true;
        offered_xid_ = decision.transaction_id;
        client_mac_ = decision.client_mac;
        return;
    }
    if (decision.response_message_type == kDhcpAck) {
        has_lease_ = true;
        client_mac_ = decision.client_mac;
    }
}

const char* isolated_dhcp_reject_reason_name(
    IsolatedDhcpRejectReason reason) noexcept {
    switch (reason) {
        case IsolatedDhcpRejectReason::none: return "none";
        case IsolatedDhcpRejectReason::invalid_configuration: return "invalid_configuration";
        case IsolatedDhcpRejectReason::malformed_request: return "malformed_request";
        case IsolatedDhcpRejectReason::local_interface_client: return "local_interface_client";
        case IsolatedDhcpRejectReason::lease_owned_by_other_client:
            return "lease_owned_by_other_client";
        case IsolatedDhcpRejectReason::request_without_offer: return "request_without_offer";
        case IsolatedDhcpRejectReason::client_mismatch: return "client_mismatch";
        case IsolatedDhcpRejectReason::server_identifier_mismatch:
            return "server_identifier_mismatch";
        case IsolatedDhcpRejectReason::requested_address_mismatch:
            return "requested_address_mismatch";
        case IsolatedDhcpRejectReason::client_address_mismatch:
            return "client_address_mismatch";
        case IsolatedDhcpRejectReason::transaction_mismatch: return "transaction_mismatch";
    }
    return "unknown";
}

}  // namespace vfdual
