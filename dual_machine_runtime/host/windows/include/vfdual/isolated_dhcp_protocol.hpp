#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace vfdual {

struct IsolatedDhcpProtocolConfig final {
    std::uint32_t server_address_network_order{};
    std::uint32_t lease_address_network_order{};
    std::uint32_t subnet_mask_network_order{};
    std::array<std::uint8_t, 6> excluded_client_mac{};
    bool has_excluded_client_mac{};
};

enum class IsolatedDhcpRejectReason : std::uint8_t {
    none,
    invalid_configuration,
    malformed_request,
    local_interface_client,
    lease_owned_by_other_client,
    request_without_offer,
    client_mismatch,
    server_identifier_mismatch,
    requested_address_mismatch,
    client_address_mismatch,
    transaction_mismatch,
};

struct IsolatedDhcpDecision final {
    bool accepted{};
    std::uint8_t request_message_type{};
    std::uint8_t response_message_type{};
    IsolatedDhcpRejectReason reject_reason{IsolatedDhcpRejectReason::none};
    std::uint32_t transaction_id{};
    std::array<std::uint8_t, 6> client_mac{};
    std::vector<std::uint8_t> reply;
};

[[nodiscard]] const char* isolated_dhcp_reject_reason_name(
    IsolatedDhcpRejectReason reason) noexcept;

/**
 * Pure single-client DHCP state machine used by the isolated wired link.
 *
 * The first external DISCOVER whose OFFER is successfully transmitted owns
 * the pending transaction. A selecting REQUEST must match it. Once ACKed,
 * later renewals may use a new XID but must retain the acknowledged MAC and
 * lease address. Failed sends are never committed into protocol state.
 */
class IsolatedDhcpProtocol final {
public:
    explicit IsolatedDhcpProtocol(IsolatedDhcpProtocolConfig config) noexcept;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] std::uint64_t rejected_packets() const noexcept;
    [[nodiscard]] IsolatedDhcpDecision process(
        std::span<const std::uint8_t> request) noexcept;
    void commit_sent_response(const IsolatedDhcpDecision& decision) noexcept;

private:
    IsolatedDhcpProtocolConfig config_{};
    bool valid_{};
    bool has_offer_{};
    bool has_lease_{};
    std::uint32_t offered_xid_{};
    std::array<std::uint8_t, 6> client_mac_{};
    std::uint64_t rejected_packets_{};
};

}  // namespace vfdual
