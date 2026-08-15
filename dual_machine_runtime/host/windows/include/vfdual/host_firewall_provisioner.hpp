#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace vfdual {

enum class HostFirewallProtocol { udp, tcp };

/** Complete identity of one narrow inbound rule owned by VisionForge Host. */
struct HostFirewallRulePolicy {
    std::wstring name;
    std::wstring description;
    std::wstring grouping;
    std::wstring application_path;
    std::wstring interface_name;
    std::wstring interface_types;
    std::string local_address;
    std::string remote_addresses;
    std::uint16_t local_port{};
    std::uint16_t remote_port{};
    HostFirewallProtocol protocol{HostFirewallProtocol::udp};
    bool inbound{true};
    bool enabled{true};
    bool allow{true};
    bool edge_traversal{};
    std::wstring service_name;
    std::wstring local_app_package_id;
    std::wstring local_user_owner;
    std::wstring local_user_authorized_list;
    std::wstring remote_user_authorized_list;
    std::wstring remote_machine_authorized_list;
    long secure_flags{};
};

/** Read-only state used by the pure reconciliation policy. */
struct HostFirewallRuleSnapshot : HostFirewallRulePolicy {
    long protocol_number{};
    long edge_traversal_options{};
    long profiles{};
    bool all_profiles{};
};

/** Minimal fields needed to audit additional effective rules for this executable. */
struct HostFirewallRuleAuditEntry {
    std::wstring name;
    std::wstring application_path;
    std::wstring description;
    std::wstring grouping;
    bool inbound{};
    bool enabled{};
    bool allow{};
};

/** Read-only active-profile facts used by the pure enforcement policy. */
struct HostFirewallActiveProfileState {
    long active_profile_mask{};
    bool domain_active{};
    bool private_active{};
    bool public_active{};
    bool domain_enabled{};
    bool private_enabled{};
    bool public_enabled{};
    bool unknown_profile_active{};
};

/** Builds the exact CAT6 and on-link LAN/Wi-Fi inbound allowlist. */
[[nodiscard]] std::vector<HostFirewallRulePolicy> build_host_firewall_policy(
    std::wstring application_path);

/** Returns true only when an existing rule is already the exact desired rule. */
[[nodiscard]] bool host_firewall_rule_is_current(
    const HostFirewallRulePolicy& desired,
    const HostFirewallRuleSnapshot& existing) noexcept;

/** Requires exactly one current instance; duplicate display names are stale. */
[[nodiscard]] bool host_firewall_rule_set_is_current(
    const HostFirewallRulePolicy& desired,
    const std::vector<HostFirewallRuleSnapshot>& existing) noexcept;

/** Recognizes a previous narrow VisionForge rule without trusting marker text alone. */
[[nodiscard]] bool host_firewall_rule_is_recognized_owned(
    const HostFirewallRulePolicy& desired,
    const HostFirewallRuleSnapshot& existing) noexcept;

/** Returns true only when every active, supported Windows Firewall profile is enabled. */
[[nodiscard]] bool host_firewall_active_profiles_are_enabled(
    const HostFirewallActiveProfileState& profiles) noexcept;

/** True when Windows currently reports known active profiles, all with filtering disabled. */
[[nodiscard]] bool host_firewall_active_profiles_are_all_disabled(
    const HostFirewallActiveProfileState& profiles) noexcept;

/** Detects an additional enabled inbound allow rule targeting the current Host EXE. */
[[nodiscard]] bool host_firewall_rule_is_conflicting_executable_allow(
    std::wstring_view application_path,
    const std::vector<HostFirewallRulePolicy>& owned_rules,
    const HostFirewallRuleAuditEntry& existing) noexcept;

enum class HostFirewallStatus {
    ready,
    provisioned,
    requires_elevation,
    unavailable,
    failed,
};

struct HostFirewallProvisioningResult {
    HostFirewallStatus status{HostFirewallStatus::unavailable};
    std::uint32_t checked_rules{};
    std::uint32_t changed_rules{};
    std::string detail;
};

/**
 * Reconciles only the VisionForge-owned CAT6 and on-link LAN/Wi-Fi UDP rules. It
 * never changes firewall defaults or unrelated rules.
 */
[[nodiscard]] HostFirewallProvisioningResult ensure_host_firewall_rules();

[[nodiscard]] bool host_firewall_is_ready(HostFirewallStatus status) noexcept;
[[nodiscard]] const char* host_firewall_status_name(HostFirewallStatus status) noexcept;

}  // namespace vfdual
