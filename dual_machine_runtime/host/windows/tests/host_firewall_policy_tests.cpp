#include "vfdual/host_firewall_provisioner.hpp"
#include "vfdual/wired_link_contract.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
    std::exit(EXIT_FAILURE);
}

vfdual::HostFirewallRuleSnapshot snapshot_of(
    const vfdual::HostFirewallRulePolicy& policy) {
    vfdual::HostFirewallRuleSnapshot snapshot{};
    static_cast<vfdual::HostFirewallRulePolicy&>(snapshot) = policy;
    snapshot.protocol_number = policy.protocol == vfdual::HostFirewallProtocol::tcp
        ? 6L : 17L;
    snapshot.edge_traversal_options = 0L;
    snapshot.profiles = 0x7fffffffL;
    snapshot.all_profiles = true;
    return snapshot;
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

int main() {
    using vfdual::HostFirewallProtocol;
    const std::wstring executable = L"C:\\Program Files\\VF\\VFHost.exe";
    const auto policy = vfdual::build_host_firewall_policy(executable);

    CHECK(policy.size() == 7U);
    CHECK(policy[0].name == L"VF Host CAT6 DHCP Inbound");
    CHECK(policy[1].name == L"VF Host CAT6 Announcement Inbound");
    CHECK(policy[2].name == L"VF Host CAT6 IDR Inbound");
    CHECK(policy[3].name == L"VF Host Wireless LAN Announcement Inbound");
    CHECK(policy[4].name == L"VF Host Wireless LAN IDR Inbound");
    CHECK(policy[5].name == L"VF Host CAT6 First Pairing Inbound");
    CHECK(policy[6].name == L"VF Host Wireless LAN First Pairing Inbound");
    for (const auto& rule : policy) {
        CHECK(rule.application_path == executable);
        CHECK(rule.grouping == L"VF Host Transport");
        CHECK(rule.interface_name.empty());
        CHECK(rule.inbound && rule.enabled && rule.allow);
        CHECK(!rule.edge_traversal);
    }

    CHECK(policy[0].local_port == vfdual::kWiredDhcpServerPort);
    CHECK(policy[0].remote_port == vfdual::kWiredDhcpClientPort);
    CHECK(policy[0].local_address == "*");
    CHECK(policy[0].remote_addresses == "*");
    CHECK(policy[1].local_port == vfdual::kWiredAnnouncementPort);
    CHECK(policy[1].remote_port == vfdual::kWiredProbePort);
    CHECK(policy[1].local_address == vfdual::kWiredHostIpv4);
    CHECK(policy[1].remote_addresses == vfdual::kWiredMobileIpv4);
    CHECK(policy[2].local_port == vfdual::kWiredIdrPort);
    CHECK(policy[2].remote_port == vfdual::kWiredVideoPort);
    CHECK(policy[2].local_address == vfdual::kWiredHostIpv4);
    CHECK(policy[2].remote_addresses == vfdual::kWiredMobileIpv4);
    CHECK(policy[3].interface_types == L"LAN,Wireless");
    CHECK(policy[3].local_port == vfdual::kWiredAnnouncementPort);
    CHECK(policy[3].remote_port == vfdual::kWiredProbePort);
    CHECK(policy[3].local_address == "*");
    CHECK(policy[3].remote_addresses == "LocalSubnet");
    CHECK(policy[4].interface_types == L"LAN,Wireless");
    CHECK(policy[4].local_port == vfdual::kWiredIdrPort);
    CHECK(policy[4].remote_port == vfdual::kWiredVideoPort);
    for (std::size_t index = 0U; index < 5U; ++index) {
        CHECK(policy[index].protocol == HostFirewallProtocol::udp);
    }
    CHECK(policy[5].protocol == HostFirewallProtocol::tcp);
    CHECK(policy[5].interface_types == L"LAN");
    CHECK(policy[5].local_address == vfdual::kWiredHostIpv4);
    CHECK(policy[5].remote_addresses == vfdual::kWiredMobileIpv4);
    CHECK(policy[5].local_port == vfdual::kWiredAuthenticatedControlPort);
    CHECK(policy[5].remote_port == 0U);
    CHECK(policy[6].protocol == HostFirewallProtocol::tcp);
    CHECK(policy[6].interface_types == L"LAN,Wireless");
    CHECK(policy[6].local_address == "*");
    CHECK(policy[6].remote_addresses == "LocalSubnet");
    CHECK(policy[6].local_port == vfdual::kWiredAuthenticatedControlPort);
    CHECK(policy[6].remote_port == 0U);
    auto current = snapshot_of(policy[6]);
    CHECK(vfdual::host_firewall_rule_is_current(policy[6], current));
    current.protocol = HostFirewallProtocol::udp;
    current.protocol_number = 17L;
    CHECK(!vfdual::host_firewall_rule_is_current(policy[6], current));

    current = snapshot_of(policy[0]);
    CHECK(vfdual::host_firewall_rule_is_current(policy[0], current));
    CHECK(vfdual::host_firewall_rule_set_is_current(policy[0], {current}));
    CHECK(!vfdual::host_firewall_rule_set_is_current(policy[0], {}));
    CHECK(!vfdual::host_firewall_rule_set_is_current(policy[0], {current, current}));
    current.application_path = L"c:/program files/vf/vfhost.exe";
    CHECK(vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.application_path = L"C:\\Old\\VisionForgeHost.exe";
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.interface_name = L"Wi-Fi";
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.edge_traversal = true;
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.remote_addresses = vfdual::kWiredMobileIpv4;
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.local_address = vfdual::kWiredHostIpv4;
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[1]);
    current.local_address = "10.57.23.1/255.255.255.255";
    current.remote_addresses = "10.57.23.2/255.255.255.255";
    CHECK(vfdual::host_firewall_rule_is_current(policy[1], current));
    current.local_address = "10.57.23.1/32";
    current.remote_addresses = "10.57.23.2/32";
    CHECK(vfdual::host_firewall_rule_is_current(policy[1], current));
    current.local_address = "10.57.23.1/255.255.255.0";
    CHECK(!vfdual::host_firewall_rule_is_current(policy[1], current));
    current = snapshot_of(policy[1]);
    current.remote_addresses = "10.57.23.2/255.255.255.255,10.57.23.3/32";
    CHECK(!vfdual::host_firewall_rule_is_current(policy[1], current));
    current = snapshot_of(policy[0]);
    current.protocol = HostFirewallProtocol::tcp;
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.protocol_number = 6L;
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.edge_traversal_options = 2L;
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.all_profiles = false;
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.interface_types = L"Wireless";
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[3]);
    current.interface_types = L"Wireless, LAN";
    CHECK(vfdual::host_firewall_rule_is_current(policy[3], current));
    current = snapshot_of(policy[0]);
    current.service_name = L"Dhcp";
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.local_app_package_id = L"package";
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.local_user_owner = L"S-1-5-21-owner";
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.local_user_authorized_list = L"O:LSD:(A;;CC;;;WD)";
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.remote_user_authorized_list = L"O:LSD:(A;;CC;;;WD)";
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.remote_machine_authorized_list = L"O:LSD:(A;;CC;;;WD)";
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));
    current = snapshot_of(policy[0]);
    current.secure_flags = 1L;
    CHECK(!vfdual::host_firewall_rule_is_current(policy[0], current));

    auto owned = snapshot_of(policy[1]);
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    auto legacy_owned = snapshot_of(policy[1]);
    legacy_owned.name = L"VisionForge Host CAT6 Announcement Inbound";
    legacy_owned.description = L"VisionForge Host isolated CAT6 transport";
    legacy_owned.grouping = L"VisionForge Host Transport";
    CHECK(!vfdual::host_firewall_rule_is_current(policy[1], legacy_owned));
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(
        policy[1], legacy_owned));
    legacy_owned.grouping = L"VisionForge Host CAT6";
    legacy_owned.interface_name = L"Ethernet 2";
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(
        policy[1], legacy_owned));
    legacy_owned.description = L"Imposter";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(
        policy[1], legacy_owned));
    owned.application_path = L"C:\\Old\\VisionForgeHost.exe";
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Old\\VisionForgeHost (1).exe";
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Old\\VisionForgeHost (999).exe";
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Releases\\VisionForgeHost_1.0.8.exe";
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Releases\\VFHost_18.2.104.exe";
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Releases\\VisionForgeHost_1.0.exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Releases\\VisionForgeHost_1.0.8-beta.exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Releases\\VisionForgeHost_1.0.8_backup.exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Releases\\VisionForgeHost_1..8.exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path =
        L"C:\\Releases\\VisionForgeHost_12345678901.0.8.exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Releases\\Other_VisionForgeHost_1.0.8.exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Releases\\VisionForgeHost_1.0.8.exe.bak";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Old\\VisionForgeHost (0).exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Old\\VisionForgeHost (1000).exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Old\\VisionForgeHost (backup).exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path = L"C:\\Old\\VFHost.exe";
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path =
        L"C:\\Old\\VisionForgeHost_Portable_Test_20260723.exe";
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path =
        L"C:\\Old\\VisionForgeHost_Portable_Test_20260724.exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path =
        L"C:\\Old\\VFHost.failed-a4652d034ed41087.exe";
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path =
        L"C:\\Old\\VFHost.failed-not-a-content-hash.exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path =
        L"C:\\Old\\VisionForgeHost.failed-a4652d034ed41087.exe";
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path =
        L"C:\\Old\\VisionForgeHost.failed-"
        L"2fe408b0fe3723fc84f57400578d2566e968ee3a22b8b67ec8f1bd49fb116f82.exe";
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned.application_path =
        L"C:\\Old\\VisionForgeHost.failed-not-a-content-hash.exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    const auto renamed_policy = vfdual::build_host_firewall_policy(
        L"C:\\Portable\\RenamedHost.exe");
    auto renamed_owned = snapshot_of(renamed_policy[1]);
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(
        renamed_policy[1], renamed_owned));
    renamed_owned.application_path = L"C:\\Old\\VisionForgeHost.exe";
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(
        renamed_policy[1], renamed_owned));
    renamed_owned.application_path = L"C:\\Other\\RenamedHost.exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(
        renamed_policy[1], renamed_owned));
    owned = snapshot_of(policy[1]);
    owned.application_path = L"C:\\Old\\Other.exe";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned = snapshot_of(policy[1]);
    owned.local_address = "*";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned = snapshot_of(policy[1]);
    owned.remote_addresses = "*";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned = snapshot_of(policy[1]);
    owned.local_port = 1U;
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned = snapshot_of(policy[1]);
    owned.interface_types = L"Wireless";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned = snapshot_of(policy[1]);
    owned.protocol_number = 6L;
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned = snapshot_of(policy[1]);
    owned.edge_traversal_options = 2L;
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned = snapshot_of(policy[1]);
    owned.profiles = 1L;
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned = snapshot_of(policy[1]);
    owned.secure_flags = 1L;
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));
    owned = snapshot_of(policy[1]);
    owned.local_user_authorized_list = L"O:LSD:(A;;CC;;;WD)";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(policy[1], owned));

    auto legacy_wireless_scope = snapshot_of(policy[3]);
    legacy_wireless_scope.interface_types = L"Wireless";
    CHECK(!vfdual::host_firewall_rule_is_current(
        policy[3], legacy_wireless_scope));
    CHECK(vfdual::host_firewall_rule_is_recognized_owned(
        policy[3], legacy_wireless_scope));
    legacy_wireless_scope.interface_types = L"LAN";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(
        policy[3], legacy_wireless_scope));
    legacy_wireless_scope.interface_types = L"LAN,Wireless,RemoteAccess";
    CHECK(!vfdual::host_firewall_rule_is_recognized_owned(
        policy[3], legacy_wireless_scope));

    vfdual::HostFirewallActiveProfileState profiles{};
    CHECK(!vfdual::host_firewall_active_profiles_are_enabled(profiles));
    profiles.domain_active = true;
    CHECK(!vfdual::host_firewall_active_profiles_are_enabled(profiles));
    profiles.domain_enabled = true;
    CHECK(vfdual::host_firewall_active_profiles_are_enabled(profiles));
    profiles.private_active = true;
    CHECK(!vfdual::host_firewall_active_profiles_are_enabled(profiles));
    profiles.private_enabled = true;
    profiles.public_active = true;
    profiles.public_enabled = true;
    CHECK(vfdual::host_firewall_active_profiles_are_enabled(profiles));
    profiles.unknown_profile_active = true;
    CHECK(!vfdual::host_firewall_active_profiles_are_enabled(profiles));
    CHECK(!vfdual::host_firewall_active_profiles_are_all_disabled(profiles));

    profiles = {};
    profiles.active_profile_mask = 4L;
    profiles.public_active = true;
    CHECK(vfdual::host_firewall_active_profiles_are_all_disabled(profiles));
    profiles.public_enabled = true;
    CHECK(!vfdual::host_firewall_active_profiles_are_all_disabled(profiles));

    vfdual::HostFirewallRuleAuditEntry audit{};
    audit.name = policy[0].name;
    audit.application_path = executable;
    audit.description = policy[0].description;
    audit.grouping = policy[0].grouping;
    audit.inbound = true;
    audit.enabled = true;
    audit.allow = true;
    CHECK(!vfdual::host_firewall_rule_is_conflicting_executable_allow(
        executable, policy, audit));
    audit.name = L"VisionForge Host CAT6 DHCP Inbound";
    audit.description = L"VisionForge Host isolated CAT6 transport";
    audit.grouping = L"VisionForge Host Transport";
    CHECK(!vfdual::host_firewall_rule_is_conflicting_executable_allow(
        executable, policy, audit));
    audit.name = policy[0].name;
    audit.description = policy[0].description;
    audit.grouping = policy[0].grouping;
    audit.description = L"Imposter";
    CHECK(vfdual::host_firewall_rule_is_conflicting_executable_allow(
        executable, policy, audit));
    audit.description = policy[0].description;
    audit.grouping = L"Imposter";
    CHECK(vfdual::host_firewall_rule_is_conflicting_executable_allow(
        executable, policy, audit));
    audit.grouping = policy[0].grouping;
    audit.name = L"VFHost broad UDP";
    CHECK(vfdual::host_firewall_rule_is_conflicting_executable_allow(
        L"c:/program files/vf/vfhost.exe", policy, audit));
    audit.name = L"VisionForgeHost broad UDP";
    CHECK(vfdual::host_firewall_rule_is_conflicting_executable_allow(
        L"c:/program files/vf/vfhost.exe", policy, audit));
    audit.enabled = false;
    CHECK(!vfdual::host_firewall_rule_is_conflicting_executable_allow(
        executable, policy, audit));
    audit.enabled = true;
    audit.inbound = false;
    CHECK(!vfdual::host_firewall_rule_is_conflicting_executable_allow(
        executable, policy, audit));
    audit.inbound = true;
    audit.allow = false;
    CHECK(!vfdual::host_firewall_rule_is_conflicting_executable_allow(
        executable, policy, audit));
    audit.allow = true;
    audit.application_path = L"C:\\Other\\VFHost.exe";
    CHECK(!vfdual::host_firewall_rule_is_conflicting_executable_allow(
        executable, policy, audit));

    CHECK(vfdual::host_firewall_is_ready(vfdual::HostFirewallStatus::ready));
    CHECK(vfdual::host_firewall_is_ready(vfdual::HostFirewallStatus::provisioned));
    CHECK(!vfdual::host_firewall_is_ready(vfdual::HostFirewallStatus::requires_elevation));
    CHECK(!vfdual::host_firewall_is_ready(vfdual::HostFirewallStatus::failed));
    return 0;
}
