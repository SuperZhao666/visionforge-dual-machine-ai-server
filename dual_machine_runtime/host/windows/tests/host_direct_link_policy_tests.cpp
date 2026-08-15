#include "vfdual/host_direct_link_provisioner.hpp"

#include <cstdlib>
#include <iostream>
#include <vector>

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
    std::exit(EXIT_FAILURE);
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

int main() {
    using vfdual::HostAdapterTransport;
    using vfdual::HostNetworkIpv4AddressProfile;
    using vfdual::HostNetworkAdapterProfile;

    const std::vector<HostNetworkAdapterProfile> direct_pair{
        {L"Ethernet", "wired", HostAdapterTransport::ethernet, true, true, false, false, true, false, false, 9},
        {L"Internet uplink", "uplink", HostAdapterTransport::other, true, true, true, true, false, false, false, 20},
    };
    const auto selected = vfdual::choose_host_direct_link_plan(direct_pair);
    CHECK(selected.downstream_adapter == 0U);
    CHECK(!selected.upstream_adapter.has_value());
    CHECK(!selected.downstream_already_ready);

    auto ready_pair = direct_pair;
    ready_pair[0].has_link_local_ipv4 = false;
    ready_pair[0].has_usable_ipv4 = true;
    ready_pair[0].has_isolated_private_ipv4 = true;
    const auto ready = vfdual::choose_host_direct_link_plan(ready_pair);
    CHECK(ready.downstream_adapter == 0U);
    CHECK(ready.downstream_already_ready);

    auto routed_ethernet = direct_pair;
    routed_ethernet[0].has_default_gateway = true;
    routed_ethernet[0].has_usable_ipv4 = true;
    routed_ethernet[0].has_link_local_ipv4 = false;
    routed_ethernet[0].ipv4_gateways = {"192.168.50.1"};
    const auto no_downstream = vfdual::choose_host_direct_link_plan(routed_ethernet);
    CHECK(!no_downstream.downstream_adapter.has_value());
    CHECK(no_downstream.reason.find("inventory_count=2") != std::string::npos);
    CHECK(no_downstream.reason.find("name=\"Ethernet\"") != std::string::npos);
    CHECK(no_downstream.reason.find("guid=\"wired\"") != std::string::npos);
    CHECK(no_downstream.reason.find("ifindex=9") != std::string::npos);
    CHECK(no_downstream.reason.find("hardware=true") != std::string::npos);
    CHECK(no_downstream.reason.find("oper=up") != std::string::npos);
    CHECK(no_downstream.reason.find("transport=ethernet") != std::string::npos);
    CHECK(no_downstream.reason.find("has_default_gateway=true") != std::string::npos);
    CHECK(no_downstream.reason.find("gateways=[192.168.50.1]") !=
          std::string::npos);
    CHECK(no_downstream.reason.find("dhcp=false") != std::string::npos);
    CHECK(no_downstream.reason.find("rejected_by=[has_default_gateway") !=
          std::string::npos);

    auto e_drive_routed_dhcp = direct_pair;
    e_drive_routed_dhcp[0].has_default_gateway = true;
    e_drive_routed_dhcp[0].has_usable_ipv4 = true;
    e_drive_routed_dhcp[0].has_link_local_ipv4 = false;
    e_drive_routed_dhcp[0].dhcp_enabled = true;
    e_drive_routed_dhcp[0].ipv4_gateways = {"10.35.90.105"};
    e_drive_routed_dhcp[0].ipv4_addresses = {
        HostNetworkIpv4AddressProfile{
            .address = "10.35.90.250",
            .prefix_length = 24,
            .prefix_origin = 3,
            .suffix_origin = 3,
            .dad_state = 4,
            .skip_as_source = false,
        },
    };
    const auto e_drive_routed_plan =
        vfdual::choose_host_direct_link_plan(e_drive_routed_dhcp);
    CHECK(e_drive_routed_plan.downstream_adapter == 0U);
    CHECK(!e_drive_routed_plan.downstream_already_ready);
    CHECK(e_drive_routed_plan.reason ==
          "isolated_routed_dhcp_wired_adapter_selected");

    auto isolated_adapters_only = direct_pair;
    isolated_adapters_only.pop_back();
    const auto isolated_only = vfdual::choose_host_direct_link_plan(isolated_adapters_only);
    CHECK(isolated_only.downstream_adapter == 0U);
    CHECK(!isolated_only.upstream_adapter.has_value());

    auto legacy_ics = direct_pair;
    legacy_ics[0].has_link_local_ipv4 = false;
    legacy_ics[0].has_usable_ipv4 = true;
    legacy_ics[0].has_ics_private_ipv4 = true;
    const auto migratable = vfdual::choose_host_direct_link_plan(legacy_ics);
    CHECK(migratable.downstream_adapter == 0U);
    CHECK(!migratable.downstream_already_ready);

    auto ambiguous = direct_pair;
    ambiguous.insert(ambiguous.begin() + 1,
                     {L"Second Ethernet", "wired-2", HostAdapterTransport::ethernet,
                      true, true, false, false, true, false, false, 10});
    const auto ambiguous_plan = vfdual::choose_host_direct_link_plan(ambiguous);
    CHECK(!ambiguous_plan.downstream_adapter.has_value());
    CHECK(ambiguous_plan.ambiguous_downstream);
    CHECK(ambiguous_plan.reason.find(
              "reason=ambiguous_unrouted_ethernet_adapters candidate_count=2 "
              "adapter_ids=wired,wired-2") == 0U);
    CHECK(ambiguous_plan.reason.find("inventory_count=3") != std::string::npos);

    auto one_existing_cat6 = ambiguous;
    one_existing_cat6[1].has_link_local_ipv4 = false;
    one_existing_cat6[1].has_usable_ipv4 = true;
    one_existing_cat6[1].has_isolated_private_ipv4 = true;
    const auto existing_cat6 = vfdual::choose_host_direct_link_plan(one_existing_cat6);
    CHECK(existing_cat6.downstream_adapter == 1U);
    CHECK(existing_cat6.downstream_already_ready);

    auto multiple_existing_cat6 = one_existing_cat6;
    multiple_existing_cat6[0].has_link_local_ipv4 = false;
    multiple_existing_cat6[0].has_usable_ipv4 = true;
    multiple_existing_cat6[0].has_isolated_private_ipv4 = true;
    const auto multiple_existing = vfdual::choose_host_direct_link_plan(multiple_existing_cat6);
    CHECK(!multiple_existing.downstream_adapter.has_value());
    CHECK(multiple_existing.ambiguous_downstream);
    CHECK(multiple_existing.reason.find(
              "reason=multiple_existing_cat6_adapters candidate_count=2 "
              "adapter_ids=wired,wired-2") == 0U);
    CHECK(multiple_existing.reason.find("inventory_count=3") != std::string::npos);

    auto virtual_and_physical = ambiguous;
    virtual_and_physical[0].hardware_interface = false;
    const auto physical_only = vfdual::choose_host_direct_link_plan(virtual_and_physical);
    CHECK(physical_only.downstream_adapter == 1U);
    CHECK(!physical_only.ambiguous_downstream);

    auto dhcp_assigned = direct_pair;
    dhcp_assigned[0].has_link_local_ipv4 = false;
    dhcp_assigned[0].has_usable_ipv4 = true;
    dhcp_assigned[0].dhcp_enabled = true;
    dhcp_assigned[0].ipv4_addresses = {
        HostNetworkIpv4AddressProfile{
            .address = "172.20.10.4",
            .prefix_length = 28,
            .prefix_origin = 3,
            .suffix_origin = 3,
            .dad_state = 4,
            .skip_as_source = false,
        },
    };
    const auto dhcp_assigned_plan =
        vfdual::choose_host_direct_link_plan(dhcp_assigned);
    CHECK(dhcp_assigned_plan.downstream_adapter == 0U);
    CHECK(!dhcp_assigned_plan.downstream_already_ready);

    auto manually_assigned = dhcp_assigned;
    manually_assigned[0].ipv4_addresses[0].prefix_origin = 1;
    manually_assigned[0].ipv4_addresses[0].suffix_origin = 1;
    const auto manually_assigned_plan =
        vfdual::choose_host_direct_link_plan(manually_assigned);
    CHECK(!manually_assigned_plan.downstream_adapter.has_value());
    CHECK(manually_assigned_plan.reason.find("preexisting_static_ipv4") !=
          std::string::npos);
    CHECK(manually_assigned_plan.reason.find("address=172.20.10.4") !=
          std::string::npos);
    CHECK(manually_assigned_plan.reason.find("prefix=28") != std::string::npos);
    CHECK(manually_assigned_plan.reason.find("dad=preferred(4)") !=
          std::string::npos);
    CHECK(manually_assigned_plan.reason.find("skip_as_source=false") !=
          std::string::npos);

    auto compatibility_alias = manually_assigned;
    compatibility_alias[0].ipv4_addresses[0].address = "10.57.49.60";
    compatibility_alias[0].ipv4_addresses[0].prefix_length = 24;
    compatibility_alias[0].ipv4_addresses[0].skip_as_source = true;
    const auto compatibility_alias_plan =
        vfdual::choose_host_direct_link_plan(compatibility_alias);
    CHECK(compatibility_alias_plan.downstream_adapter == 0U);
    CHECK(!compatibility_alias_plan.downstream_already_ready);

    auto tentative_manual = manually_assigned;
    tentative_manual[0].has_usable_ipv4 = false;
    tentative_manual[0].ipv4_addresses[0].dad_state = 1;
    const auto tentative_manual_plan =
        vfdual::choose_host_direct_link_plan(tentative_manual);
    CHECK(!tentative_manual_plan.downstream_adapter.has_value());

    HostNetworkAdapterProfile tentative_isolated = direct_pair[0];
    tentative_isolated.ipv4_addresses = {
        HostNetworkIpv4AddressProfile{
            .address = "10.57.23.1",
            .prefix_length = 24,
            .prefix_origin = 1,
            .suffix_origin = 1,
            .dad_state = 1,
            .skip_as_source = true,
        },
    };
    CHECK(vfdual::host_direct_link_has_any_isolated_address(tentative_isolated));
    tentative_isolated.ipv4_addresses[0].address = "10.57.23.2";
    CHECK(!vfdual::host_direct_link_has_any_isolated_address(tentative_isolated));
    const std::vector<HostNetworkAdapterProfile> conflicting_owned_subnet{
        tentative_isolated,
    };
    const auto conflicting_owned_subnet_plan =
        vfdual::choose_host_direct_link_plan(conflicting_owned_subnet);
    CHECK(!conflicting_owned_subnet_plan.downstream_adapter.has_value());
    CHECK(conflicting_owned_subnet_plan.reason.find(
              "owned_subnet_address_conflict") != std::string::npos);

    HostNetworkAdapterProfile tentative_own_address = direct_pair[0];
    tentative_own_address.has_link_local_ipv4 = false;
    tentative_own_address.has_usable_ipv4 = false;
    tentative_own_address.ipv4_addresses = {
        HostNetworkIpv4AddressProfile{
            .address = "10.57.23.1",
            .prefix_length = 24,
            .prefix_origin = 1,
            .suffix_origin = 1,
            .dad_state = 1,
            .skip_as_source = false,
        },
    };
    const auto tentative_own_plan =
        vfdual::choose_host_direct_link_plan({tentative_own_address});
    CHECK(tentative_own_plan.downstream_adapter == 0U);
    CHECK(tentative_own_plan.downstream_already_ready);
    CHECK(tentative_own_plan.downstream_isolated_pending_preference);
    CHECK(tentative_own_plan.reason == "direct_wired_ipv4_pending_preference");

    std::vector<vfdual::HostDirectLinkMutationStep> applied;
    std::uint32_t rollback_calls{};
    const auto committed = vfdual::execute_host_direct_link_transaction({
        .apply = [&](vfdual::HostDirectLinkMutationStep step, std::string&) {
            applied.push_back(step);
            return true;
        },
        .verify = [](std::string&) { return true; },
        .rollback = [&](std::string&) {
            ++rollback_calls;
            return true;
        },
    });
    CHECK(committed.succeeded);
    CHECK(committed.applied_steps == 3U);
    CHECK(!committed.rollback_attempted);
    CHECK(rollback_calls == 0U);

    applied.clear();
    const auto partial_failure = vfdual::execute_host_direct_link_transaction({
        .apply = [&](vfdual::HostDirectLinkMutationStep step, std::string& detail) {
            applied.push_back(step);
            if (step == vfdual::HostDirectLinkMutationStep::dns) {
                detail = "injected_dns_failure";
                return false;
            }
            return true;
        },
        .verify = [](std::string&) { return true; },
        .rollback = [&](std::string&) {
            ++rollback_calls;
            return true;
        },
    });
    CHECK(!partial_failure.succeeded);
    CHECK(partial_failure.failed_step == vfdual::HostDirectLinkMutationStep::dns);
    CHECK(partial_failure.applied_steps == 1U);
    CHECK(partial_failure.rollback_attempted);
    CHECK(partial_failure.rollback_succeeded);
    CHECK(partial_failure.detail.find("injected_dns_failure") != std::string::npos);
    CHECK(rollback_calls == 1U);

    const auto verification_failure = vfdual::execute_host_direct_link_transaction({
        .apply = [](vfdual::HostDirectLinkMutationStep, std::string&) {
            return true;
        },
        .verify = [](std::string& detail) {
            detail = "injected_verify_failure";
            return false;
        },
        .rollback = [](std::string& detail) {
            detail = "injected_rollback_failure";
            return false;
        },
    });
    CHECK(!verification_failure.succeeded);
    CHECK(verification_failure.failed_step ==
          vfdual::HostDirectLinkMutationStep::verify);
    CHECK(verification_failure.applied_steps == 3U);
    CHECK(verification_failure.rollback_attempted);
    CHECK(!verification_failure.rollback_succeeded);
    CHECK(verification_failure.detail.find("injected_rollback_failure") !=
          std::string::npos);
    return 0;
}
