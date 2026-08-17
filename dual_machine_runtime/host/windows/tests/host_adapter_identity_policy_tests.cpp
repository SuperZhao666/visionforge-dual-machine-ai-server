#include "vfdual/host_adapter_identity_policy.hpp"

#include <cstdlib>
#include <iostream>

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
    using vfdual::HostAdapterIdentityFacts;

    const HostAdapterIdentityFacts physical{
        .hardware_interface = true,
        .connector_present = true,
        .connection_name = L"Ethernet 2",
        .description = L"Realtek PCIe 2.5GbE Family Controller",
    };
    CHECK(!vfdual::host_adapter_has_virtual_or_loopback_identity(physical));
    CHECK(vfdual::host_adapter_has_physical_connector_identity(physical));

    auto npcap = physical;
    npcap.connection_name = L"Npcap Loopback Adapter";
    npcap.description = L"Npcap Packet Driver (NPCAP)";
    CHECK(vfdual::host_adapter_has_virtual_or_loopback_identity(npcap));
    CHECK(!vfdual::host_adapter_has_physical_connector_identity(npcap));

    auto filter = physical;
    filter.filter_interface = true;
    CHECK(vfdual::host_adapter_has_virtual_or_loopback_identity(filter));
    CHECK(!vfdual::host_adapter_has_physical_connector_identity(filter));

    auto endpoint = physical;
    endpoint.endpoint_interface = true;
    CHECK(vfdual::host_adapter_has_virtual_or_loopback_identity(endpoint));
    CHECK(!vfdual::host_adapter_has_physical_connector_identity(endpoint));

    auto no_connector = physical;
    no_connector.connector_present = false;
    CHECK(!vfdual::host_adapter_has_physical_connector_identity(no_connector));

    auto tunnel = physical;
    tunnel.software_loopback_or_tunnel = true;
    CHECK(vfdual::host_adapter_has_virtual_or_loopback_identity(tunnel));
    CHECK(!vfdual::host_adapter_has_physical_connector_identity(tunnel));

    auto case_insensitive_npcap = physical;
    case_insensitive_npcap.connection_name = L"NPCAP LOOPBACK ADAPTER";
    CHECK(vfdual::host_adapter_has_virtual_or_loopback_identity(
        case_insensitive_npcap));
    return 0;
}
