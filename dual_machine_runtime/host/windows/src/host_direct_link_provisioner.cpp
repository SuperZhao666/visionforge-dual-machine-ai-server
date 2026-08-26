#include "vfdual/host_direct_link_provisioner.hpp"
#include "vfdual/host_adapter_identity_policy.hpp"
#include "vfdual/host_firewall_provisioner.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <windows.h>
#include <wincrypt.h>
#include <netcon.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <sstream>
#include <string_view>
#include <thread>
#include <utility>

namespace vfdual {
namespace {

using Microsoft::WRL::ComPtr;

constexpr std::uint32_t kLinkLocalNetwork = 0xA9FE0000U;
constexpr std::uint32_t kLinkLocalMask = 0xFFFF0000U;
constexpr std::uint32_t kIcsPrivateAddress = 0xC0A88901U;  // 192.168.137.1
constexpr std::uint32_t kIsolatedPrivateAddress = 0x0A391701U;  // 10.57.23.1
constexpr std::uint8_t kIsolatedPrivatePrefixLength = 24U;
constexpr DWORD kNetshTimeoutMs = 8'000U;
constexpr DWORD kNetshTerminationGraceMs = 1'000U;
constexpr std::uint32_t kMaximumSnapshotDnsServers = 8U;
constexpr auto kAddressDadTimeout = std::chrono::seconds(5);
constexpr std::size_t kMaximumNetshOutputBytes = 16U * 1024U;
constexpr std::uintmax_t kMaximumSnapshotBytes = 64U * 1024U;
constexpr std::string_view kSnapshotFileName = "host-direct-link-restore-v1.conf";

// An adapter-scoped netsh operation may try both the stable alias and the
// volatile interface index.  Worker timeouts are derived from the maximum
// number of bounded operations, including a complete rollback, so the parent
// never terminates an elevated worker while it is restoring the user's NIC.
constexpr DWORD kNetshAdapterOperationBudgetMs =
    2U * (kNetshTimeoutMs + kNetshTerminationGraceMs);
constexpr DWORD kMaximumRestoreNetshOperations =
    2U + kMaximumSnapshotDnsServers;  // address + DNS entries + interface policy
constexpr DWORD kMaximumProvisionNetshOperations =
    3U + kMaximumRestoreNetshOperations;  // apply address/DNS/policy + rollback
constexpr DWORD kWorkerSafetyMarginMs = 30'000U;
constexpr DWORD kProvisioningWorkerTimeoutMs =
    kMaximumProvisionNetshOperations * kNetshAdapterOperationBudgetMs +
    2U * 5'000U + kWorkerSafetyMarginMs;
constexpr DWORD kRestorationWorkerTimeoutMs =
    kMaximumRestoreNetshOperations * kNetshAdapterOperationBudgetMs +
    kWorkerSafetyMarginMs;
constexpr DWORD kFirewallWorkerTimeoutMs = 60'000U;
constexpr wchar_t kPreferPersistentBackendEnv[] =
    L"VISIONFORGE_HOST_DIRECT_LINK_PREFER_PERSISTENT_BACKEND";

std::atomic_bool g_prefer_persistent_address_backend{false};

enum class OriginalAddressMode {
    dhcp,
    ics_private,
};

enum class AppliedAddressBackend {
    none,
    transient_ip_helper,
    persistent_netsh,
};

enum class RestoreAddressBackendHint {
    infer_from_live_state,
    transient_ip_helper,
    persistent_netsh,
};

enum class TransientAddressCreateStatus {
    created,
    ownership_conflict,
    validation_failed,
    failed,
};

struct HostDirectLinkChangeSnapshot final {
    std::string adapter_id;
    std::uint32_t interface_index{};
    OriginalAddressMode address_mode{OriginalAddressMode::dhcp};
    RestoreAddressBackendHint owned_address_backend{
        RestoreAddressBackendHint::infer_from_live_state};
    std::vector<std::string> static_ipv4_dns_servers;
    bool forwarding_enabled{};
    bool advertising_enabled{};
    std::uint32_t mtu{1500U};
    NL_ROUTER_DISCOVERY_BEHAVIOR router_discovery{RouterDiscoveryDisabled};
    bool weak_host_send{};
    bool weak_host_receive{};
    bool ignore_default_routes{};
    bool advertise_default_route{};
    std::string sha256;
};

struct ComApartment final {
    ComApartment() noexcept : result(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {}
    ~ComApartment() {
        if (result == S_OK || result == S_FALSE) CoUninitialize();
    }
    [[nodiscard]] bool usable() const noexcept {
        return SUCCEEDED(result) || result == RPC_E_CHANGED_MODE;
    }
    HRESULT result{};
};

struct SharingConnection final {
    ComPtr<INetConnection> connection;
    ComPtr<INetSharingConfiguration> configuration;
    std::wstring name;
    std::string normalized_guid;
    bool sharing_enabled{};
    SHARINGCONNECTIONTYPE sharing_type{ICSSHARINGTYPE_PUBLIC};
};

bool is_link_local(std::uint32_t ipv4) noexcept {
    return (ipv4 & kLinkLocalMask) == kLinkLocalNetwork;
}

bool is_usable_unicast(std::uint32_t ipv4) noexcept {
    if (ipv4 == 0U || (ipv4 & 0xFF000000U) == 0x7F000000U) return false;
    return !is_link_local(ipv4);
}

std::string format_ipv4(std::uint32_t ipv4) {
    return std::to_string((ipv4 >> 24U) & 0xFFU) + "." +
        std::to_string((ipv4 >> 16U) & 0xFFU) + "." +
        std::to_string((ipv4 >> 8U) & 0xFFU) + "." +
        std::to_string(ipv4 & 0xFFU);
}

std::optional<std::uint32_t> parse_ipv4(std::string_view text) noexcept {
    std::array<unsigned, 4> octets{};
    std::size_t octet_index{};
    unsigned value{};
    bool has_digit{};
    for (const char character : text) {
        if (character >= '0' && character <= '9') {
            has_digit = true;
            value = value * 10U + static_cast<unsigned>(character - '0');
            if (value > 255U) return std::nullopt;
            continue;
        }
        if (character != '.' || !has_digit || octet_index >= 3U) {
            return std::nullopt;
        }
        octets[octet_index++] = value;
        value = 0U;
        has_digit = false;
    }
    if (!has_digit || octet_index != 3U) return std::nullopt;
    octets[3] = value;
    return (octets[0] << 24U) | (octets[1] << 16U) |
        (octets[2] << 8U) | octets[3];
}

bool is_usable_address(
    const HostNetworkIpv4AddressProfile& address) noexcept {
    const auto parsed = parse_ipv4(address.address);
    return parsed.has_value() && is_usable_unicast(*parsed);
}

bool is_preferred_usable_address(
    const HostNetworkIpv4AddressProfile& address) noexcept {
    return address.dad_state == static_cast<std::uint32_t>(IpDadStatePreferred) &&
        is_usable_address(address);
}

bool has_preexisting_static_usable_ipv4(
    const HostNetworkAdapterProfile& adapter) noexcept {
    return std::any_of(
        adapter.ipv4_addresses.begin(), adapter.ipv4_addresses.end(),
        [](const HostNetworkIpv4AddressProfile& address) {
            return is_usable_address(address) &&
                (address.prefix_origin ==
                     static_cast<std::uint32_t>(IpPrefixOriginManual) ||
                 address.suffix_origin ==
                     static_cast<std::uint32_t>(IpSuffixOriginManual));
        });
}

bool has_dhcp_assigned_usable_ipv4(
    const HostNetworkAdapterProfile& adapter) noexcept {
    return std::any_of(
        adapter.ipv4_addresses.begin(), adapter.ipv4_addresses.end(),
        [](const HostNetworkIpv4AddressProfile& address) {
            return is_preferred_usable_address(address) &&
                address.prefix_origin ==
                    static_cast<std::uint32_t>(IpPrefixOriginDhcp) &&
                address.suffix_origin ==
                    static_cast<std::uint32_t>(IpSuffixOriginDhcp);
        });
}

bool has_unclassified_usable_ipv4(
    const HostNetworkAdapterProfile& adapter) noexcept {
    if (!adapter.has_usable_ipv4) return false;
    if (adapter.has_ics_private_ipv4 || adapter.has_isolated_private_ipv4) {
        return false;
    }
    return !has_preexisting_static_usable_ipv4(adapter) &&
        !has_dhcp_assigned_usable_ipv4(adapter);
}

bool has_ipv4_gateway(const IP_ADAPTER_GATEWAY_ADDRESS_LH* gateway) noexcept {
    for (auto* current = gateway; current != nullptr; current = current->Next) {
        if (current->Address.lpSockaddr == nullptr ||
            current->Address.lpSockaddr->sa_family != AF_INET) continue;
        const auto* address = reinterpret_cast<const sockaddr_in*>(current->Address.lpSockaddr);
        if (address->sin_addr.s_addr != INADDR_ANY) return true;
    }
    return false;
}

std::string normalize_identifier(std::string value) {
    value.erase(std::remove_if(value.begin(), value.end(), [](char character) {
        return character == '{' || character == '}' || std::isspace(static_cast<unsigned char>(character)) != 0;
    }), value.end());
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

std::string narrow_ascii(std::wstring_view value) {
    std::string result;
    result.reserve(value.size());
    for (const wchar_t character : value) {
        result.push_back(character >= 0 && character <= 0x7f ? static_cast<char>(character) : '?');
    }
    return result;
}

std::string wide_to_utf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) return narrow_ascii(value);
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(
            CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
            result.data(), required, nullptr, nullptr) != required) {
        return narrow_ascii(value);
    }
    return result;
}

std::string console_bytes_to_utf8(std::string_view value) {
    if (value.empty()) return {};
    const int required = MultiByteToWideChar(
        CP_OEMCP, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (required <= 0) return std::string(value);
    std::wstring wide(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(
            CP_OEMCP, 0, value.data(), static_cast<int>(value.size()),
            wide.data(), required) != required) {
        return std::string(value);
    }
    return wide_to_utf8(wide);
}

std::string compact_process_output(std::string_view value) {
    std::string compact;
    compact.reserve(value.size());
    bool pending_space = false;
    for (const unsigned char character : value) {
        if (std::isspace(character) != 0) {
            pending_space = !compact.empty();
            continue;
        }
        if (pending_space) compact.push_back(' ');
        compact.push_back(static_cast<char>(character));
        pending_space = false;
    }
    return compact;
}

std::string format_win32_error(DWORD error) {
    wchar_t* message{};
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0, reinterpret_cast<wchar_t*>(&message), 0, nullptr);
    std::string result = "win32=" + std::to_string(error);
    if (length != 0U && message != nullptr) {
        const std::string text = compact_process_output(
            wide_to_utf8(std::wstring_view{message, length}));
        if (!text.empty()) result += " message=[" + text + "]";
    }
    if (message != nullptr) LocalFree(message);
    return result;
}

std::wstring take_bstr(BSTR value) {
    std::wstring result = value == nullptr ? std::wstring{} : std::wstring{value, SysStringLen(value)};
    SysFreeString(value);
    return result;
}

std::vector<HostNetworkAdapterProfile> enumerate_network_profiles() {
    std::vector<unsigned char> storage(16U * 1024U);
    ULONG size = static_cast<ULONG>(storage.size());
    constexpr ULONG address_flags =
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG result = GetAdaptersAddresses(
        AF_UNSPEC, address_flags,
        nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()), &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        storage.resize(size);
        result = GetAdaptersAddresses(
            AF_UNSPEC, address_flags,
            nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()), &size);
    }
    std::vector<HostNetworkAdapterProfile> profiles;
    for (auto* adapter = result == NO_ERROR
             ? reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()) : nullptr;
         adapter != nullptr; adapter = adapter->Next) {
        HostNetworkAdapterProfile profile{};
        profile.connection_name = adapter->FriendlyName == nullptr
            ? std::wstring{} : std::wstring{adapter->FriendlyName};
        profile.adapter_id = adapter->AdapterName == nullptr
            ? std::string{} : normalize_identifier(adapter->AdapterName);
        profile.interface_index = adapter->IfIndex;
        profile.description = adapter->Description == nullptr
            ? std::wstring{} : std::wstring{adapter->Description};
        MIB_IF_ROW2 interface_row{};
        interface_row.InterfaceLuid = adapter->Luid;
        const bool interface_row_available =
            GetIfEntry2(&interface_row) == NO_ERROR;
        profile.hardware_interface = interface_row_available &&
            interface_row.InterfaceAndOperStatusFlags.HardwareInterface != FALSE;
        profile.connector_present = interface_row_available &&
            interface_row.InterfaceAndOperStatusFlags.ConnectorPresent != FALSE;
        profile.filter_interface = interface_row_available &&
            interface_row.InterfaceAndOperStatusFlags.FilterInterface != FALSE;
        profile.endpoint_interface = interface_row_available &&
            interface_row.InterfaceAndOperStatusFlags.EndPointInterface != FALSE;
        if (interface_row_available && interface_row.Description[0] != L'\0') {
            profile.description = interface_row.Description;
        }
        profile.virtual_or_loopback =
            host_adapter_has_virtual_or_loopback_identity(
                HostAdapterIdentityFacts{
                    .hardware_interface = profile.hardware_interface,
                    .connector_present = profile.connector_present,
                    .filter_interface = profile.filter_interface,
                    .endpoint_interface = profile.endpoint_interface,
                    .software_loopback_or_tunnel =
                        adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
                        adapter->IfType == IF_TYPE_TUNNEL,
                    .connection_name = profile.connection_name,
                    .description = profile.description,
                });
        profile.operational = adapter->OperStatus == IfOperStatusUp;
        profile.has_default_gateway = has_ipv4_gateway(adapter->FirstGatewayAddress);
        profile.dhcp_enabled = (adapter->Flags & IP_ADAPTER_DHCP_ENABLED) != 0;
        for (auto* gateway = adapter->FirstGatewayAddress;
             gateway != nullptr; gateway = gateway->Next) {
            if (gateway->Address.lpSockaddr == nullptr ||
                gateway->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }
            const auto* address =
                reinterpret_cast<const sockaddr_in*>(gateway->Address.lpSockaddr);
            const std::uint32_t ipv4 = ntohl(address->sin_addr.s_addr);
            if (ipv4 != 0U) profile.ipv4_gateways.push_back(format_ipv4(ipv4));
        }
        if (adapter->IfType == IF_TYPE_ETHERNET_CSMACD) {
            profile.transport = HostAdapterTransport::ethernet;
        }
        for (auto* unicast = adapter->FirstUnicastAddress;
             unicast != nullptr; unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == nullptr ||
                unicast->Address.lpSockaddr->sa_family != AF_INET) continue;
            const auto* address = reinterpret_cast<const sockaddr_in*>(unicast->Address.lpSockaddr);
            const std::uint32_t ipv4 = ntohl(address->sin_addr.s_addr);
            const bool preferred = unicast->DadState == IpDadStatePreferred;
            HostNetworkIpv4AddressProfile address_profile{
                .address = format_ipv4(ipv4),
                .prefix_length = unicast->OnLinkPrefixLength,
                .prefix_origin =
                    static_cast<std::uint32_t>(unicast->PrefixOrigin),
                .suffix_origin =
                    static_cast<std::uint32_t>(unicast->SuffixOrigin),
                .dad_state = static_cast<std::uint32_t>(unicast->DadState),
            };
            MIB_UNICASTIPADDRESS_ROW address_row{};
            InitializeUnicastIpAddressEntry(&address_row);
            address_row.InterfaceIndex = adapter->IfIndex;
            address_row.Address.Ipv4 = *address;
            if (GetUnicastIpAddressEntry(&address_row) == NO_ERROR) {
                address_profile.skip_as_source =
                    address_row.SkipAsSource != FALSE;
            }
            profile.ipv4_addresses.push_back(std::move(address_profile));
            profile.has_link_local_ipv4 =
                profile.has_link_local_ipv4 || (preferred && is_link_local(ipv4));
            profile.has_usable_ipv4 =
                profile.has_usable_ipv4 || (preferred && is_usable_unicast(ipv4));
            profile.has_ics_private_ipv4 =
                profile.has_ics_private_ipv4 ||
                (preferred && ipv4 == kIcsPrivateAddress);
            profile.has_isolated_private_ipv4 =
                profile.has_isolated_private_ipv4 ||
                (preferred && ipv4 == kIsolatedPrivateAddress &&
                 unicast->OnLinkPrefixLength == kIsolatedPrivatePrefixLength);
        }
        profiles.push_back(std::move(profile));
    }
    // GetAdaptersAddresses omits unicast addresses whose SkipAsSource flag is
    // set, and the transient isolated 10.57.23.1 is created exactly that way.
    // Merge the raw unicast table so already-ready detection and conflict
    // analysis see every address an interface really carries. (E-system
    // acceptance 2026-07-25: the transient address was invisible to GAA, so
    // retries could not recognize the link as already provisioned.)
    MIB_UNICASTIPADDRESS_TABLE* unicast_table = nullptr;
    if (GetUnicastIpAddressTable(AF_INET, &unicast_table) == NO_ERROR &&
        unicast_table != nullptr) {
        for (ULONG row_index = 0; row_index < unicast_table->NumEntries; ++row_index) {
            const MIB_UNICASTIPADDRESS_ROW& row = unicast_table->Table[row_index];
            if (row.Address.si_family != AF_INET) continue;
            for (auto& profile : profiles) {
                if (profile.interface_index != row.InterfaceIndex) continue;
                const std::uint32_t ipv4 = ntohl(row.Address.Ipv4.sin_addr.s_addr);
                const std::string text = format_ipv4(ipv4);
                const bool already_listed = std::any_of(
                    profile.ipv4_addresses.begin(), profile.ipv4_addresses.end(),
                    [&](const HostNetworkIpv4AddressProfile& address) {
                        return address.address == text;
                    });
                if (already_listed) break;
                const bool preferred = row.DadState == IpDadStatePreferred;
                profile.ipv4_addresses.push_back(HostNetworkIpv4AddressProfile{
                    .address = text,
                    .prefix_length = row.OnLinkPrefixLength,
                    .prefix_origin = static_cast<std::uint32_t>(row.PrefixOrigin),
                    .suffix_origin = static_cast<std::uint32_t>(row.SuffixOrigin),
                    .dad_state = static_cast<std::uint32_t>(row.DadState),
                    .skip_as_source = row.SkipAsSource != FALSE,
                });
                profile.has_link_local_ipv4 =
                    profile.has_link_local_ipv4 || (preferred && is_link_local(ipv4));
                profile.has_usable_ipv4 =
                    profile.has_usable_ipv4 || (preferred && is_usable_unicast(ipv4));
                profile.has_ics_private_ipv4 =
                    profile.has_ics_private_ipv4 ||
                    (preferred && ipv4 == kIcsPrivateAddress);
                profile.has_isolated_private_ipv4 =
                    profile.has_isolated_private_ipv4 ||
                    (preferred && ipv4 == kIsolatedPrivateAddress &&
                     row.OnLinkPrefixLength == kIsolatedPrivatePrefixLength);
                break;
            }
        }
        FreeMibTable(unicast_table);
    }
    return profiles;
}

bool process_is_elevated() noexcept {
    HANDLE token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD returned{};
    const bool succeeded = GetTokenInformation(
        token, TokenElevation, &elevation, sizeof(elevation), &returned) != FALSE;
    CloseHandle(token);
    return succeeded && elevation.TokenIsElevated != 0;
}

std::string format_hresult(HRESULT result) {
    std::ostringstream value;
    value << "hresult=0x" << std::hex << static_cast<unsigned long>(result);
    return value.str();
}

bool same_connection(const SharingConnection& connection,
                     const HostNetworkAdapterProfile& profile) {
    if (!profile.adapter_id.empty() && connection.normalized_guid == profile.adapter_id) return true;
    return !profile.connection_name.empty() && !connection.name.empty() &&
        _wcsicmp(connection.name.c_str(), profile.connection_name.c_str()) == 0;
}

HRESULT enumerate_sharing_connections(
    INetSharingManager* manager, std::vector<SharingConnection>& destination) {
    if (manager == nullptr) return E_POINTER;
    ComPtr<INetSharingEveryConnectionCollection> collection;
    HRESULT result = manager->get_EnumEveryConnection(&collection);
    if (FAILED(result) || collection == nullptr) return FAILED(result) ? result : E_NOINTERFACE;
    ComPtr<IUnknown> unknown_enumerator;
    result = collection->get__NewEnum(&unknown_enumerator);
    if (FAILED(result) || unknown_enumerator == nullptr) return FAILED(result) ? result : E_NOINTERFACE;
    ComPtr<IEnumVARIANT> enumerator;
    result = unknown_enumerator.As(&enumerator);
    if (FAILED(result) || enumerator == nullptr) return FAILED(result) ? result : E_NOINTERFACE;

    for (;;) {
        VARIANT item;
        VariantInit(&item);
        ULONG fetched{};
        result = enumerator->Next(1U, &item, &fetched);
        if (result == S_FALSE || fetched == 0U) {
            VariantClear(&item);
            return S_OK;
        }
        if (FAILED(result)) {
            VariantClear(&item);
            return result;
        }
        ComPtr<INetConnection> connection;
        if (item.vt == VT_UNKNOWN && item.punkVal != nullptr) {
            item.punkVal->QueryInterface(IID_PPV_ARGS(&connection));
        } else if (item.vt == VT_DISPATCH && item.pdispVal != nullptr) {
            item.pdispVal->QueryInterface(IID_PPV_ARGS(&connection));
        }
        if (connection != nullptr) {
            ComPtr<INetConnectionProps> properties;
            ComPtr<INetSharingConfiguration> configuration;
            if (SUCCEEDED(manager->get_NetConnectionProps(connection.Get(), &properties)) &&
                properties != nullptr &&
                SUCCEEDED(manager->get_INetSharingConfigurationForINetConnection(
                    connection.Get(), &configuration)) && configuration != nullptr) {
                BSTR name{};
                BSTR guid{};
                properties->get_Name(&name);
                properties->get_Guid(&guid);
                SharingConnection entry{};
                entry.connection = connection;
                entry.configuration = configuration;
                entry.name = take_bstr(name);
                entry.normalized_guid = normalize_identifier(narrow_ascii(take_bstr(guid)));
                VARIANT_BOOL enabled{VARIANT_FALSE};
                if (SUCCEEDED(configuration->get_SharingEnabled(&enabled)) && enabled == VARIANT_TRUE) {
                    entry.sharing_enabled = true;
                    configuration->get_SharingConnectionType(&entry.sharing_type);
                }
                destination.push_back(std::move(entry));
            }
        }
        VariantClear(&item);
    }
}

bool adapter_has_isolated_address(std::string_view adapter_id) {
    const auto profiles = enumerate_network_profiles();
    const auto found = std::find_if(profiles.begin(), profiles.end(), [&](const auto& profile) {
        return profile.adapter_id == adapter_id;
    });
    return found != profiles.end() && found->has_isolated_private_ipv4 &&
        !found->has_default_gateway;
}

bool disable_selected_private_sharing(const HostNetworkAdapterProfile& downstream,
                                      std::string& detail) {
    if (!downstream.has_ics_private_ipv4) return true;
    ComApartment apartment;
    if (!apartment.usable()) {
        detail = "com_initialization_failed " + format_hresult(apartment.result);
        return false;
    }
    ComPtr<INetSharingManager> manager;
    HRESULT result = CoCreateInstance(
        CLSID_NetSharingManager, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&manager));
    if (FAILED(result) || manager == nullptr) {
        detail = "ics_manager_unavailable " + format_hresult(result);
        return false;
    }
    std::vector<SharingConnection> connections;
    result = enumerate_sharing_connections(manager.Get(), connections);
    if (FAILED(result)) {
        detail = "ics_connection_enumeration_failed " + format_hresult(result);
        return false;
    }
    const auto connection = std::find_if(connections.begin(), connections.end(), [&](const auto& entry) {
        return same_connection(entry, downstream);
    });
    if (connection == connections.end()) {
        detail = "ics_downstream_connection_not_found";
        return false;
    }
    if (connection->sharing_enabled && FAILED(connection->configuration->DisableSharing())) {
        detail = "disable_private_ics_failed";
        return false;
    }
    return true;
}

bool enable_selected_private_sharing(const HostNetworkAdapterProfile& downstream,
                                     std::string& detail) {
    ComApartment apartment;
    if (!apartment.usable()) {
        detail = "com_initialization_failed " + format_hresult(apartment.result);
        return false;
    }
    ComPtr<INetSharingManager> manager;
    HRESULT result = CoCreateInstance(
        CLSID_NetSharingManager, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&manager));
    if (FAILED(result) || manager == nullptr) {
        detail = "ics_manager_unavailable " + format_hresult(result);
        return false;
    }
    std::vector<SharingConnection> connections;
    result = enumerate_sharing_connections(manager.Get(), connections);
    if (FAILED(result)) {
        detail = "ics_connection_enumeration_failed " + format_hresult(result);
        return false;
    }
    const auto connection = std::find_if(connections.begin(), connections.end(), [&](const auto& entry) {
        return same_connection(entry, downstream);
    });
    if (connection == connections.end()) {
        detail = "ics_downstream_connection_not_found";
        return false;
    }
    if (connection->sharing_enabled) {
        if (connection->sharing_type == ICSSHARINGTYPE_PRIVATE) return true;
        detail = "ics_downstream_has_unexpected_public_sharing";
        return false;
    }
    if (FAILED(connection->configuration->EnableSharing(ICSSHARINGTYPE_PRIVATE))) {
        detail = "restore_private_ics_failed";
        return false;
    }
    return true;
}

class OwnedHandle final {
public:
    OwnedHandle() = default;
    explicit OwnedHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~OwnedHandle() { reset(); }
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] HANDLE* put() noexcept {
        reset();
        return &handle_;
    }
    [[nodiscard]] bool valid() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }
    void reset(HANDLE replacement = nullptr) noexcept {
        if (valid()) CloseHandle(handle_);
        handle_ = replacement;
    }

private:
    HANDLE handle_{};
};

struct NetshProcessContext final {
    OwnedHandle output_read;
    OwnedHandle output_write;
    OwnedHandle null_input;
    OwnedHandle worker_job;
    OwnedHandle process;
    OwnedHandle thread;
    std::string captured_output;
};

void drain_netsh_output(NetshProcessContext& context) {
    for (;;) {
        DWORD available{};
        if (!PeekNamedPipe(
                context.output_read.get(), nullptr, 0U, nullptr, &available, nullptr) ||
            available == 0U) {
            return;
        }
        std::array<char, 1024U> buffer{};
        const std::size_t remaining =
            context.captured_output.size() < kMaximumNetshOutputBytes
            ? kMaximumNetshOutputBytes - context.captured_output.size() : 0U;
        std::size_t requested_size =
            (std::min)(static_cast<std::size_t>(available), buffer.size());
        if (remaining != 0U) requested_size = (std::min)(requested_size, remaining);
        DWORD read{};
        if (!ReadFile(
                context.output_read.get(), buffer.data(),
                static_cast<DWORD>(requested_size), &read, nullptr) || read == 0U) {
            return;
        }
        if (remaining != 0U) context.captured_output.append(buffer.data(), read);
    }
}

bool prepare_netsh_process(
    const std::wstring& executable,
    std::wstring& command_line,
    NetshProcessContext& context,
    std::string& detail) {
    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    if (!CreatePipe(context.output_read.put(), context.output_write.put(), &security, 0U)) {
        detail = "netsh_output_pipe_create_failed " + format_win32_error(GetLastError());
        return false;
    }
    if (!SetHandleInformation(context.output_read.get(), HANDLE_FLAG_INHERIT, 0U)) {
        detail = "netsh_output_pipe_configure_failed " + format_win32_error(GetLastError());
        return false;
    }
    context.null_input.reset(CreateFileW(
        L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!context.null_input.valid()) {
        detail = "netsh_null_input_open_failed " + format_win32_error(GetLastError());
        return false;
    }
    context.worker_job.reset(CreateJobObjectW(nullptr, nullptr));
    if (!context.worker_job.valid()) {
        detail = "netsh_job_create_failed " + format_win32_error(GetLastError());
        return false;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(
            context.worker_job.get(), JobObjectExtendedLimitInformation,
            &limits, sizeof(limits))) {
        detail = "netsh_job_configure_failed " + format_win32_error(GetLastError());
        return false;
    }
    SIZE_T attribute_bytes{};
    InitializeProcThreadAttributeList(nullptr, 1U, 0U, &attribute_bytes);
    if (attribute_bytes == 0U) {
        detail = "netsh_attribute_size_failed " + format_win32_error(GetLastError());
        return false;
    }
    std::vector<unsigned char> attribute_storage(attribute_bytes);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        attribute_storage.data());
    if (!InitializeProcThreadAttributeList(attributes, 1U, 0U, &attribute_bytes)) {
        detail = "netsh_attribute_initialize_failed " +
            format_win32_error(GetLastError());
        return false;
    }
    std::array<HANDLE, 2U> inherited_handles{
        context.null_input.get(), context.output_write.get()};
    if (!UpdateProcThreadAttribute(
            attributes, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited_handles.data(),
            sizeof(inherited_handles), nullptr, nullptr)) {
        const DWORD attribute_error = GetLastError();
        DeleteProcThreadAttributeList(attributes);
        detail = "netsh_attribute_update_failed " +
            format_win32_error(attribute_error);
        return false;
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = context.null_input.get();
    startup.StartupInfo.hStdOutput = context.output_write.get();
    startup.StartupInfo.hStdError = context.output_write.get();
    PROCESS_INFORMATION process{};
    const BOOL launched = CreateProcessW(
            executable.c_str(), command_line.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
            nullptr, nullptr, &startup.StartupInfo, &process);
    const DWORD launch_error = launched ? ERROR_SUCCESS : GetLastError();
    DeleteProcThreadAttributeList(attributes);
    if (!launched) {
        detail = "netsh_launch_failed " + format_win32_error(launch_error);
        return false;
    }
    context.process.reset(process.hProcess);
    context.thread.reset(process.hThread);
    context.null_input.reset();
    context.output_write.reset();
    context.captured_output.reserve(1024U);
    return true;
}

bool start_netsh_process(NetshProcessContext& context, std::string& detail) {
    if (!AssignProcessToJobObject(context.worker_job.get(), context.process.get())) {
        const DWORD error = GetLastError();
        TerminateProcess(context.process.get(), ERROR_CANCELLED);
        WaitForSingleObject(context.process.get(), kNetshTerminationGraceMs);
        drain_netsh_output(context);
        detail = "netsh_job_assign_failed " + format_win32_error(error);
        return false;
    }
    if (ResumeThread(context.thread.get()) == static_cast<DWORD>(-1)) {
        const DWORD error = GetLastError();
        TerminateProcess(context.process.get(), ERROR_CANCELLED);
        WaitForSingleObject(context.process.get(), kNetshTerminationGraceMs);
        drain_netsh_output(context);
        detail = "netsh_resume_failed " + format_win32_error(error);
        return false;
    }
    context.thread.reset();
    return true;
}

DWORD wait_for_netsh_process(NetshProcessContext& context, std::string& detail) {
    const ULONGLONG deadline = GetTickCount64() + kNetshTimeoutMs;
    DWORD wait_result = WAIT_TIMEOUT;
    while (GetTickCount64() < deadline) {
        drain_netsh_output(context);
        const DWORD remaining = static_cast<DWORD>((std::min)(
            deadline - GetTickCount64(), static_cast<ULONGLONG>(50U)));
        wait_result = WaitForSingleObject(context.process.get(), remaining);
        if (wait_result != WAIT_TIMEOUT) break;
    }
    if (wait_result == WAIT_TIMEOUT) {
        TerminateProcess(context.process.get(), ERROR_TIMEOUT);
        WaitForSingleObject(context.process.get(), kNetshTerminationGraceMs);
        detail = "netsh_timeout";
    } else if (wait_result != WAIT_OBJECT_0) {
        detail = "netsh_wait_failed " + format_win32_error(GetLastError());
    }
    drain_netsh_output(context);
    return wait_result;
}

bool run_netsh(std::wstring_view arguments, std::string& detail) {
    std::wstring system_directory(MAX_PATH, L'\0');
    const UINT length = GetSystemDirectoryW(system_directory.data(),
                                             static_cast<UINT>(system_directory.size()));
    if (length == 0U || length >= system_directory.size()) {
        detail = "system_directory_unavailable win32=" + std::to_string(GetLastError());
        return false;
    }
    system_directory.resize(length);
    const std::wstring executable = system_directory + L"\\netsh.exe";
    std::wstring command_line = L"\"" + executable + L"\" " + std::wstring(arguments);
    NetshProcessContext context{};
    if (!prepare_netsh_process(executable, command_line, context, detail) ||
        !start_netsh_process(context, detail)) {
        return false;
    }
    const DWORD wait_result = wait_for_netsh_process(context, detail);
    DWORD exit_code = ERROR_GEN_FAILURE;
    if (wait_result == WAIT_OBJECT_0) {
        GetExitCodeProcess(context.process.get(), &exit_code);
    }
    if (wait_result != WAIT_OBJECT_0 || exit_code != ERROR_SUCCESS) {
        const std::string output = compact_process_output(
            console_bytes_to_utf8(context.captured_output));
        if (detail.empty()) detail = "netsh_failed exit_code=" + std::to_string(exit_code);
        detail += " command=[" + wide_to_utf8(arguments) + "]";
        if (!output.empty()) detail += " output=[" + output + "]";
        return false;
    }
    detail.clear();
    return true;
}

bool run_netsh_for_adapter(
    const HostNetworkAdapterProfile& adapter,
    std::wstring_view argument_prefix,
    std::wstring_view argument_suffix,
    std::string& detail) {
    std::string alias_failure;
    if (!adapter.connection_name.empty() &&
        adapter.connection_name.find(L'"') == std::wstring::npos) {
        const std::wstring alias_arguments = std::wstring(argument_prefix) + L"\"" +
            adapter.connection_name + L"\"" + std::wstring(argument_suffix);
        if (run_netsh(alias_arguments, alias_failure)) {
            detail.clear();
            return true;
        }
    }

    std::string index_failure;
    const std::wstring index_arguments = std::wstring(argument_prefix) +
        std::to_wstring(adapter.interface_index) + std::wstring(argument_suffix);
    if (run_netsh(index_arguments, index_failure)) {
        detail.clear();
        return true;
    }
    detail = alias_failure.empty()
        ? "netsh_index_attempt={" + index_failure + "}"
        : "netsh_alias_attempt={" + alias_failure +
            "} netsh_index_attempt={" + index_failure + "}";
    return false;
}

void initialize_isolated_unicast_row(
    std::uint32_t interface_index, MIB_UNICASTIPADDRESS_ROW& row) noexcept {
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceIndex = interface_index;
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr.s_addr = htonl(kIsolatedPrivateAddress);
    row.OnLinkPrefixLength = kIsolatedPrivatePrefixLength;
}

bool delete_transient_isolated_address(
    std::uint32_t interface_index, std::string& detail);

bool isolated_address_is_preferred(
    std::uint32_t interface_index, std::string& detail) {
    MIB_UNICASTIPADDRESS_ROW address{};
    initialize_isolated_unicast_row(interface_index, address);
    const DWORD found = GetUnicastIpAddressEntry(&address);
    if (found != NO_ERROR) {
        detail = "ip_helper_address_status_failed " + format_win32_error(found);
        return false;
    }
    if (address.DadState == IpDadStatePreferred) {
        detail.clear();
        return true;
    }
    detail = "ip_helper_address_not_preferred dad_state=" +
        std::to_string(static_cast<unsigned>(address.DadState));
    return false;
}

bool mark_isolated_address_skip_as_source(
    std::uint32_t interface_index, std::string& detail) {
    // Contract change (E-system evidence): the isolated address must NOT be
    // marked skip-as-source. On DHCP-enabled adapters running build 22621 the
    // stack purges skip-as-source addresses within ~1s, which killed every
    // DHCP bind with 10049; the production working configuration has always
    // been skip_as_source=false. The link is gateway-less and DNS-less, so
    // source-address selection never needed the flag. Keep this as an
    // explicit normalization to FALSE for older persistent configurations.
    MIB_UNICASTIPADDRESS_ROW address{};
    initialize_isolated_unicast_row(interface_index, address);
    const DWORD read_result = GetUnicastIpAddressEntry(&address);
    if (read_result != NO_ERROR) {
        detail = "ip_helper_skip_as_source_read_failed " +
            format_win32_error(read_result);
        return false;
    }
    if (address.SkipAsSource == FALSE) {
        detail.clear();
        return true;
    }
    address.SkipAsSource = FALSE;
    const DWORD update_result = SetUnicastIpAddressEntry(&address);
    if (update_result != NO_ERROR) {
        detail = "ip_helper_skip_as_source_update_failed " +
            format_win32_error(update_result);
        return false;
    }
    detail.clear();
    return true;
}

bool wait_for_isolated_address_preferred(
    std::uint32_t interface_index, std::string& detail) {
    const auto deadline = std::chrono::steady_clock::now() + kAddressDadTimeout;
    while (std::chrono::steady_clock::now() < deadline) {
        MIB_UNICASTIPADDRESS_ROW address{};
        initialize_isolated_unicast_row(interface_index, address);
        const DWORD found = GetUnicastIpAddressEntry(&address);
        if (found != NO_ERROR) {
            detail = "ip_helper_address_status_failed " + format_win32_error(found);
            return false;
        }
        if (address.DadState == IpDadStatePreferred) {
            detail.clear();
            return true;
        }
        if (address.DadState != IpDadStateTentative) {
            detail = "ip_helper_address_dad_failed dad_state=" +
                std::to_string(static_cast<unsigned>(address.DadState));
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    detail = "ip_helper_address_dad_timeout";
    return false;
}

TransientAddressCreateStatus create_transient_isolated_address(
    std::uint32_t interface_index, std::string& detail) {
    MIB_UNICASTIPADDRESS_ROW existing{};
    initialize_isolated_unicast_row(interface_index, existing);
    const DWORD existing_result = GetUnicastIpAddressEntry(&existing);
    if (existing_result == NO_ERROR) {
        // A previous failed attempt or a crashed run may have left our own
        // dedicated isolated address behind: no rollback path removes the
        // transient variant, so every retry would otherwise fail here
        // permanently. The address is unique to this direct link, so adopt
        // it and re-validate instead of declaring an ownership conflict.
        // (E-system acceptance 2026-07-25: retry attempts 2/3 were poisoned
        // by exactly this leftover from attempt 1.)
        if (!wait_for_isolated_address_preferred(interface_index, detail)) {
            return TransientAddressCreateStatus::validation_failed;
        }
        detail.clear();
        return TransientAddressCreateStatus::created;
    }
    if (existing_result != ERROR_NOT_FOUND &&
        existing_result != ERROR_FILE_NOT_FOUND) {
        detail = "ip_helper_address_probe_failed " + format_win32_error(existing_result);
        return TransientAddressCreateStatus::failed;
    }

    MIB_UNICASTIPADDRESS_ROW address{};
    initialize_isolated_unicast_row(interface_index, address);
    address.PrefixOrigin = IpPrefixOriginManual;
    address.SuffixOrigin = IpSuffixOriginManual;
    address.ValidLifetime = 0xFFFFFFFFU;
    address.PreferredLifetime = 0xFFFFFFFFU;
    address.DadState = IpDadStatePreferred;
    // SkipAsSource must stay FALSE on the isolated link. Marking the transient
    // address skip-as-source gets it purged by the stack on DHCP-enabled
    // adapters (E-system build 22621 evidence: the address vanished within
    // ~1s of creation and every DHCP bind failed 10049), while the unmarked
    // form survived the full mobile wait on the same machine. The link has no
    // gateway and no DNS, so source-address selection is unaffected anyway.
    address.SkipAsSource = FALSE;
    const DWORD created = CreateUnicastIpAddressEntry(&address);
    if (created == ERROR_ALREADY_EXISTS || created == ERROR_OBJECT_ALREADY_EXISTS) {
        detail = "ip_helper_address_ownership_conflict " + format_win32_error(created);
        return TransientAddressCreateStatus::ownership_conflict;
    }
    if (created != NO_ERROR) {
        detail = "ip_helper_address_create_failed " + format_win32_error(created);
        return TransientAddressCreateStatus::failed;
    }
    if (!wait_for_isolated_address_preferred(interface_index, detail)) {
        const std::string dad_failure = detail;
        std::string cleanup_detail;
        if (!delete_transient_isolated_address(interface_index, cleanup_detail)) {
            detail = dad_failure + " cleanup={" + cleanup_detail + "}";
        }
        return TransientAddressCreateStatus::validation_failed;
    }
    detail.clear();
    return TransientAddressCreateStatus::created;
}

bool delete_transient_isolated_address(
    std::uint32_t interface_index, std::string& detail) {
    MIB_UNICASTIPADDRESS_ROW address{};
    initialize_isolated_unicast_row(interface_index, address);
    const DWORD found = GetUnicastIpAddressEntry(&address);
    if (found == ERROR_NOT_FOUND || found == ERROR_FILE_NOT_FOUND) {
        detail.clear();
        return true;
    }
    if (found != NO_ERROR) {
        detail = "ip_helper_address_probe_failed " + format_win32_error(found);
        return false;
    }
    const DWORD removed = DeleteUnicastIpAddressEntry(&address);
    if (removed != NO_ERROR && removed != ERROR_NOT_FOUND &&
        removed != ERROR_FILE_NOT_FOUND) {
        detail = "ip_helper_address_delete_failed " + format_win32_error(removed);
        return false;
    }
    detail.clear();
    return true;
}

}  // namespace

std::string describe_host_isolated_subnet_state() noexcept {
    MIB_UNICASTIPADDRESS_TABLE* table = nullptr;
    if (GetUnicastIpAddressTable(AF_INET, &table) != NO_ERROR || table == nullptr) {
        return "probe_failed";
    }
    std::string state;
    constexpr std::uint32_t kIsolatedNetworkMask = 0xFFFF0000U;   // 10.57.0.0/16
    constexpr std::uint32_t kIsolatedNetwork = 0x0A390000U;
    for (ULONG index = 0; index < table->NumEntries; ++index) {
        const MIB_UNICASTIPADDRESS_ROW& row = table->Table[index];
        if (row.Address.si_family != AF_INET) continue;
        const std::uint32_t ipv4 = ntohl(row.Address.Ipv4.sin_addr.s_addr);
        if ((ipv4 & kIsolatedNetworkMask) != kIsolatedNetwork) continue;
        if (!state.empty()) state += " | ";
        state += format_ipv4(ipv4) + "@if" + std::to_string(row.InterfaceIndex) +
            " dad=" + std::to_string(static_cast<unsigned>(row.DadState)) +
            " skip=" + std::to_string(row.SkipAsSource != FALSE ? 1 : 0);
    }
    FreeMibTable(table);
    return state.empty() ? std::string{"none"} : state;
}

std::string describe_host_ipv4_unicast_table() noexcept {
    MIB_UNICASTIPADDRESS_TABLE* table = nullptr;
    const DWORD status = GetUnicastIpAddressTable(AF_INET, &table);
    if (status != NO_ERROR || table == nullptr) {
        return "probe_failed " + format_win32_error(status);
    }
    std::ostringstream detail;
    detail << "rows=" << table->NumEntries << " ipv4=[";
    for (ULONG index = 0; index < table->NumEntries; ++index) {
        const MIB_UNICASTIPADDRESS_ROW& row = table->Table[index];
        if (row.Address.si_family != AF_INET) continue;
        if (index != 0U) detail << ';';
        const std::uint32_t ipv4 = ntohl(row.Address.Ipv4.sin_addr.s_addr);
        detail << "{address=" << format_ipv4(ipv4)
               << " ifindex=" << row.InterfaceIndex
               << " prefix=" << static_cast<unsigned>(row.OnLinkPrefixLength)
               << " dad=" << static_cast<unsigned>(row.DadState)
               << " skip_as_source="
               << (row.SkipAsSource != FALSE ? "true" : "false")
               << " prefix_origin=" << static_cast<unsigned>(row.PrefixOrigin)
               << " suffix_origin=" << static_cast<unsigned>(row.SuffixOrigin)
               << " valid_lifetime=" << row.ValidLifetime
               << " preferred_lifetime=" << row.PreferredLifetime
               << '}';
    }
    detail << ']';
    FreeMibTable(table);
    return detail.str();
}

void set_host_direct_link_prefer_persistent_backend(bool prefer) noexcept {
    g_prefer_persistent_address_backend.store(prefer, std::memory_order_relaxed);
}

namespace {

bool read_ipv4_interface(
    std::uint32_t interface_index, MIB_IPINTERFACE_ROW& row, std::string& detail) {
    InitializeIpInterfaceEntry(&row);
    row.Family = AF_INET;
    row.InterfaceIndex = interface_index;
    const DWORD result = GetIpInterfaceEntry(&row);
    if (result != NO_ERROR) {
        detail = "ip_helper_interface_read_failed " + format_win32_error(result);
        return false;
    }
    return true;
}

bool apply_isolated_interface_policy(
    std::uint32_t interface_index, std::string& detail) {
    MIB_IPINTERFACE_ROW row{};
    if (!read_ipv4_interface(interface_index, row, detail)) return false;
    row.ForwardingEnabled = FALSE;
    row.AdvertisingEnabled = FALSE;
    row.NlMtu = 1500U;
    row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    row.WeakHostSend = FALSE;
    row.WeakHostReceive = FALSE;
    row.DisableDefaultRoutes = TRUE;
    row.AdvertiseDefaultRoute = FALSE;
    const DWORD result = SetIpInterfaceEntry(&row);
    if (result != NO_ERROR) {
        detail = "ip_helper_interface_policy_failed " + format_win32_error(result);
        return false;
    }
    detail.clear();
    return true;
}

bool apply_isolated_interface_policy_with_fallback(
    const HostNetworkAdapterProfile& downstream, std::string& detail) {
    std::string native_detail;
    if (apply_isolated_interface_policy(downstream.interface_index, native_detail)) {
        detail.clear();
        return true;
    }
    std::string netsh_detail;
    if (run_netsh_for_adapter(
            downstream, L"interface ipv4 set interface interface=",
            L" forwarding=disabled advertise=disabled mtu=1500"
            L" routerdiscovery=disabled weakhostsend=disabled"
            L" weakhostreceive=disabled ignoredefaultroutes=enabled"
            L" advertisedefaultroute=disabled store=persistent",
            netsh_detail)) {
        detail.clear();
        return true;
    }
    detail = "ip_helper_attempt={" + native_detail +
        "} netsh_fallback={" + netsh_detail + "}";
    return false;
}

bool restore_interface_policy(
    const HostDirectLinkChangeSnapshot& snapshot,
    std::uint32_t current_interface_index,
    std::string& detail) {
    MIB_IPINTERFACE_ROW row{};
    if (!read_ipv4_interface(current_interface_index, row, detail)) return false;
    row.ForwardingEnabled = snapshot.forwarding_enabled ? TRUE : FALSE;
    row.AdvertisingEnabled = snapshot.advertising_enabled ? TRUE : FALSE;
    row.NlMtu = snapshot.mtu;
    row.RouterDiscoveryBehavior = snapshot.router_discovery;
    row.WeakHostSend = snapshot.weak_host_send ? TRUE : FALSE;
    row.WeakHostReceive = snapshot.weak_host_receive ? TRUE : FALSE;
    row.DisableDefaultRoutes = snapshot.ignore_default_routes ? TRUE : FALSE;
    row.AdvertiseDefaultRoute = snapshot.advertise_default_route ? TRUE : FALSE;
    const DWORD result = SetIpInterfaceEntry(&row);
    if (result != NO_ERROR) {
        detail = "ip_helper_interface_restore_failed " + format_win32_error(result);
        return false;
    }
    detail.clear();
    return true;
}

std::filesystem::path direct_link_snapshot_path() {
    PWSTR known_folder{};
    if (SUCCEEDED(SHGetKnownFolderPath(
            FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &known_folder)) &&
        known_folder != nullptr && *known_folder != L'\0') {
        const std::filesystem::path path = std::filesystem::path(known_folder) /
            "VisionForge" / "DualMachine" / kSnapshotFileName;
        CoTaskMemFree(known_folder);
        return path;
    }
    if (known_folder != nullptr) CoTaskMemFree(known_folder);
    wchar_t* local_app_data{};
    std::size_t local_app_data_length{};
    const errno_t environment_result = _wdupenv_s(
        &local_app_data, &local_app_data_length, L"LOCALAPPDATA");
    if (environment_result != 0 || local_app_data == nullptr ||
        local_app_data_length <= 1U) {
        std::free(local_app_data);
        return {};
    }
    const std::filesystem::path path = std::filesystem::path(local_app_data) /
        "VisionForge" / "DualMachine" / kSnapshotFileName;
    std::free(local_app_data);
    return path;
}

std::string sha256_hex(std::string_view value) {
    HCRYPTPROV provider{};
    HCRYPTHASH hash{};
    std::array<BYTE, 32> digest{};
    DWORD digest_size = static_cast<DWORD>(digest.size());
    if (!CryptAcquireContextW(
            &provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) ||
        !CryptHashData(
            hash, reinterpret_cast<const BYTE*>(value.data()),
            static_cast<DWORD>(value.size()), 0) ||
        !CryptGetHashParam(hash, HP_HASHVAL, digest.data(), &digest_size, 0) ||
        digest_size != digest.size()) {
        if (hash != 0) CryptDestroyHash(hash);
        if (provider != 0) CryptReleaseContext(provider, 0);
        return {};
    }
    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);
    std::ostringstream encoded;
    encoded << std::hex << std::setfill('0');
    for (const BYTE byte : digest) encoded << std::setw(2) << static_cast<unsigned>(byte);
    return encoded.str();
}

std::string snapshot_payload(const HostDirectLinkChangeSnapshot& snapshot) {
    std::ostringstream output;
    output << "version=2\n"
           << "adapter_id=" << snapshot.adapter_id << '\n'
           << "interface_index=" << snapshot.interface_index << '\n'
           << "address_mode="
           << (snapshot.address_mode == OriginalAddressMode::dhcp ? "dhcp" : "ics_private")
           << '\n'
           << "owned_address_backend=";
    switch (snapshot.owned_address_backend) {
        case RestoreAddressBackendHint::transient_ip_helper:
            output << "transient_ip_helper";
            break;
        case RestoreAddressBackendHint::persistent_netsh:
            output << "persistent_netsh";
            break;
        case RestoreAddressBackendHint::infer_from_live_state:
            output << "infer_from_live_state";
            break;
    }
    output << '\n'
           << "forwarding_enabled=" << snapshot.forwarding_enabled << '\n'
           << "advertising_enabled=" << snapshot.advertising_enabled << '\n'
           << "mtu=" << snapshot.mtu << '\n'
           << "router_discovery=" << static_cast<int>(snapshot.router_discovery) << '\n'
           << "weak_host_send=" << snapshot.weak_host_send << '\n'
           << "weak_host_receive=" << snapshot.weak_host_receive << '\n'
           << "ignore_default_routes=" << snapshot.ignore_default_routes << '\n'
           << "advertise_default_route=" << snapshot.advertise_default_route << '\n'
           << "dns_count=" << snapshot.static_ipv4_dns_servers.size() << '\n';
    for (std::size_t index = 0; index < snapshot.static_ipv4_dns_servers.size(); ++index) {
        output << "dns_" << index << '=' << snapshot.static_ipv4_dns_servers[index] << '\n';
    }
    return output.str();
}

bool parse_unsigned(std::string_view value, std::uint32_t& destination) {
    const auto [end, error] = std::from_chars(
        value.data(), value.data() + value.size(), destination);
    return error == std::errc{} && end == value.data() + value.size();
}

bool parse_bool(std::string_view value, bool& destination) {
    if (value == "0") {
        destination = false;
        return true;
    }
    if (value == "1") {
        destination = true;
        return true;
    }
    return false;
}

bool parse_snapshot_backend(
    std::string_view value, RestoreAddressBackendHint& destination) noexcept {
    if (value == "transient_ip_helper") {
        destination = RestoreAddressBackendHint::transient_ip_helper;
        return true;
    }
    if (value == "persistent_netsh") {
        destination = RestoreAddressBackendHint::persistent_netsh;
        return true;
    }
    if (value == "infer_from_live_state") {
        destination = RestoreAddressBackendHint::infer_from_live_state;
        return true;
    }
    return false;
}

bool valid_adapter_id(std::string_view value) {
    return !value.empty() && value.size() <= 64U &&
        std::all_of(value.begin(), value.end(), [](unsigned char character) {
            return std::isalnum(character) != 0 || character == '-';
        });
}

bool valid_ipv4(std::string_view value) {
    if (value.empty() || value.size() >= INET_ADDRSTRLEN) return false;
    std::array<char, INET_ADDRSTRLEN> buffer{};
    std::copy(value.begin(), value.end(), buffer.begin());
    in_addr address{};
    return InetPtonA(AF_INET, buffer.data(), &address) == 1;
}

bool write_snapshot(HostDirectLinkChangeSnapshot& snapshot, std::string& detail) {
    const std::filesystem::path path = direct_link_snapshot_path();
    if (path.empty()) {
        detail = "snapshot_local_app_data_unavailable";
        return false;
    }
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    if (error) {
        detail = "snapshot_directory_create_failed win32=" + std::to_string(error.value());
        return false;
    }
    const std::string payload = snapshot_payload(snapshot);
    snapshot.sha256 = sha256_hex(payload);
    if (snapshot.sha256.empty()) {
        detail = "snapshot_sha256_failed";
        return false;
    }
    const std::filesystem::path temporary =
        path.native() + L"." + std::to_wstring(GetCurrentProcessId()) + L".tmp";
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) {
            detail = "snapshot_temporary_open_failed";
            return false;
        }
        output << payload << "sha256=" << snapshot.sha256 << '\n';
        output.flush();
        if (!output) {
            detail = "snapshot_temporary_write_failed";
            output.close();
            std::filesystem::remove(temporary, error);
            return false;
        }
    }
    if (!MoveFileExW(
            temporary.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH)) {
        detail = "snapshot_commit_failed win32=" + std::to_string(GetLastError());
        std::filesystem::remove(temporary, error);
        return false;
    }
    return true;
}

bool load_snapshot(HostDirectLinkChangeSnapshot& snapshot, std::string& detail) {
    const std::filesystem::path path = direct_link_snapshot_path();
    if (path.empty()) {
        detail = "snapshot_local_app_data_unavailable";
        return false;
    }
    std::error_code size_error;
    const std::uintmax_t snapshot_size = std::filesystem::file_size(path, size_error);
    if (size_error) {
        detail = "snapshot_size_read_failed win32=" +
            std::to_string(size_error.value());
        return false;
    }
    if (snapshot_size == 0U || snapshot_size > kMaximumSnapshotBytes) {
        detail = "snapshot_size_invalid bytes=" + std::to_string(snapshot_size);
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        detail = "snapshot_open_failed";
        return false;
    }
    std::string contents(static_cast<std::size_t>(kMaximumSnapshotBytes) + 1U, '\0');
    input.read(contents.data(), static_cast<std::streamsize>(contents.size()));
    const std::streamsize bytes_read = input.gcount();
    if (input.bad()) {
        detail = "snapshot_read_failed";
        return false;
    }
    if (bytes_read <= 0 ||
        bytes_read > static_cast<std::streamsize>(kMaximumSnapshotBytes)) {
        detail = "snapshot_size_invalid bytes=" + std::to_string(bytes_read);
        return false;
    }
    contents.resize(static_cast<std::size_t>(bytes_read));
    const std::string marker = "sha256=";
    const std::size_t marker_position = contents.rfind(marker);
    if (marker_position == std::string::npos ||
        (marker_position != 0U && contents[marker_position - 1U] != '\n')) {
        detail = "snapshot_sha256_missing";
        return false;
    }
    const std::string payload = contents.substr(0, marker_position);
    std::size_t hash_end = contents.find('\n', marker_position);
    if (hash_end == std::string::npos) hash_end = contents.size();
    snapshot.sha256 = contents.substr(marker_position + marker.size(),
                                      hash_end - marker_position - marker.size());
    if (snapshot.sha256.size() != 64U || sha256_hex(payload) != snapshot.sha256) {
        detail = "snapshot_sha256_mismatch";
        return false;
    }

    std::map<std::string, std::string> fields;
    std::istringstream lines(payload);
    for (std::string line; std::getline(lines, line);) {
        const std::size_t separator = line.find('=');
        if (separator == std::string::npos || separator == 0U ||
            !fields.emplace(line.substr(0, separator), line.substr(separator + 1U)).second) {
            detail = "snapshot_field_invalid";
            return false;
        }
    }
    const auto field = [&](std::string_view name) -> const std::string* {
        const auto found = fields.find(std::string{name});
        return found == fields.end() ? nullptr : &found->second;
    };
    const std::string* version = field("version");
    const std::string* adapter_id = field("adapter_id");
    const std::string* interface_index = field("interface_index");
    const std::string* address_mode = field("address_mode");
    const std::string* owned_address_backend = field("owned_address_backend");
    const std::string* forwarding = field("forwarding_enabled");
    const std::string* advertising = field("advertising_enabled");
    const std::string* mtu = field("mtu");
    const std::string* router_discovery = field("router_discovery");
    const std::string* weak_send = field("weak_host_send");
    const std::string* weak_receive = field("weak_host_receive");
    const std::string* ignore_default_routes = field("ignore_default_routes");
    const std::string* advertise_default_route = field("advertise_default_route");
    const std::string* dns_count = field("dns_count");
    std::uint32_t router_discovery_value{};
    std::uint32_t dns_server_count{};
    if (version == nullptr || (*version != "1" && *version != "2") ||
        adapter_id == nullptr ||
        !valid_adapter_id(*adapter_id) || interface_index == nullptr ||
        !parse_unsigned(*interface_index, snapshot.interface_index) ||
        snapshot.interface_index == 0U || address_mode == nullptr ||
        forwarding == nullptr || !parse_bool(*forwarding, snapshot.forwarding_enabled) ||
        advertising == nullptr || !parse_bool(*advertising, snapshot.advertising_enabled) ||
        mtu == nullptr || !parse_unsigned(*mtu, snapshot.mtu) ||
        snapshot.mtu < 576U || snapshot.mtu > 9000U ||
        router_discovery == nullptr ||
        !parse_unsigned(*router_discovery, router_discovery_value) ||
        router_discovery_value > static_cast<std::uint32_t>(RouterDiscoveryDhcp) ||
        weak_send == nullptr || !parse_bool(*weak_send, snapshot.weak_host_send) ||
        weak_receive == nullptr || !parse_bool(*weak_receive, snapshot.weak_host_receive) ||
        ignore_default_routes == nullptr ||
        !parse_bool(*ignore_default_routes, snapshot.ignore_default_routes) ||
        advertise_default_route == nullptr ||
        !parse_bool(*advertise_default_route, snapshot.advertise_default_route) ||
        dns_count == nullptr || !parse_unsigned(*dns_count, dns_server_count) ||
        dns_server_count > kMaximumSnapshotDnsServers) {
        detail = "snapshot_contract_invalid";
        return false;
    }
    if (*version == "2") {
        if (owned_address_backend == nullptr ||
            !parse_snapshot_backend(
                *owned_address_backend, snapshot.owned_address_backend)) {
            detail = "snapshot_owned_backend_invalid";
            return false;
        }
    } else {
        snapshot.owned_address_backend =
            RestoreAddressBackendHint::infer_from_live_state;
    }
    if (*address_mode == "dhcp") snapshot.address_mode = OriginalAddressMode::dhcp;
    else if (*address_mode == "ics_private") {
        snapshot.address_mode = OriginalAddressMode::ics_private;
    } else {
        detail = "snapshot_address_mode_invalid";
        return false;
    }
    snapshot.adapter_id = *adapter_id;
    snapshot.router_discovery =
        static_cast<NL_ROUTER_DISCOVERY_BEHAVIOR>(router_discovery_value);
    snapshot.static_ipv4_dns_servers.clear();
    for (std::uint32_t index = 0; index < dns_server_count; ++index) {
        const std::string key = "dns_" + std::to_string(index);
        const std::string* server = field(key);
        if (server == nullptr || !valid_ipv4(*server)) {
            detail = "snapshot_dns_invalid";
            return false;
        }
        snapshot.static_ipv4_dns_servers.push_back(*server);
    }
    const std::size_t expected_fields =
        (*version == "2" ? 14U : 13U) + dns_server_count;
    if (fields.size() != expected_fields) {
        detail = "snapshot_unknown_field";
        return false;
    }
    return true;
}

bool read_static_ipv4_dns_servers(
    std::string_view adapter_id,
    std::vector<std::string>& servers,
    std::string& detail) {
    std::wstring wide_adapter_id(adapter_id.begin(), adapter_id.end());
    const std::wstring key_path =
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{" +
        wide_adapter_id + L"}";
    HKEY key{};
    const LSTATUS opened = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE, key_path.c_str(), 0,
        KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    if (opened != ERROR_SUCCESS) {
        detail = "snapshot_dns_registry_open_failed win32=" + std::to_string(opened);
        return false;
    }
    DWORD type{};
    DWORD bytes{};
    const LSTATUS measured =
        RegQueryValueExW(key, L"NameServer", nullptr, &type, nullptr, &bytes);
    if (measured == ERROR_FILE_NOT_FOUND) {
        RegCloseKey(key);
        return true;
    }
    if (measured != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ)) {
        RegCloseKey(key);
        detail = "snapshot_dns_registry_query_failed win32=" +
            std::to_string(measured);
        return false;
    }
    if (bytes < sizeof(wchar_t)) {
        RegCloseKey(key);
        return true;
    }
    std::wstring value(bytes / sizeof(wchar_t), L'\0');
    const LSTATUS queried = RegQueryValueExW(
        key, L"NameServer", nullptr, &type,
        reinterpret_cast<BYTE*>(value.data()), &bytes);
    RegCloseKey(key);
    if (queried != ERROR_SUCCESS) {
        detail = "snapshot_dns_registry_read_failed win32=" +
            std::to_string(queried);
        return false;
    }
    value.resize(wcsnlen_s(value.c_str(), value.size()));

    std::string token;
    const auto flush = [&] {
        if (valid_ipv4(token)) servers.push_back(token);
        token.clear();
    };
    for (const wchar_t character : value) {
        if (character == L',' || character == L';' || std::iswspace(character) != 0) {
            flush();
        } else if (character >= 0 && character <= 0x7f) {
            token.push_back(static_cast<char>(character));
        }
    }
    flush();
    return true;
}

bool capture_snapshot(const HostNetworkAdapterProfile& downstream,
                      HostDirectLinkChangeSnapshot& snapshot,
                      std::string& detail) {
    if (!valid_adapter_id(downstream.adapter_id)) {
        detail = "snapshot_adapter_id_invalid";
        return false;
    }
    if (!downstream.dhcp_enabled && !downstream.has_ics_private_ipv4) {
        detail = "unsupported_preexisting_static_ipv4";
        return false;
    }
    NET_LUID luid{};
    if (ConvertInterfaceIndexToLuid(downstream.interface_index, &luid) != NO_ERROR) {
        detail = "snapshot_interface_luid_unavailable";
        return false;
    }
    MIB_IPINTERFACE_ROW row{};
    InitializeIpInterfaceEntry(&row);
    row.Family = AF_INET;
    row.InterfaceLuid = luid;
    if (GetIpInterfaceEntry(&row) != NO_ERROR) {
        detail = "snapshot_ip_interface_unavailable";
        return false;
    }
    snapshot.adapter_id = downstream.adapter_id;
    snapshot.interface_index = downstream.interface_index;
    snapshot.address_mode = downstream.has_ics_private_ipv4
        ? OriginalAddressMode::ics_private : OriginalAddressMode::dhcp;
    if (!read_static_ipv4_dns_servers(
            downstream.adapter_id, snapshot.static_ipv4_dns_servers, detail)) {
        return false;
    }
    snapshot.forwarding_enabled = row.ForwardingEnabled != FALSE;
    snapshot.advertising_enabled = row.AdvertisingEnabled != FALSE;
    snapshot.mtu = row.NlMtu;
    snapshot.router_discovery = row.RouterDiscoveryBehavior;
    snapshot.weak_host_send = row.WeakHostSend != FALSE;
    snapshot.weak_host_receive = row.WeakHostReceive != FALSE;
    snapshot.ignore_default_routes = row.DisableDefaultRoutes != FALSE;
    snapshot.advertise_default_route = row.AdvertiseDefaultRoute != FALSE;
    return true;
}

bool snapshot_can_use_transient_address_backend(
    const HostDirectLinkChangeSnapshot& snapshot,
    const HostNetworkAdapterProfile& downstream) noexcept {
    return snapshot.address_mode == OriginalAddressMode::dhcp &&
        downstream.dhcp_enabled && !downstream.has_default_gateway &&
        snapshot.static_ipv4_dns_servers.empty();
}

RestoreAddressBackendHint choose_snapshot_owned_address_backend(
    const HostDirectLinkChangeSnapshot& snapshot,
    const HostNetworkAdapterProfile& downstream) noexcept {
    if (!g_prefer_persistent_address_backend.load(std::memory_order_relaxed) &&
        snapshot_can_use_transient_address_backend(snapshot, downstream)) {
        return RestoreAddressBackendHint::transient_ip_helper;
    }
    return RestoreAddressBackendHint::persistent_netsh;
}

bool persist_snapshot_owned_address_backend(
    HostDirectLinkChangeSnapshot& snapshot,
    RestoreAddressBackendHint backend,
    std::string& detail) {
    if (snapshot.owned_address_backend == backend) {
        detail.clear();
        return true;
    }
    snapshot.owned_address_backend = backend;
    return write_snapshot(snapshot, detail);
}

const HostNetworkAdapterProfile* find_snapshot_adapter(
    const HostDirectLinkChangeSnapshot& snapshot,
    const std::vector<HostNetworkAdapterProfile>& adapters) {
    const auto found = std::find_if(adapters.begin(), adapters.end(), [&](const auto& adapter) {
        return adapter.adapter_id == snapshot.adapter_id;
    });
    return found == adapters.end() ? nullptr : &*found;
}

bool snapshot_interface_policy_matches(
    const HostDirectLinkChangeSnapshot& snapshot,
    std::uint32_t current_interface_index) {
    MIB_IPINTERFACE_ROW row{};
    std::string detail;
    if (!read_ipv4_interface(current_interface_index, row, detail)) return false;
    return (row.ForwardingEnabled != FALSE) == snapshot.forwarding_enabled &&
        (row.AdvertisingEnabled != FALSE) == snapshot.advertising_enabled &&
        row.NlMtu == snapshot.mtu &&
        row.RouterDiscoveryBehavior == snapshot.router_discovery &&
        (row.WeakHostSend != FALSE) == snapshot.weak_host_send &&
        (row.WeakHostReceive != FALSE) == snapshot.weak_host_receive &&
        (row.DisableDefaultRoutes != FALSE) == snapshot.ignore_default_routes &&
        (row.AdvertiseDefaultRoute != FALSE) == snapshot.advertise_default_route;
}

bool snapshot_dns_matches(const HostDirectLinkChangeSnapshot& snapshot) {
    std::vector<std::string> current;
    std::string detail;
    return read_static_ipv4_dns_servers(snapshot.adapter_id, current, detail) &&
        current == snapshot.static_ipv4_dns_servers;
}

bool snapshot_configuration_matches(const HostDirectLinkChangeSnapshot& snapshot) {
    const auto adapters = enumerate_network_profiles();
    const HostNetworkAdapterProfile* adapter = find_snapshot_adapter(snapshot, adapters);
    if (adapter == nullptr || adapter->has_default_gateway ||
        host_direct_link_has_any_isolated_address(*adapter)) {
        return false;
    }
    if (snapshot.owned_address_backend ==
        RestoreAddressBackendHint::transient_ip_helper) {
        return snapshot_interface_policy_matches(snapshot, adapter->interface_index);
    }
    const bool address_matches = snapshot.address_mode == OriginalAddressMode::dhcp
        ? adapter->dhcp_enabled
        : adapter->has_ics_private_ipv4;
    return address_matches && snapshot_dns_matches(snapshot) &&
        snapshot_interface_policy_matches(snapshot, adapter->interface_index);
}

std::wstring enabled_text(bool enabled) {
    return enabled ? L"enabled" : L"disabled";
}

std::wstring router_discovery_text(NL_ROUTER_DISCOVERY_BEHAVIOR value) {
    switch (value) {
        case RouterDiscoveryDisabled: return L"disabled";
        case RouterDiscoveryEnabled: return L"enabled";
        case RouterDiscoveryDhcp: return L"dhcp";
        default: return {};
    }
}

bool apply_dns_snapshot(
    const HostDirectLinkChangeSnapshot& snapshot,
    const HostNetworkAdapterProfile& downstream,
    std::string& detail) {
    if (snapshot.static_ipv4_dns_servers.empty()) {
        return run_netsh_for_adapter(
            downstream, L"interface ipv4 set dnsservers name=",
            L" source=dhcp register=none validate=no",
            detail);
    }
    std::wstring first(
        snapshot.static_ipv4_dns_servers.front().begin(),
        snapshot.static_ipv4_dns_servers.front().end());
    if (!run_netsh_for_adapter(
            downstream, L"interface ipv4 set dnsservers name=",
            L" source=static address=" + first + L" register=none validate=no",
            detail)) {
        return false;
    }
    for (std::size_t index = 1; index < snapshot.static_ipv4_dns_servers.size(); ++index) {
        const std::wstring server(
            snapshot.static_ipv4_dns_servers[index].begin(),
            snapshot.static_ipv4_dns_servers[index].end());
        if (!run_netsh_for_adapter(
                downstream, L"interface ipv4 add dnsservers name=",
                L" address=" + server + L" index=" + std::to_wstring(index + 1U) +
                    L" validate=no",
                detail)) {
            return false;
        }
    }
    return true;
}

bool apply_interface_snapshot(
    const HostDirectLinkChangeSnapshot& snapshot,
    const HostNetworkAdapterProfile& downstream,
    std::string& detail) {
    std::string native_detail;
    if (restore_interface_policy(snapshot, downstream.interface_index, native_detail)) {
        detail.clear();
        return true;
    }
    const std::wstring discovery = router_discovery_text(snapshot.router_discovery);
    if (discovery.empty()) {
        detail = "snapshot_router_discovery_invalid";
        return false;
    }
    std::string netsh_detail;
    const bool restored = run_netsh_for_adapter(
        downstream, L"interface ipv4 set interface interface=",
        L" forwarding=" + enabled_text(snapshot.forwarding_enabled) +
            L" advertise=" + enabled_text(snapshot.advertising_enabled) +
            L" mtu=" + std::to_wstring(snapshot.mtu) +
            L" routerdiscovery=" + discovery +
            L" weakhostsend=" + enabled_text(snapshot.weak_host_send) +
            L" weakhostreceive=" + enabled_text(snapshot.weak_host_receive) +
            L" ignoredefaultroutes=" + enabled_text(snapshot.ignore_default_routes) +
            L" advertisedefaultroute=" + enabled_text(snapshot.advertise_default_route) +
            L" store=persistent",
        netsh_detail);
    if (restored) {
        detail.clear();
        return true;
    }
    detail = "ip_helper_attempt={" + native_detail +
        "} netsh_fallback={" + netsh_detail + "}";
    return false;
}

bool snapshot_is_restored(const HostDirectLinkChangeSnapshot& snapshot) {
    return snapshot_configuration_matches(snapshot);
}

bool restore_snapshot_configuration(
    const HostDirectLinkChangeSnapshot& snapshot,
    const HostNetworkAdapterProfile& downstream,
    RestoreAddressBackendHint backend_hint,
    std::string& detail) {
    if (snapshot_configuration_matches(snapshot)) {
        detail.clear();
        return true;
    }

    const RestoreAddressBackendHint effective_backend_hint =
        backend_hint != RestoreAddressBackendHint::infer_from_live_state
        ? backend_hint
        : snapshot.owned_address_backend;
    const bool transient_address_path =
        effective_backend_hint == RestoreAddressBackendHint::transient_ip_helper ||
        (effective_backend_hint == RestoreAddressBackendHint::infer_from_live_state &&
         snapshot.address_mode == OriginalAddressMode::dhcp &&
         downstream.dhcp_enabled && snapshot.static_ipv4_dns_servers.empty());
    if (transient_address_path) {
        if (!delete_transient_isolated_address(downstream.interface_index, detail) ||
            !apply_interface_snapshot(snapshot, downstream, detail)) {
            return false;
        }
    } else {
        if (snapshot.address_mode == OriginalAddressMode::dhcp) {
            if (!run_netsh_for_adapter(
                    downstream, L"interface ipv4 set address name=",
                    L" source=dhcp store=persistent", detail)) {
                return false;
            }
        } else if (!run_netsh_for_adapter(
                       downstream, L"interface ipv4 set address name=",
                       L" source=static address=192.168.137.1 mask=255.255.255.0"
                       L" gateway=none store=persistent",
                       detail)) {
            return false;
        }
        if (!apply_dns_snapshot(snapshot, downstream, detail) ||
            !apply_interface_snapshot(snapshot, downstream, detail)) {
            return false;
        }
        if (snapshot.address_mode == OriginalAddressMode::ics_private &&
            !enable_selected_private_sharing(downstream, detail)) {
            return false;
        }
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline && !snapshot_is_restored(snapshot)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    if (!snapshot_is_restored(snapshot)) {
        detail = "snapshot_restore_not_observed";
        return false;
    }
    return true;
}

bool remove_snapshot_file(std::string& detail) {
    std::error_code error;
    const std::filesystem::path path = direct_link_snapshot_path();
    if (path.empty()) {
        detail = "snapshot_local_app_data_unavailable";
        return false;
    }
    const bool removed = std::filesystem::remove(path, error);
    if (error) {
        detail = "snapshot_remove_failed win32=" + std::to_string(error.value());
        return false;
    }
    if (!removed && std::filesystem::exists(path, error)) {
        detail = "snapshot_remove_not_observed";
        return false;
    }
    return true;
}

bool launch_elevated_worker(
    std::wstring_view argument, DWORD timeout_ms, std::string& detail) {
    std::wstring executable(32'768U, L'\0');
    const DWORD executable_length = GetModuleFileNameW(
        nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (executable_length == 0U || executable_length >= executable.size()) {
        detail = "direct_wired_worker_executable_unavailable";
        return false;
    }
    executable.resize(executable_length);

    const std::wstring parameters{argument};
    SHELLEXECUTEINFOW launch{};
    launch.cbSize = sizeof(launch);
    launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    launch.lpVerb = L"runas";
    launch.lpFile = executable.c_str();
    launch.lpParameters = parameters.c_str();
    launch.nShow = SW_HIDE;
    if (!ShellExecuteExW(&launch) || launch.hProcess == nullptr) {
        const DWORD error = GetLastError();
        detail = error == ERROR_CANCELLED
            ? "direct_wired_uac_cancelled"
            : "direct_wired_elevated_worker_launch_failed win32=" + std::to_string(error);
        return false;
    }

    const DWORD wait_result = WaitForSingleObject(launch.hProcess, timeout_ms);
    const DWORD wait_error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
    DWORD exit_code = ERROR_GEN_FAILURE;
    if (wait_result == WAIT_OBJECT_0) GetExitCodeProcess(launch.hProcess, &exit_code);
    if (wait_result == WAIT_TIMEOUT) {
        if (!TerminateProcess(launch.hProcess, ERROR_TIMEOUT)) {
            const DWORD terminate_error = GetLastError();
            CloseHandle(launch.hProcess);
            detail = "direct_wired_elevated_worker_timeout_terminate_failed win32=" +
                std::to_string(terminate_error);
            return false;
        }
        const DWORD terminated = WaitForSingleObject(launch.hProcess, 5'000U);
        const DWORD termination_wait_error = terminated == WAIT_FAILED
            ? GetLastError() : ERROR_SUCCESS;
        CloseHandle(launch.hProcess);
        if (terminated != WAIT_OBJECT_0) {
            detail = terminated == WAIT_TIMEOUT
                ? "direct_wired_elevated_worker_termination_timeout"
                : "direct_wired_elevated_worker_termination_wait_failed win32=" +
                    std::to_string(termination_wait_error);
            return false;
        }
        detail = "direct_wired_elevated_worker_timeout_terminated";
        return false;
    }
    CloseHandle(launch.hProcess);
    if (wait_result != WAIT_OBJECT_0) {
        detail = "direct_wired_elevated_worker_wait_failed win32=" +
            std::to_string(wait_error);
        return false;
    }
    if (exit_code != ERROR_SUCCESS) {
        detail = "direct_wired_elevated_worker_failed exit_code=" +
            std::to_string(exit_code);
        return false;
    }
    detail = "direct_wired_elevated_worker_succeeded";
    return true;
}

}  // namespace

namespace {

const char* bool_text(bool value) noexcept {
    return value ? "true" : "false";
}

const char* transport_name(HostAdapterTransport transport) noexcept {
    return transport == HostAdapterTransport::ethernet ? "ethernet" : "other";
}

const char* prefix_origin_name(std::uint32_t origin) noexcept {
    switch (origin) {
        case IpPrefixOriginOther: return "other";
        case IpPrefixOriginManual: return "manual";
        case IpPrefixOriginWellKnown: return "well_known";
        case IpPrefixOriginDhcp: return "dhcp";
        case IpPrefixOriginRouterAdvertisement: return "router_advertisement";
        case IpPrefixOriginUnchanged: return "unchanged";
        default: return "unknown";
    }
}

const char* suffix_origin_name(std::uint32_t origin) noexcept {
    switch (origin) {
        case IpSuffixOriginOther: return "other";
        case IpSuffixOriginManual: return "manual";
        case IpSuffixOriginWellKnown: return "well_known";
        case IpSuffixOriginDhcp: return "dhcp";
        case IpSuffixOriginLinkLayerAddress: return "link_layer";
        case IpSuffixOriginRandom: return "random";
        case IpSuffixOriginUnchanged: return "unchanged";
        default: return "unknown";
    }
}

const char* dad_state_name(std::uint32_t state) noexcept {
    switch (state) {
        case IpDadStateInvalid: return "invalid";
        case IpDadStateTentative: return "tentative";
        case IpDadStateDuplicate: return "duplicate";
        case IpDadStateDeprecated: return "deprecated";
        case IpDadStatePreferred: return "preferred";
        default: return "unknown";
    }
}

bool is_base_direct_link_candidate(
    const HostNetworkAdapterProfile& adapter) noexcept {
    return host_adapter_has_physical_connector_identity(
               HostAdapterIdentityFacts{
                   .hardware_interface = adapter.hardware_interface,
                   .connector_present = adapter.connector_present,
                   .filter_interface = adapter.filter_interface,
                   .endpoint_interface = adapter.endpoint_interface,
                   .software_loopback_or_tunnel = adapter.virtual_or_loopback,
                   .connection_name = adapter.connection_name,
                   .description = adapter.description,
               }) && adapter.operational &&
        adapter.transport == HostAdapterTransport::ethernet &&
        !adapter.has_default_gateway;
}

bool is_operational_physical_ethernet(
    const HostNetworkAdapterProfile& adapter) noexcept {
    return host_adapter_has_physical_connector_identity(
               HostAdapterIdentityFacts{
                   .hardware_interface = adapter.hardware_interface,
                   .connector_present = adapter.connector_present,
                   .filter_interface = adapter.filter_interface,
                   .endpoint_interface = adapter.endpoint_interface,
                   .software_loopback_or_tunnel = adapter.virtual_or_loopback,
                   .connection_name = adapter.connection_name,
                   .description = adapter.description,
               }) && adapter.operational &&
        adapter.transport == HostAdapterTransport::ethernet;
}

bool is_temporarily_pending_direct_link_candidate(
    const HostNetworkAdapterProfile& adapter) noexcept {
    const bool physical_ethernet =
        host_adapter_has_physical_connector_identity(
            HostAdapterIdentityFacts{
                .hardware_interface = adapter.hardware_interface,
                .connector_present = adapter.connector_present,
                .filter_interface = adapter.filter_interface,
                .endpoint_interface = adapter.endpoint_interface,
                .software_loopback_or_tunnel = adapter.virtual_or_loopback,
                .connection_name = adapter.connection_name,
                .description = adapter.description,
            }) &&
        adapter.transport == HostAdapterTransport::ethernet &&
        !adapter.has_default_gateway;
    if (!physical_ethernet) return false;
    if (!adapter.operational) return true;
    return std::any_of(
        adapter.ipv4_addresses.begin(), adapter.ipv4_addresses.end(),
        [](const HostNetworkIpv4AddressProfile& address) {
            return address.dad_state ==
                static_cast<std::uint32_t>(IpDadStateTentative);
        });
}

bool has_temporarily_pending_direct_link_candidate(
    const std::vector<HostNetworkAdapterProfile>& adapters) noexcept {
    return std::any_of(
        adapters.begin(), adapters.end(),
        is_temporarily_pending_direct_link_candidate);
}

bool is_compatibility_transient_manual_address(
    const HostNetworkIpv4AddressProfile& address) noexcept {
    const auto parsed = parse_ipv4(address.address);
    if (!parsed.has_value()) return false;
    constexpr std::uint32_t kCompatibilityNetwork = 0x0A390000U;  // 10.57.0.0/16
    constexpr std::uint32_t kCompatibilityMask = 0xFFFF0000U;
    constexpr std::uint32_t kOwnedSubnet = 0x0A391700U;  // 10.57.23.0/24
    constexpr std::uint32_t kOwnedSubnetMask = 0xFFFFFF00U;
    return address.prefix_origin == IpPrefixOriginManual &&
        address.suffix_origin == IpSuffixOriginManual &&
        address.prefix_length == 24U &&
        (*parsed & kCompatibilityMask) == kCompatibilityNetwork &&
        (*parsed & kOwnedSubnetMask) != kOwnedSubnet;
}

bool has_only_compatibility_transient_manual_addresses(
    const HostNetworkAdapterProfile& adapter) noexcept {
    bool found{};
    for (const auto& address : adapter.ipv4_addresses) {
        if (!is_usable_address(address) ||
            address.prefix_origin != IpPrefixOriginManual) {
            continue;
        }
        found = true;
        if (!is_compatibility_transient_manual_address(address)) return false;
    }
    return found;
}

bool has_owned_subnet_address_conflict(
    const HostNetworkAdapterProfile& adapter) noexcept {
    constexpr std::uint32_t kOwnedSubnet = 0x0A391700U;  // 10.57.23.0/24
    constexpr std::uint32_t kOwnedSubnetMask = 0xFFFFFF00U;
    return std::any_of(
        adapter.ipv4_addresses.begin(), adapter.ipv4_addresses.end(),
        [](const HostNetworkIpv4AddressProfile& address) {
            const auto parsed = parse_ipv4(address.address);
            return parsed.has_value() && *parsed != kIsolatedPrivateAddress &&
                (*parsed & kOwnedSubnetMask) == kOwnedSubnet;
        });
}

bool is_configurable_direct_link_candidate(
    const HostNetworkAdapterProfile& adapter) noexcept {
    if (!is_base_direct_link_candidate(adapter) ||
        host_direct_link_has_any_isolated_address(adapter) ||
        has_owned_subnet_address_conflict(adapter)) {
        return false;
    }
    if (adapter.has_ics_private_ipv4) return true;
    // Some compatibility layers and machine-identity tools add a transient
    // manual address while leaving DHCP enabled. A second IP Helper alias is
    // non-destructive on that unique, physical, unrouted Ethernet interface.
    if (has_preexisting_static_usable_ipv4(adapter)) {
        return adapter.dhcp_enabled &&
            has_only_compatibility_transient_manual_addresses(adapter);
    }
    if (!adapter.has_usable_ipv4) return true;
    return adapter.dhcp_enabled &&
        has_dhcp_assigned_usable_ipv4(adapter) &&
        !has_unclassified_usable_ipv4(adapter);
}

bool is_routed_dhcp_direct_link_candidate(
    const HostNetworkAdapterProfile& adapter) noexcept {
    if (!is_operational_physical_ethernet(adapter) ||
        !adapter.has_default_gateway ||
        host_direct_link_has_any_isolated_address(adapter) ||
        has_owned_subnet_address_conflict(adapter)) {
        return false;
    }
    if (!adapter.dhcp_enabled || !adapter.has_usable_ipv4) return false;
    if (has_preexisting_static_usable_ipv4(adapter)) return false;
    return has_dhcp_assigned_usable_ipv4(adapter) &&
        !has_unclassified_usable_ipv4(adapter);
}

std::vector<std::string_view> rejection_predicates(
    const HostNetworkAdapterProfile& adapter) {
    std::vector<std::string_view> predicates;
    if (!adapter.hardware_interface) predicates.emplace_back("not_hardware");
    if (!adapter.connector_present) predicates.emplace_back("connector_not_present");
    if (adapter.filter_interface) predicates.emplace_back("filter_interface");
    if (adapter.endpoint_interface) predicates.emplace_back("endpoint_interface");
    if (adapter.virtual_or_loopback) {
        predicates.emplace_back("virtual_or_loopback_identity");
    }
    if (!adapter.operational) predicates.emplace_back("not_operational");
    if (adapter.transport != HostAdapterTransport::ethernet) {
        predicates.emplace_back("transport_not_ethernet");
    }
    if (adapter.has_default_gateway &&
        !is_routed_dhcp_direct_link_candidate(adapter)) {
        predicates.emplace_back("has_default_gateway");
    }
    if (!is_base_direct_link_candidate(adapter) &&
        !is_routed_dhcp_direct_link_candidate(adapter)) {
        return predicates;
    }
    if (adapter.has_isolated_private_ipv4) return predicates;
    if (host_direct_link_has_any_isolated_address(adapter)) {
        return predicates;
    }
    if (has_owned_subnet_address_conflict(adapter)) {
        predicates.emplace_back("owned_subnet_address_conflict");
        return predicates;
    }
    if (is_configurable_direct_link_candidate(adapter)) return predicates;
    if (has_preexisting_static_usable_ipv4(adapter)) {
        predicates.emplace_back("preexisting_static_ipv4");
    }
    if (has_unclassified_usable_ipv4(adapter)) {
        predicates.emplace_back("preexisting_unclassified_usable_ipv4");
    }
    if (adapter.has_usable_ipv4 && !adapter.dhcp_enabled) {
        predicates.emplace_back("dhcp_disabled_with_usable_ipv4");
    } else if (adapter.has_usable_ipv4 &&
               !has_dhcp_assigned_usable_ipv4(adapter) &&
               !has_preexisting_static_usable_ipv4(adapter)) {
        predicates.emplace_back("no_dhcp_address_evidence");
    }
    return predicates;
}

std::string describe_adapter_inventory(
    const std::vector<HostNetworkAdapterProfile>& adapters) {
    std::ostringstream detail;
    detail << "inventory_count=" << adapters.size() << " inventory=[";
    for (std::size_t index = 0; index < adapters.size(); ++index) {
        if (index != 0U) detail << ';';
        const auto& adapter = adapters[index];
        detail << "{index=" << index
               << " name=" << std::quoted(wide_to_utf8(adapter.connection_name))
               << " guid=" << std::quoted(adapter.adapter_id)
               << " ifindex=" << adapter.interface_index
               << " description="
               << std::quoted(wide_to_utf8(adapter.description))
               << " hardware=" << bool_text(adapter.hardware_interface)
               << " connector_present="
               << bool_text(adapter.connector_present)
               << " filter_interface="
               << bool_text(adapter.filter_interface)
               << " endpoint_interface="
               << bool_text(adapter.endpoint_interface)
               << " virtual_or_loopback="
               << bool_text(adapter.virtual_or_loopback)
               << " oper=" << (adapter.operational ? "up" : "down")
               << " transport=" << transport_name(adapter.transport)
               << " has_default_gateway="
               << bool_text(adapter.has_default_gateway)
               << " gateways=[";
        for (std::size_t gateway_index = 0;
             gateway_index < adapter.ipv4_gateways.size(); ++gateway_index) {
            if (gateway_index != 0U) detail << ',';
            detail << adapter.ipv4_gateways[gateway_index];
        }
        detail << "] dhcp=" << bool_text(adapter.dhcp_enabled)
               << " ipv4=[";
        for (std::size_t address_index = 0;
             address_index < adapter.ipv4_addresses.size(); ++address_index) {
            if (address_index != 0U) detail << ',';
            const auto& address = adapter.ipv4_addresses[address_index];
            detail << "{address=" << address.address
                   << " prefix=" << static_cast<unsigned>(address.prefix_length)
                   << " dad=" << dad_state_name(address.dad_state)
                   << '(' << address.dad_state << ')'
                   << " skip_as_source=";
            if (address.skip_as_source.has_value()) {
                detail << bool_text(*address.skip_as_source);
            } else {
                detail << "unknown";
            }
            detail << " prefix_origin=" << prefix_origin_name(address.prefix_origin)
                   << '(' << address.prefix_origin << ')'
                   << " suffix_origin=" << suffix_origin_name(address.suffix_origin)
                   << '(' << address.suffix_origin << ")}";
        }
        const auto rejected = rejection_predicates(adapter);
        const char* selection_state =
            adapter.has_isolated_private_ipv4 && is_base_direct_link_candidate(adapter)
            ? "ready"
            : (host_direct_link_has_any_isolated_address(adapter) &&
                   is_base_direct_link_candidate(adapter)
                ? "ready_pending"
            : (is_configurable_direct_link_candidate(adapter)
                ? "configurable"
                : (is_routed_dhcp_direct_link_candidate(adapter)
                    ? "configurable_routed_dhcp" : "rejected")));
        detail << "] selection=" << selection_state << " rejected_by=[";
        for (std::size_t predicate_index = 0;
             predicate_index < rejected.size(); ++predicate_index) {
            if (predicate_index != 0U) detail << ',';
            detail << rejected[predicate_index];
        }
        detail << "]}";
    }
    detail << ']';
    return detail.str();
}

std::string describe_ambiguous_adapters(
    std::string_view reason, const std::vector<HostNetworkAdapterProfile>& adapters,
    const std::vector<std::size_t>& candidates) {
    std::ostringstream detail;
    detail << "reason=" << reason << " candidate_count=" << candidates.size()
           << " adapter_ids=";
    for (std::size_t position = 0; position < candidates.size(); ++position) {
        if (position != 0U) detail << ',';
        const auto& adapter = adapters[candidates[position]];
        if (!adapter.adapter_id.empty()) detail << adapter.adapter_id;
        else detail << "ifindex:" << adapter.interface_index;
    }
    detail << ' ' << describe_adapter_inventory(adapters);
    return detail.str();
}

}  // namespace

bool host_direct_link_has_any_isolated_address(
    const HostNetworkAdapterProfile& adapter) noexcept {
    if (adapter.has_isolated_private_ipv4) return true;
    return std::any_of(
        adapter.ipv4_addresses.begin(), adapter.ipv4_addresses.end(),
        [](const HostNetworkIpv4AddressProfile& address) {
            return address.address == "10.57.23.1";
        });
}

HostDirectLinkPlan choose_host_direct_link_plan(
    const std::vector<HostNetworkAdapterProfile>& adapters) {
    HostDirectLinkPlan plan{};
    std::vector<std::size_t> ready_adapters;
    std::vector<std::size_t> configurable_adapters;
    std::vector<std::size_t> routed_dhcp_adapters;
    for (std::size_t index = 0; index < adapters.size(); ++index) {
        const auto& adapter = adapters[index];
        if (!is_base_direct_link_candidate(adapter)) {
            if (is_routed_dhcp_direct_link_candidate(adapter)) {
                routed_dhcp_adapters.push_back(index);
            }
            continue;
        }
        if (host_direct_link_has_any_isolated_address(adapter)) {
            ready_adapters.push_back(index);
        }
        if (is_configurable_direct_link_candidate(adapter)) {
            configurable_adapters.push_back(index);
        }
    }
    if (ready_adapters.size() == 1U) {
        const std::size_t ready_index = ready_adapters.front();
        plan.downstream_adapter = ready_index;
        plan.downstream_already_ready = true;
        plan.downstream_isolated_pending_preference =
            !adapters[ready_index].has_isolated_private_ipv4;
        plan.reason = plan.downstream_isolated_pending_preference
            ? "direct_wired_ipv4_pending_preference"
            : "direct_wired_ipv4_already_ready";
        return plan;
    }
    if (ready_adapters.size() > 1U) {
        plan.ambiguous_downstream = true;
        plan.reason = describe_ambiguous_adapters(
            "multiple_existing_cat6_adapters", adapters, ready_adapters);
        return plan;
    }
    if (configurable_adapters.empty() && routed_dhcp_adapters.empty()) {
        plan.reason = "reason=no_unnumbered_wired_adapter " +
            describe_adapter_inventory(adapters);
        return plan;
    }
    if (configurable_adapters.empty()) {
        if (routed_dhcp_adapters.size() > 1U) {
            plan.ambiguous_downstream = true;
            plan.reason = describe_ambiguous_adapters(
                "ambiguous_routed_dhcp_ethernet_adapters",
                adapters, routed_dhcp_adapters);
            return plan;
        }
        plan.downstream_adapter = routed_dhcp_adapters.front();
        plan.reason = "isolated_routed_dhcp_wired_adapter_selected";
        return plan;
    }
    if (configurable_adapters.size() > 1U) {
        plan.ambiguous_downstream = true;
        plan.reason = describe_ambiguous_adapters(
            "ambiguous_unrouted_ethernet_adapters", adapters, configurable_adapters);
        return plan;
    }

    plan.downstream_adapter = configurable_adapters.front();
    plan.reason = "isolated_wired_adapter_selected";
    return plan;
}

HostDirectLinkTransactionResult execute_host_direct_link_transaction(
    const HostDirectLinkTransactionOperations& operations) {
    HostDirectLinkTransactionResult result{};
    if (!operations.apply || !operations.verify || !operations.rollback) {
        result.detail = "transaction_callbacks_incomplete";
        return result;
    }
    constexpr std::array steps{
        HostDirectLinkMutationStep::address,
        HostDirectLinkMutationStep::dns,
        HostDirectLinkMutationStep::interface_policy,
    };
    std::string operation_detail;
    for (const HostDirectLinkMutationStep step : steps) {
        if (!operations.apply(step, operation_detail)) {
            result.failed_step = step;
            break;
        }
        ++result.applied_steps;
    }
    if (result.applied_steps == steps.size()) {
        result.failed_step = HostDirectLinkMutationStep::verify;
        if (operations.verify(operation_detail)) {
            result.succeeded = true;
            result.detail = "transaction_committed";
            return result;
        }
    }
    result.rollback_attempted = true;
    std::string rollback_detail;
    result.rollback_succeeded = operations.rollback(rollback_detail);
    result.detail =
        "failed_step=" + std::string(host_direct_link_mutation_step_name(result.failed_step)) +
        " failure=" + operation_detail +
        " rollback=" + (result.rollback_succeeded ? "restored" : "failed") +
        (rollback_detail.empty() ? std::string{} : " rollback_detail=" + rollback_detail);
    return result;
}

HostDirectLinkProvisioningResult ensure_host_direct_link_ipv4() {
    const auto adapters = enumerate_network_profiles();
    const auto plan = choose_host_direct_link_plan(adapters);
    HostDirectLinkProvisioningResult outcome{};
    outcome.detail = plan.reason;
    if (!plan.downstream_adapter.has_value()) {
        outcome.status = plan.ambiguous_downstream
            ? HostDirectLinkStatus::ambiguous_wired_adapter
            : HostDirectLinkStatus::no_wired_adapter;
        outcome.detection_temporarily_pending =
            !plan.ambiguous_downstream &&
            has_temporarily_pending_direct_link_candidate(adapters);
        return outcome;
    }
    const auto& downstream = adapters[*plan.downstream_adapter];
    outcome.downstream_name = downstream.connection_name;
    const std::filesystem::path snapshot_path = direct_link_snapshot_path();
    if (!snapshot_path.empty()) {
        outcome.snapshot_path = wide_to_utf8(snapshot_path.native());
    }
    if (plan.downstream_already_ready) {
        if (plan.downstream_isolated_pending_preference) {
            std::string dad_detail;
            if (!wait_for_isolated_address_preferred(
                    downstream.interface_index, dad_detail)) {
                outcome.status = HostDirectLinkStatus::failed;
                outcome.detail +=
                    " isolated_address_pending_preference_failed " +
                    dad_detail + ' ' + describe_adapter_inventory(adapters);
                return outcome;
            }
            outcome.detail += " isolated_address_preferred_after_wait";
        }
        outcome.status = HostDirectLinkStatus::already_ready;
        std::error_code exists_error;
        if (!snapshot_path.empty() && std::filesystem::exists(snapshot_path, exists_error)) {
            HostDirectLinkChangeSnapshot pending{};
            std::string pending_error;
            if (load_snapshot(pending, pending_error)) {
                outcome.snapshot_sha256 = pending.sha256;
                outcome.detail += " restore_snapshot=pending";
            } else {
                outcome.detail += " restore_snapshot=invalid detail=" + pending_error;
            }
        }
        return outcome;
    }
    if (!process_is_elevated()) {
        outcome.status = HostDirectLinkStatus::requires_elevation;
        outcome.detail = "isolated_wired_configuration_requires_elevation";
        return outcome;
    }
    if (downstream.interface_index == 0U) {
        outcome.status = HostDirectLinkStatus::failed;
        outcome.detail = "isolated_wired_interface_index_unavailable";
        return outcome;
    }

    HostDirectLinkChangeSnapshot snapshot{};
    std::error_code exists_error;
    const bool snapshot_exists = !snapshot_path.empty() &&
        std::filesystem::exists(snapshot_path, exists_error);
    std::string snapshot_error;
    if (exists_error) {
        outcome.status = HostDirectLinkStatus::failed;
        outcome.detail = "snapshot_exists_check_failed win32=" +
            std::to_string(exists_error.value());
        return outcome;
    }
    bool capture_fresh_snapshot = !snapshot_exists;
    if (snapshot_exists) {
        if (!load_snapshot(snapshot, snapshot_error) ||
            snapshot.adapter_id != downstream.adapter_id) {
            outcome.status = HostDirectLinkStatus::failed;
            outcome.detail = snapshot_error.empty()
                ? "pending_snapshot_adapter_mismatch"
                : snapshot_error;
            return outcome;
        }
        if (snapshot_configuration_matches(snapshot)) {
            if (!remove_snapshot_file(snapshot_error)) {
                outcome.status = HostDirectLinkStatus::failed;
                outcome.detail = "stale_snapshot_cleanup_failed " + snapshot_error;
                return outcome;
            }
            capture_fresh_snapshot = true;
        }
    }
    if (capture_fresh_snapshot) {
        if (!capture_snapshot(downstream, snapshot, snapshot_error)) {
            outcome.status = HostDirectLinkStatus::unavailable;
            outcome.detail = snapshot_error;
            return outcome;
        }
        snapshot.owned_address_backend =
            choose_snapshot_owned_address_backend(snapshot, downstream);
        if (!write_snapshot(snapshot, snapshot_error)) {
            outcome.status = HostDirectLinkStatus::failed;
            outcome.detail = snapshot_error;
            return outcome;
        }
    }
    outcome.snapshot_sha256 = snapshot.sha256;

    const bool transient_address_candidate =
        snapshot_can_use_transient_address_backend(snapshot, downstream);
    const bool prefer_persistent_backend =
        g_prefer_persistent_address_backend.load(std::memory_order_relaxed);
    const bool coexisting_preexisting_ipv4 =
        has_preexisting_static_usable_ipv4(downstream);
    if (coexisting_preexisting_ipv4 &&
        !transient_address_candidate) {
        outcome.status = HostDirectLinkStatus::unavailable;
        outcome.detail =
            "preexisting_static_ipv4_requires_non_destructive_alias_but_static_dns_is_present";
        return outcome;
    }
    AppliedAddressBackend applied_address_backend = AppliedAddressBackend::none;
    const HostDirectLinkTransactionResult transaction =
        execute_host_direct_link_transaction({
            .apply = [&](HostDirectLinkMutationStep step, std::string& detail) {
                switch (step) {
                    case HostDirectLinkMutationStep::address: {
                        if (!disable_selected_private_sharing(downstream, detail)) return false;
                        if (transient_address_candidate && !prefer_persistent_backend) {
                            std::string native_detail;
                            const TransientAddressCreateStatus native_status =
                                create_transient_isolated_address(
                                    downstream.interface_index, native_detail);
                            if (native_status == TransientAddressCreateStatus::created) {
                                applied_address_backend =
                                    AppliedAddressBackend::transient_ip_helper;
                                detail.clear();
                                return true;
                            }
                            if (native_status ==
                                    TransientAddressCreateStatus::ownership_conflict ||
                                native_status ==
                                    TransientAddressCreateStatus::validation_failed) {
                                detail = native_detail;
                                return false;
                            }
                            if (coexisting_preexisting_ipv4) {
                                detail =
                                    "non_destructive_alias_required_no_netsh_fallback " +
                                    native_detail;
                                return false;
                            }
                            std::string netsh_detail;
                            // netsh can change DHCP/static state before it
                            // returns an error or times out.  Record ownership
                            // before starting it so rollback always restores
                            // the persistent address mode after partial apply.
                            if (!persist_snapshot_owned_address_backend(
                                    snapshot,
                                    RestoreAddressBackendHint::persistent_netsh,
                                    netsh_detail)) {
                                detail = "snapshot_backend_update_failed " +
                                    netsh_detail;
                                return false;
                            }
                            applied_address_backend =
                                AppliedAddressBackend::persistent_netsh;
                            if (run_netsh_for_adapter(
                                    downstream, L"interface ipv4 set address name=",
                                    L" source=static address=10.57.23.1 mask=255.255.255.0"
                                     L" gateway=none store=persistent",
                                    netsh_detail)) {
                                if (!mark_isolated_address_skip_as_source(
                                        downstream.interface_index, netsh_detail)) {
                                    detail = "netsh_address_configured " + netsh_detail;
                                    return false;
                                }
                                detail.clear();
                                return true;
                            }
                            detail = "ip_helper_attempt={" + native_detail +
                                "} netsh_fallback={" + netsh_detail + "}";
                            return false;
                        }
                        std::string snapshot_backend_detail;
                        if (!persist_snapshot_owned_address_backend(
                                snapshot,
                                RestoreAddressBackendHint::persistent_netsh,
                                snapshot_backend_detail)) {
                            detail = "snapshot_backend_update_failed " +
                                snapshot_backend_detail;
                            return false;
                        }
                        applied_address_backend =
                            AppliedAddressBackend::persistent_netsh;
                        const bool configured = run_netsh_for_adapter(
                            downstream, L"interface ipv4 set address name=",
                            L" source=static address=10.57.23.1 mask=255.255.255.0"
                             L" gateway=none store=persistent",
                            detail);
                        if (configured && !mark_isolated_address_skip_as_source(
                                downstream.interface_index, detail)) {
                            return false;
                        }
                        return configured;
                    }
                    case HostDirectLinkMutationStep::dns:
                        if (applied_address_backend ==
                            AppliedAddressBackend::transient_ip_helper) {
                            detail.clear();
                            return true;
                        }
                        return run_netsh_for_adapter(
                            downstream, L"interface ipv4 set dnsservers name=",
                            L" source=static address=none register=none validate=no",
                            detail);
                    case HostDirectLinkMutationStep::interface_policy:
                        return apply_isolated_interface_policy_with_fallback(
                            downstream, detail);
                    case HostDirectLinkMutationStep::verify:
                        detail = "verify_is_not_an_apply_step";
                        return false;
                }
                return false;
            },
            .verify = [&](std::string& detail) {
                return wait_for_isolated_address_preferred(
                    downstream.interface_index, detail);
            },
            .rollback = [&](std::string& detail) {
                const RestoreAddressBackendHint hint =
                    applied_address_backend == AppliedAddressBackend::transient_ip_helper
                    ? RestoreAddressBackendHint::transient_ip_helper
                    : (applied_address_backend == AppliedAddressBackend::persistent_netsh
                        ? RestoreAddressBackendHint::persistent_netsh
                        : RestoreAddressBackendHint::infer_from_live_state);
                return restore_snapshot_configuration(
                    snapshot, downstream, hint, detail);
            },
        });
    if (!transaction.succeeded) {
        outcome.status = HostDirectLinkStatus::failed;
        outcome.detail = transaction.detail;
        if (transaction.rollback_succeeded) {
            std::string remove_detail;
            if (!remove_snapshot_file(remove_detail)) {
                outcome.detail += " " + remove_detail;
            }
        }
        return outcome;
    }
    outcome.status = HostDirectLinkStatus::provisioned;
    outcome.detail = std::string("isolated_ipv4_ready_no_gateway_no_dns address_backend=") +
        (applied_address_backend == AppliedAddressBackend::transient_ip_helper
             ? "ip_helper_transient" : "netsh_persistent") +
        " preferred_backend=" +
        (prefer_persistent_backend ? "persistent_netsh" : "auto") +
        " dhcp_explicit_source_required=1 isolated_subnet_state={" +
        describe_host_isolated_subnet_state() +
        "} coexisting_preexisting_ipv4=" +
        (coexisting_preexisting_ipv4 ? "1" : "0") +
        " interface_policy=ip_helper_or_diagnostic_fallback restore_snapshot=pending";
    return outcome;
}

HostDirectLinkProvisioningResult ensure_host_direct_link_ipv4_automatically() {
    HostDirectLinkProvisioningResult outcome = ensure_host_direct_link_ipv4();
    if (outcome.status != HostDirectLinkStatus::requires_elevation) return outcome;

    std::string worker_error;
    if (!launch_host_direct_link_provisioning_worker(worker_error)) {
        outcome.status = HostDirectLinkStatus::failed;
        outcome.detail = worker_error;
        return outcome;
    }
    return ensure_host_direct_link_ipv4();
}

bool launch_host_direct_link_provisioning_worker(std::string& detail) {
    const bool prefer_persistent_backend =
        g_prefer_persistent_address_backend.load(std::memory_order_relaxed);
    SetEnvironmentVariableW(
        kPreferPersistentBackendEnv,
        prefer_persistent_backend ? L"1" : nullptr);
    const bool launched = launch_elevated_worker(
        kHostDirectLinkWorkerArgument, kProvisioningWorkerTimeoutMs, detail);
    SetEnvironmentVariableW(kPreferPersistentBackendEnv, nullptr);
    if (!detail.empty()) {
        detail += prefer_persistent_backend
            ? " preferred_backend=persistent_netsh"
            : " preferred_backend=auto";
    }
    return launched;
}

HostDirectLinkRestorationResult restore_host_direct_link_ipv4() {
    HostDirectLinkRestorationResult outcome{};
    const std::filesystem::path path = direct_link_snapshot_path();
    if (!path.empty()) outcome.snapshot_path = wide_to_utf8(path.native());
    if (path.empty()) {
        outcome.status = HostDirectLinkRestoreStatus::failed;
        outcome.detail = "snapshot_local_app_data_unavailable";
        return outcome;
    }
    std::error_code exists_error;
    if (!std::filesystem::exists(path, exists_error)) {
        outcome.status = exists_error
            ? HostDirectLinkRestoreStatus::failed
            : HostDirectLinkRestoreStatus::not_required;
        outcome.detail = exists_error
            ? "snapshot_exists_check_failed win32=" + std::to_string(exists_error.value())
            : "no_pending_direct_link_snapshot";
        return outcome;
    }
    HostDirectLinkChangeSnapshot snapshot{};
    if (!load_snapshot(snapshot, outcome.detail)) {
        outcome.status = HostDirectLinkRestoreStatus::unsafe_snapshot;
        return outcome;
    }
    outcome.snapshot_sha256 = snapshot.sha256;
    const auto adapters = enumerate_network_profiles();
    const HostNetworkAdapterProfile* downstream = find_snapshot_adapter(snapshot, adapters);
    if (downstream == nullptr ||
        !host_adapter_has_physical_connector_identity(
            HostAdapterIdentityFacts{
                .hardware_interface = downstream->hardware_interface,
                .connector_present = downstream->connector_present,
                .filter_interface = downstream->filter_interface,
                .endpoint_interface = downstream->endpoint_interface,
                .software_loopback_or_tunnel = downstream->virtual_or_loopback,
                .connection_name = downstream->connection_name,
                .description = downstream->description,
            }) ||
        downstream->transport != HostAdapterTransport::ethernet ||
        downstream->has_default_gateway) {
        outcome.status = HostDirectLinkRestoreStatus::unsafe_snapshot;
        outcome.detail = "snapshot_adapter_identity_or_route_mismatch";
        return outcome;
    }
    outcome.downstream_name = downstream->connection_name;
    if (snapshot_configuration_matches(snapshot)) {
        if (!remove_snapshot_file(outcome.detail)) {
            outcome.status = HostDirectLinkRestoreStatus::failed;
            return outcome;
        }
        outcome.status = HostDirectLinkRestoreStatus::restored;
        outcome.detail = "stale_snapshot_removed_configuration_already_restored";
        return outcome;
    }
    if (!process_is_elevated()) {
        outcome.status = HostDirectLinkRestoreStatus::requires_elevation;
        outcome.detail = "direct_link_restore_requires_elevation";
        return outcome;
    }
    if (!restore_snapshot_configuration(
            snapshot, *downstream,
            RestoreAddressBackendHint::infer_from_live_state, outcome.detail)) {
        outcome.status = HostDirectLinkRestoreStatus::failed;
        return outcome;
    }
    if (!remove_snapshot_file(outcome.detail)) {
        outcome.status = HostDirectLinkRestoreStatus::failed;
        return outcome;
    }
    outcome.status = HostDirectLinkRestoreStatus::restored;
    outcome.detail = "original_wired_configuration_restored";
    return outcome;
}

HostDirectLinkRestorationResult restore_host_direct_link_ipv4_automatically() {
    HostDirectLinkRestorationResult outcome = restore_host_direct_link_ipv4();
    if (outcome.status != HostDirectLinkRestoreStatus::requires_elevation) return outcome;
    std::string worker_error;
    if (!launch_host_direct_link_restore_worker(worker_error)) {
        outcome.status = HostDirectLinkRestoreStatus::failed;
        outcome.detail = worker_error;
        return outcome;
    }
    outcome.status = HostDirectLinkRestoreStatus::restored;
    outcome.detail = worker_error;
    return outcome;
}

bool launch_host_direct_link_restore_worker(std::string& detail) {
    return launch_elevated_worker(
        kHostDirectLinkRestoreWorkerArgument, kRestorationWorkerTimeoutMs, detail);
}

bool launch_host_firewall_provisioning_worker(std::string& detail) {
    return launch_elevated_worker(
        kHostFirewallWorkerArgument, kFirewallWorkerTimeoutMs, detail);
}

HostFirewallProvisioningResult ensure_host_firewall_rules_automatically() {
    HostFirewallProvisioningResult outcome = ensure_host_firewall_rules();
    if (outcome.status != HostFirewallStatus::requires_elevation) return outcome;
    const std::string initial_detail = outcome.detail;
    std::string worker_detail;
    if (!launch_host_firewall_provisioning_worker(worker_detail)) {
        outcome.status = HostFirewallStatus::failed;
        outcome.detail = "stage=firewall_elevated_worker " + worker_detail +
            " initial={" + initial_detail + '}';
        return outcome;
    }
    outcome = ensure_host_firewall_rules();
    outcome.detail += " elevated_worker={" + worker_detail + '}';
    return outcome;
}

int run_host_direct_link_provisioning_worker() {
    wchar_t prefer_value[8]{};
    const DWORD prefer_length = GetEnvironmentVariableW(
        kPreferPersistentBackendEnv, prefer_value,
        static_cast<DWORD>(sizeof(prefer_value) / sizeof(prefer_value[0])));
    set_host_direct_link_prefer_persistent_backend(
        prefer_length > 0U && prefer_value[0] == L'1');
    const HostDirectLinkProvisioningResult outcome = ensure_host_direct_link_ipv4();
    if (!host_direct_link_is_ready(outcome.status)) return static_cast<int>(ERROR_GEN_FAILURE);
    const HostFirewallProvisioningResult firewall =
        ensure_host_firewall_rules();
    if (host_firewall_is_ready(firewall.status)) {
        return static_cast<int>(ERROR_SUCCESS);
    }
    // The elevated worker owns the whole initial mutation boundary. Do not
    // leave a newly numbered interface behind when its required firewall
    // contract could not be installed.
    static_cast<void>(restore_host_direct_link_ipv4());
    return static_cast<int>(ERROR_GEN_FAILURE);
}

int run_host_direct_link_restore_worker() {
    const HostDirectLinkRestorationResult outcome = restore_host_direct_link_ipv4();
    return outcome.status == HostDirectLinkRestoreStatus::restored ||
        outcome.status == HostDirectLinkRestoreStatus::not_required
        ? static_cast<int>(ERROR_SUCCESS) : static_cast<int>(ERROR_GEN_FAILURE);
}

int run_host_firewall_provisioning_worker() {
    const HostFirewallProvisioningResult outcome = ensure_host_firewall_rules();
    return host_firewall_is_ready(outcome.status)
        ? static_cast<int>(ERROR_SUCCESS) : static_cast<int>(ERROR_GEN_FAILURE);
}

bool host_direct_link_is_ready(HostDirectLinkStatus status) noexcept {
    return status == HostDirectLinkStatus::already_ready || status == HostDirectLinkStatus::provisioned;
}

const char* host_direct_link_status_name(HostDirectLinkStatus status) noexcept {
    switch (status) {
        case HostDirectLinkStatus::not_required: return "not_required";
        case HostDirectLinkStatus::already_ready: return "already_ready";
        case HostDirectLinkStatus::provisioned: return "provisioned";
        case HostDirectLinkStatus::no_wired_adapter: return "no_wired_adapter";
        case HostDirectLinkStatus::no_upstream_adapter: return "no_upstream_adapter";
        case HostDirectLinkStatus::requires_elevation: return "requires_elevation";
        case HostDirectLinkStatus::conflicting_sharing: return "conflicting_sharing";
        case HostDirectLinkStatus::ambiguous_wired_adapter: return "ambiguous_wired_adapter";
        case HostDirectLinkStatus::unavailable: return "unavailable";
        case HostDirectLinkStatus::failed: return "failed";
    }
    return "unknown";
}

const char* host_direct_link_restore_status_name(
    HostDirectLinkRestoreStatus status) noexcept {
    switch (status) {
        case HostDirectLinkRestoreStatus::not_required: return "not_required";
        case HostDirectLinkRestoreStatus::restored: return "restored";
        case HostDirectLinkRestoreStatus::requires_elevation: return "requires_elevation";
        case HostDirectLinkRestoreStatus::unsafe_snapshot: return "unsafe_snapshot";
        case HostDirectLinkRestoreStatus::failed: return "failed";
    }
    return "unknown";
}

const char* host_direct_link_mutation_step_name(
    HostDirectLinkMutationStep step) noexcept {
    switch (step) {
        case HostDirectLinkMutationStep::address: return "address";
        case HostDirectLinkMutationStep::dns: return "dns";
        case HostDirectLinkMutationStep::interface_policy: return "interface_policy";
        case HostDirectLinkMutationStep::verify: return "verify";
    }
    return "unknown";
}

}  // namespace vfdual
