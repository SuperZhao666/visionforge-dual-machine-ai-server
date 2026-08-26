#include "vfdual/host_firewall_provisioner.hpp"
#include "vfdual/host_release_identity_policy.hpp"

#include "vfdual/wired_link_contract.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <netfw.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string_view>
#include <utility>

namespace vfdual {
namespace {

using Microsoft::WRL::ComPtr;

inline constexpr wchar_t kDhcpRuleName[] = L"VF Host CAT6 DHCP Inbound";
inline constexpr wchar_t kAnnouncementRuleName[] =
    L"VF Host CAT6 Announcement Inbound";
inline constexpr wchar_t kIdrRuleName[] = L"VF Host CAT6 IDR Inbound";
inline constexpr wchar_t kWirelessAnnouncementRuleName[] =
    L"VF Host Wireless LAN Announcement Inbound";
inline constexpr wchar_t kWirelessIdrRuleName[] =
    L"VF Host Wireless LAN IDR Inbound";
inline constexpr wchar_t kCat6FirstPairingRuleName[] =
    L"VF Host CAT6 First Pairing Inbound";
inline constexpr wchar_t kWirelessFirstPairingRuleName[] =
    L"VF Host Wireless LAN First Pairing Inbound";
inline constexpr wchar_t kCat6AuthenticatedControlRuleName[] =
    L"VF Host CAT6 Authenticated Control Inbound";
inline constexpr wchar_t kWirelessAuthenticatedControlRuleName[] =
    L"VF Host Wireless LAN Authenticated Control Inbound";
inline constexpr wchar_t kCat6RuleDescription[] =
    L"VF Host isolated CAT6 transport";
inline constexpr wchar_t kWirelessRuleDescription[] =
    L"VF Host wireless LAN UDP transport";
inline constexpr wchar_t kCat6FirstPairingRuleDescription[] =
    L"VF Host isolated CAT6 activation-only pairing";
inline constexpr wchar_t kWirelessFirstPairingRuleDescription[] =
    L"VF Host wireless LAN activation-only pairing";
inline constexpr wchar_t kCat6AuthenticatedControlRuleDescription[] =
    L"VF Host isolated CAT6 bound authenticated control";
inline constexpr wchar_t kWirelessAuthenticatedControlRuleDescription[] =
    L"VF Host wireless LAN bound authenticated control";
inline constexpr wchar_t kRuleGrouping[] = L"VF Host Transport";
inline constexpr wchar_t kLegacyDhcpRuleName[] =
    L"VisionForge Host CAT6 DHCP Inbound";
inline constexpr wchar_t kLegacyAnnouncementRuleName[] =
    L"VisionForge Host CAT6 Announcement Inbound";
inline constexpr wchar_t kLegacyIdrRuleName[] =
    L"VisionForge Host CAT6 IDR Inbound";
inline constexpr wchar_t kLegacyWirelessAnnouncementRuleName[] =
    L"VisionForge Host Wireless LAN Announcement Inbound";
inline constexpr wchar_t kLegacyWirelessIdrRuleName[] =
    L"VisionForge Host Wireless LAN IDR Inbound";
inline constexpr wchar_t kLegacyCat6RuleDescription[] =
    L"VisionForge Host isolated CAT6 transport";
inline constexpr wchar_t kLegacyWirelessRuleDescription[] =
    L"VisionForge Host wireless LAN UDP transport";
inline constexpr wchar_t kLegacyRuleGrouping[] = L"VisionForge Host Transport";
inline constexpr wchar_t kLegacyCat6RuleGrouping[] = L"VisionForge Host CAT6";
inline constexpr wchar_t kCanonicalHostExecutableName[] = L"VFHost.exe";
inline constexpr wchar_t kLegacyHostExecutableName[] = L"VisionForgeHost.exe";
inline constexpr wchar_t kLegacyPortableHostExecutableName[] =
    L"VisionForgeHost_Portable_Test_20260723.exe";
inline constexpr wchar_t kWiredInterfaceType[] = L"LAN";
inline constexpr wchar_t kLocalNetworkInterfaceTypes[] = L"LAN,Wireless";
inline constexpr wchar_t kLegacyWirelessInterfaceType[] = L"Wireless";
inline constexpr char kAnyLocalAddress[] = "*";
inline constexpr char kAnyRemoteAddress[] = "*";
inline constexpr char kLocalSubnet[] = "LocalSubnet";
inline constexpr std::uint16_t kAnyFirewallPort = 0U;

long firewall_protocol_number(HostFirewallProtocol protocol) noexcept {
    return protocol == HostFirewallProtocol::tcp
        ? NET_FW_IP_PROTOCOL_TCP : NET_FW_IP_PROTOCOL_UDP;
}

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

struct EnumeratedRule final {
    bool readable{};
    HostFirewallRuleSnapshot snapshot;
};

struct RuleReconciliationPlan final {
    HostFirewallRulePolicy desired;
    std::vector<HostFirewallRuleSnapshot> original;
    bool needs_reconciliation{};
};

struct LegacyRuleBranding final {
    std::wstring_view name;
    std::wstring_view description;
};

bool firewall_rule_is_owned(
    const HostFirewallRulePolicy& desired,
    const HostFirewallRuleSnapshot& snapshot) noexcept;

std::string narrow_utf8(std::wstring_view value);
bool equals_insensitive(
    std::wstring_view left, std::wstring_view right) noexcept;

std::optional<LegacyRuleBranding> legacy_rule_branding(
    std::wstring_view current_name) noexcept {
    if (equals_insensitive(current_name, kDhcpRuleName)) {
        return LegacyRuleBranding{kLegacyDhcpRuleName, kLegacyCat6RuleDescription};
    }
    if (equals_insensitive(current_name, kAnnouncementRuleName)) {
        return LegacyRuleBranding{
            kLegacyAnnouncementRuleName, kLegacyCat6RuleDescription};
    }
    if (equals_insensitive(current_name, kIdrRuleName)) {
        return LegacyRuleBranding{kLegacyIdrRuleName, kLegacyCat6RuleDescription};
    }
    if (equals_insensitive(current_name, kWirelessAnnouncementRuleName)) {
        return LegacyRuleBranding{
            kLegacyWirelessAnnouncementRuleName,
            kLegacyWirelessRuleDescription};
    }
    if (equals_insensitive(current_name, kWirelessIdrRuleName)) {
        return LegacyRuleBranding{
            kLegacyWirelessIdrRuleName, kLegacyWirelessRuleDescription};
    }
    return std::nullopt;
}

bool firewall_rule_branding_is_owned(
    const HostFirewallRulePolicy& desired,
    std::wstring_view name,
    std::wstring_view description,
    std::wstring_view grouping) noexcept {
    if (equals_insensitive(desired.name, name) &&
        desired.description == description && desired.grouping == grouping) {
        return true;
    }
    const auto legacy = legacy_rule_branding(desired.name);
    if (!legacy.has_value() || !equals_insensitive(legacy->name, name) ||
        legacy->description != description) {
        return false;
    }
    return grouping == kLegacyRuleGrouping ||
        (equals_insensitive(desired.interface_types, kWiredInterfaceType) &&
         grouping == kLegacyCat6RuleGrouping);
}

std::string format_hresult(HRESULT result) {
    std::ostringstream value;
    value << "hresult=0x" << std::hex << static_cast<unsigned long>(result)
          << std::dec << " signed=" << static_cast<long>(result);
    wchar_t* message{};
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, static_cast<DWORD>(result), 0,
        reinterpret_cast<wchar_t*>(&message), 0, nullptr);
    if (length != 0U && message != nullptr) {
        std::wstring text{message, length};
        while (!text.empty() &&
               (text.back() == L'\r' || text.back() == L'\n' ||
                text.back() == L' ' || text.back() == L'\t')) {
            text.pop_back();
        }
        if (!text.empty()) value << " message=[" << narrow_utf8(text) << ']';
    }
    if (message != nullptr) LocalFree(message);
    return value.str();
}

bool equals_insensitive(std::wstring_view left, std::wstring_view right) noexcept {
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        const wchar_t left_character = left[index] == L'/' ? L'\\' : left[index];
        const wchar_t right_character = right[index] == L'/' ? L'\\' : right[index];
        if (std::towlower(left_character) != std::towlower(right_character)) return false;
    }
    return true;
}

std::wstring_view trim_wide(std::wstring_view value) noexcept {
    while (!value.empty() &&
           (value.front() == L' ' || value.front() == L'\t')) {
        value.remove_prefix(1U);
    }
    while (!value.empty() &&
           (value.back() == L' ' || value.back() == L'\t')) {
        value.remove_suffix(1U);
    }
    return value;
}

std::optional<std::uint32_t> firewall_interface_type_mask(
    std::wstring_view value) noexcept {
    if (value.empty()) return 0U;
    std::uint32_t mask{};
    std::size_t offset{};
    while (offset <= value.size()) {
        const std::size_t separator = value.find(L',', offset);
        const std::size_t end = separator == std::wstring_view::npos
            ? value.size() : separator;
        const std::wstring_view token = trim_wide(
            value.substr(offset, end - offset));
        std::uint32_t token_mask{};
        if (equals_insensitive(token, L"LAN")) token_mask = 1U << 0U;
        else if (equals_insensitive(token, L"Wireless")) token_mask = 1U << 1U;
        else if (equals_insensitive(token, L"RemoteAccess")) token_mask = 1U << 2U;
        else if (equals_insensitive(token, L"All")) token_mask = 1U << 3U;
        else return std::nullopt;
        mask |= token_mask;
        if (separator == std::wstring_view::npos) break;
        offset = separator + 1U;
    }
    return mask;
}

bool firewall_interface_types_equal(
    std::wstring_view left,
    std::wstring_view right) noexcept {
    const auto left_mask = firewall_interface_type_mask(left);
    const auto right_mask = firewall_interface_type_mask(right);
    return left_mask.has_value() && right_mask.has_value() &&
        *left_mask == *right_mask;
}

bool firewall_interface_types_are_owned(
    const HostFirewallRulePolicy& desired,
    const HostFirewallRuleSnapshot& existing) noexcept {
    if (firewall_interface_types_equal(
            desired.interface_types, existing.interface_types)) {
        return true;
    }
    const bool local_network_rule =
        equals_insensitive(desired.name, kWirelessAnnouncementRuleName) ||
        equals_insensitive(desired.name, kWirelessIdrRuleName) ||
        equals_insensitive(desired.name, kWirelessFirstPairingRuleName) ||
        equals_insensitive(
            desired.name, kWirelessAuthenticatedControlRuleName);
    return local_network_rule &&
        firewall_interface_types_equal(
            desired.interface_types, kLocalNetworkInterfaceTypes) &&
        firewall_interface_types_equal(
            existing.interface_types, kLegacyWirelessInterfaceType);
}

std::wstring take_bstr(BSTR value) {
    std::wstring result = value == nullptr ? std::wstring{} : std::wstring{value, SysStringLen(value)};
    SysFreeString(value);
    return result;
}

template <typename Interface>
bool read_bstr_property(
    Interface* object,
    HRESULT (STDMETHODCALLTYPE Interface::*getter)(BSTR*),
    std::wstring& destination) {
    if (object == nullptr) return false;
    BSTR value{};
    const HRESULT result = (object->*getter)(&value);
    if (FAILED(result)) {
        SysFreeString(value);
        return false;
    }
    destination = value == nullptr
        ? std::wstring{} : std::wstring{value, SysStringLen(value)};
    SysFreeString(value);
    return true;
}

std::string narrow_ascii(std::wstring_view value) {
    std::string result;
    result.reserve(value.size());
    for (const wchar_t character : value) {
        result.push_back(character >= 0 && character <= 0x7f
            ? static_cast<char>(character) : '?');
    }
    return result;
}

std::string narrow_utf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) return narrow_ascii(value);
    std::string result(static_cast<std::size_t>(required), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        result.data(), required, nullptr, nullptr);
    return written == required ? result : narrow_ascii(value);
}

std::string join_rule_names(const std::vector<std::wstring>& names) {
    std::string result;
    for (const auto& name : names) {
        if (!result.empty()) result.push_back('|');
        result += narrow_utf8(name);
    }
    return result;
}

std::string_view trim_ascii(std::string_view value) noexcept {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1U);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1U);
    }
    return value;
}

std::string canonical_firewall_addresses(std::string_view value) {
    // Windows Firewall normalizes a single IPv4 host to either /32 or an
    // explicit host mask when the rule is persisted.  Preserve token order and
    // reject every wider prefix so comparison cannot silently broaden a rule.
    constexpr std::string_view kIpv4HostMask = "/255.255.255.255";
    constexpr std::string_view kIpv4HostPrefix = "/32";
    std::string canonical;
    std::size_t offset{};
    while (offset <= value.size()) {
        const std::size_t separator = value.find(',', offset);
        const std::size_t end = separator == std::string_view::npos
            ? value.size() : separator;
        std::string_view token = trim_ascii(value.substr(offset, end - offset));
        if (token.ends_with(kIpv4HostMask)) {
            token.remove_suffix(kIpv4HostMask.size());
        } else if (token.ends_with(kIpv4HostPrefix)) {
            token.remove_suffix(kIpv4HostPrefix.size());
        }
        if (!canonical.empty()) canonical.push_back(',');
        canonical.append(token);
        if (separator == std::string_view::npos) break;
        offset = separator + 1U;
    }
    return canonical;
}

bool firewall_addresses_equal(
    std::string_view desired, std::string_view existing) {
    return canonical_firewall_addresses(desired) ==
        canonical_firewall_addresses(existing);
}

std::string describe_rule_mismatch(
    const HostFirewallRulePolicy& desired,
    const HostFirewallRuleSnapshot& existing) {
    const auto bool_value = [](bool value) { return value ? "1" : "0"; };
    if (!equals_insensitive(desired.name, existing.name)) return "field=name";
    if (existing.description != desired.description) return "field=description";
    if (existing.grouping != desired.grouping) return "field=grouping";
    if (!equals_insensitive(desired.application_path, existing.application_path)) {
        return "field=application_path expected=[" +
            narrow_utf8(desired.application_path) + "] actual=[" +
            narrow_utf8(existing.application_path) + "]";
    }
    if (!equals_insensitive(desired.interface_name, existing.interface_name)) {
        return "field=interface_name";
    }
    if (!firewall_interface_types_equal(
            desired.interface_types, existing.interface_types)) {
        return "field=interface_types";
    }
    if (!firewall_addresses_equal(desired.local_address, existing.local_address)) {
        return "field=local_address expected=" + desired.local_address +
            " actual=" + existing.local_address;
    }
    if (!firewall_addresses_equal(desired.remote_addresses, existing.remote_addresses)) {
        return "field=remote_addresses expected=" + desired.remote_addresses +
            " actual=" + existing.remote_addresses;
    }
    if (desired.local_port != existing.local_port) {
        return "field=local_port expected=" + std::to_string(desired.local_port) +
            " actual=" + std::to_string(existing.local_port);
    }
    if (desired.remote_port != existing.remote_port) {
        return "field=remote_port expected=" + std::to_string(desired.remote_port) +
            " actual=" + std::to_string(existing.remote_port);
    }
    if (existing.protocol != desired.protocol ||
        existing.protocol_number != firewall_protocol_number(desired.protocol)) {
        return "field=protocol";
    }
    if (desired.inbound != existing.inbound) {
        return "field=inbound expected=" + std::string{bool_value(desired.inbound)} +
            " actual=" + bool_value(existing.inbound);
    }
    if (desired.enabled != existing.enabled) {
        return "field=enabled expected=" + std::string{bool_value(desired.enabled)} +
            " actual=" + bool_value(existing.enabled);
    }
    if (desired.allow != existing.allow) return "field=action";
    if (desired.edge_traversal != existing.edge_traversal ||
        existing.edge_traversal_options != NET_FW_EDGE_TRAVERSAL_TYPE_DENY) {
        return "field=edge_traversal";
    }
    if (desired.service_name != existing.service_name) return "field=service_name";
    if (desired.local_app_package_id != existing.local_app_package_id) {
        return "field=local_app_package_id";
    }
    if (desired.local_user_owner != existing.local_user_owner) return "field=local_user_owner";
    if (desired.local_user_authorized_list != existing.local_user_authorized_list) {
        return "field=local_user_authorized_list";
    }
    if (desired.remote_user_authorized_list != existing.remote_user_authorized_list) {
        return "field=remote_user_authorized_list";
    }
    if (desired.remote_machine_authorized_list != existing.remote_machine_authorized_list) {
        return "field=remote_machine_authorized_list";
    }
    if (desired.secure_flags != existing.secure_flags) return "field=secure_flags";
    if (!existing.all_profiles) return "field=profiles";
    return "field=unknown";
}

std::string describe_rule_snapshot(const HostFirewallRuleSnapshot& snapshot) {
    std::ostringstream detail;
    detail << "actual={name=[" << narrow_utf8(snapshot.name)
           << "] description=[" << narrow_utf8(snapshot.description)
           << "] grouping=[" << narrow_utf8(snapshot.grouping)
           << "] application=[" << narrow_utf8(snapshot.application_path)
           << "] interface=[" << narrow_utf8(snapshot.interface_name)
           << "] interface_types=[" << narrow_utf8(snapshot.interface_types)
           << "] local_address=[" << snapshot.local_address
           << "] remote_addresses=[" << snapshot.remote_addresses
           << "] local_port=" << snapshot.local_port
           << " remote_port=" << snapshot.remote_port
           << " protocol_number=" << snapshot.protocol_number
           << " inbound=" << snapshot.inbound
           << " enabled=" << snapshot.enabled
           << " allow=" << snapshot.allow
           << " edge_traversal=" << snapshot.edge_traversal
           << " edge_options=" << snapshot.edge_traversal_options
           << " profiles=0x" << std::hex
           << static_cast<unsigned long>(snapshot.profiles) << std::dec
           << " service=[" << narrow_utf8(snapshot.service_name)
           << "] package=[" << narrow_utf8(snapshot.local_app_package_id)
           << "] owner=[" << narrow_utf8(snapshot.local_user_owner)
           << "] secure_flags=" << snapshot.secure_flags << '}';
    return detail.str();
}

std::string describe_active_profiles(
    const HostFirewallActiveProfileState& state) {
    std::ostringstream detail;
    detail << "profiles={mask=0x" << std::hex
           << static_cast<unsigned long>(state.active_profile_mask) << std::dec
           << " domain_active=" << state.domain_active
           << " domain_enabled=" << state.domain_enabled
           << " private_active=" << state.private_active
           << " private_enabled=" << state.private_enabled
           << " public_active=" << state.public_active
           << " public_enabled=" << state.public_enabled
           << " unknown_active=" << state.unknown_profile_active << '}';
    return detail.str();
}

std::optional<std::uint16_t> parse_port(std::wstring_view value) noexcept {
    if (value.empty() || value == L"*") return kAnyFirewallPort;
    std::uint32_t port{};
    for (const wchar_t character : value) {
        if (character < L'0' || character > L'9') return std::nullopt;
        port = port * 10U + static_cast<std::uint32_t>(character - L'0');
        if (port > 65'535U) return std::nullopt;
    }
    return static_cast<std::uint16_t>(port);
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

std::optional<std::wstring> current_executable_path(std::string& detail) {
    std::wstring module_path(512U, L'\0');
    for (;;) {
        const DWORD length = GetModuleFileNameW(
            nullptr, module_path.data(), static_cast<DWORD>(module_path.size()));
        if (length == 0U) {
            detail = "stage=resolve_executable win32=" + std::to_string(GetLastError());
            return std::nullopt;
        }
        if (length < module_path.size() - 1U) {
            module_path.resize(length);
            break;
        }
        if (module_path.size() >= 32'768U) {
            detail = "stage=resolve_executable reason=path_too_long";
            return std::nullopt;
        }
        module_path.resize(module_path.size() * 2U);
    }

    const DWORD required = GetFullPathNameW(module_path.c_str(), 0U, nullptr, nullptr);
    if (required == 0U) {
        detail = "stage=normalize_executable win32=" + std::to_string(GetLastError());
        return std::nullopt;
    }
    std::wstring absolute_path(required, L'\0');
    const DWORD length = GetFullPathNameW(
        module_path.c_str(), required, absolute_path.data(), nullptr);
    if (length == 0U || length >= required) {
        detail = "stage=normalize_executable win32=" + std::to_string(GetLastError());
        return std::nullopt;
    }
    absolute_path.resize(length);
    try {
        std::filesystem::path normalized = std::filesystem::path{absolute_path}.lexically_normal();
        if (!normalized.is_absolute()) {
            detail = "stage=normalize_executable reason=path_not_absolute";
            return std::nullopt;
        }
        return normalized.native();
    } catch (const std::filesystem::filesystem_error&) {
        detail = "stage=normalize_executable reason=invalid_path";
        return std::nullopt;
    }
}

bool read_interface_names(const VARIANT& value, std::vector<std::wstring>& names) {
    if ((value.vt & VT_ARRAY) == 0 || value.parray == nullptr) return false;
    LONG lower{};
    LONG upper{};
    if (FAILED(SafeArrayGetLBound(value.parray, 1U, &lower)) ||
        FAILED(SafeArrayGetUBound(value.parray, 1U, &upper))) return false;
    const VARTYPE element_type = static_cast<VARTYPE>(value.vt & VT_TYPEMASK);
    for (LONG index = lower; index <= upper; ++index) {
        if (element_type == VT_BSTR) {
            BSTR item{};
            if (FAILED(SafeArrayGetElement(value.parray, &index, &item))) return false;
            names.push_back(take_bstr(item));
            continue;
        }
        if (element_type != VT_VARIANT) return false;
        VARIANT item;
        VariantInit(&item);
        const HRESULT result = SafeArrayGetElement(value.parray, &index, &item);
        if (FAILED(result) || item.vt != VT_BSTR) {
            VariantClear(&item);
            return false;
        }
        names.push_back(item.bstrVal == nullptr
            ? std::wstring{} : std::wstring{item.bstrVal, SysStringLen(item.bstrVal)});
        VariantClear(&item);
    }
    return true;
}

bool read_rule_snapshot(INetFwRule3* rule, HostFirewallRuleSnapshot& snapshot) {
    if (rule == nullptr) return false;
    INetFwRule* base_rule = rule;
    INetFwRule2* rule2 = rule;
    std::wstring local_address;
    std::wstring remote_addresses;
    std::wstring local_ports;
    std::wstring remote_ports;
    if (!read_bstr_property(base_rule, &INetFwRule::get_Name, snapshot.name) ||
        !read_bstr_property(
            base_rule, &INetFwRule::get_Description, snapshot.description) ||
        !read_bstr_property(base_rule, &INetFwRule::get_Grouping, snapshot.grouping) ||
        !read_bstr_property(
            base_rule, &INetFwRule::get_ApplicationName, snapshot.application_path) ||
        !read_bstr_property(base_rule, &INetFwRule::get_ServiceName, snapshot.service_name) ||
        !read_bstr_property(base_rule, &INetFwRule::get_LocalAddresses, local_address) ||
        !read_bstr_property(base_rule, &INetFwRule::get_RemoteAddresses, remote_addresses) ||
        !read_bstr_property(base_rule, &INetFwRule::get_LocalPorts, local_ports) ||
        !read_bstr_property(base_rule, &INetFwRule::get_RemotePorts, remote_ports) ||
        !read_bstr_property(
            rule, &INetFwRule3::get_LocalAppPackageId, snapshot.local_app_package_id) ||
        !read_bstr_property(rule, &INetFwRule3::get_LocalUserOwner, snapshot.local_user_owner) ||
        !read_bstr_property(
            rule, &INetFwRule3::get_LocalUserAuthorizedList,
            snapshot.local_user_authorized_list) ||
        !read_bstr_property(
            rule, &INetFwRule3::get_RemoteUserAuthorizedList,
            snapshot.remote_user_authorized_list) ||
        !read_bstr_property(
            rule, &INetFwRule3::get_RemoteMachineAuthorizedList,
            snapshot.remote_machine_authorized_list)) return false;
    snapshot.local_address = narrow_ascii(local_address);
    snapshot.remote_addresses = narrow_ascii(remote_addresses);
    const auto local_port = parse_port(local_ports);
    const auto remote_port = parse_port(remote_ports);
    if (!local_port.has_value() || !remote_port.has_value()) return false;
    snapshot.local_port = *local_port;
    snapshot.remote_port = *remote_port;

    long protocol{};
    NET_FW_RULE_DIRECTION direction{};
    NET_FW_ACTION action{};
    VARIANT_BOOL enabled{VARIANT_FALSE};
    long profiles{};
    long edge_options{};
    if (FAILED(rule->get_Protocol(&protocol)) ||
        FAILED(rule->get_Direction(&direction)) ||
        FAILED(rule->get_Action(&action)) ||
        FAILED(rule->get_Enabled(&enabled)) ||
        FAILED(rule->get_Profiles(&profiles)) ||
        FAILED(rule2->get_EdgeTraversalOptions(&edge_options)) ||
        FAILED(rule->get_SecureFlags(&snapshot.secure_flags))) return false;
    snapshot.protocol = protocol == NET_FW_IP_PROTOCOL_UDP
        ? HostFirewallProtocol::udp : HostFirewallProtocol::tcp;
    snapshot.protocol_number = protocol;
    snapshot.inbound = direction == NET_FW_RULE_DIR_IN;
    snapshot.allow = action == NET_FW_ACTION_ALLOW;
    snapshot.enabled = enabled == VARIANT_TRUE;
    snapshot.profiles = profiles;
    snapshot.all_profiles = profiles == NET_FW_PROFILE2_ALL;
    snapshot.edge_traversal = edge_options != NET_FW_EDGE_TRAVERSAL_TYPE_DENY;
    snapshot.edge_traversal_options = edge_options;

    std::wstring interface_types;
    if (!read_bstr_property(
            base_rule, &INetFwRule::get_InterfaceTypes, interface_types)) return false;
    snapshot.interface_types = interface_types;
    VARIANT interfaces;
    VariantInit(&interfaces);
    const HRESULT interface_result = base_rule->get_Interfaces(&interfaces);
    std::vector<std::wstring> names;
    const bool no_specific_interfaces =
        SUCCEEDED(interface_result) &&
        (interfaces.vt == VT_EMPTY || interfaces.vt == VT_NULL);
    const bool interfaces_read = no_specific_interfaces ||
        (SUCCEEDED(interface_result) && read_interface_names(interfaces, names));
    VariantClear(&interfaces);
    if (!interfaces_read || names.size() > 1U) return false;
    snapshot.interface_name = names.empty() ? std::wstring{} : std::move(names.front());
    return true;
}

HRESULT enumerate_rules_named(
    INetFwRules* rules,
    std::wstring_view name,
    std::vector<EnumeratedRule>& matches) {
    if (rules == nullptr) return E_POINTER;
    ComPtr<IUnknown> unknown_enumerator;
    HRESULT result = rules->get__NewEnum(&unknown_enumerator);
    if (FAILED(result) || unknown_enumerator == nullptr) {
        return FAILED(result) ? result : E_NOINTERFACE;
    }
    ComPtr<IEnumVARIANT> enumerator;
    result = unknown_enumerator.As(&enumerator);
    if (FAILED(result) || enumerator == nullptr) {
        return FAILED(result) ? result : E_NOINTERFACE;
    }
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
        ComPtr<INetFwRule> base_rule;
        if (item.vt == VT_DISPATCH && item.pdispVal != nullptr) {
            result = item.pdispVal->QueryInterface(IID_PPV_ARGS(&base_rule));
        } else if (item.vt == VT_UNKNOWN && item.punkVal != nullptr) {
            result = item.punkVal->QueryInterface(IID_PPV_ARGS(&base_rule));
        } else {
            result = E_NOINTERFACE;
        }
        VariantClear(&item);
        if (FAILED(result) || base_rule == nullptr) {
            return FAILED(result) ? result : E_NOINTERFACE;
        }
        std::wstring existing_name;
        if (!read_bstr_property(base_rule.Get(), &INetFwRule::get_Name, existing_name)) {
            return E_FAIL;
        }
        if (!equals_insensitive(existing_name, name)) continue;
        EnumeratedRule match{};
        ComPtr<INetFwRule3> rule;
        if (SUCCEEDED(base_rule.As(&rule)) && rule != nullptr) {
            match.readable = read_rule_snapshot(rule.Get(), match.snapshot);
        }
        matches.push_back(std::move(match));
    }
}

HRESULT read_active_profile_state(
    INetFwPolicy2* policy, HostFirewallActiveProfileState& state) {
    if (policy == nullptr) return E_POINTER;
    long active_profiles{};
    HRESULT result = policy->get_CurrentProfileTypes(&active_profiles);
    if (FAILED(result)) return result;
    state.active_profile_mask = active_profiles;
    constexpr long kKnownProfiles = NET_FW_PROFILE2_DOMAIN |
        NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_PUBLIC;
    state.unknown_profile_active = (active_profiles & ~kKnownProfiles) != 0;
    const auto read_profile = [&](NET_FW_PROFILE_TYPE2 profile, bool& active, bool& enabled) {
        active = (active_profiles & static_cast<long>(profile)) != 0;
        if (!active) return S_OK;
        VARIANT_BOOL firewall_enabled{VARIANT_FALSE};
        const HRESULT profile_result = policy->get_FirewallEnabled(profile, &firewall_enabled);
        if (FAILED(profile_result)) return profile_result;
        enabled = firewall_enabled == VARIANT_TRUE;
        return S_OK;
    };
    if (FAILED(result = read_profile(
            NET_FW_PROFILE2_DOMAIN, state.domain_active, state.domain_enabled)) ||
        FAILED(result = read_profile(
            NET_FW_PROFILE2_PRIVATE, state.private_active, state.private_enabled)) ||
        FAILED(result = read_profile(
            NET_FW_PROFILE2_PUBLIC, state.public_active, state.public_enabled))) {
        return result;
    }
    return S_OK;
}

HRESULT read_rule_audit_entry(INetFwRule* rule, HostFirewallRuleAuditEntry& entry) {
    if (rule == nullptr) return E_POINTER;
    if (!read_bstr_property(rule, &INetFwRule::get_Name, entry.name) ||
        !read_bstr_property(rule, &INetFwRule::get_Description, entry.description) ||
        !read_bstr_property(rule, &INetFwRule::get_Grouping, entry.grouping) ||
        !read_bstr_property(
            rule, &INetFwRule::get_ApplicationName, entry.application_path)) {
        return E_FAIL;
    }
    NET_FW_RULE_DIRECTION direction{};
    NET_FW_ACTION action{};
    VARIANT_BOOL enabled{VARIANT_FALSE};
    HRESULT result{};
    if (FAILED(result = rule->get_Direction(&direction)) ||
        FAILED(result = rule->get_Action(&action)) ||
        FAILED(result = rule->get_Enabled(&enabled))) {
        return result;
    }
    entry.inbound = direction == NET_FW_RULE_DIR_IN;
    entry.allow = action == NET_FW_ACTION_ALLOW;
    entry.enabled = enabled == VARIANT_TRUE;
    return S_OK;
}

HRESULT find_conflicting_executable_rules(
    INetFwRules* rules,
    const std::wstring& executable_path,
    const std::vector<HostFirewallRulePolicy>& owned_rules,
    std::vector<std::wstring>& conflicts) {
    if (rules == nullptr) return E_POINTER;
    ComPtr<IUnknown> unknown_enumerator;
    HRESULT result = rules->get__NewEnum(&unknown_enumerator);
    if (FAILED(result) || unknown_enumerator == nullptr) {
        return FAILED(result) ? result : E_NOINTERFACE;
    }
    ComPtr<IEnumVARIANT> enumerator;
    result = unknown_enumerator.As(&enumerator);
    if (FAILED(result) || enumerator == nullptr) {
        return FAILED(result) ? result : E_NOINTERFACE;
    }

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
        ComPtr<INetFwRule> rule;
        if (item.vt == VT_DISPATCH && item.pdispVal != nullptr) {
            result = item.pdispVal->QueryInterface(IID_PPV_ARGS(&rule));
        } else if (item.vt == VT_UNKNOWN && item.punkVal != nullptr) {
            result = item.punkVal->QueryInterface(IID_PPV_ARGS(&rule));
        } else {
            result = E_NOINTERFACE;
        }
        VariantClear(&item);
        if (FAILED(result) || rule == nullptr) {
            return FAILED(result) ? result : E_NOINTERFACE;
        }
        HostFirewallRuleAuditEntry entry{};
        result = read_rule_audit_entry(rule.Get(), entry);
        if (FAILED(result)) return result;
        if (host_firewall_rule_is_conflicting_executable_allow(
                executable_path, owned_rules, entry)) {
            conflicts.push_back(std::move(entry.name));
            continue;
        }
        const bool relevant_allow = entry.inbound && entry.enabled && entry.allow &&
            equals_insensitive(executable_path, entry.application_path);
        if (!relevant_allow) continue;
        const auto desired = std::find_if(
            owned_rules.begin(), owned_rules.end(), [&](const auto& candidate) {
                return equals_insensitive(candidate.name, entry.name);
            });
        if (desired == owned_rules.end()) {
            conflicts.push_back(std::move(entry.name));
            continue;
        }
        ComPtr<INetFwRule3> rule3;
        HostFirewallRuleSnapshot snapshot{};
        result = rule.As(&rule3);
        if (FAILED(result) || rule3 == nullptr ||
            !read_rule_snapshot(rule3.Get(), snapshot)) {
            return FAILED(result) ? result : E_FAIL;
        }
        if (!firewall_rule_is_owned(*desired, snapshot)) {
            conflicts.push_back(std::move(entry.name));
        }
    }
}

template <typename Interface>
HRESULT put_bstr(HRESULT (STDMETHODCALLTYPE Interface::*setter)(BSTR),
                  Interface* rule, std::wstring_view value) {
    BSTR text = SysAllocStringLen(value.data(), static_cast<UINT>(value.size()));
    if (text == nullptr) return E_OUTOFMEMORY;
    const HRESULT result = (rule->*setter)(text);
    SysFreeString(text);
    return result;
}

HRESULT set_rule_interfaces(INetFwRule2* rule, const std::wstring& interface_name) {
    SAFEARRAY* array = SafeArrayCreateVector(VT_VARIANT, 0L, 1U);
    if (array == nullptr) return E_OUTOFMEMORY;
    VARIANT item;
    VariantInit(&item);
    item.vt = VT_BSTR;
    item.bstrVal = SysAllocStringLen(
        interface_name.data(), static_cast<UINT>(interface_name.size()));
    if (item.bstrVal == nullptr) {
        SafeArrayDestroy(array);
        return E_OUTOFMEMORY;
    }
    LONG index{};
    const HRESULT inserted = SafeArrayPutElement(array, &index, &item);
    VariantClear(&item);
    if (FAILED(inserted)) {
        SafeArrayDestroy(array);
        return inserted;
    }
    VARIANT interfaces;
    VariantInit(&interfaces);
    interfaces.vt = VT_ARRAY | VT_VARIANT;
    interfaces.parray = array;
    const HRESULT result = rule->put_Interfaces(interfaces);
    VariantClear(&interfaces);
    return result;
}

HostFirewallRuleSnapshot snapshot_from_policy(const HostFirewallRulePolicy& policy) {
    HostFirewallRuleSnapshot snapshot{};
    static_cast<HostFirewallRulePolicy&>(snapshot) = policy;
    snapshot.protocol_number = firewall_protocol_number(policy.protocol);
    snapshot.edge_traversal_options = NET_FW_EDGE_TRAVERSAL_TYPE_DENY;
    snapshot.profiles = NET_FW_PROFILE2_ALL;
    snapshot.all_profiles = true;
    return snapshot;
}

HRESULT create_rule_from_snapshot(
    const HostFirewallRuleSnapshot& snapshot,
    ComPtr<INetFwRule3>& rule) {
    HRESULT result = CoCreateInstance(
        CLSID_NetFwRule, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&rule));
    if (FAILED(result) || rule == nullptr) return FAILED(result) ? result : E_NOINTERFACE;
    INetFwRule* base_rule = rule.Get();
    const std::wstring local_port = std::to_wstring(snapshot.local_port);
    const std::wstring remote_port = snapshot.remote_port == kAnyFirewallPort
        ? L"*" : std::to_wstring(snapshot.remote_port);
    const std::wstring local_address{
        snapshot.local_address.begin(), snapshot.local_address.end()};
    const std::wstring remote_addresses{
        snapshot.remote_addresses.begin(), snapshot.remote_addresses.end()};
    const long protocol = snapshot.protocol_number;
    if (FAILED(result = put_bstr(&INetFwRule::put_Name, base_rule, snapshot.name)) ||
        FAILED(result = put_bstr(
            &INetFwRule::put_Description, base_rule, snapshot.description)) ||
        FAILED(result = put_bstr(
            &INetFwRule::put_ApplicationName, base_rule, snapshot.application_path)) ||
        (!snapshot.service_name.empty() && FAILED(result = put_bstr(
            &INetFwRule::put_ServiceName, base_rule, snapshot.service_name))) ||
        FAILED(result = base_rule->put_Protocol(protocol)) ||
        FAILED(result = put_bstr(&INetFwRule::put_LocalPorts, base_rule, local_port)) ||
        FAILED(result = put_bstr(&INetFwRule::put_RemotePorts, base_rule, remote_port)) ||
        FAILED(result = put_bstr(
            &INetFwRule::put_LocalAddresses, base_rule, local_address)) ||
        FAILED(result = put_bstr(
            &INetFwRule::put_RemoteAddresses, base_rule, remote_addresses)) ||
        FAILED(result = base_rule->put_Direction(
            snapshot.inbound ? NET_FW_RULE_DIR_IN : NET_FW_RULE_DIR_OUT)) ||
        (!snapshot.interface_name.empty() && FAILED(result =
            set_rule_interfaces(rule.Get(), snapshot.interface_name))) ||
        FAILED(result = put_bstr(
            &INetFwRule::put_InterfaceTypes, base_rule, snapshot.interface_types)) ||
        FAILED(result = base_rule->put_Profiles(snapshot.profiles)) ||
        FAILED(result = base_rule->put_EdgeTraversal(
            snapshot.edge_traversal ? VARIANT_TRUE : VARIANT_FALSE)) ||
        FAILED(result = rule->put_EdgeTraversalOptions(snapshot.edge_traversal_options)) ||
        FAILED(result = put_bstr(&INetFwRule::put_Grouping, base_rule, snapshot.grouping)) ||
        FAILED(result = base_rule->put_Action(
            snapshot.allow ? NET_FW_ACTION_ALLOW : NET_FW_ACTION_BLOCK)) ||
        FAILED(result = base_rule->put_Enabled(
            snapshot.enabled ? VARIANT_TRUE : VARIANT_FALSE))) return result;

    if ((!snapshot.local_app_package_id.empty() && FAILED(result = put_bstr(
            &INetFwRule3::put_LocalAppPackageId, rule.Get(),
            snapshot.local_app_package_id))) ||
        (!snapshot.local_user_owner.empty() && FAILED(result = put_bstr(
            &INetFwRule3::put_LocalUserOwner, rule.Get(), snapshot.local_user_owner))) ||
        (!snapshot.local_user_authorized_list.empty() && FAILED(result = put_bstr(
            &INetFwRule3::put_LocalUserAuthorizedList, rule.Get(),
            snapshot.local_user_authorized_list))) ||
        (!snapshot.remote_user_authorized_list.empty() && FAILED(result = put_bstr(
            &INetFwRule3::put_RemoteUserAuthorizedList, rule.Get(),
            snapshot.remote_user_authorized_list))) ||
        (!snapshot.remote_machine_authorized_list.empty() && FAILED(result = put_bstr(
            &INetFwRule3::put_RemoteMachineAuthorizedList, rule.Get(),
            snapshot.remote_machine_authorized_list))) ||
        FAILED(result = rule->put_SecureFlags(snapshot.secure_flags))) return result;
    return S_OK;
}

HRESULT create_rule(const HostFirewallRulePolicy& policy, ComPtr<INetFwRule3>& rule) {
    return create_rule_from_snapshot(snapshot_from_policy(policy), rule);
}

bool is_legacy_browser_download_name(std::wstring_view filename) noexcept {
    constexpr std::wstring_view kPrefix = L"VisionForgeHost (";
    constexpr std::wstring_view kSuffix = L").exe";
    if (filename.size() <= kPrefix.size() + kSuffix.size() ||
        !equals_insensitive(filename.substr(0, kPrefix.size()), kPrefix) ||
        !equals_insensitive(
            filename.substr(filename.size() - kSuffix.size()), kSuffix)) {
        return false;
    }
    const std::wstring_view duplicate_number = filename.substr(
        kPrefix.size(),
        filename.size() - kPrefix.size() - kSuffix.size());
    if (duplicate_number.empty() || duplicate_number.size() > 3U ||
        duplicate_number.front() == L'0') {
        return false;
    }
    return std::all_of(
        duplicate_number.begin(), duplicate_number.end(),
        [](wchar_t character) {
            return character >= L'0' && character <= L'9';
        });
}

bool has_host_executable_identity(
    std::wstring_view desired_application_path,
    std::wstring_view existing_application_path) noexcept {
    try {
        const std::filesystem::path desired_path{desired_application_path};
        const std::filesystem::path existing_path{existing_application_path};
        if (!desired_path.is_absolute() || !existing_path.is_absolute()) return false;
        if (equals_insensitive(desired_path.native(), existing_path.native())) return true;

        // V1.0.0 was briefly shipped under this portable-test name. Keep this
        // exact migration identity so the canonical build can repair its three
        // narrow CAT6 rules without accepting arbitrary Host executable names.
        const std::wstring filename = existing_path.filename().native();
        if (equals_insensitive(filename, kCanonicalHostExecutableName) ||
            equals_insensitive(filename, kLegacyHostExecutableName) ||
            equals_insensitive(filename, kLegacyPortableHostExecutableName) ||
            is_legacy_browser_download_name(filename) ||
            host_release_executable_name_is_recognized(filename)) {
            return true;
        }

        // A failed portable replacement is archived with a content-hash
        // suffix. Accept only this exact, machine-generated migration shape;
        // arbitrary VFHost*.exe and legacy VisionForgeHost*.exe names remain
        // untrusted.
        constexpr std::wstring_view kFailedPrefix = L"VFHost.failed-";
        constexpr std::wstring_view kLegacyFailedPrefix =
            L"VisionForgeHost.failed-";
        constexpr std::wstring_view kExecutableSuffix = L".exe";
        std::wstring_view failed_prefix;
        if (filename.size() > kFailedPrefix.size() + kExecutableSuffix.size() &&
            equals_insensitive(
                std::wstring_view{filename}.substr(0, kFailedPrefix.size()),
                kFailedPrefix)) {
            failed_prefix = kFailedPrefix;
        } else if (
            filename.size() >
                kLegacyFailedPrefix.size() + kExecutableSuffix.size() &&
            equals_insensitive(
                std::wstring_view{filename}.substr(
                    0, kLegacyFailedPrefix.size()),
                kLegacyFailedPrefix)) {
            failed_prefix = kLegacyFailedPrefix;
        } else {
            return false;
        }
        if (!equals_insensitive(
                std::wstring_view{filename}.substr(
                    filename.size() - kExecutableSuffix.size()),
                kExecutableSuffix)) return false;
        const std::wstring_view hash = std::wstring_view{filename}.substr(
            failed_prefix.size(),
            filename.size() - failed_prefix.size() - kExecutableSuffix.size());
        if (hash.size() != 16U && hash.size() != 64U) return false;
        return std::all_of(hash.begin(), hash.end(), [](wchar_t character) {
            return (character >= L'0' && character <= L'9') ||
                (character >= L'a' && character <= L'f') ||
                (character >= L'A' && character <= L'F');
        });
    } catch (...) {
        return false;
    }
}

bool firewall_rule_is_owned(
    const HostFirewallRulePolicy& desired,
    const HostFirewallRuleSnapshot& snapshot) noexcept {
    // Mutable marker strings alone are not ownership proof. A replaceable
    // previous rule must also retain the complete narrow transport fingerprint;
    // only a controlled executable/branding/interface-scope migration may differ.
    const bool legacy_cat6_rule =
        equals_insensitive(desired.interface_types, kWiredInterfaceType) &&
        snapshot.grouping == kLegacyCat6RuleGrouping;
    const bool compatible_interface =
        equals_insensitive(snapshot.interface_name, desired.interface_name) ||
        (legacy_cat6_rule && desired.interface_name.empty() &&
         !snapshot.interface_name.empty());
    return firewall_rule_branding_is_owned(
               desired, snapshot.name, snapshot.description, snapshot.grouping) &&
        has_host_executable_identity(
            desired.application_path, snapshot.application_path) &&
        compatible_interface &&
        firewall_interface_types_are_owned(desired, snapshot) &&
        firewall_addresses_equal(desired.local_address, snapshot.local_address) &&
        firewall_addresses_equal(desired.remote_addresses, snapshot.remote_addresses) &&
        desired.local_port == snapshot.local_port &&
        desired.remote_port == snapshot.remote_port &&
        snapshot.protocol_number == firewall_protocol_number(desired.protocol) &&
        snapshot.protocol == desired.protocol && snapshot.inbound &&
        snapshot.enabled && snapshot.allow && !snapshot.edge_traversal &&
        snapshot.edge_traversal_options == NET_FW_EDGE_TRAVERSAL_TYPE_DENY &&
        snapshot.profiles == NET_FW_PROFILE2_ALL &&
        snapshot.service_name.empty() && snapshot.local_app_package_id.empty() &&
        snapshot.local_user_owner.empty() && snapshot.local_user_authorized_list.empty() &&
        snapshot.remote_user_authorized_list.empty() &&
        snapshot.remote_machine_authorized_list.empty() && snapshot.secure_flags == 0L;
}

bool snapshots_equal(
    const HostFirewallRuleSnapshot& left,
    const HostFirewallRuleSnapshot& right) noexcept {
    return equals_insensitive(left.name, right.name) &&
        left.description == right.description && left.grouping == right.grouping &&
        equals_insensitive(left.application_path, right.application_path) &&
        left.service_name == right.service_name &&
        equals_insensitive(left.interface_name, right.interface_name) &&
        firewall_interface_types_equal(
            left.interface_types, right.interface_types) &&
        firewall_addresses_equal(left.local_address, right.local_address) &&
        firewall_addresses_equal(left.remote_addresses, right.remote_addresses) &&
        left.local_port == right.local_port && left.remote_port == right.remote_port &&
        left.protocol == right.protocol && left.protocol_number == right.protocol_number &&
        left.inbound == right.inbound &&
        left.enabled == right.enabled && left.allow == right.allow &&
        left.edge_traversal == right.edge_traversal &&
        left.edge_traversal_options == right.edge_traversal_options &&
        left.profiles == right.profiles &&
        left.local_app_package_id == right.local_app_package_id &&
        left.local_user_owner == right.local_user_owner &&
        left.local_user_authorized_list == right.local_user_authorized_list &&
        left.remote_user_authorized_list == right.remote_user_authorized_list &&
        left.remote_machine_authorized_list == right.remote_machine_authorized_list &&
        left.secure_flags == right.secure_flags;
}

bool snapshot_multiset_equal(
    const std::vector<HostFirewallRuleSnapshot>& expected,
    const std::vector<HostFirewallRuleSnapshot>& actual) noexcept {
    if (expected.size() != actual.size()) return false;
    std::vector<bool> matched(expected.size());
    for (const auto& candidate : actual) {
        bool found{};
        for (std::size_t index = 0; index < expected.size(); ++index) {
            if (!matched[index] && snapshots_equal(expected[index], candidate)) {
                matched[index] = true;
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

bool collect_owned_snapshots(
    INetFwRules* rules,
    const HostFirewallRulePolicy& desired,
    std::vector<HostFirewallRuleSnapshot>& snapshots,
    std::string& detail) {
    const auto collect_name = [&](std::wstring_view name) {
        std::vector<EnumeratedRule> matches;
        const HRESULT result = enumerate_rules_named(rules, name, matches);
        if (FAILED(result)) {
            detail = "stage=enumerate_rule rule=" + narrow_utf8(name) +
                " " + format_hresult(result);
            return false;
        }
        for (std::size_t index = 0; index < matches.size(); ++index) {
            if (!matches[index].readable) {
                detail = "stage=ownership_validation rule=" + narrow_utf8(name) +
                    " index=" + std::to_string(index) +
                    " reason=unreadable_same_name_rule";
                return false;
            }
            if (!firewall_rule_is_owned(desired, matches[index].snapshot)) {
                detail = "stage=ownership_validation rule=" + narrow_utf8(name) +
                    " index=" + std::to_string(index) +
                    " reason=ambiguous_same_name_rule mismatch=" +
                    describe_rule_mismatch(desired, matches[index].snapshot) + " " +
                    describe_rule_snapshot(matches[index].snapshot);
                return false;
            }
            snapshots.push_back(std::move(matches[index].snapshot));
        }
        return true;
    };
    if (!collect_name(desired.name)) return false;
    const auto legacy = legacy_rule_branding(desired.name);
    return !legacy.has_value() || collect_name(legacy->name);
}

bool snapshot_is_allowed(
    const HostFirewallRuleSnapshot& snapshot,
    const std::vector<HostFirewallRuleSnapshot>& allowed) noexcept {
    return std::any_of(allowed.begin(), allowed.end(), [&](const auto& candidate) {
        return snapshots_equal(snapshot, candidate);
    });
}

HRESULT remove_rule_name(INetFwRules* rules, std::wstring_view name) {
    BSTR rule_name = SysAllocStringLen(name.data(), static_cast<UINT>(name.size()));
    if (rule_name == nullptr) return E_OUTOFMEMORY;
    const HRESULT result = rules->Remove(rule_name);
    SysFreeString(rule_name);
    return result;
}

bool remove_all_owned_named_rules(
    INetFwRules* rules,
    const HostFirewallRulePolicy& desired,
    const std::vector<HostFirewallRuleSnapshot>& allowed,
    std::uint32_t& removed,
    std::string& detail) {
    const std::size_t maximum_attempts = (std::max)(
        std::size_t{4}, allowed.size() + std::size_t{2});
    std::size_t attempts{};
    for (;;) {
        std::vector<HostFirewallRuleSnapshot> current;
        if (!collect_owned_snapshots(rules, desired, current, detail)) return false;
        if (current.empty()) return true;
        if (attempts >= maximum_attempts) {
            detail = "stage=remove_rule rule=" + narrow_utf8(desired.name) +
                " reason=attempt_limit concurrent_recreation_suspected attempts=" +
                std::to_string(attempts);
            return false;
        }
        if (std::any_of(current.begin(), current.end(), [&](const auto& snapshot) {
                return !snapshot_is_allowed(snapshot, allowed);
            })) {
            detail = "stage=remove_rule rule=" + narrow_utf8(desired.name) +
                " reason=concurrent_rule_change";
            return false;
        }
        const std::size_t before = current.size();
        ++attempts;
        const std::wstring removal_name = current.front().name;
        const HRESULT result = remove_rule_name(rules, removal_name);
        if (FAILED(result)) {
            detail = "stage=remove_rule rule=" + narrow_utf8(removal_name) +
                " before=" + std::to_string(before) + " " + format_hresult(result);
            return false;
        }
        current.clear();
        if (!collect_owned_snapshots(rules, desired, current, detail)) return false;
        if (current.size() >= before) {
            detail = "stage=remove_rule rule=" + narrow_utf8(desired.name) +
                " reason=count_not_decreased before=" + std::to_string(before) +
                " after=" + std::to_string(current.size());
            return false;
        }
        removed += static_cast<std::uint32_t>(before - current.size());
    }
}

bool verify_rule_plans(
    INetFwRules* rules,
    const std::vector<RuleReconciliationPlan>& plans,
    bool verify_original,
    std::string& detail) {
    for (const auto& plan : plans) {
        std::vector<HostFirewallRuleSnapshot> current;
        if (!collect_owned_snapshots(rules, plan.desired, current, detail)) return false;
        if (verify_original) {
            if (!snapshot_multiset_equal(plan.original, current)) {
                detail = "stage=rollback_verify rule=" + narrow_utf8(plan.desired.name) +
                    " expected=" + std::to_string(plan.original.size()) +
                    " actual=" + std::to_string(current.size());
                return false;
            }
        } else if (!host_firewall_rule_set_is_current(plan.desired, current)) {
            detail = "stage=verify_rule rule=" + narrow_utf8(plan.desired.name) +
                " reason=rule_set_mismatch expected=1 actual=" +
                std::to_string(current.size()) +
                (current.size() == 1U ? " " + describe_rule_mismatch(
                    plan.desired, current.front()) : std::string{});
            return false;
        }
    }
    return true;
}

bool rollback_rule_plans(
    INetFwRules* rules,
    const std::vector<RuleReconciliationPlan>& plans,
    const std::vector<std::size_t>& touched,
    std::string& detail) {
    bool succeeded = true;
    std::string first_failure;
    for (const std::size_t index : touched) {
        const auto& plan = plans[index];
        auto allowed = plan.original;
        allowed.push_back(snapshot_from_policy(plan.desired));
        std::uint32_t ignored{};
        std::string operation_detail;
        if (!remove_all_owned_named_rules(
                rules, plan.desired, allowed, ignored, operation_detail)) {
            succeeded = false;
            if (first_failure.empty()) first_failure = std::move(operation_detail);
            continue;
        }
        for (const auto& snapshot : plan.original) {
            ComPtr<INetFwRule3> restored;
            HRESULT result = create_rule_from_snapshot(snapshot, restored);
            if (SUCCEEDED(result) && restored != nullptr) result = rules->Add(restored.Get());
            if (FAILED(result)) {
                succeeded = false;
                if (first_failure.empty()) {
                    first_failure = "stage=rollback_restore rule=" +
                        narrow_utf8(plan.desired.name) + " " + format_hresult(result);
                }
                break;
            }
        }
    }
    std::string verify_detail;
    if (!verify_rule_plans(rules, plans, true, verify_detail)) {
        succeeded = false;
        if (first_failure.empty()) first_failure = std::move(verify_detail);
    }
    detail = succeeded ? "rollback=complete" : "rollback=failed " + first_failure;
    return succeeded;
}

}  // namespace

std::vector<HostFirewallRulePolicy> build_host_firewall_policy(
    std::wstring application_path) {
    const auto rule = [&](const wchar_t* name,
                          const wchar_t* description,
                          const wchar_t* interface_types,
                          const char* local_address,
                          std::uint16_t local_port,
                          const char* remote_addresses,
                          std::uint16_t remote_port,
                          HostFirewallProtocol protocol = HostFirewallProtocol::udp) {
        HostFirewallRulePolicy policy{};
        policy.name = name;
        policy.description = description;
        policy.grouping = kRuleGrouping;
        policy.application_path = application_path;
        policy.interface_types = interface_types;
        policy.local_address = local_address;
        policy.remote_addresses = remote_addresses;
        policy.local_port = local_port;
        policy.remote_port = remote_port;
        policy.protocol = protocol;
        return policy;
    };
    return {
        rule(kDhcpRuleName, kCat6RuleDescription, kWiredInterfaceType,
             kAnyLocalAddress, kWiredDhcpServerPort,
             kAnyRemoteAddress, kWiredDhcpClientPort),
        rule(kAnnouncementRuleName, kCat6RuleDescription, kWiredInterfaceType,
             kWiredHostIpv4, kWiredAnnouncementPort,
             kWiredMobileIpv4, kWiredProbePort),
        rule(kIdrRuleName, kCat6RuleDescription, kWiredInterfaceType,
             kWiredHostIpv4, kWiredIdrPort,
             kWiredMobileIpv4, kWiredVideoPort),
        rule(kWirelessAnnouncementRuleName, kWirelessRuleDescription,
             kLocalNetworkInterfaceTypes, kAnyLocalAddress,
             kWiredAnnouncementPort,
             kLocalSubnet, kWiredProbePort),
        rule(kWirelessIdrRuleName, kWirelessRuleDescription,
             kLocalNetworkInterfaceTypes, kAnyLocalAddress, kWiredIdrPort,
             kLocalSubnet, kWiredVideoPort),
        rule(kCat6FirstPairingRuleName, kCat6FirstPairingRuleDescription,
             kWiredInterfaceType, kWiredHostIpv4,
             kWiredFirstPairingPort, kWiredMobileIpv4,
             kAnyFirewallPort, HostFirewallProtocol::tcp),
        rule(kWirelessFirstPairingRuleName,
             kWirelessFirstPairingRuleDescription,
             kLocalNetworkInterfaceTypes, kAnyLocalAddress,
             kWiredFirstPairingPort, kLocalSubnet,
             kAnyFirewallPort, HostFirewallProtocol::tcp),
        rule(kCat6AuthenticatedControlRuleName,
             kCat6AuthenticatedControlRuleDescription,
             kWiredInterfaceType, kWiredHostIpv4,
             kWiredAuthenticatedControlPort, kWiredMobileIpv4,
             kAnyFirewallPort, HostFirewallProtocol::tcp),
        rule(kWirelessAuthenticatedControlRuleName,
             kWirelessAuthenticatedControlRuleDescription,
             kLocalNetworkInterfaceTypes, kAnyLocalAddress,
             kWiredAuthenticatedControlPort, kLocalSubnet,
             kAnyFirewallPort, HostFirewallProtocol::tcp),
    };
}

bool host_firewall_rule_is_current(
    const HostFirewallRulePolicy& desired,
    const HostFirewallRuleSnapshot& existing) noexcept {
    return equals_insensitive(desired.name, existing.name) &&
        existing.description == desired.description &&
        existing.grouping == desired.grouping &&
        equals_insensitive(desired.application_path, existing.application_path) &&
        equals_insensitive(desired.interface_name, existing.interface_name) &&
        firewall_interface_types_equal(
            desired.interface_types, existing.interface_types) &&
        firewall_addresses_equal(desired.local_address, existing.local_address) &&
        firewall_addresses_equal(desired.remote_addresses, existing.remote_addresses) &&
        desired.local_port == existing.local_port &&
        desired.remote_port == existing.remote_port &&
        desired.protocol == existing.protocol &&
        existing.protocol_number == firewall_protocol_number(desired.protocol) &&
        desired.inbound == existing.inbound && desired.enabled == existing.enabled &&
        desired.allow == existing.allow && desired.edge_traversal == existing.edge_traversal &&
        existing.edge_traversal_options == NET_FW_EDGE_TRAVERSAL_TYPE_DENY &&
        desired.service_name == existing.service_name &&
        desired.local_app_package_id == existing.local_app_package_id &&
        desired.local_user_owner == existing.local_user_owner &&
        desired.local_user_authorized_list == existing.local_user_authorized_list &&
        desired.remote_user_authorized_list == existing.remote_user_authorized_list &&
        desired.remote_machine_authorized_list == existing.remote_machine_authorized_list &&
        desired.secure_flags == existing.secure_flags && existing.all_profiles;
}

bool host_firewall_rule_set_is_current(
    const HostFirewallRulePolicy& desired,
    const std::vector<HostFirewallRuleSnapshot>& existing) noexcept {
    return existing.size() == 1U &&
        host_firewall_rule_is_current(desired, existing.front());
}

bool host_firewall_rule_is_recognized_owned(
    const HostFirewallRulePolicy& desired,
    const HostFirewallRuleSnapshot& existing) noexcept {
    return firewall_rule_is_owned(desired, existing);
}

bool host_firewall_active_profiles_are_enabled(
    const HostFirewallActiveProfileState& profiles) noexcept {
    const bool any_profile = profiles.domain_active ||
        profiles.private_active || profiles.public_active;
    return any_profile && !profiles.unknown_profile_active &&
        (!profiles.domain_active || profiles.domain_enabled) &&
        (!profiles.private_active || profiles.private_enabled) &&
        (!profiles.public_active || profiles.public_enabled);
}

bool host_firewall_active_profiles_are_all_disabled(
    const HostFirewallActiveProfileState& profiles) noexcept {
    const bool any_profile = profiles.domain_active ||
        profiles.private_active || profiles.public_active;
    return any_profile && !profiles.unknown_profile_active &&
        (!profiles.domain_active || !profiles.domain_enabled) &&
        (!profiles.private_active || !profiles.private_enabled) &&
        (!profiles.public_active || !profiles.public_enabled);
}

bool host_firewall_rule_is_conflicting_executable_allow(
    std::wstring_view application_path,
    const std::vector<HostFirewallRulePolicy>& owned_rules,
    const HostFirewallRuleAuditEntry& existing) noexcept {
    if (!existing.inbound || !existing.enabled || !existing.allow ||
        !equals_insensitive(application_path, existing.application_path)) {
        return false;
    }
    return std::none_of(owned_rules.begin(), owned_rules.end(), [&](const auto& owned) {
        return firewall_rule_branding_is_owned(
            owned, existing.name, existing.description, existing.grouping);
    });
}

HostFirewallProvisioningResult ensure_host_firewall_rules() {
    HostFirewallProvisioningResult outcome{};
    std::string executable_error;
    const auto executable_path = current_executable_path(executable_error);
    if (!executable_path.has_value()) {
        outcome.status = HostFirewallStatus::failed;
        outcome.detail = executable_error;
        return outcome;
    }

    ComApartment apartment;
    if (!apartment.usable()) {
        outcome.status = HostFirewallStatus::unavailable;
        outcome.detail = "stage=com_initialization " + format_hresult(apartment.result);
        return outcome;
    }
    ComPtr<INetFwPolicy2> policy;
    HRESULT result = CoCreateInstance(
        CLSID_NetFwPolicy2, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&policy));
    if (FAILED(result) || policy == nullptr) {
        outcome.status = HostFirewallStatus::unavailable;
        outcome.detail = "stage=firewall_policy " + format_hresult(result);
        return outcome;
    }
    HostFirewallActiveProfileState active_profiles{};
    result = read_active_profile_state(policy.Get(), active_profiles);
    if (FAILED(result)) {
        outcome.status = HostFirewallStatus::unavailable;
        outcome.detail = "stage=firewall_profiles " + format_hresult(result);
        return outcome;
    }
    const std::string profile_detail = describe_active_profiles(active_profiles);
    const bool filtering_inactive =
        host_firewall_active_profiles_are_all_disabled(active_profiles);
    const auto with_profiles = [&](std::string detail) {
        return std::move(detail) + " " + profile_detail;
    };
    ComPtr<INetFwRules> rules;
    result = policy->get_Rules(&rules);
    if (FAILED(result) || rules == nullptr) {
        outcome.status = filtering_inactive
            ? HostFirewallStatus::ready : HostFirewallStatus::unavailable;
        outcome.detail = with_profiles(
            "stage=firewall_rules result=" +
            std::string(filtering_inactive
                ? "filtering_inactive_rules_api_unavailable"
                : "rules_api_unavailable") +
            " " + format_hresult(result));
        return outcome;
    }

    const auto desired_rules = build_host_firewall_policy(*executable_path);
    std::vector<std::wstring> conflicting_rules;
    result = find_conflicting_executable_rules(
        rules.Get(), *executable_path, desired_rules, conflicting_rules);
    if (FAILED(result)) {
        outcome.status = HostFirewallStatus::failed;
        outcome.detail = with_profiles(
            "stage=audit_executable_rules " + format_hresult(result));
        return outcome;
    }
    if (!conflicting_rules.empty()) {
        outcome.status = HostFirewallStatus::failed;
        outcome.detail = with_profiles(
            "stage=audit_executable_rules reason=extra_enabled_inbound_allow names=" +
            join_rule_names(conflicting_rules));
        return outcome;
    }
    std::vector<RuleReconciliationPlan> plans;
    plans.reserve(desired_rules.size());
    for (const auto& desired : desired_rules) {
        RuleReconciliationPlan plan{};
        plan.desired = desired;
        std::string preflight_detail;
        if (!collect_owned_snapshots(
                rules.Get(), desired, plan.original, preflight_detail)) {
            outcome.status = HostFirewallStatus::failed;
            outcome.detail = with_profiles(std::move(preflight_detail));
            return outcome;
        }
        ++outcome.checked_rules;
        plan.needs_reconciliation =
            !host_firewall_rule_set_is_current(desired, plan.original);
        plans.push_back(std::move(plan));
    }
    const std::size_t stale_count = static_cast<std::size_t>(std::count_if(
        plans.begin(), plans.end(), [](const auto& plan) {
            return plan.needs_reconciliation;
        }));
    if (stale_count == 0U) {
        outcome.status = HostFirewallStatus::ready;
        outcome.detail = with_profiles(
            "stage=complete result=rules_current checked=" +
            std::to_string(desired_rules.size()) + " filtering=" +
            std::string(filtering_inactive ? "inactive" : "active_or_transitional"));
        return outcome;
    }
    if (!process_is_elevated()) {
        outcome.status = HostFirewallStatus::requires_elevation;
        outcome.detail = with_profiles(
            "stage=reconcile result=elevation_required stale=" +
            std::to_string(stale_count));
        return outcome;
    }

    std::vector<ComPtr<INetFwRule3>> replacements(plans.size());
    for (std::size_t index = 0; index < plans.size(); ++index) {
        if (!plans[index].needs_reconciliation) continue;
        if (FAILED(result = create_rule(plans[index].desired, replacements[index])) ||
            replacements[index] == nullptr) {
            outcome.status = HostFirewallStatus::failed;
            outcome.detail = with_profiles("stage=create_rule rule=" +
                narrow_utf8(plans[index].desired.name) +
                " " + format_hresult(result));
            return outcome;
        }
    }

    std::vector<std::size_t> touched;
    std::uint32_t removed_rules{};
    for (std::size_t index = 0; index < plans.size(); ++index) {
        auto& plan = plans[index];
        if (!plan.needs_reconciliation) continue;
        touched.push_back(index);
        std::string primary_detail;
        if (!remove_all_owned_named_rules(
                rules.Get(), plan.desired, plan.original,
                removed_rules, primary_detail)) {
            outcome.status = HostFirewallStatus::failed;
            std::string rollback_detail;
            (void)rollback_rule_plans(rules.Get(), plans, touched, rollback_detail);
            outcome.detail = with_profiles(primary_detail + " " + rollback_detail);
            return outcome;
        }
        result = rules->Add(replacements[index].Get());
        if (FAILED(result)) {
            outcome.status = HostFirewallStatus::failed;
            primary_detail = "stage=add_rule rule=" + narrow_utf8(plan.desired.name) +
                " " + format_hresult(result);
            std::string rollback_detail;
            (void)rollback_rule_plans(rules.Get(), plans, touched, rollback_detail);
            outcome.detail = with_profiles(primary_detail + " " + rollback_detail);
            return outcome;
        }
        ++outcome.changed_rules;
    }
    std::string verify_detail;
    if (!verify_rule_plans(rules.Get(), plans, false, verify_detail)) {
        outcome.status = HostFirewallStatus::failed;
        std::string rollback_detail;
        (void)rollback_rule_plans(rules.Get(), plans, touched, rollback_detail);
        outcome.detail = with_profiles(verify_detail + " " + rollback_detail);
        return outcome;
    }
    conflicting_rules.clear();
    result = find_conflicting_executable_rules(
        rules.Get(), *executable_path, desired_rules, conflicting_rules);
    if (FAILED(result) || !conflicting_rules.empty()) {
        outcome.status = HostFirewallStatus::failed;
        const std::string primary_detail = FAILED(result)
            ? "stage=post_commit_audit " + format_hresult(result)
            : "stage=post_commit_audit reason=extra_enabled_inbound_allow names=" +
                join_rule_names(conflicting_rules);
        std::string rollback_detail;
        (void)rollback_rule_plans(rules.Get(), plans, touched, rollback_detail);
        outcome.detail = with_profiles(primary_detail + " " + rollback_detail);
        return outcome;
    }
    outcome.status = HostFirewallStatus::provisioned;
    outcome.detail = with_profiles("stage=complete result=rules_reconciled changed=" +
        std::to_string(outcome.changed_rules) +
        " removed=" + std::to_string(removed_rules) +
        " filtering=" +
        std::string(filtering_inactive ? "inactive" : "active_or_transitional"));
    return outcome;
}

bool host_firewall_is_ready(HostFirewallStatus status) noexcept {
    return status == HostFirewallStatus::ready || status == HostFirewallStatus::provisioned;
}

const char* host_firewall_status_name(HostFirewallStatus status) noexcept {
    switch (status) {
        case HostFirewallStatus::ready: return "ready";
        case HostFirewallStatus::provisioned: return "provisioned";
        case HostFirewallStatus::requires_elevation: return "requires_elevation";
        case HostFirewallStatus::unavailable: return "unavailable";
        case HostFirewallStatus::failed: return "failed";
    }
    return "unknown";
}

}  // namespace vfdual
