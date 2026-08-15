#include "vfdual/isolated_dhcp_server.hpp"
#include "vfdual/isolated_dhcp_protocol.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <array>
#include <algorithm>
#include <chrono>
#include <exception>
#include <optional>
#include <vector>

namespace vfdual {
namespace {

constexpr std::uint8_t kDhcpDiscover = 1;
constexpr std::uint8_t kDhcpRequest = 3;

struct InterfaceBinding final {
    DWORD interface_index{};
    std::array<std::uint8_t, 6> physical_mac{};
    bool has_physical_mac{};
};

struct DhcpSendResult final {
    int bytes_sent{-1};
    int error{};
};

struct DhcpReceiveResult final {
    int bytes_received{-1};
    int error{};
    sockaddr_in source{};
    DWORD interface_index{};
    bool has_interface_index{};
};

DhcpSendResult send_reply_from_interface(
    SOCKET socket_handle, const sockaddr_in& destination,
    std::span<const std::uint8_t> reply, const in_addr source_address,
    DWORD interface_index) noexcept {
    WSABUF payload{
        static_cast<ULONG>(reply.size()),
        reinterpret_cast<char*>(const_cast<std::uint8_t*>(reply.data())),
    };
    alignas(WSACMSGHDR)
        std::array<char, WSA_CMSG_SPACE(sizeof(IN_PKTINFO))> control{};
    WSAMSG message{};
    message.name = reinterpret_cast<sockaddr*>(
        const_cast<sockaddr_in*>(&destination));
    message.namelen = sizeof(destination);
    message.lpBuffers = &payload;
    message.dwBufferCount = 1;
    message.Control.buf = control.data();
    message.Control.len = static_cast<ULONG>(control.size());

    WSACMSGHDR* header = WSA_CMSG_FIRSTHDR(&message);
    if (header == nullptr) return {-1, WSAEINVAL};
    header->cmsg_level = IPPROTO_IP;
    header->cmsg_type = IP_PKTINFO;
    header->cmsg_len = WSA_CMSG_LEN(sizeof(IN_PKTINFO));
    auto* packet_info = reinterpret_cast<IN_PKTINFO*>(WSA_CMSG_DATA(header));
    packet_info->ipi_addr = source_address;
    packet_info->ipi_ifindex = interface_index;

    DWORD sent{};
    if (WSASendMsg(socket_handle, &message, 0, &sent, nullptr, nullptr) != 0) {
        return {-1, WSAGetLastError()};
    }
    return {static_cast<int>(sent), 0};
}

LPFN_WSARECVMSG load_receive_message_function(SOCKET socket_handle) noexcept {
    GUID extension_id = WSAID_WSARECVMSG;
    LPFN_WSARECVMSG receive_message{};
    DWORD bytes_returned{};
    const int result = WSAIoctl(
        socket_handle, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &extension_id, sizeof(extension_id), &receive_message,
        sizeof(receive_message), &bytes_returned, nullptr, nullptr);
    if (result != 0) return nullptr;
    return receive_message;
}

DhcpReceiveResult receive_datagram_with_packet_info(
    SOCKET socket_handle, LPFN_WSARECVMSG receive_message,
    std::span<std::uint8_t> buffer) noexcept {
    if (receive_message == nullptr) return {-1, WSAEINVAL};
    WSABUF payload{
        static_cast<ULONG>(buffer.size()),
        reinterpret_cast<char*>(buffer.data()),
    };
    alignas(WSACMSGHDR)
        std::array<char, WSA_CMSG_SPACE(sizeof(IN_PKTINFO))> control{};
    DhcpReceiveResult result{};
    WSAMSG message{};
    message.name = reinterpret_cast<sockaddr*>(&result.source);
    message.namelen = sizeof(result.source);
    message.lpBuffers = &payload;
    message.dwBufferCount = 1;
    message.Control.buf = control.data();
    message.Control.len = static_cast<ULONG>(control.size());

    DWORD received{};
    if (receive_message(socket_handle, &message, &received, nullptr, nullptr) != 0) {
        result.error = WSAGetLastError();
        return result;
    }
    result.bytes_received = static_cast<int>(received);
    for (WSACMSGHDR* header = WSA_CMSG_FIRSTHDR(&message); header != nullptr;
         header = WSA_CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != IPPROTO_IP ||
            header->cmsg_type != IP_PKTINFO) {
            continue;
        }
        const auto* packet_info =
            reinterpret_cast<const IN_PKTINFO*>(WSA_CMSG_DATA(header));
        result.interface_index = packet_info->ipi_ifindex;
        result.has_interface_index = true;
        break;
    }
    return result;
}

DhcpReceiveResult receive_datagram(
    SOCKET socket_handle, std::span<std::uint8_t> buffer) noexcept {
    DhcpReceiveResult result{};
    int source_size = sizeof(result.source);
    result.bytes_received = recvfrom(
        socket_handle, reinterpret_cast<char*>(buffer.data()),
        static_cast<int>(buffer.size()), 0,
        reinterpret_cast<sockaddr*>(&result.source), &source_size);
    if (result.bytes_received <= 0) result.error = WSAGetLastError();
    return result;
}

std::optional<InterfaceBinding> find_interface_binding(
    const in_addr server_address,
    std::uint32_t& match_count) noexcept {
    // GetAdaptersAddresses omits unicast addresses whose SkipAsSource flag is
    // set, and the transient isolated address is created exactly that way, so
    // the GAA-based lookup never saw it on a freshly provisioned link. Query
    // the unicast table directly: it always carries 10.57.23.1 regardless of
    // the skip-as-source flag. (E-system acceptance 2026-07-25: GAA never saw
    // the transient address, so DHCP startup failed with WSAEADDRNOTAVAIL.)
    MIB_UNICASTIPADDRESS_TABLE* table = nullptr;
    if (GetUnicastIpAddressTable(AF_INET, &table) != NO_ERROR || table == nullptr) {
        return std::nullopt;
    }
    std::vector<DWORD> interface_indices;
    for (ULONG index = 0; index < table->NumEntries; ++index) {
        const MIB_UNICASTIPADDRESS_ROW& row = table->Table[index];
        if (row.Address.si_family != AF_INET) continue;
        if (row.Address.Ipv4.sin_addr.s_addr != server_address.s_addr) continue;
        interface_indices.push_back(row.InterfaceIndex);
    }
    FreeMibTable(table);
    std::sort(interface_indices.begin(), interface_indices.end());
    interface_indices.erase(
        std::unique(interface_indices.begin(), interface_indices.end()),
        interface_indices.end());
    match_count = static_cast<std::uint32_t>(interface_indices.size());
    if (interface_indices.size() != 1U) return std::nullopt;
    InterfaceBinding binding{};
    binding.interface_index = interface_indices.front();
    MIB_IF_ROW2 interface_row{};
    interface_row.InterfaceIndex = binding.interface_index;
    if (GetIfEntry2(&interface_row) == NO_ERROR &&
        interface_row.PhysicalAddressLength >= binding.physical_mac.size()) {
        std::copy_n(
            interface_row.PhysicalAddress, binding.physical_mac.size(),
            binding.physical_mac.begin());
        const bool all_zero = std::all_of(
            binding.physical_mac.begin(), binding.physical_mac.end(),
            [](std::uint8_t byte) { return byte == 0; });
        const bool all_ff = std::all_of(
            binding.physical_mac.begin(), binding.physical_mac.end(),
            [](std::uint8_t byte) { return byte == 0xff; });
        binding.has_physical_mac = !all_zero && !all_ff;
    }
    return binding;
}

class WinsockSession final {
public:
    WinsockSession() noexcept { ready_ = WSAStartup(MAKEWORD(2, 2), &data_) == 0; }
    ~WinsockSession() { if (ready_) WSACleanup(); }
    [[nodiscard]] bool ready() const noexcept { return ready_; }
private:
    WSADATA data_{};
    bool ready_{};
};

}  // namespace

IsolatedDhcpServer::~IsolatedDhcpServer() { stop(); }

const char* isolated_dhcp_startup_stage_name(
    IsolatedDhcpStartupStage stage) noexcept {
    switch (stage) {
        case IsolatedDhcpStartupStage::none: return "none";
        case IsolatedDhcpStartupStage::validate_config: return "validate_config";
        case IsolatedDhcpStartupStage::winsock: return "winsock";
        case IsolatedDhcpStartupStage::parse_config: return "parse_config";
        case IsolatedDhcpStartupStage::find_interface: return "find_interface";
        case IsolatedDhcpStartupStage::create_socket: return "create_socket";
        case IsolatedDhcpStartupStage::exclusive_address: return "exclusive_address";
        case IsolatedDhcpStartupStage::interface_filter: return "interface_filter";
        case IsolatedDhcpStartupStage::bind_socket: return "bind_socket";
        case IsolatedDhcpStartupStage::protocol: return "protocol";
        case IsolatedDhcpStartupStage::running: return "running";
        case IsolatedDhcpStartupStage::worker_thread: return "worker_thread";
    }
    return "unknown";
}

bool IsolatedDhcpServer::start(std::string server_ipv4, std::string lease_ipv4,
                               std::string subnet_mask, std::uint16_t server_port,
                               std::uint16_t client_port) noexcept {
    stop();
    set_startup_stage(IsolatedDhcpStartupStage::validate_config);
    in_addr server{};
    in_addr lease{};
    in_addr mask{};
    if (InetPtonA(AF_INET, server_ipv4.c_str(), &server) != 1 ||
        InetPtonA(AF_INET, lease_ipv4.c_str(), &lease) != 1 ||
        InetPtonA(AF_INET, subnet_mask.c_str(), &mask) != 1 ||
        (server.s_addr & mask.s_addr) != (lease.s_addr & mask.s_addr) ||
        server.s_addr == lease.s_addr || server_port == 0 || client_port == 0 ||
        server_port == client_port) {
        last_error_ = WSAEINVAL;
        return false;
    }
    server_ipv4_ = std::move(server_ipv4);
    lease_ipv4_ = std::move(lease_ipv4);
    subnet_mask_ = std::move(subnet_mask);
    server_port_ = server_port;
    client_port_ = client_port;
    {
        std::lock_guard lock(metrics_mutex_);
        metrics_ = {};
    }
    stop_requested_ = false;
    running_ = false;
    last_error_ = 0;
    set_startup_stage(IsolatedDhcpStartupStage::none);
    static_assert(isolated_dhcp_startup_wait_covers_interface_probe());
    set_startup_stage(IsolatedDhcpStartupStage::worker_thread);
    try {
        worker_ = std::thread(&IsolatedDhcpServer::run, this);
    } catch (const std::exception&) {
        last_error_ = WSAENOBUFS;
        running_ = false;
        return false;
    } catch (...) {
        last_error_ = WSAENOBUFS;
        running_ = false;
        return false;
    }
    for (int attempt = 0;
         attempt < kIsolatedDhcpStartupWaitAttempts && !running_ &&
         last_error_ == 0;
         ++attempt) {
        std::this_thread::sleep_for(kIsolatedDhcpStartupWaitInterval);
    }
    if (running_) return true;
    stop();
    return false;
}

void IsolatedDhcpServer::stop() noexcept {
    stop_requested_ = true;
    try {
        if (worker_.joinable()) worker_.join();
    } catch (...) {
    }
    running_ = false;
}

bool IsolatedDhcpServer::running() const noexcept { return running_; }
std::uint32_t IsolatedDhcpServer::last_error() const noexcept { return last_error_; }
IsolatedDhcpStartupStage IsolatedDhcpServer::startup_stage() const noexcept {
    return static_cast<IsolatedDhcpStartupStage>(
        startup_stage_.load(std::memory_order_relaxed));
}

IsolatedDhcpMetrics IsolatedDhcpServer::metrics() const noexcept {
    std::lock_guard lock(metrics_mutex_);
    return metrics_;
}

void IsolatedDhcpServer::set_startup_stage(
    IsolatedDhcpStartupStage stage) noexcept {
    const auto encoded = static_cast<std::uint32_t>(stage);
    startup_stage_.store(encoded, std::memory_order_relaxed);
    std::lock_guard lock(metrics_mutex_);
    metrics_.startup_stage = encoded;
}

void IsolatedDhcpServer::run() noexcept {
    set_startup_stage(IsolatedDhcpStartupStage::winsock);
    WinsockSession winsock;
    if (!winsock.ready()) {
        last_error_ = WSAGetLastError();
        return;
    }
    set_startup_stage(IsolatedDhcpStartupStage::parse_config);
    in_addr server{};
    in_addr lease{};
    in_addr mask{};
    if (InetPtonA(AF_INET, server_ipv4_.c_str(), &server) != 1 ||
        InetPtonA(AF_INET, lease_ipv4_.c_str(), &lease) != 1 ||
        InetPtonA(AF_INET, subnet_mask_.c_str(), &mask) != 1) {
        last_error_ = WSAEINVAL;
        return;
    }
    // The isolated address may have been created via the IP Helper API only
    // milliseconds earlier; GetAdaptersAddresses can lag behind the
    // CreateUnicastIpAddressEntry/DAD completion that the provisioner already
    // verified. Poll briefly before declaring the binding missing. (E-system
    // acceptance 2026-07-25: first attempt failed here with WSAEADDRNOTAVAIL.)
    set_startup_stage(IsolatedDhcpStartupStage::find_interface);
    std::optional<InterfaceBinding> interface_binding;
    for (int attempt = 0;
         attempt < kIsolatedDhcpInterfaceProbeAttempts && !stop_requested_;
         ++attempt) {
        std::uint32_t match_count{};
        interface_binding = find_interface_binding(server, match_count);
        {
            std::lock_guard lock(metrics_mutex_);
            metrics_.interface_match_count = match_count;
        }
        if (interface_binding.has_value()) break;
        std::this_thread::sleep_for(kIsolatedDhcpInterfaceProbeInterval);
    }
    if (!interface_binding.has_value()) {
        last_error_ = WSAEADDRNOTAVAIL;
        return;
    }
    {
        std::lock_guard lock(metrics_mutex_);
        metrics_.interface_index = interface_binding->interface_index;
    }
    set_startup_stage(IsolatedDhcpStartupStage::create_socket);
    const SOCKET socket_handle = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_handle == INVALID_SOCKET) {
        last_error_ = WSAGetLastError();
        return;
    }
    set_startup_stage(IsolatedDhcpStartupStage::exclusive_address);
    const BOOL enabled = TRUE;
    if (setsockopt(socket_handle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   reinterpret_cast<const char*>(&enabled), sizeof(enabled)) != 0) {
        last_error_ = WSAGetLastError();
        closesocket(socket_handle);
        return;
    }
    setsockopt(socket_handle, SOL_SOCKET, SO_BROADCAST,
               reinterpret_cast<const char*>(&enabled), sizeof(enabled));
    // DHCP clients without an address send to 255.255.255.255. A socket bound
    // only to 10.57.23.1 does not own that local destination on Windows and the
    // kernel rejects the datagram as "port unreachable". Bind the wildcard
    // address, then use Windows' IFLIST to keep reception constrained to the
    // exact Ethernet interface that owns 10.57.23.1. Some Windows adapter
    // stacks reject IP_IFLIST even though IP_PKTINFO is available, so keep a
    // second in-process guard: every DHCP packet must report the expected
    // ingress interface before the protocol handler can answer it.
    set_startup_stage(IsolatedDhcpStartupStage::interface_filter);
    const DWORD interface_filter_enabled = TRUE;
    bool interface_filter_active =
        setsockopt(socket_handle, IPPROTO_IP, IP_IFLIST,
                   reinterpret_cast<const char*>(&interface_filter_enabled),
                   sizeof(interface_filter_enabled)) == 0 &&
        setsockopt(socket_handle, IPPROTO_IP, IP_ADD_IFLIST,
                   reinterpret_cast<const char*>(&interface_binding->interface_index),
                   sizeof(interface_binding->interface_index)) == 0;
    const std::uint32_t interface_filter_error = interface_filter_active
        ? 0U : static_cast<std::uint32_t>(WSAGetLastError());
    DWORD packet_info_enabled = TRUE;
    bool packet_info_active =
        setsockopt(socket_handle, IPPROTO_IP, IP_PKTINFO,
                   reinterpret_cast<const char*>(&packet_info_enabled),
                   sizeof(packet_info_enabled)) == 0;
    std::uint32_t packet_info_error = packet_info_active
        ? 0U : static_cast<std::uint32_t>(WSAGetLastError());
    LPFN_WSARECVMSG receive_message{};
    if (packet_info_active) {
        receive_message = load_receive_message_function(socket_handle);
        if (receive_message == nullptr) {
            packet_info_active = false;
            packet_info_error = static_cast<std::uint32_t>(WSAGetLastError());
            if (packet_info_error == 0U) packet_info_error = WSAEINVAL;
        }
    }
    {
        std::lock_guard lock(metrics_mutex_);
        metrics_.interface_filter_active = interface_filter_active ? 1U : 0U;
        metrics_.interface_filter_error = interface_filter_error;
        metrics_.packet_info_active = packet_info_active ? 1U : 0U;
        metrics_.packet_info_error = packet_info_error;
    }
    if (!interface_filter_active && !packet_info_active) {
        last_error_ = interface_filter_error != 0U
            ? interface_filter_error : packet_info_error;
        closesocket(socket_handle);
        return;
    }
    const DWORD receive_timeout_ms = 200;
    setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&receive_timeout_ms), sizeof(receive_timeout_ms));
    sockaddr_in bind_address{};
    bind_address.sin_family = AF_INET;
    bind_address.sin_port = htons(server_port_);
    bind_address.sin_addr.s_addr = htonl(INADDR_ANY);
    set_startup_stage(IsolatedDhcpStartupStage::bind_socket);
    if (::bind(socket_handle, reinterpret_cast<const sockaddr*>(&bind_address), sizeof(bind_address)) != 0) {
        last_error_ = WSAGetLastError();
        closesocket(socket_handle);
        return;
    }
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(client_port_);
    destination.sin_addr.s_addr = server.s_addr | ~mask.s_addr;
    IsolatedDhcpProtocolConfig protocol_config{
        server.s_addr,
        lease.s_addr,
        mask.s_addr,
    };
    protocol_config.excluded_client_mac = interface_binding->physical_mac;
    protocol_config.has_excluded_client_mac = interface_binding->has_physical_mac;
    set_startup_stage(IsolatedDhcpStartupStage::protocol);
    IsolatedDhcpProtocol protocol(protocol_config);
    if (!protocol.valid()) {
        last_error_ = WSAEINVAL;
        closesocket(socket_handle);
        return;
    }
    running_ = true;
    set_startup_stage(IsolatedDhcpStartupStage::running);
    std::array<std::uint8_t, 1500> buffer{};
    while (!stop_requested_) {
        const DhcpReceiveResult receive_result = packet_info_active
            ? receive_datagram_with_packet_info(socket_handle, receive_message, buffer)
            : receive_datagram(socket_handle, buffer);
        if (receive_result.bytes_received <= 0) {
            const int error = receive_result.error;
            if (error != WSAETIMEDOUT && error != WSAEWOULDBLOCK) last_error_ = error;
            continue;
        }
        if (receive_result.has_interface_index &&
            receive_result.interface_index != interface_binding->interface_index) {
            std::lock_guard lock(metrics_mutex_);
            ++metrics_.inbound_interface_drops;
            continue;
        }
        if (!receive_result.has_interface_index && !interface_filter_active) {
            std::lock_guard lock(metrics_mutex_);
            ++metrics_.inbound_unverified_drops;
            continue;
        }
        {
            std::lock_guard lock(metrics_mutex_);
            ++metrics_.received_packets;
        }
        const auto decision = protocol.process(
            std::span<const std::uint8_t>(
                buffer.data(), static_cast<std::size_t>(receive_result.bytes_received)));
        if (!decision.accepted) {
            std::lock_guard lock(metrics_mutex_);
            ++metrics_.rejected_packets;
            metrics_.last_reject_reason = decision.reject_reason;
            switch (decision.reject_reason) {
                case IsolatedDhcpRejectReason::malformed_request:
                case IsolatedDhcpRejectReason::invalid_configuration:
                    ++metrics_.malformed_packets;
                    break;
                case IsolatedDhcpRejectReason::local_interface_client:
                    ++metrics_.local_interface_packets;
                    break;
                case IsolatedDhcpRejectReason::lease_owned_by_other_client:
                case IsolatedDhcpRejectReason::client_mismatch:
                    ++metrics_.client_conflict_packets;
                    break;
                case IsolatedDhcpRejectReason::request_without_offer:
                case IsolatedDhcpRejectReason::transaction_mismatch:
                    ++metrics_.request_state_packets;
                    break;
                case IsolatedDhcpRejectReason::server_identifier_mismatch:
                case IsolatedDhcpRejectReason::requested_address_mismatch:
                case IsolatedDhcpRejectReason::client_address_mismatch:
                    ++metrics_.address_mismatch_packets;
                    break;
                case IsolatedDhcpRejectReason::none:
                    break;
            }
            continue;
        }
        const DhcpSendResult send_result = send_reply_from_interface(
            socket_handle, destination, decision.reply, server,
            interface_binding->interface_index);
        std::lock_guard lock(metrics_mutex_);
        if (decision.request_message_type == kDhcpDiscover) ++metrics_.discovers;
        else ++metrics_.requests;
        if (send_result.bytes_sent == static_cast<int>(decision.reply.size())) {
            protocol.commit_sent_response(decision);
            ++metrics_.explicit_source_sends;
            if (decision.request_message_type == kDhcpDiscover) ++metrics_.offers;
            else ++metrics_.acknowledgements;
        } else {
            ++metrics_.send_failures;
            metrics_.last_send_error = static_cast<std::uint32_t>(send_result.error);
        }
    }
    running_ = false;
    closesocket(socket_handle);
}

}  // namespace vfdual
