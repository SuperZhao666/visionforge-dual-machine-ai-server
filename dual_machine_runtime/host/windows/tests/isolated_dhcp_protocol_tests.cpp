#include "vfdual/isolated_dhcp_protocol.hpp"
#include "vfdual/isolated_dhcp_server.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <cstdint>
#include <cstring>
#include <map>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#ifndef VFDUAL_SOURCE_DIR
#error "VFDUAL_SOURCE_DIR must point at the dual_machine_runtime source directory"
#endif

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
    std::exit(EXIT_FAILURE);
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

namespace {

constexpr std::size_t kBootpFixedBytes = 236;
constexpr std::array<std::uint8_t, 4> kCookie{99, 130, 83, 99};
constexpr std::array<std::uint8_t, 6> kPhoneMac{0x00, 0xe0, 0x4c, 0x2f, 0x2f, 0x08};
constexpr std::array<std::uint8_t, 6> kOtherMac{0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
constexpr std::uint32_t kXid = 0x78563412U;

std::uint32_t network_address(std::array<std::uint8_t, 4> octets) {
    std::uint32_t value{};
    std::memcpy(&value, octets.data(), octets.size());
    return value;
}

void append_option(std::vector<std::uint8_t>& packet, std::uint8_t code,
                   std::span<const std::uint8_t> value) {
    packet.push_back(code);
    packet.push_back(static_cast<std::uint8_t>(value.size()));
    packet.insert(packet.end(), value.begin(), value.end());
}

void append_u32(std::vector<std::uint8_t>& packet, std::uint8_t code, std::uint32_t value) {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&value);
    append_option(packet, code, std::span<const std::uint8_t>(bytes, 4));
}

std::string read_source(const char* relative_path) {
    const std::string path = std::string{VFDUAL_SOURCE_DIR} + "/" + relative_path;
    std::ifstream input{path, std::ios::binary};
    CHECK(input.good());
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

std::string slice_between(
    const std::string& source, const std::string& begin, const std::string& end) {
    const std::size_t begin_index = source.find(begin);
    CHECK(begin_index != std::string::npos);
    const std::size_t end_index = source.find(end, begin_index + begin.size());
    CHECK(end_index != std::string::npos);
    return source.substr(begin_index, end_index - begin_index);
}

std::vector<std::uint8_t> request_packet(
    std::uint8_t message_type, std::uint32_t xid, const std::array<std::uint8_t, 6>& mac,
    std::uint32_t requested_address = 0, std::uint32_t server_identifier = 0,
    std::uint32_t client_address = 0) {
    std::vector<std::uint8_t> packet(kBootpFixedBytes, 0);
    packet[0] = 1;
    packet[1] = 1;
    packet[2] = 6;
    std::memcpy(packet.data() + 4, &xid, 4);
    std::memcpy(packet.data() + 12, &client_address, 4);
    std::copy(mac.begin(), mac.end(), packet.begin() + 28);
    packet.insert(packet.end(), kCookie.begin(), kCookie.end());
    append_option(packet, 53, std::span<const std::uint8_t>(&message_type, 1));
    if (requested_address != 0) append_u32(packet, 50, requested_address);
    if (server_identifier != 0) append_u32(packet, 54, server_identifier);
    packet.push_back(255);
    return packet;
}

std::map<std::uint8_t, std::vector<std::uint8_t>> parse_options(
    const std::vector<std::uint8_t>& packet) {
    std::map<std::uint8_t, std::vector<std::uint8_t>> options;
    std::size_t cursor = kBootpFixedBytes + kCookie.size();
    while (cursor < packet.size()) {
        const auto code = packet[cursor++];
        if (code == 255) break;
        if (code == 0) continue;
        CHECK(cursor < packet.size());
        const std::size_t length = packet[cursor++];
        CHECK(length <= packet.size() - cursor);
        options.emplace(code, std::vector<std::uint8_t>(
            packet.begin() + static_cast<std::ptrdiff_t>(cursor),
            packet.begin() + static_cast<std::ptrdiff_t>(cursor + length)));
        cursor += length;
    }
    return options;
}

vfdual::IsolatedDhcpProtocolConfig valid_config() {
    return {
        network_address({10, 57, 23, 1}),
        network_address({10, 57, 23, 2}),
        network_address({255, 255, 255, 0}),
    };
}

void test_dora_and_minimal_options() {
    const auto config = valid_config();
    vfdual::IsolatedDhcpProtocol protocol(config);
    CHECK(protocol.valid());

    const auto discover = request_packet(1, kXid, kPhoneMac);
    const auto offer = protocol.process(discover);
    CHECK(offer.accepted);
    CHECK(offer.request_message_type == 1);
    CHECK(offer.response_message_type == 2);
    CHECK(offer.reply.size() == 300);
    CHECK(std::equal(discover.begin() + 4, discover.begin() + 8, offer.reply.begin() + 4));
    CHECK(std::equal(kPhoneMac.begin(), kPhoneMac.end(), offer.reply.begin() + 28));
    CHECK(std::memcmp(offer.reply.data() + 16, &config.lease_address_network_order, 4) == 0);
    CHECK(std::memcmp(offer.reply.data() + 20, &config.server_address_network_order, 4) == 0);

    const auto options = parse_options(offer.reply);
    const std::array<std::uint8_t, 6> expected_codes{1, 51, 53, 54, 58, 59};
    CHECK(options.size() == expected_codes.size());
    for (const auto code : expected_codes) CHECK(options.contains(code));
    CHECK(!options.contains(3));
    CHECK(!options.contains(6));
    CHECK(options.at(53) == std::vector<std::uint8_t>{2});
    protocol.commit_sent_response(offer);

    const auto selecting_request = request_packet(
        3, kXid, kPhoneMac, config.lease_address_network_order,
        config.server_address_network_order);
    const auto acknowledgement = protocol.process(selecting_request);
    CHECK(acknowledgement.accepted);
    CHECK(acknowledgement.response_message_type == 5);
    CHECK(parse_options(acknowledgement.reply).at(53) == std::vector<std::uint8_t>{5});
    protocol.commit_sent_response(acknowledgement);
    CHECK(protocol.rejected_packets() == 0);

    const auto renewal = request_packet(
        3, 0x44332211U, kPhoneMac, 0, 0, config.lease_address_network_order);
    CHECK(protocol.process(renewal).accepted);
}

void test_transaction_identity_and_address_rejections() {
    const auto config = valid_config();
    vfdual::IsolatedDhcpProtocol protocol(config);

    const auto request_without_offer = protocol.process(request_packet(
        3, kXid, kPhoneMac, config.lease_address_network_order,
        config.server_address_network_order));
    CHECK(!request_without_offer.accepted);
    CHECK(request_without_offer.reject_reason ==
          vfdual::IsolatedDhcpRejectReason::request_without_offer);
    const auto phone_offer = protocol.process(request_packet(1, kXid, kPhoneMac));
    CHECK(phone_offer.accepted);
    protocol.commit_sent_response(phone_offer);
    const auto other_pending_client =
        protocol.process(request_packet(1, 0x10203040U, kOtherMac));
    CHECK(!other_pending_client.accepted);
    CHECK(other_pending_client.reject_reason ==
          vfdual::IsolatedDhcpRejectReason::client_mismatch);
    const auto wrong_transaction = protocol.process(request_packet(
        3, 0x01020304U, kPhoneMac, config.lease_address_network_order,
        config.server_address_network_order));
    CHECK(!wrong_transaction.accepted);
    CHECK(wrong_transaction.reject_reason ==
          vfdual::IsolatedDhcpRejectReason::transaction_mismatch);
    const auto wrong_address = protocol.process(request_packet(
        3, kXid, kPhoneMac, network_address({10, 57, 23, 99}),
        config.server_address_network_order));
    CHECK(!wrong_address.accepted);
    CHECK(wrong_address.reject_reason ==
          vfdual::IsolatedDhcpRejectReason::requested_address_mismatch);
    const auto wrong_server = protocol.process(request_packet(
        3, kXid, kPhoneMac, config.lease_address_network_order,
        network_address({10, 57, 23, 99})));
    CHECK(!wrong_server.accepted);
    CHECK(wrong_server.reject_reason ==
          vfdual::IsolatedDhcpRejectReason::server_identifier_mismatch);

    const auto phone_ack = protocol.process(request_packet(
        3, kXid, kPhoneMac, config.lease_address_network_order,
        config.server_address_network_order));
    CHECK(phone_ack.accepted);
    protocol.commit_sent_response(phone_ack);
    const auto leased_to_other = protocol.process(
        request_packet(1, 0x11223344U, kOtherMac));
    CHECK(!leased_to_other.accepted);
    CHECK(leased_to_other.reject_reason ==
          vfdual::IsolatedDhcpRejectReason::lease_owned_by_other_client);

    auto malformed = request_packet(1, kXid, kPhoneMac);
    malformed[2] = 5;
    CHECK(!protocol.process(malformed).accepted);
    CHECK(!protocol.process(request_packet(1, kXid, {})).accepted);
    CHECK(!protocol.process(request_packet(
        1, kXid, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff})).accepted);
    CHECK(protocol.rejected_packets() == 9);
}

void test_local_interface_discover_is_excluded() {
    auto config = valid_config();
    config.excluded_client_mac = kOtherMac;
    config.has_excluded_client_mac = true;
    vfdual::IsolatedDhcpProtocol protocol(config);

    const auto local_discover = protocol.process(request_packet(1, kXid, kOtherMac));
    CHECK(!local_discover.accepted);
    CHECK(local_discover.reject_reason ==
          vfdual::IsolatedDhcpRejectReason::local_interface_client);
    CHECK(protocol.process(request_packet(1, kXid, kPhoneMac)).accepted);
}

void test_failed_offer_send_does_not_lock_client() {
    vfdual::IsolatedDhcpProtocol protocol(valid_config());
    const auto unsent_offer = protocol.process(request_packet(1, kXid, kOtherMac));
    CHECK(unsent_offer.accepted);

    const auto phone_offer =
        protocol.process(request_packet(1, 0x10203040U, kPhoneMac));
    CHECK(phone_offer.accepted);
    protocol.commit_sent_response(phone_offer);

    const auto late_other_client =
        protocol.process(request_packet(1, 0x11223344U, kOtherMac));
    CHECK(!late_other_client.accepted);
    CHECK(late_other_client.reject_reason ==
          vfdual::IsolatedDhcpRejectReason::client_mismatch);
}

void test_configuration_and_exact_interface_binding() {
    CHECK(std::strcmp(vfdual::isolated_dhcp_startup_stage_name(
              vfdual::IsolatedDhcpStartupStage::find_interface),
          "find_interface") == 0);
    CHECK(std::strcmp(vfdual::isolated_dhcp_startup_stage_name(
              vfdual::IsolatedDhcpStartupStage::worker_thread),
          "worker_thread") == 0);

    auto config = valid_config();
    config.lease_address_network_order = network_address({10, 57, 24, 2});
    CHECK(!vfdual::IsolatedDhcpProtocol(config).valid());

    vfdual::IsolatedDhcpServer server;
    CHECK(!server.start("203.0.113.1", "203.0.113.2", "255.255.255.0"));
    CHECK(!server.running());
    CHECK(server.last_error() != 0);
    CHECK(server.startup_stage() ==
          vfdual::IsolatedDhcpStartupStage::find_interface);

    vfdual::IsolatedDhcpServer first;
    vfdual::IsolatedDhcpServer second;
    CHECK(first.start("127.0.0.1", "127.0.0.2", "255.0.0.0", 17667, 17668));
    const vfdual::IsolatedDhcpMetrics first_metrics = first.metrics();
    CHECK(first_metrics.interface_index != 0U);
    CHECK(first_metrics.interface_filter_active != 0U ||
          first_metrics.packet_info_active != 0U);
    CHECK(!second.start("127.0.0.1", "127.0.0.2", "255.0.0.0", 17667, 17668));
    CHECK(second.last_error() != 0);
    first.stop();
}

void test_server_noexcept_start_catches_worker_thread_creation_failure() {
    const std::string header =
        read_source("host/windows/include/vfdual/isolated_dhcp_server.hpp");
    const std::string source =
        read_source("host/windows/src/isolated_dhcp_server.cpp");
    CHECK(header.find(") noexcept;") != std::string::npos);
    const std::string start_method = slice_between(
        source, "bool IsolatedDhcpServer::start(",
        "void IsolatedDhcpServer::stop()");
    const std::size_t worker_stage_index = start_method.find(
        "set_startup_stage(IsolatedDhcpStartupStage::worker_thread);");
    const std::size_t worker_assignment_index =
        start_method.find("worker_ = std::thread");
    const std::size_t catch_index =
        start_method.find("catch (const std::exception&)");
    CHECK(worker_stage_index != std::string::npos);
    CHECK(worker_assignment_index != std::string::npos);
    CHECK(catch_index != std::string::npos);
    CHECK(worker_stage_index < worker_assignment_index);
    CHECK(worker_assignment_index < catch_index);
    CHECK(start_method.find("last_error_ = WSAENOBUFS;") != std::string::npos);
    CHECK(start_method.find("return false;", catch_index) != std::string::npos);
}

}  // namespace

int main() {
    test_dora_and_minimal_options();
    test_transaction_identity_and_address_rejections();
    test_local_interface_discover_is_excluded();
    test_failed_offer_send_does_not_lock_client();
    test_configuration_and_exact_interface_binding();
    test_server_noexcept_start_catches_worker_thread_creation_failure();
    return 0;
}
