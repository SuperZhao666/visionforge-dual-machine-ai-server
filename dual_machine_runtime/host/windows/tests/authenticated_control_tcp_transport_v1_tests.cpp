#include "vfdual/authenticated_control_tcp_transport_v1.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <string_view>
#include <thread>
#include <vector>

namespace {

void require(
    const bool condition,
    const char* expression,
    const char* file,
    const int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: "
              << expression << '\n';
    std::exit(EXIT_FAILURE);
}

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

[[nodiscard]] std::vector<std::byte> ascii(
    const std::string_view value) {
    std::vector<std::byte> result;
    result.reserve(value.size());
    std::transform(
        value.begin(), value.end(), std::back_inserter(result),
        [](const char character) {
            return std::byte{static_cast<std::uint8_t>(character)};
        });
    return result;
}

[[nodiscard]] vfdual::ControlBootstrapEncodeResultV1 encode(
    const vfdual::ControlBootstrapDirectionV1 direction,
    const vfdual::ControlBootstrapMessageTypeV1 type,
    const std::string_view payload) {
    auto result = vfdual::encode_authenticated_control_bootstrap_record_v1(
        direction, type, ascii(payload));
    CHECK(result.status ==
        vfdual::ControlBootstrapEncodeStatusV1::encoded);
    return result;
}

[[nodiscard]] vfdual::AuthenticatedControlTrafficKeyV1
authenticated_traffic_key(
    const vfdual::ControlRecordDirectionV1 direction) {
    vfdual::AuthenticatedControlTrafficKeyV1 key;
    key.tuple = {
        .connection_id = 0x0102030405060708ULL,
        .session_generation = 7U,
        .key_epoch = 1U,
        .direction = direction,
    };
    for (std::size_t index{}; index < key.aes_256_key.size(); ++index) {
        key.aes_256_key[index] = std::byte{
            static_cast<std::uint8_t>(0x20U + index)};
    }
    for (std::size_t index{}; index < key.nonce_prefix.size(); ++index) {
        key.nonce_prefix[index] = std::byte{
            static_cast<std::uint8_t>(0xa0U + index)};
    }
    return key;
}

void test_loopback_reads_writes_and_preserves_record_boundaries() {
    using D = vfdual::ControlBootstrapDirectionV1;
    using M = vfdual::ControlBootstrapMessageTypeV1;
    using T = vfdual::AuthenticatedControlTcpStatusV1;

    vfdual::AuthenticatedControlTcpListenerV1 listener;
    CHECK(listener.start("127.0.0.1", 0U).succeeded());
    const std::uint16_t port = listener.local_port();
    CHECK(port != 0U);

    const auto inbound = encode(
        D::android_to_host, M::android_challenge_request,
        "android-challenge");
    const auto first_outbound = encode(
        D::host_to_android, M::host_challenge_proof,
        "host-proof-one");
    const auto second_outbound = encode(
        D::host_to_android, M::host_final_proof,
        "host-proof-two");
    std::atomic_bool server_finished{};
    std::thread server([&] {
        auto accepted = listener.accept("127.0.0.1", 2'000U);
        CHECK(accepted.succeeded());
        CHECK(accepted.connection->local_ipv4() == "127.0.0.1");
        CHECK(accepted.connection->peer_ipv4() == "127.0.0.1");
        CHECK(accepted.connection->local_port() == port);
        CHECK(accepted.connection->peer_port() != 0U);
        auto read = accepted.connection->read_bootstrap_record(
            D::android_to_host, 2'000U);
        CHECK(read.succeeded());
        CHECK(read.encoded_record == inbound.record);
        CHECK(accepted.connection->write_bootstrap_record(
            first_outbound.record, D::host_to_android, 2'000U).succeeded());
        CHECK(accepted.connection->write_bootstrap_record(
            second_outbound.record, D::host_to_android, 2'000U).succeeded());
        server_finished.store(true, std::memory_order_release);
    });

    auto connected = vfdual::AuthenticatedControlTcpConnectionV1::connect(
        {}, "127.0.0.1", port, 2'000U);
    CHECK(connected.succeeded());
    CHECK(connected.connection->peer_port() == port);
    CHECK(connected.connection->write_bootstrap_record(
        inbound.record, D::android_to_host, 2'000U).succeeded());
    auto first = connected.connection->read_bootstrap_record(
        D::host_to_android, 2'000U);
    CHECK(first.succeeded());
    CHECK(first.encoded_record == first_outbound.record);
    auto second = connected.connection->read_bootstrap_record(
        D::host_to_android, 2'000U);
    CHECK(second.succeeded());
    CHECK(second.encoded_record == second_outbound.record);
    server.join();
    CHECK(server_finished.load(std::memory_order_acquire));
    CHECK(connected.connection->is_open());
    connected.connection->close();
    CHECK(!connected.connection->is_open());
    CHECK(connected.error.status == T::succeeded);
}

void test_maximum_record_completes_short_write_loop() {
    using D = vfdual::ControlBootstrapDirectionV1;
    using M = vfdual::ControlBootstrapMessageTypeV1;
    std::vector<std::byte> payload(
        vfdual::kMaximumAuthenticatedControlBootstrapPayloadBytes,
        std::byte{0xa5U});
    const auto encoded =
        vfdual::encode_authenticated_control_bootstrap_record_v1(
            D::host_to_android,
            M::host_handshake_signature,
            payload);
    CHECK(encoded.status ==
        vfdual::ControlBootstrapEncodeStatusV1::encoded);

    vfdual::AuthenticatedControlTcpListenerV1 listener;
    CHECK(listener.start("127.0.0.1", 0U).succeeded());
    const std::uint16_t port = listener.local_port();
    std::thread server([&] {
        auto accepted = listener.accept("127.0.0.1", 2'000U);
        CHECK(accepted.succeeded());
        CHECK(accepted.connection->write_bootstrap_record(
            encoded.record, D::host_to_android, 2'000U).succeeded());
    });
    auto client = vfdual::AuthenticatedControlTcpConnectionV1::connect(
        {}, "127.0.0.1", port, 2'000U);
    CHECK(client.succeeded());
    auto received = client.connection->read_bootstrap_record(
        D::host_to_android, 2'000U);
    CHECK(received.succeeded());
    CHECK(received.encoded_record == encoded.record);
    server.join();
}

void test_coalesced_authenticated_header_and_body_complete_without_stall() {
    using D = vfdual::ControlRecordDirectionV1;
    using M = vfdual::ControlMessageTypeV1;

    auto provider = vfdual::make_platform_aes_256_gcm_provider();
    CHECK(provider != nullptr);
    vfdual::AuthenticatedControlRecordSealerV1 sealer(
        authenticated_traffic_key(D::android_to_host), *provider);
    std::array<std::byte, 16U> nonce{};
    for (std::size_t index{}; index < nonce.size(); ++index) {
        nonce[index] = std::byte{static_cast<std::uint8_t>(index + 1U)};
    }
    auto sealed = sealer.seal(
        M::usage_authorization_sign_request, nonce);
    CHECK(sealed.status == vfdual::ControlRecordSealStatusV1::sealed);

    vfdual::AuthenticatedControlTcpListenerV1 listener;
    CHECK(listener.start("127.0.0.1", 0U).succeeded());
    const std::uint16_t port = listener.local_port();
    std::thread server([&] {
        auto accepted = listener.accept("127.0.0.1", 2'000U);
        CHECK(accepted.succeeded());
        auto received = accepted.connection->read_authenticated_record(
            D::android_to_host, 250U);
        CHECK(received.succeeded());
        CHECK(received.encoded_record == sealed.envelope);
    });
    auto client = vfdual::AuthenticatedControlTcpConnectionV1::connect(
        {}, "127.0.0.1", port, 2'000U);
    CHECK(client.succeeded());
    CHECK(client.connection->write_authenticated_record(
        sealed.envelope, D::android_to_host, 2'000U).succeeded());
    server.join();
}

void test_timeout_peer_mismatch_and_invalid_write_fail_closed() {
    using D = vfdual::ControlBootstrapDirectionV1;
    using M = vfdual::ControlBootstrapMessageTypeV1;
    using T = vfdual::AuthenticatedControlTcpStatusV1;

    vfdual::AuthenticatedControlTcpListenerV1 idle;
    CHECK(idle.start("127.0.0.1", 0U).succeeded());
    const auto timed_out = idle.accept("127.0.0.1", 20U);
    CHECK(timed_out.error.status == T::timed_out);
    CHECK(idle.is_open());

    vfdual::AuthenticatedControlTcpListenerV1 mismatch_listener;
    CHECK(mismatch_listener.start("127.0.0.1", 0U).succeeded());
    const std::uint16_t mismatch_port = mismatch_listener.local_port();
    std::thread mismatch_server([&] {
        auto rejected = mismatch_listener.accept("127.0.0.2", 2'000U);
        CHECK(rejected.error.status == T::peer_mismatch);
        CHECK(rejected.connection == nullptr);
    });
    auto mismatch_client =
        vfdual::AuthenticatedControlTcpConnectionV1::connect(
            {}, "127.0.0.1", mismatch_port, 2'000U);
    CHECK(mismatch_client.succeeded());
    mismatch_server.join();

    vfdual::AuthenticatedControlTcpListenerV1 invalid_listener;
    CHECK(invalid_listener.start("127.0.0.1", 0U).succeeded());
    const std::uint16_t invalid_port = invalid_listener.local_port();
    std::thread invalid_server([&] {
        auto accepted = invalid_listener.accept("127.0.0.1", 2'000U);
        CHECK(accepted.succeeded());
        auto read = accepted.connection->read_bootstrap_record(
            D::host_to_android, 2'000U);
        CHECK(read.error.status == T::peer_closed ||
            read.error.status == T::socket_error);
    });
    auto invalid_client =
        vfdual::AuthenticatedControlTcpConnectionV1::connect(
            {}, "127.0.0.1", invalid_port, 2'000U);
    CHECK(invalid_client.succeeded());
    const auto reflected = encode(
        D::host_to_android, M::host_hello, "reflection");
    const auto rejected_write =
        invalid_client.connection->write_bootstrap_record(
            reflected.record, D::android_to_host, 2'000U);
    CHECK(rejected_write.status == T::invalid_record);
    CHECK(!invalid_client.connection->is_open());
    invalid_server.join();
}

void test_explicit_first_pair_accept_exposes_actual_socket_route() {
    vfdual::AuthenticatedControlTcpListenerV1 listener;
    CHECK(listener.start("127.0.0.1", 0U).succeeded());
    const std::uint16_t port = listener.local_port();
    std::thread server([&] {
        auto accepted = listener.accept_untrusted_first_pair(2'000U);
        CHECK(accepted.succeeded());
        CHECK(accepted.connection->local_ipv4() == "127.0.0.1");
        CHECK(accepted.connection->peer_ipv4() == "127.0.0.1");
        CHECK(accepted.connection->local_port() == port);
        CHECK(accepted.connection->peer_port() != 0U);
    });
    auto client = vfdual::AuthenticatedControlTcpConnectionV1::connect(
        {}, "127.0.0.1", port, 2'000U);
    CHECK(client.succeeded());
    server.join();
}

}  // namespace

int main() {
    test_loopback_reads_writes_and_preserves_record_boundaries();
    test_maximum_record_completes_short_write_loop();
    test_coalesced_authenticated_header_and_body_complete_without_stall();
    test_timeout_peer_mismatch_and_invalid_write_fail_closed();
    test_explicit_first_pair_accept_exposes_actual_socket_route();
    std::cout << "authenticated control TCP transport v1 tests passed\n";
    return EXIT_SUCCESS;
}
