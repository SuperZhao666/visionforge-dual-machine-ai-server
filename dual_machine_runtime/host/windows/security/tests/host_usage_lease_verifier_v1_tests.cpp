#include "vfdual/host_data_plane_authorization_gate.hpp"
#include "vfdual/host_usage_lease_verifier_v1.hpp"

#include <array>
#include <cstdlib>
#include <iostream>
#include <string>

namespace {

constexpr std::array<std::uint8_t, 422U> kFixturePublicSpkiDer{
    0x30U, 0x82U, 0x01U, 0xa2U, 0x30U, 0x0dU, 0x06U, 0x09U, 0x2aU, 0x86U, 0x48U, 0x86U,
    0xf7U, 0x0dU, 0x01U, 0x01U, 0x01U, 0x05U, 0x00U, 0x03U, 0x82U, 0x01U, 0x8fU, 0x00U,
    0x30U, 0x82U, 0x01U, 0x8aU, 0x02U, 0x82U, 0x01U, 0x81U, 0x00U, 0x9dU, 0xedU, 0x67U,
    0xabU, 0x71U, 0x0fU, 0xd3U, 0xfaU, 0xffU, 0x73U, 0xe3U, 0x17U, 0x23U, 0x25U, 0x38U,
    0x04U, 0x20U, 0x21U, 0x62U, 0x0cU, 0xb7U, 0x60U, 0x76U, 0x1fU, 0xceU, 0x95U, 0x50U,
    0x30U, 0x85U, 0xb4U, 0xbeU, 0x34U, 0x21U, 0x3eU, 0x58U, 0x65U, 0x31U, 0x25U, 0x55U,
    0xeeU, 0x01U, 0x8eU, 0xafU, 0x16U, 0xdcU, 0xd0U, 0x6dU, 0xffU, 0x02U, 0x8aU, 0x20U,
    0x94U, 0xd3U, 0x3dU, 0x98U, 0xfaU, 0x5aU, 0x67U, 0xcfU, 0xdeU, 0x56U, 0xe4U, 0x28U,
    0xb7U, 0x4aU, 0x92U, 0xecU, 0xb4U, 0xc4U, 0xe8U, 0x75U, 0xc2U, 0xa1U, 0xe0U, 0xabU,
    0x2eU, 0xf9U, 0xc2U, 0x01U, 0xe8U, 0xc5U, 0xf7U, 0x98U, 0xefU, 0x7fU, 0x58U, 0x03U,
    0x4aU, 0x13U, 0x96U, 0xedU, 0x98U, 0x58U, 0xf9U, 0x5fU, 0x82U, 0xfaU, 0x2bU, 0xb7U,
    0xacU, 0x4bU, 0xa0U, 0xcfU, 0x60U, 0xbbU, 0x16U, 0xb1U, 0xe4U, 0xeeU, 0xabU, 0x19U,
    0x48U, 0x58U, 0xedU, 0x2eU, 0x8eU, 0x6fU, 0xaeU, 0xe3U, 0xb4U, 0xf0U, 0x4cU, 0x69U,
    0xcbU, 0xa9U, 0x84U, 0xa8U, 0x84U, 0xdeU, 0xe1U, 0xf2U, 0x8dU, 0x72U, 0xe2U, 0xceU,
    0xa2U, 0x18U, 0x56U, 0x2dU, 0xefU, 0xbcU, 0xf3U, 0x58U, 0x00U, 0x03U, 0xf8U, 0xeaU,
    0x56U, 0x3aU, 0x25U, 0x87U, 0x7dU, 0x5aU, 0x5bU, 0x89U, 0xc6U, 0x0eU, 0xcaU, 0x96U,
    0xe4U, 0xcbU, 0x41U, 0x57U, 0x01U, 0x9cU, 0x13U, 0x2cU, 0x78U, 0x2aU, 0x0aU, 0x67U,
    0xebU, 0xf0U, 0x4cU, 0xbdU, 0x4bU, 0x12U, 0xb4U, 0x30U, 0x9fU, 0xbaU, 0xb3U, 0x45U,
    0xa2U, 0x79U, 0x96U, 0xfdU, 0x31U, 0x4eU, 0x3eU, 0x2bU, 0x45U, 0xacU, 0xd6U, 0xefU,
    0x5aU, 0x21U, 0xb0U, 0x22U, 0xb3U, 0x6fU, 0xf8U, 0xfeU, 0xe2U, 0x6eU, 0x6aU, 0x8eU,
    0x04U, 0x2cU, 0xd9U, 0x2fU, 0x8aU, 0xf8U, 0x9aU, 0xb2U, 0xc4U, 0x14U, 0x4dU, 0x60U,
    0x3eU, 0xeeU, 0x5eU, 0x91U, 0x98U, 0x34U, 0xd7U, 0x24U, 0x02U, 0x91U, 0x3fU, 0xc4U,
    0x1fU, 0x30U, 0xd8U, 0x3cU, 0x12U, 0x3aU, 0xabU, 0x8dU, 0xcbU, 0xd7U, 0xfaU, 0xc9U,
    0x0bU, 0xddU, 0x3bU, 0xe9U, 0x4eU, 0xa1U, 0x5cU, 0xaaU, 0x5aU, 0x21U, 0x43U, 0x44U,
    0x4fU, 0x29U, 0x75U, 0xdfU, 0xefU, 0x63U, 0x19U, 0xb0U, 0xb8U, 0x42U, 0x03U, 0x5aU,
    0x4bU, 0x7dU, 0x9dU, 0xedU, 0x6dU, 0xc3U, 0x5bU, 0x65U, 0xcdU, 0x4dU, 0x71U, 0x0dU,
    0xedU, 0x05U, 0x7eU, 0x7cU, 0x3eU, 0xefU, 0x97U, 0x0cU, 0x4bU, 0xddU, 0x86U, 0x9cU,
    0x88U, 0x3fU, 0x07U, 0x49U, 0x97U, 0xf1U, 0x4eU, 0x37U, 0x64U, 0xffU, 0x4cU, 0xa3U,
    0xf8U, 0x3dU, 0x1aU, 0x9aU, 0xb6U, 0x10U, 0x0bU, 0x9dU, 0xdeU, 0xc6U, 0x6aU, 0x61U,
    0x22U, 0xbaU, 0x64U, 0xe3U, 0xd4U, 0xfcU, 0xc2U, 0x26U, 0xd6U, 0xdaU, 0x8aU, 0x35U,
    0x24U, 0xd7U, 0x01U, 0x52U, 0xb9U, 0x14U, 0x04U, 0xa6U, 0x4eU, 0x36U, 0x21U, 0x03U,
    0xbeU, 0x50U, 0x98U, 0xb5U, 0xcdU, 0x7aU, 0xcbU, 0x4eU, 0x49U, 0x9dU, 0x51U, 0xafU,
    0x11U, 0xc1U, 0x8fU, 0xe3U, 0x3aU, 0xb7U, 0x69U, 0x2aU, 0xfdU, 0x23U, 0x21U, 0x01U,
    0xe9U, 0xc0U, 0xc9U, 0x2fU, 0x30U, 0x7aU, 0xa8U, 0xc5U, 0xbbU, 0xbaU, 0xb2U, 0xfcU,
    0xf4U, 0xf6U, 0x83U, 0xdeU, 0x6aU, 0x36U, 0x40U, 0x43U, 0xe7U, 0x02U, 0x03U, 0x01U,
    0x00U, 0x01U,
};

constexpr std::string_view kValidToken{
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhmZGZhNDdiMjhkYTI2MWYiLCJ0eXAiOiJKV1QifQ.eyJha2giOiI1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1IiwiYXVkIjoidmlzaW9uZm9yZ2UtZHVhbC1tYWNoaW5lLWRhdGEtcGxhbmUiLCJhdXRob3JpemF0aW9uX2tpbmQiOiJkYXkiLCJjYmgiOiI2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2IiwiZXhwIjoxNzAwMDAwMDA1LCJoa2giOiI0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0IiwiaWF0IjoxNzAwMDAwMDAwLCJpc19wZXJtYW5lbnQiOmZhbHNlLCJpc3MiOiJ2aXNpb25mb3JnZS1kdWFsLW1hY2hpbmUtc2VydmljZSIsImp0aSI6IjczZjJmYjE4NjZjN2RkY2FkYjE1NDc0Zjg5ZDRkY2QwIiwibmJmIjoxNzAwMDAwMDAwLCJwaGFzZSI6ImFjdGl2ZSIsInBpZCI6IjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyIiwicHRoIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInB2IjoyLCJyZW1haW5pbmciOjM2MDAsInJ2Ijo3LCJzZXEiOjAsInNpZCI6IjMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzIiwic3ViIjoiMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTEiLCJ0eXAiOiJ2Zi1kdWFsLW1hY2hpbmUtdXNhZ2UtbGVhc2UtdjEifQ.ZGN8cWG6n5s40LCH2Q09T2FZ81Hx9g4uicHv24wlKESysDfkKLvM906zcsbKp7kDdDIUJLpal8_l2dxzGJbIzGGSe6eBgisapspdGFmz603VctGaVmmeSo91AcWEXPdB1FkUknaYmOEytqxrNh9wOtwJ0o3BULFhlpinIgg4AJ4gbgVRxfbfhSt9qrIUNNv53E9LhkCnFDDNjvlJv_KqxWjDS0asy9yEUsxo2kR8HW58oqAngsNF21-qK5w_v2vt0C9RfoqCx9Tm-914nydPBd9j9GK1Xx1kX8BEGtNv07KPmXVBMX22B9vHy3HPklI-I5QbDmaLvmNMlEwe2X5eSDpuehKZFNp2IJAyUY8hr9uv0gY8Ks4y0B5wRbOfpYJ6dmbo37b4tEzqScUSywquR7Tm2WEDV9MdNC__jw2DESmPyDIltqUCpkDR1JW3i3e2v-zBZMtzkqJUrLOjaPa-QBDAEq0786pVtKqKsDxZhQVR1iEVZpd4qmubqMxp0SNw"};

constexpr std::string_view kTokenSha256{
    "6df49290a80131b5a8a3e13a85d5a30fe7ccf97bfb57cd5ce1501490d46e9780"};

void require(const bool condition, const char* expression, const int line) {
    if (condition) return;
    std::cerr << "CHECK failed: " << expression << " (line " << line << ")\n";
    std::exit(EXIT_FAILURE);
}

#define VFDUAL_TEST_REQUIRE(expression) \
    require(static_cast<bool>(expression), #expression, __LINE__)

std::string hex(const char value, const std::size_t size) {
    return std::string(size, value);
}

vfdual::UsageLeaseBinding expected_binding() {
    return {
        .entitlement_id = hex('1', 32U),
        .pair_id = hex('2', 32U),
        .session_id = hex('3', 32U),
        .protocol_version = vfdual::kUsageLeaseProtocolVersion,
        .revocation_version = 7U,
        .host_key_sha256 = hex('4', 64U),
        .android_key_sha256 = hex('5', 64U),
        .channel_binding_sha256 = hex('6', 64U),
    };
}

std::unique_ptr<vfdual::HostUsageLeaseVerifierV1> make_verifier() {
    const std::array keys{
        vfdual::HostUsageLeaseTestPublicKeyV1{kFixturePublicSpkiDer}};
    auto result =
        vfdual::HostUsageLeaseVerifierV1::create_for_test_fixture_keyring(keys);
    VFDUAL_TEST_REQUIRE(result.succeeded());
    return std::move(result.verifier);
}

void verifies_server_contract_and_opens_gate() {
    auto verifier = make_verifier();
    auto verified = verifier->verify(kValidToken, expected_binding(), 1'700'000'000U);
    VFDUAL_TEST_REQUIRE(verified.succeeded());
    VFDUAL_TEST_REQUIRE(verified.lease->ticket_sha256 == kTokenSha256);
    VFDUAL_TEST_REQUIRE(verified.lease->claims.sequence == 0U);
    VFDUAL_TEST_REQUIRE(verified.lease->claims.authorization_kind == "day");
    VFDUAL_TEST_REQUIRE(!verified.lease->claims.is_permanent);
    VFDUAL_TEST_REQUIRE(verified.lease->claims.remaining_seconds == 3'600U);
    VFDUAL_TEST_REQUIRE(
        verified.lease->claims.lease_id == "73f2fb1866c7ddcadb15474f89d4dcd0");

    std::uint64_t monotonic_milliseconds = 100'000U;
    vfdual::HostDataPlaneAuthorizationGate gate(
        [&monotonic_milliseconds] { return monotonic_milliseconds; });
    VFDUAL_TEST_REQUIRE(gate.install_confirmed_peer_binding(expected_binding()));
    VFDUAL_TEST_REQUIRE(gate.submit_verified_ticket(
                            *verified.lease, 1'700'000'000U) ==
                        vfdual::UsageLeaseAdmission::accepted_current);
    VFDUAL_TEST_REQUIRE(gate.permits_data_plane());
    monotonic_milliseconds += 5'000U;
    VFDUAL_TEST_REQUIRE(!gate.permits_data_plane());
}

void rejects_tampering_wrong_binding_and_time() {
    auto verifier = make_verifier();
    std::string tampered{kValidToken};
    tampered.back() = tampered.back() == 'A' ? 'B' : 'A';
    VFDUAL_TEST_REQUIRE(!verifier->verify(
                             tampered, expected_binding(), 1'700'000'000U)
                             .succeeded());

    auto wrong_binding = expected_binding();
    wrong_binding.channel_binding_sha256 = hex('7', 64U);
    VFDUAL_TEST_REQUIRE(!verifier->verify(
                             kValidToken, wrong_binding, 1'700'000'000U)
                             .succeeded());
    VFDUAL_TEST_REQUIRE(!verifier->verify(
                             kValidToken,
                             expected_binding(),
                             1'700'000'005U)
                             .succeeded());
    VFDUAL_TEST_REQUIRE(!verifier->verify(
                             kValidToken,
                             expected_binding(),
                             1'699'999'997U)
                             .succeeded());
}

void rejects_empty_duplicate_and_invalid_context() {
    const std::array<vfdual::HostUsageLeaseTestPublicKeyV1, 0U> no_keys{};
    VFDUAL_TEST_REQUIRE(
        !vfdual::HostUsageLeaseVerifierV1::create_for_test_fixture_keyring(
             no_keys)
             .succeeded());
    const std::array duplicate_keys{
        vfdual::HostUsageLeaseTestPublicKeyV1{kFixturePublicSpkiDer},
        vfdual::HostUsageLeaseTestPublicKeyV1{kFixturePublicSpkiDer}};
    VFDUAL_TEST_REQUIRE(
        !vfdual::HostUsageLeaseVerifierV1::create_for_test_fixture_keyring(
             duplicate_keys)
             .succeeded());

    auto verifier = make_verifier();
    auto invalid = expected_binding();
    invalid.host_key_sha256 = hex('0', 64U);
    const auto result = verifier->verify(kValidToken, invalid, 1'700'000'000U);
    VFDUAL_TEST_REQUIRE(!result.succeeded());
    VFDUAL_TEST_REQUIRE(
        result.error.code ==
        vfdual::HostUsageLeaseVerificationErrorCodeV1::source_invalid);
}

void confirmed_peer_adopts_only_the_server_signed_session() {
    auto verifier = make_verifier();
    auto peer_binding = expected_binding();
    peer_binding.session_id.clear();
    auto verified = verifier
        ->verify_for_confirmed_peer_with_signed_session(
            kValidToken, peer_binding, 1'700'000'000U);
    VFDUAL_TEST_REQUIRE(verified.succeeded());
    VFDUAL_TEST_REQUIRE(
        verified.lease->claims.session_id == hex('3', 32U));

    // The exact-session API remains strict, and the peer API cannot be used
    // with a caller-selected session id or a changed channel binding.
    VFDUAL_TEST_REQUIRE(!verifier->verify(
                             kValidToken,
                             peer_binding,
                             1'700'000'000U)
                             .succeeded());
    peer_binding.session_id = hex('3', 32U);
    VFDUAL_TEST_REQUIRE(
        !verifier->verify_for_confirmed_peer_with_signed_session(
                     kValidToken,
                     peer_binding,
                     1'700'000'000U)
                     .succeeded());
    peer_binding.session_id.clear();
    peer_binding.channel_binding_sha256 = hex('7', 64U);
    VFDUAL_TEST_REQUIRE(
        !verifier->verify_for_confirmed_peer_with_signed_session(
                     kValidToken,
                     peer_binding,
                     1'700'000'000U)
                     .succeeded());
}

}  // namespace

int main() {
    verifies_server_contract_and_opens_gate();
    rejects_tampering_wrong_binding_and_time();
    rejects_empty_duplicate_and_invalid_context();
    confirmed_peer_adopts_only_the_server_signed_session();
    return EXIT_SUCCESS;
}
