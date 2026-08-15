#include "vfdual/usage_authorization_contract.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

#define CHECK(condition)                                                      \
    do {                                                                      \
        if (!(condition)) {                                                   \
            std::cerr << "CHECK failed at line " << __LINE__ << ": "         \
                      << #condition << '\n';                                  \
            return EXIT_FAILURE;                                              \
        }                                                                     \
    } while (false)

std::string repeated(const char character, const std::size_t count) {
    return std::string(count, character);
}

}  // namespace

int main() {
    using namespace vfdual;

    const std::string h1 = repeated('1', 32U);
    const std::string h2 = repeated('2', 32U);
    const std::string h3 = repeated('3', 32U);
    const std::string h4 = repeated('4', 32U);
    const std::string s5 = repeated('5', 64U);
    const std::string s7 = repeated('7', 64U);
    const std::string activation_token_sha256{
        "d066a4f4c1bea1ab8d47372ded551bc3f1d06dcba0608d179c4a6d2844fec548"};
    const std::string empty_device_profile_sha256{
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"};
    const std::string start_token_sha256{
        "e2ae1865c75fe404f1e7b3049aab3c729bc5114998665ea2ff7aaa68cb0e9381"};
    const std::string previous_lease_sha256{
        "292c06e5943f1f0f623acbb683d00c6b5b6ecd5359336fdf7f0f124f1f387434"};

    const ActivationConfirmationProof activation_proof{
        .activation_mode = "activate",
        .android_client_version = "1.0.0",
        .android_device_code = "ANDROID-ABC",
        .android_device_profile_sha256 = empty_device_profile_sha256,
        .android_key_sha256 = s5,
        .challenge_id = h1,
        .challenge_token_sha256 = activation_token_sha256,
        .host_client_version = "17.8.81",
        .host_device_code = "HOST-XYZ",
        .host_key_sha256 = s7,
        .pair_id = h2,
        .protocol_version = 2U,
        .request_id = h3,
        .target_entitlement_id = "",
    };
    const auto activation =
        build_activation_confirmation_payload(activation_proof);
    CHECK(activation.has_value());
    CHECK(*activation ==
        "{\"activation_mode\":\"activate\","
        "\"android_client_version\":\"1.0.0\","
        "\"android_device_code\":\"ANDROID-ABC\","
        "\"android_device_profile_sha256\":\"" +
        empty_device_profile_sha256 +
        "\",\"android_key_sha256\":\"" + s5 +
        "\",\"challenge_id\":\"" + h1 +
        "\",\"challenge_token_sha256\":\"" + activation_token_sha256 +
        "\",\"domain\":\"visionforge-dual-machine-card-activate-v1\","
        "\"host_client_version\":\"17.8.81\","
        "\"host_device_code\":\"HOST-XYZ\","
        "\"host_key_sha256\":\"" + s7 +
        "\",\"pair_id\":\"" + h2 +
        "\",\"protocol_version\":2,\"request_id\":\"" + h3 +
        "\",\"target_entitlement_id\":\"\"}");

    auto bind_device_proof = activation_proof;
    bind_device_proof.activation_mode = "bind_device";
    bind_device_proof.target_entitlement_id = h4;
    const auto bind_device =
        build_activation_confirmation_payload(bind_device_proof);
    CHECK(bind_device.has_value());
    CHECK(*bind_device ==
        "{\"activation_mode\":\"bind_device\"," 
        "\"android_client_version\":\"1.0.0\","
        "\"android_device_code\":\"ANDROID-ABC\","
        "\"android_device_profile_sha256\":\"" +
        empty_device_profile_sha256 +
        "\",\"android_key_sha256\":\"" + s5 +
        "\",\"challenge_id\":\"" + h1 +
        "\",\"challenge_token_sha256\":\"" + activation_token_sha256 +
        "\",\"domain\":\"visionforge-dual-machine-card-activate-v1\","
        "\"host_client_version\":\"17.8.81\","
        "\"host_device_code\":\"HOST-XYZ\","
        "\"host_key_sha256\":\"" + s7 +
        "\",\"pair_id\":\"" + h2 +
        "\",\"protocol_version\":2,\"request_id\":\"" + h3 +
        "\",\"target_entitlement_id\":\"" + h4 + "\"}");

    auto reactivation_proof = activation_proof;
    reactivation_proof.activation_mode = "reactivate";
    reactivation_proof.target_entitlement_id = h4;
    const auto reactivation =
        build_activation_confirmation_payload(reactivation_proof);
    CHECK(reactivation.has_value());
    CHECK(*reactivation ==
        "{\"activation_mode\":\"reactivate\"," 
        "\"android_client_version\":\"1.0.0\"," 
        "\"android_device_code\":\"ANDROID-ABC\"," 
        "\"android_device_profile_sha256\":\"" +
        empty_device_profile_sha256 +
        "\",\"android_key_sha256\":\"" + s5 +
        "\",\"challenge_id\":\"" + h1 +
        "\",\"challenge_token_sha256\":\"" + activation_token_sha256 +
        "\",\"domain\":\"visionforge-dual-machine-card-activate-v1\"," 
        "\"host_client_version\":\"17.8.81\"," 
        "\"host_device_code\":\"HOST-XYZ\"," 
        "\"host_key_sha256\":\"" + s7 +
        "\",\"pair_id\":\"" + h2 +
        "\",\"protocol_version\":2,\"request_id\":\"" + h3 +
        "\",\"target_entitlement_id\":\"" + h4 + "\"}");

    auto invalid_activation = activation_proof;
    invalid_activation.activation_mode = "unsupported";
    CHECK(!build_activation_confirmation_payload(invalid_activation).has_value());
    invalid_activation = activation_proof;
    invalid_activation.target_entitlement_id = h4;
    CHECK(!build_activation_confirmation_payload(invalid_activation).has_value());
    invalid_activation = activation_proof;
    invalid_activation.activation_mode = "bind_device";
    CHECK(!build_activation_confirmation_payload(invalid_activation).has_value());
    invalid_activation.activation_mode = "reactivate";
    CHECK(!build_activation_confirmation_payload(invalid_activation).has_value());
    invalid_activation.target_entitlement_id = repeated('0', 32U);
    CHECK(!build_activation_confirmation_payload(invalid_activation).has_value());
    invalid_activation.target_entitlement_id = repeated('A', 32U);
    CHECK(!build_activation_confirmation_payload(invalid_activation).has_value());
    invalid_activation = activation_proof;
    invalid_activation.android_device_profile_sha256.pop_back();
    CHECK(!build_activation_confirmation_payload(invalid_activation).has_value());

    const auto start_challenge = build_usage_start_challenge_payload({
        .channel_binding_sha256 = s5,
        .entitlement_id = h1,
        .pair_id = h2,
        .protocol_version = 2U,
        .request_id = h3,
        .request_nonce = h4,
        .revocation_version = 9U,
    });
    CHECK(start_challenge.has_value());
    CHECK(*start_challenge ==
        "{\"channel_binding_sha256\":\"" + s5 +
        "\",\"domain\":\"visionforge-dual-machine-usage-start-challenge-v1\","
        "\"entitlement_id\":\"" + h1 +
        "\",\"pair_id\":\"" + h2 +
        "\",\"protocol_version\":2,\"request_id\":\"" + h3 +
        "\",\"request_nonce\":\"" + h4 +
        "\",\"revocation_version\":9}");

    const auto start = build_usage_start_payload({
        .android_frames_total = 11U,
        .android_runtime_ready = true,
        .channel_binding_sha256 = s5,
        .entitlement_id = h1,
        .host_frames_total = 12U,
        .host_runtime_ready = true,
        .pair_id = h2,
        .protocol_version = 2U,
        .request_id = h3,
        .request_nonce = h4,
        .revocation_version = 9U,
        .start_challenge_id = h4,
        .start_challenge_token_sha256 = start_token_sha256,
    });
    CHECK(start.has_value());
    CHECK(*start ==
        "{\"android_frames_total\":11,\"android_runtime_ready\":true,"
        "\"channel_binding_sha256\":\"" + s5 +
        "\",\"domain\":\"visionforge-dual-machine-usage-start-v1\","
        "\"entitlement_id\":\"" + h1 +
        "\",\"host_frames_total\":12,\"host_runtime_ready\":true,"
        "\"pair_id\":\"" + h2 +
        "\",\"protocol_version\":2,\"request_id\":\"" + h3 +
        "\",\"request_nonce\":\"" + h4 +
        "\",\"revocation_version\":9,\"start_challenge_id\":\"" + h4 +
        "\",\"start_challenge_token_sha256\":\"" + start_token_sha256 + "\"}");

    const auto heartbeat = build_usage_heartbeat_payload({
        .android_frames_total = 21U,
        .channel_binding_sha256 = s5,
        .entitlement_id = h1,
        .host_frames_total = 22U,
        .pair_id = h2,
        .previous_lease_sha256 = previous_lease_sha256,
        .protocol_version = 2U,
        .request_id = h3,
        .request_nonce = h4,
        .revocation_version = 9U,
        .sequence = 1U,
        .session_id = h4,
    });
    CHECK(heartbeat.has_value());
    CHECK(*heartbeat ==
        "{\"android_frames_total\":21,\"channel_binding_sha256\":\"" + s5 +
        "\",\"domain\":\"visionforge-dual-machine-usage-heartbeat-v1\","
        "\"entitlement_id\":\"" + h1 +
        "\",\"host_frames_total\":22,\"pair_id\":\"" + h2 +
        "\",\"previous_lease_sha256\":\"" + previous_lease_sha256 +
        "\",\"protocol_version\":2,\"request_id\":\"" + h3 +
        "\",\"request_nonce\":\"" + h4 +
        "\",\"revocation_version\":9,\"sequence\":1,\"session_id\":\"" +
        h4 + "\"}");

    const auto stop = build_usage_stop_payload({
        .channel_binding_sha256 = s5,
        .entitlement_id = h1,
        .pair_id = h2,
        .previous_lease_sha256 = previous_lease_sha256,
        .protocol_version = 2U,
        .request_id = h3,
        .request_nonce = h4,
        .revocation_version = 9U,
        .session_id = h4,
    });
    CHECK(stop.has_value());
    CHECK(*stop ==
        "{\"channel_binding_sha256\":\"" + s5 +
        "\",\"domain\":\"visionforge-dual-machine-usage-stop-v1\","
        "\"entitlement_id\":\"" + h1 +
        "\",\"pair_id\":\"" + h2 +
        "\",\"previous_lease_sha256\":\"" + previous_lease_sha256 +
        "\",\"protocol_version\":2,\"request_id\":\"" + h3 +
        "\",\"request_nonce\":\"" + h4 +
        "\",\"revocation_version\":9,\"session_id\":\"" + h4 + "\"}");

    const auto status = build_entitlement_status_payload({
        .entitlement_id = h1,
        .pair_id = h2,
        .protocol_version = 2U,
        .request_nonce = h4,
        .revocation_version = 9U,
    });
    CHECK(status.has_value());
    CHECK(*status ==
        "{\"domain\":\"visionforge-dual-machine-entitlement-status-v1\","
        "\"entitlement_id\":\"" + h1 +
        "\",\"pair_id\":\"" + h2 +
        "\",\"protocol_version\":2,\"request_nonce\":\"" + h4 +
        "\",\"revocation_version\":9}");

    UsageStartProof invalid{};
    invalid.entitlement_id = h1;
    invalid.pair_id = h2;
    invalid.channel_binding_sha256 = s5;
    invalid.request_id = h3;
    invalid.request_nonce = h4;
    invalid.revocation_version = 1U;
    invalid.start_challenge_id = h4;
    invalid.start_challenge_token_sha256 = start_token_sha256;
    CHECK(!build_usage_start_payload(invalid).has_value());
    invalid.android_runtime_ready = true;
    invalid.host_runtime_ready = true;
    CHECK(build_usage_start_payload(invalid).has_value());

    const std::string zero128 = repeated('0', 32U);
    const std::string zero256 = repeated('0', 64U);

    auto zero_activation = activation_proof;
    zero_activation.android_key_sha256 = zero256;
    CHECK(!build_activation_confirmation_payload(
        zero_activation).has_value());
    zero_activation = bind_device_proof;
    zero_activation.target_entitlement_id = zero128;
    CHECK(!build_activation_confirmation_payload(
        zero_activation).has_value());

    UsageStartChallengeProof zero_start_challenge{
        .channel_binding_sha256 = s5,
        .entitlement_id = h1,
        .pair_id = h2,
        .protocol_version = 2U,
        .request_id = h3,
        .request_nonce = h4,
        .revocation_version = 9U,
    };
    zero_start_challenge.entitlement_id = zero128;
    CHECK(!build_usage_start_challenge_payload(
        zero_start_challenge).has_value());
    zero_start_challenge.entitlement_id = h1;
    zero_start_challenge.channel_binding_sha256 = zero256;
    CHECK(!build_usage_start_challenge_payload(
        zero_start_challenge).has_value());
    zero_start_challenge.channel_binding_sha256 = s5;
    zero_start_challenge.request_nonce = zero128;
    CHECK(!build_usage_start_challenge_payload(
        zero_start_challenge).has_value());

    auto zero_start = invalid;
    zero_start.start_challenge_token_sha256 = zero256;
    CHECK(!build_usage_start_payload(zero_start).has_value());

    UsageHeartbeatProof zero_heartbeat{
        .android_frames_total = 21U,
        .channel_binding_sha256 = s5,
        .entitlement_id = h1,
        .host_frames_total = 22U,
        .pair_id = h2,
        .previous_lease_sha256 = zero256,
        .protocol_version = 2U,
        .request_id = h3,
        .request_nonce = h4,
        .revocation_version = 9U,
        .sequence = 1U,
        .session_id = h4,
    };
    CHECK(!build_usage_heartbeat_payload(zero_heartbeat).has_value());

    UsageStopProof zero_stop{
        .channel_binding_sha256 = s5,
        .entitlement_id = h1,
        .pair_id = h2,
        .previous_lease_sha256 = previous_lease_sha256,
        .protocol_version = 2U,
        .request_id = h3,
        .request_nonce = h4,
        .revocation_version = 9U,
        .session_id = zero128,
    };
    CHECK(!build_usage_stop_payload(zero_stop).has_value());

    EntitlementStatusProof zero_status{
        .entitlement_id = h1,
        .pair_id = h2,
        .protocol_version = 2U,
        .request_nonce = zero128,
        .revocation_version = 9U,
    };
    CHECK(!build_entitlement_status_payload(zero_status).has_value());

    std::cout << "VFDUAL_USAGE_AUTHORIZATION_CONTRACT_OK\n";
    return EXIT_SUCCESS;
}
