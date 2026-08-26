#pragma once

#include "vfdual/host_cng_device_identity.h"
#include "vfdual/usage_authorization_contract.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace vfdual {

/** Result of signing one locally reconstructed, typed usage proof. */
struct HostUsageAuthorizationSigningResultV1 final {
    bool payload_valid{};
    std::string canonical_payload;
    std::array<std::uint8_t, 32U> canonical_payload_sha256{};
    std::vector<std::uint8_t> signature_der_low_s;
    HostIdentityError identity_error;

    [[nodiscard]] bool succeeded() const noexcept {
        return payload_valid && !canonical_payload.empty() &&
            canonical_payload_sha256 != std::array<std::uint8_t, 32U>{} &&
            !signature_der_low_s.empty() && !identity_error.has_error();
    }
};

/**
 * Restricted signer for server usage-authorization contracts.
 *
 * It accepts a typed entitlement-status proof, rebuilds the canonical JSON
 * locally, hashes it locally, and then invokes the dedicated CNG bridge.  It
 * never accepts caller-selected bytes or a caller-selected digest.
 */
class HostUsageAuthorizationSignerV1 final {
public:
    explicit HostUsageAuthorizationSignerV1(
        HostCngDeviceIdentity& identity) noexcept;

    [[nodiscard]] HostUsageAuthorizationSigningResultV1
    build_and_sign_entitlement_status(
        const EntitlementStatusProof& proof) noexcept;

    [[nodiscard]] HostUsageAuthorizationSigningResultV1
    build_and_sign_usage_start_challenge(
        const UsageStartChallengeProof& proof) noexcept;
    [[nodiscard]] HostUsageAuthorizationSigningResultV1
    build_and_sign_usage_start(const UsageStartProof& proof) noexcept;
    [[nodiscard]] HostUsageAuthorizationSigningResultV1
    build_and_sign_usage_start_cancel(
        const UsageStartCancelProof& proof) noexcept;
    [[nodiscard]] HostUsageAuthorizationSigningResultV1
    build_and_sign_usage_heartbeat(
        const UsageHeartbeatProof& proof) noexcept;
    [[nodiscard]] HostUsageAuthorizationSigningResultV1
    build_and_sign_usage_stop(const UsageStopProof& proof) noexcept;

private:
    [[nodiscard]] HostUsageAuthorizationSigningResultV1
    sign_locally_built_payload(
        std::optional<std::string> canonical,
        std::string operation) noexcept;

    HostCngDeviceIdentity& identity_;
};

}  // namespace vfdual
