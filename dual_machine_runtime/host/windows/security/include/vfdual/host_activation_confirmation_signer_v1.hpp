#pragma once

#include "vfdual/host_cng_device_identity.h"
#include "vfdual/usage_authorization_contract.hpp"

#include <cstdint>
#include <array>
#include <string>
#include <vector>

namespace vfdual {

/** Exact server activation payload signed by the current Host identity. */
struct HostActivationConfirmationSigningResultV1 final {
    bool payload_valid{};
    std::string canonical_payload;
    std::array<std::uint8_t, 32U> canonical_payload_sha256{};
    std::vector<std::uint8_t> signature_der_low_s;
    HostIdentityError identity_error;

    [[nodiscard]] bool succeeded() const noexcept {
        return payload_valid && !canonical_payload.empty() &&
            canonical_payload_sha256 !=
                std::array<std::uint8_t, 32U>{} &&
            !signature_der_low_s.empty() && !identity_error.has_error();
    }
};

/**
 * Restricted activation signer used after the two-sided first-pair approval.
 * It rebuilds the exact canonical server contract internally and exposes no
 * raw-byte or raw-digest signing operation.
 */
class HostActivationConfirmationSignerV1 final {
public:
    explicit HostActivationConfirmationSignerV1(
        HostCngDeviceIdentity& identity) noexcept;

    [[nodiscard]] HostActivationConfirmationSigningResultV1
    build_and_sign_activation_confirmation(
        const ActivationConfirmationProof& proof) noexcept;

private:
    HostCngDeviceIdentity& identity_;
};

}  // namespace vfdual
