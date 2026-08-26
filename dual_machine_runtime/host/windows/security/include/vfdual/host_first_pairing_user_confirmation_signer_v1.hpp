#pragma once

#include "vfdual/first_pairing_commitment_v1.hpp"
#include "vfdual/host_cng_device_identity.h"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace vfdual {

/**
 * Result of one Host-local first-pairing approval.
 *
 * The caller supplies only the frozen VFU1 fields.  The signer rejects an
 * Android role and never accepts caller-built bytes or a caller-built digest.
 */
struct HostFirstPairingUserConfirmationSigningResultV1 final {
    FirstPairingUserConfirmationResultV1 payload;
    std::vector<std::uint8_t> signature_der_low_s;
    HostIdentityError identity_error;

    [[nodiscard]] bool succeeded() const noexcept {
        return payload.succeeded() && !signature_der_low_s.empty() &&
            !identity_error.has_error();
    }
};

class HostFirstPairingUserConfirmationSignerV1 final {
public:
    explicit HostFirstPairingUserConfirmationSignerV1(
        HostCngDeviceIdentity& identity) noexcept;

    [[nodiscard]] HostFirstPairingUserConfirmationSigningResultV1
    build_and_sign_after_local_user_confirmation(
        const FirstPairingUserConfirmationFieldsV1& fields) noexcept;

private:
    HostCngDeviceIdentity& identity_;
};

/**
 * Typed Android confirmation verifier for the Host first-pair coordinator.
 *
 * The expected fingerprint must come from the locally rebuilt VFP1
 * commitment.  A valid result proves only possession of that Android key and
 * approval of this exact VFU1 payload; it does not activate a card or release
 * the data plane.
 */
[[nodiscard]] HostIdentityVerificationResult
verify_android_first_pairing_user_confirmation_v1(
    std::span<const std::uint8_t> android_subject_public_key_info_der,
    const std::array<std::uint8_t, 32U>&
        expected_android_identity_spki_sha256,
    const FirstPairingUserConfirmationFieldsV1& fields,
    std::span<const std::uint8_t> signature_der_low_s) noexcept;

}  // namespace vfdual
