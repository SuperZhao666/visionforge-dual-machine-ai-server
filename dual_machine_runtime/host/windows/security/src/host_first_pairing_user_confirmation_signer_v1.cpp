#include "vfdual/host_first_pairing_user_confirmation_signer_v1.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace vfdual {
namespace {

[[nodiscard]] std::array<std::uint8_t, 32U> digest_as_uint8(
    const PeerHandshakeSha256& digest) noexcept {
    std::array<std::uint8_t, 32U> result{};
    std::transform(
        digest.begin(), digest.end(), result.begin(),
        [](const std::byte value) {
            return std::to_integer<std::uint8_t>(value);
        });
    return result;
}

}  // namespace

HostFirstPairingUserConfirmationSignerV1::
HostFirstPairingUserConfirmationSignerV1(
    HostCngDeviceIdentity& identity) noexcept
    : identity_(identity) {}

HostFirstPairingUserConfirmationSigningResultV1
HostFirstPairingUserConfirmationSignerV1::
build_and_sign_after_local_user_confirmation(
    const FirstPairingUserConfirmationFieldsV1& fields) noexcept {
    HostFirstPairingUserConfirmationSigningResultV1 result{};
    if (fields.role != FirstPairingConfirmationRoleV1::host) return result;
    result.payload = build_first_pairing_user_confirmation_v1(fields);
    if (!result.payload.succeeded()) return result;

    HostIdentityBytesResult signature =
        identity_.create_first_pairing_user_confirmation_signature(
            digest_as_uint8(result.payload.payload_sha256));
    if (!signature.succeeded()) {
        result.identity_error = std::move(signature.error);
        return result;
    }
    result.signature_der_low_s = std::move(signature.bytes);
    return result;
}

}  // namespace vfdual
