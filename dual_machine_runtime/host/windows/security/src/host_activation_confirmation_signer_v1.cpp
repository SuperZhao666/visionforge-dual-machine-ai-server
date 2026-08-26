#include "vfdual/host_activation_confirmation_signer_v1.hpp"

#ifndef _WIN32
#error "host_activation_confirmation_signer_v1 is Windows-only"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <limits>
#include <optional>
#include <span>
#include <utility>

namespace vfdual {
namespace {

[[nodiscard]] HostIdentityError hash_error(
    const NTSTATUS status,
    std::string operation) {
    return {
        .code = HostIdentityErrorCode::sha256_failed,
        .native_domain = HostIdentityNativeStatusDomain::bcrypt_ntstatus,
        .native_status = static_cast<std::uint32_t>(status),
        .operation = std::move(operation),
    };
}

[[nodiscard]] std::optional<std::array<std::uint8_t, 32U>> sha256(
    const std::span<const std::uint8_t> input,
    HostIdentityError& error) noexcept {
    if (input.empty() ||
        input.size() > (std::numeric_limits<ULONG>::max)()) {
        error = {
            .code = HostIdentityErrorCode::sha256_failed,
            .operation = "validate_activation_confirmation_payload_size",
        };
        return std::nullopt;
    }
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    const auto close = [&]() noexcept {
        if (hash != nullptr) static_cast<void>(BCryptDestroyHash(hash));
        if (algorithm != nullptr) {
            static_cast<void>(BCryptCloseAlgorithmProvider(algorithm, 0U));
        }
    };
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U);
    if (!BCRYPT_SUCCESS(status)) {
        error = hash_error(status, "open_activation_sha256");
        close();
        return std::nullopt;
    }
    status = BCryptCreateHash(
        algorithm, &hash, nullptr, 0U, nullptr, 0U, 0U);
    if (!BCRYPT_SUCCESS(status)) {
        error = hash_error(status, "create_activation_sha256");
        close();
        return std::nullopt;
    }
    status = BCryptHashData(
        hash,
        const_cast<PUCHAR>(input.data()),
        static_cast<ULONG>(input.size()),
        0U);
    std::array<std::uint8_t, 32U> output{};
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptFinishHash(
            hash, output.data(), static_cast<ULONG>(output.size()), 0U);
    }
    close();
    if (!BCRYPT_SUCCESS(status)) {
        output.fill(0U);
        error = hash_error(status, "hash_activation_confirmation_payload");
        return std::nullopt;
    }
    error = {};
    return output;
}

}  // namespace

HostActivationConfirmationSignerV1::HostActivationConfirmationSignerV1(
    HostCngDeviceIdentity& identity) noexcept
    : identity_(identity) {}

HostActivationConfirmationSigningResultV1
HostActivationConfirmationSignerV1::build_and_sign_activation_confirmation(
    const ActivationConfirmationProof& proof) noexcept {
    HostActivationConfirmationSigningResultV1 result{};
    try {
        if (proof.host_key_sha256 !=
            identity_.public_identity().public_key_sha256_hex) {
            return result;
        }
        const std::optional<std::string> canonical =
            build_activation_confirmation_payload(proof);
        if (!canonical.has_value()) return result;
        result.payload_valid = true;
        result.canonical_payload = *canonical;
        const auto bytes = std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t*>(
                result.canonical_payload.data()),
            result.canonical_payload.size()};
        const auto digest = sha256(bytes, result.identity_error);
        if (!digest.has_value()) return result;
        result.canonical_payload_sha256 = *digest;
        HostIdentityBytesResult signature =
            identity_.create_activation_confirmation_signature(*digest);
        if (!signature.succeeded()) {
            result.identity_error = std::move(signature.error);
            return result;
        }
        result.signature_der_low_s = std::move(signature.bytes);
        return result;
    } catch (...) {
        result.identity_error = {
            .code = HostIdentityErrorCode::signature_failed,
            .operation = "build_and_sign_activation_confirmation",
        };
        return result;
    }
}

}  // namespace vfdual
