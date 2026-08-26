#include "vfdual/host_usage_authorization_signer_v1.hpp"

#ifndef _WIN32
#error "host_usage_authorization_signer_v1 is Windows-only"
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
            .operation = "validate_usage_authorization_payload_size",
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
        error = hash_error(status, "open_usage_authorization_sha256");
        close();
        return std::nullopt;
    }
    status = BCryptCreateHash(
        algorithm, &hash, nullptr, 0U, nullptr, 0U, 0U);
    if (!BCRYPT_SUCCESS(status)) {
        error = hash_error(status, "create_usage_authorization_sha256");
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
        error = hash_error(status, "hash_usage_authorization_payload");
        return std::nullopt;
    }
    error = {};
    return output;
}

}  // namespace

HostUsageAuthorizationSignerV1::HostUsageAuthorizationSignerV1(
    HostCngDeviceIdentity& identity) noexcept : identity_(identity) {}

HostUsageAuthorizationSigningResultV1
HostUsageAuthorizationSignerV1::build_and_sign_entitlement_status(
    const EntitlementStatusProof& proof) noexcept {
    return sign_locally_built_payload(
        build_entitlement_status_payload(proof),
        "build_and_sign_entitlement_status");
}

HostUsageAuthorizationSigningResultV1
HostUsageAuthorizationSignerV1::build_and_sign_usage_start_challenge(
    const UsageStartChallengeProof& proof) noexcept {
    return sign_locally_built_payload(
        build_usage_start_challenge_payload(proof),
        "build_and_sign_usage_start_challenge");
}

HostUsageAuthorizationSigningResultV1
HostUsageAuthorizationSignerV1::build_and_sign_usage_start(
    const UsageStartProof& proof) noexcept {
    return sign_locally_built_payload(
        build_usage_start_payload(proof),
        "build_and_sign_usage_start");
}

HostUsageAuthorizationSigningResultV1
HostUsageAuthorizationSignerV1::build_and_sign_usage_start_cancel(
    const UsageStartCancelProof& proof) noexcept {
    return sign_locally_built_payload(
        build_usage_start_cancel_payload(proof),
        "build_and_sign_usage_start_cancel");
}

HostUsageAuthorizationSigningResultV1
HostUsageAuthorizationSignerV1::build_and_sign_usage_heartbeat(
    const UsageHeartbeatProof& proof) noexcept {
    return sign_locally_built_payload(
        build_usage_heartbeat_payload(proof),
        "build_and_sign_usage_heartbeat");
}

HostUsageAuthorizationSigningResultV1
HostUsageAuthorizationSignerV1::build_and_sign_usage_stop(
    const UsageStopProof& proof) noexcept {
    return sign_locally_built_payload(
        build_usage_stop_payload(proof),
        "build_and_sign_usage_stop");
}

HostUsageAuthorizationSigningResultV1
HostUsageAuthorizationSignerV1::sign_locally_built_payload(
    std::optional<std::string> canonical,
    std::string operation) noexcept {
    HostUsageAuthorizationSigningResultV1 result{};
    try {
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
            identity_.create_usage_authorization_signature(*digest);
        if (!signature.succeeded()) {
            result.identity_error = std::move(signature.error);
            return result;
        }
        result.signature_der_low_s = std::move(signature.bytes);
        return result;
    } catch (...) {
        result.identity_error = {
            .code = HostIdentityErrorCode::signature_failed,
            .operation = std::move(operation),
        };
        return result;
    }
}

}  // namespace vfdual
