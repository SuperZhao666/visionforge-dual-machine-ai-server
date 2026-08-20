#pragma once

#include "vfdual/usage_lease_gate.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

namespace vfdual {

inline constexpr std::size_t kHostUsageLeaseMaximumTokenBytesV1 = 8192U;
inline constexpr std::uint64_t kHostUsageLeaseMaximumTtlSecondsV1 = 10U;
inline constexpr std::uint64_t kHostUsageLeaseServerAheadGraceSecondsV1 = 2U;

enum class HostUsageLeaseVerificationErrorCodeV1 : std::uint8_t {
    none = 0U,
    key_invalid,
    source_invalid,
    token_invalid,
    crypto_unavailable,
    allocation_failed,
    operation_failed,
};

/** Sanitized error metadata. It never retains token, claim, key, or path data. */
struct HostUsageLeaseVerificationErrorV1 final {
    HostUsageLeaseVerificationErrorCodeV1 code{
        HostUsageLeaseVerificationErrorCodeV1::none};

    [[nodiscard]] bool has_error() const noexcept {
        return code != HostUsageLeaseVerificationErrorCodeV1::none;
    }
};

[[nodiscard]] const char* host_usage_lease_verification_error_code_name_v1(
    HostUsageLeaseVerificationErrorCodeV1 code) noexcept;

struct HostUsageLeaseVerificationResultV1 final {
    std::optional<VerifiedUsageLease> lease;
    HostUsageLeaseVerificationErrorV1 error;

    [[nodiscard]] bool succeeded() const noexcept {
        return lease.has_value() && !error.has_error();
    }
};

class HostUsageLeaseVerifierV1;

struct HostUsageLeaseVerifierConstructionResultV1 final {
    std::unique_ptr<HostUsageLeaseVerifierV1> verifier;
    HostUsageLeaseVerificationErrorV1 error;

    [[nodiscard]] bool succeeded() const noexcept {
        return verifier != nullptr && !error.has_error();
    }
};

#if defined(VFDUAL_ENABLE_HOST_USAGE_LEASE_TEST_ACCESS)
/** Runtime-generated or isolated fixture public material for verifier tests. */
struct HostUsageLeaseTestPublicKeyV1 final {
    std::span<const std::uint8_t> canonical_spki_der;
};
#endif

/**
 * Strict Windows CNG verifier for the sidecar's compact RS256 usage lease.
 *
 * The production factory takes no runtime key source. Its bounded rotation ring
 * is generated from the formal build's public-only input and compiled into the
 * verifier target. Raw tokens, expected peer binding and trusted time enter at
 * this boundary; only a successful result may be forwarded to the lease gate.
 */
class HostUsageLeaseVerifierV1 final {
public:
    ~HostUsageLeaseVerifierV1();
    HostUsageLeaseVerifierV1(const HostUsageLeaseVerifierV1&) = delete;
    HostUsageLeaseVerifierV1& operator=(const HostUsageLeaseVerifierV1&) = delete;
    HostUsageLeaseVerifierV1(HostUsageLeaseVerifierV1&&) = delete;
    HostUsageLeaseVerifierV1& operator=(HostUsageLeaseVerifierV1&&) = delete;

    [[nodiscard]] static HostUsageLeaseVerifierConstructionResultV1
    create_from_build_pinned_keyring() noexcept;

#if defined(VFDUAL_ENABLE_HOST_USAGE_LEASE_TEST_ACCESS)
    [[nodiscard]] static HostUsageLeaseVerifierConstructionResultV1
    create_for_test_fixture_keyring(
        std::span<const HostUsageLeaseTestPublicKeyV1> keys) noexcept;
#endif

    [[nodiscard]] HostUsageLeaseVerificationResultV1 verify(
        std::string_view compact_token_ascii,
        const UsageLeaseBinding& expected_binding,
        std::uint64_t trusted_now_epoch) const noexcept;

private:
    struct Implementation;

    [[nodiscard]] static HostUsageLeaseVerifierConstructionResultV1
    create_from_canonical_spki_der_for_internal_use(
        std::span<const std::span<const std::uint8_t>> keys) noexcept;

    explicit HostUsageLeaseVerifierV1(
        std::unique_ptr<Implementation> implementation) noexcept;

    std::unique_ptr<Implementation> implementation_;
};

}  // namespace vfdual
