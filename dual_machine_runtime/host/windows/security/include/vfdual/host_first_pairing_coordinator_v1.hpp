#pragma once

#include "vfdual/authenticated_control_bootstrap_record_v1.hpp"
#include "vfdual/first_pairing_bootstrap_payload_v1.hpp"
#include "vfdual/host_authenticated_control_coordinator_v1.hpp"
#include "vfdual/host_device_identity_runtime.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace vfdual {

inline constexpr std::uint64_t kHostFirstPairingMaximumLifetimeSecondsV1 = 300U;
inline constexpr std::uint64_t
    kHostFirstPairingMaximumLifetimeMillisecondsV1 = 300'000U;

struct HostFirstPairingRouteV1 final {
    std::array<std::byte, 4U> host_ipv4{};
    std::array<std::byte, 4U> android_ipv4{};
    std::uint16_t video_port{};
    std::uint16_t control_port{};
};

enum class HostFirstPairingErrorCodeV1 : std::uint8_t {
    none = 0U,
    invalid_configuration,
    timed_out,
    unexpected_record,
    cryptographic_verification_failed,
    identity_binding_mismatch,
    activation_proof_rejected,
    closed,
};

struct HostFirstPairingErrorV1 final {
    HostFirstPairingErrorCodeV1 code{HostFirstPairingErrorCodeV1::none};
    [[nodiscard]] bool has_error() const noexcept {
        return code != HostFirstPairingErrorCodeV1::none;
    }
};

class HostFirstPairingCoordinatorV1;

struct HostFirstPairingConstructionResultV1 final {
    std::unique_ptr<HostFirstPairingCoordinatorV1> coordinator;
    std::vector<std::byte> host_offer_record;
    HostFirstPairingErrorV1 error;
    [[nodiscard]] bool succeeded() const noexcept {
        return coordinator != nullptr && !host_offer_record.empty() &&
            !error.has_error();
    }
};

struct HostFirstPairingOfferAcceptedResultV1 final {
    std::string decimal_sas;
    PeerHandshakeSha256 commitment_sha256{};
    HostFirstPairingErrorV1 error;
    [[nodiscard]] bool succeeded() const noexcept {
        return decimal_sas.size() == 6U &&
            commitment_sha256 != PeerHandshakeSha256{} &&
            !error.has_error();
    }
};

struct HostFirstPairingRecordResultV1 final {
    std::vector<std::byte> outbound_record;
    HostFirstPairingErrorV1 error;
    [[nodiscard]] bool succeeded() const noexcept {
        return !outbound_record.empty() && !error.has_error();
    }
};

struct HostFirstPairingCompletionResultV1 final {
    std::vector<std::byte> complete_record;
    HostAuthenticatedControlPairBindingV1 provisional_pair_binding;
    HostFirstPairingErrorV1 error;
    [[nodiscard]] bool succeeded() const noexcept {
        return !complete_record.empty() &&
            !provisional_pair_binding.entitlement_id.empty() &&
            !error.has_error();
    }
};

/**
 * Host owner for one fresh, user-confirmed first-pair attempt.
 *
 * No output from this owner authorizes video/control traffic. The activation
 * result is provisional and must be followed by a new connection that passes
 * the existing server-credential-bound nine-record VFB1 handshake.
 */
class HostFirstPairingCoordinatorV1 final {
public:
    ~HostFirstPairingCoordinatorV1();
    HostFirstPairingCoordinatorV1(
        const HostFirstPairingCoordinatorV1&) = delete;
    HostFirstPairingCoordinatorV1& operator=(
        const HostFirstPairingCoordinatorV1&) = delete;

    [[nodiscard]] static HostFirstPairingConstructionResultV1 create(
        HostDeviceIdentityRuntime& identity_runtime,
        const HostFirstPairingRouteV1& route,
        std::string host_runtime_version,
        std::string host_client_version,
        FirstPairingConfirmationMethodV1 confirmation_method,
        const HostAuthenticatedControlTimeV1& now) noexcept;

    [[nodiscard]] HostFirstPairingOfferAcceptedResultV1
    accept_android_offer(
        std::span<const std::byte> encoded_record,
        const HostAuthenticatedControlTimeV1& now) noexcept;
    [[nodiscard]] HostFirstPairingRecordResultV1
    confirm_local_user(
        const HostAuthenticatedControlTimeV1& now) noexcept;
    [[nodiscard]] HostFirstPairingErrorV1
    accept_android_user_confirmation(
        std::span<const std::byte> encoded_record,
        const HostAuthenticatedControlTimeV1& now) noexcept;
    [[nodiscard]] HostFirstPairingRecordResultV1
    accept_activation_proof_request(
        std::span<const std::byte> encoded_record,
        const HostAuthenticatedControlTimeV1& now) noexcept;
    [[nodiscard]] HostFirstPairingCompletionResultV1
    accept_activation_result(
        std::span<const std::byte> encoded_record,
        const HostAuthenticatedControlTimeV1& now) noexcept;

    void close() noexcept;
    [[nodiscard]] bool is_closed() const noexcept;

private:
    HostFirstPairingCoordinatorV1(
        HostDeviceIdentityRuntime& identity_runtime,
        HostFirstPairingRouteV1 route,
        std::string host_runtime_version,
        std::string host_client_version,
        FirstPairingOfferPayloadV1 host_offer,
        std::unique_ptr<PlatformP256EphemeralKeyAgreementV1>
            host_ephemeral,
        std::uint64_t started_monotonic_milliseconds) noexcept;

    [[nodiscard]] bool time_valid(
        const HostAuthenticatedControlTimeV1& now) const noexcept;
    void burn(HostFirstPairingErrorCodeV1 code) noexcept;

    HostDeviceIdentityRuntime& identity_runtime_;
    HostFirstPairingRouteV1 route_;
    std::string host_runtime_version_;
    std::string host_client_version_;
    FirstPairingOfferPayloadV1 host_offer_;
    FirstPairingOfferPayloadV1 android_offer_;
    std::unique_ptr<PlatformP256EphemeralKeyAgreementV1> host_ephemeral_;
    FirstPairingCommitmentResultV1 commitment_;
    std::vector<std::byte> local_confirmation_record_;
    std::vector<std::uint8_t> android_identity_spki_der_;
    PeerHandshakeSha256 android_identity_sha256_{};
    std::string android_identity_sha256_hex_;
    std::string expected_host_device_code_;
    std::string expected_android_device_code_;
    std::string activation_pair_id_;
    std::uint64_t started_monotonic_milliseconds_{};
    bool offer_accepted_{};
    bool local_confirmed_{};
    bool android_confirmed_{};
    bool activation_signed_{};
    bool completed_{};
    bool closed_{};
    HostFirstPairingErrorV1 terminal_error_;
};

}  // namespace vfdual
