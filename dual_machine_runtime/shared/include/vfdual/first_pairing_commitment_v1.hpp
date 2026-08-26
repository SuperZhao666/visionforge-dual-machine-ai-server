#pragma once

#include "vfdual/authenticated_peer_handshake_v1.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vfdual {

inline constexpr std::size_t kFirstPairingAttemptIdBytesV1 = 16U;
inline constexpr std::size_t kFirstPairingCommitmentBytesV1 = 368U;
inline constexpr std::size_t kFirstPairingUserConfirmationBytesV1 = 64U;
inline constexpr std::uint32_t
    kFirstPairingCapabilityTwoSidedUserConfirmationV1 = 0x00000001U;

enum class FirstPairingTransportKindV1 : std::uint8_t {
    ethernet = 1U,
};

enum class FirstPairingConfirmationRoleV1 : std::uint8_t {
    host = 1U,
    android = 2U,
};

enum class FirstPairingConfirmationMethodV1 : std::uint8_t {
    decimal_sas = 1U,
    qr = 2U,
};

/**
 * Locally observed inputs committed before a user confirms a first pairing.
 *
 * Identity and runtime-version hashes must be computed from the exact values
 * each endpoint will subsequently use. Route fields come from the connected
 * socket, never from a peer-supplied payload. No card code or private key is
 * included.
 */
struct FirstPairingCommitmentFieldsV1 final {
    FirstPairingTransportKindV1 transport_kind{
        FirstPairingTransportKindV1::ethernet};
    std::uint32_t required_capabilities{
        kFirstPairingCapabilityTwoSidedUserConfirmationV1};
    std::array<std::byte, kFirstPairingAttemptIdBytesV1> attempt_id{};
    PeerHandshakeSha256 host_identity_spki_sha256{};
    PeerHandshakeSha256 android_identity_spki_sha256{};
    PeerHandshakeP256PublicKey host_ephemeral_public_key{};
    PeerHandshakeP256PublicKey android_ephemeral_public_key{};
    PeerHandshakeNonce host_nonce{};
    PeerHandshakeNonce android_nonce{};
    std::array<std::byte, 4U> host_ipv4{};
    std::array<std::byte, 4U> android_ipv4{};
    std::uint16_t video_port{};
    std::uint16_t control_port{};
    PeerHandshakeSha256 host_runtime_version_sha256{};
    PeerHandshakeSha256 android_runtime_version_sha256{};
    std::uint64_t expires_at_epoch{};
};

enum class FirstPairingCommitmentStatusV1 : std::uint8_t {
    built = 1U,
    invalid_field = 2U,
    hash_failed = 3U,
};

/** Public confirmation material; it contains no card code, token, or key. */
struct FirstPairingCommitmentResultV1 final {
    FirstPairingCommitmentStatusV1 status{
        FirstPairingCommitmentStatusV1::invalid_field};
    std::vector<std::byte> canonical_encoding;
    PeerHandshakeSha256 commitment_sha256{};
    std::array<char, 7U> decimal_sas{};

    [[nodiscard]] bool succeeded() const noexcept {
        return status == FirstPairingCommitmentStatusV1::built &&
            canonical_encoding.size() == kFirstPairingCommitmentBytesV1 &&
            decimal_sas[6U] == '\0';
    }

    [[nodiscard]] std::string sas() const {
        return succeeded() ? std::string{decimal_sas.data(), 6U} :
            std::string{};
    }
};

/** Builds the frozen VFP1 commitment and a uniformly mapped six-digit SAS. */
[[nodiscard]] FirstPairingCommitmentResultV1
build_first_pairing_commitment_v1(
    const FirstPairingCommitmentFieldsV1& fields) noexcept;

/** Exact public fields signed only after the local user confirms the UI. */
struct FirstPairingUserConfirmationFieldsV1 final {
    FirstPairingConfirmationRoleV1 role{
        FirstPairingConfirmationRoleV1::host};
    FirstPairingConfirmationMethodV1 method{
        FirstPairingConfirmationMethodV1::decimal_sas};
    std::array<std::byte, kFirstPairingAttemptIdBytesV1> attempt_id{};
    PeerHandshakeSha256 commitment_sha256{};
    std::uint64_t expires_at_epoch{};
};

struct FirstPairingUserConfirmationResultV1 final {
    FirstPairingCommitmentStatusV1 status{
        FirstPairingCommitmentStatusV1::invalid_field};
    std::array<std::byte, kFirstPairingUserConfirmationBytesV1>
        canonical_encoding{};
    PeerHandshakeSha256 payload_sha256{};

    [[nodiscard]] bool succeeded() const noexcept {
        return status == FirstPairingCommitmentStatusV1::built;
    }
};

/** Builds the frozen VFU1 payload; rejection is represented by no signature. */
[[nodiscard]] FirstPairingUserConfirmationResultV1
build_first_pairing_user_confirmation_v1(
    const FirstPairingUserConfirmationFieldsV1& fields) noexcept;

}  // namespace vfdual
