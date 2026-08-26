#pragma once

#include "vfdual/authenticated_control_bootstrap_record_v1.hpp"
#include "vfdual/first_pairing_commitment_v1.hpp"
#include "vfdual/usage_authorization_contract.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace vfdual {

/** One endpoint's public contribution to the VFP1 first-pair commitment. */
struct FirstPairingOfferPayloadV1 final {
    std::uint32_t required_capabilities{
        kFirstPairingCapabilityTwoSidedUserConfirmationV1};
    FirstPairingConfirmationMethodV1 confirmation_method{
        FirstPairingConfirmationMethodV1::decimal_sas};
    std::array<std::byte, kFirstPairingAttemptIdBytesV1> attempt_id{};
    std::vector<std::uint8_t> identity_subject_public_key_info_der;
    PeerHandshakeP256PublicKey ephemeral_public_key{};
    PeerHandshakeNonce nonce{};
    PeerHandshakeSha256 runtime_version_sha256{};
    std::uint64_t expires_at_epoch{};
};

struct FirstPairingConfirmationPayloadV1 final {
    FirstPairingUserConfirmationFieldsV1 fields;
    std::vector<std::uint8_t> signature_der_low_s;
};

struct FirstPairingActivationSignaturePayloadV1 final {
    PeerHandshakeSha256 canonical_payload_sha256{};
    std::vector<std::uint8_t> signature_der_low_s;
};

/** Provisional only; VFB1 pair credential must verify before durable use. */
struct FirstPairingActivationResultPayloadV1 final {
    std::string entitlement_id;
    std::string pair_id;
    std::string binding_id;
    std::uint64_t binding_revision{};
    std::uint64_t revocation_version{};
};

[[nodiscard]] std::optional<std::vector<std::byte>>
encode_first_pairing_offer_payload_v1(
    ControlBootstrapMessageTypeV1 message_type,
    const FirstPairingOfferPayloadV1& payload) noexcept;
[[nodiscard]] std::optional<FirstPairingOfferPayloadV1>
parse_first_pairing_offer_payload_v1(
    ControlBootstrapMessageTypeV1 message_type,
    std::span<const std::byte> encoded) noexcept;

[[nodiscard]] std::optional<std::vector<std::byte>>
encode_first_pairing_confirmation_payload_v1(
    ControlBootstrapMessageTypeV1 message_type,
    const FirstPairingConfirmationPayloadV1& payload) noexcept;
[[nodiscard]] std::optional<FirstPairingConfirmationPayloadV1>
parse_first_pairing_confirmation_payload_v1(
    ControlBootstrapMessageTypeV1 message_type,
    std::span<const std::byte> encoded) noexcept;

[[nodiscard]] std::optional<std::vector<std::byte>>
encode_first_pairing_activation_proof_request_v1(
    const ActivationConfirmationProof& proof) noexcept;
[[nodiscard]] std::optional<ActivationConfirmationProof>
parse_first_pairing_activation_proof_request_v1(
    std::span<const std::byte> encoded) noexcept;

[[nodiscard]] std::optional<std::vector<std::byte>>
encode_first_pairing_activation_signature_payload_v1(
    const FirstPairingActivationSignaturePayloadV1& payload) noexcept;
[[nodiscard]] std::optional<FirstPairingActivationSignaturePayloadV1>
parse_first_pairing_activation_signature_payload_v1(
    std::span<const std::byte> encoded) noexcept;

[[nodiscard]] std::optional<std::vector<std::byte>>
encode_first_pairing_activation_result_payload_v1(
    const FirstPairingActivationResultPayloadV1& payload) noexcept;
[[nodiscard]] std::optional<FirstPairingActivationResultPayloadV1>
parse_first_pairing_activation_result_payload_v1(
    std::span<const std::byte> encoded) noexcept;

[[nodiscard]] std::optional<std::vector<std::byte>>
encode_first_pairing_complete_payload_v1(
    const PeerHandshakeSha256& commitment_sha256) noexcept;
[[nodiscard]] std::optional<PeerHandshakeSha256>
parse_first_pairing_complete_payload_v1(
    std::span<const std::byte> encoded) noexcept;

}  // namespace vfdual
