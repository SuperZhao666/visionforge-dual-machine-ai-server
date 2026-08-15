#pragma once

#include "vfdual/authenticated_peer_handshake_v1.hpp"
#include "vfdual/host_cng_device_identity.h"

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace vfdual {

/**
 * Typed, bound-pair inputs that the Host identity is allowed to authorize.
 *
 * The Host identity fingerprint is deliberately absent: the signer always
 * obtains it from its current HostCngDeviceIdentity.  The Host ephemeral
 * public key is also absent: ownership of a fresh platform ECDH key is moved
 * into this request and the signer reads that key's own public component.
 *
 * Every integration must source android_identity_spki_sha256 only from a
 * locally verified pair record. This foundation validates and signs the
 * supplied binding but does not prove that the Android identity was paired,
 * attested, or approved by the service.
 */
struct HostPeerHandshakeSigningInputV1 final {
    std::unique_ptr<PlatformP256EphemeralKeyAgreementV1> host_ephemeral;
    PeerHandshakeSha256 android_identity_spki_sha256{};
    PeerHandshakeP256PublicKey android_ephemeral_public_key{};
    PeerHandshakeNonce host_nonce{};
    PeerHandshakeNonce android_nonce{};
    std::uint64_t connection_id{};
    std::uint64_t session_generation{};
    PeerHandshakeTransportKind transport_kind{
        PeerHandshakeTransportKind::cat6};
    std::array<std::byte, 4U> host_ipv4{};
    std::array<std::byte, 4U> android_ipv4{};
    std::uint16_t video_port{};
    std::uint16_t control_port{};
    std::string pair_id;
    std::string host_runtime_version;
    std::string android_runtime_version;
};

/**
 * Signed Host-side handshake state.
 *
 * The ECDH owner never leaves this context.  After the peer's long-term
 * identity signature has been verified against the exact Android SPKI hash
 * in transcript(), the caller can perform exactly one Host-role derivation
 * for this already-signed transcript.  No API accepts replacement bytes,
 * hashes, roles, or transcripts.
 */
class HostSignedPeerHandshakeContextV1 final {
public:
    ~HostSignedPeerHandshakeContextV1();
    HostSignedPeerHandshakeContextV1(
        const HostSignedPeerHandshakeContextV1&) = delete;
    HostSignedPeerHandshakeContextV1& operator=(
        const HostSignedPeerHandshakeContextV1&) = delete;
    HostSignedPeerHandshakeContextV1(
        HostSignedPeerHandshakeContextV1&&) = delete;
    HostSignedPeerHandshakeContextV1& operator=(
        HostSignedPeerHandshakeContextV1&&) = delete;

    [[nodiscard]] const CanonicalPeerHandshakeTranscriptV1&
    transcript() const noexcept;
    [[nodiscard]] std::span<const std::uint8_t>
    signature_der_low_s() const noexcept;

    [[nodiscard]] std::unique_ptr<PendingPeerHandshakeConfirmationV1>
    derive_pending_after_peer_identity_verified_for_bound_transcript(
        PeerHandshakeError& error) noexcept;

private:
    HostSignedPeerHandshakeContextV1(
        CanonicalPeerHandshakeTranscriptV1 transcript,
        std::vector<std::uint8_t> signature_der_low_s,
        std::unique_ptr<PlatformP256EphemeralKeyAgreementV1>
            host_ephemeral) noexcept;

    friend class HostPeerHandshakeTranscriptSignerV1;

    CanonicalPeerHandshakeTranscriptV1 transcript_;
    std::vector<std::uint8_t> signature_der_low_s_;
    std::mutex host_ephemeral_mutex_;
    std::unique_ptr<PlatformP256EphemeralKeyAgreementV1> host_ephemeral_;
};

struct HostPeerHandshakeSigningResultV1 final {
    std::unique_ptr<HostSignedPeerHandshakeContextV1> context;
    PeerHandshakeError transcript_error;
    HostIdentityError identity_error;

    [[nodiscard]] bool succeeded() const noexcept {
        return context != nullptr && !transcript_error.has_error() &&
            !identity_error.has_error();
    }
};

/**
 * Restricted Host identity capability.  Its sole operation accepts typed
 * protocol fields, reconstructs the canonical bound-pair transcript inside
 * the module, and signs that transcript with the current Host identity.
 */
class HostPeerHandshakeTranscriptSignerV1 final {
public:
    explicit HostPeerHandshakeTranscriptSignerV1(
        HostCngDeviceIdentity& identity) noexcept;

    [[nodiscard]] HostPeerHandshakeSigningResultV1
    build_and_sign_bound_transcript(
        HostPeerHandshakeSigningInputV1 input) noexcept;

private:
    HostCngDeviceIdentity& identity_;
};

}  // namespace vfdual
