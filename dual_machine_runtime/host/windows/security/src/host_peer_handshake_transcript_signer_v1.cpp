#include "vfdual/host_peer_handshake_transcript_signer_v1.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <utility>

namespace vfdual {
namespace {

// This object is fully initialized before any signing request. Copying its
// string_view-only error state cannot allocate, and the intentionally empty
// operation avoids constructing diagnostics while already handling OOM.
inline constexpr PeerHandshakeError kAllocationFailureError{
    .code = PeerHandshakeErrorCode::allocation_failed,
};

[[nodiscard]] PeerHandshakeSha256 identity_hash_as_bytes(
    const std::array<std::uint8_t, 32U>& identity_hash) noexcept {
    PeerHandshakeSha256 result{};
    std::transform(
        identity_hash.begin(),
        identity_hash.end(),
        result.begin(),
        [](const std::uint8_t value) { return std::byte{value}; });
    return result;
}

[[nodiscard]] std::array<std::uint8_t, 32U> digest_as_uint8(
    const PeerHandshakeSha256& digest) noexcept {
    std::array<std::uint8_t, 32U> result{};
    std::transform(
        digest.begin(),
        digest.end(),
        result.begin(),
        [](const std::byte value) {
            return std::to_integer<std::uint8_t>(value);
        });
    return result;
}

[[nodiscard]] PeerHandshakeTranscriptFields rebuild_typed_transcript_fields(
    const HostPublicIdentity& host_identity,
    HostPeerHandshakeSigningInputV1& input) {
    PeerHandshakeTranscriptFields fields;
    fields.host_identity_spki_sha256 = identity_hash_as_bytes(
        host_identity.public_key_sha256);
    fields.android_identity_spki_sha256 =
        input.android_identity_spki_sha256;
    std::copy(
        input.host_ephemeral->public_key_sec1().begin(),
        input.host_ephemeral->public_key_sec1().end(),
        fields.host_ephemeral_public_key.begin());
    fields.android_ephemeral_public_key =
        input.android_ephemeral_public_key;
    fields.host_nonce = input.host_nonce;
    fields.android_nonce = input.android_nonce;
    fields.connection_id = input.connection_id;
    fields.session_generation = input.session_generation;
    fields.transport_kind = input.transport_kind;
    fields.host_ipv4 = input.host_ipv4;
    fields.android_ipv4 = input.android_ipv4;
    fields.video_port = input.video_port;
    fields.control_port = input.control_port;
    fields.pair_id = std::move(input.pair_id);
    fields.host_runtime_version = std::move(input.host_runtime_version);
    fields.android_runtime_version =
        std::move(input.android_runtime_version);
    return fields;
}

}  // namespace

HostSignedPeerHandshakeContextV1::HostSignedPeerHandshakeContextV1(
    CanonicalPeerHandshakeTranscriptV1 transcript,
    std::vector<std::uint8_t> signature_der_low_s,
    std::unique_ptr<PlatformP256EphemeralKeyAgreementV1> host_ephemeral)
    noexcept
    : transcript_(std::move(transcript)),
      signature_der_low_s_(std::move(signature_der_low_s)),
      host_ephemeral_(std::move(host_ephemeral)) {}

HostSignedPeerHandshakeContextV1::~HostSignedPeerHandshakeContextV1() =
    default;

const CanonicalPeerHandshakeTranscriptV1&
HostSignedPeerHandshakeContextV1::transcript() const noexcept {
    return transcript_;
}

std::span<const std::uint8_t>
HostSignedPeerHandshakeContextV1::signature_der_low_s() const noexcept {
    return signature_der_low_s_;
}

std::unique_ptr<PendingPeerHandshakeConfirmationV1>
HostSignedPeerHandshakeContextV1::
derive_pending_after_peer_identity_verified_for_bound_transcript(
    PeerHandshakeError& error) noexcept {
    error = {};
    std::unique_ptr<PlatformP256EphemeralKeyAgreementV1> ephemeral;
    {
        std::lock_guard lock(host_ephemeral_mutex_);
        if (host_ephemeral_ == nullptr) {
            error = {
                .code = PeerHandshakeErrorCode::
                    ephemeral_private_key_already_consumed,
                .operation =
                    "reject_reused_signed_host_handshake_context",
            };
            return nullptr;
        }
        // The availability check and ownership transition must remain one
        // indivisible operation. After this move, every concurrent caller
        // observes the consumed state while this caller derives off-lock.
        ephemeral = std::move(host_ephemeral_);
    }
    return ephemeral->derive_pending_after_peer_identity_verified(
        PeerHandshakeRole::host, transcript_, error);
}

HostPeerHandshakeTranscriptSignerV1::
HostPeerHandshakeTranscriptSignerV1(
    HostCngDeviceIdentity& identity) noexcept
    : identity_(identity) {}

HostPeerHandshakeSigningResultV1
HostPeerHandshakeTranscriptSignerV1::build_and_sign_bound_transcript(
    HostPeerHandshakeSigningInputV1 input) noexcept {
    try {
        if (input.host_ephemeral == nullptr) {
            return {nullptr, {
                .code = PeerHandshakeErrorCode::
                    invalid_ephemeral_public_key,
                .operation = "require_owned_fresh_host_ephemeral",
            }, {}};
        }

        PeerHandshakeError freshness_error;
        if (!input.host_ephemeral->is_fresh_for_host_transcript_signing(
                freshness_error)) {
            return {nullptr, freshness_error, {}};
        }

        PeerHandshakeTranscriptFields fields =
            rebuild_typed_transcript_fields(
                identity_.public_identity(), input);
        PeerHandshakeTranscriptResult built =
            build_canonical_peer_handshake_transcript_v1(
                fields,
                PeerHandshakePairIdRequirement::require_bound_pair);
        if (!built.succeeded()) {
            return {nullptr, built.error, {}};
        }

        const auto digest = digest_as_uint8(
            built.transcript->transcript_sha256());
        HostIdentityBytesResult signed_digest =
            identity_.create_peer_handshake_transcript_signature(digest);
        if (!signed_digest.succeeded()) {
            return {nullptr, {}, std::move(signed_digest.error)};
        }

        auto context = std::unique_ptr<HostSignedPeerHandshakeContextV1>(
            new HostSignedPeerHandshakeContextV1(
                std::move(*built.transcript),
                std::move(signed_digest.bytes),
                std::move(input.host_ephemeral)));
        return {std::move(context), {}, {}};
    } catch (const std::bad_alloc&) {
        return {nullptr, kAllocationFailureError, {}};
    } catch (...) {
        return {nullptr, {
            .code = PeerHandshakeErrorCode::crypto_operation_failed,
            .operation = "build_and_sign_bound_host_transcript",
        }, {}};
    }
}

}  // namespace vfdual
