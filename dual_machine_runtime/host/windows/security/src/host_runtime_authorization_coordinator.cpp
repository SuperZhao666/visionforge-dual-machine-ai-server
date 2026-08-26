#include "vfdual/host_runtime_authorization_coordinator.hpp"

#include "vfdual/host_runtime_service.hpp"
#include "vfdual/host_device_identity_runtime.hpp"
#include "vfdual/host_usage_lease_verifier_v1.hpp"
#include "vfdual/host_usage_authorization_signer_v1.hpp"
#include "vfdual/authenticated_control_record_v1.hpp"
#include "vfdual/usage_authorization_contract.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace vfdual {
namespace {

[[nodiscard]] std::string lower_hex(
    const PeerHandshakeSha256& digest) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string result(digest.size() * 2U, '0');
    for (std::size_t index{}; index < digest.size(); ++index) {
        const auto value = std::to_integer<std::uint8_t>(digest[index]);
        result[index * 2U] = alphabet[value >> 4U];
        result[index * 2U + 1U] = alphabet[value & 0x0fU];
    }
    return result;
}

[[nodiscard]] std::string lower_hex(
    const std::span<const std::byte> bytes) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string result(bytes.size() * 2U, '0');
    for (std::size_t index{}; index < bytes.size(); ++index) {
        const auto value = std::to_integer<std::uint8_t>(bytes[index]);
        result[index * 2U] = alphabet[value >> 4U];
        result[index * 2U + 1U] = alphabet[value & 0x0fU];
    }
    return result;
}

[[nodiscard]] AuthenticatedControlTrafficKeyV1 traffic_key(
    const PeerHandshakeDataPlaneKeyView material,
    const std::uint64_t connection_id,
    const std::uint64_t session_generation,
    const ControlRecordDirectionV1 direction) noexcept {
    AuthenticatedControlTrafficKeyV1 result;
    result.tuple = {
        .connection_id = connection_id,
        .session_generation = session_generation,
        .key_epoch = 1U,
        .direction = direction,
    };
    std::copy(material.aes_256_key.begin(), material.aes_256_key.end(),
        result.aes_256_key.begin());
    std::copy(material.nonce_prefix.begin(), material.nonce_prefix.end(),
        result.nonce_prefix.begin());
    return result;
}

void erase(std::vector<std::byte>& value) noexcept {
    std::fill(value.begin(), value.end(), std::byte{0U});
    value.clear();
}

void erase(std::string& value) noexcept {
    std::fill(value.begin(), value.end(), '\0');
    value.clear();
}

[[nodiscard]] std::uint64_t current_epoch_seconds() noexcept {
    const auto count = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return count > 0 ? static_cast<std::uint64_t>(count) : 0U;
}

[[nodiscard]] bool compact_token_ascii_valid(
    const std::span<const std::byte> bytes) noexcept {
    if (bytes.empty() ||
        bytes.size() > kHostUsageLeaseMaximumTokenBytesV1) {
        return false;
    }
    return std::all_of(bytes.begin(), bytes.end(), [](const std::byte value) {
        const auto character = std::to_integer<std::uint8_t>(value);
        return character >= 0x21U && character <= 0x7eU;
    });
}

[[nodiscard]] bool lower_hex_digest_bytes(
    const std::string_view digest,
    std::span<std::byte, 32U> output) noexcept {
    if (digest.size() != output.size() * 2U) return false;
    const auto nibble = [](const char value) -> int {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        return -1;
    };
    for (std::size_t index{}; index < output.size(); ++index) {
        const int high = nibble(digest[index * 2U]);
        const int low = nibble(digest[index * 2U + 1U]);
        if (high < 0 || low < 0) return false;
        output[index] = static_cast<std::byte>((high << 4) | low);
    }
    return true;
}

[[nodiscard]] std::array<std::byte, 40U> lease_commitment(
    const VerifiedUsageLease& lease) noexcept {
    std::array<std::byte, 40U> output{};
    if (!lower_hex_digest_bytes(
            lease.ticket_sha256,
            std::span<std::byte, 32U>{output.data(), 32U})) {
        return {};
    }
    for (std::size_t index{}; index < 8U; ++index) {
        output[32U + index] = static_cast<std::byte>(
            (lease.claims.sequence >> ((7U - index) * 8U)) & 0xffU);
    }
    return output;
}

[[nodiscard]] bool lease_commitment_matches(
    const std::span<const std::byte> candidate,
    const VerifiedUsageLease& lease) noexcept {
    if (candidate.size() != 40U) return false;
    const auto expected = lease_commitment(lease);
    std::uint8_t difference{};
    for (std::size_t index{}; index < expected.size(); ++index) {
        difference |= std::to_integer<std::uint8_t>(
            candidate[index] ^ expected[index]);
    }
    return difference == 0U;
}

[[nodiscard]] bool admission_succeeded(
    const UsageLeaseAdmission admission) noexcept {
    return admission == UsageLeaseAdmission::accepted_current ||
        admission == UsageLeaseAdmission::staged_future ||
        admission == UsageLeaseAdmission::accepted_idempotent;
}

enum class TypedUsageProofKindV1 : std::uint8_t {
    invalid = 0U,
    start_challenge = 1U,
    start = 2U,
    start_cancel = 3U,
    heartbeat = 4U,
    stop = 5U,
};

class TypedUsageProofCursorV1 final {
public:
    explicit TypedUsageProofCursorV1(
        const std::span<const std::byte> source) noexcept : source_(source) {}

    [[nodiscard]] bool read_header(TypedUsageProofKindV1& kind) noexcept {
        if (source_.size() < 8U || source_[0] != std::byte{'V'} ||
            source_[1] != std::byte{'U'} || source_[2] != std::byte{'S'} ||
            source_[3] != std::byte{'1'} || source_[4] != std::byte{1U} ||
            source_[6] != std::byte{0U} || source_[7] != std::byte{0U}) {
            return false;
        }
        const auto value = std::to_integer<std::uint8_t>(source_[5]);
        if (value < static_cast<std::uint8_t>(
                        TypedUsageProofKindV1::start_challenge) ||
            value > static_cast<std::uint8_t>(TypedUsageProofKindV1::stop)) {
            return false;
        }
        kind = static_cast<TypedUsageProofKindV1>(value);
        offset_ = 8U;
        return true;
    }

    [[nodiscard]] bool read_ascii(
        const std::size_t size, std::string& output) {
        if (size > source_.size() - offset_) return false;
        output.clear();
        output.reserve(size);
        for (std::size_t index{}; index < size; ++index) {
            const auto value = std::to_integer<std::uint8_t>(
                source_[offset_ + index]);
            if (value > 0x7fU) return false;
            output.push_back(static_cast<char>(value));
        }
        offset_ += size;
        return true;
    }

    [[nodiscard]] bool read_u64(std::uint64_t& output) noexcept {
        if (8U > source_.size() - offset_) return false;
        output = 0U;
        for (std::size_t index{}; index < 8U; ++index) {
            output = (output << 8U) |
                std::to_integer<std::uint8_t>(source_[offset_ + index]);
        }
        offset_ += 8U;
        return true;
    }

    [[nodiscard]] bool read_u32(std::uint32_t& output) noexcept {
        if (4U > source_.size() - offset_) return false;
        output = 0U;
        for (std::size_t index{}; index < 4U; ++index) {
            output = (output << 8U) |
                std::to_integer<std::uint8_t>(source_[offset_ + index]);
        }
        offset_ += 4U;
        return true;
    }

    [[nodiscard]] bool read_bool(bool& output) noexcept {
        if (offset_ >= source_.size()) return false;
        const auto value = std::to_integer<std::uint8_t>(source_[offset_++]);
        if (value > 1U) return false;
        output = value == 1U;
        return true;
    }

    [[nodiscard]] bool finished() const noexcept {
        return offset_ == source_.size();
    }

private:
    std::span<const std::byte> source_;
    std::size_t offset_{};
};

[[nodiscard]] bool usage_context_matches(
    const std::string& entitlement_id,
    const std::string& pair_id,
    const std::uint32_t protocol_version,
    const std::uint64_t revocation_version,
    const std::string& channel_binding_sha256,
    const UsageLeaseBinding& expected) noexcept {
    return entitlement_id == expected.entitlement_id &&
        pair_id == expected.pair_id &&
        protocol_version == expected.protocol_version &&
        revocation_version == expected.revocation_version &&
        channel_binding_sha256 == expected.channel_binding_sha256;
}

struct TypedUsageSigningResultV1 final {
    HostUsageAuthorizationSigningResultV1 signed_proof;
    TypedUsageProofKindV1 kind{TypedUsageProofKindV1::invalid};
    bool request_valid{};
};

[[nodiscard]] TypedUsageSigningResultV1 sign_typed_usage_request(
    const std::span<const std::byte> request,
    HostUsageAuthorizationSignerV1& signer,
    const UsageLeaseBinding& expected,
    const std::optional<VerifiedUsageLease>& committed) noexcept {
    TypedUsageSigningResultV1 result;
    try {
        TypedUsageProofCursorV1 cursor(request);
        if (!cursor.read_header(result.kind)) return result;
        switch (result.kind) {
        case TypedUsageProofKindV1::start_challenge: {
            UsageStartChallengeProof proof;
            if (!cursor.read_ascii(64U, proof.channel_binding_sha256) ||
                !cursor.read_ascii(32U, proof.entitlement_id) ||
                !cursor.read_ascii(32U, proof.pair_id) ||
                !cursor.read_u32(proof.protocol_version) ||
                !cursor.read_ascii(32U, proof.request_id) ||
                !cursor.read_ascii(32U, proof.request_nonce) ||
                !cursor.read_u64(proof.revocation_version) ||
                !cursor.finished() ||
                !usage_context_matches(
                    proof.entitlement_id,
                    proof.pair_id,
                    proof.protocol_version,
                    proof.revocation_version,
                    proof.channel_binding_sha256,
                    expected)) {
                return result;
            }
            result.signed_proof =
                signer.build_and_sign_usage_start_challenge(proof);
            break;
        }
        case TypedUsageProofKindV1::start: {
            UsageStartProof proof;
            if (!cursor.read_u64(proof.android_frames_total) ||
                !cursor.read_bool(proof.android_runtime_ready) ||
                !cursor.read_ascii(64U, proof.channel_binding_sha256) ||
                !cursor.read_ascii(32U, proof.entitlement_id) ||
                !cursor.read_u64(proof.host_frames_total) ||
                !cursor.read_bool(proof.host_runtime_ready) ||
                !cursor.read_ascii(32U, proof.pair_id) ||
                !cursor.read_u32(proof.protocol_version) ||
                !cursor.read_ascii(32U, proof.request_id) ||
                !cursor.read_ascii(32U, proof.request_nonce) ||
                !cursor.read_u64(proof.revocation_version) ||
                !cursor.read_ascii(32U, proof.start_challenge_id) ||
                !cursor.read_ascii(
                    64U, proof.start_challenge_token_sha256) ||
                !cursor.finished() ||
                !usage_context_matches(
                    proof.entitlement_id,
                    proof.pair_id,
                    proof.protocol_version,
                    proof.revocation_version,
                    proof.channel_binding_sha256,
                    expected)) {
                return result;
            }
            result.signed_proof = signer.build_and_sign_usage_start(proof);
            break;
        }
        case TypedUsageProofKindV1::start_cancel: {
            UsageStartCancelProof proof;
            if (!cursor.read_ascii(64U, proof.channel_binding_sha256) ||
                !cursor.read_ascii(32U, proof.entitlement_id) ||
                !cursor.read_ascii(32U, proof.pair_id) ||
                !cursor.read_u32(proof.protocol_version) ||
                !cursor.read_ascii(32U, proof.request_id) ||
                !cursor.read_ascii(32U, proof.request_nonce) ||
                !cursor.read_u64(proof.revocation_version) ||
                !cursor.read_ascii(32U, proof.start_request_id) ||
                !cursor.finished() ||
                !usage_context_matches(
                    proof.entitlement_id,
                    proof.pair_id,
                    proof.protocol_version,
                    proof.revocation_version,
                    proof.channel_binding_sha256,
                    expected)) {
                return result;
            }
            result.signed_proof =
                signer.build_and_sign_usage_start_cancel(proof);
            break;
        }
        case TypedUsageProofKindV1::heartbeat: {
            UsageHeartbeatProof proof;
            if (!cursor.read_u64(proof.android_frames_total) ||
                !cursor.read_ascii(64U, proof.channel_binding_sha256) ||
                !cursor.read_ascii(32U, proof.entitlement_id) ||
                !cursor.read_u64(proof.host_frames_total) ||
                !cursor.read_ascii(32U, proof.pair_id) ||
                !cursor.read_ascii(64U, proof.previous_lease_sha256) ||
                !cursor.read_u32(proof.protocol_version) ||
                !cursor.read_ascii(32U, proof.request_id) ||
                !cursor.read_ascii(32U, proof.request_nonce) ||
                !cursor.read_u64(proof.revocation_version) ||
                !cursor.read_u64(proof.sequence) ||
                !cursor.read_ascii(32U, proof.session_id) ||
                !cursor.finished() ||
                !usage_context_matches(
                    proof.entitlement_id,
                    proof.pair_id,
                    proof.protocol_version,
                    proof.revocation_version,
                    proof.channel_binding_sha256,
                    expected) ||
                !committed.has_value() ||
                proof.session_id != committed->claims.session_id ||
                proof.previous_lease_sha256 != committed->ticket_sha256 ||
                committed->claims.sequence ==
                    (std::numeric_limits<std::uint64_t>::max)() ||
                proof.sequence != committed->claims.sequence + 1U) {
                return result;
            }
            result.signed_proof =
                signer.build_and_sign_usage_heartbeat(proof);
            break;
        }
        case TypedUsageProofKindV1::stop: {
            UsageStopProof proof;
            if (!cursor.read_ascii(64U, proof.channel_binding_sha256) ||
                !cursor.read_ascii(32U, proof.entitlement_id) ||
                !cursor.read_ascii(32U, proof.pair_id) ||
                !cursor.read_ascii(64U, proof.previous_lease_sha256) ||
                !cursor.read_u32(proof.protocol_version) ||
                !cursor.read_ascii(32U, proof.request_id) ||
                !cursor.read_ascii(32U, proof.request_nonce) ||
                !cursor.read_u64(proof.revocation_version) ||
                !cursor.read_ascii(32U, proof.session_id) ||
                !cursor.finished() ||
                !usage_context_matches(
                    proof.entitlement_id,
                    proof.pair_id,
                    proof.protocol_version,
                    proof.revocation_version,
                    proof.channel_binding_sha256,
                    expected) ||
                !committed.has_value() ||
                proof.session_id != committed->claims.session_id ||
                proof.previous_lease_sha256 != committed->ticket_sha256) {
                return result;
            }
            result.signed_proof = signer.build_and_sign_usage_stop(proof);
            break;
        }
        case TypedUsageProofKindV1::invalid:
            return result;
        }
        result.request_valid = result.signed_proof.succeeded();
        return result;
    } catch (...) {
        return result;
    }
}

}  // namespace

HostRuntimeAuthorizationCoordinator::HostRuntimeAuthorizationCoordinator(
    HostRuntimeService& runtime) noexcept : runtime_(runtime) {}

HostRuntimeAuthorizationCoordinator::~HostRuntimeAuthorizationCoordinator() {
    close();
}

bool HostRuntimeAuthorizationCoordinator::install_authenticated_channel(
    HostDeviceIdentityRuntime& identity_runtime,
    const HostAuthenticatedControlPairBindingV1& pair,
    const std::uint64_t generation,
    std::unique_ptr<ConfirmedPeerHandshakeSessionV1> session,
    std::unique_ptr<AuthenticatedControlTcpConnectionV1> connection)
    noexcept {
    try {
        close();
        if (session == nullptr || connection == nullptr ||
            !connection->is_open() ||
            session->local_role() != PeerHandshakeRole::host) {
            return false;
        }
        const auto binding = session->binding();
        if (generation == 0U || binding.session_generation != generation ||
            binding.pair_id != pair.pair_id ||
            lower_hex(binding.host_identity_spki_sha256) !=
                pair.host_identity_spki_sha256 ||
            lower_hex(binding.android_identity_spki_sha256) !=
                pair.android_identity_spki_sha256) {
            return false;
        }
        if (!runtime_.install_authenticated_data_plane_session(*session)) {
            return false;
        }
        {
            std::lock_guard lock(mutex_);
            identity_runtime_ = &identity_runtime;
            pair_ = pair;
            session_ = std::move(session);
            connection_ = std::move(connection);
            stopping_.store(false);
        }
        try {
            worker_ = std::thread([this] { run_authenticated_control(); });
        } catch (...) {
            close();
            return false;
        }
        log_host_runtime_event(
            "host_authenticated_control_channel_ready",
            "peer_finished=true usage_signing_ready=true "
            "raw_lease_installed=false data_plane_open=false");
        return true;
    } catch (...) {
        return false;
    }
}

bool HostRuntimeAuthorizationCoordinator::has_authenticated_channel()
    const noexcept {
    std::lock_guard lock(mutex_);
    return session_ != nullptr && connection_ != nullptr &&
        connection_->is_open();
}

void HostRuntimeAuthorizationCoordinator::run_authenticated_control()
    noexcept {
    try {
        HostDeviceIdentityRuntime* identity{};
        HostAuthenticatedControlPairBindingV1 pair;
        ConfirmedPeerHandshakeSessionV1* session{};
        AuthenticatedControlTcpConnectionV1* connection{};
        {
            std::lock_guard lock(mutex_);
            identity = identity_runtime_;
            pair = pair_;
            session = session_.get();
            connection = connection_.get();
        }
        if (identity == nullptr || session == nullptr || connection == nullptr) {
            return;
        }
        const auto binding = session->binding();
        UsageLeaseBinding expected_peer_binding{
            .entitlement_id = pair.entitlement_id,
            .pair_id = pair.pair_id,
            .session_id = {},
            .protocol_version = kUsageLeaseProtocolVersion,
            .revocation_version = pair.revocation_version,
            .host_key_sha256 = lower_hex(binding.host_identity_spki_sha256),
            .android_key_sha256 =
                lower_hex(binding.android_identity_spki_sha256),
            .channel_binding_sha256 =
                lower_hex(binding.channel_binding_sha256),
        };
        auto verifier_result =
            HostUsageLeaseVerifierV1::create_from_build_pinned_keyring();
        if (!verifier_result.succeeded()) {
            log_host_runtime_event(
                "host_authenticated_control_worker_failed",
                "stage=lease_verifier construction_failed=true "
                "data_plane_open=false");
            return;
        }
        auto provider = make_platform_aes_256_gcm_provider();
        if (provider == nullptr) {
            log_host_runtime_event(
                "host_authenticated_control_worker_failed",
                "stage=aes_provider unavailable=true data_plane_open=false");
            return;
        }
        AuthenticatedControlRecordOpenerV1 opener(
            traffic_key(
                session->control_android_to_host(),
                binding.connection_id,
                binding.session_generation,
                ControlRecordDirectionV1::android_to_host),
            *provider);
        AuthenticatedControlRecordSealerV1 sealer(
            traffic_key(
                session->control_host_to_android(),
                binding.connection_id,
                binding.session_generation,
                ControlRecordDirectionV1::host_to_android),
            *provider);
        std::optional<VerifiedUsageLease> pending_lease;
        std::optional<VerifiedUsageLease> committed_lease;
        bool runtime_binding_installed = false;

        const auto send_record = [&](const ControlMessageTypeV1 type,
                                     const std::span<const std::byte> payload)
            noexcept -> bool {
            auto sealed = sealer.seal(type, payload);
            const bool sent =
                sealed.status == ControlRecordSealStatusV1::sealed &&
                connection->write_authenticated_record(
                    sealed.envelope,
                    ControlRecordDirectionV1::host_to_android,
                    60'000U).succeeded();
            erase(sealed.envelope);
            return sent;
        };

        while (!stopping_.load() && connection->is_open()) {
            auto incoming = connection->read_authenticated_record(
                ControlRecordDirectionV1::android_to_host, 300'000U);
            if (!incoming.succeeded()) {
                // close() sets stopping_ before interrupting the blocking
                // socket read.  WSAENOTSOCK/WSANOTINITIALISED from that
                // deliberate interruption is normal shutdown, not a red
                // authenticated-channel failure.
                if (stopping_.load()) break;
                log_host_runtime_event(
                    "host_authenticated_control_worker_failed",
                    "stage=record_read status=" + std::to_string(
                        static_cast<unsigned>(incoming.error.status)) +
                    " native_error=" +
                        std::to_string(incoming.error.native_error) +
                    " data_plane_open=false");
                break;
            }
            auto opened = opener.open(incoming.encoded_record);
            erase(incoming.encoded_record);
            if (opened.status != ControlRecordOpenStatusV1::opened) {
                log_host_runtime_event(
                    "host_authenticated_control_worker_failed",
                    "stage=record_open status=" + std::to_string(
                        static_cast<unsigned>(opened.status)) +
                    " message_type=" + std::to_string(static_cast<unsigned>(
                        opened.message_type)) +
                    " payload_bytes=" +
                        std::to_string(opened.plaintext.size()) +
                    " data_plane_open=false");
                erase(opened.plaintext);
                break;
            }

            if (opened.message_type ==
                ControlMessageTypeV1::host_start_intent_claim_request) {
                if (opened.plaintext.size() != 16U) {
                    log_host_runtime_event(
                        "host_authenticated_control_worker_failed",
                        "stage=start_intent_claim payload_invalid=true "
                        "data_plane_open=false billing_started=false");
                    erase(opened.plaintext);
                    break;
                }
                std::vector<std::byte> response(32U, std::byte{0U});
                std::copy(
                    opened.plaintext.begin(), opened.plaintext.end(),
                    response.begin());
                erase(opened.plaintext);
                for (std::size_t index{}; index < 8U; ++index) {
                    response[16U + index] = static_cast<std::byte>(
                        (binding.connection_id >> ((7U - index) * 8U)) &
                        0xffU);
                }
                const std::uint64_t intent_token =
                    runtime_.claim_pending_start_intent();
                for (std::size_t index{}; index < 8U; ++index) {
                    response[24U + index] = static_cast<std::byte>(
                        (intent_token >> ((7U - index) * 8U)) & 0xffU);
                }
                const bool sent = send_record(
                    ControlMessageTypeV1::host_start_intent_claim_response,
                    response);
                erase(response);
                if (!sent) {
                    log_host_runtime_event(
                        "host_authenticated_control_worker_failed",
                        "stage=start_intent_claim_response_write "
                        "data_plane_open=false billing_started=false");
                    break;
                }
                // Empty claims are a normal mobile poll while the operator has
                // not requested a start. They are intentionally not emitted as
                // events; otherwise a healthy idle session floods diagnostics.
                if (intent_token != 0U) {
                    log_host_runtime_event(
                        "host_start_intent_claimed",
                        "channel_authenticated=true one_shot=true "
                        "data_plane_open=false prelease_video=false "
                        "billing_started=false");
                }
                continue;
            }

            if (opened.message_type ==
                ControlMessageTypeV1::entitlement_status_sign_request) {
                if (opened.plaintext.size() != 16U) {
                    log_host_runtime_event(
                        "host_authenticated_control_worker_failed",
                        "stage=status_request payload_invalid=true "
                        "data_plane_open=false");
                    erase(opened.plaintext);
                    break;
                }
                EntitlementStatusProof proof{
                    .entitlement_id = pair.entitlement_id,
                    .pair_id = pair.pair_id,
                    .protocol_version = kUsageAuthorizationProtocolVersion,
                    .request_nonce = lower_hex(opened.plaintext),
                    .revocation_version = pair.revocation_version,
                };
                auto signed_status = identity->usage_authorization_signer()
                    .build_and_sign_entitlement_status(proof);
                if (!signed_status.succeeded()) {
                    log_host_runtime_event(
                        "host_authenticated_control_worker_failed",
                        "stage=status_signing typed_request=true "
                        "data_plane_open=false");
                    erase(opened.plaintext);
                    break;
                }
                std::vector<std::byte> response;
                response.reserve(
                    opened.plaintext.size() +
                    signed_status.signature_der_low_s.size());
                response.insert(
                    response.end(),
                    opened.plaintext.begin(), opened.plaintext.end());
                response.insert(
                    response.end(),
                    reinterpret_cast<const std::byte*>(
                        signed_status.signature_der_low_s.data()),
                    reinterpret_cast<const std::byte*>(
                        signed_status.signature_der_low_s.data() +
                        signed_status.signature_der_low_s.size()));
                erase(opened.plaintext);
                std::fill(
                    signed_status.signature_der_low_s.begin(),
                    signed_status.signature_der_low_s.end(),
                    std::uint8_t{0U});
                const bool sent = send_record(
                    ControlMessageTypeV1::entitlement_status_sign_response,
                    response);
                erase(response);
                if (!sent) {
                    log_host_runtime_event(
                        "host_authenticated_control_worker_failed",
                        "stage=status_response_write data_plane_open=false");
                    break;
                }
                log_host_runtime_event(
                    "host_entitlement_status_proof_signed",
                    "typed_request=true channel_authenticated=true");
                continue;
            }

            if (opened.message_type ==
                ControlMessageTypeV1::usage_authorization_sign_request) {
                auto typed = sign_typed_usage_request(
                    opened.plaintext,
                    identity->usage_authorization_signer(),
                    expected_peer_binding,
                    committed_lease);
                erase(opened.plaintext);
                if (!typed.request_valid) {
                    log_host_runtime_event(
                        "host_usage_authorization_sign_rejected",
                        "typed_request=true context_valid=false "
                        "data_plane_open=false");
                    break;
                }
                std::vector<std::byte> response;
                response.reserve(
                    typed.signed_proof.canonical_payload_sha256.size() +
                    typed.signed_proof.signature_der_low_s.size());
                response.insert(
                    response.end(),
                    reinterpret_cast<const std::byte*>(
                        typed.signed_proof.canonical_payload_sha256.data()),
                    reinterpret_cast<const std::byte*>(
                        typed.signed_proof.canonical_payload_sha256.data() +
                        typed.signed_proof.canonical_payload_sha256.size()));
                response.insert(
                    response.end(),
                    reinterpret_cast<const std::byte*>(
                        typed.signed_proof.signature_der_low_s.data()),
                    reinterpret_cast<const std::byte*>(
                        typed.signed_proof.signature_der_low_s.data() +
                        typed.signed_proof.signature_der_low_s.size()));
                erase(typed.signed_proof.canonical_payload);
                typed.signed_proof.canonical_payload_sha256.fill(0U);
                std::fill(
                    typed.signed_proof.signature_der_low_s.begin(),
                    typed.signed_proof.signature_der_low_s.end(),
                    std::uint8_t{0U});
                const bool sent = send_record(
                    ControlMessageTypeV1::usage_authorization_sign_response,
                    response);
                erase(response);
                if (!sent) {
                    log_host_runtime_event(
                        "host_authenticated_control_worker_failed",
                        "stage=usage_sign_response_write "
                        "data_plane_open=false");
                    break;
                }
                log_host_runtime_event(
                    "host_usage_authorization_proof_signed",
                    "typed_request=true proof_kind=" +
                        std::to_string(static_cast<unsigned>(typed.kind)) +
                    " channel_authenticated=true");
                continue;
            }

            if (opened.message_type == ControlMessageTypeV1::lease_offer) {
                if (!compact_token_ascii_valid(opened.plaintext)) {
                    log_host_runtime_event(
                        "host_usage_lease_offer_rejected",
                        "stage=source_validation data_plane_open=false");
                    erase(opened.plaintext);
                    break;
                }
                std::string raw_lease(
                    reinterpret_cast<const char*>(opened.plaintext.data()),
                    opened.plaintext.size());
                erase(opened.plaintext);
                const std::uint64_t trusted_now = current_epoch_seconds();
                auto verified = verifier_result.verifier
                    ->verify_for_confirmed_peer_with_signed_session(
                        raw_lease, expected_peer_binding, trusted_now);
                erase(raw_lease);
                if (!verified.succeeded()) {
                    log_host_runtime_event(
                        "host_usage_lease_offer_rejected",
                        "stage=independent_signature_or_claim_validation "
                        "error_code=" + std::to_string(static_cast<unsigned>(
                            verified.error.code)) +
                        " data_plane_open=false");
                    break;
                }
                VerifiedUsageLease candidate =
                    std::move(verified.lease.value());
                const auto runtime_authorization =
                    runtime_.authorization_snapshot();
                const bool prior_session_terminal =
                    !runtime_authorization.permits_data_plane &&
                    !runtime_authorization.monotonic_clock_rollback &&
                    (runtime_authorization.lease_state ==
                            UsageLeaseGateState::expired ||
                        runtime_authorization.lease_state ==
                            UsageLeaseGateState::stopped);
                const bool successor_session_genesis =
                    committed_lease.has_value() &&
                    candidate.claims.sequence == 0U &&
                    candidate.claims.session_id !=
                        committed_lease->claims.session_id &&
                    prior_session_terminal;
                const bool same_as_committed = committed_lease.has_value() &&
                    candidate.claims.sequence ==
                        committed_lease->claims.sequence &&
                    candidate.ticket_sha256 == committed_lease->ticket_sha256;
                const bool next_after_committed =
                    committed_lease.has_value() &&
                    committed_lease->claims.sequence !=
                        (std::numeric_limits<std::uint64_t>::max)() &&
                    candidate.claims.sequence ==
                        committed_lease->claims.sequence + 1U &&
                    candidate.claims.previous_ticket_sha256 ==
                        committed_lease->ticket_sha256 &&
                    candidate.claims.session_id ==
                        committed_lease->claims.session_id;
                const bool genesis = !committed_lease.has_value() &&
                    candidate.claims.sequence == 0U;
                const bool same_as_pending = pending_lease.has_value() &&
                    candidate.claims.sequence ==
                        pending_lease->claims.sequence &&
                    candidate.ticket_sha256 == pending_lease->ticket_sha256;
                if ((pending_lease.has_value() && !same_as_pending) ||
                    (!genesis && !same_as_committed &&
                        !next_after_committed &&
                        !successor_session_genesis)) {
                    log_host_runtime_event(
                        "host_usage_lease_offer_rejected",
                        "stage=sequence_or_fork_validation "
                        "data_plane_open=false");
                    break;
                }
                pending_lease = std::move(candidate);
                const auto acceptance = lease_commitment(*pending_lease);
                if (!send_record(
                        ControlMessageTypeV1::lease_accept, acceptance)) {
                    log_host_runtime_event(
                        "host_authenticated_control_worker_failed",
                        "stage=lease_accept_write data_plane_open=false");
                    break;
                }
                log_host_runtime_event(
                    "host_usage_lease_offer_accepted",
                    "independently_verified=true commit_pending=true "
                    "sequence=" + std::to_string(
                        pending_lease->claims.sequence) +
                    " successor_session_genesis=" +
                        (successor_session_genesis
                            ? std::string{"true"}
                            : std::string{"false"}) +
                    " data_plane_open=false");
                continue;
            }

            if (opened.message_type == ControlMessageTypeV1::lease_commit) {
                if (!pending_lease.has_value() ||
                    !lease_commitment_matches(
                        opened.plaintext, *pending_lease)) {
                    log_host_runtime_event(
                        "host_usage_lease_commit_rejected",
                        "stage=commitment_validation data_plane_open=false");
                    erase(opened.plaintext);
                    break;
                }
                erase(opened.plaintext);
                const auto runtime_authorization =
                    runtime_.authorization_snapshot();
                const bool successor_session_genesis =
                    committed_lease.has_value() &&
                    pending_lease->claims.sequence == 0U &&
                    pending_lease->claims.session_id !=
                        committed_lease->claims.session_id &&
                    !runtime_authorization.permits_data_plane &&
                    !runtime_authorization.monotonic_clock_rollback &&
                    (runtime_authorization.lease_state ==
                            UsageLeaseGateState::expired ||
                        runtime_authorization.lease_state ==
                            UsageLeaseGateState::stopped);
                if (successor_session_genesis) {
                    runtime_.reset_data_plane_authorization_for_new_session();
                    runtime_binding_installed = false;
                    committed_lease.reset();
                }
                UsageLeaseBinding runtime_binding = expected_peer_binding;
                runtime_binding.session_id =
                    pending_lease->claims.session_id;
                if (!runtime_binding_installed) {
                    if (!runtime_.install_confirmed_peer_binding(
                            std::move(runtime_binding))) {
                        log_host_runtime_event(
                            "host_usage_lease_commit_rejected",
                            "stage=peer_binding_install "
                            "data_plane_open=false");
                        break;
                    }
                    runtime_binding_installed = true;
                } else if (committed_lease.has_value() &&
                    committed_lease->claims.session_id !=
                        pending_lease->claims.session_id) {
                    log_host_runtime_event(
                        "host_usage_lease_commit_rejected",
                        "stage=session_fork_validation "
                        "data_plane_open=false");
                    break;
                }
                const std::uint64_t trusted_now = current_epoch_seconds();
                const UsageLeaseAdmission admission =
                    runtime_.submit_verified_usage_lease(
                        *pending_lease, trusted_now);
                if (!admission_succeeded(admission)) {
                    log_host_runtime_event(
                        "host_usage_lease_commit_rejected",
                        "stage=runtime_gate admission=" +
                            std::to_string(static_cast<unsigned>(admission)) +
                        " data_plane_open=false");
                    break;
                }
                runtime_.complete_pending_start_intent();
                committed_lease = std::move(pending_lease);
                pending_lease.reset();
                log_host_runtime_event(
                    "host_usage_lease_committed",
                    "raw_lease_verified=true android_commit_verified=true "
                    "sequence=" + std::to_string(
                        committed_lease->claims.sequence) +
                    " data_plane_open=" +
                        (runtime_.authorization_snapshot().permits_data_plane
                            ? std::string{"true"}
                            : std::string{"false"}));
                continue;
            }

            log_host_runtime_event(
                "host_authenticated_control_worker_failed",
                "stage=unexpected_message message_type=" +
                    std::to_string(static_cast<unsigned>(
                        opened.message_type)) +
                    " data_plane_open=false");
            erase(opened.plaintext);
            break;
        }
    } catch (...) {
        log_host_runtime_event(
            "host_authenticated_control_worker_failed",
            "stage=unexpected_exception data_plane_open=false");
    }
    std::lock_guard lock(mutex_);
    if (connection_ != nullptr) connection_->close();
    runtime_.revoke_data_plane_authorization();
}

void HostRuntimeAuthorizationCoordinator::close() noexcept {
    stopping_.store(true);
    {
        std::lock_guard lock(mutex_);
        if (connection_ != nullptr) connection_->close();
    }
    if (worker_.joinable() &&
        worker_.get_id() != std::this_thread::get_id()) {
        worker_.join();
    }
    {
        std::lock_guard lock(mutex_);
        connection_.reset();
        session_.reset();
        identity_runtime_ = nullptr;
        pair_ = {};
    }
    runtime_.revoke_data_plane_authorization();
}

}  // namespace vfdual
