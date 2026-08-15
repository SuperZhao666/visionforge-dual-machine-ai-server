#include "vfdual/pair_generation_proposal_v1.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#endif

namespace vfdual {
namespace {

constexpr std::size_t kTlvHeaderBytes = 5U;
constexpr std::uint8_t kNoFieldTag = 0xffU;

enum class ProposalTag : std::uint8_t {
    domain = 0U,
    protocol_version = 1U,
    host_identity_spki_sha256 = 2U,
    android_identity_spki_sha256 = 3U,
    host_ephemeral_public_key = 4U,
    android_ephemeral_public_key = 5U,
    host_nonce = 6U,
    android_nonce = 7U,
    connection_id = 8U,
    transport_kind = 9U,
    host_ipv4 = 10U,
    android_ipv4 = 11U,
    video_port = 12U,
    control_port = 13U,
    pair_id = 14U,
    host_runtime_version = 15U,
    android_runtime_version = 16U,
};

[[nodiscard]] constexpr std::uint8_t tag_value(
    const ProposalTag tag) noexcept {
    return static_cast<std::uint8_t>(tag);
}

[[nodiscard]] PairGenerationProposalError proposal_error(
    const PairGenerationProposalErrorCode code,
    const std::uint8_t field_tag = kNoFieldTag) noexcept {
    return {.code = code, .field_tag = field_tag};
}

[[nodiscard]] bool contains_nonzero(
    const std::span<const std::byte> value) noexcept {
    return std::any_of(value.begin(), value.end(), [](const std::byte byte) {
        return byte != std::byte{0U};
    });
}

[[nodiscard]] bool stable_semver_valid(
    const std::string_view value) noexcept {
    if (value.empty() ||
        value.size() > kPeerHandshakeMaximumRuntimeVersionBytes) {
        return false;
    }
    std::size_t component_start{};
    std::size_t component_count{};
    for (std::size_t index{}; index <= value.size(); ++index) {
        if (index != value.size() && value[index] != '.') {
            if (value[index] < '0' || value[index] > '9') return false;
            continue;
        }
        const std::size_t component_size = index - component_start;
        if (component_size == 0U ||
            (component_size > 1U && value[component_start] == '0')) {
            return false;
        }
        ++component_count;
        component_start = index + 1U;
    }
    return component_count == 3U;
}

[[nodiscard]] bool pair_id_valid(const std::string_view value) noexcept {
    return value.size() == kPairGenerationProposalPairIdBytes &&
        std::all_of(value.begin(), value.end(), [](const char character) {
            return (character >= '0' && character <= '9') ||
                (character >= 'a' && character <= 'f');
        });
}

[[nodiscard]] PeerHandshakeTranscriptFields final_fields_from_proposal(
    const PairGenerationProposalFields& fields,
    const std::uint64_t generation) {
    PeerHandshakeTranscriptFields final_fields;
    final_fields.host_identity_spki_sha256 =
        fields.host_identity_spki_sha256;
    final_fields.android_identity_spki_sha256 =
        fields.android_identity_spki_sha256;
    final_fields.host_ephemeral_public_key =
        fields.host_ephemeral_public_key;
    final_fields.android_ephemeral_public_key =
        fields.android_ephemeral_public_key;
    final_fields.host_nonce = fields.host_nonce;
    final_fields.android_nonce = fields.android_nonce;
    final_fields.connection_id = fields.connection_id;
    final_fields.session_generation = generation;
    final_fields.transport_kind = fields.transport_kind;
    final_fields.host_ipv4 = fields.host_ipv4;
    final_fields.android_ipv4 = fields.android_ipv4;
    final_fields.video_port = fields.video_port;
    final_fields.control_port = fields.control_port;
    final_fields.pair_id = fields.pair_id;
    final_fields.host_runtime_version = fields.host_runtime_version;
    final_fields.android_runtime_version = fields.android_runtime_version;
    return final_fields;
}

[[nodiscard]] PairGenerationProposalError validate_fields(
    const PairGenerationProposalFields& fields) {
    if (!contains_nonzero(fields.host_identity_spki_sha256) ||
        !contains_nonzero(fields.android_identity_spki_sha256) ||
        fields.host_identity_spki_sha256 ==
            fields.android_identity_spki_sha256) {
        return proposal_error(
            PairGenerationProposalErrorCode::invalid_identity_binding,
            tag_value(ProposalTag::host_identity_spki_sha256));
    }
    if (fields.host_ephemeral_public_key ==
        fields.android_ephemeral_public_key) {
        return proposal_error(
            PairGenerationProposalErrorCode::invalid_ephemeral_public_key,
            tag_value(ProposalTag::android_ephemeral_public_key));
    }
    if (!contains_nonzero(fields.host_nonce) ||
        !contains_nonzero(fields.android_nonce) ||
        fields.host_nonce == fields.android_nonce) {
        return proposal_error(
            PairGenerationProposalErrorCode::invalid_nonce,
            tag_value(ProposalTag::host_nonce));
    }
    if (fields.connection_id == 0U ||
        fields.connection_id > kPairGenerationProposalSigned64Maximum) {
        return proposal_error(
            PairGenerationProposalErrorCode::invalid_connection_id,
            tag_value(ProposalTag::connection_id));
    }
    switch (fields.transport_kind) {
        case PeerHandshakeTransportKind::cat6:
        case PeerHandshakeTransportKind::wlan:
            break;
        default:
            return proposal_error(
                PairGenerationProposalErrorCode::invalid_transport_kind,
                tag_value(ProposalTag::transport_kind));
    }
    if (fields.video_port == 0U || fields.control_port == 0U ||
        fields.video_port == fields.control_port) {
        return proposal_error(
            PairGenerationProposalErrorCode::invalid_endpoint,
            tag_value(ProposalTag::video_port));
    }
    if (!pair_id_valid(fields.pair_id)) {
        return proposal_error(
            PairGenerationProposalErrorCode::invalid_pair_id,
            tag_value(ProposalTag::pair_id));
    }
    if (!stable_semver_valid(fields.host_runtime_version)) {
        return proposal_error(
            PairGenerationProposalErrorCode::invalid_runtime_version,
            tag_value(ProposalTag::host_runtime_version));
    }
    if (!stable_semver_valid(fields.android_runtime_version)) {
        return proposal_error(
            PairGenerationProposalErrorCode::invalid_runtime_version,
            tag_value(ProposalTag::android_runtime_version));
    }

    const PeerHandshakeTranscriptResult validation =
        build_canonical_peer_handshake_transcript_v1(
            final_fields_from_proposal(fields, 1U),
            PeerHandshakePairIdRequirement::require_bound_pair);
    if (validation.succeeded()) return {};
    switch (validation.error.code) {
        case PeerHandshakeErrorCode::invalid_ephemeral_public_key:
            return proposal_error(
                PairGenerationProposalErrorCode::invalid_ephemeral_public_key,
                validation.error.field_tag == 4U
                    ? tag_value(ProposalTag::host_ephemeral_public_key)
                    : tag_value(ProposalTag::android_ephemeral_public_key));
        case PeerHandshakeErrorCode::platform_crypto_unavailable:
        case PeerHandshakeErrorCode::crypto_provider_failed:
            return proposal_error(
                PairGenerationProposalErrorCode::crypto_unavailable);
        case PeerHandshakeErrorCode::allocation_failed:
            return proposal_error(
                PairGenerationProposalErrorCode::allocation_failed);
        default:
            return proposal_error(
                PairGenerationProposalErrorCode::operation_failed);
    }
}

void append_u16_be(
    std::vector<std::byte>& output, const std::uint16_t value) {
    output.push_back(std::byte{static_cast<std::uint8_t>(value >> 8U)});
    output.push_back(std::byte{static_cast<std::uint8_t>(value)});
}

void append_u32_be(
    std::vector<std::byte>& output, const std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        output.push_back(std::byte{static_cast<std::uint8_t>(
            value >> static_cast<unsigned>(shift))});
    }
}

void append_u64_be(
    std::vector<std::byte>& output, const std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(std::byte{static_cast<std::uint8_t>(
            value >> static_cast<unsigned>(shift))});
    }
}

void append_tlv(
    std::vector<std::byte>& output,
    const ProposalTag tag,
    const std::span<const std::byte> value) {
    output.push_back(std::byte{tag_value(tag)});
    append_u32_be(output, static_cast<std::uint32_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
}

[[nodiscard]] std::span<const std::byte> string_bytes(
    const std::string_view value) noexcept {
    return {
        reinterpret_cast<const std::byte*>(value.data()), value.size()};
}

[[nodiscard]] std::vector<std::byte> encode_fields(
    const PairGenerationProposalFields& fields) {
    std::vector<std::byte> output;
    output.reserve(kPairGenerationProposalMaximumCanonicalBytes);
    append_tlv(
        output,
        ProposalTag::domain,
        string_bytes(kPairGenerationProposalDomain));

    std::vector<std::byte> scalar;
    scalar.reserve(8U);
    append_u32_be(scalar, kPairGenerationProposalVersion);
    append_tlv(output, ProposalTag::protocol_version, scalar);
    append_tlv(
        output,
        ProposalTag::host_identity_spki_sha256,
        fields.host_identity_spki_sha256);
    append_tlv(
        output,
        ProposalTag::android_identity_spki_sha256,
        fields.android_identity_spki_sha256);
    append_tlv(
        output,
        ProposalTag::host_ephemeral_public_key,
        fields.host_ephemeral_public_key);
    append_tlv(
        output,
        ProposalTag::android_ephemeral_public_key,
        fields.android_ephemeral_public_key);
    append_tlv(output, ProposalTag::host_nonce, fields.host_nonce);
    append_tlv(output, ProposalTag::android_nonce, fields.android_nonce);
    scalar.clear();
    append_u64_be(scalar, fields.connection_id);
    append_tlv(output, ProposalTag::connection_id, scalar);
    const std::array<std::byte, 1U> transport{
        std::byte{static_cast<std::uint8_t>(fields.transport_kind)}};
    append_tlv(output, ProposalTag::transport_kind, transport);
    append_tlv(output, ProposalTag::host_ipv4, fields.host_ipv4);
    append_tlv(output, ProposalTag::android_ipv4, fields.android_ipv4);
    scalar.clear();
    append_u16_be(scalar, fields.video_port);
    append_tlv(output, ProposalTag::video_port, scalar);
    scalar.clear();
    append_u16_be(scalar, fields.control_port);
    append_tlv(output, ProposalTag::control_port, scalar);
    append_tlv(output, ProposalTag::pair_id, string_bytes(fields.pair_id));
    append_tlv(
        output,
        ProposalTag::host_runtime_version,
        string_bytes(fields.host_runtime_version));
    append_tlv(
        output,
        ProposalTag::android_runtime_version,
        string_bytes(fields.android_runtime_version));
    return output;
}

[[nodiscard]] std::uint16_t load_u16_be(
    const std::span<const std::byte> value) noexcept {
    return static_cast<std::uint16_t>(
        (std::to_integer<std::uint16_t>(value[0]) << 8U) |
        std::to_integer<std::uint16_t>(value[1]));
}

[[nodiscard]] std::uint32_t load_u32_be(
    const std::span<const std::byte> value) noexcept {
    std::uint32_t result{};
    for (const std::byte byte : value) {
        result = (result << 8U) | std::to_integer<std::uint8_t>(byte);
    }
    return result;
}

[[nodiscard]] std::uint64_t load_u64_be(
    const std::span<const std::byte> value) noexcept {
    std::uint64_t result{};
    for (const std::byte byte : value) {
        result = (result << 8U) | std::to_integer<std::uint8_t>(byte);
    }
    return result;
}

[[nodiscard]] constexpr std::array<std::size_t,
    kPairGenerationProposalFieldCount> maximum_field_lengths() noexcept {
    return {
        kPairGenerationProposalDomain.size(),
        4U,
        32U,
        32U,
        65U,
        65U,
        32U,
        32U,
        8U,
        1U,
        4U,
        4U,
        2U,
        2U,
        32U,
        kPeerHandshakeMaximumRuntimeVersionBytes,
        kPeerHandshakeMaximumRuntimeVersionBytes,
    };
}

[[nodiscard]] PairGenerationProposalError validate_lengths(
    const std::array<std::span<const std::byte>,
        kPairGenerationProposalFieldCount>& values) noexcept {
    constexpr std::array<std::size_t,
        kPairGenerationProposalFieldCount> exact_lengths{
        kPairGenerationProposalDomain.size(),
        4U,
        32U,
        32U,
        65U,
        65U,
        32U,
        32U,
        8U,
        1U,
        4U,
        4U,
        2U,
        2U,
        32U,
        std::numeric_limits<std::size_t>::max(),
        std::numeric_limits<std::size_t>::max(),
    };
    for (std::size_t tag{}; tag < exact_lengths.size(); ++tag) {
        if (exact_lengths[tag] !=
                std::numeric_limits<std::size_t>::max() &&
            values[tag].size() != exact_lengths[tag]) {
            return proposal_error(
                PairGenerationProposalErrorCode::invalid_field_length,
                static_cast<std::uint8_t>(tag));
        }
    }
    if (values[tag_value(ProposalTag::host_runtime_version)].empty() ||
        values[tag_value(ProposalTag::android_runtime_version)].empty()) {
        return proposal_error(
            PairGenerationProposalErrorCode::invalid_field_length);
    }
    return {};
}

template <std::size_t Size>
void copy_exact(
    const std::span<const std::byte> source,
    std::array<std::byte, Size>& destination) noexcept {
    std::copy(source.begin(), source.end(), destination.begin());
}

#if defined(_WIN32)
class UniqueAlgorithm final {
public:
    UniqueAlgorithm() = default;
    ~UniqueAlgorithm() {
        if (handle != nullptr) {
            static_cast<void>(BCryptCloseAlgorithmProvider(handle, 0U));
        }
    }
    UniqueAlgorithm(const UniqueAlgorithm&) = delete;
    UniqueAlgorithm& operator=(const UniqueAlgorithm&) = delete;

    BCRYPT_ALG_HANDLE handle{};
};

class UniqueHash final {
public:
    UniqueHash() = default;
    ~UniqueHash() {
        if (handle != nullptr) static_cast<void>(BCryptDestroyHash(handle));
    }
    UniqueHash(const UniqueHash&) = delete;
    UniqueHash& operator=(const UniqueHash&) = delete;

    BCRYPT_HASH_HANDLE handle{};
};

[[nodiscard]] bool bcrypt_succeeded(const NTSTATUS status) noexcept {
    return status >= 0;
}
#endif

[[nodiscard]] PairGenerationProposalError sha256_bytes(
    const std::span<const std::byte> input,
    PeerHandshakeSha256& output) noexcept {
#if defined(_WIN32)
    if (input.size() > std::numeric_limits<ULONG>::max()) {
        return proposal_error(PairGenerationProposalErrorCode::operation_failed);
    }
    try {
        UniqueAlgorithm algorithm;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &algorithm.handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0U);
        if (!bcrypt_succeeded(status)) {
            return proposal_error(
                PairGenerationProposalErrorCode::crypto_unavailable);
        }
        ULONG object_bytes{};
        ULONG copied{};
        status = BCryptGetProperty(
            algorithm.handle,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_bytes),
            sizeof(object_bytes),
            &copied,
            0U);
        if (!bcrypt_succeeded(status) || copied != sizeof(object_bytes) ||
            object_bytes == 0U) {
            return proposal_error(
                PairGenerationProposalErrorCode::crypto_unavailable);
        }
        std::vector<std::byte> object(object_bytes);
        UniqueHash hash;
        status = BCryptCreateHash(
            algorithm.handle,
            &hash.handle,
            reinterpret_cast<PUCHAR>(object.data()),
            object_bytes,
            nullptr,
            0U,
            0U);
        if (!bcrypt_succeeded(status)) {
            return proposal_error(PairGenerationProposalErrorCode::operation_failed);
        }
        status = BCryptHashData(
            hash.handle,
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(input.data())),
            static_cast<ULONG>(input.size()),
            0U);
        if (!bcrypt_succeeded(status)) {
            return proposal_error(PairGenerationProposalErrorCode::operation_failed);
        }
        status = BCryptFinishHash(
            hash.handle,
            reinterpret_cast<PUCHAR>(output.data()),
            static_cast<ULONG>(output.size()),
            0U);
        if (!bcrypt_succeeded(status)) {
            output.fill(std::byte{0U});
            return proposal_error(PairGenerationProposalErrorCode::operation_failed);
        }
        return {};
    } catch (const std::bad_alloc&) {
        output.fill(std::byte{0U});
        return proposal_error(
            PairGenerationProposalErrorCode::allocation_failed);
    } catch (...) {
        output.fill(std::byte{0U});
        return proposal_error(PairGenerationProposalErrorCode::operation_failed);
    }
#else
    static_cast<void>(input);
    output.fill(std::byte{0U});
    return proposal_error(PairGenerationProposalErrorCode::crypto_unavailable);
#endif
}

[[nodiscard]] PeerHandshakeError invalid_final_generation_error() noexcept {
    return {
        .code = PeerHandshakeErrorCode::invalid_session_generation,
        .native_domain = PeerHandshakeNativeStatusDomain::none,
        .native_status = 0U,
        .field_tag = 9U,
        .operation = "validate_proposal_generation",
    };
}

[[nodiscard]] PeerHandshakeError final_transition_error(
    const PeerHandshakeErrorCode code,
    const std::string_view operation) noexcept {
    return {
        .code = code,
        .native_domain = PeerHandshakeNativeStatusDomain::none,
        .native_status = 0U,
        .field_tag = kNoFieldTag,
        .operation = operation,
    };
}

}  // namespace

const char* pair_generation_proposal_error_code_name(
    const PairGenerationProposalErrorCode code) noexcept {
    switch (code) {
        case PairGenerationProposalErrorCode::none: return "none";
        case PairGenerationProposalErrorCode::allocation_failed: return "allocation_failed";
        case PairGenerationProposalErrorCode::proposal_too_large: return "proposal_too_large";
        case PairGenerationProposalErrorCode::truncated_tlv: return "truncated_tlv";
        case PairGenerationProposalErrorCode::unknown_tag: return "unknown_tag";
        case PairGenerationProposalErrorCode::duplicate_tag: return "duplicate_tag";
        case PairGenerationProposalErrorCode::out_of_order_tag: return "out_of_order_tag";
        case PairGenerationProposalErrorCode::missing_field: return "missing_field";
        case PairGenerationProposalErrorCode::trailing_data: return "trailing_data";
        case PairGenerationProposalErrorCode::noncanonical_encoding: return "noncanonical_encoding";
        case PairGenerationProposalErrorCode::invalid_field_length: return "invalid_field_length";
        case PairGenerationProposalErrorCode::invalid_domain: return "invalid_domain";
        case PairGenerationProposalErrorCode::unsupported_version: return "unsupported_version";
        case PairGenerationProposalErrorCode::invalid_identity_binding: return "invalid_identity_binding";
        case PairGenerationProposalErrorCode::invalid_ephemeral_public_key: return "invalid_ephemeral_public_key";
        case PairGenerationProposalErrorCode::invalid_nonce: return "invalid_nonce";
        case PairGenerationProposalErrorCode::invalid_connection_id: return "invalid_connection_id";
        case PairGenerationProposalErrorCode::invalid_transport_kind: return "invalid_transport_kind";
        case PairGenerationProposalErrorCode::invalid_endpoint: return "invalid_endpoint";
        case PairGenerationProposalErrorCode::invalid_pair_id: return "invalid_pair_id";
        case PairGenerationProposalErrorCode::invalid_runtime_version: return "invalid_runtime_version";
        case PairGenerationProposalErrorCode::invalid_generation: return "invalid_generation";
        case PairGenerationProposalErrorCode::crypto_unavailable: return "crypto_unavailable";
        case PairGenerationProposalErrorCode::operation_failed: return "operation_failed";
    }
    return "unknown";
}

VerifiedPairGenerationProposalV1::VerifiedPairGenerationProposalV1(
    PairGenerationProposalFields fields,
    std::vector<std::byte> canonical_bytes,
    const PeerHandshakeSha256 proposal_sha256)
    : fields_(std::move(fields)),
      canonical_bytes_(std::move(canonical_bytes)),
      proposal_sha256_(proposal_sha256) {}

const PairGenerationProposalFields&
VerifiedPairGenerationProposalV1::fields() const noexcept {
    return fields_;
}

std::span<const std::byte>
VerifiedPairGenerationProposalV1::canonical_bytes() const noexcept {
    return canonical_bytes_;
}

const PeerHandshakeSha256&
VerifiedPairGenerationProposalV1::proposal_sha256() const noexcept {
    return proposal_sha256_;
}

PairGenerationProposalResult build_pair_generation_proposal_v1(
    const PairGenerationProposalFields& fields) noexcept {
    try {
        PairGenerationProposalError error = validate_fields(fields);
        if (error.has_error()) return {std::nullopt, error};
        std::vector<std::byte> canonical = encode_fields(fields);
        if (canonical.size() >
            kPairGenerationProposalMaximumCanonicalBytes) {
            return {std::nullopt, proposal_error(
                PairGenerationProposalErrorCode::proposal_too_large)};
        }
        PeerHandshakeSha256 digest{};
        error = sha256_bytes(canonical, digest);
        if (error.has_error()) return {std::nullopt, error};
        return {
            VerifiedPairGenerationProposalV1{
                fields, std::move(canonical), digest},
            {},
        };
    } catch (const std::bad_alloc&) {
        return {std::nullopt, proposal_error(
            PairGenerationProposalErrorCode::allocation_failed)};
    } catch (...) {
        return {std::nullopt, proposal_error(
            PairGenerationProposalErrorCode::operation_failed)};
    }
}

PairGenerationProposalResult parse_pair_generation_proposal_v1(
    const std::span<const std::byte> canonical_bytes) noexcept {
    if (canonical_bytes.size() >
        kPairGenerationProposalMaximumCanonicalBytes) {
        return {std::nullopt, proposal_error(
            PairGenerationProposalErrorCode::proposal_too_large)};
    }
    try {
        std::array<std::span<const std::byte>,
            kPairGenerationProposalFieldCount> values{};
        std::array<bool, kPairGenerationProposalFieldCount> seen{};
        const auto maximum_lengths = maximum_field_lengths();
        std::size_t offset{};
        for (std::size_t expected_tag{};
             expected_tag < kPairGenerationProposalFieldCount;
             ++expected_tag) {
            const std::size_t remaining = canonical_bytes.size() - offset;
            if (remaining == 0U) {
                return {std::nullopt, proposal_error(
                    PairGenerationProposalErrorCode::missing_field,
                    static_cast<std::uint8_t>(expected_tag))};
            }
            if (remaining < kTlvHeaderBytes) {
                return {std::nullopt, proposal_error(
                    PairGenerationProposalErrorCode::truncated_tlv)};
            }
            const std::uint8_t actual_tag =
                std::to_integer<std::uint8_t>(canonical_bytes[offset]);
            if (actual_tag >= kPairGenerationProposalFieldCount) {
                return {std::nullopt, proposal_error(
                    PairGenerationProposalErrorCode::unknown_tag,
                    actual_tag)};
            }
            if (seen[actual_tag]) {
                return {std::nullopt, proposal_error(
                    PairGenerationProposalErrorCode::duplicate_tag,
                    actual_tag)};
            }
            if (actual_tag != expected_tag) {
                return {std::nullopt, proposal_error(
                    PairGenerationProposalErrorCode::out_of_order_tag,
                    actual_tag)};
            }
            const std::uint32_t encoded_length = load_u32_be(
                canonical_bytes.subspan(offset + 1U, 4U));
            if (encoded_length > maximum_lengths[actual_tag]) {
                return {std::nullopt, proposal_error(
                    PairGenerationProposalErrorCode::invalid_field_length,
                    actual_tag)};
            }
            const std::size_t value_offset = offset + kTlvHeaderBytes;
            if (encoded_length > canonical_bytes.size() - value_offset) {
                return {std::nullopt, proposal_error(
                    PairGenerationProposalErrorCode::truncated_tlv,
                    actual_tag)};
            }
            values[actual_tag] = canonical_bytes.subspan(
                value_offset, encoded_length);
            seen[actual_tag] = true;
            offset = value_offset + encoded_length;
        }
        if (offset != canonical_bytes.size()) {
            return {std::nullopt, proposal_error(
                PairGenerationProposalErrorCode::trailing_data)};
        }
        PairGenerationProposalError error = validate_lengths(values);
        if (error.has_error()) return {std::nullopt, error};
        if (!std::equal(
                values[0].begin(),
                values[0].end(),
                reinterpret_cast<const std::byte*>(
                    kPairGenerationProposalDomain.data()),
                reinterpret_cast<const std::byte*>(
                    kPairGenerationProposalDomain.data() +
                    kPairGenerationProposalDomain.size()))) {
            return {std::nullopt, proposal_error(
                PairGenerationProposalErrorCode::invalid_domain,
                tag_value(ProposalTag::domain))};
        }
        if (load_u32_be(values[1]) != kPairGenerationProposalVersion) {
            return {std::nullopt, proposal_error(
                PairGenerationProposalErrorCode::unsupported_version,
                tag_value(ProposalTag::protocol_version))};
        }

        PairGenerationProposalFields fields;
        copy_exact(values[2], fields.host_identity_spki_sha256);
        copy_exact(values[3], fields.android_identity_spki_sha256);
        copy_exact(values[4], fields.host_ephemeral_public_key);
        copy_exact(values[5], fields.android_ephemeral_public_key);
        copy_exact(values[6], fields.host_nonce);
        copy_exact(values[7], fields.android_nonce);
        fields.connection_id = load_u64_be(values[8]);
        fields.transport_kind = static_cast<PeerHandshakeTransportKind>(
            std::to_integer<std::uint8_t>(values[9].front()));
        copy_exact(values[10], fields.host_ipv4);
        copy_exact(values[11], fields.android_ipv4);
        fields.video_port = load_u16_be(values[12]);
        fields.control_port = load_u16_be(values[13]);
        fields.pair_id.assign(
            reinterpret_cast<const char*>(values[14].data()),
            values[14].size());
        fields.host_runtime_version.assign(
            reinterpret_cast<const char*>(values[15].data()),
            values[15].size());
        fields.android_runtime_version.assign(
            reinterpret_cast<const char*>(values[16].data()),
            values[16].size());

        PairGenerationProposalResult rebuilt =
            build_pair_generation_proposal_v1(fields);
        if (!rebuilt.succeeded()) return rebuilt;
        if (!std::equal(
                rebuilt.proposal->canonical_bytes().begin(),
                rebuilt.proposal->canonical_bytes().end(),
                canonical_bytes.begin(),
                canonical_bytes.end())) {
            return {std::nullopt, proposal_error(
                PairGenerationProposalErrorCode::noncanonical_encoding)};
        }
        return rebuilt;
    } catch (const std::bad_alloc&) {
        return {std::nullopt, proposal_error(
            PairGenerationProposalErrorCode::allocation_failed)};
    } catch (...) {
        return {std::nullopt, proposal_error(
            PairGenerationProposalErrorCode::operation_failed)};
    }
}

PeerHandshakeTranscriptResult
build_final_peer_handshake_transcript_from_proposal_v1(
    const VerifiedPairGenerationProposalV1& proposal,
    const std::int64_t generation) noexcept {
    if (generation <= 0) {
        return {std::nullopt, invalid_final_generation_error()};
    }
    try {
        return build_canonical_peer_handshake_transcript_v1(
            final_fields_from_proposal(
                proposal.fields(), static_cast<std::uint64_t>(generation)),
            PeerHandshakePairIdRequirement::require_bound_pair);
    } catch (const std::bad_alloc&) {
        return {std::nullopt, final_transition_error(
            PeerHandshakeErrorCode::allocation_failed,
            "copy_proposal_fields_to_final_transcript")};
    } catch (...) {
        return {std::nullopt, final_transition_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            "copy_proposal_fields_to_final_transcript")};
    }
}

}  // namespace vfdual
