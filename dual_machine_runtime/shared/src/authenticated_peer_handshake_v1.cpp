#include "vfdual/authenticated_peer_handshake_v1.hpp"

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

constexpr std::uint8_t kNoFieldTag = 0xffU;
constexpr std::size_t kTlvHeaderBytes = 5U;
constexpr std::size_t kMaximumHkdfInfoBytes = 96U;
constexpr std::string_view kFinishedProofDomain{
    "VFDUAL/PEER-HS/V1/finished-proof"};
constexpr std::string_view kChannelBindingDomain{
    "visionforge-peer-channel-binding-v1"};
constexpr std::string_view kControlHostToAndroidLabel{
    "VFDUAL/PEER-HS/V1/control/host-to-android"};
constexpr std::string_view kControlAndroidToHostLabel{
    "VFDUAL/PEER-HS/V1/control/android-to-host"};
constexpr std::string_view kPresenceHostToAndroidLabel{
    "VFDUAL/PEER-HS/V1/presence/host-to-android"};
constexpr std::string_view kVideoHostToAndroidLabel{
    "VFDUAL/PEER-HS/V1/video/host-to-android"};
constexpr std::string_view kIdrAndroidToHostLabel{
    "VFDUAL/PEER-HS/V1/idr/android-to-host"};
constexpr std::string_view kMouseHostToAndroidLabel{
    "VFDUAL/PEER-HS/V1/mouse/host-to-android"};
constexpr std::string_view kFinishedHostLabel{
    "VFDUAL/PEER-HS/V1/finished/host"};
constexpr std::string_view kFinishedAndroidLabel{
    "VFDUAL/PEER-HS/V1/finished/android"};
constexpr std::string_view kChannelBindingExporterLabel{
    "VFDUAL/PEER-HS/V1/channel-binding-exporter"};

enum class TranscriptTag : std::uint8_t {
    domain = 0U,
    protocol_version = 1U,
    host_identity_spki_sha256 = 2U,
    android_identity_spki_sha256 = 3U,
    host_ephemeral_public_key = 4U,
    android_ephemeral_public_key = 5U,
    host_nonce = 6U,
    android_nonce = 7U,
    connection_id = 8U,
    session_generation = 9U,
    transport_kind = 10U,
    host_ipv4 = 11U,
    android_ipv4 = 12U,
    video_port = 13U,
    control_port = 14U,
    pair_id = 15U,
    host_runtime_version = 16U,
    android_runtime_version = 17U,
};

[[nodiscard]] constexpr std::uint8_t tag_value(
    const TranscriptTag tag) noexcept {
    return static_cast<std::uint8_t>(tag);
}

void erase_bytes(const std::span<std::byte> bytes) noexcept {
    if (bytes.empty()) return;
#if defined(_WIN32)
    SecureZeroMemory(bytes.data(), bytes.size());
#else
    volatile auto* destination =
        reinterpret_cast<volatile unsigned char*>(bytes.data());
    for (std::size_t index{}; index < bytes.size(); ++index) {
        destination[index] = 0U;
    }
#endif
}

template <std::size_t Size>
class SecureFixedBytes final {
public:
    SecureFixedBytes() = default;
    ~SecureFixedBytes() {
        erase_bytes(bytes_);
    }
    SecureFixedBytes(const SecureFixedBytes&) = delete;
    SecureFixedBytes& operator=(const SecureFixedBytes&) = delete;

    [[nodiscard]] std::array<std::byte, Size>& bytes() noexcept {
        return bytes_;
    }
    [[nodiscard]] const std::array<std::byte, Size>& bytes() const noexcept {
        return bytes_;
    }

private:
    std::array<std::byte, Size> bytes_{};
};

class SecureVector final {
public:
    SecureVector() = default;
    explicit SecureVector(const std::size_t size) : bytes_(size) {}
    ~SecureVector() {
        erase_bytes(bytes_);
    }
    SecureVector(const SecureVector&) = delete;
    SecureVector& operator=(const SecureVector&) = delete;

    [[nodiscard]] std::vector<std::byte>& bytes() noexcept {
        return bytes_;
    }
    [[nodiscard]] const std::vector<std::byte>& bytes() const noexcept {
        return bytes_;
    }

private:
    std::vector<std::byte> bytes_;
};

[[nodiscard]] PeerHandshakeError protocol_error(
    const PeerHandshakeErrorCode code,
    const std::string_view operation,
    const std::uint8_t field_tag = kNoFieldTag) noexcept {
    return {
        .code = code,
        .native_domain = PeerHandshakeNativeStatusDomain::none,
        .native_status = 0U,
        .field_tag = field_tag,
        .operation = operation,
    };
}

#if defined(_WIN32)
[[nodiscard]] PeerHandshakeError bcrypt_error(
    const PeerHandshakeErrorCode code,
    const NTSTATUS status,
    const std::string_view operation,
    const std::uint8_t field_tag = kNoFieldTag) noexcept {
    return {
        .code = code,
        .native_domain = PeerHandshakeNativeStatusDomain::bcrypt_ntstatus,
        .native_status = static_cast<std::uint32_t>(status),
        .field_tag = field_tag,
        .operation = operation,
    };
}

[[nodiscard]] bool bcrypt_succeeded(const NTSTATUS status) noexcept {
    return status >= 0;
}

[[nodiscard]] PUCHAR writable_bytes(
    const std::span<std::byte> bytes) noexcept {
    return reinterpret_cast<PUCHAR>(bytes.data());
}

[[nodiscard]] PUCHAR readonly_bytes(
    const std::span<const std::byte> bytes) noexcept {
    return const_cast<PUCHAR>(
        reinterpret_cast<const UCHAR*>(bytes.data()));
}

class UniqueBcryptAlgorithm final {
public:
    UniqueBcryptAlgorithm() = default;
    ~UniqueBcryptAlgorithm() {
        if (handle != nullptr) {
            static_cast<void>(BCryptCloseAlgorithmProvider(handle, 0U));
        }
    }
    UniqueBcryptAlgorithm(const UniqueBcryptAlgorithm&) = delete;
    UniqueBcryptAlgorithm& operator=(const UniqueBcryptAlgorithm&) = delete;

    BCRYPT_ALG_HANDLE handle{};
};

class UniqueBcryptHash final {
public:
    UniqueBcryptHash() = default;
    ~UniqueBcryptHash() {
        if (handle != nullptr) static_cast<void>(BCryptDestroyHash(handle));
    }
    UniqueBcryptHash(const UniqueBcryptHash&) = delete;
    UniqueBcryptHash& operator=(const UniqueBcryptHash&) = delete;

    BCRYPT_HASH_HANDLE handle{};
};

class UniqueBcryptKey final {
public:
    UniqueBcryptKey() = default;
    ~UniqueBcryptKey() {
        if (handle != nullptr) static_cast<void>(BCryptDestroyKey(handle));
    }
    UniqueBcryptKey(const UniqueBcryptKey&) = delete;
    UniqueBcryptKey& operator=(const UniqueBcryptKey&) = delete;

    BCRYPT_KEY_HANDLE handle{};
};

class UniqueBcryptSecret final {
public:
    UniqueBcryptSecret() = default;
    ~UniqueBcryptSecret() {
        if (handle != nullptr) {
            static_cast<void>(BCryptDestroySecret(handle));
        }
    }
    UniqueBcryptSecret(const UniqueBcryptSecret&) = delete;
    UniqueBcryptSecret& operator=(const UniqueBcryptSecret&) = delete;

    BCRYPT_SECRET_HANDLE handle{};
};
#endif

[[nodiscard]] PeerHandshakeError sha256_bytes(
    const std::span<const std::byte> input,
    PeerHandshakeSha256& output,
    const std::string_view operation) noexcept {
#if defined(_WIN32)
    if (input.size() > std::numeric_limits<ULONG>::max()) {
        return protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed, operation);
    }
    try {
        UniqueBcryptAlgorithm algorithm;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &algorithm.handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0U);
        if (!bcrypt_succeeded(status)) {
            return bcrypt_error(
                PeerHandshakeErrorCode::crypto_provider_failed,
                status,
                operation);
        }

        ULONG object_bytes{};
        ULONG hash_bytes{};
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
            return bcrypt_error(
                PeerHandshakeErrorCode::crypto_provider_failed,
                status,
                operation);
        }
        status = BCryptGetProperty(
            algorithm.handle,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_bytes),
            sizeof(hash_bytes),
            &copied,
            0U);
        if (!bcrypt_succeeded(status) || copied != sizeof(hash_bytes) ||
            hash_bytes != output.size()) {
            return bcrypt_error(
                PeerHandshakeErrorCode::crypto_provider_failed,
                status,
                operation);
        }

        SecureVector object(object_bytes);
        UniqueBcryptHash hash;
        status = BCryptCreateHash(
            algorithm.handle,
            &hash.handle,
            writable_bytes(object.bytes()),
            object_bytes,
            nullptr,
            0U,
            0U);
        if (!bcrypt_succeeded(status)) {
            return bcrypt_error(
                PeerHandshakeErrorCode::crypto_operation_failed,
                status,
                operation);
        }
        status = BCryptHashData(
            hash.handle,
            readonly_bytes(input),
            static_cast<ULONG>(input.size()),
            0U);
        if (!bcrypt_succeeded(status)) {
            return bcrypt_error(
                PeerHandshakeErrorCode::crypto_operation_failed,
                status,
                operation);
        }
        status = BCryptFinishHash(
            hash.handle,
            writable_bytes(output),
            static_cast<ULONG>(output.size()),
            0U);
        if (!bcrypt_succeeded(status)) {
            erase_bytes(output);
            return bcrypt_error(
                PeerHandshakeErrorCode::crypto_operation_failed,
                status,
                operation);
        }
        return {};
    } catch (const std::bad_alloc&) {
        erase_bytes(output);
        return protocol_error(PeerHandshakeErrorCode::allocation_failed, operation);
    } catch (...) {
        erase_bytes(output);
        return protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed, operation);
    }
#else
    static_cast<void>(input);
    erase_bytes(output);
    return protocol_error(
        PeerHandshakeErrorCode::platform_crypto_unavailable, operation);
#endif
}

[[nodiscard]] PeerHandshakeError hmac_sha256_bytes(
    const std::span<const std::byte> key,
    const std::span<const std::byte> input,
    PeerHandshakeSha256& output,
    const std::string_view operation) noexcept {
#if defined(_WIN32)
    if (key.size() > std::numeric_limits<ULONG>::max() ||
        input.size() > std::numeric_limits<ULONG>::max()) {
        return protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed, operation);
    }
    try {
        UniqueBcryptAlgorithm algorithm;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &algorithm.handle,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (!bcrypt_succeeded(status)) {
            return bcrypt_error(
                PeerHandshakeErrorCode::crypto_provider_failed,
                status,
                operation);
        }

        ULONG object_bytes{};
        ULONG hash_bytes{};
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
            return bcrypt_error(
                PeerHandshakeErrorCode::crypto_provider_failed,
                status,
                operation);
        }
        status = BCryptGetProperty(
            algorithm.handle,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_bytes),
            sizeof(hash_bytes),
            &copied,
            0U);
        if (!bcrypt_succeeded(status) || copied != sizeof(hash_bytes) ||
            hash_bytes != output.size()) {
            return bcrypt_error(
                PeerHandshakeErrorCode::crypto_provider_failed,
                status,
                operation);
        }

        SecureVector object(object_bytes);
        UniqueBcryptHash hash;
        status = BCryptCreateHash(
            algorithm.handle,
            &hash.handle,
            writable_bytes(object.bytes()),
            object_bytes,
            readonly_bytes(key),
            static_cast<ULONG>(key.size()),
            0U);
        if (!bcrypt_succeeded(status)) {
            return bcrypt_error(
                PeerHandshakeErrorCode::crypto_operation_failed,
                status,
                operation);
        }
        status = BCryptHashData(
            hash.handle,
            readonly_bytes(input),
            static_cast<ULONG>(input.size()),
            0U);
        if (!bcrypt_succeeded(status)) {
            return bcrypt_error(
                PeerHandshakeErrorCode::crypto_operation_failed,
                status,
                operation);
        }
        status = BCryptFinishHash(
            hash.handle,
            writable_bytes(output),
            static_cast<ULONG>(output.size()),
            0U);
        if (!bcrypt_succeeded(status)) {
            erase_bytes(output);
            return bcrypt_error(
                PeerHandshakeErrorCode::crypto_operation_failed,
                status,
                operation);
        }
        return {};
    } catch (const std::bad_alloc&) {
        erase_bytes(output);
        return protocol_error(PeerHandshakeErrorCode::allocation_failed, operation);
    } catch (...) {
        erase_bytes(output);
        return protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed, operation);
    }
#else
    static_cast<void>(key);
    static_cast<void>(input);
    erase_bytes(output);
    return protocol_error(
        PeerHandshakeErrorCode::platform_crypto_unavailable, operation);
#endif
}

[[nodiscard, maybe_unused]] PeerHandshakeError hkdf_expand_sha256(
    const std::span<const std::byte, kPeerHandshakeSha256Bytes> prk,
    const std::string_view ascii_info,
    const std::span<std::byte> output) noexcept {
    if (output.size() > kHkdfSha256MaximumOutputBytes) {
        return protocol_error(
            PeerHandshakeErrorCode::hkdf_output_too_large,
            "validate_hkdf_output_length");
    }
    if (ascii_info.empty() || ascii_info.size() > kMaximumHkdfInfoBytes) {
        return protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            "validate_hkdf_info");
    }
    if (output.empty()) return {};

    SecureFixedBytes<kPeerHandshakeSha256Bytes> previous;
    SecureFixedBytes<kPeerHandshakeSha256Bytes> next;
    SecureFixedBytes<
        kPeerHandshakeSha256Bytes + kMaximumHkdfInfoBytes + 1U> message;
    std::size_t previous_bytes{};
    std::size_t written{};
    std::uint16_t block_index{1U};

    while (written < output.size()) {
        auto& message_bytes = message.bytes();
        std::copy_n(
            previous.bytes().begin(), previous_bytes, message_bytes.begin());
        std::transform(
            ascii_info.begin(),
            ascii_info.end(),
            message_bytes.begin() + static_cast<std::ptrdiff_t>(previous_bytes),
            [](const char character) {
                return std::byte{static_cast<std::uint8_t>(character)};
            });
        const std::size_t counter_offset = previous_bytes + ascii_info.size();
        message_bytes[counter_offset] =
            std::byte{static_cast<std::uint8_t>(block_index)};

        PeerHandshakeError error = hmac_sha256_bytes(
            prk,
            std::span<const std::byte>{
                message_bytes.data(), counter_offset + 1U},
            next.bytes(),
            "hkdf_expand_hmac_sha256");
        if (error.has_error()) return error;

        const std::size_t copy_bytes = std::min(
            next.bytes().size(), output.size() - written);
        std::copy_n(
            next.bytes().begin(),
            copy_bytes,
            output.begin() + static_cast<std::ptrdiff_t>(written));
        std::copy(next.bytes().begin(), next.bytes().end(), previous.bytes().begin());
        previous_bytes = previous.bytes().size();
        written += copy_bytes;
        ++block_index;
    }
    return {};
}

[[nodiscard, maybe_unused]] PeerHandshakeError derive_prk(
    const std::span<const std::byte, kPeerHandshakeSha256Bytes>
        transcript_sha256,
    const std::span<const std::byte, 32U> shared_secret_be,
    PeerHandshakeSha256& prk) noexcept {
    return hmac_sha256_bytes(
        transcript_sha256,
        shared_secret_be,
        prk,
        "hkdf_extract_hmac_sha256");
}

[[nodiscard]] bool contains_nonzero(
    const std::span<const std::byte> bytes) noexcept {
    return std::any_of(bytes.begin(), bytes.end(), [](const std::byte value) {
        return value != std::byte{0U};
    });
}

[[nodiscard]] bool pair_id_character_valid(const char character) noexcept {
    return (character >= 'A' && character <= 'Z') ||
        (character >= 'a' && character <= 'z') ||
        (character >= '0' && character <= '9') ||
        character == '.' || character == '_' || character == ':' ||
        character == '-';
}

[[nodiscard]] bool stable_semver_valid(const std::string_view value) noexcept {
    if (value.empty() ||
        value.size() > kPeerHandshakeMaximumRuntimeVersionBytes) {
        return false;
    }
    std::size_t component_start{};
    std::size_t components{};
    for (std::size_t index{}; index <= value.size(); ++index) {
        if (index != value.size() && value[index] != '.') {
            if (value[index] < '0' || value[index] > '9') return false;
            continue;
        }
        const std::size_t component_size = index - component_start;
        if (component_size == 0U) return false;
        if (component_size > 1U && value[component_start] == '0') return false;
        ++components;
        component_start = index + 1U;
    }
    return components == 3U;
}

[[nodiscard]] bool pair_requirement_valid(
    const PeerHandshakePairIdRequirement requirement) noexcept {
    switch (requirement) {
        case PeerHandshakePairIdRequirement::allow_empty_before_activation:
        case PeerHandshakePairIdRequirement::require_bound_pair:
            return true;
    }
    return false;
}

[[nodiscard]] PeerHandshakeError validate_sec1_p256_public_key(
    const std::span<const std::byte, kPeerHandshakeP256PublicKeyBytes> key,
    const std::uint8_t field_tag) noexcept {
    if (key.front() != std::byte{0x04U}) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_ephemeral_public_key,
            "validate_sec1_uncompressed_prefix",
            field_tag);
    }
#if defined(_WIN32)
    UniqueBcryptAlgorithm algorithm;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm.handle, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0U);
    if (!bcrypt_succeeded(status)) {
        return bcrypt_error(
            PeerHandshakeErrorCode::crypto_provider_failed,
            status,
            "open_p256_point_validator",
            field_tag);
    }

    std::array<std::byte,
        sizeof(BCRYPT_ECCKEY_BLOB) + 2U * 32U> public_blob{};
    const BCRYPT_ECCKEY_BLOB header{
        .dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC,
        .cbKey = 32U,
    };
    std::memcpy(public_blob.data(), &header, sizeof(header));
    std::copy(
        key.begin() + 1,
        key.end(),
        public_blob.begin() + static_cast<std::ptrdiff_t>(sizeof(header)));

    UniqueBcryptKey imported;
    status = BCryptImportKeyPair(
        algorithm.handle,
        nullptr,
        BCRYPT_ECCPUBLIC_BLOB,
        &imported.handle,
        writable_bytes(public_blob),
        static_cast<ULONG>(public_blob.size()),
        0U);
    if (!bcrypt_succeeded(status)) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_ephemeral_public_key,
            "validate_p256_curve_point",
            field_tag);
    }
    return {};
#else
    static_cast<void>(field_tag);
    return protocol_error(
        PeerHandshakeErrorCode::platform_crypto_unavailable,
        "validate_p256_curve_point",
        field_tag);
#endif
}

[[nodiscard]] PeerHandshakeError validate_transcript_fields(
    const PeerHandshakeTranscriptFields& fields,
    const PeerHandshakePairIdRequirement pair_id_requirement) noexcept {
    if (!pair_requirement_valid(pair_id_requirement)) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_pair_id_requirement,
            "validate_pair_id_requirement");
    }
    if (fields.domain != kAuthenticatedPeerHandshakeDomain) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_domain,
            "validate_handshake_domain",
            tag_value(TranscriptTag::domain));
    }
    if (fields.protocol_version != kAuthenticatedPeerHandshakeVersion) {
        return protocol_error(
            PeerHandshakeErrorCode::unsupported_protocol_version,
            "validate_protocol_version",
            tag_value(TranscriptTag::protocol_version));
    }
    if (!contains_nonzero(fields.host_identity_spki_sha256)) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_identity_binding,
            "reject_zero_host_identity_fingerprint",
            tag_value(TranscriptTag::host_identity_spki_sha256));
    }
    if (!contains_nonzero(fields.android_identity_spki_sha256)) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_identity_binding,
            "reject_zero_android_identity_fingerprint",
            tag_value(TranscriptTag::android_identity_spki_sha256));
    }
    if (fields.host_identity_spki_sha256 ==
        fields.android_identity_spki_sha256) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_identity_binding,
            "reject_reflected_identity_fingerprint",
            tag_value(TranscriptTag::android_identity_spki_sha256));
    }

    PeerHandshakeError error = validate_sec1_p256_public_key(
        fields.host_ephemeral_public_key,
        tag_value(TranscriptTag::host_ephemeral_public_key));
    if (error.has_error()) return error;
    error = validate_sec1_p256_public_key(
        fields.android_ephemeral_public_key,
        tag_value(TranscriptTag::android_ephemeral_public_key));
    if (error.has_error()) return error;
    if (fields.host_ephemeral_public_key ==
        fields.android_ephemeral_public_key) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_ephemeral_public_key,
            "reject_reflected_ephemeral_public_key",
            tag_value(TranscriptTag::android_ephemeral_public_key));
    }

    if (!contains_nonzero(fields.host_nonce)) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_nonce,
            "validate_host_nonce",
            tag_value(TranscriptTag::host_nonce));
    }
    if (!contains_nonzero(fields.android_nonce)) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_nonce,
            "validate_android_nonce",
            tag_value(TranscriptTag::android_nonce));
    }
    if (fields.host_nonce == fields.android_nonce) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_nonce,
            "reject_reflected_nonce",
            tag_value(TranscriptTag::android_nonce));
    }
    if (fields.connection_id == 0U) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_connection_id,
            "validate_connection_id",
            tag_value(TranscriptTag::connection_id));
    }
    if (fields.session_generation == 0U) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_session_generation,
            "validate_session_generation",
            tag_value(TranscriptTag::session_generation));
    }
    switch (fields.transport_kind) {
        case PeerHandshakeTransportKind::cat6:
        case PeerHandshakeTransportKind::wlan:
            break;
        default:
            return protocol_error(
                PeerHandshakeErrorCode::invalid_transport_kind,
                "validate_transport_kind",
                tag_value(TranscriptTag::transport_kind));
    }
    if (fields.video_port == 0U || fields.control_port == 0U ||
        fields.video_port == fields.control_port) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_endpoint,
            "validate_distinct_nonzero_ports",
            tag_value(TranscriptTag::video_port));
    }
    if (fields.pair_id.size() > kPeerHandshakeMaximumPairIdBytes ||
        !std::all_of(
            fields.pair_id.begin(),
            fields.pair_id.end(),
            pair_id_character_valid) ||
        (pair_id_requirement ==
                PeerHandshakePairIdRequirement::require_bound_pair &&
            fields.pair_id.empty())) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_pair_id,
            "validate_pair_id",
            tag_value(TranscriptTag::pair_id));
    }
    if (!stable_semver_valid(fields.host_runtime_version)) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_runtime_version,
            "validate_host_runtime_version",
            tag_value(TranscriptTag::host_runtime_version));
    }
    if (!stable_semver_valid(fields.android_runtime_version)) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_runtime_version,
            "validate_android_runtime_version",
            tag_value(TranscriptTag::android_runtime_version));
    }
    return {};
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
    const TranscriptTag tag,
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

[[nodiscard]] std::vector<std::byte> encode_transcript_fields(
    const PeerHandshakeTranscriptFields& fields) {
    std::vector<std::byte> output;
    output.reserve(kPeerHandshakeMaximumCanonicalBytes);
    append_tlv(output, TranscriptTag::domain, string_bytes(fields.domain));

    std::vector<std::byte> scalar;
    scalar.reserve(8U);
    append_u32_be(scalar, fields.protocol_version);
    append_tlv(output, TranscriptTag::protocol_version, scalar);
    append_tlv(
        output,
        TranscriptTag::host_identity_spki_sha256,
        fields.host_identity_spki_sha256);
    append_tlv(
        output,
        TranscriptTag::android_identity_spki_sha256,
        fields.android_identity_spki_sha256);
    append_tlv(
        output,
        TranscriptTag::host_ephemeral_public_key,
        fields.host_ephemeral_public_key);
    append_tlv(
        output,
        TranscriptTag::android_ephemeral_public_key,
        fields.android_ephemeral_public_key);
    append_tlv(output, TranscriptTag::host_nonce, fields.host_nonce);
    append_tlv(output, TranscriptTag::android_nonce, fields.android_nonce);

    scalar.clear();
    append_u64_be(scalar, fields.connection_id);
    append_tlv(output, TranscriptTag::connection_id, scalar);
    scalar.clear();
    append_u64_be(scalar, fields.session_generation);
    append_tlv(output, TranscriptTag::session_generation, scalar);
    const std::array<std::byte, 1U> transport{
        std::byte{static_cast<std::uint8_t>(fields.transport_kind)}};
    append_tlv(output, TranscriptTag::transport_kind, transport);
    append_tlv(output, TranscriptTag::host_ipv4, fields.host_ipv4);
    append_tlv(output, TranscriptTag::android_ipv4, fields.android_ipv4);
    scalar.clear();
    append_u16_be(scalar, fields.video_port);
    append_tlv(output, TranscriptTag::video_port, scalar);
    scalar.clear();
    append_u16_be(scalar, fields.control_port);
    append_tlv(output, TranscriptTag::control_port, scalar);
    append_tlv(output, TranscriptTag::pair_id, string_bytes(fields.pair_id));
    append_tlv(
        output,
        TranscriptTag::host_runtime_version,
        string_bytes(fields.host_runtime_version));
    append_tlv(
        output,
        TranscriptTag::android_runtime_version,
        string_bytes(fields.android_runtime_version));
    return output;
}

[[nodiscard]] std::uint16_t load_u16_be(
    const std::span<const std::byte> input) noexcept {
    return static_cast<std::uint16_t>(
        (std::to_integer<std::uint16_t>(input[0]) << 8U) |
        std::to_integer<std::uint16_t>(input[1]));
}

[[nodiscard]] std::uint32_t load_u32_be(
    const std::span<const std::byte> input) noexcept {
    std::uint32_t value{};
    for (const std::byte byte : input) {
        value = (value << 8U) | std::to_integer<std::uint8_t>(byte);
    }
    return value;
}

[[nodiscard]] std::uint64_t load_u64_be(
    const std::span<const std::byte> input) noexcept {
    std::uint64_t value{};
    for (const std::byte byte : input) {
        value = (value << 8U) | std::to_integer<std::uint8_t>(byte);
    }
    return value;
}

[[nodiscard]] PeerHandshakeError validate_tlv_lengths(
    const std::array<std::span<const std::byte>,
        kPeerHandshakeFieldCount>& values) noexcept {
    constexpr std::array<std::size_t, kPeerHandshakeFieldCount> lengths{
        kAuthenticatedPeerHandshakeDomain.size(),
        4U,
        32U,
        32U,
        65U,
        65U,
        32U,
        32U,
        8U,
        8U,
        1U,
        4U,
        4U,
        2U,
        2U,
        std::numeric_limits<std::size_t>::max(),
        std::numeric_limits<std::size_t>::max(),
        std::numeric_limits<std::size_t>::max(),
    };
    for (std::size_t index{}; index < lengths.size(); ++index) {
        if (lengths[index] != std::numeric_limits<std::size_t>::max() &&
            values[index].size() != lengths[index]) {
            return protocol_error(
                PeerHandshakeErrorCode::invalid_field_length,
                "validate_fixed_tlv_length",
                static_cast<std::uint8_t>(index));
        }
    }
    if (values[tag_value(TranscriptTag::pair_id)].size() >
            kPeerHandshakeMaximumPairIdBytes ||
        values[tag_value(TranscriptTag::host_runtime_version)].empty() ||
        values[tag_value(TranscriptTag::host_runtime_version)].size() >
            kPeerHandshakeMaximumRuntimeVersionBytes ||
        values[tag_value(TranscriptTag::android_runtime_version)].empty() ||
        values[tag_value(TranscriptTag::android_runtime_version)].size() >
            kPeerHandshakeMaximumRuntimeVersionBytes) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_field_length,
            "validate_variable_tlv_length");
    }
    return {};
}

template <std::size_t Size>
void copy_exact(
    const std::span<const std::byte> source,
    std::array<std::byte, Size>& destination) noexcept {
    std::copy(source.begin(), source.end(), destination.begin());
}

[[nodiscard]] bool constant_time_equal(
    const std::span<const std::byte> left,
    const std::span<const std::byte> right) noexcept {
    if (left.size() != right.size()) return false;
    std::uint8_t difference{};
    for (std::size_t index{}; index < left.size(); ++index) {
        difference |= static_cast<std::uint8_t>(
            std::to_integer<std::uint8_t>(left[index]) ^
            std::to_integer<std::uint8_t>(right[index]));
    }
    return difference == 0U;
}

[[nodiscard]] PeerHandshakeDataPlaneKeyView data_plane_view(
    const std::array<
        std::byte, kPeerHandshakeDataPlaneMaterialBytes>& material) noexcept {
    const std::span<const std::byte,
        kPeerHandshakeDataPlaneMaterialBytes> all{material};
    return {
        .aes_256_key = all.first<kPeerHandshakeAes256KeyBytes>(),
        .nonce_prefix = all.last<kPeerHandshakeNoncePrefixBytes>(),
    };
}

}  // namespace

struct PlatformP256EphemeralKeyAgreementV1::Impl final {
#if defined(_WIN32)
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_KEY_HANDLE key{};

    ~Impl() {
        if (key != nullptr) static_cast<void>(BCryptDestroyKey(key));
        if (algorithm != nullptr) {
            static_cast<void>(BCryptCloseAlgorithmProvider(algorithm, 0U));
        }
    }
#else
    ~Impl() = default;
#endif
    Impl() = default;
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
};

const char* peer_handshake_error_code_name(
    const PeerHandshakeErrorCode code) noexcept {
    switch (code) {
        case PeerHandshakeErrorCode::none: return "none";
        case PeerHandshakeErrorCode::allocation_failed: return "allocation_failed";
        case PeerHandshakeErrorCode::transcript_too_large: return "transcript_too_large";
        case PeerHandshakeErrorCode::truncated_tlv: return "truncated_tlv";
        case PeerHandshakeErrorCode::unknown_tag: return "unknown_tag";
        case PeerHandshakeErrorCode::duplicate_tag: return "duplicate_tag";
        case PeerHandshakeErrorCode::out_of_order_tag: return "out_of_order_tag";
        case PeerHandshakeErrorCode::missing_field: return "missing_field";
        case PeerHandshakeErrorCode::invalid_field_length: return "invalid_field_length";
        case PeerHandshakeErrorCode::invalid_domain: return "invalid_domain";
        case PeerHandshakeErrorCode::unsupported_protocol_version: return "unsupported_protocol_version";
        case PeerHandshakeErrorCode::invalid_identity_binding: return "invalid_identity_binding";
        case PeerHandshakeErrorCode::invalid_ephemeral_public_key: return "invalid_ephemeral_public_key";
        case PeerHandshakeErrorCode::invalid_nonce: return "invalid_nonce";
        case PeerHandshakeErrorCode::invalid_connection_id: return "invalid_connection_id";
        case PeerHandshakeErrorCode::invalid_session_generation: return "invalid_session_generation";
        case PeerHandshakeErrorCode::invalid_transport_kind: return "invalid_transport_kind";
        case PeerHandshakeErrorCode::invalid_endpoint: return "invalid_endpoint";
        case PeerHandshakeErrorCode::invalid_pair_id: return "invalid_pair_id";
        case PeerHandshakeErrorCode::invalid_runtime_version: return "invalid_runtime_version";
        case PeerHandshakeErrorCode::invalid_pair_id_requirement: return "invalid_pair_id_requirement";
        case PeerHandshakeErrorCode::invalid_role: return "invalid_role";
        case PeerHandshakeErrorCode::pair_binding_required_for_key_derivation: return "pair_binding_required_for_key_derivation";
        case PeerHandshakeErrorCode::ephemeral_private_key_already_consumed: return "ephemeral_private_key_already_consumed";
        case PeerHandshakeErrorCode::local_ephemeral_key_mismatch: return "local_ephemeral_key_mismatch";
        case PeerHandshakeErrorCode::pending_confirmation_closed: return "pending_confirmation_closed";
        case PeerHandshakeErrorCode::local_finished_not_generated: return "local_finished_not_generated";
        case PeerHandshakeErrorCode::peer_finished_authentication_failed: return "peer_finished_authentication_failed";
        case PeerHandshakeErrorCode::platform_crypto_unavailable: return "platform_crypto_unavailable";
        case PeerHandshakeErrorCode::crypto_provider_failed: return "crypto_provider_failed";
        case PeerHandshakeErrorCode::crypto_operation_failed: return "crypto_operation_failed";
        case PeerHandshakeErrorCode::hkdf_output_too_large: return "hkdf_output_too_large";
    }
    return "unknown";
}

CanonicalPeerHandshakeTranscriptV1::CanonicalPeerHandshakeTranscriptV1(
    PeerHandshakeTranscriptFields fields,
    std::vector<std::byte> canonical_bytes,
    PeerHandshakeSha256 transcript_sha256)
    : fields_(std::move(fields)),
      canonical_bytes_(std::move(canonical_bytes)),
      transcript_sha256_(transcript_sha256) {}

const PeerHandshakeTranscriptFields&
CanonicalPeerHandshakeTranscriptV1::fields() const noexcept {
    return fields_;
}

std::span<const std::byte>
CanonicalPeerHandshakeTranscriptV1::canonical_bytes() const noexcept {
    return canonical_bytes_;
}

const PeerHandshakeSha256&
CanonicalPeerHandshakeTranscriptV1::transcript_sha256() const noexcept {
    return transcript_sha256_;
}

PeerHandshakeTranscriptResult build_canonical_peer_handshake_transcript_v1(
    const PeerHandshakeTranscriptFields& fields,
    const PeerHandshakePairIdRequirement pair_id_requirement) noexcept {
    PeerHandshakeError error =
        validate_transcript_fields(fields, pair_id_requirement);
    if (error.has_error()) return {std::nullopt, error};
    try {
        std::vector<std::byte> canonical = encode_transcript_fields(fields);
        if (canonical.size() > kPeerHandshakeMaximumCanonicalBytes) {
            return {std::nullopt, protocol_error(
                PeerHandshakeErrorCode::transcript_too_large,
                "validate_encoded_transcript_size")};
        }
        PeerHandshakeSha256 digest{};
        error = sha256_bytes(
            canonical, digest, "hash_canonical_peer_handshake_transcript");
        if (error.has_error()) return {std::nullopt, error};
        return {
            CanonicalPeerHandshakeTranscriptV1{
                fields, std::move(canonical), digest},
            {},
        };
    } catch (const std::bad_alloc&) {
        return {std::nullopt, protocol_error(
            PeerHandshakeErrorCode::allocation_failed,
            "encode_canonical_peer_handshake_transcript")};
    } catch (...) {
        return {std::nullopt, protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            "encode_canonical_peer_handshake_transcript")};
    }
}

PeerHandshakeTranscriptResult parse_canonical_peer_handshake_transcript_v1(
    const std::span<const std::byte> canonical_bytes,
    const PeerHandshakePairIdRequirement pair_id_requirement) noexcept {
    if (!pair_requirement_valid(pair_id_requirement)) {
        return {std::nullopt, protocol_error(
            PeerHandshakeErrorCode::invalid_pair_id_requirement,
            "validate_pair_id_requirement")};
    }
    if (canonical_bytes.size() > kPeerHandshakeMaximumCanonicalBytes) {
        return {std::nullopt, protocol_error(
            PeerHandshakeErrorCode::transcript_too_large,
            "validate_received_transcript_size")};
    }
    try {
        std::array<std::span<const std::byte>,
            kPeerHandshakeFieldCount> values{};
        std::array<bool, kPeerHandshakeFieldCount> seen{};
        std::optional<std::uint8_t> previous_tag;
        std::size_t offset{};
        while (offset < canonical_bytes.size()) {
            if (canonical_bytes.size() - offset < kTlvHeaderBytes) {
                return {std::nullopt, protocol_error(
                    PeerHandshakeErrorCode::truncated_tlv,
                    "parse_tlv_header")};
            }
            const std::uint8_t tag =
                std::to_integer<std::uint8_t>(canonical_bytes[offset]);
            if (tag >= kPeerHandshakeFieldCount) {
                return {std::nullopt, protocol_error(
                    PeerHandshakeErrorCode::unknown_tag,
                    "reject_unknown_tlv_tag",
                    tag)};
            }
            if (seen[tag]) {
                return {std::nullopt, protocol_error(
                    PeerHandshakeErrorCode::duplicate_tag,
                    "reject_duplicate_tlv_tag",
                    tag)};
            }
            if (previous_tag.has_value() && tag < *previous_tag) {
                return {std::nullopt, protocol_error(
                    PeerHandshakeErrorCode::out_of_order_tag,
                    "reject_out_of_order_tlv_tag",
                    tag)};
            }
            const std::uint32_t encoded_length = load_u32_be(
                canonical_bytes.subspan(offset + 1U, 4U));
            const std::size_t remaining =
                canonical_bytes.size() - offset - kTlvHeaderBytes;
            if (static_cast<std::uint64_t>(encoded_length) >
                static_cast<std::uint64_t>(remaining)) {
                return {std::nullopt, protocol_error(
                    PeerHandshakeErrorCode::truncated_tlv,
                    "parse_tlv_value",
                    tag)};
            }
            values[tag] = canonical_bytes.subspan(
                offset + kTlvHeaderBytes, encoded_length);
            seen[tag] = true;
            previous_tag = tag;
            offset += kTlvHeaderBytes + encoded_length;
        }
        for (std::size_t tag{}; tag < seen.size(); ++tag) {
            if (!seen[tag]) {
                return {std::nullopt, protocol_error(
                    PeerHandshakeErrorCode::missing_field,
                    "reject_missing_tlv_field",
                    static_cast<std::uint8_t>(tag))};
            }
        }
        PeerHandshakeError error = validate_tlv_lengths(values);
        if (error.has_error()) return {std::nullopt, error};

        PeerHandshakeTranscriptFields fields;
        fields.domain.assign(
            reinterpret_cast<const char*>(values[0].data()), values[0].size());
        fields.protocol_version = load_u32_be(values[1]);
        copy_exact(values[2], fields.host_identity_spki_sha256);
        copy_exact(values[3], fields.android_identity_spki_sha256);
        copy_exact(values[4], fields.host_ephemeral_public_key);
        copy_exact(values[5], fields.android_ephemeral_public_key);
        copy_exact(values[6], fields.host_nonce);
        copy_exact(values[7], fields.android_nonce);
        fields.connection_id = load_u64_be(values[8]);
        fields.session_generation = load_u64_be(values[9]);
        fields.transport_kind = static_cast<PeerHandshakeTransportKind>(
            std::to_integer<std::uint8_t>(values[10].front()));
        copy_exact(values[11], fields.host_ipv4);
        copy_exact(values[12], fields.android_ipv4);
        fields.video_port = load_u16_be(values[13]);
        fields.control_port = load_u16_be(values[14]);
        fields.pair_id.assign(
            reinterpret_cast<const char*>(values[15].data()), values[15].size());
        fields.host_runtime_version.assign(
            reinterpret_cast<const char*>(values[16].data()), values[16].size());
        fields.android_runtime_version.assign(
            reinterpret_cast<const char*>(values[17].data()), values[17].size());

        error = validate_transcript_fields(fields, pair_id_requirement);
        if (error.has_error()) return {std::nullopt, error};
        const std::vector<std::byte> reencoded = encode_transcript_fields(fields);
        if (!std::equal(
                reencoded.begin(),
                reencoded.end(),
                canonical_bytes.begin(),
                canonical_bytes.end())) {
            return {std::nullopt, protocol_error(
                PeerHandshakeErrorCode::out_of_order_tag,
                "validate_canonical_reencoding")};
        }
        PeerHandshakeSha256 digest{};
        error = sha256_bytes(
            canonical_bytes,
            digest,
            "hash_received_canonical_peer_handshake_transcript");
        if (error.has_error()) return {std::nullopt, error};
        return {
            CanonicalPeerHandshakeTranscriptV1{
                std::move(fields),
                std::vector<std::byte>(
                    canonical_bytes.begin(), canonical_bytes.end()),
                digest},
            {},
        };
    } catch (const std::bad_alloc&) {
        return {std::nullopt, protocol_error(
            PeerHandshakeErrorCode::allocation_failed,
            "parse_canonical_peer_handshake_transcript")};
    } catch (...) {
        return {std::nullopt, protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            "parse_canonical_peer_handshake_transcript")};
    }
}

ConfirmedPeerHandshakeSessionV1::~ConfirmedPeerHandshakeSessionV1() {
    erase();
}

void ConfirmedPeerHandshakeSessionV1::erase() noexcept {
    connection_id_ = 0U;
    erase_bytes(control_host_to_android_);
    erase_bytes(control_android_to_host_);
    erase_bytes(presence_host_to_android_);
    erase_bytes(video_host_to_android_);
    erase_bytes(idr_android_to_host_);
    erase_bytes(mouse_host_to_android_);
    erase_bytes(finished_host_);
    erase_bytes(finished_android_);
    erase_bytes(channel_binding_exporter_);
    erase_bytes(transcript_sha256_);
    erase_bytes(channel_binding_sha256_);
}

PeerHandshakeRole
ConfirmedPeerHandshakeSessionV1::local_role() const noexcept {
    return local_role_;
}

std::uint64_t
ConfirmedPeerHandshakeSessionV1::connection_id() const noexcept {
    return connection_id_;
}

PeerHandshakeDataPlaneKeyView
ConfirmedPeerHandshakeSessionV1::control_host_to_android() const noexcept {
    return data_plane_view(control_host_to_android_);
}

PeerHandshakeDataPlaneKeyView
ConfirmedPeerHandshakeSessionV1::control_android_to_host() const noexcept {
    return data_plane_view(control_android_to_host_);
}

PeerHandshakeDataPlaneKeyView
ConfirmedPeerHandshakeSessionV1::presence_host_to_android() const noexcept {
    return data_plane_view(presence_host_to_android_);
}

PeerHandshakeDataPlaneKeyView
ConfirmedPeerHandshakeSessionV1::video_host_to_android() const noexcept {
    return data_plane_view(video_host_to_android_);
}

PeerHandshakeDataPlaneKeyView
ConfirmedPeerHandshakeSessionV1::idr_android_to_host() const noexcept {
    return data_plane_view(idr_android_to_host_);
}

PeerHandshakeDataPlaneKeyView
ConfirmedPeerHandshakeSessionV1::mouse_host_to_android() const noexcept {
    return data_plane_view(mouse_host_to_android_);
}

const PeerHandshakeSha256&
ConfirmedPeerHandshakeSessionV1::transcript_sha256() const noexcept {
    return transcript_sha256_;
}

const PeerHandshakeSha256&
ConfirmedPeerHandshakeSessionV1::channel_binding_sha256() const noexcept {
    return channel_binding_sha256_;
}

PeerHandshakeDigestResult
ConfirmedPeerHandshakeSessionV1::create_finished_mac_for_role(
    const PeerHandshakeRole role) const noexcept {
    const std::array<std::byte, 32U>* key{};
    switch (role) {
        case PeerHandshakeRole::host:
            key = &finished_host_;
            break;
        case PeerHandshakeRole::android:
            key = &finished_android_;
            break;
        default:
            return {std::nullopt, protocol_error(
                PeerHandshakeErrorCode::invalid_role,
                "create_finished_validate_role")};
    }

    std::array<std::byte,
        kFinishedProofDomain.size() + 1U + kPeerHandshakeSha256Bytes> message{};
    std::transform(
        kFinishedProofDomain.begin(),
        kFinishedProofDomain.end(),
        message.begin(),
        [](const char character) {
            return std::byte{static_cast<std::uint8_t>(character)};
        });
    message[kFinishedProofDomain.size()] =
        std::byte{static_cast<std::uint8_t>(role)};
    std::copy(
        transcript_sha256_.begin(),
        transcript_sha256_.end(),
        message.begin() +
            static_cast<std::ptrdiff_t>(kFinishedProofDomain.size() + 1U));

    PeerHandshakeSha256 digest{};
    PeerHandshakeError error = hmac_sha256_bytes(
        *key, message, digest, "create_finished_hmac_sha256");
    if (error.has_error()) return {std::nullopt, error};
    return {digest, {}};
}

bool ConfirmedPeerHandshakeSessionV1::verify_finished_mac_for_role(
    const PeerHandshakeRole role,
    const std::span<const std::byte> candidate_mac,
    PeerHandshakeError& error) const noexcept {
    error = {};
    const PeerHandshakeDigestResult expected =
        create_finished_mac_for_role(role);
    if (!expected.succeeded()) {
        error = expected.error;
        return false;
    }
    if (!constant_time_equal(*expected.digest, candidate_mac)) {
        error = protocol_error(
            PeerHandshakeErrorCode::peer_finished_authentication_failed,
            "verify_peer_finished_hmac_sha256");
        return false;
    }
    return true;
}

PendingPeerHandshakeConfirmationV1::PendingPeerHandshakeConfirmationV1(
    const PeerHandshakeRole local_role,
    std::unique_ptr<ConfirmedPeerHandshakeSessionV1> unconfirmed_session)
    noexcept
    : local_role_(local_role),
      unconfirmed_session_(std::move(unconfirmed_session)),
      closed_(unconfirmed_session_ == nullptr) {}

PendingPeerHandshakeConfirmationV1::~PendingPeerHandshakeConfirmationV1() {
    close();
}

PendingPeerHandshakeConfirmationV1::PendingPeerHandshakeConfirmationV1(
    PendingPeerHandshakeConfirmationV1&& other) noexcept
    : local_role_(other.local_role_),
      unconfirmed_session_(std::move(other.unconfirmed_session_)),
      closed_(other.closed_),
      local_finished_generated_(other.local_finished_generated_) {
    other.closed_ = true;
    other.local_finished_generated_ = false;
}

PendingPeerHandshakeConfirmationV1&
PendingPeerHandshakeConfirmationV1::operator=(
    PendingPeerHandshakeConfirmationV1&& other) noexcept {
    if (this == &other) return *this;
    close();
    local_role_ = other.local_role_;
    unconfirmed_session_ = std::move(other.unconfirmed_session_);
    closed_ = other.closed_;
    local_finished_generated_ = other.local_finished_generated_;
    other.closed_ = true;
    other.local_finished_generated_ = false;
    return *this;
}

void PendingPeerHandshakeConfirmationV1::close() noexcept {
    unconfirmed_session_.reset();
    closed_ = true;
    local_finished_generated_ = false;
}

PeerHandshakeRole
PendingPeerHandshakeConfirmationV1::local_role() const noexcept {
    return local_role_;
}

PeerHandshakeDigestResult
PendingPeerHandshakeConfirmationV1::create_local_finished_mac() noexcept {
    if (closed_ || unconfirmed_session_ == nullptr) {
        return {std::nullopt, protocol_error(
            PeerHandshakeErrorCode::pending_confirmation_closed,
            "create_local_finished_on_closed_pending_state")};
    }
    PeerHandshakeDigestResult result =
        unconfirmed_session_->create_finished_mac_for_role(local_role_);
    if (!result.succeeded()) {
        close();
        return result;
    }
    local_finished_generated_ = true;
    return result;
}

PeerHandshakeConfirmationResult
PendingPeerHandshakeConfirmationV1::confirm_peer_finished_and_consume(
    const std::span<const std::byte> peer_finished_mac) && noexcept {
    if (closed_ || unconfirmed_session_ == nullptr) {
        close();
        return {nullptr, protocol_error(
            PeerHandshakeErrorCode::pending_confirmation_closed,
            "confirm_peer_finished_on_closed_pending_state")};
    }
    if (!local_finished_generated_) {
        close();
        return {nullptr, protocol_error(
            PeerHandshakeErrorCode::local_finished_not_generated,
            "require_local_finished_before_peer_confirmation")};
    }
    const PeerHandshakeRole peer_role =
        local_role_ == PeerHandshakeRole::host
        ? PeerHandshakeRole::android
        : PeerHandshakeRole::host;
    PeerHandshakeError error;
    if (!unconfirmed_session_->verify_finished_mac_for_role(
            peer_role, peer_finished_mac, error)) {
        close();
        return {nullptr, error};
    }
    // Finished keys and the exporter have no post-confirmation role. Retain
    // only traffic material, transcript hash, and the derived public binding.
    erase_bytes(unconfirmed_session_->finished_host_);
    erase_bytes(unconfirmed_session_->finished_android_);
    erase_bytes(unconfirmed_session_->channel_binding_exporter_);
    unconfirmed_session_->local_role_ = local_role_;
    auto confirmed = std::move(unconfirmed_session_);
    closed_ = true;
    local_finished_generated_ = false;
    return {std::move(confirmed), {}};
}

PlatformP256EphemeralKeyAgreementV1::PlatformP256EphemeralKeyAgreementV1(
    std::unique_ptr<Impl> impl,
    PeerHandshakeP256PublicKey public_key) noexcept
    : impl_(std::move(impl)), public_key_(public_key) {}

PlatformP256EphemeralKeyAgreementV1::~PlatformP256EphemeralKeyAgreementV1() =
    default;
PlatformP256EphemeralKeyAgreementV1::PlatformP256EphemeralKeyAgreementV1(
    PlatformP256EphemeralKeyAgreementV1&& other) noexcept {
    std::lock_guard lock(other.mutex_);
    impl_ = std::move(other.impl_);
    public_key_ = other.public_key_;
}
PlatformP256EphemeralKeyAgreementV1&
PlatformP256EphemeralKeyAgreementV1::operator=(
    PlatformP256EphemeralKeyAgreementV1&& other) noexcept {
    if (this == &other) return *this;
    std::scoped_lock lock(mutex_, other.mutex_);
    impl_ = std::move(other.impl_);
    public_key_ = other.public_key_;
    return *this;
}

#if defined(_WIN32)
namespace {

[[nodiscard]] PeerHandshakeError export_sec1_public_key(
    const BCRYPT_KEY_HANDLE key,
    PeerHandshakeP256PublicKey& output) noexcept {
    ULONG required{};
    NTSTATUS status = BCryptExportKey(
        key, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0U, &required, 0U);
    constexpr ULONG kExpectedBytes =
        static_cast<ULONG>(sizeof(BCRYPT_ECCKEY_BLOB) + 64U);
    if (!bcrypt_succeeded(status) || required != kExpectedBytes) {
        return bcrypt_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            status,
            "query_ephemeral_public_key");
    }
    std::array<std::byte, kExpectedBytes> blob{};
    ULONG written{};
    status = BCryptExportKey(
        key,
        nullptr,
        BCRYPT_ECCPUBLIC_BLOB,
        writable_bytes(blob),
        static_cast<ULONG>(blob.size()),
        &written,
        0U);
    if (!bcrypt_succeeded(status) || written != blob.size()) {
        return bcrypt_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            status,
            "export_ephemeral_public_key");
    }
    BCRYPT_ECCKEY_BLOB header{};
    std::memcpy(&header, blob.data(), sizeof(header));
    if (header.dwMagic != BCRYPT_ECDH_PUBLIC_P256_MAGIC ||
        header.cbKey != 32U) {
        return protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            "validate_exported_ephemeral_public_key");
    }
    output[0] = std::byte{0x04U};
    std::copy(
        blob.begin() + static_cast<std::ptrdiff_t>(sizeof(header)),
        blob.end(),
        output.begin() + 1);
    return {};
}

[[nodiscard]] PeerHandshakeError import_peer_public_key(
    const BCRYPT_ALG_HANDLE algorithm,
    const std::span<const std::byte, kPeerHandshakeP256PublicKeyBytes> sec1,
    UniqueBcryptKey& imported) noexcept {
    PeerHandshakeError error = validate_sec1_p256_public_key(
        sec1, kNoFieldTag);
    if (error.has_error()) return error;
    std::array<std::byte,
        sizeof(BCRYPT_ECCKEY_BLOB) + 64U> blob{};
    const BCRYPT_ECCKEY_BLOB header{
        .dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC,
        .cbKey = 32U,
    };
    std::memcpy(blob.data(), &header, sizeof(header));
    std::copy(
        sec1.begin() + 1,
        sec1.end(),
        blob.begin() + static_cast<std::ptrdiff_t>(sizeof(header)));
    const NTSTATUS status = BCryptImportKeyPair(
        algorithm,
        nullptr,
        BCRYPT_ECCPUBLIC_BLOB,
        &imported.handle,
        writable_bytes(blob),
        static_cast<ULONG>(blob.size()),
        0U);
    if (!bcrypt_succeeded(status)) {
        return protocol_error(
            PeerHandshakeErrorCode::invalid_ephemeral_public_key,
            "import_peer_ephemeral_public_key");
    }
    return {};
}

}  // namespace
#endif

std::unique_ptr<PlatformP256EphemeralKeyAgreementV1>
PlatformP256EphemeralKeyAgreementV1::generate_platform(
    PeerHandshakeError& error) noexcept {
    error = {};
#if defined(_WIN32)
    try {
        auto impl = std::make_unique<Impl>();
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &impl->algorithm, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0U);
        if (!bcrypt_succeeded(status)) {
            error = bcrypt_error(
                PeerHandshakeErrorCode::crypto_provider_failed,
                status,
                "open_ephemeral_p256_provider");
            return nullptr;
        }
        status = BCryptGenerateKeyPair(
            impl->algorithm, &impl->key, 256U, 0U);
        if (!bcrypt_succeeded(status)) {
            error = bcrypt_error(
                PeerHandshakeErrorCode::crypto_operation_failed,
                status,
                "generate_ephemeral_p256_key");
            return nullptr;
        }
        status = BCryptFinalizeKeyPair(impl->key, 0U);
        if (!bcrypt_succeeded(status)) {
            error = bcrypt_error(
                PeerHandshakeErrorCode::crypto_operation_failed,
                status,
                "finalize_ephemeral_p256_key");
            return nullptr;
        }
        PeerHandshakeP256PublicKey public_key{};
        error = export_sec1_public_key(impl->key, public_key);
        if (error.has_error()) return nullptr;
        return std::unique_ptr<PlatformP256EphemeralKeyAgreementV1>(
            new PlatformP256EphemeralKeyAgreementV1(
                std::move(impl), public_key));
    } catch (const std::bad_alloc&) {
        error = protocol_error(
            PeerHandshakeErrorCode::allocation_failed,
            "generate_platform_ephemeral_key");
        return nullptr;
    } catch (...) {
        error = protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            "generate_platform_ephemeral_key");
        return nullptr;
    }
#else
    error = protocol_error(
        PeerHandshakeErrorCode::platform_crypto_unavailable,
        "generate_platform_ephemeral_key");
    return nullptr;
#endif
}

std::span<const std::byte, kPeerHandshakeP256PublicKeyBytes>
PlatformP256EphemeralKeyAgreementV1::public_key_sec1() const noexcept {
    return public_key_;
}

bool PlatformP256EphemeralKeyAgreementV1::
is_fresh_for_host_transcript_signing(
    PeerHandshakeError& error) const noexcept {
    error = {};
    std::lock_guard lock(mutex_);
    if (impl_ != nullptr) return true;
    error = protocol_error(
        PeerHandshakeErrorCode::ephemeral_private_key_already_consumed,
        "require_fresh_host_ephemeral_for_transcript_signing");
    return false;
}

std::unique_ptr<PendingPeerHandshakeConfirmationV1>
PlatformP256EphemeralKeyAgreementV1::
derive_pending_after_peer_identity_verified(
    const PeerHandshakeRole local_role,
    const CanonicalPeerHandshakeTranscriptV1& transcript,
    PeerHandshakeError& error) noexcept {
    error = {};
    // Consume before inspecting any caller-controlled role or transcript
    // field. The local unique_ptr destroys the key on every return path.
    std::unique_ptr<Impl> consumed_impl;
    {
        std::lock_guard lock(mutex_);
        consumed_impl = std::move(impl_);
    }
    if (consumed_impl == nullptr) {
        error = protocol_error(
            PeerHandshakeErrorCode::ephemeral_private_key_already_consumed,
            "reject_reused_ephemeral_private_key");
        return nullptr;
    }
    const PeerHandshakeP256PublicKey* local_transcript_key{};
    const PeerHandshakeP256PublicKey* peer_transcript_key{};
    switch (local_role) {
        case PeerHandshakeRole::host:
            local_transcript_key =
                &transcript.fields().host_ephemeral_public_key;
            peer_transcript_key =
                &transcript.fields().android_ephemeral_public_key;
            break;
        case PeerHandshakeRole::android:
            local_transcript_key =
                &transcript.fields().android_ephemeral_public_key;
            peer_transcript_key =
                &transcript.fields().host_ephemeral_public_key;
            break;
        default:
            error = protocol_error(
                PeerHandshakeErrorCode::invalid_role,
                "derive_pending_validate_local_role");
            return nullptr;
    }
    if (transcript.fields().pair_id.empty()) {
        error = protocol_error(
            PeerHandshakeErrorCode::pair_binding_required_for_key_derivation,
            "require_bound_pair_before_key_derivation",
            tag_value(TranscriptTag::pair_id));
        return nullptr;
    }
    if (public_key_ != *local_transcript_key) {
        error = protocol_error(
            PeerHandshakeErrorCode::local_ephemeral_key_mismatch,
            "bind_local_ephemeral_key_to_transcript");
        return nullptr;
    }
#if defined(_WIN32)
    if (consumed_impl->algorithm == nullptr || consumed_impl->key == nullptr) {
        error = protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            "validate_consumed_ephemeral_key_state");
        return nullptr;
    }
    try {
        UniqueBcryptKey peer_key;
        error = import_peer_public_key(
            consumed_impl->algorithm, *peer_transcript_key, peer_key);
        if (error.has_error()) return nullptr;

        UniqueBcryptSecret agreement;
        NTSTATUS status = BCryptSecretAgreement(
            consumed_impl->key, peer_key.handle, &agreement.handle, 0U);
        if (!bcrypt_succeeded(status)) {
            error = bcrypt_error(
                PeerHandshakeErrorCode::crypto_operation_failed,
                status,
                "perform_ephemeral_p256_ecdh");
            return nullptr;
        }

        SecureFixedBytes<32U> raw_secret;
        ULONG written{};
        status = BCryptDeriveKey(
            agreement.handle,
            BCRYPT_KDF_RAW_SECRET,
            nullptr,
            writable_bytes(raw_secret.bytes()),
            static_cast<ULONG>(raw_secret.bytes().size()),
            &written,
            0U);
        if (!bcrypt_succeeded(status) || written != raw_secret.bytes().size()) {
            error = bcrypt_error(
                PeerHandshakeErrorCode::crypto_operation_failed,
                status,
                "export_raw_ecdh_shared_secret");
            return nullptr;
        }

        // CNG exposes BCRYPT_KDF_RAW_SECRET in little-endian byte order. The
        // wire contract and Java BigInteger/EC agreement use big-endian.
        SecureFixedBytes<32U> shared_secret_be;
        std::reverse_copy(
            raw_secret.bytes().begin(),
            raw_secret.bytes().end(),
            shared_secret_be.bytes().begin());
        SecureFixedBytes<32U> prk;
        error = derive_prk(
            transcript.transcript_sha256(),
            shared_secret_be.bytes(),
            prk.bytes());
        if (error.has_error()) return nullptr;

        auto secrets = std::unique_ptr<ConfirmedPeerHandshakeSessionV1>(
            new ConfirmedPeerHandshakeSessionV1());
        secrets->local_role_ = local_role;
        secrets->connection_id_ = transcript.fields().connection_id;
        const auto expand = [&prk, &error](
            const std::string_view label,
            const std::span<std::byte> output) {
            error = hkdf_expand_sha256(prk.bytes(), label, output);
            return !error.has_error();
        };
        if (!expand(
                kControlHostToAndroidLabel,
                secrets->control_host_to_android_) ||
            !expand(
                kControlAndroidToHostLabel,
                secrets->control_android_to_host_) ||
            !expand(
                kPresenceHostToAndroidLabel,
                secrets->presence_host_to_android_) ||
            !expand(
                kVideoHostToAndroidLabel,
                secrets->video_host_to_android_) ||
            !expand(
                kIdrAndroidToHostLabel,
                secrets->idr_android_to_host_) ||
            !expand(
                kMouseHostToAndroidLabel,
                secrets->mouse_host_to_android_) ||
            !expand(kFinishedHostLabel, secrets->finished_host_) ||
            !expand(kFinishedAndroidLabel, secrets->finished_android_) ||
            !expand(
                kChannelBindingExporterLabel,
                secrets->channel_binding_exporter_)) {
            return nullptr;
        }
        secrets->transcript_sha256_ = transcript.transcript_sha256();
        SecureFixedBytes<
            kChannelBindingDomain.size() + 2U * kPeerHandshakeSha256Bytes>
            binding_input;
        std::transform(
            kChannelBindingDomain.begin(),
            kChannelBindingDomain.end(),
            binding_input.bytes().begin(),
            [](const char character) {
                return std::byte{static_cast<std::uint8_t>(character)};
            });
        auto binding_output = binding_input.bytes().begin() +
            static_cast<std::ptrdiff_t>(kChannelBindingDomain.size());
        binding_output = std::copy(
            secrets->transcript_sha256_.begin(),
            secrets->transcript_sha256_.end(),
            binding_output);
        std::copy(
            secrets->channel_binding_exporter_.begin(),
            secrets->channel_binding_exporter_.end(),
            binding_output);
        error = sha256_bytes(
            binding_input.bytes(),
            secrets->channel_binding_sha256_,
            "derive_channel_binding_sha256");
        if (error.has_error()) return nullptr;
        return std::unique_ptr<PendingPeerHandshakeConfirmationV1>(
            new PendingPeerHandshakeConfirmationV1(
                local_role, std::move(secrets)));
    } catch (const std::bad_alloc&) {
        error = protocol_error(
            PeerHandshakeErrorCode::allocation_failed,
            "derive_pending_peer_handshake_confirmation");
        return nullptr;
    } catch (...) {
        error = protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            "derive_pending_peer_handshake_confirmation");
        return nullptr;
    }
#else
    static_cast<void>(peer_transcript_key);
    static_cast<void>(consumed_impl);
    error = protocol_error(
        PeerHandshakeErrorCode::platform_crypto_unavailable,
        "derive_pending_peer_handshake_confirmation");
    return nullptr;
#endif
}

#if defined(VFDUAL_ENABLE_AUTHENTICATED_PEER_HANDSHAKE_TEST_ACCESS)

std::unique_ptr<PlatformP256EphemeralKeyAgreementV1>
PlatformP256EphemeralKeyAgreementV1::import_test_private_key(
    const std::span<const std::byte, 32U> private_scalar_be,
    const std::span<
        const std::byte, kPeerHandshakeP256PublicKeyBytes>
        expected_public_key_sec1,
    PeerHandshakeError& error) noexcept {
    error = {};
#if defined(_WIN32)
    error = validate_sec1_p256_public_key(
        expected_public_key_sec1, kNoFieldTag);
    if (error.has_error()) return nullptr;
    if (!contains_nonzero(private_scalar_be)) {
        error = protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            "validate_test_private_scalar");
        return nullptr;
    }
    try {
        auto impl = std::make_unique<Impl>();
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &impl->algorithm, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0U);
        if (!bcrypt_succeeded(status)) {
            error = bcrypt_error(
                PeerHandshakeErrorCode::crypto_provider_failed,
                status,
                "open_test_ephemeral_p256_provider");
            return nullptr;
        }

        SecureVector private_blob(
            sizeof(BCRYPT_ECCKEY_BLOB) + 3U * 32U);
        const BCRYPT_ECCKEY_BLOB header{
            .dwMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC,
            .cbKey = 32U,
        };
        std::memcpy(private_blob.bytes().data(), &header, sizeof(header));
        auto output = private_blob.bytes().begin() +
            static_cast<std::ptrdiff_t>(sizeof(header));
        output = std::copy(
            expected_public_key_sec1.begin() + 1,
            expected_public_key_sec1.end(),
            output);
        std::copy(private_scalar_be.begin(), private_scalar_be.end(), output);
        status = BCryptImportKeyPair(
            impl->algorithm,
            nullptr,
            BCRYPT_ECCPRIVATE_BLOB,
            &impl->key,
            writable_bytes(private_blob.bytes()),
            static_cast<ULONG>(private_blob.bytes().size()),
            0U);
        if (!bcrypt_succeeded(status)) {
            error = bcrypt_error(
                PeerHandshakeErrorCode::crypto_operation_failed,
                status,
                "import_test_ephemeral_private_key");
            return nullptr;
        }
        PeerHandshakeP256PublicKey exported{};
        error = export_sec1_public_key(impl->key, exported);
        if (error.has_error()) return nullptr;
        if (!std::equal(
                exported.begin(),
                exported.end(),
                expected_public_key_sec1.begin(),
                expected_public_key_sec1.end())) {
            error = protocol_error(
                PeerHandshakeErrorCode::crypto_operation_failed,
                "bind_test_private_key_to_expected_public_key");
            return nullptr;
        }
        return std::unique_ptr<PlatformP256EphemeralKeyAgreementV1>(
            new PlatformP256EphemeralKeyAgreementV1(
                std::move(impl), exported));
    } catch (const std::bad_alloc&) {
        error = protocol_error(
            PeerHandshakeErrorCode::allocation_failed,
            "import_test_ephemeral_private_key");
        return nullptr;
    } catch (...) {
        error = protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            "import_test_ephemeral_private_key");
        return nullptr;
    }
#else
    static_cast<void>(private_scalar_be);
    static_cast<void>(expected_public_key_sec1);
    error = protocol_error(
        PeerHandshakeErrorCode::platform_crypto_unavailable,
        "import_test_ephemeral_private_key");
    return nullptr;
#endif
}

PeerHandshakeDigestResult
PlatformP256EphemeralKeyAgreementV1::derive_test_prk(
    const std::span<const std::byte, 32U> shared_secret_be,
    const std::span<const std::byte, 32U> transcript_sha256) noexcept {
    PeerHandshakeSha256 prk{};
    PeerHandshakeError error =
        derive_prk(transcript_sha256, shared_secret_be, prk);
    if (error.has_error()) return {std::nullopt, error};
    return {prk, {}};
}

PeerHandshakeDigestResult
PlatformP256EphemeralKeyAgreementV1::derive_test_shared_secret(
    const std::span<
        const std::byte, kPeerHandshakeP256PublicKeyBytes>
        peer_public_key_sec1) const noexcept {
#if defined(_WIN32)
    std::lock_guard lock(mutex_);
    if (impl_ == nullptr || impl_->algorithm == nullptr || impl_->key == nullptr) {
        return {std::nullopt, protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            "validate_test_ephemeral_key_state")};
    }
    UniqueBcryptKey peer_key;
    PeerHandshakeError error = import_peer_public_key(
        impl_->algorithm, peer_public_key_sec1, peer_key);
    if (error.has_error()) return {std::nullopt, error};
    UniqueBcryptSecret agreement;
    NTSTATUS status = BCryptSecretAgreement(
        impl_->key, peer_key.handle, &agreement.handle, 0U);
    if (!bcrypt_succeeded(status)) {
        return {std::nullopt, bcrypt_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            status,
            "perform_test_ephemeral_p256_ecdh")};
    }
    SecureFixedBytes<32U> raw_secret;
    ULONG written{};
    status = BCryptDeriveKey(
        agreement.handle,
        BCRYPT_KDF_RAW_SECRET,
        nullptr,
        writable_bytes(raw_secret.bytes()),
        static_cast<ULONG>(raw_secret.bytes().size()),
        &written,
        0U);
    if (!bcrypt_succeeded(status) || written != raw_secret.bytes().size()) {
        return {std::nullopt, bcrypt_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            status,
            "export_test_raw_ecdh_shared_secret")};
    }
    PeerHandshakeSha256 shared_secret_be{};
    std::reverse_copy(
        raw_secret.bytes().begin(),
        raw_secret.bytes().end(),
        shared_secret_be.begin());
    return {shared_secret_be, {}};
#else
    static_cast<void>(peer_public_key_sec1);
    return {std::nullopt, protocol_error(
        PeerHandshakeErrorCode::platform_crypto_unavailable,
        "derive_test_shared_secret")};
#endif
}

PeerHandshakeError
PlatformP256EphemeralKeyAgreementV1::exercise_test_hkdf_expand(
    const std::size_t output_bytes) noexcept {
    if (output_bytes > kHkdfSha256MaximumOutputBytes) {
        return protocol_error(
            PeerHandshakeErrorCode::hkdf_output_too_large,
            "validate_hkdf_output_length");
    }
    try {
        SecureFixedBytes<32U> prk;
        std::fill(prk.bytes().begin(), prk.bytes().end(), std::byte{0x0bU});
        SecureVector output(output_bytes);
        return hkdf_expand_sha256(
            prk.bytes(), "VFDUAL/PEER-HS/V1/test", output.bytes());
    } catch (const std::bad_alloc&) {
        return protocol_error(
            PeerHandshakeErrorCode::allocation_failed,
            "exercise_test_hkdf_expand");
    } catch (...) {
        return protocol_error(
            PeerHandshakeErrorCode::crypto_operation_failed,
            "exercise_test_hkdf_expand");
    }
}

void PlatformP256EphemeralKeyAgreementV1::
invalidate_platform_provider_for_test() noexcept {
#if defined(_WIN32)
    std::lock_guard lock(mutex_);
    if (impl_ != nullptr && impl_->algorithm != nullptr) {
        static_cast<void>(BCryptCloseAlgorithmProvider(impl_->algorithm, 0U));
        impl_->algorithm = nullptr;
    }
#endif
}

#endif

}  // namespace vfdual
