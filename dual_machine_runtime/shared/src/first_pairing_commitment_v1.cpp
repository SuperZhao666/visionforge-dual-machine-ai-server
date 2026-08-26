#include "vfdual/first_pairing_commitment_v1.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <span>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#endif

namespace vfdual {
namespace {

constexpr std::array<std::byte, 4U> kMagic{
    std::byte{0x56U}, std::byte{0x46U},
    std::byte{0x50U}, std::byte{0x31U}};  // VFP1
constexpr std::array<std::byte, 4U> kUserConfirmationMagic{
    std::byte{0x56U}, std::byte{0x46U},
    std::byte{0x55U}, std::byte{0x31U}};  // VFU1
constexpr std::uint8_t kVersion = 1U;
constexpr std::string_view kSasDomain{
    "visionforge-dual-machine-first-pairing-sas-v1"};
constexpr std::uint32_t kSasModulus = 1'000'000U;
constexpr std::uint64_t kSasAcceptLimit =
    (std::uint64_t{1U} << 32U) / kSasModulus * kSasModulus;

template <std::size_t Size>
[[nodiscard]] bool all_zero(
    const std::array<std::byte, Size>& value) noexcept {
    return std::all_of(value.begin(), value.end(), [](const std::byte item) {
        return item == std::byte{0U};
    });
}

template <std::size_t Size>
[[nodiscard]] bool append(
    std::vector<std::byte>& output,
    const std::array<std::byte, Size>& value) noexcept {
    try {
        output.insert(output.end(), value.begin(), value.end());
        return true;
    } catch (...) {
        return false;
    }
}

void write_u16_be(
    std::span<std::byte, 2U> output,
    const std::uint16_t value) noexcept {
    output[0U] = std::byte{static_cast<std::uint8_t>(value >> 8U)};
    output[1U] = std::byte{static_cast<std::uint8_t>(value)};
}

void write_u32_be(
    std::span<std::byte, 4U> output,
    const std::uint32_t value) noexcept {
    output[0U] = std::byte{static_cast<std::uint8_t>(value >> 24U)};
    output[1U] = std::byte{static_cast<std::uint8_t>(value >> 16U)};
    output[2U] = std::byte{static_cast<std::uint8_t>(value >> 8U)};
    output[3U] = std::byte{static_cast<std::uint8_t>(value)};
}

void write_u64_be(
    std::span<std::byte, 8U> output,
    const std::uint64_t value) noexcept {
    for (std::size_t index = 0U; index < output.size(); ++index) {
        output[index] = std::byte{static_cast<std::uint8_t>(
            value >> ((output.size() - 1U - index) * 8U))};
    }
}

[[nodiscard]] std::uint32_t read_u32_be(
    const std::span<const std::byte, 4U> input) noexcept {
    return (static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(input[0U])) << 24U) |
        (static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(input[1U])) << 16U) |
        (static_cast<std::uint32_t>(
                std::to_integer<std::uint8_t>(input[2U])) << 8U) |
        static_cast<std::uint32_t>(
            std::to_integer<std::uint8_t>(input[3U]));
}

[[nodiscard]] bool valid_fields(
    const FirstPairingCommitmentFieldsV1& fields) noexcept {
    return fields.transport_kind == FirstPairingTransportKindV1::ethernet &&
        fields.required_capabilities ==
            kFirstPairingCapabilityTwoSidedUserConfirmationV1 &&
        !all_zero(fields.attempt_id) &&
        !all_zero(fields.host_identity_spki_sha256) &&
        !all_zero(fields.android_identity_spki_sha256) &&
        fields.host_identity_spki_sha256 !=
            fields.android_identity_spki_sha256 &&
        fields.host_ephemeral_public_key[0U] == std::byte{0x04U} &&
        fields.android_ephemeral_public_key[0U] == std::byte{0x04U} &&
        fields.host_ephemeral_public_key !=
            fields.android_ephemeral_public_key &&
        !all_zero(fields.host_nonce) &&
        !all_zero(fields.android_nonce) &&
        fields.host_nonce != fields.android_nonce &&
        !all_zero(fields.host_ipv4) &&
        !all_zero(fields.android_ipv4) &&
        fields.host_ipv4 != fields.android_ipv4 &&
        fields.video_port != 0U && fields.control_port != 0U &&
        fields.video_port != fields.control_port &&
        !all_zero(fields.host_runtime_version_sha256) &&
        !all_zero(fields.android_runtime_version_sha256) &&
        fields.expires_at_epoch != 0U &&
        fields.expires_at_epoch <=
            static_cast<std::uint64_t>(
                (std::numeric_limits<std::int64_t>::max)());
}

[[nodiscard]] bool valid_confirmation_fields(
    const FirstPairingUserConfirmationFieldsV1& fields) noexcept {
    const bool valid_role =
        fields.role == FirstPairingConfirmationRoleV1::host ||
        fields.role == FirstPairingConfirmationRoleV1::android;
    const bool valid_method =
        fields.method == FirstPairingConfirmationMethodV1::decimal_sas ||
        fields.method == FirstPairingConfirmationMethodV1::qr;
    return valid_role && valid_method && !all_zero(fields.attempt_id) &&
        !all_zero(fields.commitment_sha256) &&
        fields.expires_at_epoch != 0U &&
        fields.expires_at_epoch <=
            static_cast<std::uint64_t>(
                (std::numeric_limits<std::int64_t>::max)());
}

[[nodiscard]] bool sha256(
    const std::span<const std::byte> input,
    PeerHandshakeSha256& output) noexcept {
#if defined(_WIN32)
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    const auto close = [&]() noexcept {
        if (hash != nullptr) BCryptDestroyHash(hash);
        if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0U);
    };
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U);
    if (!BCRYPT_SUCCESS(status)) {
        close();
        return false;
    }
    status = BCryptCreateHash(
        algorithm, &hash, nullptr, 0U, nullptr, 0U, 0U);
    if (BCRYPT_SUCCESS(status) && !input.empty()) {
        if (input.size() > (std::numeric_limits<ULONG>::max)()) {
            close();
            return false;
        }
        status = BCryptHashData(
            hash,
            reinterpret_cast<PUCHAR>(
                const_cast<std::byte*>(input.data())),
            static_cast<ULONG>(input.size()),
            0U);
    }
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptFinishHash(
            hash,
            reinterpret_cast<PUCHAR>(output.data()),
            static_cast<ULONG>(output.size()),
            0U);
    }
    close();
    if (!BCRYPT_SUCCESS(status)) output.fill(std::byte{0U});
    return BCRYPT_SUCCESS(status);
#else
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        output.fill(std::byte{0U});
        return false;
    }
    bool succeeded =
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
    if (succeeded && !input.empty()) {
        succeeded = EVP_DigestUpdate(
            context,
            static_cast<const void*>(input.data()),
            input.size()) == 1;
    }
    unsigned int digest_bytes{};
    if (succeeded) {
        succeeded = EVP_DigestFinal_ex(
            context,
            reinterpret_cast<unsigned char*>(output.data()),
            &digest_bytes) == 1 &&
            digest_bytes == output.size();
    }
    EVP_MD_CTX_free(context);
    if (!succeeded) output.fill(std::byte{0U});
    return succeeded;
#endif
}

[[nodiscard]] bool derive_sas(
    const PeerHandshakeSha256& commitment,
    std::array<char, 7U>& output) noexcept {
    std::vector<std::byte> message;
    try {
        message.reserve(kSasDomain.size() + 1U + commitment.size() + 1U);
        for (const char value : kSasDomain) {
            message.push_back(std::byte{static_cast<std::uint8_t>(value)});
        }
        message.push_back(std::byte{0U});
        message.insert(message.end(), commitment.begin(), commitment.end());
        message.push_back(std::byte{0U});
    } catch (...) {
        return false;
    }
    for (std::uint16_t counter = 0U; counter <= 0xffU; ++counter) {
        message.back() = std::byte{static_cast<std::uint8_t>(counter)};
        PeerHandshakeSha256 digest{};
        if (!sha256(message, digest)) return false;
        const auto candidate = read_u32_be(
            std::span<const std::byte, 4U>{digest.data(), 4U});
        if (static_cast<std::uint64_t>(candidate) >= kSasAcceptLimit) {
            continue;
        }
        std::uint32_t value = candidate % kSasModulus;
        for (std::size_t index = 6U; index > 0U; --index) {
            output[index - 1U] = static_cast<char>('0' + (value % 10U));
            value /= 10U;
        }
        output[6U] = '\0';
        return true;
    }
    return false;
}

}  // namespace

FirstPairingCommitmentResultV1 build_first_pairing_commitment_v1(
    const FirstPairingCommitmentFieldsV1& fields) noexcept {
    FirstPairingCommitmentResultV1 result{};
    if (!valid_fields(fields)) return result;
    try {
        result.canonical_encoding.reserve(kFirstPairingCommitmentBytesV1);
        result.canonical_encoding.insert(
            result.canonical_encoding.end(), kMagic.begin(), kMagic.end());
        result.canonical_encoding.push_back(std::byte{kVersion});
        result.canonical_encoding.push_back(std::byte{
            static_cast<std::uint8_t>(fields.transport_kind)});
        std::array<std::byte, 4U> encoded_u32{};
        write_u32_be(encoded_u32, fields.required_capabilities);
        if (!append(result.canonical_encoding, encoded_u32) ||
            !append(result.canonical_encoding, fields.attempt_id) ||
            !append(result.canonical_encoding,
                fields.host_identity_spki_sha256) ||
            !append(result.canonical_encoding,
                fields.android_identity_spki_sha256) ||
            !append(result.canonical_encoding,
                fields.host_ephemeral_public_key) ||
            !append(result.canonical_encoding,
                fields.android_ephemeral_public_key) ||
            !append(result.canonical_encoding, fields.host_nonce) ||
            !append(result.canonical_encoding, fields.android_nonce) ||
            !append(result.canonical_encoding, fields.host_ipv4) ||
            !append(result.canonical_encoding, fields.android_ipv4)) {
            result.canonical_encoding.clear();
            return result;
        }
        std::array<std::byte, 2U> encoded_u16{};
        write_u16_be(encoded_u16, fields.video_port);
        if (!append(result.canonical_encoding, encoded_u16)) return result;
        write_u16_be(encoded_u16, fields.control_port);
        if (!append(result.canonical_encoding, encoded_u16) ||
            !append(result.canonical_encoding,
                fields.host_runtime_version_sha256) ||
            !append(result.canonical_encoding,
                fields.android_runtime_version_sha256)) {
            result.canonical_encoding.clear();
            return result;
        }
        std::array<std::byte, 8U> encoded_u64{};
        write_u64_be(encoded_u64, fields.expires_at_epoch);
        if (!append(result.canonical_encoding, encoded_u64) ||
            result.canonical_encoding.size() !=
                kFirstPairingCommitmentBytesV1) {
            result.canonical_encoding.clear();
            return result;
        }
    } catch (...) {
        result.canonical_encoding.clear();
        return result;
    }
    if (!sha256(result.canonical_encoding, result.commitment_sha256) ||
        !derive_sas(result.commitment_sha256, result.decimal_sas)) {
        result.status = FirstPairingCommitmentStatusV1::hash_failed;
        result.canonical_encoding.clear();
        result.commitment_sha256.fill(std::byte{0U});
        result.decimal_sas.fill('\0');
        return result;
    }
    result.status = FirstPairingCommitmentStatusV1::built;
    return result;
}

FirstPairingUserConfirmationResultV1
build_first_pairing_user_confirmation_v1(
    const FirstPairingUserConfirmationFieldsV1& fields) noexcept {
    FirstPairingUserConfirmationResultV1 result{};
    if (!valid_confirmation_fields(fields)) return result;
    auto cursor = result.canonical_encoding.begin();
    cursor = std::copy(
        kUserConfirmationMagic.begin(), kUserConfirmationMagic.end(), cursor);
    *cursor++ = std::byte{kVersion};
    *cursor++ = std::byte{static_cast<std::uint8_t>(fields.role)};
    *cursor++ = std::byte{static_cast<std::uint8_t>(fields.method)};
    *cursor++ = std::byte{0U};
    cursor = std::copy(fields.attempt_id.begin(), fields.attempt_id.end(), cursor);
    cursor = std::copy(
        fields.commitment_sha256.begin(),
        fields.commitment_sha256.end(),
        cursor);
    std::array<std::byte, 8U> expiry{};
    write_u64_be(expiry, fields.expires_at_epoch);
    cursor = std::copy(expiry.begin(), expiry.end(), cursor);
    if (cursor != result.canonical_encoding.end() ||
        !sha256(result.canonical_encoding, result.payload_sha256)) {
        result.status = FirstPairingCommitmentStatusV1::hash_failed;
        result.canonical_encoding.fill(std::byte{0U});
        result.payload_sha256.fill(std::byte{0U});
        return result;
    }
    result.status = FirstPairingCommitmentStatusV1::built;
    return result;
}

}  // namespace vfdual
