#include "vfdual/host_pair_generation_credential_verifier_v1.hpp"

#if !defined(_WIN32)
#error "The Host pair-generation credential verifier requires Windows CNG"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <bcrypt.h>
#include <wincrypt.h>

#include "vfdual/host_pair_generation_credential_keyring_build.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <utility>
#include <vector>

namespace vfdual {
namespace {

constexpr std::size_t kMaximumSpkiDerBytes = 4096U;
constexpr std::size_t kMaximumOuterPemBase64Bytes = 32768U;
constexpr std::size_t kMinimumPairRsaBits = 3072U;
constexpr std::string_view kPemBegin{"-----BEGIN PUBLIC KEY-----"};
constexpr std::string_view kPemEnd{"-----END PUBLIC KEY-----"};
constexpr std::array<std::uint8_t, 3U> kRequiredRsaExponent{
    0x01U, 0x00U, 0x01U};
constexpr std::array<std::uint8_t, 2U> kCanonicalDerNull{
    0x05U, 0x00U};

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

class UniqueKey final {
public:
    UniqueKey() = default;
    explicit UniqueKey(BCRYPT_KEY_HANDLE key) noexcept : handle_(key) {}
    ~UniqueKey() {
        if (handle_ != nullptr) static_cast<void>(BCryptDestroyKey(handle_));
    }
    UniqueKey(const UniqueKey&) = delete;
    UniqueKey& operator=(const UniqueKey&) = delete;
    UniqueKey(UniqueKey&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)) {}
    UniqueKey& operator=(UniqueKey&& other) noexcept {
        if (this == &other) return *this;
        if (handle_ != nullptr) static_cast<void>(BCryptDestroyKey(handle_));
        handle_ = std::exchange(other.handle_, nullptr);
        return *this;
    }

    [[nodiscard]] BCRYPT_KEY_HANDLE get() const noexcept { return handle_; }

private:
    BCRYPT_KEY_HANDLE handle_{};
};

class LocalPublicKeyInfo final {
public:
    LocalPublicKeyInfo() = default;
    ~LocalPublicKeyInfo() {
        if (value != nullptr) static_cast<void>(LocalFree(value));
    }
    LocalPublicKeyInfo(const LocalPublicKeyInfo&) = delete;
    LocalPublicKeyInfo& operator=(const LocalPublicKeyInfo&) = delete;

    CERT_PUBLIC_KEY_INFO* value{};
};

struct VerificationKey final {
    std::string key_id;
    std::array<std::uint8_t, 32U> spki_sha256{};
    std::vector<std::uint8_t> canonical_spki_der;
    UniqueKey public_key;
    std::size_t signature_bytes{};

    VerificationKey() = default;
    VerificationKey(const VerificationKey&) = delete;
    VerificationKey& operator=(const VerificationKey&) = delete;
    VerificationKey(VerificationKey&&) noexcept = default;
    VerificationKey& operator=(VerificationKey&&) noexcept = default;
};

struct ParsedHeader final {
    std::string key_id;
};

struct ParsedClaims final {
    std::string allocation_request_id;
    std::string android_identity_spki_sha256;
    std::string audience;
    std::string binding_id;
    std::int64_t binding_revision{};
    std::int64_t connection_id{};
    std::string credential_nonce;
    std::string entitlement_id;
    std::int64_t expires_at_epoch{};
    std::int64_t generation{};
    std::string host_identity_spki_sha256;
    std::int64_t issued_at_epoch{};
    std::string issuer;
    std::int64_t not_before_epoch{};
    std::string pair_id;
    std::int64_t revocation_version{};
    std::string transcript_proposal_sha256;
    std::string credential_type;
};

[[nodiscard]] HostPairGenerationCredentialErrorV1 error(
    const HostPairGenerationCredentialErrorCodeV1 code) noexcept {
    return {.code = code};
}

[[nodiscard]] bool constant_time_equal(
    const std::span<const std::uint8_t> left,
    const std::span<const std::uint8_t> right) noexcept {
    if (left.size() != right.size()) return false;
    std::uint8_t difference{};
    for (std::size_t index{}; index < left.size(); ++index) {
        difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
    }
    return difference == 0U;
}

[[nodiscard]] bool constant_time_equal(
    const std::string_view left,
    const std::string_view right) noexcept {
    return constant_time_equal(
        {reinterpret_cast<const std::uint8_t*>(left.data()), left.size()},
        {reinterpret_cast<const std::uint8_t*>(right.data()), right.size()});
}

[[nodiscard]] bool decode_standard_base64_canonical(
    const std::string_view encoded,
    std::vector<std::uint8_t>& decoded) {
    decoded.clear();
    if (encoded.empty() || encoded.size() > kMaximumOuterPemBase64Bytes ||
        encoded.size() % 4U != 0U ||
        encoded.size() > std::numeric_limits<DWORD>::max()) {
        return false;
    }
    std::size_t first_padding = encoded.size();
    for (std::size_t index{}; index < encoded.size(); ++index) {
        const char character = encoded[index];
        const bool data = (character >= 'A' && character <= 'Z') ||
            (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9') || character == '+' ||
            character == '/';
        if (character == '=') {
            if (first_padding == encoded.size()) first_padding = index;
        } else if (!data || first_padding != encoded.size()) {
            return false;
        }
    }
    if (encoded.size() - first_padding > 2U) return false;

    DWORD required{};
    if (!CryptStringToBinaryA(
            encoded.data(),
            static_cast<DWORD>(encoded.size()),
            CRYPT_STRING_BASE64,
            nullptr,
            &required,
            nullptr,
            nullptr) ||
        required == 0U) {
        return false;
    }
    decoded.resize(required);
    DWORD written = required;
    if (!CryptStringToBinaryA(
            encoded.data(),
            static_cast<DWORD>(encoded.size()),
            CRYPT_STRING_BASE64,
            decoded.data(),
            &written,
            nullptr,
            nullptr) ||
        written != required) {
        decoded.clear();
        return false;
    }

    DWORD canonical_size{};
    if (!CryptBinaryToStringA(
            decoded.data(),
            written,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            nullptr,
            &canonical_size) ||
        canonical_size == 0U) {
        decoded.clear();
        return false;
    }
    std::string canonical(canonical_size, '\0');
    if (!CryptBinaryToStringA(
            decoded.data(),
            written,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            canonical.data(),
            &canonical_size)) {
        decoded.clear();
        return false;
    }
    if (!canonical.empty() && canonical.back() == '\0') canonical.pop_back();
    if (!constant_time_equal(canonical, encoded)) {
        decoded.clear();
        return false;
    }
    return true;
}

[[nodiscard]] bool decode_public_pem_outer_base64(
    const std::string_view outer_base64,
    std::vector<std::uint8_t>& canonical_spki_der) {
    std::vector<std::uint8_t> pem_bytes;
    if (!decode_standard_base64_canonical(outer_base64, pem_bytes)) {
        return false;
    }
    std::string normalized;
    normalized.reserve(pem_bytes.size());
    for (std::size_t index{}; index < pem_bytes.size(); ++index) {
        const std::uint8_t character = pem_bytes[index];
        if (character == '\r') {
            if (index + 1U >= pem_bytes.size() ||
                pem_bytes[index + 1U] != '\n') {
                return false;
            }
            continue;
        }
        if (character != '\n' &&
            (character < 0x20U || character > 0x7eU)) {
            return false;
        }
        normalized.push_back(static_cast<char>(character));
    }
    if (!normalized.empty() && normalized.back() == '\n') {
        normalized.pop_back();
    }
    const std::string prefix = std::string{kPemBegin} + "\n";
    const std::string suffix = "\n" + std::string{kPemEnd};
    if (!normalized.starts_with(prefix) || !normalized.ends_with(suffix) ||
        normalized.find("PRIVATE KEY") != std::string::npos ||
        normalized.find(kPemBegin, prefix.size()) != std::string::npos ||
        normalized.find(kPemEnd) != normalized.size() - kPemEnd.size()) {
        return false;
    }
    const std::string_view body = std::string_view{normalized}.substr(
        prefix.size(), normalized.size() - prefix.size() - suffix.size());
    if (body.empty()) return false;
    std::string compact_body;
    compact_body.reserve(body.size());
    std::size_t line_size{};
    for (const char character : body) {
        if (character == '\n') {
            if (line_size != 64U) return false;
            line_size = 0U;
            continue;
        }
        const bool valid = (character >= 'A' && character <= 'Z') ||
            (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9') || character == '+' ||
            character == '/' || character == '=';
        if (!valid || line_size >= 64U) return false;
        compact_body.push_back(character);
        ++line_size;
    }
    if (line_size == 0U || line_size > 64U) return false;
    return decode_standard_base64_canonical(
        compact_body, canonical_spki_der);
}

[[nodiscard]] bool sha256(
    const std::span<const std::uint8_t> input,
    std::array<std::uint8_t, 32U>& digest) noexcept {
    if (input.size() > std::numeric_limits<ULONG>::max()) return false;
    UniqueAlgorithm algorithm;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm.handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0U);
    if (!BCRYPT_SUCCESS(status)) return false;
    DWORD hash_length{};
    DWORD copied{};
    status = BCryptGetProperty(
        algorithm.handle,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hash_length),
        sizeof(hash_length),
        &copied,
        0U);
    if (!BCRYPT_SUCCESS(status) || copied != sizeof(hash_length) ||
        hash_length != digest.size()) {
        return false;
    }
    UniqueHash hash;
    status = BCryptCreateHash(
        algorithm.handle, &hash.handle, nullptr, 0U, nullptr, 0U, 0U);
    if (!BCRYPT_SUCCESS(status)) return false;
    status = BCryptHashData(
        hash.handle,
        const_cast<PUCHAR>(input.data()),
        static_cast<ULONG>(input.size()),
        0U);
    if (!BCRYPT_SUCCESS(status)) return false;
    status = BCryptFinishHash(
        hash.handle,
        digest.data(),
        static_cast<ULONG>(digest.size()),
        0U);
    return BCRYPT_SUCCESS(status);
}

[[nodiscard]] std::string lowercase_hex_prefix(
    const std::array<std::uint8_t, 32U>& digest,
    const std::size_t byte_count) {
    constexpr std::string_view kHex{"0123456789abcdef"};
    std::string output(byte_count * 2U, '0');
    for (std::size_t index{}; index < byte_count; ++index) {
        output[index * 2U] = kHex[digest[index] >> 4U];
        output[index * 2U + 1U] = kHex[digest[index] & 0x0fU];
    }
    return output;
}

[[nodiscard]] bool decode_canonical_rsa_algorithm_spki(
    const std::span<const std::uint8_t> der,
    LocalPublicKeyInfo& decoded) {
    if (der.empty() || der.size() > kMaximumSpkiDerBytes ||
        der.size() > std::numeric_limits<DWORD>::max()) {
        return false;
    }
    DWORD decoded_size{};
    if (!CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            der.data(),
            static_cast<DWORD>(der.size()),
            CRYPT_DECODE_ALLOC_FLAG,
            nullptr,
            &decoded.value,
            &decoded_size) ||
        decoded.value == nullptr || decoded_size == 0U) {
        return false;
    }
    const CRYPT_ALGORITHM_IDENTIFIER& algorithm = decoded.value->Algorithm;
    if (algorithm.pszObjId == nullptr ||
        std::strcmp(algorithm.pszObjId, szOID_RSA_RSA) != 0 ||
        algorithm.Parameters.cbData != kCanonicalDerNull.size() ||
        algorithm.Parameters.pbData == nullptr ||
        !constant_time_equal(
            {algorithm.Parameters.pbData, algorithm.Parameters.cbData},
            kCanonicalDerNull) ||
        decoded.value->PublicKey.cUnusedBits != 0U) {
        return false;
    }
    return true;
}

[[nodiscard]] bool public_blob_contract_valid(
    const std::span<const std::uint8_t> blob,
    const bool require_pair_key_strength,
    std::size_t& signature_bytes) noexcept {
    if (blob.size() < sizeof(BCRYPT_RSAKEY_BLOB)) return false;
    BCRYPT_RSAKEY_BLOB header{};
    std::memcpy(&header, blob.data(), sizeof(header));
    if (header.Magic != BCRYPT_RSAPUBLIC_MAGIC ||
        header.cbPrime1 != 0U || header.cbPrime2 != 0U ||
        header.cbPublicExp == 0U || header.cbModulus == 0U) {
        return false;
    }
    const std::size_t body_size = static_cast<std::size_t>(header.cbPublicExp) +
        static_cast<std::size_t>(header.cbModulus);
    if (body_size > blob.size() - sizeof(header) ||
        sizeof(header) + body_size != blob.size()) {
        return false;
    }
    const std::span<const std::uint8_t> exponent = blob.subspan(
        sizeof(header), header.cbPublicExp);
    const std::span<const std::uint8_t> modulus = blob.subspan(
        sizeof(header) + header.cbPublicExp, header.cbModulus);
    if (exponent.empty() || exponent.front() == 0U || modulus.empty() ||
        modulus.front() == 0U ||
        header.BitLength == 0U ||
        (static_cast<std::size_t>(header.BitLength) + 7U) / 8U !=
            header.cbModulus) {
        return false;
    }
    std::uint8_t first_modulus_byte = modulus.front();
    std::size_t leading_zero_bits{};
    while ((first_modulus_byte & 0x80U) == 0U) {
        first_modulus_byte <<= 1U;
        ++leading_zero_bits;
    }
    const std::size_t actual_modulus_bits =
        (modulus.size() - 1U) * 8U + (8U - leading_zero_bits);
    if (actual_modulus_bits != header.BitLength) return false;
    if (require_pair_key_strength &&
        (actual_modulus_bits < kMinimumPairRsaBits ||
         !constant_time_equal(exponent, kRequiredRsaExponent))) {
        return false;
    }
    signature_bytes = header.cbModulus;
    return true;
}

void append_der_length(
    std::vector<std::uint8_t>& output, const std::size_t length) {
    if (length < 128U) {
        output.push_back(static_cast<std::uint8_t>(length));
        return;
    }
    std::array<std::uint8_t, sizeof(std::size_t)> encoded{};
    std::size_t count{};
    std::size_t remaining = length;
    while (remaining != 0U) {
        encoded[encoded.size() - 1U - count] =
            static_cast<std::uint8_t>(remaining & 0xffU);
        remaining >>= 8U;
        ++count;
    }
    output.push_back(static_cast<std::uint8_t>(0x80U | count));
    output.insert(
        output.end(), encoded.end() - static_cast<std::ptrdiff_t>(count),
        encoded.end());
}

void append_der_tlv(
    std::vector<std::uint8_t>& output,
    const std::uint8_t tag,
    const std::span<const std::uint8_t> value) {
    output.push_back(tag);
    append_der_length(output, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

void append_positive_der_integer(
    std::vector<std::uint8_t>& output,
    const std::span<const std::uint8_t> magnitude) {
    std::vector<std::uint8_t> content;
    content.reserve(magnitude.size() + 1U);
    if ((magnitude.front() & 0x80U) != 0U) content.push_back(0U);
    content.insert(content.end(), magnitude.begin(), magnitude.end());
    append_der_tlv(output, 0x02U, content);
}

[[nodiscard]] std::vector<std::uint8_t> canonical_spki_from_public_blob(
    const std::span<const std::uint8_t> blob) {
    BCRYPT_RSAKEY_BLOB header{};
    std::memcpy(&header, blob.data(), sizeof(header));
    const auto exponent = blob.subspan(
        sizeof(header), header.cbPublicExp);
    const auto modulus = blob.subspan(
        sizeof(header) + header.cbPublicExp, header.cbModulus);

    std::vector<std::uint8_t> rsa_public_key_content;
    rsa_public_key_content.reserve(modulus.size() + exponent.size() + 16U);
    append_positive_der_integer(rsa_public_key_content, modulus);
    append_positive_der_integer(rsa_public_key_content, exponent);
    std::vector<std::uint8_t> rsa_public_key;
    append_der_tlv(rsa_public_key, 0x30U, rsa_public_key_content);

    constexpr std::array<std::uint8_t, 15U> kRsaAlgorithmIdentifier{
        0x30U, 0x0dU, 0x06U, 0x09U, 0x2aU, 0x86U, 0x48U, 0x86U,
        0xf7U, 0x0dU, 0x01U, 0x01U, 0x01U, 0x05U, 0x00U};
    std::vector<std::uint8_t> bit_string_content;
    bit_string_content.reserve(rsa_public_key.size() + 1U);
    bit_string_content.push_back(0U);
    bit_string_content.insert(
        bit_string_content.end(), rsa_public_key.begin(), rsa_public_key.end());
    std::vector<std::uint8_t> spki_content;
    spki_content.reserve(
        kRsaAlgorithmIdentifier.size() + bit_string_content.size() + 8U);
    spki_content.insert(
        spki_content.end(),
        kRsaAlgorithmIdentifier.begin(),
        kRsaAlgorithmIdentifier.end());
    append_der_tlv(spki_content, 0x03U, bit_string_content);
    std::vector<std::uint8_t> spki;
    append_der_tlv(spki, 0x30U, spki_content);
    return spki;
}

[[nodiscard]] bool import_verification_key(
    const std::span<const std::uint8_t> canonical_spki_der,
    const bool require_pair_key_strength,
    VerificationKey& output) {
    LocalPublicKeyInfo decoded;
    if (!decode_canonical_rsa_algorithm_spki(canonical_spki_der, decoded)) {
        return false;
    }
    BCRYPT_KEY_HANDLE imported{};
    if (!CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING, decoded.value, 0U, nullptr, &imported) ||
        imported == nullptr) {
        return false;
    }
    UniqueKey public_key(imported);
    ULONG blob_size{};
    NTSTATUS status = BCryptExportKey(
        public_key.get(),
        nullptr,
        BCRYPT_RSAPUBLIC_BLOB,
        nullptr,
        0U,
        &blob_size,
        0U);
    if (!BCRYPT_SUCCESS(status) || blob_size < sizeof(BCRYPT_RSAKEY_BLOB)) {
        return false;
    }
    std::vector<std::uint8_t> blob(blob_size);
    ULONG written{};
    status = BCryptExportKey(
        public_key.get(),
        nullptr,
        BCRYPT_RSAPUBLIC_BLOB,
        blob.data(),
        blob_size,
        &written,
        0U);
    if (!BCRYPT_SUCCESS(status) || written != blob_size) return false;
    std::size_t signature_bytes{};
    if (!public_blob_contract_valid(
            blob, require_pair_key_strength, signature_bytes)) {
        return false;
    }
    const std::vector<std::uint8_t> independently_encoded_spki =
        canonical_spki_from_public_blob(blob);
    if (!constant_time_equal(
            canonical_spki_der, independently_encoded_spki)) {
        return false;
    }
    std::array<std::uint8_t, 32U> spki_sha256{};
    if (!sha256(canonical_spki_der, spki_sha256)) return false;
    output.key_id = lowercase_hex_prefix(spki_sha256, 8U);
    output.spki_sha256 = spki_sha256;
    output.canonical_spki_der.assign(
        canonical_spki_der.begin(), canonical_spki_der.end());
    output.public_key = std::move(public_key);
    output.signature_bytes = signature_bytes;
    return true;
}

[[nodiscard]] bool lower_hex_valid(
    const std::string_view value, const std::size_t required_size) noexcept {
    if (value.size() != required_size) return false;
    bool contains_nonzero{};
    for (const char character : value) {
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f'))) {
            return false;
        }
        contains_nonzero = contains_nonzero || character != '0';
    }
    return contains_nonzero;
}

[[nodiscard]] bool allocation_request_id_valid(
    const std::string_view value) noexcept {
    if (value.empty() || value.size() > 128U) return false;
    return std::all_of(value.begin(), value.end(), [](const char character) {
        return (character >= 'A' && character <= 'Z') ||
            (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9') || character == '.' ||
            character == '_' || character == ':' || character == '-';
    });
}

[[nodiscard]] bool positive_signed_64(const std::int64_t value) noexcept {
    return value > 0;
}

[[nodiscard]] bool expected_valid(
    const HostPairGenerationCredentialExpectedV1& expected) noexcept {
    return allocation_request_id_valid(expected.allocation_request_id) &&
        lower_hex_valid(expected.pair_id, 32U) &&
        lower_hex_valid(expected.entitlement_id, 32U) &&
        lower_hex_valid(expected.binding_id, 32U) &&
        positive_signed_64(expected.binding_revision) &&
        positive_signed_64(expected.revocation_version) &&
        positive_signed_64(expected.generation) &&
        positive_signed_64(expected.connection_id) &&
        lower_hex_valid(expected.host_identity_spki_sha256, 64U) &&
        lower_hex_valid(expected.android_identity_spki_sha256, 64U) &&
        lower_hex_valid(expected.transcript_proposal_sha256, 64U) &&
        !constant_time_equal(
            expected.host_identity_spki_sha256,
            expected.android_identity_spki_sha256);
}

[[nodiscard]] int base64url_value(const char character) noexcept {
    if (character >= 'A' && character <= 'Z') return character - 'A';
    if (character >= 'a' && character <= 'z') return character - 'a' + 26;
    if (character >= '0' && character <= '9') return character - '0' + 52;
    if (character == '-') return 62;
    if (character == '_') return 63;
    return -1;
}

[[nodiscard]] bool decode_base64url_canonical(
    const std::string_view encoded,
    std::vector<std::uint8_t>& decoded) {
    decoded.clear();
    if (encoded.empty() || encoded.size() % 4U == 1U) return false;
    decoded.reserve((encoded.size() * 3U) / 4U + 2U);
    std::size_t offset{};
    while (encoded.size() - offset >= 4U) {
        const int first = base64url_value(encoded[offset]);
        const int second = base64url_value(encoded[offset + 1U]);
        const int third = base64url_value(encoded[offset + 2U]);
        const int fourth = base64url_value(encoded[offset + 3U]);
        if (first < 0 || second < 0 || third < 0 || fourth < 0) return false;
        decoded.push_back(static_cast<std::uint8_t>(
            (static_cast<unsigned>(first) << 2U) |
            (static_cast<unsigned>(second) >> 4U)));
        decoded.push_back(static_cast<std::uint8_t>(
            (static_cast<unsigned>(second) << 4U) |
            (static_cast<unsigned>(third) >> 2U)));
        decoded.push_back(static_cast<std::uint8_t>(
            (static_cast<unsigned>(third) << 6U) |
            static_cast<unsigned>(fourth)));
        offset += 4U;
    }
    const std::size_t remaining = encoded.size() - offset;
    if (remaining == 2U) {
        const int first = base64url_value(encoded[offset]);
        const int second = base64url_value(encoded[offset + 1U]);
        if (first < 0 || second < 0 || (second & 0x0f) != 0) return false;
        decoded.push_back(static_cast<std::uint8_t>(
            (static_cast<unsigned>(first) << 2U) |
            (static_cast<unsigned>(second) >> 4U)));
    } else if (remaining == 3U) {
        const int first = base64url_value(encoded[offset]);
        const int second = base64url_value(encoded[offset + 1U]);
        const int third = base64url_value(encoded[offset + 2U]);
        if (first < 0 || second < 0 || third < 0 || (third & 0x03) != 0) {
            return false;
        }
        decoded.push_back(static_cast<std::uint8_t>(
            (static_cast<unsigned>(first) << 2U) |
            (static_cast<unsigned>(second) >> 4U)));
        decoded.push_back(static_cast<std::uint8_t>(
            (static_cast<unsigned>(second) << 4U) |
            (static_cast<unsigned>(third) >> 2U)));
    } else if (remaining != 0U) {
        return false;
    }
    return true;
}

class CanonicalJsonCursor final {
public:
    explicit CanonicalJsonCursor(
        const std::span<const std::uint8_t> input) noexcept
        : input_(input) {}

    [[nodiscard]] bool consume(const std::string_view literal) noexcept {
        if (literal.size() > input_.size() - offset_) return false;
        const auto actual = input_.subspan(offset_, literal.size());
        const auto expected = std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t*>(literal.data()),
            literal.size()};
        if (!constant_time_equal(actual, expected)) return false;
        offset_ += literal.size();
        return true;
    }

    [[nodiscard]] bool parse_string(std::string& output) {
        if (offset_ >= input_.size() || input_[offset_] != '"') return false;
        ++offset_;
        const std::size_t start = offset_;
        while (offset_ < input_.size() && input_[offset_] != '"') {
            const std::uint8_t character = input_[offset_];
            // Every valid v1 claim is restricted ASCII. Rejecting escapes is
            // equivalent to requiring Python ensure_ascii canonical output.
            if (character < 0x20U || character > 0x7eU ||
                character == '\\') {
                return false;
            }
            ++offset_;
        }
        if (offset_ >= input_.size()) return false;
        output.assign(
            reinterpret_cast<const char*>(input_.data() + start),
            offset_ - start);
        ++offset_;
        return true;
    }

    [[nodiscard]] bool parse_positive_int64(std::int64_t& output) noexcept {
        if (offset_ >= input_.size() || input_[offset_] < '0' ||
            input_[offset_] > '9') {
            return false;
        }
        if (input_[offset_] == '0') return false;
        std::uint64_t value{};
        while (offset_ < input_.size() && input_[offset_] >= '0' &&
               input_[offset_] <= '9') {
            const std::uint64_t digit = input_[offset_] - '0';
            if (value >
                (static_cast<std::uint64_t>(
                     std::numeric_limits<std::int64_t>::max()) - digit) /
                    10U) {
                return false;
            }
            value = value * 10U + digit;
            ++offset_;
        }
        if (value == 0U) return false;
        output = static_cast<std::int64_t>(value);
        return true;
    }

    [[nodiscard]] bool at_end() const noexcept {
        return offset_ == input_.size();
    }

private:
    std::span<const std::uint8_t> input_;
    std::size_t offset_{};
};

[[nodiscard]] bool parse_canonical_header(
    const std::span<const std::uint8_t> raw,
    ParsedHeader& header) {
    CanonicalJsonCursor cursor(raw);
    std::string algorithm;
    std::string token_type;
    return cursor.consume("{\"alg\":") &&
        cursor.parse_string(algorithm) && algorithm == "RS256" &&
        cursor.consume(",\"kid\":") &&
        cursor.parse_string(header.key_id) &&
        lower_hex_valid(header.key_id, 16U) &&
        cursor.consume(",\"typ\":") && cursor.parse_string(token_type) &&
        token_type == "JWT" && cursor.consume("}") && cursor.at_end();
}

[[nodiscard]] bool parse_canonical_payload(
    const std::span<const std::uint8_t> raw,
    ParsedClaims& claims) {
    CanonicalJsonCursor cursor(raw);
    return cursor.consume("{\"allocation_request_id\":") &&
        cursor.parse_string(claims.allocation_request_id) &&
        cursor.consume(",\"android_identity_spki_sha256\":") &&
        cursor.parse_string(claims.android_identity_spki_sha256) &&
        cursor.consume(",\"aud\":") &&
        cursor.parse_string(claims.audience) &&
        cursor.consume(",\"binding_id\":") &&
        cursor.parse_string(claims.binding_id) &&
        cursor.consume(",\"binding_revision\":") &&
        cursor.parse_positive_int64(claims.binding_revision) &&
        cursor.consume(",\"connection_id\":") &&
        cursor.parse_positive_int64(claims.connection_id) &&
        cursor.consume(",\"credential_nonce\":") &&
        cursor.parse_string(claims.credential_nonce) &&
        cursor.consume(",\"entitlement_id\":") &&
        cursor.parse_string(claims.entitlement_id) &&
        cursor.consume(",\"exp\":") &&
        cursor.parse_positive_int64(claims.expires_at_epoch) &&
        cursor.consume(",\"generation\":") &&
        cursor.parse_positive_int64(claims.generation) &&
        cursor.consume(",\"host_identity_spki_sha256\":") &&
        cursor.parse_string(claims.host_identity_spki_sha256) &&
        cursor.consume(",\"iat\":") &&
        cursor.parse_positive_int64(claims.issued_at_epoch) &&
        cursor.consume(",\"iss\":") && cursor.parse_string(claims.issuer) &&
        cursor.consume(",\"nbf\":") &&
        cursor.parse_positive_int64(claims.not_before_epoch) &&
        cursor.consume(",\"pair_id\":") &&
        cursor.parse_string(claims.pair_id) &&
        cursor.consume(",\"revocation_version\":") &&
        cursor.parse_positive_int64(claims.revocation_version) &&
        cursor.consume(",\"transcript_proposal_sha256\":") &&
        cursor.parse_string(claims.transcript_proposal_sha256) &&
        cursor.consume(",\"typ\":") &&
        cursor.parse_string(claims.credential_type) && cursor.consume("}") &&
        cursor.at_end();
}

[[nodiscard]] bool claims_valid(
    const ParsedClaims& claims, const std::int64_t now_epoch) noexcept {
    if (!allocation_request_id_valid(claims.allocation_request_id) ||
        !lower_hex_valid(claims.pair_id, 32U) ||
        !lower_hex_valid(claims.entitlement_id, 32U) ||
        !lower_hex_valid(claims.binding_id, 32U) ||
        !lower_hex_valid(claims.host_identity_spki_sha256, 64U) ||
        !lower_hex_valid(claims.android_identity_spki_sha256, 64U) ||
        !lower_hex_valid(claims.transcript_proposal_sha256, 64U) ||
        !lower_hex_valid(claims.credential_nonce, 64U) ||
        constant_time_equal(
            claims.host_identity_spki_sha256,
            claims.android_identity_spki_sha256) ||
        claims.credential_type != kPairGenerationCredentialTypeV1 ||
        claims.issuer != kPairGenerationCredentialIssuerV1 ||
        claims.audience != kPairGenerationCredentialAudienceV1 ||
        claims.not_before_epoch != claims.issued_at_epoch ||
        claims.expires_at_epoch <= claims.issued_at_epoch ||
        claims.expires_at_epoch - claims.issued_at_epoch >
            kPairGenerationCredentialMaximumTtlSecondsV1 ||
        claims.expires_at_epoch <= now_epoch) {
        return false;
    }
    return claims.issued_at_epoch <= now_epoch ||
        claims.issued_at_epoch - now_epoch <=
            kPairGenerationCredentialMaximumFutureSecondsV1;
}

[[nodiscard]] bool claims_match_expected(
    const ParsedClaims& claims,
    const HostPairGenerationCredentialExpectedV1& expected) noexcept {
    return constant_time_equal(
               claims.allocation_request_id,
               expected.allocation_request_id) &&
        constant_time_equal(claims.pair_id, expected.pair_id) &&
        constant_time_equal(
            claims.entitlement_id, expected.entitlement_id) &&
        constant_time_equal(claims.binding_id, expected.binding_id) &&
        claims.binding_revision == expected.binding_revision &&
        claims.revocation_version == expected.revocation_version &&
        claims.generation == expected.generation &&
        claims.connection_id == expected.connection_id &&
        constant_time_equal(
            claims.host_identity_spki_sha256,
            expected.host_identity_spki_sha256) &&
        constant_time_equal(
            claims.android_identity_spki_sha256,
            expected.android_identity_spki_sha256) &&
        constant_time_equal(
            claims.transcript_proposal_sha256,
            expected.transcript_proposal_sha256);
}

[[nodiscard]] bool rsa_pkcs1_sha256_signature_valid(
    const VerificationKey& key,
    const std::span<const std::uint8_t> signing_input,
    const std::span<const std::uint8_t> signature) noexcept {
    if (signature.size() != key.signature_bytes ||
        signing_input.size() > std::numeric_limits<ULONG>::max() ||
        signature.size() > std::numeric_limits<ULONG>::max()) {
        return false;
    }
    std::array<std::uint8_t, 32U> digest{};
    if (!sha256(signing_input, digest)) return false;
    BCRYPT_PKCS1_PADDING_INFO padding{
        .pszAlgId = BCRYPT_SHA256_ALGORITHM};
    const NTSTATUS status = BCryptVerifySignature(
        key.public_key.get(),
        &padding,
        digest.data(),
        static_cast<ULONG>(digest.size()),
        const_cast<PUCHAR>(signature.data()),
        static_cast<ULONG>(signature.size()),
        BCRYPT_PAD_PKCS1);
    return BCRYPT_SUCCESS(status);
}

[[nodiscard]] const VerificationKey* select_key(
    const std::vector<VerificationKey>& keys,
    const std::string_view key_id) noexcept {
    const VerificationKey* selected{};
    for (const VerificationKey& key : keys) {
        if (constant_time_equal(key.key_id, key_id)) selected = &key;
    }
    return selected;
}

}  // namespace

struct VerifiedHostPairGenerationCredentialV1::Claims final {
    std::string key_id;
    std::string allocation_request_id;
    std::string pair_id;
    std::string entitlement_id;
    std::string binding_id;
    std::int64_t binding_revision{};
    std::int64_t revocation_version{};
    std::int64_t generation{};
    std::int64_t connection_id{};
    std::string host_identity_spki_sha256;
    std::string android_identity_spki_sha256;
    std::string transcript_proposal_sha256;
    std::string credential_nonce;
    std::int64_t issued_at_epoch{};
    std::int64_t not_before_epoch{};
    std::int64_t expires_at_epoch{};
    std::array<std::uint8_t, 32U> token_sha256{};
};

struct HostPairGenerationCredentialV1Verifier::Implementation final {
    std::vector<VerificationKey> verification_keys;
};

HostPairGenerationCredentialV1VerifierConstructionResult
HostPairGenerationCredentialV1Verifier::
create_from_canonical_spki_der_for_internal_use(
    const std::span<const std::span<const std::uint8_t>> pair_keys,
    const std::span<const std::span<const std::uint8_t>>
        other_purpose_keys) noexcept {
    if (pair_keys.empty() || pair_keys.size() > 3U) {
        return {nullptr, error(
            HostPairGenerationCredentialErrorCodeV1::key_invalid)};
    }
    try {
        auto implementation =
            std::make_unique<HostPairGenerationCredentialV1Verifier::
                Implementation>();
        implementation->verification_keys.reserve(pair_keys.size());
        for (const std::span<const std::uint8_t> source : pair_keys) {
            VerificationKey key;
            if (!import_verification_key(source, true, key)) {
                return {nullptr, error(
                    HostPairGenerationCredentialErrorCodeV1::key_invalid)};
            }
            for (const VerificationKey& existing :
                 implementation->verification_keys) {
                if (constant_time_equal(
                        existing.canonical_spki_der,
                        key.canonical_spki_der) ||
                    constant_time_equal(existing.key_id, key.key_id)) {
                    return {nullptr, error(
                        HostPairGenerationCredentialErrorCodeV1::
                            key_invalid)};
                }
            }
            implementation->verification_keys.push_back(std::move(key));
        }

        std::vector<std::array<std::uint8_t, 32U>> other_purpose_hashes;
        other_purpose_hashes.reserve(other_purpose_keys.size());
        for (const std::span<const std::uint8_t> source :
             other_purpose_keys) {
            VerificationKey key;
            if (!import_verification_key(source, false, key)) {
                return {nullptr, error(
                    HostPairGenerationCredentialErrorCodeV1::key_invalid)};
            }
            other_purpose_hashes.push_back(key.spki_sha256);
        }
        for (const VerificationKey& pair_key :
             implementation->verification_keys) {
            for (const auto& other_hash : other_purpose_hashes) {
                if (constant_time_equal(pair_key.spki_sha256, other_hash)) {
                    return {nullptr, error(
                        HostPairGenerationCredentialErrorCodeV1::
                            key_invalid)};
                }
            }
        }
        auto verifier = std::unique_ptr<
            HostPairGenerationCredentialV1Verifier>(
            new HostPairGenerationCredentialV1Verifier(
                std::move(implementation)));
        return {std::move(verifier), {}};
    } catch (const std::bad_alloc&) {
        return {nullptr, error(
            HostPairGenerationCredentialErrorCodeV1::allocation_failed)};
    } catch (...) {
        return {nullptr, error(
            HostPairGenerationCredentialErrorCodeV1::operation_failed)};
    }
}

const char* host_pair_generation_credential_error_code_name_v1(
    const HostPairGenerationCredentialErrorCodeV1 code) noexcept {
    switch (code) {
        case HostPairGenerationCredentialErrorCodeV1::none:
            return "none";
        case HostPairGenerationCredentialErrorCodeV1::key_invalid:
            return "pair_generation_credential_key_invalid";
        case HostPairGenerationCredentialErrorCodeV1::source_invalid:
            return "pair_generation_credential_source_invalid";
        case HostPairGenerationCredentialErrorCodeV1::token_invalid:
            return "pair_generation_credential_invalid";
        case HostPairGenerationCredentialErrorCodeV1::crypto_unavailable:
            return "pair_generation_credential_crypto_unavailable";
        case HostPairGenerationCredentialErrorCodeV1::allocation_failed:
            return "pair_generation_credential_allocation_failed";
        case HostPairGenerationCredentialErrorCodeV1::operation_failed:
            return "pair_generation_credential_operation_failed";
    }
    return "pair_generation_credential_operation_failed";
}

VerifiedHostPairGenerationCredentialV1::
VerifiedHostPairGenerationCredentialV1(
    std::shared_ptr<const Claims> claims) noexcept
    : claims_(std::move(claims)) {}

const std::string& VerifiedHostPairGenerationCredentialV1::key_id()
    const noexcept {
    return claims_->key_id;
}

const std::string&
VerifiedHostPairGenerationCredentialV1::allocation_request_id()
    const noexcept {
    return claims_->allocation_request_id;
}

const std::string& VerifiedHostPairGenerationCredentialV1::pair_id()
    const noexcept {
    return claims_->pair_id;
}

const std::string& VerifiedHostPairGenerationCredentialV1::entitlement_id()
    const noexcept {
    return claims_->entitlement_id;
}

const std::string& VerifiedHostPairGenerationCredentialV1::binding_id()
    const noexcept {
    return claims_->binding_id;
}

std::int64_t VerifiedHostPairGenerationCredentialV1::binding_revision()
    const noexcept {
    return claims_->binding_revision;
}

std::int64_t VerifiedHostPairGenerationCredentialV1::revocation_version()
    const noexcept {
    return claims_->revocation_version;
}

std::int64_t VerifiedHostPairGenerationCredentialV1::generation()
    const noexcept {
    return claims_->generation;
}

std::int64_t VerifiedHostPairGenerationCredentialV1::connection_id()
    const noexcept {
    return claims_->connection_id;
}

const std::string&
VerifiedHostPairGenerationCredentialV1::host_identity_spki_sha256()
    const noexcept {
    return claims_->host_identity_spki_sha256;
}

const std::string&
VerifiedHostPairGenerationCredentialV1::android_identity_spki_sha256()
    const noexcept {
    return claims_->android_identity_spki_sha256;
}

const std::string&
VerifiedHostPairGenerationCredentialV1::transcript_proposal_sha256()
    const noexcept {
    return claims_->transcript_proposal_sha256;
}

const std::string& VerifiedHostPairGenerationCredentialV1::credential_nonce()
    const noexcept {
    return claims_->credential_nonce;
}

std::int64_t VerifiedHostPairGenerationCredentialV1::issued_at_epoch()
    const noexcept {
    return claims_->issued_at_epoch;
}

std::int64_t VerifiedHostPairGenerationCredentialV1::not_before_epoch()
    const noexcept {
    return claims_->not_before_epoch;
}

std::int64_t VerifiedHostPairGenerationCredentialV1::expires_at_epoch()
    const noexcept {
    return claims_->expires_at_epoch;
}

const std::array<std::uint8_t, 32U>&
VerifiedHostPairGenerationCredentialV1::token_sha256() const noexcept {
    return claims_->token_sha256;
}

HostPairGenerationCredentialV1Verifier::
HostPairGenerationCredentialV1Verifier(
    std::unique_ptr<Implementation> implementation) noexcept
    : implementation_(std::move(implementation)) {}

HostPairGenerationCredentialV1Verifier::
~HostPairGenerationCredentialV1Verifier() = default;

HostPairGenerationCredentialV1VerifierConstructionResult
HostPairGenerationCredentialV1Verifier::
create_from_build_pinned_keyring() noexcept {
    try {
        std::vector<std::vector<std::uint8_t>> owned_pair_der;
        owned_pair_der.reserve(
            build::kPairGenerationCredentialPublicPemBase64.size());
        for (const std::string_view encoded :
             build::kPairGenerationCredentialPublicPemBase64) {
            std::vector<std::uint8_t> der;
            if (!decode_public_pem_outer_base64(encoded, der)) {
                return {nullptr, error(
                    HostPairGenerationCredentialErrorCodeV1::key_invalid)};
            }
            owned_pair_der.push_back(std::move(der));
        }

        std::vector<std::vector<std::uint8_t>> owned_other_der;
        owned_other_der.reserve(
            build::kPairGenerationOtherPurposeUsageTicketPublicPemBase64
                .size());
        for (const std::string_view encoded :
             build::kPairGenerationOtherPurposeUsageTicketPublicPemBase64) {
            std::vector<std::uint8_t> der;
            if (!decode_public_pem_outer_base64(encoded, der)) {
                return {nullptr, error(
                    HostPairGenerationCredentialErrorCodeV1::key_invalid)};
            }
            owned_other_der.push_back(std::move(der));
        }

        std::vector<std::span<const std::uint8_t>> pair_spans;
        pair_spans.reserve(owned_pair_der.size());
        for (const auto& der : owned_pair_der) pair_spans.emplace_back(der);
        std::vector<std::span<const std::uint8_t>> other_spans;
        other_spans.reserve(owned_other_der.size());
        for (const auto& der : owned_other_der) other_spans.emplace_back(der);
        return create_from_canonical_spki_der_for_internal_use(
            pair_spans, other_spans);
    } catch (const std::bad_alloc&) {
        return {nullptr, error(
            HostPairGenerationCredentialErrorCodeV1::allocation_failed)};
    } catch (...) {
        return {nullptr, error(
            HostPairGenerationCredentialErrorCodeV1::operation_failed)};
    }
}

#if defined(VFDUAL_ENABLE_HOST_PAIR_CREDENTIAL_TEST_ACCESS)
HostPairGenerationCredentialV1VerifierConstructionResult
HostPairGenerationCredentialV1Verifier::
create_for_test_fixture_keyring(
    const std::span<const HostPairGenerationCredentialTestPublicKeyV1>
        pair_credential_keys,
    const std::span<const HostPairGenerationCredentialTestPublicKeyV1>
        other_purpose_keys) noexcept {
    try {
        std::vector<std::span<const std::uint8_t>> pair;
        std::vector<std::span<const std::uint8_t>> other;
        pair.reserve(pair_credential_keys.size());
        other.reserve(other_purpose_keys.size());
        for (const auto& key : pair_credential_keys) {
            pair.push_back({key.canonical_spki_der});
        }
        for (const auto& key : other_purpose_keys) {
            other.push_back({key.canonical_spki_der});
        }
        return create_from_canonical_spki_der_for_internal_use(pair, other);
    } catch (const std::bad_alloc&) {
        return {nullptr, error(
            HostPairGenerationCredentialErrorCodeV1::allocation_failed)};
    } catch (...) {
        return {nullptr, error(
            HostPairGenerationCredentialErrorCodeV1::operation_failed)};
    }
}
#endif

HostPairGenerationCredentialVerificationResultV1
HostPairGenerationCredentialV1Verifier::verify(
    const std::string_view compact_token_ascii,
    const HostPairGenerationCredentialExpectedV1& expected,
    const std::int64_t now_epoch) const noexcept {
    if (!expected_valid(expected)) {
        return {std::nullopt, error(
            HostPairGenerationCredentialErrorCodeV1::source_invalid)};
    }
    if (now_epoch <= 0 || implementation_ == nullptr ||
        compact_token_ascii.empty() ||
        compact_token_ascii.size() >
            kPairGenerationCredentialMaximumTokenBytesV1) {
        return {std::nullopt, error(
            HostPairGenerationCredentialErrorCodeV1::token_invalid)};
    }
    try {
        const std::size_t first_dot = compact_token_ascii.find('.');
        if (first_dot == std::string_view::npos || first_dot == 0U) {
            return {std::nullopt, error(
                HostPairGenerationCredentialErrorCodeV1::token_invalid)};
        }
        const std::size_t second_dot = compact_token_ascii.find(
            '.', first_dot + 1U);
        if (second_dot == std::string_view::npos ||
            second_dot == first_dot + 1U ||
            second_dot + 1U >= compact_token_ascii.size() ||
            compact_token_ascii.find('.', second_dot + 1U) !=
                std::string_view::npos) {
            return {std::nullopt, error(
                HostPairGenerationCredentialErrorCodeV1::token_invalid)};
        }
        const std::string_view header_segment =
            compact_token_ascii.substr(0U, first_dot);
        const std::string_view payload_segment = compact_token_ascii.substr(
            first_dot + 1U, second_dot - first_dot - 1U);
        const std::string_view signature_segment =
            compact_token_ascii.substr(second_dot + 1U);

        std::vector<std::uint8_t> header_raw;
        std::vector<std::uint8_t> payload_raw;
        std::vector<std::uint8_t> signature;
        if (!decode_base64url_canonical(header_segment, header_raw) ||
            !decode_base64url_canonical(payload_segment, payload_raw) ||
            !decode_base64url_canonical(signature_segment, signature)) {
            return {std::nullopt, error(
                HostPairGenerationCredentialErrorCodeV1::token_invalid)};
        }
        ParsedHeader header;
        if (!parse_canonical_header(header_raw, header)) {
            return {std::nullopt, error(
                HostPairGenerationCredentialErrorCodeV1::token_invalid)};
        }
        const VerificationKey* key = select_key(
            implementation_->verification_keys, header.key_id);
        if (key == nullptr) {
            return {std::nullopt, error(
                HostPairGenerationCredentialErrorCodeV1::token_invalid)};
        }
        const auto signing_input = std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t*>(
                compact_token_ascii.data()),
            second_dot};
        if (!rsa_pkcs1_sha256_signature_valid(
                *key, signing_input, signature)) {
            return {std::nullopt, error(
                HostPairGenerationCredentialErrorCodeV1::token_invalid)};
        }
        ParsedClaims parsed;
        if (!parse_canonical_payload(payload_raw, parsed) ||
            !claims_valid(parsed, now_epoch) ||
            !claims_match_expected(parsed, expected)) {
            return {std::nullopt, error(
                HostPairGenerationCredentialErrorCodeV1::token_invalid)};
        }

        auto claims = std::make_shared<
            VerifiedHostPairGenerationCredentialV1::Claims>();
        claims->key_id = std::move(header.key_id);
        claims->allocation_request_id =
            std::move(parsed.allocation_request_id);
        claims->pair_id = std::move(parsed.pair_id);
        claims->entitlement_id = std::move(parsed.entitlement_id);
        claims->binding_id = std::move(parsed.binding_id);
        claims->binding_revision = parsed.binding_revision;
        claims->revocation_version = parsed.revocation_version;
        claims->generation = parsed.generation;
        claims->connection_id = parsed.connection_id;
        claims->host_identity_spki_sha256 =
            std::move(parsed.host_identity_spki_sha256);
        claims->android_identity_spki_sha256 =
            std::move(parsed.android_identity_spki_sha256);
        claims->transcript_proposal_sha256 =
            std::move(parsed.transcript_proposal_sha256);
        claims->credential_nonce = std::move(parsed.credential_nonce);
        claims->issued_at_epoch = parsed.issued_at_epoch;
        claims->not_before_epoch = parsed.not_before_epoch;
        claims->expires_at_epoch = parsed.expires_at_epoch;
        if (!sha256(
                {reinterpret_cast<const std::uint8_t*>(
                     compact_token_ascii.data()),
                 compact_token_ascii.size()},
                claims->token_sha256)) {
            return {std::nullopt, error(
                HostPairGenerationCredentialErrorCodeV1::token_invalid)};
        }
        std::shared_ptr<const
            VerifiedHostPairGenerationCredentialV1::Claims> immutable_claims =
            std::move(claims);
        return {
            VerifiedHostPairGenerationCredentialV1{
                std::move(immutable_claims)},
            {},
        };
    } catch (const std::bad_alloc&) {
        return {std::nullopt, error(
            HostPairGenerationCredentialErrorCodeV1::allocation_failed)};
    } catch (...) {
        return {std::nullopt, error(
            HostPairGenerationCredentialErrorCodeV1::operation_failed)};
    }
}

}  // namespace vfdual
