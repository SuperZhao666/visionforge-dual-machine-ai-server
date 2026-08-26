#include "vfdual/host_usage_lease_verifier_v1.hpp"

#if !defined(_WIN32)
#error "The Host usage-lease verifier requires Windows CNG"
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

#include "vfdual/host_usage_ticket_keyring_build.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <utility>
#include <vector>

namespace vfdual {
namespace {

constexpr std::size_t kMaximumSpkiDerBytes = 4096U;
constexpr std::size_t kMaximumOuterPemBase64Bytes = 32768U;
constexpr std::size_t kMinimumRsaBits = 3072U;
constexpr std::size_t kMaximumRsaBits = 16384U;
constexpr std::string_view kPemBegin{"-----BEGIN PUBLIC KEY-----"};
constexpr std::string_view kPemEnd{"-----END PUBLIC KEY-----"};
constexpr std::string_view kZeroSha256{
    "0000000000000000000000000000000000000000000000000000000000000000"};

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
    explicit UniqueKey(BCRYPT_KEY_HANDLE handle) noexcept : handle_(handle) {}
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

template <typename T>
class LocalAllocation final {
public:
    LocalAllocation() = default;
    ~LocalAllocation() {
        if (value != nullptr) static_cast<void>(LocalFree(value));
    }
    LocalAllocation(const LocalAllocation&) = delete;
    LocalAllocation& operator=(const LocalAllocation&) = delete;

    T* value{};
};

struct VerificationKey final {
    std::string key_id;
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
    std::string android_key_sha256;
    std::string audience;
    std::string authorization_kind;
    std::string channel_binding_sha256;
    std::uint64_t expires_at_epoch{};
    std::string host_key_sha256;
    std::uint64_t issued_at_epoch{};
    bool is_permanent{};
    std::string issuer;
    std::string lease_id;
    std::uint64_t not_before_epoch{};
    std::string phase;
    std::string pair_id;
    std::string previous_ticket_sha256;
    std::uint64_t protocol_version{};
    std::uint64_t remaining_seconds{};
    std::uint64_t revocation_version{};
    std::uint64_t sequence{};
    std::string session_id;
    std::string entitlement_id;
    std::string type;
};

[[nodiscard]] HostUsageLeaseVerificationErrorV1 error(
    const HostUsageLeaseVerificationErrorCodeV1 code) noexcept {
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
    const std::string_view left, const std::string_view right) noexcept {
    return constant_time_equal(
        {reinterpret_cast<const std::uint8_t*>(left.data()), left.size()},
        {reinterpret_cast<const std::uint8_t*>(right.data()), right.size()});
}

[[nodiscard]] bool sha256(
    const std::span<const std::uint8_t> input,
    std::array<std::uint8_t, 32U>& digest) noexcept {
    if (input.size() > std::numeric_limits<ULONG>::max()) return false;
    UniqueAlgorithm algorithm;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm.handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0U);
    if (!BCRYPT_SUCCESS(status)) return false;
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

[[nodiscard]] std::string lowercase_hex(
    const std::span<const std::uint8_t> bytes) {
    constexpr std::string_view kHex{"0123456789abcdef"};
    std::string output(bytes.size() * 2U, '0');
    for (std::size_t index{}; index < bytes.size(); ++index) {
        output[index * 2U] = kHex[bytes[index] >> 4U];
        output[index * 2U + 1U] = kHex[bytes[index] & 0x0fU];
    }
    return output;
}

[[nodiscard]] bool lower_hex_valid(
    const std::string_view value,
    const std::size_t required_size,
    const bool permit_all_zero = false) noexcept {
    if (value.size() != required_size) return false;
    bool contains_nonzero{};
    for (const char character : value) {
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f'))) {
            return false;
        }
        contains_nonzero = contains_nonzero || character != '0';
    }
    return permit_all_zero || contains_nonzero;
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
    return decode_standard_base64_canonical(compact_body, canonical_spki_der);
}

[[nodiscard]] bool canonical_rsa_spki_valid(
    const std::span<const std::uint8_t> der,
    LocalAllocation<CERT_PUBLIC_KEY_INFO>& decoded) {
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
    constexpr std::array<std::uint8_t, 2U> kCanonicalNull{0x05U, 0x00U};
    if (algorithm.pszObjId == nullptr ||
        std::strcmp(algorithm.pszObjId, szOID_RSA_RSA) != 0 ||
        algorithm.Parameters.cbData != kCanonicalNull.size() ||
        algorithm.Parameters.pbData == nullptr ||
        !constant_time_equal(
            {algorithm.Parameters.pbData, algorithm.Parameters.cbData},
            kCanonicalNull) ||
        decoded.value->PublicKey.cUnusedBits != 0U) {
        return false;
    }

    LocalAllocation<std::uint8_t> reencoded;
    DWORD reencoded_size{};
    if (!CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            decoded.value,
            CRYPT_ENCODE_ALLOC_FLAG,
            nullptr,
            &reencoded.value,
            &reencoded_size) ||
        reencoded.value == nullptr || reencoded_size != der.size() ||
        !constant_time_equal(
            der, {reencoded.value, static_cast<std::size_t>(reencoded_size)})) {
        return false;
    }
    return true;
}

[[nodiscard]] bool import_verification_key(
    const std::span<const std::uint8_t> canonical_spki_der,
    VerificationKey& output) {
    LocalAllocation<CERT_PUBLIC_KEY_INFO> decoded;
    if (!canonical_rsa_spki_valid(canonical_spki_der, decoded)) return false;
    BCRYPT_KEY_HANDLE imported{};
    if (!CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING, decoded.value, 0U, nullptr, &imported) ||
        imported == nullptr) {
        return false;
    }
    UniqueKey key(imported);
    ULONG key_bits{};
    ULONG copied{};
    const NTSTATUS status = BCryptGetProperty(
        key.get(),
        BCRYPT_KEY_LENGTH,
        reinterpret_cast<PUCHAR>(&key_bits),
        sizeof(key_bits),
        &copied,
        0U);
    if (!BCRYPT_SUCCESS(status) || copied != sizeof(key_bits) ||
        key_bits < kMinimumRsaBits || key_bits > kMaximumRsaBits ||
        key_bits % 8U != 0U) {
        return false;
    }
    std::array<std::uint8_t, 32U> digest{};
    if (!sha256(canonical_spki_der, digest)) return false;
    output.key_id = lowercase_hex(std::span{digest}.first<8U>());
    output.canonical_spki_der.assign(
        canonical_spki_der.begin(), canonical_spki_der.end());
    output.signature_bytes = key_bits / 8U;
    output.public_key = std::move(key);
    return true;
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

    [[nodiscard]] bool parse_nonnegative_uint64(
        std::uint64_t& output) noexcept {
        if (offset_ >= input_.size() || input_[offset_] < '0' ||
            input_[offset_] > '9') {
            return false;
        }
        if (input_[offset_] == '0') {
            ++offset_;
            if (offset_ < input_.size() && input_[offset_] >= '0' &&
                input_[offset_] <= '9') {
                return false;
            }
            output = 0U;
            return true;
        }
        std::uint64_t value{};
        while (offset_ < input_.size() && input_[offset_] >= '0' &&
               input_[offset_] <= '9') {
            const std::uint64_t digit = input_[offset_] - '0';
            if (value > (std::numeric_limits<std::uint64_t>::max() - digit) /
                    10U) {
                return false;
            }
            value = value * 10U + digit;
            ++offset_;
        }
        output = value;
        return true;
    }

    [[nodiscard]] bool parse_boolean(bool& output) noexcept {
        if (consume("true")) {
            output = true;
            return true;
        }
        if (consume("false")) {
            output = false;
            return true;
        }
        return false;
    }

    [[nodiscard]] bool at_end() const noexcept {
        return offset_ == input_.size();
    }

private:
    std::span<const std::uint8_t> input_;
    std::size_t offset_{};
};

[[nodiscard]] bool parse_canonical_header(
    const std::span<const std::uint8_t> raw, ParsedHeader& header) {
    CanonicalJsonCursor cursor(raw);
    std::string algorithm;
    std::string token_type;
    return cursor.consume("{\"alg\":") &&
        cursor.parse_string(algorithm) && algorithm == "RS256" &&
        cursor.consume(",\"kid\":") && cursor.parse_string(header.key_id) &&
        lower_hex_valid(header.key_id, 16U) &&
        cursor.consume(",\"typ\":") && cursor.parse_string(token_type) &&
        token_type == "JWT" && cursor.consume("}") && cursor.at_end();
}

[[nodiscard]] bool parse_canonical_payload(
    const std::span<const std::uint8_t> raw, ParsedClaims& claims) {
    CanonicalJsonCursor cursor(raw);
    return cursor.consume("{\"akh\":") &&
        cursor.parse_string(claims.android_key_sha256) &&
        cursor.consume(",\"aud\":") && cursor.parse_string(claims.audience) &&
        cursor.consume(",\"authorization_kind\":") &&
        cursor.parse_string(claims.authorization_kind) &&
        cursor.consume(",\"cbh\":") &&
        cursor.parse_string(claims.channel_binding_sha256) &&
        cursor.consume(",\"exp\":") &&
        cursor.parse_nonnegative_uint64(claims.expires_at_epoch) &&
        cursor.consume(",\"hkh\":") &&
        cursor.parse_string(claims.host_key_sha256) &&
        cursor.consume(",\"iat\":") &&
        cursor.parse_nonnegative_uint64(claims.issued_at_epoch) &&
        cursor.consume(",\"is_permanent\":") &&
        cursor.parse_boolean(claims.is_permanent) &&
        cursor.consume(",\"iss\":") && cursor.parse_string(claims.issuer) &&
        cursor.consume(",\"jti\":") && cursor.parse_string(claims.lease_id) &&
        cursor.consume(",\"nbf\":") &&
        cursor.parse_nonnegative_uint64(claims.not_before_epoch) &&
        cursor.consume(",\"phase\":") && cursor.parse_string(claims.phase) &&
        cursor.consume(",\"pid\":") && cursor.parse_string(claims.pair_id) &&
        cursor.consume(",\"pth\":") &&
        cursor.parse_string(claims.previous_ticket_sha256) &&
        cursor.consume(",\"pv\":") &&
        cursor.parse_nonnegative_uint64(claims.protocol_version) &&
        cursor.consume(",\"remaining\":") &&
        cursor.parse_nonnegative_uint64(claims.remaining_seconds) &&
        cursor.consume(",\"rv\":") &&
        cursor.parse_nonnegative_uint64(claims.revocation_version) &&
        cursor.consume(",\"seq\":") &&
        cursor.parse_nonnegative_uint64(claims.sequence) &&
        cursor.consume(",\"sid\":") &&
        cursor.parse_string(claims.session_id) &&
        cursor.consume(",\"sub\":") &&
        cursor.parse_string(claims.entitlement_id) &&
        cursor.consume(",\"typ\":") && cursor.parse_string(claims.type) &&
        cursor.consume("}") && cursor.at_end();
}

[[nodiscard]] bool authorization_kind_valid(
    const std::string_view value) noexcept {
    return value == "legacy_balance" || value == "day" || value == "week" ||
        value == "month" || value == "permanent";
}

[[nodiscard]] bool previous_ticket_valid(
    const std::string_view value, const std::uint64_t sequence) noexcept {
    if (sequence == 0U) return constant_time_equal(value, kZeroSha256);
    return lower_hex_valid(value, 64U);
}

[[nodiscard]] std::string canonical_claims_without_lease_id(
    const ParsedClaims& claims) {
    std::string output;
    output.reserve(768U);
    output.append("{\"akh\":\"").append(claims.android_key_sha256);
    output.append("\",\"aud\":\"").append(claims.audience);
    output.append("\",\"authorization_kind\":\"")
        .append(claims.authorization_kind);
    output.append("\",\"cbh\":\"").append(claims.channel_binding_sha256);
    output.append("\",\"exp\":").append(std::to_string(claims.expires_at_epoch));
    output.append(",\"hkh\":\"").append(claims.host_key_sha256);
    output.append("\",\"iat\":").append(std::to_string(claims.issued_at_epoch));
    output.append(",\"is_permanent\":")
        .append(claims.is_permanent ? "true" : "false");
    output.append(",\"iss\":\"").append(claims.issuer);
    output.append("\",\"nbf\":").append(std::to_string(claims.not_before_epoch));
    output.append(",\"phase\":\"").append(claims.phase);
    output.append("\",\"pid\":\"").append(claims.pair_id);
    output.append("\",\"pth\":\"").append(claims.previous_ticket_sha256);
    output.append("\",\"pv\":").append(std::to_string(claims.protocol_version));
    output.append(",\"remaining\":")
        .append(std::to_string(claims.remaining_seconds));
    output.append(",\"rv\":").append(std::to_string(claims.revocation_version));
    output.append(",\"seq\":").append(std::to_string(claims.sequence));
    output.append(",\"sid\":\"").append(claims.session_id);
    output.append("\",\"sub\":\"").append(claims.entitlement_id);
    output.append("\",\"typ\":\"").append(claims.type).append("\"}");
    return output;
}

[[nodiscard]] bool lease_id_valid(const ParsedClaims& claims) {
    if (!lower_hex_valid(claims.lease_id, 32U)) return false;
    const std::string canonical = canonical_claims_without_lease_id(claims);
    std::array<std::uint8_t, 32U> digest{};
    if (!sha256(
            {reinterpret_cast<const std::uint8_t*>(canonical.data()),
             canonical.size()},
            digest)) {
        return false;
    }
    const std::string expected = lowercase_hex(std::span{digest}.first<16U>());
    return constant_time_equal(claims.lease_id, expected);
}

[[nodiscard]] bool expected_binding_valid(
    const UsageLeaseBinding& binding) noexcept {
    return lower_hex_valid(binding.entitlement_id, 32U) &&
        lower_hex_valid(binding.pair_id, 32U) &&
        lower_hex_valid(binding.session_id, 32U) &&
        binding.protocol_version == kUsageLeaseProtocolVersion &&
        binding.revocation_version > 0U &&
        lower_hex_valid(binding.host_key_sha256, 64U) &&
        lower_hex_valid(binding.android_key_sha256, 64U) &&
        lower_hex_valid(binding.channel_binding_sha256, 64U) &&
        !constant_time_equal(
            binding.host_key_sha256, binding.android_key_sha256);
}

[[nodiscard]] bool expected_confirmed_peer_binding_valid(
    const UsageLeaseBinding& binding) noexcept {
    return lower_hex_valid(binding.entitlement_id, 32U) &&
        lower_hex_valid(binding.pair_id, 32U) &&
        binding.session_id.empty() &&
        binding.protocol_version == kUsageLeaseProtocolVersion &&
        binding.revocation_version > 0U &&
        lower_hex_valid(binding.host_key_sha256, 64U) &&
        lower_hex_valid(binding.android_key_sha256, 64U) &&
        lower_hex_valid(binding.channel_binding_sha256, 64U) &&
        !constant_time_equal(
            binding.host_key_sha256, binding.android_key_sha256);
}

[[nodiscard]] bool claims_valid(
    const ParsedClaims& claims,
    const std::uint64_t trusted_now_epoch) {
    if (claims.type != kUsageLeaseType ||
        claims.issuer != kUsageLeaseIssuer ||
        claims.audience != kUsageLeaseAudience ||
        claims.phase != kUsageLeaseActivePhase ||
        !authorization_kind_valid(claims.authorization_kind) ||
        claims.is_permanent != (claims.authorization_kind == "permanent") ||
        (claims.is_permanent && claims.remaining_seconds != 0U) ||
        !lower_hex_valid(claims.entitlement_id, 32U) ||
        !lower_hex_valid(claims.pair_id, 32U) ||
        !lower_hex_valid(claims.session_id, 32U) ||
        !lower_hex_valid(claims.host_key_sha256, 64U) ||
        !lower_hex_valid(claims.android_key_sha256, 64U) ||
        !lower_hex_valid(claims.channel_binding_sha256, 64U) ||
        constant_time_equal(
            claims.host_key_sha256, claims.android_key_sha256) ||
        claims.protocol_version != kUsageLeaseProtocolVersion ||
        claims.revocation_version == 0U ||
        !previous_ticket_valid(
            claims.previous_ticket_sha256, claims.sequence) ||
        claims.issued_at_epoch == 0U ||
        claims.not_before_epoch < claims.issued_at_epoch ||
        claims.expires_at_epoch <= claims.not_before_epoch ||
        claims.expires_at_epoch - claims.not_before_epoch >
            kHostUsageLeaseMaximumTtlSecondsV1 ||
        claims.expires_at_epoch <= trusted_now_epoch) {
        return false;
    }
    if (claims.issued_at_epoch > trusted_now_epoch &&
        claims.issued_at_epoch - trusted_now_epoch >
            kHostUsageLeaseServerAheadGraceSecondsV1) {
        return false;
    }
    return lease_id_valid(claims);
}

[[nodiscard]] bool claims_match_expected(
    const ParsedClaims& claims,
    const UsageLeaseBinding& expected,
    const bool accept_signed_session_id) noexcept {
    return constant_time_equal(
               claims.entitlement_id, expected.entitlement_id) &&
        constant_time_equal(claims.pair_id, expected.pair_id) &&
        (accept_signed_session_id ||
            constant_time_equal(claims.session_id, expected.session_id)) &&
        claims.protocol_version == expected.protocol_version &&
        claims.revocation_version == expected.revocation_version &&
        constant_time_equal(
            claims.host_key_sha256, expected.host_key_sha256) &&
        constant_time_equal(
            claims.android_key_sha256, expected.android_key_sha256) &&
        constant_time_equal(
            claims.channel_binding_sha256,
            expected.channel_binding_sha256);
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
    BCRYPT_PKCS1_PADDING_INFO padding{.pszAlgId = BCRYPT_SHA256_ALGORITHM};
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

struct HostUsageLeaseVerifierV1::Implementation final {
    std::vector<VerificationKey> verification_keys;
};

const char* host_usage_lease_verification_error_code_name_v1(
    const HostUsageLeaseVerificationErrorCodeV1 code) noexcept {
    switch (code) {
        case HostUsageLeaseVerificationErrorCodeV1::none:
            return "none";
        case HostUsageLeaseVerificationErrorCodeV1::key_invalid:
            return "host_usage_lease_key_invalid";
        case HostUsageLeaseVerificationErrorCodeV1::source_invalid:
            return "host_usage_lease_source_invalid";
        case HostUsageLeaseVerificationErrorCodeV1::token_invalid:
            return "host_usage_lease_invalid";
        case HostUsageLeaseVerificationErrorCodeV1::crypto_unavailable:
            return "host_usage_lease_crypto_unavailable";
        case HostUsageLeaseVerificationErrorCodeV1::allocation_failed:
            return "host_usage_lease_allocation_failed";
        case HostUsageLeaseVerificationErrorCodeV1::operation_failed:
            return "host_usage_lease_operation_failed";
    }
    return "host_usage_lease_operation_failed";
}

HostUsageLeaseVerifierV1::HostUsageLeaseVerifierV1(
    std::unique_ptr<Implementation> implementation) noexcept
    : implementation_(std::move(implementation)) {}

HostUsageLeaseVerifierV1::~HostUsageLeaseVerifierV1() = default;

HostUsageLeaseVerifierConstructionResultV1
HostUsageLeaseVerifierV1::create_from_canonical_spki_der_for_internal_use(
    const std::span<const std::span<const std::uint8_t>> keys) noexcept {
    if (keys.empty() || keys.size() > 3U) {
        return {nullptr, error(
            HostUsageLeaseVerificationErrorCodeV1::key_invalid)};
    }
    try {
        auto implementation = std::make_unique<Implementation>();
        implementation->verification_keys.reserve(keys.size());
        for (const std::span<const std::uint8_t> source : keys) {
            VerificationKey key;
            if (!import_verification_key(source, key)) {
                return {nullptr, error(
                    HostUsageLeaseVerificationErrorCodeV1::key_invalid)};
            }
            for (const VerificationKey& existing :
                 implementation->verification_keys) {
                if (constant_time_equal(
                        existing.canonical_spki_der,
                        key.canonical_spki_der) ||
                    constant_time_equal(existing.key_id, key.key_id)) {
                    return {nullptr, error(
                        HostUsageLeaseVerificationErrorCodeV1::key_invalid)};
                }
            }
            implementation->verification_keys.push_back(std::move(key));
        }
        auto verifier = std::unique_ptr<HostUsageLeaseVerifierV1>(
            new HostUsageLeaseVerifierV1(std::move(implementation)));
        return {std::move(verifier), {}};
    } catch (const std::bad_alloc&) {
        return {nullptr, error(
            HostUsageLeaseVerificationErrorCodeV1::allocation_failed)};
    } catch (...) {
        return {nullptr, error(
            HostUsageLeaseVerificationErrorCodeV1::operation_failed)};
    }
}

HostUsageLeaseVerifierConstructionResultV1
HostUsageLeaseVerifierV1::create_from_build_pinned_keyring() noexcept {
    try {
        std::vector<std::vector<std::uint8_t>> owned_der;
        owned_der.reserve(build::kUsageTicketPublicPemBase64.size());
        for (const std::string_view encoded :
             build::kUsageTicketPublicPemBase64) {
            std::vector<std::uint8_t> der;
            if (!decode_public_pem_outer_base64(encoded, der)) {
                return {nullptr, error(
                    HostUsageLeaseVerificationErrorCodeV1::key_invalid)};
            }
            owned_der.push_back(std::move(der));
        }
        std::vector<std::span<const std::uint8_t>> spans;
        spans.reserve(owned_der.size());
        for (const auto& der : owned_der) spans.emplace_back(der);
        return create_from_canonical_spki_der_for_internal_use(spans);
    } catch (const std::bad_alloc&) {
        return {nullptr, error(
            HostUsageLeaseVerificationErrorCodeV1::allocation_failed)};
    } catch (...) {
        return {nullptr, error(
            HostUsageLeaseVerificationErrorCodeV1::operation_failed)};
    }
}

#if defined(VFDUAL_ENABLE_HOST_USAGE_LEASE_TEST_ACCESS)
HostUsageLeaseVerifierConstructionResultV1
HostUsageLeaseVerifierV1::create_for_test_fixture_keyring(
    const std::span<const HostUsageLeaseTestPublicKeyV1> keys) noexcept {
    try {
        std::vector<std::span<const std::uint8_t>> spans;
        spans.reserve(keys.size());
        for (const auto& key : keys) spans.push_back(key.canonical_spki_der);
        return create_from_canonical_spki_der_for_internal_use(spans);
    } catch (const std::bad_alloc&) {
        return {nullptr, error(
            HostUsageLeaseVerificationErrorCodeV1::allocation_failed)};
    } catch (...) {
        return {nullptr, error(
            HostUsageLeaseVerificationErrorCodeV1::operation_failed)};
    }
}
#endif

HostUsageLeaseVerificationResultV1 HostUsageLeaseVerifierV1::verify(
    const std::string_view compact_token_ascii,
    const UsageLeaseBinding& expected_binding,
    const std::uint64_t trusted_now_epoch) const noexcept {
    return verify_internal(
        compact_token_ascii,
        expected_binding,
        trusted_now_epoch,
        false);
}

HostUsageLeaseVerificationResultV1
HostUsageLeaseVerifierV1::verify_for_confirmed_peer_with_signed_session(
    const std::string_view compact_token_ascii,
    const UsageLeaseBinding& expected_peer_binding,
    const std::uint64_t trusted_now_epoch) const noexcept {
    return verify_internal(
        compact_token_ascii,
        expected_peer_binding,
        trusted_now_epoch,
        true);
}

HostUsageLeaseVerificationResultV1 HostUsageLeaseVerifierV1::verify_internal(
    const std::string_view compact_token_ascii,
    const UsageLeaseBinding& expected_binding,
    const std::uint64_t trusted_now_epoch,
    const bool accept_signed_session_id) const noexcept {
    const bool binding_valid = accept_signed_session_id
        ? expected_confirmed_peer_binding_valid(expected_binding)
        : expected_binding_valid(expected_binding);
    if (!binding_valid) {
        return {std::nullopt, error(
            HostUsageLeaseVerificationErrorCodeV1::source_invalid)};
    }
    if (trusted_now_epoch == 0U || implementation_ == nullptr ||
        compact_token_ascii.empty() ||
        compact_token_ascii.size() > kHostUsageLeaseMaximumTokenBytesV1) {
        return {std::nullopt, error(
            HostUsageLeaseVerificationErrorCodeV1::token_invalid)};
    }
    try {
        const std::size_t first_dot = compact_token_ascii.find('.');
        if (first_dot == std::string_view::npos || first_dot == 0U) {
            return {std::nullopt, error(
                HostUsageLeaseVerificationErrorCodeV1::token_invalid)};
        }
        const std::size_t second_dot = compact_token_ascii.find(
            '.', first_dot + 1U);
        if (second_dot == std::string_view::npos ||
            second_dot == first_dot + 1U ||
            second_dot + 1U >= compact_token_ascii.size() ||
            compact_token_ascii.find('.', second_dot + 1U) !=
                std::string_view::npos) {
            return {std::nullopt, error(
                HostUsageLeaseVerificationErrorCodeV1::token_invalid)};
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
                HostUsageLeaseVerificationErrorCodeV1::token_invalid)};
        }
        ParsedHeader header;
        if (!parse_canonical_header(header_raw, header)) {
            return {std::nullopt, error(
                HostUsageLeaseVerificationErrorCodeV1::token_invalid)};
        }
        const VerificationKey* key = select_key(
            implementation_->verification_keys, header.key_id);
        if (key == nullptr) {
            return {std::nullopt, error(
                HostUsageLeaseVerificationErrorCodeV1::token_invalid)};
        }
        const auto signing_input = std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t*>(compact_token_ascii.data()),
            second_dot};
        if (!rsa_pkcs1_sha256_signature_valid(
                *key, signing_input, signature)) {
            return {std::nullopt, error(
                HostUsageLeaseVerificationErrorCodeV1::token_invalid)};
        }
        ParsedClaims parsed;
        if (!parse_canonical_payload(payload_raw, parsed) ||
            !claims_valid(parsed, trusted_now_epoch) ||
            !claims_match_expected(
                parsed, expected_binding, accept_signed_session_id)) {
            return {std::nullopt, error(
                HostUsageLeaseVerificationErrorCodeV1::token_invalid)};
        }
        std::array<std::uint8_t, 32U> token_digest{};
        if (!sha256(
                {reinterpret_cast<const std::uint8_t*>(
                     compact_token_ascii.data()),
                 compact_token_ascii.size()},
                token_digest)) {
            return {std::nullopt, error(
                HostUsageLeaseVerificationErrorCodeV1::crypto_unavailable)};
        }
        VerifiedUsageLease lease{
            .claims = VerifiedUsageLeaseClaims{
                .type = std::move(parsed.type),
                .issuer = std::move(parsed.issuer),
                .audience = std::move(parsed.audience),
                .entitlement_id = std::move(parsed.entitlement_id),
                .pair_id = std::move(parsed.pair_id),
                .session_id = std::move(parsed.session_id),
                .protocol_version =
                    static_cast<std::uint32_t>(parsed.protocol_version),
                .revocation_version = parsed.revocation_version,
                .host_key_sha256 = std::move(parsed.host_key_sha256),
                .android_key_sha256 = std::move(parsed.android_key_sha256),
                .channel_binding_sha256 =
                    std::move(parsed.channel_binding_sha256),
                .previous_ticket_sha256 =
                    std::move(parsed.previous_ticket_sha256),
                .sequence = parsed.sequence,
                .phase = std::move(parsed.phase),
                .authorization_kind = std::move(parsed.authorization_kind),
                .is_permanent = parsed.is_permanent,
                .remaining_seconds = parsed.remaining_seconds,
                .lease_id = std::move(parsed.lease_id),
                .issued_at_epoch = parsed.issued_at_epoch,
                .not_before_epoch = parsed.not_before_epoch,
                .expires_at_epoch = parsed.expires_at_epoch,
            },
            .ticket_sha256 = lowercase_hex(token_digest),
        };
        return {std::move(lease), {}};
    } catch (const std::bad_alloc&) {
        return {std::nullopt, error(
            HostUsageLeaseVerificationErrorCodeV1::allocation_failed)};
    } catch (...) {
        return {std::nullopt, error(
            HostUsageLeaseVerificationErrorCodeV1::operation_failed)};
    }
}

}  // namespace vfdual
