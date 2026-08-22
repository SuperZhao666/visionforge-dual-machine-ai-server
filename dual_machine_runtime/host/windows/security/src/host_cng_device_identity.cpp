#include "vfdual/host_cng_device_identity.h"

#ifndef _WIN32
#error "host_cng_device_identity is a Windows-only module"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <bcrypt.h>
#include <ncrypt.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <utility>

namespace vfdual {
namespace {

constexpr std::size_t kSha256Bytes = 32U;
constexpr std::size_t kP256SignatureBytes = 64U;
constexpr std::size_t kP256PublicCoordinateBytes = 32U;
constexpr std::size_t kMaximumP256DerSignatureBytes = 72U;
constexpr std::size_t kMaximumHostIdBytes = 128U;
constexpr std::size_t kMaximumCngPropertyBytes = 4096U;
constexpr std::size_t kMaximumSignatureBytes = 512U;
constexpr std::size_t kMaximumPublicBlobBytes = 1024U;
constexpr std::size_t kMaximumTokenUserBytes = 64U * 1024U;
constexpr DWORD kCreateRaceOpenAttempts = 25U;
constexpr DWORD kCreateRaceRetryDelayMilliseconds = 10U;
constexpr NTSTATUS kStatusInvalidSignature =
    static_cast<NTSTATUS>(0xc000a000UL);

constexpr std::array<std::uint8_t, 27U> kP256SpkiPrefix{
    0x30U, 0x59U,
    0x30U, 0x13U,
    0x06U, 0x07U, 0x2aU, 0x86U, 0x48U, 0xceU, 0x3dU, 0x02U, 0x01U,
    0x06U, 0x08U, 0x2aU, 0x86U, 0x48U, 0xceU, 0x3dU, 0x03U, 0x01U, 0x07U,
    0x03U, 0x42U, 0x00U, 0x04U,
};
constexpr std::array<std::uint8_t, 32U> kP256Order{
    0xffU, 0xffU, 0xffU, 0xffU, 0x00U, 0x00U, 0x00U, 0x00U,
    0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
    0xbcU, 0xe6U, 0xfaU, 0xadU, 0xa7U, 0x17U, 0x9eU, 0x84U,
    0xf3U, 0xb9U, 0xcaU, 0xc2U, 0xfcU, 0x63U, 0x25U, 0x51U,
};
constexpr std::array<std::uint8_t, 32U> kP256HalfOrder{
    0x7fU, 0xffU, 0xffU, 0xffU, 0x80U, 0x00U, 0x00U, 0x00U,
    0x7fU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
    0xdeU, 0x73U, 0x7dU, 0x56U, 0xd3U, 0x8bU, 0xcfU, 0x42U,
    0x79U, 0xdcU, 0xe5U, 0x61U, 0x7eU, 0x31U, 0x92U, 0xa8U,
};

[[nodiscard]] HostIdentityError make_error(
    const HostIdentityErrorCode code,
    const HostIdentityNativeStatusDomain domain,
    const std::uint32_t native_status,
    const std::string_view operation) {
    return HostIdentityError{
        .code = code,
        .native_domain = domain,
        .native_status = native_status,
        .operation = std::string(operation),
    };
}

[[nodiscard]] HostIdentityError policy_error(
    const HostIdentityErrorCode code, const std::string_view operation) {
    return make_error(
        code, HostIdentityNativeStatusDomain::none, 0U, operation);
}

[[nodiscard]] HostIdentityError ncrypt_error(
    const HostIdentityErrorCode code,
    const SECURITY_STATUS status,
    const std::string_view operation) {
    return make_error(
        code,
        HostIdentityNativeStatusDomain::ncrypt_security_status,
        static_cast<std::uint32_t>(status),
        operation);
}

[[nodiscard]] HostIdentityError bcrypt_error(
    const HostIdentityErrorCode code,
    const NTSTATUS status,
    const std::string_view operation) {
    return make_error(
        code,
        HostIdentityNativeStatusDomain::bcrypt_ntstatus,
        static_cast<std::uint32_t>(status),
        operation);
}

[[nodiscard]] HostIdentityError win32_error(
    const HostIdentityErrorCode code,
    const DWORD status,
    const std::string_view operation) {
    return make_error(
        code,
        HostIdentityNativeStatusDomain::win32_error,
        static_cast<std::uint32_t>(status),
        operation);
}

class UniqueWin32Handle final {
public:
    UniqueWin32Handle() = default;
    explicit UniqueWin32Handle(HANDLE handle) noexcept : handle_(handle) {}
    ~UniqueWin32Handle() {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            (void)CloseHandle(handle_);
        }
    }
    UniqueWin32Handle(const UniqueWin32Handle&) = delete;
    UniqueWin32Handle& operator=(const UniqueWin32Handle&) = delete;
    UniqueWin32Handle(UniqueWin32Handle&&) = delete;
    UniqueWin32Handle& operator=(UniqueWin32Handle&&) = delete;

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }

private:
    HANDLE handle_{};
};

class UniqueNcryptHandle final {
public:
    UniqueNcryptHandle() = default;
    explicit UniqueNcryptHandle(const NCRYPT_HANDLE handle) noexcept
        : handle_(handle) {}
    ~UniqueNcryptHandle() {
        reset();
    }
    UniqueNcryptHandle(const UniqueNcryptHandle&) = delete;
    UniqueNcryptHandle& operator=(const UniqueNcryptHandle&) = delete;
    UniqueNcryptHandle(UniqueNcryptHandle&& other) noexcept
        : handle_(other.release()) {}
    UniqueNcryptHandle& operator=(UniqueNcryptHandle&& other) noexcept {
        if (this != &other) reset(other.release());
        return *this;
    }

    [[nodiscard]] NCRYPT_HANDLE get() const noexcept {
        return handle_;
    }
    [[nodiscard]] NCRYPT_HANDLE release() noexcept {
        return std::exchange(handle_, 0U);
    }
    void reset(const NCRYPT_HANDLE handle = 0U) noexcept {
        if (handle_ != 0U) (void)NCryptFreeObject(handle_);
        handle_ = handle;
    }

private:
    NCRYPT_HANDLE handle_{};
};

class UniqueBcryptAlgorithm final {
public:
    ~UniqueBcryptAlgorithm() {
        if (handle != nullptr) (void)BCryptCloseAlgorithmProvider(handle, 0U);
    }
    UniqueBcryptAlgorithm(const UniqueBcryptAlgorithm&) = delete;
    UniqueBcryptAlgorithm& operator=(const UniqueBcryptAlgorithm&) = delete;
    UniqueBcryptAlgorithm() = default;
    BCRYPT_ALG_HANDLE handle{};
};

class UniqueBcryptHash final {
public:
    ~UniqueBcryptHash() {
        if (handle != nullptr) (void)BCryptDestroyHash(handle);
    }
    UniqueBcryptHash(const UniqueBcryptHash&) = delete;
    UniqueBcryptHash& operator=(const UniqueBcryptHash&) = delete;
    UniqueBcryptHash() = default;
    BCRYPT_HASH_HANDLE handle{};
};

class UniqueBcryptKey final {
public:
    ~UniqueBcryptKey() {
        if (handle != nullptr) (void)BCryptDestroyKey(handle);
    }
    UniqueBcryptKey(const UniqueBcryptKey&) = delete;
    UniqueBcryptKey& operator=(const UniqueBcryptKey&) = delete;
    UniqueBcryptKey() = default;
    BCRYPT_KEY_HANDLE handle{};
};

[[nodiscard]] bool has_embedded_null(const std::wstring_view value) noexcept {
    return value.find(L'\0') != std::wstring_view::npos;
}

template <std::size_t Size>
[[nodiscard]] bool contains_nonzero(
    const std::array<std::uint8_t, Size>& value) noexcept {
    return std::any_of(value.begin(), value.end(), [](const std::uint8_t byte) {
        return byte != 0U;
    });
}

[[nodiscard]] bool is_host_id(const std::string_view value) noexcept {
    if (value.empty() || value.size() > kMaximumHostIdBytes) return false;
    return std::all_of(value.begin(), value.end(), [](const char character) {
        return (character >= 'A' && character <= 'Z') ||
            (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9') ||
            character == '.' || character == '_' || character == ':' ||
            character == '-';
    });
}

[[nodiscard]] bool is_challenge_type(
    const HostIdentityChallengeType type) noexcept {
    switch (type) {
        case HostIdentityChallengeType::pairing:
        case HostIdentityChallengeType::session_binding:
        case HostIdentityChallengeType::session_rekey:
            return true;
    }
    return false;
}

[[nodiscard]] bool is_assurance(
    const HostIdentityAssurance assurance) noexcept {
    switch (assurance) {
        case HostIdentityAssurance::formal_platform_tpm:
        case HostIdentityAssurance::non_formal_development_software:
            return true;
    }
    return false;
}

void append_u32_be(
    std::vector<std::uint8_t>& output, const std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void append_u64_be(
    std::vector<std::uint8_t>& output, const std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(
            (value >> static_cast<unsigned>(shift)) & 0xffU));
    }
}

void append_tlv(
    std::vector<std::uint8_t>& output,
    const std::uint8_t tag,
    const std::span<const std::uint8_t> value) {
    output.push_back(tag);
    append_u32_be(output, static_cast<std::uint32_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
}

[[nodiscard]] HostIdentityBytesResult sha256(
    const std::span<const std::uint8_t> input,
    const std::string_view operation) {
    if (input.size() > std::numeric_limits<ULONG>::max()) {
        return {{}, policy_error(HostIdentityErrorCode::sha256_failed, operation)};
    }

    UniqueBcryptAlgorithm algorithm;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm.handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0U);
    if (!BCRYPT_SUCCESS(status)) {
        return {{}, bcrypt_error(
            HostIdentityErrorCode::sha256_failed, status, operation)};
    }

    ULONG object_size{};
    ULONG copied{};
    status = BCryptGetProperty(
        algorithm.handle,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_size),
        sizeof(object_size),
        &copied,
        0U);
    if (!BCRYPT_SUCCESS(status) || copied != sizeof(object_size) ||
        object_size == 0U || object_size > kMaximumCngPropertyBytes) {
        return {{}, BCRYPT_SUCCESS(status)
            ? policy_error(HostIdentityErrorCode::sha256_failed, operation)
            : bcrypt_error(
                HostIdentityErrorCode::sha256_failed, status, operation)};
    }

    std::vector<std::uint8_t> hash_object(object_size);
    UniqueBcryptHash hash;
    status = BCryptCreateHash(
        algorithm.handle,
        &hash.handle,
        hash_object.data(),
        static_cast<ULONG>(hash_object.size()),
        nullptr,
        0U,
        0U);
    if (!BCRYPT_SUCCESS(status)) {
        return {{}, bcrypt_error(
            HostIdentityErrorCode::sha256_failed, status, operation)};
    }

    status = BCryptHashData(
        hash.handle,
        const_cast<PUCHAR>(input.data()),
        static_cast<ULONG>(input.size()),
        0U);
    if (!BCRYPT_SUCCESS(status)) {
        return {{}, bcrypt_error(
            HostIdentityErrorCode::sha256_failed, status, operation)};
    }

    std::vector<std::uint8_t> digest(kSha256Bytes);
    status = BCryptFinishHash(
        hash.handle,
        digest.data(),
        static_cast<ULONG>(digest.size()),
        0U);
    if (!BCRYPT_SUCCESS(status)) {
        return {{}, bcrypt_error(
            HostIdentityErrorCode::sha256_failed, status, operation)};
    }
    return {std::move(digest), {}};
}

[[nodiscard]] std::string lower_hex(
    const std::span<const std::uint8_t> bytes) {
    constexpr std::array<char, 16U> kHex{
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string result(bytes.size() * 2U, '0');
    for (std::size_t index = 0U; index < bytes.size(); ++index) {
        result[index * 2U] = kHex[(bytes[index] >> 4U) & 0x0fU];
        result[index * 2U + 1U] = kHex[bytes[index] & 0x0fU];
    }
    return result;
}

[[nodiscard]] HostIdentityBytesResult ecc_public_blob_to_spki(
    const std::span<const std::uint8_t> blob) {
    if (blob.size() < sizeof(BCRYPT_ECCKEY_BLOB)) {
        return {{}, policy_error(
            HostIdentityErrorCode::public_key_format_rejected,
            "validate_public_ecc_blob")};
    }
    BCRYPT_ECCKEY_BLOB header{};
    std::memcpy(&header, blob.data(), sizeof(header));
    const std::size_t expected = sizeof(header) +
        static_cast<std::size_t>(header.cbKey) * 2U;
    if (header.dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC ||
        header.cbKey != kP256PublicCoordinateBytes || blob.size() != expected) {
        return {{}, policy_error(
            HostIdentityErrorCode::public_key_format_rejected,
            "validate_public_ecc_blob")};
    }

    std::vector<std::uint8_t> spki;
    spki.reserve(kP256SpkiPrefix.size() + kP256SignatureBytes);
    spki.insert(spki.end(), kP256SpkiPrefix.begin(), kP256SpkiPrefix.end());
    spki.insert(
        spki.end(), blob.begin() + static_cast<std::ptrdiff_t>(sizeof(header)),
        blob.end());
    return {std::move(spki), {}};
}

[[nodiscard]] HostIdentityBytesResult spki_to_ecc_public_blob(
    const std::span<const std::uint8_t> spki) {
    const std::size_t expected_size =
        kP256SpkiPrefix.size() + kP256SignatureBytes;
    if (spki.size() != expected_size || !std::equal(
            kP256SpkiPrefix.begin(), kP256SpkiPrefix.end(), spki.begin())) {
        return {{}, policy_error(
            HostIdentityErrorCode::public_key_format_rejected,
            "parse_subject_public_key_info")};
    }

    BCRYPT_ECCKEY_BLOB header{
        .dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
        .cbKey = static_cast<ULONG>(kP256PublicCoordinateBytes),
    };
    std::vector<std::uint8_t> blob(sizeof(header) + kP256SignatureBytes);
    std::memcpy(blob.data(), &header, sizeof(header));
    std::copy(
        spki.begin() + static_cast<std::ptrdiff_t>(kP256SpkiPrefix.size()),
        spki.end(),
        blob.begin() + static_cast<std::ptrdiff_t>(sizeof(header)));
    return {std::move(blob), {}};
}

[[nodiscard]] bool scalar_is_zero(
    const std::array<std::uint8_t, 32U>& scalar) noexcept {
    return std::all_of(
        scalar.begin(), scalar.end(), [](const std::uint8_t value) {
            return value == 0U;
        });
}

[[nodiscard]] bool scalar_is_less_than(
    const std::array<std::uint8_t, 32U>& left,
    const std::array<std::uint8_t, 32U>& right) noexcept {
    return std::lexicographical_compare(
        left.begin(), left.end(), right.begin(), right.end());
}

[[nodiscard]] std::array<std::uint8_t, 32U> subtract_scalar(
    const std::array<std::uint8_t, 32U>& left,
    const std::array<std::uint8_t, 32U>& right) noexcept {
    std::array<std::uint8_t, 32U> result{};
    unsigned borrow{};
    for (std::size_t index = result.size(); index-- > 0U;) {
        const unsigned subtrahend =
            static_cast<unsigned>(right[index]) + borrow;
        if (static_cast<unsigned>(left[index]) >= subtrahend) {
            result[index] = static_cast<std::uint8_t>(
                static_cast<unsigned>(left[index]) - subtrahend);
            borrow = 0U;
        } else {
            result[index] = static_cast<std::uint8_t>(
                0x100U + static_cast<unsigned>(left[index]) - subtrahend);
            borrow = 1U;
        }
    }
    return result;
}

void append_der_integer(
    std::vector<std::uint8_t>& output,
    const std::array<std::uint8_t, 32U>& scalar) {
    const auto first_nonzero = std::find_if(
        scalar.begin(), scalar.end(), [](const std::uint8_t value) {
            return value != 0U;
        });
    const bool needs_positive_prefix = (*first_nonzero & 0x80U) != 0U;
    const std::size_t scalar_bytes = static_cast<std::size_t>(
        scalar.end() - first_nonzero);
    output.push_back(0x02U);
    output.push_back(static_cast<std::uint8_t>(
        scalar_bytes + (needs_positive_prefix ? 1U : 0U)));
    if (needs_positive_prefix) output.push_back(0x00U);
    output.insert(output.end(), first_nonzero, scalar.end());
}

[[nodiscard]] HostIdentityBytesResult p1363_to_canonical_der(
    const std::span<const std::uint8_t> signature) {
    if (signature.size() != kP256SignatureBytes) {
        return {{}, policy_error(
            HostIdentityErrorCode::signature_failed,
            "validate_p1363_signature_size")};
    }
    std::array<std::uint8_t, 32U> r{};
    std::array<std::uint8_t, 32U> s{};
    std::copy_n(signature.begin(), r.size(), r.begin());
    std::copy_n(
        signature.begin() + static_cast<std::ptrdiff_t>(r.size()),
        s.size(), s.begin());
    if (scalar_is_zero(r) || scalar_is_zero(s) ||
        !scalar_is_less_than(r, kP256Order) ||
        !scalar_is_less_than(s, kP256Order)) {
        return {{}, policy_error(
            HostIdentityErrorCode::signature_failed,
            "validate_p256_signature_scalars")};
    }
    if (scalar_is_less_than(kP256HalfOrder, s)) {
        s = subtract_scalar(kP256Order, s);
    }

    std::vector<std::uint8_t> payload;
    payload.reserve(70U);
    append_der_integer(payload, r);
    append_der_integer(payload, s);
    std::vector<std::uint8_t> der;
    der.reserve(payload.size() + 2U);
    der.push_back(0x30U);
    der.push_back(static_cast<std::uint8_t>(payload.size()));
    der.insert(der.end(), payload.begin(), payload.end());
    if (der.size() > kMaximumP256DerSignatureBytes) {
        return {{}, policy_error(
            HostIdentityErrorCode::signature_failed,
            "validate_der_signature_size")};
    }
    return {std::move(der), {}};
}

[[nodiscard]] bool parse_der_scalar(
    const std::span<const std::uint8_t> signature,
    std::size_t& offset,
    std::array<std::uint8_t, 32U>& scalar) noexcept {
    if (offset + 2U > signature.size() || signature[offset] != 0x02U) {
        return false;
    }
    const std::size_t length = signature[offset + 1U];
    offset += 2U;
    if (length == 0U || length > 33U ||
        offset + length > signature.size()) {
        return false;
    }
    const std::span<const std::uint8_t> encoded =
        signature.subspan(offset, length);
    offset += length;
    if ((encoded.front() & 0x80U) != 0U ||
        (encoded.size() > 1U && encoded.front() == 0U &&
            (encoded[1U] & 0x80U) == 0U)) {
        return false;
    }
    const std::span<const std::uint8_t> magnitude =
        encoded.size() == 33U ? encoded.subspan(1U) : encoded;
    if (magnitude.size() > scalar.size() ||
        (encoded.size() == 33U && encoded.front() != 0U)) {
        return false;
    }
    std::copy(
        magnitude.begin(), magnitude.end(),
        scalar.end() - static_cast<std::ptrdiff_t>(magnitude.size()));
    return !scalar_is_zero(scalar) && scalar_is_less_than(scalar, kP256Order);
}

[[nodiscard]] HostIdentityBytesResult canonical_der_to_p1363(
    const std::span<const std::uint8_t> signature) {
    if (signature.size() < 8U ||
        signature.size() > kMaximumP256DerSignatureBytes ||
        signature[0U] != 0x30U ||
        signature[1U] != signature.size() - 2U) {
        return {{}, policy_error(
            HostIdentityErrorCode::signature_format_rejected,
            "validate_der_signature_sequence")};
    }
    std::size_t offset = 2U;
    std::array<std::uint8_t, 32U> r{};
    std::array<std::uint8_t, 32U> s{};
    if (!parse_der_scalar(signature, offset, r) ||
        !parse_der_scalar(signature, offset, s) ||
        offset != signature.size() ||
        scalar_is_less_than(kP256HalfOrder, s)) {
        return {{}, policy_error(
            HostIdentityErrorCode::signature_format_rejected,
            "validate_canonical_low_s_signature")};
    }
    std::vector<std::uint8_t> p1363;
    p1363.reserve(kP256SignatureBytes);
    p1363.insert(p1363.end(), r.begin(), r.end());
    p1363.insert(p1363.end(), s.begin(), s.end());
    return {std::move(p1363), {}};
}

[[nodiscard]] HostIdentityError verify_canonical_p256_signature_for_digest(
    const std::span<const std::uint8_t> subject_public_key_info_der,
    const std::span<const std::uint8_t> digest,
    const std::span<const std::uint8_t> signature_der) {
    HostIdentityBytesResult normalized_raw =
        canonical_der_to_p1363(signature_der);
    if (!normalized_raw.succeeded()) return std::move(normalized_raw.error);

    HostIdentityBytesResult public_blob = spki_to_ecc_public_blob(
        subject_public_key_info_der);
    if (!public_blob.succeeded()) return std::move(public_blob.error);

    UniqueBcryptAlgorithm algorithm;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm.handle, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0U);
    if (!BCRYPT_SUCCESS(status)) {
        return bcrypt_error(
            HostIdentityErrorCode::signature_failed,
            status,
            "open_peer_handshake_signature_verifier");
    }
    UniqueBcryptKey public_key;
    status = BCryptImportKeyPair(
        algorithm.handle,
        nullptr,
        BCRYPT_ECCPUBLIC_BLOB,
        &public_key.handle,
        public_blob.bytes.data(),
        static_cast<ULONG>(public_blob.bytes.size()),
        0U);
    if (!BCRYPT_SUCCESS(status)) {
        return bcrypt_error(
            HostIdentityErrorCode::signature_failed,
            status,
            "import_peer_handshake_signature_verifier");
    }
    status = BCryptVerifySignature(
        public_key.handle,
        nullptr,
        const_cast<PUCHAR>(digest.data()),
        static_cast<ULONG>(digest.size()),
        normalized_raw.bytes.data(),
        static_cast<ULONG>(normalized_raw.bytes.size()),
        0U);
    if (BCRYPT_SUCCESS(status)) return {};
    return status == kStatusInvalidSignature
        ? policy_error(
            HostIdentityErrorCode::signature_failed,
            "post_sign_verify_peer_handshake_transcript")
        : bcrypt_error(
            HostIdentityErrorCode::signature_failed,
            status,
            "verify_peer_handshake_transcript_signature");
}

[[nodiscard]] bool read_ncrypt_dword(
    const NCRYPT_HANDLE handle,
    LPCWSTR property,
    const std::string_view operation,
    std::uint32_t& value,
    HostIdentityError& error) {
    DWORD native_value{};
    DWORD copied{};
    const SECURITY_STATUS status = NCryptGetProperty(
        handle,
        property,
        reinterpret_cast<PBYTE>(&native_value),
        sizeof(native_value),
        &copied,
        0U);
    if (status != ERROR_SUCCESS) {
        error = ncrypt_error(
            HostIdentityErrorCode::key_property_read_failed,
            status,
            operation);
        return false;
    }
    if (copied != sizeof(native_value)) {
        error = policy_error(
            HostIdentityErrorCode::key_property_read_failed, operation);
        return false;
    }
    value = native_value;
    return true;
}

[[nodiscard]] bool read_ncrypt_wstring(
    const NCRYPT_HANDLE handle,
    LPCWSTR property,
    const std::string_view operation,
    std::wstring& value,
    HostIdentityError& error) {
    DWORD required{};
    SECURITY_STATUS status = NCryptGetProperty(
        handle, property, nullptr, 0U, &required, 0U);
    if (status != ERROR_SUCCESS) {
        error = ncrypt_error(
            HostIdentityErrorCode::key_property_read_failed,
            status,
            operation);
        return false;
    }
    if (required < sizeof(wchar_t) ||
        required > kMaximumCngPropertyBytes ||
        required % sizeof(wchar_t) != 0U) {
        error = policy_error(
            HostIdentityErrorCode::key_property_read_failed, operation);
        return false;
    }

    std::vector<wchar_t> buffer(required / sizeof(wchar_t), L'\0');
    DWORD copied{};
    status = NCryptGetProperty(
        handle,
        property,
        reinterpret_cast<PBYTE>(buffer.data()),
        required,
        &copied,
        0U);
    if (status != ERROR_SUCCESS) {
        error = ncrypt_error(
            HostIdentityErrorCode::key_property_read_failed,
            status,
            operation);
        return false;
    }
    if (copied < sizeof(wchar_t) || copied > required ||
        copied % sizeof(wchar_t) != 0U) {
        error = policy_error(
            HostIdentityErrorCode::key_property_read_failed, operation);
        return false;
    }
    const std::size_t character_count = copied / sizeof(wchar_t);
    const auto terminator = std::find(
        buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(character_count),
        L'\0');
    if (terminator == buffer.begin() +
            static_cast<std::ptrdiff_t>(character_count)) {
        error = policy_error(
            HostIdentityErrorCode::key_property_read_failed, operation);
        return false;
    }
    value.assign(buffer.begin(), terminator);
    return true;
}

[[nodiscard]] bool set_ncrypt_dword(
    const NCRYPT_KEY_HANDLE key,
    LPCWSTR property,
    DWORD value,
    const std::string_view operation,
    HostIdentityError& error) {
    const SECURITY_STATUS status = NCryptSetProperty(
        key,
        property,
        reinterpret_cast<PBYTE>(&value),
        sizeof(value),
        NCRYPT_PERSIST_FLAG);
    if (status == ERROR_SUCCESS) return true;
    error = ncrypt_error(
        HostIdentityErrorCode::key_property_write_failed,
        status,
        operation);
    return false;
}

[[nodiscard]] bool sid_bytes_are_valid(
    const std::span<const std::uint8_t> sid) noexcept {
    constexpr std::size_t kSidFixedBytes = 8U;
    if (sid.size() < kSidFixedBytes) return false;
    const std::uint8_t sub_authority_count = sid[1U];
    if (sub_authority_count > SID_MAX_SUB_AUTHORITIES) return false;
    const std::size_t required =
        kSidFixedBytes + sizeof(DWORD) * sub_authority_count;
    return sid.size() == required && sid[0U] == SID_REVISION;
}

[[nodiscard]] bool sid_bytes_equal(
    const std::span<const std::uint8_t> left,
    const std::span<const std::uint8_t> right) noexcept {
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin());
}

[[nodiscard]] bool copy_well_known_sid(
    const WELL_KNOWN_SID_TYPE type,
    std::vector<std::uint8_t>& sid,
    HostIdentityError& error) {
    DWORD required = SECURITY_MAX_SID_SIZE;
    sid.assign(required, 0U);
    if (!CreateWellKnownSid(type, nullptr, sid.data(), &required)) {
        error = win32_error(
            HostIdentityErrorCode::key_access_control_failed,
            GetLastError(),
            "create_formal_principal_sid");
        sid.clear();
        return false;
    }
    if (required == 0U || required > sid.size()) {
        error = policy_error(
            HostIdentityErrorCode::key_access_control_failed,
            "validate_formal_principal_sid_size");
        sid.clear();
        return false;
    }
    sid.resize(required);
    if (!sid_bytes_are_valid(sid)) {
        error = policy_error(
            HostIdentityErrorCode::key_access_control_failed,
            "validate_formal_principal_sid");
        sid.clear();
        return false;
    }
    return true;
}

[[nodiscard]] bool collect_formal_machine_key_principals(
    const std::span<const std::uint8_t> authorized_user_sid,
    std::vector<std::vector<std::uint8_t>>& principals,
    HostIdentityError& error) {
    if (!sid_bytes_are_valid(authorized_user_sid)) {
        error = policy_error(
            HostIdentityErrorCode::key_access_control_failed,
            "validate_authorized_user_sid");
        return false;
    }

    std::vector<std::uint8_t> local_system_sid;
    std::vector<std::uint8_t> administrators_sid;
    if (!copy_well_known_sid(
            WinLocalSystemSid, local_system_sid, error) ||
        !copy_well_known_sid(
            WinBuiltinAdministratorsSid, administrators_sid, error)) {
        return false;
    }

    principals.clear();
    principals.reserve(3U);
    const auto add_distinct = [&principals](
        const std::span<const std::uint8_t> candidate) {
        const bool already_present = std::any_of(
            principals.begin(), principals.end(),
            [candidate](const std::vector<std::uint8_t>& existing) {
                return sid_bytes_equal(existing, candidate);
            });
        if (!already_present) {
            principals.emplace_back(candidate.begin(), candidate.end());
        }
    };
    add_distinct(local_system_sid);
    add_distinct(administrators_sid);
    add_distinct(authorized_user_sid);
    return true;
}

[[nodiscard]] bool validate_formal_machine_key_security_descriptor_impl(
    const std::span<const std::uint8_t> descriptor,
    const std::span<const std::uint8_t> authorized_user_sid,
    HostIdentityError& error) {
    const auto reject = [&error](const std::string_view operation) {
        error = policy_error(
            HostIdentityErrorCode::key_access_control_failed, operation);
        return false;
    };

    std::vector<std::vector<std::uint8_t>> expected_principals;
    if (!collect_formal_machine_key_principals(
            authorized_user_sid, expected_principals, error)) {
        return false;
    }
    if (descriptor.size() < sizeof(SECURITY_DESCRIPTOR_RELATIVE)) {
        return reject("validate_formal_security_descriptor_size");
    }

    SECURITY_DESCRIPTOR_RELATIVE relative{};
    std::memcpy(&relative, descriptor.data(), sizeof(relative));
    if (relative.Revision != SECURITY_DESCRIPTOR_REVISION ||
        (relative.Control & SE_SELF_RELATIVE) == 0U ||
        (relative.Control & SE_DACL_PRESENT) == 0U ||
        (relative.Control & SE_DACL_PROTECTED) == 0U ||
        relative.Dacl < sizeof(SECURITY_DESCRIPTOR_RELATIVE) ||
        relative.Dacl > descriptor.size() - sizeof(ACL) ||
        relative.Dacl % alignof(DWORD) != 0U) {
        return reject("validate_formal_protected_dacl_header");
    }

    ACL acl{};
    std::memcpy(&acl, descriptor.data() + relative.Dacl, sizeof(acl));
    if (acl.AclRevision != ACL_REVISION ||
        acl.AclSize < sizeof(ACL) ||
        acl.AclSize > descriptor.size() - relative.Dacl ||
        acl.AceCount != expected_principals.size()) {
        return reject("validate_formal_dacl_shape");
    }

    std::vector<bool> principal_seen(expected_principals.size(), false);
    std::size_t ace_offset = sizeof(ACL);
    for (std::size_t index{}; index < acl.AceCount; ++index) {
        if (ace_offset > acl.AclSize - sizeof(ACE_HEADER)) {
            return reject("validate_formal_ace_bounds");
        }
        ACE_HEADER ace_header{};
        std::memcpy(
            &ace_header,
            descriptor.data() + relative.Dacl + ace_offset,
            sizeof(ace_header));
        constexpr std::size_t kAllowedAceSidOffset =
            offsetof(ACCESS_ALLOWED_ACE, SidStart);
        if (ace_header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            ace_header.AceFlags != 0U ||
            ace_header.AceSize < kAllowedAceSidOffset + 8U ||
            ace_header.AceSize > acl.AclSize - ace_offset) {
            return reject("validate_formal_allow_ace");
        }

        ACCESS_MASK access_mask{};
        std::memcpy(
            &access_mask,
            descriptor.data() + relative.Dacl + ace_offset +
                sizeof(ACE_HEADER),
            sizeof(access_mask));
        if (access_mask != GENERIC_ALL) {
            return reject("validate_formal_ace_access_mask");
        }

        const std::size_t sid_offset =
            relative.Dacl + ace_offset + kAllowedAceSidOffset;
        const std::size_t maximum_sid_size =
            ace_header.AceSize - kAllowedAceSidOffset;
        const auto sid_prefix = descriptor.subspan(
            sid_offset, maximum_sid_size);
        if (sid_prefix.size() < 8U ||
            sid_prefix[1U] > SID_MAX_SUB_AUTHORITIES) {
            return reject("validate_formal_ace_sid");
        }
        const std::size_t sid_size =
            8U + sizeof(DWORD) * sid_prefix[1U];
        if (sid_size != maximum_sid_size) {
            return reject("validate_formal_ace_sid_size");
        }
        const auto sid = sid_prefix.first(sid_size);
        if (!sid_bytes_are_valid(sid)) {
            return reject("validate_formal_ace_sid");
        }

        std::optional<std::size_t> principal_index;
        for (std::size_t principal{};
             principal < expected_principals.size(); ++principal) {
            if (sid_bytes_equal(sid, expected_principals[principal])) {
                principal_index = principal;
                break;
            }
        }
        if (!principal_index.has_value() ||
            principal_seen[*principal_index]) {
            return reject("validate_formal_ace_principal_set");
        }
        principal_seen[*principal_index] = true;
        ace_offset += ace_header.AceSize;
    }
    if (ace_offset != acl.AclSize ||
        std::any_of(
            principal_seen.begin(), principal_seen.end(),
            [](const bool seen) { return !seen; })) {
        return reject("validate_formal_dacl_principal_completeness");
    }
    error = {};
    return true;
}

[[nodiscard]] bool read_current_process_user_sid(
    std::vector<std::uint8_t>& user_sid,
    HostIdentityError& error) {
    HANDLE token_handle{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token_handle)) {
        error = win32_error(
            HostIdentityErrorCode::key_access_control_failed,
            GetLastError(),
            "open_current_process_token");
        return false;
    }
    UniqueWin32Handle token(token_handle);

    DWORD required{};
    if (GetTokenInformation(
            token.get(), TokenUser, nullptr, 0U, &required) != FALSE ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        required < sizeof(TOKEN_USER) ||
        required > kMaximumTokenUserBytes) {
        error = win32_error(
            HostIdentityErrorCode::key_access_control_failed,
            GetLastError(),
            "query_current_process_user_size");
        return false;
    }

    std::vector<std::uint8_t> token_user_buffer(required, 0U);
    if (!GetTokenInformation(
            token.get(), TokenUser, token_user_buffer.data(), required,
            &required)) {
        error = win32_error(
            HostIdentityErrorCode::key_access_control_failed,
            GetLastError(),
            "read_current_process_user");
        return false;
    }
    const auto* token_user =
        reinterpret_cast<const TOKEN_USER*>(token_user_buffer.data());
    if (token_user->User.Sid == nullptr ||
        !IsValidSid(token_user->User.Sid)) {
        error = policy_error(
            HostIdentityErrorCode::key_access_control_failed,
            "validate_current_process_user_sid");
        return false;
    }
    const DWORD sid_size = GetLengthSid(token_user->User.Sid);
    if (sid_size == 0U || sid_size > SECURITY_MAX_SID_SIZE) {
        error = policy_error(
            HostIdentityErrorCode::key_access_control_failed,
            "validate_current_process_user_sid_size");
        return false;
    }
    user_sid.assign(sid_size, 0U);
    if (!CopySid(sid_size, user_sid.data(), token_user->User.Sid) ||
        !sid_bytes_are_valid(user_sid)) {
        error = win32_error(
            HostIdentityErrorCode::key_access_control_failed,
            GetLastError(),
            "copy_current_process_user_sid");
        user_sid.clear();
        return false;
    }
    return true;
}

[[nodiscard]] bool build_formal_machine_key_security_descriptor(
    const std::span<const std::uint8_t> authorized_user_sid,
    std::vector<std::uint8_t>& descriptor,
    HostIdentityError& error) {
    std::vector<std::vector<std::uint8_t>> principals;
    if (!collect_formal_machine_key_principals(
            authorized_user_sid, principals, error)) {
        return false;
    }

    std::size_t acl_size = sizeof(ACL);
    for (const auto& sid : principals) {
        acl_size += offsetof(ACCESS_ALLOWED_ACE, SidStart) + sid.size();
    }
    if (acl_size > (std::numeric_limits<WORD>::max)()) {
        error = policy_error(
            HostIdentityErrorCode::key_access_control_failed,
            "validate_formal_dacl_size");
        return false;
    }
    std::vector<std::uint8_t> acl_bytes(acl_size, 0U);
    auto* acl = reinterpret_cast<ACL*>(acl_bytes.data());
    if (!InitializeAcl(
            acl, static_cast<DWORD>(acl_bytes.size()), ACL_REVISION)) {
        error = win32_error(
            HostIdentityErrorCode::key_access_control_failed,
            GetLastError(),
            "initialize_formal_dacl");
        return false;
    }
    for (const auto& sid : principals) {
        if (!AddAccessAllowedAceEx(
                acl, ACL_REVISION, 0U, GENERIC_ALL,
                const_cast<std::uint8_t*>(sid.data()))) {
            error = win32_error(
                HostIdentityErrorCode::key_access_control_failed,
                GetLastError(),
                "add_formal_dacl_principal");
            return false;
        }
    }

    SECURITY_DESCRIPTOR absolute{};
    if (!InitializeSecurityDescriptor(
            &absolute, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&absolute, TRUE, acl, FALSE) ||
        !SetSecurityDescriptorControl(
            &absolute, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
        error = win32_error(
            HostIdentityErrorCode::key_access_control_failed,
            GetLastError(),
            "build_formal_security_descriptor");
        return false;
    }

    DWORD required{};
    if (MakeSelfRelativeSD(&absolute, nullptr, &required) != FALSE ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        required < sizeof(SECURITY_DESCRIPTOR_RELATIVE) ||
        required > kMaximumTokenUserBytes) {
        error = win32_error(
            HostIdentityErrorCode::key_access_control_failed,
            GetLastError(),
            "query_formal_security_descriptor_size");
        return false;
    }
    descriptor.assign(required, 0U);
    if (!MakeSelfRelativeSD(&absolute, descriptor.data(), &required)) {
        error = win32_error(
            HostIdentityErrorCode::key_access_control_failed,
            GetLastError(),
            "make_formal_security_descriptor_self_relative");
        descriptor.clear();
        return false;
    }
    descriptor.resize(required);
    return validate_formal_machine_key_security_descriptor_impl(
        descriptor, authorized_user_sid, error);
}

[[nodiscard]] bool provider_supports_key_security_descriptors(
    const NCRYPT_PROV_HANDLE provider,
    HostIdentityError& error) {
    DWORD supported{};
    DWORD copied{};
    const SECURITY_STATUS status = NCryptGetProperty(
        provider,
        NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY,
        reinterpret_cast<PBYTE>(&supported),
        sizeof(supported),
        &copied,
        NCRYPT_SILENT_FLAG);
    if (status != ERROR_SUCCESS) {
        error = ncrypt_error(
            HostIdentityErrorCode::key_access_control_failed,
            status,
            "read_security_descriptor_support");
        return false;
    }
    if (copied != sizeof(supported) || supported != 1U) {
        error = policy_error(
            HostIdentityErrorCode::key_access_control_failed,
            "validate_security_descriptor_support");
        return false;
    }
    return true;
}

[[nodiscard]] bool set_and_verify_formal_machine_key_dacl(
    const NCRYPT_KEY_HANDLE key,
    const std::span<const std::uint8_t> authorized_user_sid,
    HostIdentityError& error) {
    std::vector<std::uint8_t> expected_descriptor;
    if (!build_formal_machine_key_security_descriptor(
            authorized_user_sid, expected_descriptor, error)) {
        return false;
    }
    const DWORD security_flags =
        NCRYPT_PERSIST_FLAG | NCRYPT_SILENT_FLAG |
        DACL_SECURITY_INFORMATION;
    SECURITY_STATUS status = NCryptSetProperty(
        key,
        NCRYPT_SECURITY_DESCR_PROPERTY,
        expected_descriptor.data(),
        static_cast<DWORD>(expected_descriptor.size()),
        security_flags);
    if (status != ERROR_SUCCESS) {
        error = ncrypt_error(
            HostIdentityErrorCode::key_access_control_failed,
            status,
            "persist_formal_machine_key_dacl");
        return false;
    }

    constexpr DWORD kReadSecurityFlags =
        NCRYPT_SILENT_FLAG | DACL_SECURITY_INFORMATION;
    DWORD required{};
    status = NCryptGetProperty(
        key, NCRYPT_SECURITY_DESCR_PROPERTY, nullptr, 0U, &required,
        kReadSecurityFlags);
    if (status != ERROR_SUCCESS ||
        required < sizeof(SECURITY_DESCRIPTOR_RELATIVE) ||
        required > kMaximumTokenUserBytes) {
        error = status == ERROR_SUCCESS
            ? policy_error(
                HostIdentityErrorCode::key_access_control_failed,
                "validate_persisted_formal_dacl_size")
            : ncrypt_error(
                HostIdentityErrorCode::key_access_control_failed,
                status,
                "read_persisted_formal_dacl_size");
        return false;
    }
    std::vector<std::uint8_t> persisted(required, 0U);
    DWORD copied{};
    status = NCryptGetProperty(
        key,
        NCRYPT_SECURITY_DESCR_PROPERTY,
        persisted.data(),
        required,
        &copied,
        kReadSecurityFlags);
    if (status != ERROR_SUCCESS) {
        error = ncrypt_error(
            HostIdentityErrorCode::key_access_control_failed,
            status,
            "read_persisted_formal_dacl");
        return false;
    }
    if (copied != required) {
        error = policy_error(
            HostIdentityErrorCode::key_access_control_failed,
            "validate_persisted_formal_dacl_size");
        return false;
    }
    persisted.resize(copied);
    return validate_formal_machine_key_security_descriptor_impl(
        persisted, authorized_user_sid, error);
}

class WindowsCngSigningKey final : public CngSigningKey {
public:
    WindowsCngSigningKey(
        const NCRYPT_KEY_HANDLE key, CngKeyMetadata metadata)
        : key_(key), metadata_(std::move(metadata)) {}

    [[nodiscard]] const CngKeyMetadata& metadata() const noexcept override {
        return metadata_;
    }

    [[nodiscard]] HostIdentityBytesResult export_public_ecc_blob() override {
        DWORD required{};
        SECURITY_STATUS status = NCryptExportKey(
            static_cast<NCRYPT_KEY_HANDLE>(key_.get()),
            0U,
            BCRYPT_ECCPUBLIC_BLOB,
            nullptr,
            nullptr,
            0U,
            &required,
            0U);
        if (status != ERROR_SUCCESS) {
            return {{}, ncrypt_error(
                HostIdentityErrorCode::public_key_export_failed,
                status,
                "export_public_ecc_blob_size")};
        }
        if (required < sizeof(BCRYPT_ECCKEY_BLOB) ||
            required > kMaximumPublicBlobBytes) {
            return {{}, policy_error(
                HostIdentityErrorCode::public_key_format_rejected,
                "validate_public_ecc_blob_size")};
        }
        std::vector<std::uint8_t> blob(required);
        DWORD copied{};
        status = NCryptExportKey(
            static_cast<NCRYPT_KEY_HANDLE>(key_.get()),
            0U,
            BCRYPT_ECCPUBLIC_BLOB,
            nullptr,
            blob.data(),
            static_cast<DWORD>(blob.size()),
            &copied,
            0U);
        if (status != ERROR_SUCCESS) {
            return {{}, ncrypt_error(
                HostIdentityErrorCode::public_key_export_failed,
                status,
                "export_public_ecc_blob")};
        }
        if (copied != blob.size()) {
            return {{}, policy_error(
                HostIdentityErrorCode::public_key_format_rejected,
                "validate_public_ecc_blob_size")};
        }
        return {std::move(blob), {}};
    }

    [[nodiscard]] HostIdentityBytesResult sign_sha256_digest(
        const std::span<const std::uint8_t> digest) override {
        if (digest.size() != kSha256Bytes) {
            return {{}, policy_error(
                HostIdentityErrorCode::signature_failed,
                "validate_sha256_digest")};
        }

        DWORD required{};
        SECURITY_STATUS status = NCryptSignHash(
            static_cast<NCRYPT_KEY_HANDLE>(key_.get()),
            nullptr,
            const_cast<PBYTE>(digest.data()),
            static_cast<DWORD>(digest.size()),
            nullptr,
            0U,
            &required,
            NCRYPT_SILENT_FLAG);
        if (status != ERROR_SUCCESS) {
            return {{}, ncrypt_error(
                HostIdentityErrorCode::signature_failed,
                status,
                "sign_sha256_digest_size")};
        }
        if (required != kP256SignatureBytes ||
            required > kMaximumSignatureBytes) {
            return {{}, policy_error(
                HostIdentityErrorCode::signature_failed,
                "validate_signature_size")};
        }

        std::vector<std::uint8_t> signature(required);
        DWORD copied{};
        status = NCryptSignHash(
            static_cast<NCRYPT_KEY_HANDLE>(key_.get()),
            nullptr,
            const_cast<PBYTE>(digest.data()),
            static_cast<DWORD>(digest.size()),
            signature.data(),
            static_cast<DWORD>(signature.size()),
            &copied,
            NCRYPT_SILENT_FLAG);
        if (status != ERROR_SUCCESS) {
            return {{}, ncrypt_error(
                HostIdentityErrorCode::signature_failed,
                status,
                "sign_sha256_digest")};
        }
        if (copied != signature.size()) {
            return {{}, policy_error(
                HostIdentityErrorCode::signature_failed,
                "validate_signature_size")};
        }
        return {std::move(signature), {}};
    }

    [[nodiscard]] HostIdentityError
    discard_new_persisted_key_after_failed_initialization() override {
        const auto key_handle =
            static_cast<NCRYPT_KEY_HANDLE>(key_.release());
        if (key_handle == 0U) {
            return policy_error(
                HostIdentityErrorCode::key_cleanup_failed,
                "discard_missing_new_persisted_key_handle");
        }
        const SECURITY_STATUS status = NCryptDeleteKey(
            key_handle, NCRYPT_SILENT_FLAG);
        if (status == ERROR_SUCCESS) return {};
        (void)NCryptFreeObject(key_handle);
        return ncrypt_error(
            HostIdentityErrorCode::key_cleanup_failed,
            status,
            "delete_new_persisted_key_after_failed_initialization");
    }

private:
    UniqueNcryptHandle key_;
    CngKeyMetadata metadata_;
};

[[nodiscard]] bool open_or_create_persisted_key(
    const NCRYPT_PROV_HANDLE provider,
    const CngKeyOpenRequest& request,
    UniqueNcryptHandle& key,
    bool& created,
    HostIdentityError& error) {
    const DWORD scope_flags = request.machine_scope
        ? NCRYPT_MACHINE_KEY_FLAG : 0U;
    NCRYPT_KEY_HANDLE key_handle{};
    SECURITY_STATUS status = NCryptOpenKey(
        provider,
        &key_handle,
        request.persistent_key_name.c_str(),
        0U,
        scope_flags | NCRYPT_SILENT_FLAG);

    created = false;
    if (status == static_cast<SECURITY_STATUS>(NTE_BAD_KEYSET) ||
        status == static_cast<SECURITY_STATUS>(NTE_NOT_FOUND)) {
        status = NCryptCreatePersistedKey(
            provider,
            &key_handle,
            NCRYPT_ECDSA_P256_ALGORITHM,
            request.persistent_key_name.c_str(),
            0U,
            scope_flags);
        if (status == static_cast<SECURITY_STATUS>(NTE_EXISTS)) {
            if (key_handle != 0U) (void)NCryptFreeObject(key_handle);
            key_handle = 0U;
            for (DWORD attempt{}; attempt < kCreateRaceOpenAttempts; ++attempt) {
                status = NCryptOpenKey(
                    provider,
                    &key_handle,
                    request.persistent_key_name.c_str(),
                    0U,
                    scope_flags | NCRYPT_SILENT_FLAG);
                if (status == ERROR_SUCCESS) break;
                const bool creation_still_in_progress =
                    status == static_cast<SECURITY_STATUS>(NTE_BAD_KEYSET) ||
                    status == static_cast<SECURITY_STATUS>(NTE_NOT_FOUND) ||
                    status == static_cast<SECURITY_STATUS>(NTE_BAD_KEY_STATE);
                if (!creation_still_in_progress ||
                    attempt + 1U == kCreateRaceOpenAttempts) {
                    break;
                }
                Sleep(kCreateRaceRetryDelayMilliseconds);
            }
        } else if (status == ERROR_SUCCESS) {
            created = true;
        }
    }
    if (status != ERROR_SUCCESS) {
        if (key_handle != 0U) (void)NCryptFreeObject(key_handle);
        error = ncrypt_error(
            HostIdentityErrorCode::key_open_or_create_failed,
            status,
            "open_or_create_persisted_key");
        return false;
    }
    if (key_handle == 0U) {
        error = policy_error(
            HostIdentityErrorCode::key_open_or_create_failed,
            "validate_opened_key_handle");
        return false;
    }
    key.reset(key_handle);
    return true;
}

[[nodiscard]] bool configure_new_persisted_key(
    const NCRYPT_KEY_HANDLE key, HostIdentityError& error) {
    if (!set_ncrypt_dword(
            key,
            NCRYPT_KEY_USAGE_PROPERTY,
            NCRYPT_ALLOW_SIGNING_FLAG,
            "set_signing_only_usage",
            error)) {
        return false;
    }
    constexpr DWORD kNoPrivateExport = 0U;
    if (!set_ncrypt_dword(
            key,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            kNoPrivateExport,
            "set_non_exportable_policy",
            error)) {
        return false;
    }
    const SECURITY_STATUS status = NCryptFinalizeKey(
        key, NCRYPT_SILENT_FLAG);
    if (status == ERROR_SUCCESS) return true;
    error = ncrypt_error(
        HostIdentityErrorCode::key_finalize_failed,
        status,
        "finalize_persisted_key");
    return false;
}

[[nodiscard]] bool delete_created_key_after_failure(
    UniqueNcryptHandle& key,
    HostIdentityError& error) {
    const auto key_handle =
        static_cast<NCRYPT_KEY_HANDLE>(key.release());
    if (key_handle == 0U) return true;
    const SECURITY_STATUS status = NCryptDeleteKey(
        key_handle, NCRYPT_SILENT_FLAG);
    if (status == ERROR_SUCCESS) return true;
    (void)NCryptFreeObject(key_handle);
    error = ncrypt_error(
        HostIdentityErrorCode::key_cleanup_failed,
        status,
        "delete_created_key_after_failure");
    return false;
}

[[nodiscard]] HostIdentityError cleanup_created_key_after_failure(
    UniqueNcryptHandle& key,
    HostIdentityError primary) {
    HostIdentityError cleanup_error;
    if (delete_created_key_after_failure(key, cleanup_error)) {
        return primary;
    }
    return preserve_host_identity_cleanup_failure(
        std::move(primary), cleanup_error);
}

[[nodiscard]] bool read_key_metadata(
    const NCRYPT_KEY_HANDLE key,
    const CngKeyOpenRequest& request,
    const std::uint32_t implementation_type,
    CngKeyMetadata& metadata,
    HostIdentityError& error) {
    metadata.provider_name = request.provider_name;
    metadata.implementation_type = implementation_type;
    return read_ncrypt_wstring(
            key, NCRYPT_NAME_PROPERTY, "read_key_name",
            metadata.persistent_key_name, error) &&
        read_ncrypt_wstring(
            key, NCRYPT_ALGORITHM_PROPERTY, "read_key_algorithm",
            metadata.algorithm_name, error) &&
        read_ncrypt_wstring(
            key, NCRYPT_ALGORITHM_GROUP_PROPERTY,
            "read_key_algorithm_group",
            metadata.algorithm_group_name, error) &&
        read_ncrypt_dword(
            key, NCRYPT_LENGTH_PROPERTY, "read_key_length",
            metadata.key_length_bits, error) &&
        read_ncrypt_dword(
            key, NCRYPT_KEY_USAGE_PROPERTY, "read_key_usage",
            metadata.key_usage, error) &&
        read_ncrypt_dword(
            key, NCRYPT_EXPORT_POLICY_PROPERTY,
            "read_key_export_policy",
            metadata.export_policy, error) &&
        read_ncrypt_dword(
            key, NCRYPT_KEY_TYPE_PROPERTY, "read_key_type",
            metadata.key_type, error);
}

class WindowsCngKeyStoreAdapter final : public CngKeyStoreAdapter {
public:
    [[nodiscard]] CngKeyOpenResult open_or_create_p256_signing_key(
        const CngKeyOpenRequest& request) override {
        NCRYPT_PROV_HANDLE provider_handle{};
        SECURITY_STATUS status = NCryptOpenStorageProvider(
            &provider_handle, request.provider_name.c_str(), 0U);
        if (status != ERROR_SUCCESS) {
            return {nullptr, ncrypt_error(
                HostIdentityErrorCode::provider_open_failed,
                status,
                "open_storage_provider")};
        }
        UniqueNcryptHandle provider(provider_handle);

        std::uint32_t implementation_type{};
        HostIdentityError error;
        if (!read_ncrypt_dword(
                provider.get(),
                NCRYPT_IMPL_TYPE_PROPERTY,
                "read_provider_implementation_type",
                implementation_type,
                error)) {
            return {nullptr, std::move(error)};
        }

        std::vector<std::uint8_t> authorized_user_sid;
        if (request.machine_scope &&
            (!provider_supports_key_security_descriptors(
                 provider_handle, error) ||
             !read_current_process_user_sid(
                 authorized_user_sid, error))) {
            return {nullptr, std::move(error)};
        }

        UniqueNcryptHandle key;
        bool created{};
        if (!open_or_create_persisted_key(
                provider_handle, request, key, created, error)) {
            return {nullptr, std::move(error)};
        }
        if (created && !configure_new_persisted_key(
                static_cast<NCRYPT_KEY_HANDLE>(key.get()), error)) {
            return {
                nullptr,
                cleanup_created_key_after_failure(
                    key, std::move(error)),
            };
        }
        if (request.machine_scope &&
            !set_and_verify_formal_machine_key_dacl(
                static_cast<NCRYPT_KEY_HANDLE>(key.get()),
                authorized_user_sid,
                error)) {
            if (created) {
                error = cleanup_created_key_after_failure(
                    key, std::move(error));
            }
            return {nullptr, std::move(error)};
        }

        CngKeyMetadata metadata{};
        if (!read_key_metadata(
                static_cast<NCRYPT_KEY_HANDLE>(key.get()),
                request,
                implementation_type,
                metadata,
                error)) {
            if (created) {
                error = cleanup_created_key_after_failure(
                    key, std::move(error));
            }
            return {nullptr, std::move(error)};
        }
        metadata.formal_machine_key_dacl_verified = request.machine_scope;

        return {
            std::make_unique<WindowsCngSigningKey>(
                static_cast<NCRYPT_KEY_HANDLE>(key.release()),
                std::move(metadata)),
            {},
            created,
        };
    }
};

[[nodiscard]] bool policy_is_valid(
    const HostIdentityPolicy& policy, HostIdentityError& error) {
    const std::wstring_view provider = policy.provider_name();
    if (provider.empty() || provider.size() > NCRYPT_MAX_KEY_NAME_LENGTH ||
        has_embedded_null(provider)) {
        error = policy_error(
            HostIdentityErrorCode::invalid_policy,
            "validate_provider_name");
        return false;
    }
    switch (policy.kind()) {
        case HostIdentityPolicyKind::formal_platform_tpm:
            if (provider != kMicrosoftPlatformCryptoProvider) {
                error = policy_error(
                    HostIdentityErrorCode::invalid_policy,
                    "validate_formal_provider");
                return false;
            }
            return true;
        case HostIdentityPolicyKind::development_named_software_provider:
            if (provider == kMicrosoftPlatformCryptoProvider) {
                error = policy_error(
                    HostIdentityErrorCode::invalid_policy,
                    "validate_development_software_provider");
                return false;
            }
            return true;
    }
    error = policy_error(
        HostIdentityErrorCode::invalid_policy, "validate_policy_kind");
    return false;
}

[[nodiscard]] bool metadata_matches_policy(
    const HostIdentityPolicy& policy,
    const CngKeyOpenRequest& request,
    const CngKeyMetadata& metadata,
    HostIdentityError& error) {
    const auto reject = [&error](const std::string_view operation) {
        error = policy_error(
            HostIdentityErrorCode::key_contract_rejected, operation);
        return false;
    };

    if (metadata.provider_name != request.provider_name) {
        return reject("validate_provider_binding");
    }
    if (metadata.persistent_key_name != request.persistent_key_name) {
        return reject("validate_persistent_key_name");
    }
    if (metadata.algorithm_name != NCRYPT_ECDSA_P256_ALGORITHM ||
        metadata.algorithm_group_name != NCRYPT_ECDSA_ALGORITHM_GROUP ||
        metadata.key_length_bits != 256U) {
        return reject("validate_p256_algorithm");
    }
    if (metadata.key_usage != kCngAllowSigningFlag) {
        return reject("validate_signing_only_usage");
    }
    if (metadata.export_policy != 0U ||
        (metadata.export_policy & kCngPrivateExportPolicyMask) != 0U) {
        return reject("validate_private_export_policy");
    }
    const bool machine_key =
        (metadata.key_type & kCngMachineKeyFlag) != 0U;
    if (machine_key != request.machine_scope) {
        return reject("validate_key_scope");
    }

    const bool hardware = (metadata.implementation_type &
        kCngImplementationHardwareFlag) != 0U;
    const bool software = (metadata.implementation_type &
        kCngImplementationSoftwareFlag) != 0U;
    if (policy.kind() == HostIdentityPolicyKind::formal_platform_tpm) {
        if (metadata.provider_name != kMicrosoftPlatformCryptoProvider ||
            !hardware || software) {
            return reject("validate_formal_hardware_provider");
        }
        if (!metadata.formal_machine_key_dacl_verified) {
            return reject("validate_formal_machine_key_dacl");
        }
    } else {
        if (!software || hardware) {
            return reject("validate_development_software_provider");
        }
        if (metadata.formal_machine_key_dacl_verified) {
            return reject("validate_development_dacl_assurance_claim");
        }
    }
    return true;
}

[[nodiscard]] CngKeyOpenRequest key_request_for_policy(
    const HostIdentityPolicy& policy) {
    const bool formal =
        policy.kind() == HostIdentityPolicyKind::formal_platform_tpm;
    return {
        .provider_name = std::wstring(policy.provider_name()),
        .persistent_key_name = std::wstring(
            formal ? kFormalHostIdentityKeyName
                   : kDevelopmentHostIdentityKeyName),
        .machine_scope = formal,
    };
}

[[nodiscard]] std::array<std::uint8_t, 32U> to_sha256_array(
    const std::vector<std::uint8_t>& bytes) {
    std::array<std::uint8_t, 32U> result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

}  // namespace

const char* host_identity_error_code_name(
    const HostIdentityErrorCode code) noexcept {
    switch (code) {
        case HostIdentityErrorCode::none: return "none";
        case HostIdentityErrorCode::invalid_policy: return "invalid_policy";
        case HostIdentityErrorCode::invalid_challenge: return "invalid_challenge";
        case HostIdentityErrorCode::provider_open_failed: return "provider_open_failed";
        case HostIdentityErrorCode::key_open_or_create_failed: return "key_open_or_create_failed";
        case HostIdentityErrorCode::key_property_write_failed: return "key_property_write_failed";
        case HostIdentityErrorCode::key_finalize_failed: return "key_finalize_failed";
        case HostIdentityErrorCode::key_cleanup_failed: return "key_cleanup_failed";
        case HostIdentityErrorCode::key_property_read_failed: return "key_property_read_failed";
        case HostIdentityErrorCode::key_access_control_failed: return "key_access_control_failed";
        case HostIdentityErrorCode::key_contract_rejected: return "key_contract_rejected";
        case HostIdentityErrorCode::public_key_export_failed: return "public_key_export_failed";
        case HostIdentityErrorCode::public_key_format_rejected: return "public_key_format_rejected";
        case HostIdentityErrorCode::signature_format_rejected: return "signature_format_rejected";
        case HostIdentityErrorCode::sha256_failed: return "sha256_failed";
        case HostIdentityErrorCode::signature_failed: return "signature_failed";
        case HostIdentityErrorCode::verification_failed: return "verification_failed";
    }
    return "unknown";
}

const char* host_identity_assurance_name(
    const HostIdentityAssurance assurance) noexcept {
    switch (assurance) {
        case HostIdentityAssurance::formal_platform_tpm:
            return "formal_platform_tpm";
        case HostIdentityAssurance::non_formal_development_software:
            return "non_formal_development_software";
    }
    return "unknown";
}

std::string format_host_identity_error(const HostIdentityError& error) {
    std::ostringstream formatted;
    formatted << "code=" << host_identity_error_code_name(error.code);
    if (!error.operation.empty()) formatted << " operation=" << error.operation;
    if (error.native_domain != HostIdentityNativeStatusDomain::none) {
        const char* native_domain = "unknown";
        switch (error.native_domain) {
            case HostIdentityNativeStatusDomain::none:
                native_domain = "none";
                break;
            case HostIdentityNativeStatusDomain::ncrypt_security_status:
                native_domain = "ncrypt";
                break;
            case HostIdentityNativeStatusDomain::bcrypt_ntstatus:
                native_domain = "bcrypt";
                break;
            case HostIdentityNativeStatusDomain::win32_error:
                native_domain = "win32";
                break;
        }
        formatted << " native_domain=" << native_domain
            << " native_status=0x" << std::hex << std::setw(8)
            << std::setfill('0') << error.native_status;
    }
    if (error.cleanup_failure.has_value()) {
        const HostIdentityCleanupFailure& cleanup =
            *error.cleanup_failure;
        formatted << " cleanup_code=" <<
            host_identity_error_code_name(cleanup.code);
        if (!cleanup.operation.empty()) {
            formatted << " cleanup_operation=" << cleanup.operation;
        }
        if (cleanup.native_domain !=
            HostIdentityNativeStatusDomain::none) {
            const char* cleanup_domain = "unknown";
            switch (cleanup.native_domain) {
                case HostIdentityNativeStatusDomain::none:
                    cleanup_domain = "none";
                    break;
                case HostIdentityNativeStatusDomain::ncrypt_security_status:
                    cleanup_domain = "ncrypt";
                    break;
                case HostIdentityNativeStatusDomain::bcrypt_ntstatus:
                    cleanup_domain = "bcrypt";
                    break;
                case HostIdentityNativeStatusDomain::win32_error:
                    cleanup_domain = "win32";
                    break;
            }
            formatted << " cleanup_native_domain=" << cleanup_domain
                << " cleanup_native_status=0x" << std::hex <<
                std::setw(8) << std::setfill('0') <<
                cleanup.native_status;
        }
    }
    return formatted.str();
}

HostIdentityError preserve_host_identity_cleanup_failure(
    HostIdentityError primary,
    const HostIdentityError& cleanup_failure) {
    if (!cleanup_failure.has_error()) return primary;
    if (!primary.has_error()) return cleanup_failure;

    primary.cleanup_failure = HostIdentityCleanupFailure{
        .code = cleanup_failure.code,
        .native_domain = cleanup_failure.native_domain,
        .native_status = cleanup_failure.native_status,
        .operation = cleanup_failure.operation,
    };
    return primary;
}

HostIdentityPolicy::HostIdentityPolicy(
    const HostIdentityPolicyKind kind, std::wstring provider_name)
    : kind_(kind), provider_name_(std::move(provider_name)) {}

HostIdentityPolicy HostIdentityPolicy::formal_platform_tpm() {
    return HostIdentityPolicy(
        HostIdentityPolicyKind::formal_platform_tpm,
        std::wstring(kMicrosoftPlatformCryptoProvider));
}

HostIdentityPolicy HostIdentityPolicy::development_named_software_provider(
    std::wstring provider_name) {
    return HostIdentityPolicy(
        HostIdentityPolicyKind::development_named_software_provider,
        std::move(provider_name));
}

HostIdentityPolicyKind HostIdentityPolicy::kind() const noexcept {
    return kind_;
}

std::wstring_view HostIdentityPolicy::provider_name() const noexcept {
    return provider_name_;
}

bool validate_cng_key_metadata_for_policy(
    const HostIdentityPolicy& policy,
    const CngKeyMetadata& metadata,
    HostIdentityError& error) {
    error = {};
    if (!policy_is_valid(policy, error)) return false;
    return metadata_matches_policy(
        policy, key_request_for_policy(policy), metadata, error);
}

bool validate_formal_machine_key_security_descriptor(
    const std::span<const std::uint8_t> self_relative_security_descriptor,
    const std::span<const std::uint8_t> authorized_user_sid,
    HostIdentityError& error) {
    error = {};
    return validate_formal_machine_key_security_descriptor_impl(
        self_relative_security_descriptor, authorized_user_sid, error);
}

HostIdentityBytesResult build_host_identity_challenge(
    const HostIdentityChallenge& challenge,
    const std::array<std::uint8_t, 32U>& host_public_key_sha256,
    const HostIdentityAssurance untrusted_local_assurance_claim) {
    if (challenge.protocol_version != kHostIdentityChallengeProtocolVersion ||
        !is_challenge_type(challenge.challenge_type) ||
        !is_assurance(untrusted_local_assurance_claim) ||
        !is_host_id(challenge.host_id) ||
        !contains_nonzero(host_public_key_sha256) ||
        !contains_nonzero(challenge.server_nonce) ||
        !contains_nonzero(
            challenge.android_peer_ephemeral_public_key_sha256) ||
        !contains_nonzero(
            challenge.android_peer_identity_public_key_sha256) ||
        !contains_nonzero(challenge.session_id) || challenge.epoch == 0U) {
        return {{}, policy_error(
            HostIdentityErrorCode::invalid_challenge,
            "validate_canonical_challenge")};
    }

    std::vector<std::uint8_t> canonical;
    canonical.reserve(
        kHostIdentityChallengeDomain.size() + challenge.host_id.size() +
        192U);
    append_tlv(canonical, 0U, {
        reinterpret_cast<const std::uint8_t*>(
            kHostIdentityChallengeDomain.data()),
        kHostIdentityChallengeDomain.size()});

    std::vector<std::uint8_t> scalar;
    scalar.reserve(8U);
    append_u32_be(scalar, challenge.protocol_version);
    append_tlv(canonical, 1U, scalar);
    const std::array<std::uint8_t, 1U> challenge_type{
        static_cast<std::uint8_t>(challenge.challenge_type)};
    append_tlv(canonical, 2U, challenge_type);
    const std::array<std::uint8_t, 1U> assurance_value{
        static_cast<std::uint8_t>(untrusted_local_assurance_claim)};
    append_tlv(canonical, 3U, assurance_value);
    append_tlv(canonical, 4U, {
        reinterpret_cast<const std::uint8_t*>(challenge.host_id.data()),
        challenge.host_id.size()});
    append_tlv(canonical, 5U, host_public_key_sha256);
    append_tlv(canonical, 6U, challenge.server_nonce);
    append_tlv(
        canonical, 7U,
        challenge.android_peer_ephemeral_public_key_sha256);
    append_tlv(
        canonical, 8U,
        challenge.android_peer_identity_public_key_sha256);
    append_tlv(canonical, 9U, challenge.session_id);
    scalar.clear();
    append_u64_be(scalar, challenge.epoch);
    append_tlv(canonical, 10U, scalar);
    return {std::move(canonical), {}};
}

HostCngDeviceIdentity::HostCngDeviceIdentity(
    std::unique_ptr<CngSigningKey> key,
    HostPublicIdentity public_identity)
    : key_(std::move(key)), public_identity_(std::move(public_identity)) {}

HostCngDeviceIdentity::~HostCngDeviceIdentity() = default;
HostCngDeviceIdentity::HostCngDeviceIdentity(
    HostCngDeviceIdentity&&) noexcept = default;
HostCngDeviceIdentity& HostCngDeviceIdentity::operator=(
    HostCngDeviceIdentity&&) noexcept = default;

std::unique_ptr<HostCngDeviceIdentity> HostCngDeviceIdentity::open_windows(
    const HostIdentityPolicy& policy, HostIdentityError& error) {
    WindowsCngKeyStoreAdapter adapter;
    return open_with_trusted_adapter(policy, adapter, error);
}

std::unique_ptr<HostCngDeviceIdentity>
HostCngDeviceIdentity::open_development_with_adapter(
    const HostIdentityPolicy& policy,
    CngKeyStoreAdapter& adapter,
    HostIdentityError& error) {
    error = {};
    if (policy.kind() !=
        HostIdentityPolicyKind::development_named_software_provider) {
        error = policy_error(
            HostIdentityErrorCode::invalid_policy,
            "reject_formal_test_adapter");
        return nullptr;
    }
    return open_with_trusted_adapter(policy, adapter, error);
}

std::unique_ptr<HostCngDeviceIdentity>
HostCngDeviceIdentity::open_with_trusted_adapter(
    const HostIdentityPolicy& policy,
    CngKeyStoreAdapter& adapter,
    HostIdentityError& error) {
    error = {};
    if (!policy_is_valid(policy, error)) return nullptr;

    const bool formal =
        policy.kind() == HostIdentityPolicyKind::formal_platform_tpm;
    const CngKeyOpenRequest request = key_request_for_policy(policy);
    CngKeyOpenResult opened = adapter.open_or_create_p256_signing_key(request);
    if (!opened.succeeded()) {
        error = opened.error.has_error()
            ? std::move(opened.error)
            : policy_error(
                HostIdentityErrorCode::key_open_or_create_failed,
                "adapter_open_or_create_key");
        return nullptr;
    }
    const auto fail_initialization =
        [&opened, &error](HostIdentityError primary)
        -> std::unique_ptr<HostCngDeviceIdentity> {
        if (opened.created && opened.key != nullptr) {
            const HostIdentityError cleanup = opened.key->
                discard_new_persisted_key_after_failed_initialization();
            primary = preserve_host_identity_cleanup_failure(
                std::move(primary), cleanup);
        }
        error = std::move(primary);
        return nullptr;
    };
    if (!metadata_matches_policy(
            policy, request, opened.key->metadata(), error)) {
        return fail_initialization(std::move(error));
    }

    HostIdentityBytesResult public_blob =
        opened.key->export_public_ecc_blob();
    if (!public_blob.succeeded()) {
        return fail_initialization(std::move(public_blob.error));
    }
    HostIdentityBytesResult spki = ecc_public_blob_to_spki(public_blob.bytes);
    if (!spki.succeeded()) {
        return fail_initialization(std::move(spki.error));
    }
    HostIdentityBytesResult fingerprint =
        sha256(spki.bytes, "fingerprint_subject_public_key_info");
    if (!fingerprint.succeeded() || fingerprint.bytes.size() != kSha256Bytes) {
        HostIdentityError fingerprint_error = fingerprint.error.has_error()
            ? std::move(fingerprint.error)
            : policy_error(
                HostIdentityErrorCode::sha256_failed,
                "validate_public_key_fingerprint");
        return fail_initialization(std::move(fingerprint_error));
    }

    HostPublicIdentity public_identity{
        .untrusted_local_assurance_claim = formal
            ? HostIdentityAssurance::formal_platform_tpm
            : HostIdentityAssurance::non_formal_development_software,
        .provider_name = opened.key->metadata().provider_name,
        .subject_public_key_info_der = std::move(spki.bytes),
        .public_key_sha256 = to_sha256_array(fingerprint.bytes),
        .public_key_sha256_hex = lower_hex(fingerprint.bytes),
    };
    return std::unique_ptr<HostCngDeviceIdentity>(
        new HostCngDeviceIdentity(
            std::move(opened.key), std::move(public_identity)));
}

const HostPublicIdentity& HostCngDeviceIdentity::public_identity() const noexcept {
    return public_identity_;
}

HostIdentitySignatureResult HostCngDeviceIdentity::sign_challenge(
    const HostIdentityChallenge& challenge) {
    HostIdentityBytesResult canonical = build_host_identity_challenge(
        challenge,
        public_identity_.public_key_sha256,
        public_identity_.untrusted_local_assurance_claim);
    if (!canonical.succeeded()) {
        return {std::nullopt, std::move(canonical.error)};
    }
    HostIdentityBytesResult digest =
        sha256(canonical.bytes, "hash_canonical_challenge");
    if (!digest.succeeded() || digest.bytes.size() != kSha256Bytes) {
        return {std::nullopt, digest.error.has_error()
            ? std::move(digest.error)
            : policy_error(
                HostIdentityErrorCode::sha256_failed,
                "validate_challenge_digest")};
    }
    HostIdentityBytesResult raw_signature =
        key_->sign_sha256_digest(digest.bytes);
    if (!raw_signature.succeeded()) {
        return {std::nullopt, std::move(raw_signature.error)};
    }
    HostIdentityBytesResult der_signature =
        p1363_to_canonical_der(raw_signature.bytes);
    if (!der_signature.succeeded()) {
        return {std::nullopt, std::move(der_signature.error)};
    }

    HostIdentitySignature signature{
        .untrusted_local_assurance_claim =
            public_identity_.untrusted_local_assurance_claim,
        .encoding =
            HostIdentitySignatureEncoding::ecdsa_p256_sha256_der_low_s,
        .public_key_sha256 = public_identity_.public_key_sha256,
        .challenge_sha256 = to_sha256_array(digest.bytes),
        .canonical_challenge = std::move(canonical.bytes),
        .signature_der = std::move(der_signature.bytes),
    };
    const HostIdentityVerificationResult verified =
        verify_host_identity_proof_of_possession(
            public_identity_, challenge, signature);
    if (!verified.completed()) {
        return {std::nullopt, verified.error};
    }
    if (!verified.proof_of_possession_valid) {
        return {std::nullopt, policy_error(
            HostIdentityErrorCode::signature_failed,
            "post_sign_verify")};
    }
    return {std::move(signature), {}};
}

HostIdentityBytesResult
HostCngDeviceIdentity::create_peer_handshake_transcript_signature(
    const std::array<std::uint8_t, 32U>& transcript_sha256) {
    if (key_ == nullptr || !contains_nonzero(transcript_sha256)) {
        return {{}, policy_error(
            HostIdentityErrorCode::signature_failed,
            "validate_peer_handshake_transcript_digest")};
    }

    HostIdentityBytesResult raw_signature =
        key_->sign_sha256_digest(transcript_sha256);
    if (!raw_signature.succeeded()) {
        return {std::move(raw_signature.bytes), std::move(raw_signature.error)};
    }
    HostIdentityBytesResult der_signature =
        p1363_to_canonical_der(raw_signature.bytes);
    if (!der_signature.succeeded()) return der_signature;

    // A malformed provider response must not escape merely because it has two
    // in-range scalars. Verify the normalized low-S signature against the
    // current canonical SPKI before releasing it to the protocol layer.
    HostIdentityError verification_error =
        verify_canonical_p256_signature_for_digest(
            public_identity_.subject_public_key_info_der,
            transcript_sha256,
            der_signature.bytes);
    if (verification_error.has_error()) {
        return {{}, std::move(verification_error)};
    }
    return der_signature;
}

HostIdentityVerificationResult verify_host_identity_proof_of_possession(
    const HostPublicIdentity& public_identity,
    const HostIdentityChallenge& challenge,
    const HostIdentitySignature& signature) {
    if (signature.encoding !=
            HostIdentitySignatureEncoding::ecdsa_p256_sha256_der_low_s ||
        signature.untrusted_local_assurance_claim !=
            public_identity.untrusted_local_assurance_claim ||
        signature.public_key_sha256 != public_identity.public_key_sha256 ||
        signature.signature_der.empty() ||
        signature.signature_der.size() > kMaximumP256DerSignatureBytes) {
        return {false, {}};
    }
    HostIdentityBytesResult raw_signature =
        canonical_der_to_p1363(signature.signature_der);
    if (!raw_signature.succeeded()) return {false, {}};

    HostIdentityBytesResult spki_fingerprint = sha256(
        public_identity.subject_public_key_info_der,
        "verify_public_key_fingerprint");
    if (!spki_fingerprint.succeeded() ||
        spki_fingerprint.bytes.size() != kSha256Bytes) {
        return {false, spki_fingerprint.error.has_error()
            ? std::move(spki_fingerprint.error)
            : policy_error(
                HostIdentityErrorCode::sha256_failed,
                "validate_verifier_fingerprint")};
    }
    if (to_sha256_array(spki_fingerprint.bytes) !=
            public_identity.public_key_sha256 ||
        lower_hex(spki_fingerprint.bytes) !=
            public_identity.public_key_sha256_hex) {
        return {false, {}};
    }

    HostIdentityBytesResult canonical = build_host_identity_challenge(
        challenge,
        public_identity.public_key_sha256,
        public_identity.untrusted_local_assurance_claim);
    if (!canonical.succeeded()) {
        return {false, std::move(canonical.error)};
    }
    HostIdentityBytesResult digest =
        sha256(canonical.bytes, "verify_canonical_challenge_hash");
    if (!digest.succeeded() || digest.bytes.size() != kSha256Bytes) {
        return {false, digest.error.has_error()
            ? std::move(digest.error)
            : policy_error(
                HostIdentityErrorCode::sha256_failed,
                "validate_verifier_digest")};
    }
    if (canonical.bytes != signature.canonical_challenge ||
        to_sha256_array(digest.bytes) != signature.challenge_sha256) {
        return {false, {}};
    }

    HostIdentityBytesResult public_blob = spki_to_ecc_public_blob(
        public_identity.subject_public_key_info_der);
    if (!public_blob.succeeded()) {
        return {false, std::move(public_blob.error)};
    }

    UniqueBcryptAlgorithm algorithm;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm.handle, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0U);
    if (!BCRYPT_SUCCESS(status)) {
        return {false, bcrypt_error(
            HostIdentityErrorCode::verification_failed,
            status,
            "open_ecdsa_p256_verifier")};
    }
    UniqueBcryptKey key;
    status = BCryptImportKeyPair(
        algorithm.handle,
        nullptr,
        BCRYPT_ECCPUBLIC_BLOB,
        &key.handle,
        public_blob.bytes.data(),
        static_cast<ULONG>(public_blob.bytes.size()),
        0U);
    if (!BCRYPT_SUCCESS(status)) {
        return {false, bcrypt_error(
            HostIdentityErrorCode::verification_failed,
            status,
            "import_ecdsa_p256_public_key")};
    }
    status = BCryptVerifySignature(
        key.handle,
        nullptr,
        digest.bytes.data(),
        static_cast<ULONG>(digest.bytes.size()),
        raw_signature.bytes.data(),
        static_cast<ULONG>(raw_signature.bytes.size()),
        0U);
    if (status == kStatusInvalidSignature) return {false, {}};
    if (!BCRYPT_SUCCESS(status)) {
        return {false, bcrypt_error(
            HostIdentityErrorCode::verification_failed,
            status,
            "verify_ecdsa_p256_signature")};
    }
    return {true, {}};
}

}  // namespace vfdual
