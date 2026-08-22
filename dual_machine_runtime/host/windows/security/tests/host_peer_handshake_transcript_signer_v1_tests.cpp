#include "vfdual/host_peer_handshake_transcript_signer_v1.hpp"
#include "vfdual/host_pair_generation_pop_signer_v1.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <barrier>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <thread>
#include <utility>
#include <vector>

namespace {

void require(
    const bool condition,
    const char* expression,
    const char* file,
    const int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: "
              << expression << '\n';
    std::exit(EXIT_FAILURE);
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

static_assert(!std::is_copy_constructible_v<
    vfdual::HostSignedPeerHandshakeContextV1>);
static_assert(!std::is_copy_assignable_v<
    vfdual::HostSignedPeerHandshakeContextV1>);
static_assert(!std::is_move_constructible_v<
    vfdual::HostSignedPeerHandshakeContextV1>);
static_assert(!std::is_move_assignable_v<
    vfdual::HostSignedPeerHandshakeContextV1>);
static_assert(!std::is_copy_constructible_v<
    vfdual::HostPeerHandshakeSigningInputV1>);
static_assert(std::is_move_constructible_v<
    vfdual::HostPeerHandshakeSigningInputV1>);
static_assert(std::is_nothrow_copy_constructible_v<
    vfdual::PeerHandshakeError>);
static_assert(!std::is_copy_constructible_v<
    vfdual::HostSignedPairGenerationChallengeV1>);
static_assert(!std::is_move_constructible_v<
    vfdual::HostSignedPairGenerationChallengeV1>);
static_assert(!std::is_copy_constructible_v<
    vfdual::HostSignedPairGenerationFinalProofV1>);
static_assert(!std::is_move_constructible_v<
    vfdual::HostSignedPairGenerationFinalProofV1>);

namespace {

constexpr std::array<std::uint8_t, 32U> kP256HalfOrder{
    0x7fU, 0xffU, 0xffU, 0xffU, 0x80U, 0x00U, 0x00U, 0x00U,
    0x7fU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
    0xdeU, 0x73U, 0x7dU, 0x56U, 0xd3U, 0x8bU, 0xcfU, 0x42U,
    0x79U, 0xdcU, 0xe5U, 0x61U, 0x7eU, 0x31U, 0x92U, 0xa8U};

struct FakeKeyStats final {
    std::size_t export_calls{};
    std::size_t sign_calls{};
};

enum class FakeSignBehavior : std::uint8_t {
    valid,
    provider_failure,
    corrupt_signature,
};

[[nodiscard]] vfdual::HostIdentityError bcrypt_test_error(
    const vfdual::HostIdentityErrorCode code,
    const NTSTATUS status,
    const std::string operation) {
    return {
        .code = code,
        .native_domain =
            vfdual::HostIdentityNativeStatusDomain::bcrypt_ntstatus,
        .native_status = static_cast<std::uint32_t>(status),
        .operation = std::move(operation),
    };
}

class EphemeralBcryptSigningKey final : public vfdual::CngSigningKey {
public:
    ~EphemeralBcryptSigningKey() override {
        if (key_ != nullptr) static_cast<void>(BCryptDestroyKey(key_));
        if (algorithm_ != nullptr) {
            static_cast<void>(BCryptCloseAlgorithmProvider(algorithm_, 0U));
        }
    }

    EphemeralBcryptSigningKey(const EphemeralBcryptSigningKey&) = delete;
    EphemeralBcryptSigningKey& operator=(
        const EphemeralBcryptSigningKey&) = delete;

    [[nodiscard]] static std::unique_ptr<EphemeralBcryptSigningKey> create(
        vfdual::CngKeyMetadata metadata,
        const std::shared_ptr<FakeKeyStats>& stats,
        const FakeSignBehavior behavior,
        vfdual::HostIdentityError& error) {
        auto result = std::unique_ptr<EphemeralBcryptSigningKey>(
            new EphemeralBcryptSigningKey(
                std::move(metadata), stats, behavior));
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &result->algorithm_, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            error = bcrypt_test_error(
                vfdual::HostIdentityErrorCode::key_open_or_create_failed,
                status,
                "test_open_ecdsa_provider");
            return nullptr;
        }
        status = BCryptGenerateKeyPair(
            result->algorithm_, &result->key_, 256U, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            error = bcrypt_test_error(
                vfdual::HostIdentityErrorCode::key_open_or_create_failed,
                status,
                "test_generate_ecdsa_key");
            return nullptr;
        }
        status = BCryptFinalizeKeyPair(result->key_, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            error = bcrypt_test_error(
                vfdual::HostIdentityErrorCode::key_finalize_failed,
                status,
                "test_finalize_ecdsa_key");
            return nullptr;
        }
        error = {};
        return result;
    }

    [[nodiscard]] const vfdual::CngKeyMetadata& metadata()
        const noexcept override {
        return metadata_;
    }

    [[nodiscard]] vfdual::HostIdentityBytesResult
    export_public_ecc_blob() override {
        ++stats_->export_calls;
        ULONG required{};
        NTSTATUS status = BCryptExportKey(
            key_, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0U, &required, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, bcrypt_test_error(
                vfdual::HostIdentityErrorCode::public_key_export_failed,
                status,
                "test_query_public_blob")};
        }
        std::vector<std::uint8_t> output(required);
        ULONG written{};
        status = BCryptExportKey(
            key_,
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            output.data(),
            static_cast<ULONG>(output.size()),
            &written,
            0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, bcrypt_test_error(
                vfdual::HostIdentityErrorCode::public_key_export_failed,
                status,
                "test_export_public_blob")};
        }
        output.resize(written);
        return {std::move(output), {}};
    }

    [[nodiscard]] vfdual::HostIdentityBytesResult sign_sha256_digest(
        const std::span<const std::uint8_t> digest) override {
        ++stats_->sign_calls;
        if (behavior_ == FakeSignBehavior::provider_failure) {
            return {{}, {
                .code = vfdual::HostIdentityErrorCode::signature_failed,
                .operation = "forced_test_provider_failure",
            }};
        }
        if (digest.size() != 32U) {
            return {{}, {
                .code = vfdual::HostIdentityErrorCode::signature_failed,
                .operation = "test_reject_digest_size",
            }};
        }
        ULONG required{};
        NTSTATUS status = BCryptSignHash(
            key_,
            nullptr,
            const_cast<PUCHAR>(digest.data()),
            static_cast<ULONG>(digest.size()),
            nullptr,
            0U,
            &required,
            0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, bcrypt_test_error(
                vfdual::HostIdentityErrorCode::signature_failed,
                status,
                "test_query_signature")};
        }
        std::vector<std::uint8_t> output(required);
        ULONG written{};
        status = BCryptSignHash(
            key_,
            nullptr,
            const_cast<PUCHAR>(digest.data()),
            static_cast<ULONG>(digest.size()),
            output.data(),
            static_cast<ULONG>(output.size()),
            &written,
            0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, bcrypt_test_error(
                vfdual::HostIdentityErrorCode::signature_failed,
                status,
                "test_create_signature")};
        }
        output.resize(written);
        if (behavior_ == FakeSignBehavior::corrupt_signature &&
            output.size() == 64U) {
            // Keep r strictly in range so the low-S DER normalizer accepts
            // the shape; the identity module's post-sign verification must
            // be the layer that rejects this provider corruption.
            std::fill(output.begin(), output.begin() + 32, 0U);
            output[31U] = 1U;
        }
        return {std::move(output), {}};
    }

    [[nodiscard]] vfdual::HostIdentityError
    discard_new_persisted_key_after_failed_initialization() override {
        return {};
    }

private:
    EphemeralBcryptSigningKey(
        vfdual::CngKeyMetadata metadata,
        std::shared_ptr<FakeKeyStats> stats,
        const FakeSignBehavior behavior)
        : metadata_(std::move(metadata)),
          stats_(std::move(stats)),
          behavior_(behavior) {}

    vfdual::CngKeyMetadata metadata_;
    std::shared_ptr<FakeKeyStats> stats_;
    FakeSignBehavior behavior_;
    BCRYPT_ALG_HANDLE algorithm_{};
    BCRYPT_KEY_HANDLE key_{};
};

class FakeKeyStore final : public vfdual::CngKeyStoreAdapter {
public:
    explicit FakeKeyStore(
        const FakeSignBehavior behavior = FakeSignBehavior::valid)
        : behavior_(behavior), stats(std::make_shared<FakeKeyStats>()) {}

    [[nodiscard]] vfdual::CngKeyOpenResult
    open_or_create_p256_signing_key(
        const vfdual::CngKeyOpenRequest&) override {
        vfdual::HostIdentityError error;
        auto key = EphemeralBcryptSigningKey::create(
            development_metadata(), stats, behavior_, error);
        if (key == nullptr) return {nullptr, std::move(error)};
        return {std::move(key), {}};
    }

    [[nodiscard]] static vfdual::CngKeyMetadata development_metadata() {
        return {
            .provider_name = std::wstring(
                vfdual::kMicrosoftSoftwareKeyStorageProvider),
            .persistent_key_name = std::wstring(
                vfdual::kDevelopmentHostIdentityKeyName),
            .algorithm_name = L"ECDSA_P256",
            .algorithm_group_name = L"ECDSA",
            .key_length_bits = 256U,
            .key_usage = vfdual::kCngAllowSigningFlag,
            .export_policy = 0U,
            .implementation_type = vfdual::kCngImplementationSoftwareFlag,
            .key_type = 0U,
        };
    }

    std::shared_ptr<FakeKeyStats> stats;

private:
    FakeSignBehavior behavior_;
};

[[nodiscard]] std::unique_ptr<vfdual::HostCngDeviceIdentity>
open_development_identity(FakeKeyStore& adapter) {
    vfdual::HostIdentityError error;
    auto identity =
        vfdual::HostCngDeviceIdentity::open_development_with_adapter(
            vfdual::HostIdentityPolicy::
                development_named_software_provider(
                    std::wstring(
                        vfdual::kMicrosoftSoftwareKeyStorageProvider)),
            adapter,
            error);
    CHECK(identity != nullptr);
    CHECK(!error.has_error());
    return identity;
}

template <std::size_t Size>
[[nodiscard]] std::array<std::byte, Size> filled_bytes(
    const std::uint8_t value) {
    std::array<std::byte, Size> result{};
    result.fill(std::byte{value});
    return result;
}

[[nodiscard]] vfdual::PeerHandshakeSha256 identity_hash_as_bytes(
    const std::array<std::uint8_t, 32U>& value) {
    vfdual::PeerHandshakeSha256 result{};
    std::transform(
        value.begin(), value.end(), result.begin(),
        [](const std::uint8_t byte) { return std::byte{byte}; });
    return result;
}

[[nodiscard]] std::unique_ptr<vfdual::PlatformP256EphemeralKeyAgreementV1>
fresh_ephemeral() {
    vfdual::PeerHandshakeError error;
    auto key = vfdual::PlatformP256EphemeralKeyAgreementV1::
        generate_platform(error);
    CHECK(key != nullptr);
    CHECK(!error.has_error());
    return key;
}

[[nodiscard]] vfdual::PeerHandshakeP256PublicKey fresh_public_key() {
    auto key = fresh_ephemeral();
    vfdual::PeerHandshakeP256PublicKey result{};
    std::copy(
        key->public_key_sec1().begin(),
        key->public_key_sec1().end(),
        result.begin());
    return result;
}

[[nodiscard]] vfdual::HostPeerHandshakeSigningInputV1 valid_input() {
    return {
        .host_ephemeral = fresh_ephemeral(),
        .android_identity_spki_sha256 = filled_bytes<32U>(0xa5U),
        .android_ephemeral_public_key = fresh_public_key(),
        .host_nonce = filled_bytes<32U>(0x31U),
        .android_nonce = filled_bytes<32U>(0x42U),
        .connection_id = 0x1020304050607080ULL,
        .session_generation = 0x0102030405060708ULL,
        .transport_kind = vfdual::PeerHandshakeTransportKind::cat6,
        .host_ipv4 = {
            std::byte{192U}, std::byte{168U},
            std::byte{55U}, std::byte{1U}},
        .android_ipv4 = {
            std::byte{192U}, std::byte{168U},
            std::byte{55U}, std::byte{2U}},
        .video_port = 45678U,
        .control_port = 45679U,
        .pair_id = "PAIR-2026_08.04",
        .host_runtime_version = "17.8.47",
        .android_runtime_version = "17.8.47",
    };
}

[[nodiscard]] vfdual::PeerHandshakeTranscriptFields fields_from_input(
    const vfdual::HostPublicIdentity& identity,
    const vfdual::HostPeerHandshakeSigningInputV1& input) {
    vfdual::PeerHandshakeTranscriptFields fields;
    fields.host_identity_spki_sha256 =
        identity_hash_as_bytes(identity.public_key_sha256);
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
    fields.pair_id = input.pair_id;
    fields.host_runtime_version = input.host_runtime_version;
    fields.android_runtime_version = input.android_runtime_version;
    return fields;
}

[[nodiscard]] std::array<std::uint8_t, 32U> sha256(
    const std::span<const std::byte> input) {
    BCRYPT_ALG_HANDLE algorithm{};
    CHECK(BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0U)));
    DWORD object_size{};
    DWORD copied{};
    CHECK(BCRYPT_SUCCESS(BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_size),
        sizeof(object_size),
        &copied,
        0U)));
    std::vector<std::uint8_t> object(object_size);
    BCRYPT_HASH_HANDLE hash{};
    CHECK(BCRYPT_SUCCESS(BCryptCreateHash(
        algorithm,
        &hash,
        object.data(),
        static_cast<ULONG>(object.size()),
        nullptr,
        0U,
        0U)));
    CHECK(BCRYPT_SUCCESS(BCryptHashData(
        hash,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(input.data())),
        static_cast<ULONG>(input.size()),
        0U)));
    std::array<std::uint8_t, 32U> output{};
    CHECK(BCRYPT_SUCCESS(BCryptFinishHash(
        hash, output.data(), static_cast<ULONG>(output.size()), 0U)));
    static_cast<void>(BCryptDestroyHash(hash));
    static_cast<void>(BCryptCloseAlgorithmProvider(algorithm, 0U));
    return output;
}

[[nodiscard]] bool read_der_scalar(
    const std::span<const std::uint8_t> der,
    std::size_t& offset,
    std::array<std::uint8_t, 32U>& scalar) {
    if (offset + 2U > der.size() || der[offset] != 0x02U) return false;
    const std::size_t size = der[offset + 1U];
    offset += 2U;
    if (size == 0U || size > 33U || offset + size > der.size()) return false;
    const auto encoded = der.subspan(offset, size);
    offset += size;
    if ((encoded.front() & 0x80U) != 0U ||
        (encoded.size() > 1U && encoded.front() == 0U &&
            (encoded[1U] & 0x80U) == 0U) ||
        (encoded.size() == 33U && encoded.front() != 0U)) {
        return false;
    }
    const auto magnitude = encoded.size() == 33U
        ? encoded.subspan(1U)
        : encoded;
    if (magnitude.size() > scalar.size()) return false;
    std::copy(
        magnitude.begin(),
        magnitude.end(),
        scalar.end() - static_cast<std::ptrdiff_t>(magnitude.size()));
    return std::any_of(
        scalar.begin(), scalar.end(),
        [](const std::uint8_t value) { return value != 0U; });
}

[[nodiscard]] bool canonical_low_s_der_to_p1363(
    const std::span<const std::uint8_t> der,
    std::array<std::uint8_t, 64U>& p1363) {
    if (der.size() < 8U || der.size() > 72U || der[0U] != 0x30U ||
        der[1U] != der.size() - 2U) {
        return false;
    }
    std::size_t offset = 2U;
    std::array<std::uint8_t, 32U> r{};
    std::array<std::uint8_t, 32U> s{};
    if (!read_der_scalar(der, offset, r) ||
        !read_der_scalar(der, offset, s) || offset != der.size() ||
        std::lexicographical_compare(
            kP256HalfOrder.begin(), kP256HalfOrder.end(),
            s.begin(), s.end())) {
        return false;
    }
    std::copy(r.begin(), r.end(), p1363.begin());
    std::copy(s.begin(), s.end(), p1363.begin() + 32U);
    return true;
}

[[nodiscard]] bool verify_transcript_signature(
    const vfdual::HostPublicIdentity& identity,
    const vfdual::PeerHandshakeSha256& digest,
    const std::span<const std::uint8_t> der) {
    if (identity.subject_public_key_info_der.size() != 91U) return false;
    std::array<std::uint8_t, 64U> raw_signature{};
    if (!canonical_low_s_der_to_p1363(der, raw_signature)) return false;

    BCRYPT_ECCKEY_BLOB header{
        .dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
        .cbKey = 32U,
    };
    std::array<std::uint8_t, sizeof(BCRYPT_ECCKEY_BLOB) + 64U> blob{};
    std::memcpy(blob.data(), &header, sizeof(header));
    std::copy(
        identity.subject_public_key_info_der.end() - 64,
        identity.subject_public_key_info_der.end(),
        blob.begin() + static_cast<std::ptrdiff_t>(sizeof(header)));

    BCRYPT_ALG_HANDLE algorithm{};
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0U))) {
        return false;
    }
    BCRYPT_KEY_HANDLE key{};
    const NTSTATUS imported = BCryptImportKeyPair(
        algorithm,
        nullptr,
        BCRYPT_ECCPUBLIC_BLOB,
        &key,
        blob.data(),
        static_cast<ULONG>(blob.size()),
        0U);
    if (!BCRYPT_SUCCESS(imported)) {
        static_cast<void>(BCryptCloseAlgorithmProvider(algorithm, 0U));
        return false;
    }
    std::array<std::uint8_t, 32U> digest_bytes{};
    std::transform(
        digest.begin(), digest.end(), digest_bytes.begin(),
        [](const std::byte value) {
            return std::to_integer<std::uint8_t>(value);
        });
    const NTSTATUS verified = BCryptVerifySignature(
        key,
        nullptr,
        digest_bytes.data(),
        static_cast<ULONG>(digest_bytes.size()),
        raw_signature.data(),
        static_cast<ULONG>(raw_signature.size()),
        0U);
    static_cast<void>(BCryptDestroyKey(key));
    static_cast<void>(BCryptCloseAlgorithmProvider(algorithm, 0U));
    return BCRYPT_SUCCESS(verified);
}

void expect_bound_mutation_rejected(
    const vfdual::HostPublicIdentity& identity,
    const std::span<const std::uint8_t> signature,
    const vfdual::PeerHandshakeTranscriptFields& fields) {
    const auto built = vfdual::build_canonical_peer_handshake_transcript_v1(
        fields,
        vfdual::PeerHandshakePairIdRequirement::require_bound_pair);
    CHECK(built.succeeded());
    CHECK(!verify_transcript_signature(
        identity, built.transcript->transcript_sha256(), signature));
}

void test_valid_signature_binds_every_typed_field_and_derives_once() {
    FakeKeyStore adapter;
    auto identity = open_development_identity(adapter);
    vfdual::HostPeerHandshakeTranscriptSignerV1 signer(*identity);
    auto input = valid_input();
    const auto expected_fields = fields_from_input(
        identity->public_identity(), input);

    auto result = signer.build_and_sign_bound_transcript(std::move(input));
    CHECK(result.succeeded());
    CHECK(result.context != nullptr);
    CHECK(adapter.stats->sign_calls == 1U);
    const auto& transcript = result.context->transcript();
    const auto& actual_fields = transcript.fields();
    CHECK(actual_fields.host_identity_spki_sha256 ==
        expected_fields.host_identity_spki_sha256);
    CHECK(actual_fields.android_identity_spki_sha256 ==
        expected_fields.android_identity_spki_sha256);
    CHECK(actual_fields.host_ephemeral_public_key ==
        expected_fields.host_ephemeral_public_key);
    CHECK(actual_fields.android_ephemeral_public_key ==
        expected_fields.android_ephemeral_public_key);
    CHECK(actual_fields.host_nonce == expected_fields.host_nonce);
    CHECK(actual_fields.android_nonce == expected_fields.android_nonce);
    CHECK(actual_fields.connection_id == expected_fields.connection_id);
    CHECK(actual_fields.session_generation ==
        expected_fields.session_generation);
    CHECK(actual_fields.transport_kind == expected_fields.transport_kind);
    CHECK(actual_fields.host_ipv4 == expected_fields.host_ipv4);
    CHECK(actual_fields.android_ipv4 == expected_fields.android_ipv4);
    CHECK(actual_fields.video_port == expected_fields.video_port);
    CHECK(actual_fields.control_port == expected_fields.control_port);
    CHECK(actual_fields.pair_id == expected_fields.pair_id);
    CHECK(actual_fields.host_runtime_version ==
        expected_fields.host_runtime_version);
    CHECK(actual_fields.android_runtime_version ==
        expected_fields.android_runtime_version);

    const auto independent_hash = sha256(transcript.canonical_bytes());
    CHECK(std::equal(
        independent_hash.begin(), independent_hash.end(),
        transcript.transcript_sha256().begin(),
        [](const std::uint8_t left, const std::byte right) {
            return left == std::to_integer<std::uint8_t>(right);
        }));
    std::array<std::uint8_t, 64U> normalized_signature{};
    CHECK(canonical_low_s_der_to_p1363(
        result.context->signature_der_low_s(), normalized_signature));
    CHECK(verify_transcript_signature(
        identity->public_identity(),
        transcript.transcript_sha256(),
        result.context->signature_der_low_s()));

    const auto signature = std::vector<std::uint8_t>(
        result.context->signature_der_low_s().begin(),
        result.context->signature_der_low_s().end());
    auto mutated = actual_fields;
    mutated.host_identity_spki_sha256[0U] ^= std::byte{0x01U};
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    mutated.android_identity_spki_sha256[0U] ^= std::byte{0x01U};
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    mutated.host_ephemeral_public_key = fresh_public_key();
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    mutated.android_ephemeral_public_key = fresh_public_key();
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    mutated.host_nonce[0U] ^= std::byte{0x01U};
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    mutated.android_nonce[0U] ^= std::byte{0x01U};
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    ++mutated.connection_id;
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    ++mutated.session_generation;
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    mutated.transport_kind = vfdual::PeerHandshakeTransportKind::wlan;
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    mutated.host_ipv4[3U] = std::byte{3U};
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    mutated.android_ipv4[3U] = std::byte{4U};
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    --mutated.video_port;
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    ++mutated.control_port;
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    mutated.pair_id += "-NEXT";
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    mutated.host_runtime_version = "17.8.48";
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);
    mutated = actual_fields;
    mutated.android_runtime_version = "17.8.48";
    expect_bound_mutation_rejected(
        identity->public_identity(), signature, mutated);

    vfdual::PeerHandshakeError derive_error;
    auto pending = result.context->
        derive_pending_after_peer_identity_verified_for_bound_transcript(
            derive_error);
    CHECK(pending != nullptr);
    CHECK(!derive_error.has_error());
    CHECK(pending->local_role() == vfdual::PeerHandshakeRole::host);
    auto second = result.context->
        derive_pending_after_peer_identity_verified_for_bound_transcript(
            derive_error);
    CHECK(second == nullptr);
    CHECK(derive_error.code ==
        vfdual::PeerHandshakeErrorCode::
            ephemeral_private_key_already_consumed);
}

void test_concurrent_derivation_releases_ephemeral_owner_exactly_once() {
    FakeKeyStore adapter;
    auto identity = open_development_identity(adapter);
    vfdual::HostPeerHandshakeTranscriptSignerV1 signer(*identity);
    auto signed_result = signer.build_and_sign_bound_transcript(
        valid_input());
    CHECK(signed_result.succeeded());

    constexpr std::size_t kWorkerCount = 16U;
    std::barrier start_gate{
        static_cast<std::ptrdiff_t>(kWorkerCount)};
    std::array<
        std::unique_ptr<vfdual::PendingPeerHandshakeConfirmationV1>,
        kWorkerCount> pending_results{};
    std::array<vfdual::PeerHandshakeError, kWorkerCount> errors{};
    std::vector<std::thread> workers;
    workers.reserve(kWorkerCount);
    for (std::size_t index{}; index < kWorkerCount; ++index) {
        workers.emplace_back([&, index] {
            start_gate.arrive_and_wait();
            pending_results[index] = signed_result.context->
                derive_pending_after_peer_identity_verified_for_bound_transcript(
                    errors[index]);
        });
    }
    for (auto& worker : workers) worker.join();

    std::size_t successful_derivations{};
    for (std::size_t index{}; index < kWorkerCount; ++index) {
        if (pending_results[index] != nullptr) {
            ++successful_derivations;
            CHECK(!errors[index].has_error());
            CHECK(pending_results[index]->local_role() ==
                vfdual::PeerHandshakeRole::host);
            continue;
        }
        CHECK(errors[index].code ==
            vfdual::PeerHandshakeErrorCode::
                ephemeral_private_key_already_consumed);
    }
    CHECK(successful_derivations == 1U);
}

void expect_input_rejected(
    vfdual::HostPeerHandshakeTranscriptSignerV1& signer,
    vfdual::HostPeerHandshakeSigningInputV1 input,
    const vfdual::PeerHandshakeErrorCode expected,
    const std::shared_ptr<FakeKeyStats>& stats) {
    const std::size_t calls_before = stats->sign_calls;
    const auto result = signer.build_and_sign_bound_transcript(
        std::move(input));
    CHECK(!result.succeeded());
    CHECK(result.context == nullptr);
    CHECK(result.transcript_error.code == expected);
    CHECK(!result.identity_error.has_error());
    CHECK(stats->sign_calls == calls_before);
}

void test_invalid_typed_inputs_fail_before_identity_signing() {
    FakeKeyStore adapter;
    auto identity = open_development_identity(adapter);
    vfdual::HostPeerHandshakeTranscriptSignerV1 signer(*identity);

    auto input = valid_input();
    input.host_ephemeral.reset();
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_ephemeral_public_key,
        adapter.stats);

    input = valid_input();
    input.pair_id.clear();
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_pair_id, adapter.stats);

    input = valid_input();
    input.android_identity_spki_sha256 =
        identity_hash_as_bytes(identity->public_identity().public_key_sha256);
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_identity_binding,
        adapter.stats);

    input = valid_input();
    input.android_identity_spki_sha256.fill(std::byte{0U});
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_identity_binding,
        adapter.stats);

    input = valid_input();
    input.host_nonce.fill(std::byte{0U});
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_nonce, adapter.stats);

    input = valid_input();
    input.android_nonce = input.host_nonce;
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_nonce, adapter.stats);

    input = valid_input();
    input.android_nonce.fill(std::byte{0U});
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_nonce, adapter.stats);

    input = valid_input();
    input.connection_id = 0U;
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_connection_id,
        adapter.stats);

    input = valid_input();
    input.session_generation = 0U;
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_session_generation,
        adapter.stats);

    input = valid_input();
    input.transport_kind =
        static_cast<vfdual::PeerHandshakeTransportKind>(0U);
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_transport_kind,
        adapter.stats);

    input = valid_input();
    input.video_port = 0U;
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_endpoint, adapter.stats);

    input = valid_input();
    input.control_port = input.video_port;
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_endpoint, adapter.stats);

    input = valid_input();
    input.host_runtime_version = "017.8.47";
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_runtime_version,
        adapter.stats);

    input = valid_input();
    input.android_runtime_version = "17.8.47-beta";
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_runtime_version,
        adapter.stats);

    input = valid_input();
    input.pair_id = "PAIR WITH SPACE";
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_pair_id, adapter.stats);

    input = valid_input();
    input.android_ephemeral_public_key =
        fields_from_input(identity->public_identity(), input)
            .host_ephemeral_public_key;
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::invalid_ephemeral_public_key,
        adapter.stats);

    input = valid_input();
    const auto consumed_fields = fields_from_input(
        identity->public_identity(), input);
    const auto consumed_transcript =
        vfdual::build_canonical_peer_handshake_transcript_v1(
            consumed_fields,
            vfdual::PeerHandshakePairIdRequirement::require_bound_pair);
    CHECK(consumed_transcript.succeeded());
    vfdual::PeerHandshakeError consume_error;
    auto discarded_pending = input.host_ephemeral->
        derive_pending_after_peer_identity_verified(
            vfdual::PeerHandshakeRole::host,
            *consumed_transcript.transcript,
            consume_error);
    CHECK(discarded_pending != nullptr);
    CHECK(!consume_error.has_error());
    expect_input_rejected(
        signer, std::move(input),
        vfdual::PeerHandshakeErrorCode::
            ephemeral_private_key_already_consumed,
        adapter.stats);
}

void test_provider_failures_and_invalid_provider_signatures_fail_closed() {
    for (const FakeSignBehavior behavior : {
            FakeSignBehavior::provider_failure,
            FakeSignBehavior::corrupt_signature}) {
        FakeKeyStore adapter(behavior);
        auto identity = open_development_identity(adapter);
        vfdual::HostPeerHandshakeTranscriptSignerV1 signer(*identity);
        const auto result = signer.build_and_sign_bound_transcript(
            valid_input());
        CHECK(!result.succeeded());
        CHECK(result.context == nullptr);
        CHECK(!result.transcript_error.has_error());
        CHECK(result.identity_error.code ==
            vfdual::HostIdentityErrorCode::signature_failed);
        if (behavior == FakeSignBehavior::corrupt_signature) {
            CHECK(result.identity_error.operation ==
                "post_sign_verify_peer_handshake_transcript");
        }
        CHECK(adapter.stats->sign_calls == 1U);
    }
}

[[nodiscard]] std::string repeated_hex(
    const std::uint8_t value, const std::size_t count) {
    constexpr std::string_view alphabet{"0123456789abcdef"};
    std::string result;
    result.reserve(count * 2U);
    for (std::size_t index{}; index < count; ++index) {
        result.push_back(alphabet[value >> 4U]);
        result.push_back(alphabet[value & 0x0fU]);
    }
    return result;
}

[[nodiscard]] vfdual::HostPairGenerationChallengeSigningInputV1
valid_pair_pop_input(const vfdual::PeerHandshakeSha256& android_identity) {
    return {
        .request_id = repeated_hex(0x01U, 16U),
        .allocation_request_id = repeated_hex(0x02U, 16U),
        .entitlement_id = repeated_hex(0x03U, 16U),
        .pair_id = repeated_hex(0x04U, 16U),
        .binding_id = repeated_hex(0x05U, 16U),
        .binding_revision = 7U,
        .revocation_version = 9U,
        .android_identity_spki_sha256 = android_identity,
    };
}

[[nodiscard]] vfdual::PairGenerationProposalResult build_pair_pop_proposal(
    const vfdual::HostPublicIdentity& identity,
    const vfdual::PeerHandshakeSha256& android_identity,
    const vfdual::PeerHandshakeNonce& host_nonce,
    const vfdual::PeerHandshakeNonce& android_nonce,
    const std::uint64_t connection_id) {
    vfdual::PairGenerationProposalFields fields;
    fields.host_identity_spki_sha256 =
        identity_hash_as_bytes(identity.public_key_sha256);
    fields.android_identity_spki_sha256 = android_identity;
    fields.host_ephemeral_public_key = fresh_public_key();
    fields.android_ephemeral_public_key = fresh_public_key();
    fields.host_nonce = host_nonce;
    fields.android_nonce = android_nonce;
    fields.connection_id = connection_id;
    fields.transport_kind = vfdual::PeerHandshakeTransportKind::cat6;
    fields.host_ipv4 = {
        std::byte{192U}, std::byte{168U},
        std::byte{55U}, std::byte{1U}};
    fields.android_ipv4 = {
        std::byte{192U}, std::byte{168U},
        std::byte{55U}, std::byte{2U}};
    fields.video_port = 45678U;
    fields.control_port = 45679U;
    fields.pair_id = repeated_hex(0x04U, 16U);
    fields.host_runtime_version = "17.8.47";
    fields.android_runtime_version = "17.8.47";
    return vfdual::build_pair_generation_proposal_v1(fields);
}

void test_pair_generation_pop_signer_binds_authority_and_signs_only_typed_pop() {
    FakeKeyStore adapter;
    auto identity = open_development_identity(adapter);
    vfdual::HostPairGenerationPopSignerV1 signer(*identity);
    const vfdual::PeerHandshakeSha256 android_identity =
        filled_bytes<32U>(0xa5U);

    auto invalid_input = valid_pair_pop_input(android_identity);
    invalid_input.request_id.assign(32U, '0');
    auto invalid = signer.build_and_sign_challenge(
        std::move(invalid_input));
    CHECK(!invalid.succeeded());
    CHECK(invalid.protocol_error.code ==
        vfdual::PairGenerationPopErrorCode::identifier_invalid);
    CHECK(adapter.stats->sign_calls == 0U);

    auto challenge = signer.build_and_sign_challenge(
        valid_pair_pop_input(android_identity));
    CHECK(challenge.succeeded());
    CHECK(adapter.stats->sign_calls == 1U);
    CHECK(challenge.signed_challenge->request().fields().
        host_identity_spki_sha256 ==
        identity_hash_as_bytes(identity->public_identity().public_key_sha256));
    CHECK(challenge.signed_challenge->request().fields().
        android_identity_spki_sha256 == android_identity);
    CHECK(verify_transcript_signature(
        identity->public_identity(),
        challenge.signed_challenge->request().payload_sha256(),
        challenge.signed_challenge->signature_der_low_s()));

    const vfdual::PeerHandshakeNonce host_nonce =
        filled_bytes<32U>(0x31U);
    const vfdual::PeerHandshakeNonce android_nonce =
        filled_bytes<32U>(0x42U);
    const std::array<std::byte, 32U> server_nonce =
        filled_bytes<32U>(0x53U);
    const std::string challenge_id = repeated_hex(0x06U, 16U);
    const auto connection = vfdual::derive_pair_generation_connection_id_v1(
        server_nonce,
        challenge_id,
        host_nonce,
        android_nonce,
        challenge.signed_challenge->request().fields().pair_id,
        challenge.signed_challenge->request().fields().
            host_identity_spki_sha256,
        android_identity);
    CHECK(connection.succeeded());

    auto mismatched_proposal = build_pair_pop_proposal(
        identity->public_identity(),
        android_identity,
        host_nonce,
        android_nonce,
        connection.connection_id + 1U);
    CHECK(mismatched_proposal.succeeded());
    auto mismatch = signer.build_and_sign_final_credential_proof(
        *challenge.signed_challenge,
        challenge_id,
        0x1234'5678ULL,
        server_nonce,
        *mismatched_proposal.proposal);
    CHECK(!mismatch.succeeded());
    CHECK(mismatch.protocol_error.code ==
        vfdual::PairGenerationPopErrorCode::connection_id_mismatch);
    CHECK(adapter.stats->sign_calls == 1U);

    auto proposal = build_pair_pop_proposal(
        identity->public_identity(),
        android_identity,
        host_nonce,
        android_nonce,
        connection.connection_id);
    CHECK(proposal.succeeded());
    auto final_proof = signer.build_and_sign_final_credential_proof(
        *challenge.signed_challenge,
        challenge_id,
        0x1234'5678ULL,
        server_nonce,
        *proposal.proposal);
    CHECK(final_proof.succeeded());
    CHECK(adapter.stats->sign_calls == 2U);
    CHECK(final_proof.signed_proof->proof().connection_id() ==
        connection.connection_id);
    CHECK(final_proof.signed_proof->proof().transcript_proposal_sha256() ==
        proposal.proposal->proposal_sha256());
    CHECK(verify_transcript_signature(
        identity->public_identity(),
        final_proof.signed_proof->proof().payload_sha256(),
        final_proof.signed_proof->signature_der_low_s()));
}

void test_pair_generation_pop_signer_rejects_corrupt_provider_signature() {
    FakeKeyStore adapter(FakeSignBehavior::corrupt_signature);
    auto identity = open_development_identity(adapter);
    vfdual::HostPairGenerationPopSignerV1 signer(*identity);
    const auto result = signer.build_and_sign_challenge(
        valid_pair_pop_input(filled_bytes<32U>(0xa5U)));
    CHECK(!result.succeeded());
    CHECK(result.signed_challenge == nullptr);
    CHECK(result.identity_error.code ==
        vfdual::HostIdentityErrorCode::signature_failed);
    CHECK(adapter.stats->sign_calls == 1U);
}

[[nodiscard]] std::string read_text(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    CHECK(input.good());
    std::string text{
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()};
    for (std::size_t offset = text.find("\r\n");
         offset != std::string::npos;
         offset = text.find("\r\n", offset + 1U)) {
        text.replace(offset, 2U, "\n");
    }
    return text;
}

void test_public_api_and_cmake_remain_restricted_foundations() {
    const std::filesystem::path root{VFDUAL_SOURCE_DIR};
    const std::string header = read_text(
        root /
        "host/windows/security/include/vfdual/host_peer_handshake_transcript_signer_v1.hpp");
    for (const std::string_view forbidden : {
            "sign_bytes",
            "sign_digest",
            "sign_sha256_digest",
            "caller_canonical",
            "std::span<const std::byte>"}) {
        CHECK(header.find(forbidden) == std::string::npos);
    }
    CHECK(header.find("build_and_sign_bound_transcript") !=
        std::string::npos);
    CHECK(header.find("does not prove that the Android identity was paired") !=
        std::string::npos);
    CHECK(header.find("#include <mutex>") != std::string::npos);
    CHECK(header.find("std::mutex host_ephemeral_mutex_") !=
        std::string::npos);

    const std::string pair_pop_header = read_text(
        root /
        "host/windows/security/include/vfdual/host_pair_generation_pop_signer_v1.hpp");
    for (const std::string_view forbidden : {
            "sign_bytes",
            "sign_digest",
            "sign_sha256_digest",
            "host_identity_spki_sha256{}"}) {
        CHECK(pair_pop_header.find(forbidden) == std::string::npos);
    }
    CHECK(pair_pop_header.find("build_and_sign_challenge") !=
        std::string::npos);
    CHECK(pair_pop_header.find(
        "build_and_sign_final_credential_proof") != std::string::npos);

    const std::string source = read_text(
        root /
        "host/windows/security/src/host_peer_handshake_transcript_signer_v1.cpp");
    CHECK(source.find("handshake_policy_error") == std::string::npos);
    CHECK(source.find("std::lock_guard lock(host_ephemeral_mutex_)") !=
        std::string::npos);
    const std::size_t allocation_constant = source.find(
        "inline constexpr PeerHandshakeError kAllocationFailureError");
    CHECK(allocation_constant != std::string::npos);
    const std::size_t allocation_constant_end = source.find(
        "};", allocation_constant);
    CHECK(allocation_constant_end != std::string::npos);
    const std::string allocation_constant_block = source.substr(
        allocation_constant,
        allocation_constant_end - allocation_constant);
    CHECK(allocation_constant_block.find("allocation_failed") !=
        std::string::npos);
    CHECK(allocation_constant_block.find(".operation") ==
        std::string::npos);
    const std::size_t bad_alloc_handler = source.find(
        "catch (const std::bad_alloc&)");
    CHECK(bad_alloc_handler != std::string::npos);
    const std::size_t catch_all_handler = source.find(
        "catch (...)", bad_alloc_handler);
    CHECK(catch_all_handler != std::string::npos);
    const std::string bad_alloc_block = source.substr(
        bad_alloc_handler,
        catch_all_handler - bad_alloc_handler);
    CHECK(bad_alloc_block.find("kAllocationFailureError") !=
        std::string::npos);
    CHECK(bad_alloc_block.find(".operation") == std::string::npos);
    CHECK(bad_alloc_block.find(
        "build_and_sign_bound_host_transcript") == std::string::npos);

    const std::string cmake = read_text(root / "CMakeLists.txt");
    CHECK(cmake.find(
        "add_library(vfdual_host_peer_handshake_transcript_signer_v1 STATIC") !=
        std::string::npos);
    CHECK(cmake.find(
        "add_library(vfdual_host_pair_generation_pop_signer_v1 STATIC") !=
        std::string::npos);
    CHECK(cmake.find("formal_security_loader.cmake") !=
        std::string::npos);
    CHECK(cmake.find("formal_security_capability.cmake") ==
        std::string::npos);
    const std::string formal_capability = read_text(
        root / "formal_security_capability.cmake");
    CHECK(formal_capability ==
            "set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED OFF)\n" ||
        formal_capability ==
            "set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED ON)\n");
    const std::string formal_loader = read_text(
        root / "formal_security_loader.cmake");
    CHECK(formal_loader.find(
        "include(\"${CMAKE_CURRENT_LIST_DIR}/formal_security_capability.cmake\")") ==
        0U);
    CHECK(formal_loader.find(
        "set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED") == std::string::npos);
    CHECK(formal_loader.find(
        "if(NOT DEFINED VFDUAL_FORMAL_SECURITY_IMPLEMENTED OR") !=
        std::string::npos);
    CHECK(formal_loader.find(
        "NOT \"${VFDUAL_FORMAL_SECURITY_IMPLEMENTED}\" MATCHES \"^(ON|OFF)$\")") !=
        std::string::npos);
    CHECK(formal_loader.find(
        "message(FATAL_ERROR \"Formal security capability must be exactly ON or OFF\")") !=
        std::string::npos);
    const std::size_t host_link = cmake.find(
        "target_link_libraries(VisionForgeHost PRIVATE");
    CHECK(host_link != std::string::npos);
    const std::size_t host_link_end = cmake.find(')', host_link);
    CHECK(host_link_end != std::string::npos);
    CHECK(cmake.substr(host_link, host_link_end - host_link).find(
        "vfdual_host_peer_handshake_transcript_signer_v1") ==
        std::string::npos);
}

}  // namespace

int main() {
    test_valid_signature_binds_every_typed_field_and_derives_once();
    test_concurrent_derivation_releases_ephemeral_owner_exactly_once();
    test_invalid_typed_inputs_fail_before_identity_signing();
    test_provider_failures_and_invalid_provider_signatures_fail_closed();
    test_pair_generation_pop_signer_binds_authority_and_signs_only_typed_pop();
    test_pair_generation_pop_signer_rejects_corrupt_provider_signature();
    test_public_api_and_cmake_remain_restricted_foundations();
    std::cout << "host peer handshake transcript signer v1 tests passed\n";
    return EXIT_SUCCESS;
}
