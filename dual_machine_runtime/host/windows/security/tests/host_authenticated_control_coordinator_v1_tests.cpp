#include "vfdual/host_authenticated_control_coordinator_v1.hpp"

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
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
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

namespace {

constexpr std::array<std::uint8_t, 32U> kP256HalfOrder{
    0x7fU, 0xffU, 0xffU, 0xffU, 0x80U, 0x00U, 0x00U, 0x00U,
    0x7fU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
    0xdeU, 0x73U, 0x7dU, 0x56U, 0xd3U, 0x8bU, 0xcfU, 0x42U,
    0x79U, 0xdcU, 0xe5U, 0x61U, 0x7eU, 0x31U, 0x92U, 0xa8U};
constexpr std::array<std::uint8_t, 32U> kP256Order{
    0xffU, 0xffU, 0xffU, 0xffU, 0x00U, 0x00U, 0x00U, 0x00U,
    0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
    0xbcU, 0xe6U, 0xfaU, 0xadU, 0xa7U, 0x17U, 0x9eU, 0x84U,
    0xf3U, 0xb9U, 0xcaU, 0xc2U, 0xfcU, 0x63U, 0x25U, 0x51U};

[[nodiscard]] vfdual::HostIdentityError test_error(
    const vfdual::HostIdentityErrorCode code,
    const std::string_view operation) {
    return {.code = code, .operation = std::string(operation)};
}

class EphemeralBcryptSigningKey final : public vfdual::CngSigningKey {
public:
    ~EphemeralBcryptSigningKey() override {
        if (key_ != nullptr) static_cast<void>(BCryptDestroyKey(key_));
        if (algorithm_ != nullptr) {
            static_cast<void>(BCryptCloseAlgorithmProvider(algorithm_, 0U));
        }
    }

    [[nodiscard]] static std::unique_ptr<EphemeralBcryptSigningKey> create(
        vfdual::HostIdentityError& error) {
        auto result = std::unique_ptr<EphemeralBcryptSigningKey>(
            new EphemeralBcryptSigningKey());
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &result->algorithm_, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            error = test_error(
                vfdual::HostIdentityErrorCode::key_open_or_create_failed,
                "test_open_ecdsa_provider");
            return nullptr;
        }
        status = BCryptGenerateKeyPair(
            result->algorithm_, &result->key_, 256U, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            error = test_error(
                vfdual::HostIdentityErrorCode::key_open_or_create_failed,
                "test_generate_ecdsa_key");
            return nullptr;
        }
        status = BCryptFinalizeKeyPair(result->key_, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            error = test_error(
                vfdual::HostIdentityErrorCode::key_finalize_failed,
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
        ULONG required{};
        NTSTATUS status = BCryptExportKey(
            key_, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0U, &required, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, test_error(
                vfdual::HostIdentityErrorCode::public_key_export_failed,
                "test_query_public_blob")};
        }
        std::vector<std::uint8_t> output(required);
        ULONG written{};
        status = BCryptExportKey(
            key_, nullptr, BCRYPT_ECCPUBLIC_BLOB,
            output.data(), static_cast<ULONG>(output.size()),
            &written, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, test_error(
                vfdual::HostIdentityErrorCode::public_key_export_failed,
                "test_export_public_blob")};
        }
        output.resize(written);
        return {std::move(output), {}};
    }

    [[nodiscard]] vfdual::HostIdentityBytesResult sign_sha256_digest(
        const std::span<const std::uint8_t> digest) override {
        if (digest.size() != 32U) {
            return {{}, test_error(
                vfdual::HostIdentityErrorCode::signature_failed,
                "test_reject_digest_size")};
        }
        ULONG required{};
        NTSTATUS status = BCryptSignHash(
            key_, nullptr, const_cast<PUCHAR>(digest.data()),
            static_cast<ULONG>(digest.size()), nullptr, 0U, &required, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, test_error(
                vfdual::HostIdentityErrorCode::signature_failed,
                "test_query_signature")};
        }
        std::vector<std::uint8_t> output(required);
        ULONG written{};
        status = BCryptSignHash(
            key_, nullptr, const_cast<PUCHAR>(digest.data()),
            static_cast<ULONG>(digest.size()),
            output.data(), static_cast<ULONG>(output.size()),
            &written, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, test_error(
                vfdual::HostIdentityErrorCode::signature_failed,
                "test_create_signature")};
        }
        output.resize(written);
        return {std::move(output), {}};
    }

    [[nodiscard]] vfdual::HostIdentityError
    discard_new_persisted_key_after_failed_initialization() override {
        return {};
    }

private:
    EphemeralBcryptSigningKey()
        : metadata_{
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
        } {}

    vfdual::CngKeyMetadata metadata_;
    BCRYPT_ALG_HANDLE algorithm_{};
    BCRYPT_KEY_HANDLE key_{};
};

class FakeKeyStore final : public vfdual::CngKeyStoreAdapter {
public:
    [[nodiscard]] vfdual::CngKeyOpenResult
    open_or_create_p256_signing_key(
        const vfdual::CngKeyOpenRequest&) override {
        vfdual::HostIdentityError error;
        auto key = EphemeralBcryptSigningKey::create(error);
        if (key == nullptr) return {nullptr, std::move(error)};
        last_key = key.get();
        return {std::move(key), {}};
    }

    EphemeralBcryptSigningKey* last_key{};
};

[[nodiscard]] std::unique_ptr<vfdual::HostCngDeviceIdentity>
open_identity(FakeKeyStore& store) {
    vfdual::HostIdentityError error;
    auto identity = vfdual::HostCngDeviceIdentity::
        open_development_with_adapter(
            vfdual::HostIdentityPolicy::
                development_named_software_provider(
                    std::wstring(
                        vfdual::kMicrosoftSoftwareKeyStorageProvider)),
            store,
            error);
    CHECK(identity != nullptr);
    CHECK(!error.has_error());
    CHECK(store.last_key != nullptr);
    return identity;
}

[[nodiscard]] std::unique_ptr<
    vfdual::PlatformP256EphemeralKeyAgreementV1> fresh_ephemeral() {
    vfdual::PeerHandshakeError error;
    auto key = vfdual::PlatformP256EphemeralKeyAgreementV1::
        generate_platform(error);
    CHECK(key != nullptr);
    CHECK(!error.has_error());
    return key;
}

template <std::size_t Size>
[[nodiscard]] std::array<std::byte, Size> filled_bytes(
    const std::uint8_t value) {
    std::array<std::byte, Size> result{};
    result.fill(std::byte{value});
    return result;
}

[[nodiscard]] vfdual::PeerHandshakeSha256 identity_hash(
    const vfdual::HostPublicIdentity& identity) {
    vfdual::PeerHandshakeSha256 result{};
    std::transform(
        identity.public_key_sha256.begin(),
        identity.public_key_sha256.end(),
        result.begin(),
        [](const std::uint8_t value) { return std::byte{value}; });
    return result;
}

[[nodiscard]] std::array<std::uint8_t, 32U> digest_bytes(
    const vfdual::PeerHandshakeSha256& digest) {
    std::array<std::uint8_t, 32U> result{};
    std::transform(
        digest.begin(), digest.end(), result.begin(),
        [](const std::byte value) {
            return std::to_integer<std::uint8_t>(value);
        });
    return result;
}

[[nodiscard]] std::array<std::uint8_t, 32U> subtract_scalar(
    const std::array<std::uint8_t, 32U>& minuend,
    const std::array<std::uint8_t, 32U>& subtrahend) {
    std::array<std::uint8_t, 32U> result{};
    unsigned borrow{};
    for (std::size_t offset{}; offset < result.size(); ++offset) {
        const std::size_t index = result.size() - 1U - offset;
        const unsigned left = minuend[index];
        const unsigned right =
            static_cast<unsigned>(subtrahend[index]) + borrow;
        if (left >= right) {
            result[index] = static_cast<std::uint8_t>(left - right);
            borrow = 0U;
        } else {
            result[index] = static_cast<std::uint8_t>(
                0x100U + left - right);
            borrow = 1U;
        }
    }
    CHECK(borrow == 0U);
    return result;
}

void append_der_integer(
    std::vector<std::uint8_t>& output,
    const std::array<std::uint8_t, 32U>& scalar) {
    const auto first_nonzero = std::find_if(
        scalar.begin(), scalar.end(),
        [](const std::uint8_t value) { return value != 0U; });
    CHECK(first_nonzero != scalar.end());
    const bool prefix = (*first_nonzero & 0x80U) != 0U;
    output.push_back(0x02U);
    output.push_back(static_cast<std::uint8_t>(
        scalar.end() - first_nonzero + (prefix ? 1U : 0U)));
    if (prefix) output.push_back(0x00U);
    output.insert(output.end(), first_nonzero, scalar.end());
}

[[nodiscard]] std::vector<std::uint8_t> canonical_der(
    const std::span<const std::uint8_t> p1363) {
    CHECK(p1363.size() == 64U);
    std::array<std::uint8_t, 32U> r{};
    std::array<std::uint8_t, 32U> s{};
    std::copy_n(p1363.begin(), r.size(), r.begin());
    std::copy_n(p1363.begin() + 32U, s.size(), s.begin());
    if (std::lexicographical_compare(
            kP256HalfOrder.begin(), kP256HalfOrder.end(),
            s.begin(), s.end())) {
        s = subtract_scalar(kP256Order, s);
    }
    std::vector<std::uint8_t> payload;
    append_der_integer(payload, r);
    append_der_integer(payload, s);
    std::vector<std::uint8_t> der{
        0x30U, static_cast<std::uint8_t>(payload.size())};
    der.insert(der.end(), payload.begin(), payload.end());
    return der;
}

[[nodiscard]] std::vector<std::uint8_t> sign_digest(
    EphemeralBcryptSigningKey& key,
    const vfdual::PeerHandshakeSha256& digest) {
    const auto bytes = digest_bytes(digest);
    auto raw = key.sign_sha256_digest(bytes);
    CHECK(raw.succeeded());
    return canonical_der(raw.bytes);
}

[[nodiscard]] bool verify_digest_signature(
    const vfdual::HostPublicIdentity& identity,
    const vfdual::PeerHandshakeSha256& digest,
    const std::span<const std::uint8_t> der) {
    if (identity.subject_public_key_info_der.size() != 91U ||
        der.size() < 8U || der.size() > 72U || der[0U] != 0x30U) {
        return false;
    }
    auto read_scalar = [&](std::size_t& offset,
                           std::array<std::uint8_t, 32U>& scalar) {
        if (offset + 2U > der.size() || der[offset] != 0x02U) return false;
        const std::size_t size = der[offset + 1U];
        offset += 2U;
        if (size == 0U || size > 33U || offset + size > der.size()) return false;
        auto encoded = der.subspan(offset, size);
        offset += size;
        if (size == 33U) {
            if (encoded.front() != 0U) return false;
            encoded = encoded.subspan(1U);
        }
        if (encoded.size() > scalar.size()) return false;
        std::copy(encoded.begin(), encoded.end(),
            scalar.end() - static_cast<std::ptrdiff_t>(encoded.size()));
        return true;
    };
    if (der[1U] != der.size() - 2U) return false;
    std::size_t offset = 2U;
    std::array<std::uint8_t, 32U> r{};
    std::array<std::uint8_t, 32U> s{};
    if (!read_scalar(offset, r) || !read_scalar(offset, s) ||
        offset != der.size()) return false;
    std::array<std::uint8_t, 64U> raw{};
    std::copy(r.begin(), r.end(), raw.begin());
    std::copy(s.begin(), s.end(), raw.begin() + 32U);

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
    BCRYPT_KEY_HANDLE public_key{};
    const NTSTATUS imported = BCryptImportKeyPair(
        algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB, &public_key,
        blob.data(), static_cast<ULONG>(blob.size()), 0U);
    if (!BCRYPT_SUCCESS(imported)) {
        static_cast<void>(BCryptCloseAlgorithmProvider(algorithm, 0U));
        return false;
    }
    const auto digest_value = digest_bytes(digest);
    const NTSTATUS verified = BCryptVerifySignature(
        public_key, nullptr,
        const_cast<PUCHAR>(digest_value.data()),
        static_cast<ULONG>(digest_value.size()),
        raw.data(), static_cast<ULONG>(raw.size()), 0U);
    static_cast<void>(BCryptDestroyKey(public_key));
    static_cast<void>(BCryptCloseAlgorithmProvider(algorithm, 0U));
    return BCRYPT_SUCCESS(verified);
}

[[nodiscard]] std::vector<std::byte> bytes(
    const std::span<const std::uint8_t> value) {
    std::vector<std::byte> output(value.size());
    std::transform(
        value.begin(), value.end(), output.begin(),
        [](const std::uint8_t current) { return std::byte{current}; });
    return output;
}

[[nodiscard]] std::vector<std::byte> ascii(
    const std::string_view value) {
    std::vector<std::byte> output(value.size());
    std::transform(
        value.begin(), value.end(), output.begin(),
        [](const char current) {
            return std::byte{static_cast<std::uint8_t>(current)};
        });
    return output;
}

[[nodiscard]] std::vector<std::byte> u64(const std::uint64_t value) {
    std::vector<std::byte> output(8U);
    for (std::size_t index{}; index < output.size(); ++index) {
        output[index] = std::byte{static_cast<std::uint8_t>(
            value >> ((output.size() - index - 1U) * 8U))};
    }
    return output;
}

[[nodiscard]] std::vector<std::byte> encode_android_record(
    const vfdual::ControlBootstrapMessageTypeV1 message_type,
    const std::vector<std::vector<std::byte>>& values) {
    std::vector<vfdual::ControlBootstrapPayloadFieldV1> fields;
    fields.reserve(values.size());
    for (std::size_t index{}; index < values.size(); ++index) {
        fields.push_back({static_cast<std::uint8_t>(index), values[index]});
    }
    auto payload = vfdual::encode_control_bootstrap_payload_v1(
        message_type, fields);
    CHECK(payload.status ==
        vfdual::ControlBootstrapPayloadStatusV1::encoded);
    auto record = vfdual::encode_authenticated_control_bootstrap_record_v1(
        vfdual::ControlBootstrapDirectionV1::android_to_host,
        message_type,
        payload.payload);
    CHECK(record.status == vfdual::ControlBootstrapEncodeStatusV1::encoded);
    return std::move(record.record);
}

[[nodiscard]] std::vector<std::vector<std::byte>> parse_host_record(
    const std::span<const std::byte> record,
    const vfdual::ControlBootstrapMessageTypeV1 message_type) {
    const auto framed = vfdual::parse_authenticated_control_bootstrap_record_v1(
        record, vfdual::ControlBootstrapDirectionV1::host_to_android);
    CHECK(framed.status == vfdual::ControlBootstrapParseStatusV1::parsed);
    CHECK(framed.record.message_type == message_type);
    const auto payload = vfdual::parse_control_bootstrap_payload_v1(
        message_type, framed.record.payload);
    CHECK(payload.status == vfdual::ControlBootstrapPayloadStatusV1::parsed);
    std::vector<std::vector<std::byte>> fields;
    fields.reserve(payload.payload.field_count);
    for (std::size_t index{}; index < payload.payload.field_count; ++index) {
        const auto field = payload.payload.field(
            static_cast<std::uint8_t>(index));
        fields.emplace_back(field.begin(), field.end());
    }
    return fields;
}

[[nodiscard]] std::span<const std::uint8_t> as_unsigned(
    const std::vector<std::byte>& value) {
    return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}

[[nodiscard]] bool equal_key_material(
    const vfdual::PeerHandshakeDataPlaneKeyView left,
    const vfdual::PeerHandshakeDataPlaneKeyView right) {
    return std::equal(
               left.aes_256_key.begin(), left.aes_256_key.end(),
               right.aes_256_key.begin(), right.aes_256_key.end()) &&
        std::equal(
            left.nonce_prefix.begin(), left.nonce_prefix.end(),
            right.nonce_prefix.begin(), right.nonce_prefix.end());
}

struct Scenario final {
    static constexpr std::int64_t kEpoch = 1'900'000'000;
    static constexpr std::uint64_t kMonotonic = 10'000U;
    static constexpr std::uint64_t kGeneration = 7U;

    FakeKeyStore host_store;
    FakeKeyStore android_store;
    std::unique_ptr<vfdual::HostCngDeviceIdentity> host_identity;
    std::unique_ptr<vfdual::HostCngDeviceIdentity> android_identity;
    vfdual::HostPairGenerationPopSignerV1 pair_pop_signer;
    vfdual::HostPeerHandshakeTranscriptSignerV1 transcript_signer;
    std::unique_ptr<vfdual::PlatformP256EphemeralKeyAgreementV1>
        android_ephemeral;
    vfdual::PeerHandshakeP256PublicKey host_ephemeral_public{};
    vfdual::PeerHandshakeP256PublicKey android_ephemeral_public{};
    vfdual::PeerHandshakeNonce host_nonce{filled_bytes<32U>(0x31U)};
    vfdual::PeerHandshakeNonce android_nonce{filled_bytes<32U>(0x42U)};
    vfdual::HostAuthenticatedControlPairBindingV1 pair;
    vfdual::HostAuthenticatedControlRouteV1 route;
    std::unique_ptr<vfdual::HostAuthenticatedControlCoordinatorV1> coordinator;
    std::optional<vfdual::CanonicalPairGenerationChallengeRequestV1>
        challenge_request;
    std::optional<vfdual::VerifiedPairGenerationProposalV1> proposal;
    std::optional<vfdual::CanonicalPeerHandshakeTranscriptV1> transcript;
    std::unique_ptr<vfdual::PendingPeerHandshakeConfirmationV1>
        android_pending;
    std::string request_id = std::string(32U, 'a');
    std::string allocation_request_id = std::string(32U, 'b');
    std::string challenge_id = std::string(32U, 'c');
    vfdual::PeerHandshakeNonce server_nonce{filled_bytes<32U>(0x53U)};
    bool credential_allow{true};
    bool credential_ready{};
    std::size_t credential_calls{};
    std::uint64_t expected_connection_id{};
    std::string expected_proposal_hash;

    explicit Scenario(const std::uint64_t generation_high_watermark = 0U)
        : host_identity(open_identity(host_store)),
          android_identity(open_identity(android_store)),
          pair_pop_signer(*host_identity),
          transcript_signer(*host_identity),
          android_ephemeral(fresh_ephemeral()) {
        auto host_ephemeral = fresh_ephemeral();
        std::copy(
            host_ephemeral->public_key_sec1().begin(),
            host_ephemeral->public_key_sec1().end(),
            host_ephemeral_public.begin());
        std::copy(
            android_ephemeral->public_key_sec1().begin(),
            android_ephemeral->public_key_sec1().end(),
            android_ephemeral_public.begin());
        pair = {
            .entitlement_id = std::string(32U, '1'),
            .pair_id = std::string(32U, '2'),
            .binding_id = std::string(32U, '3'),
            .binding_revision = 4U,
            .revocation_version = 5U,
            .generation_high_watermark = generation_high_watermark,
            .host_identity_spki_sha256 =
                host_identity->public_identity().public_key_sha256_hex,
            .android_identity_spki_sha256 =
                android_identity->public_identity().public_key_sha256_hex,
            .android_subject_public_key_info_der =
                android_identity->public_identity().subject_public_key_info_der,
        };
        route = {
            .transport_kind = vfdual::PeerHandshakeTransportKind::cat6,
            .host_ipv4 = {
                std::byte{10U}, std::byte{57U},
                std::byte{23U}, std::byte{1U}},
            .android_ipv4 = {
                std::byte{10U}, std::byte{57U},
                std::byte{23U}, std::byte{2U}},
            .video_port = 5000U,
            .control_port = 5006U,
            .host_runtime_version = "17.8.47",
        };
        auto created = vfdual::HostAuthenticatedControlCoordinatorV1::
            create_for_test(
                host_identity->public_identity(),
                pair_pop_signer,
                transcript_signer,
                pair,
                route,
                time(),
                std::move(host_ephemeral),
                host_nonce,
                &Scenario::verify_credential,
                this);
        CHECK(created.succeeded());
        coordinator = std::move(created.coordinator);
    }

    [[nodiscard]] static vfdual::HostAuthenticatedControlTimeV1 time(
        const std::uint64_t elapsed_ms = 0U,
        const std::int64_t elapsed_seconds = 0) {
        return {
            .epoch_seconds = kEpoch + elapsed_seconds,
            .monotonic_milliseconds = kMonotonic + elapsed_ms,
        };
    }

    [[nodiscard]] static bool verify_credential(
        void* context,
        const std::string_view token,
        const vfdual::HostPairGenerationCredentialExpectedV1& expected,
        const std::int64_t now_epoch) noexcept {
        auto& self = *static_cast<Scenario*>(context);
        ++self.credential_calls;
        return self.credential_allow && self.credential_ready &&
            token == "a.b.c" && now_epoch == kEpoch + 3 &&
            expected.allocation_request_id == self.allocation_request_id &&
            expected.pair_id == self.pair.pair_id &&
            expected.entitlement_id == self.pair.entitlement_id &&
            expected.binding_id == self.pair.binding_id &&
            expected.binding_revision ==
                static_cast<std::int64_t>(self.pair.binding_revision) &&
            expected.revocation_version ==
                static_cast<std::int64_t>(self.pair.revocation_version) &&
            expected.generation == static_cast<std::int64_t>(kGeneration) &&
            expected.connection_id ==
                static_cast<std::int64_t>(self.expected_connection_id) &&
            expected.host_identity_spki_sha256 ==
                self.pair.host_identity_spki_sha256 &&
            expected.android_identity_spki_sha256 ==
                self.pair.android_identity_spki_sha256 &&
            expected.transcript_proposal_sha256 == self.expected_proposal_hash;
    }

    [[nodiscard]] std::vector<std::byte> start() {
        auto result = coordinator->start(time());
        CHECK(result.succeeded());
        const auto fields = parse_host_record(
            result.outbound_record,
            vfdual::ControlBootstrapMessageTypeV1::host_hello);
        CHECK(fields.size() == 9U);
        CHECK(std::equal(
            as_unsigned(fields[0U]).begin(), as_unsigned(fields[0U]).end(),
            host_identity->public_identity().subject_public_key_info_der.begin(),
            host_identity->public_identity().subject_public_key_info_der.end()));
        CHECK(fields[1U] == std::vector<std::byte>(
            host_ephemeral_public.begin(), host_ephemeral_public.end()));
        CHECK(fields[2U] == std::vector<std::byte>(
            host_nonce.begin(), host_nonce.end()));
        return result.outbound_record;
    }

    [[nodiscard]] std::vector<std::byte> android_challenge_record(
        const bool corrupt_signature = false) {
        vfdual::PairGenerationChallengeFieldsV1 fields{
            .request_id = request_id,
            .allocation_request_id = allocation_request_id,
            .entitlement_id = pair.entitlement_id,
            .pair_id = pair.pair_id,
            .binding_id = pair.binding_id,
            .binding_revision = pair.binding_revision,
            .revocation_version = pair.revocation_version,
            .host_identity_spki_sha256 = identity_hash(
                host_identity->public_identity()),
            .android_identity_spki_sha256 = identity_hash(
                android_identity->public_identity()),
        };
        auto built = vfdual::build_pair_generation_challenge_request_v1(fields);
        if (!built.succeeded()) {
            std::cerr << "challenge build failed: "
                      << vfdual::pair_generation_pop_error_code_name(
                             built.error.code)
                      << '\n';
        }
        CHECK(built.succeeded());
        challenge_request = *built.request;
        auto signature = sign_digest(
            *android_store.last_key, built.request->payload_sha256());
        if (corrupt_signature) signature.back() ^= 0x01U;
        return encode_android_record(
            vfdual::ControlBootstrapMessageTypeV1::android_challenge_request,
            {
                ascii(request_id),
                ascii(allocation_request_id),
                ascii(pair.entitlement_id),
                ascii(pair.pair_id),
                ascii(pair.binding_id),
                u64(pair.binding_revision),
                u64(pair.revocation_version),
                bytes(android_identity->public_identity().
                    subject_public_key_info_der),
                std::vector<std::byte>(
                    android_ephemeral_public.begin(),
                    android_ephemeral_public.end()),
                std::vector<std::byte>(
                    android_nonce.begin(), android_nonce.end()),
                ascii("17.8.47"),
                bytes(signature),
            });
    }

    [[nodiscard]] std::vector<std::byte> accept_android_challenge() {
        auto result = coordinator->accept_android_challenge_request(
            android_challenge_record(), time(1'000U, 1));
        CHECK(result.succeeded());
        const auto fields = parse_host_record(
            result.outbound_record,
            vfdual::ControlBootstrapMessageTypeV1::host_challenge_proof);
        CHECK(fields.size() == 1U);
        CHECK(verify_digest_signature(
            host_identity->public_identity(),
            challenge_request->payload_sha256(),
            as_unsigned(fields[0U])));
        return result.outbound_record;
    }

    [[nodiscard]] std::vector<std::byte> server_challenge_record(
        const std::uint64_t expires_at =
            static_cast<std::uint64_t>(kEpoch + 31)) const {
        return encode_android_record(
            vfdual::ControlBootstrapMessageTypeV1::server_challenge,
            {
                ascii(challenge_id),
                u64(expires_at),
                std::vector<std::byte>(
                    server_nonce.begin(), server_nonce.end()),
            });
    }

    [[nodiscard]] std::vector<std::byte> accept_server_challenge() {
        const auto connection = vfdual::derive_pair_generation_connection_id_v1(
            server_nonce,
            challenge_id,
            host_nonce,
            android_nonce,
            pair.pair_id,
            identity_hash(host_identity->public_identity()),
            identity_hash(android_identity->public_identity()));
        CHECK(connection.succeeded());
        vfdual::PairGenerationProposalFields fields{
            .host_identity_spki_sha256 = identity_hash(
                host_identity->public_identity()),
            .android_identity_spki_sha256 = identity_hash(
                android_identity->public_identity()),
            .host_ephemeral_public_key = host_ephemeral_public,
            .android_ephemeral_public_key = android_ephemeral_public,
            .host_nonce = host_nonce,
            .android_nonce = android_nonce,
            .connection_id = connection.connection_id,
            .transport_kind = route.transport_kind,
            .host_ipv4 = route.host_ipv4,
            .android_ipv4 = route.android_ipv4,
            .video_port = route.video_port,
            .control_port = route.control_port,
            .pair_id = pair.pair_id,
            .host_runtime_version = route.host_runtime_version,
            .android_runtime_version = "17.8.47",
        };
        auto built = vfdual::build_pair_generation_proposal_v1(fields);
        CHECK(built.succeeded());
        proposal = *built.proposal;
        expected_connection_id = connection.connection_id;
        expected_proposal_hash = lower_hex(built.proposal->proposal_sha256());

        auto result = coordinator->accept_server_challenge(
            server_challenge_record(), time(2'000U, 2));
        CHECK(result.succeeded());
        const auto host_fields = parse_host_record(
            result.outbound_record,
            vfdual::ControlBootstrapMessageTypeV1::host_final_proof);
        CHECK(host_fields.size() == 1U);
        const auto proof = vfdual::build_pair_generation_final_credential_proof_v1(
            *challenge_request,
            challenge_id,
            static_cast<std::uint64_t>(kEpoch + 31),
            server_nonce,
            *proposal);
        CHECK(proof.succeeded());
        CHECK(verify_digest_signature(
            host_identity->public_identity(),
            proof.proof->payload_sha256(),
            as_unsigned(host_fields[0U])));
        return result.outbound_record;
    }

    [[nodiscard]] static std::string lower_hex(
        const vfdual::PeerHandshakeSha256& digest) {
        constexpr std::string_view digits{"0123456789abcdef"};
        std::string result(digest.size() * 2U, '0');
        for (std::size_t index{}; index < digest.size(); ++index) {
            const auto value = std::to_integer<std::uint8_t>(digest[index]);
            result[index * 2U] = digits[value >> 4U];
            result[index * 2U + 1U] = digits[value & 0x0fU];
        }
        return result;
    }

    [[nodiscard]] std::vector<std::byte> credential_record(
        const std::uint64_t generation = kGeneration,
        const bool wrong_connection = false,
        const bool wrong_hash = false) const {
        auto hash = proposal->proposal_sha256();
        if (wrong_hash) hash[0U] ^= std::byte{0x01U};
        return encode_android_record(
            vfdual::ControlBootstrapMessageTypeV1::pair_generation_credential,
            {
                u64(generation),
                u64(expected_connection_id + (wrong_connection ? 1U : 0U)),
                std::vector<std::byte>(hash.begin(), hash.end()),
                ascii("a.b.c"),
            });
    }

    [[nodiscard]] std::vector<std::byte> accept_credential() {
        credential_ready = true;
        auto result = coordinator->accept_pair_generation_credential(
            credential_record(), time(3'000U, 3));
        CHECK(result.succeeded());
        CHECK(credential_calls == 1U);
        auto built_transcript =
            vfdual::build_final_peer_handshake_transcript_from_proposal_v1(
                *proposal, static_cast<std::int64_t>(kGeneration));
        CHECK(built_transcript.succeeded());
        transcript = *built_transcript.transcript;
        const auto fields = parse_host_record(
            result.outbound_record,
            vfdual::ControlBootstrapMessageTypeV1::host_handshake_signature);
        CHECK(fields.size() == 1U);
        CHECK(verify_digest_signature(
            host_identity->public_identity(),
            transcript->transcript_sha256(),
            as_unsigned(fields[0U])));

        vfdual::PeerHandshakeError pending_error;
        android_pending = android_ephemeral->
            derive_pending_after_peer_identity_verified(
                vfdual::PeerHandshakeRole::android,
                *transcript,
                pending_error);
        CHECK(android_pending != nullptr);
        CHECK(!pending_error.has_error());
        return result.outbound_record;
    }

    [[nodiscard]] std::vector<std::byte> confirmation_record(
        const bool wrong_finished = false,
        const bool wrong_signature = false) {
        auto signature = sign_digest(
            *android_store.last_key, transcript->transcript_sha256());
        if (wrong_signature) signature.back() ^= 0x01U;
        auto finished = android_pending->create_local_finished_mac();
        CHECK(finished.succeeded());
        auto finished_bytes = *finished.digest;
        if (wrong_finished) finished_bytes[0U] ^= std::byte{0x01U};
        return encode_android_record(
            vfdual::ControlBootstrapMessageTypeV1::
                android_handshake_confirmation,
            {
                bytes(signature),
                std::vector<std::byte>(
                    finished_bytes.begin(), finished_bytes.end()),
            });
    }

    void complete_successfully() {
        auto result = coordinator->accept_android_handshake_confirmation(
            confirmation_record(), time(4'000U, 4));
        CHECK(result.succeeded());
        CHECK(result.session_generation == kGeneration);
        CHECK(coordinator->is_closed());
        CHECK(coordinator->is_completed());
        CHECK(coordinator->accepted_event_count() == 9U);
        const auto fields = parse_host_record(
            result.host_finished_record,
            vfdual::ControlBootstrapMessageTypeV1::host_finished);
        CHECK(fields.size() == 1U);
        auto android_confirmed = std::move(*android_pending).
            confirm_peer_finished_and_consume(fields[0U]);
        CHECK(android_confirmed.peer_finished_accepted());
        CHECK(result.confirmed_session->local_role() ==
            vfdual::PeerHandshakeRole::host);
        CHECK(android_confirmed.confirmed_session->local_role() ==
            vfdual::PeerHandshakeRole::android);
        CHECK(result.confirmed_session->connection_id() ==
            android_confirmed.confirmed_session->connection_id());
        CHECK(result.confirmed_session->transcript_sha256() ==
            android_confirmed.confirmed_session->transcript_sha256());
        CHECK(result.confirmed_session->channel_binding_sha256() ==
            android_confirmed.confirmed_session->channel_binding_sha256());
        CHECK(equal_key_material(
            result.confirmed_session->control_host_to_android(),
            android_confirmed.confirmed_session->control_host_to_android()));
        CHECK(equal_key_material(
            result.confirmed_session->control_android_to_host(),
            android_confirmed.confirmed_session->control_android_to_host()));
        CHECK(equal_key_material(
            result.confirmed_session->presence_host_to_android(),
            android_confirmed.confirmed_session->presence_host_to_android()));
        CHECK(equal_key_material(
            result.confirmed_session->video_host_to_android(),
            android_confirmed.confirmed_session->video_host_to_android()));
        CHECK(equal_key_material(
            result.confirmed_session->idr_android_to_host(),
            android_confirmed.confirmed_session->idr_android_to_host()));
        CHECK(equal_key_material(
            result.confirmed_session->mouse_host_to_android(),
            android_confirmed.confirmed_session->mouse_host_to_android()));
    }
};

void complete_full_nine_record_exchange() {
    Scenario scenario;
    static_cast<void>(scenario.start());
    static_cast<void>(scenario.accept_android_challenge());
    static_cast<void>(scenario.accept_server_challenge());
    static_cast<void>(scenario.accept_credential());
    scenario.complete_successfully();
}

void duplicate_and_out_of_order_records_burn_owner() {
    {
        Scenario scenario;
        static_cast<void>(scenario.start());
        auto duplicate = scenario.coordinator->start(Scenario::time());
        CHECK(!duplicate.succeeded());
        CHECK(duplicate.error.code ==
            vfdual::HostAuthenticatedControlErrorCodeV1::unexpected_record);
        CHECK(scenario.coordinator->is_closed());
    }
    {
        Scenario scenario;
        static_cast<void>(scenario.start());
        auto out_of_order = scenario.coordinator->accept_server_challenge(
            scenario.server_challenge_record(), Scenario::time(1'000U, 1));
        CHECK(!out_of_order.succeeded());
        CHECK(out_of_order.error.code ==
            vfdual::HostAuthenticatedControlErrorCodeV1::unexpected_record);
        CHECK(scenario.coordinator->is_closed());
    }
}

void timeout_and_android_identity_tamper_burn_owner() {
    {
        Scenario scenario;
        auto timed_out = scenario.coordinator->start(Scenario::time(
            vfdual::kHostAuthenticatedControlHandshakeTimeoutMillisecondsV1 +
                1U,
            61));
        CHECK(!timed_out.succeeded());
        CHECK(timed_out.error.code ==
            vfdual::HostAuthenticatedControlErrorCodeV1::timed_out);
        CHECK(scenario.coordinator->is_closed());
    }
    {
        Scenario scenario;
        static_cast<void>(scenario.start());
        auto rejected = scenario.coordinator->accept_android_challenge_request(
            scenario.android_challenge_record(true),
            Scenario::time(1'000U, 1));
        CHECK(!rejected.succeeded());
        CHECK(rejected.error.code ==
            vfdual::HostAuthenticatedControlErrorCodeV1::
                cryptographic_verification_failed);
        CHECK(scenario.coordinator->is_closed());
    }
}

void server_challenge_expiry_ttl_and_peer_abort_fail_closed() {
    {
        Scenario scenario;
        static_cast<void>(scenario.start());
        static_cast<void>(scenario.accept_android_challenge());
        auto expired = scenario.coordinator->accept_server_challenge(
            scenario.server_challenge_record(
                static_cast<std::uint64_t>(Scenario::kEpoch + 2)),
            Scenario::time(2'000U, 2));
        CHECK(!expired.succeeded());
        CHECK(expired.error.code ==
            vfdual::HostAuthenticatedControlErrorCodeV1::
                server_authorization_rejected);
        CHECK(scenario.coordinator->is_closed());
    }
    {
        Scenario scenario;
        static_cast<void>(scenario.start());
        static_cast<void>(scenario.accept_android_challenge());
        auto excessive_ttl = scenario.coordinator->accept_server_challenge(
            scenario.server_challenge_record(
                static_cast<std::uint64_t>(Scenario::kEpoch + 33)),
            Scenario::time(2'000U, 2));
        CHECK(!excessive_ttl.succeeded());
        CHECK(excessive_ttl.error.code ==
            vfdual::HostAuthenticatedControlErrorCodeV1::
                server_authorization_rejected);
        CHECK(scenario.coordinator->is_closed());
    }
    {
        Scenario scenario;
        static_cast<void>(scenario.start());
        auto aborted = scenario.coordinator->accept_android_challenge_request(
            encode_android_record(
                vfdual::ControlBootstrapMessageTypeV1::abort,
                {{std::byte{0x00U}, std::byte{0x01U}}}),
            Scenario::time(1'000U, 1));
        CHECK(!aborted.succeeded());
        CHECK(aborted.error.code ==
            vfdual::HostAuthenticatedControlErrorCodeV1::peer_aborted);
        CHECK(scenario.coordinator->is_closed());
    }
}

void credential_metadata_high_watermark_and_authority_rejection_fail_closed() {
    {
        Scenario scenario;
        static_cast<void>(scenario.start());
        static_cast<void>(scenario.accept_android_challenge());
        static_cast<void>(scenario.accept_server_challenge());
        scenario.credential_ready = true;
        auto rejected = scenario.coordinator->accept_pair_generation_credential(
            scenario.credential_record(Scenario::kGeneration, true, false),
            Scenario::time(3'000U, 3));
        CHECK(!rejected.succeeded());
        CHECK(rejected.error.code ==
            vfdual::HostAuthenticatedControlErrorCodeV1::
                server_authorization_rejected);
        CHECK(scenario.credential_calls == 0U);
        CHECK(scenario.coordinator->is_closed());
    }
    {
        Scenario scenario;
        static_cast<void>(scenario.start());
        static_cast<void>(scenario.accept_android_challenge());
        static_cast<void>(scenario.accept_server_challenge());
        scenario.credential_ready = true;
        auto rejected = scenario.coordinator->accept_pair_generation_credential(
            scenario.credential_record(Scenario::kGeneration, false, true),
            Scenario::time(3'000U, 3));
        CHECK(!rejected.succeeded());
        CHECK(rejected.error.code ==
            vfdual::HostAuthenticatedControlErrorCodeV1::
                server_authorization_rejected);
        CHECK(scenario.credential_calls == 0U);
        CHECK(scenario.coordinator->is_closed());
    }
    {
        Scenario scenario(Scenario::kGeneration);
        static_cast<void>(scenario.start());
        static_cast<void>(scenario.accept_android_challenge());
        static_cast<void>(scenario.accept_server_challenge());
        scenario.credential_ready = true;
        auto stale = scenario.coordinator->accept_pair_generation_credential(
            scenario.credential_record(), Scenario::time(3'000U, 3));
        CHECK(!stale.succeeded());
        CHECK(stale.error.code ==
            vfdual::HostAuthenticatedControlErrorCodeV1::
                server_authorization_rejected);
        CHECK(scenario.credential_calls == 0U);
    }
    {
        Scenario scenario;
        static_cast<void>(scenario.start());
        static_cast<void>(scenario.accept_android_challenge());
        static_cast<void>(scenario.accept_server_challenge());
        scenario.credential_ready = true;
        scenario.credential_allow = false;
        auto rejected = scenario.coordinator->accept_pair_generation_credential(
            scenario.credential_record(), Scenario::time(3'000U, 3));
        CHECK(!rejected.succeeded());
        CHECK(rejected.error.code ==
            vfdual::HostAuthenticatedControlErrorCodeV1::
                server_authorization_rejected);
        CHECK(scenario.credential_calls == 1U);
        CHECK(scenario.coordinator->is_closed());
    }
}

void wrong_android_finished_never_releases_session() {
    Scenario scenario;
    static_cast<void>(scenario.start());
    static_cast<void>(scenario.accept_android_challenge());
    static_cast<void>(scenario.accept_server_challenge());
    static_cast<void>(scenario.accept_credential());
    auto rejected = scenario.coordinator->accept_android_handshake_confirmation(
        scenario.confirmation_record(true), Scenario::time(4'000U, 4));
    CHECK(!rejected.succeeded());
    CHECK(rejected.confirmed_session == nullptr);
    CHECK(rejected.session_generation == 0U);
    CHECK(rejected.host_finished_record.empty());
    CHECK(rejected.error.code ==
        vfdual::HostAuthenticatedControlErrorCodeV1::
            cryptographic_verification_failed);
    CHECK(scenario.coordinator->is_closed());
    CHECK(!scenario.coordinator->is_completed());
}

void wrong_android_transcript_signature_never_releases_session() {
    Scenario scenario;
    static_cast<void>(scenario.start());
    static_cast<void>(scenario.accept_android_challenge());
    static_cast<void>(scenario.accept_server_challenge());
    static_cast<void>(scenario.accept_credential());
    auto rejected = scenario.coordinator->accept_android_handshake_confirmation(
        scenario.confirmation_record(false, true),
        Scenario::time(4'000U, 4));
    CHECK(!rejected.succeeded());
    CHECK(rejected.confirmed_session == nullptr);
    CHECK(rejected.session_generation == 0U);
    CHECK(rejected.host_finished_record.empty());
    CHECK(rejected.error.code ==
        vfdual::HostAuthenticatedControlErrorCodeV1::
            cryptographic_verification_failed);
    CHECK(scenario.coordinator->is_closed());
    CHECK(!scenario.coordinator->is_completed());
}

}  // namespace

int main() {
    complete_full_nine_record_exchange();
    duplicate_and_out_of_order_records_burn_owner();
    timeout_and_android_identity_tamper_burn_owner();
    server_challenge_expiry_ttl_and_peer_abort_fail_closed();
    credential_metadata_high_watermark_and_authority_rejection_fail_closed();
    wrong_android_finished_never_releases_session();
    wrong_android_transcript_signature_never_releases_session();
    std::cout << "host authenticated control coordinator v1 tests passed\n";
    return EXIT_SUCCESS;
}
