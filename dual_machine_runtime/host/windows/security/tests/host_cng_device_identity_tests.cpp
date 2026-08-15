#include "vfdual/host_cng_device_identity.h"

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
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
    std::exit(EXIT_FAILURE);
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

namespace {

struct FakeKeyStats final {
    bool public_export_called{};
    std::size_t sign_calls{};
    std::size_t discard_calls{};
    vfdual::HostIdentityError discard_error{};
};

vfdual::HostIdentityError test_bcrypt_error(
    const vfdual::HostIdentityErrorCode code,
    const NTSTATUS status,
    const char* operation) {
    return {
        .code = code,
        .native_domain =
            vfdual::HostIdentityNativeStatusDomain::bcrypt_ntstatus,
        .native_status = static_cast<std::uint32_t>(status),
        .operation = operation,
    };
}

class EphemeralBcryptSigningKey final : public vfdual::CngSigningKey {
public:
    ~EphemeralBcryptSigningKey() override {
        if (key_ != nullptr) (void)BCryptDestroyKey(key_);
        if (algorithm_ != nullptr) {
            (void)BCryptCloseAlgorithmProvider(algorithm_, 0U);
        }
    }

    EphemeralBcryptSigningKey(const EphemeralBcryptSigningKey&) = delete;
    EphemeralBcryptSigningKey& operator=(
        const EphemeralBcryptSigningKey&) = delete;

    [[nodiscard]] static std::unique_ptr<EphemeralBcryptSigningKey> create(
        vfdual::CngKeyMetadata metadata,
        std::shared_ptr<FakeKeyStats> stats,
        vfdual::HostIdentityError& error) {
        auto key = std::unique_ptr<EphemeralBcryptSigningKey>(
            new EphemeralBcryptSigningKey(
                std::move(metadata), std::move(stats)));
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &key->algorithm_, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            error = test_bcrypt_error(
                vfdual::HostIdentityErrorCode::key_open_or_create_failed,
                status,
                "test_open_ephemeral_p256");
            return nullptr;
        }
        status = BCryptGenerateKeyPair(
            key->algorithm_, &key->key_, 256U, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            error = test_bcrypt_error(
                vfdual::HostIdentityErrorCode::key_open_or_create_failed,
                status,
                "test_generate_ephemeral_p256");
            return nullptr;
        }
        status = BCryptFinalizeKeyPair(key->key_, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            error = test_bcrypt_error(
                vfdual::HostIdentityErrorCode::key_finalize_failed,
                status,
                "test_finalize_ephemeral_p256");
            return nullptr;
        }
        error = {};
        return key;
    }

    [[nodiscard]] const vfdual::CngKeyMetadata& metadata()
        const noexcept override {
        return metadata_;
    }

    [[nodiscard]] vfdual::HostIdentityBytesResult
    export_public_ecc_blob() override {
        stats_->public_export_called = true;
        ULONG required{};
        NTSTATUS status = BCryptExportKey(
            key_, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0U, &required, 0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, test_bcrypt_error(
                vfdual::HostIdentityErrorCode::public_key_export_failed,
                status,
                "test_export_public_key_size")};
        }
        std::vector<std::uint8_t> blob(required);
        ULONG copied{};
        status = BCryptExportKey(
            key_,
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            blob.data(),
            static_cast<ULONG>(blob.size()),
            &copied,
            0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, test_bcrypt_error(
                vfdual::HostIdentityErrorCode::public_key_export_failed,
                status,
                "test_export_public_key")};
        }
        blob.resize(copied);
        return {std::move(blob), {}};
    }

    [[nodiscard]] vfdual::HostIdentityBytesResult sign_sha256_digest(
        const std::span<const std::uint8_t> digest) override {
        ++stats_->sign_calls;
        if (digest.size() != 32U) {
            return {{}, {
                .code = vfdual::HostIdentityErrorCode::signature_failed,
                .operation = "test_validate_digest_size",
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
            return {{}, test_bcrypt_error(
                vfdual::HostIdentityErrorCode::signature_failed,
                status,
                "test_sign_digest_size")};
        }
        std::vector<std::uint8_t> signature(required);
        ULONG copied{};
        status = BCryptSignHash(
            key_,
            nullptr,
            const_cast<PUCHAR>(digest.data()),
            static_cast<ULONG>(digest.size()),
            signature.data(),
            static_cast<ULONG>(signature.size()),
            &copied,
            0U);
        if (!BCRYPT_SUCCESS(status)) {
            return {{}, test_bcrypt_error(
                vfdual::HostIdentityErrorCode::signature_failed,
                status,
                "test_sign_digest")};
        }
        signature.resize(copied);
        return {std::move(signature), {}};
    }

    [[nodiscard]] vfdual::HostIdentityError
    discard_new_persisted_key_after_failed_initialization() override {
        ++stats_->discard_calls;
        return stats_->discard_error;
    }

private:
    EphemeralBcryptSigningKey(
        vfdual::CngKeyMetadata metadata,
        std::shared_ptr<FakeKeyStats> stats)
        : metadata_(std::move(metadata)), stats_(std::move(stats)) {}

    vfdual::CngKeyMetadata metadata_;
    std::shared_ptr<FakeKeyStats> stats_;
    BCRYPT_ALG_HANDLE algorithm_{};
    BCRYPT_KEY_HANDLE key_{};
};

class FakeKeyStore final : public vfdual::CngKeyStoreAdapter {
public:
    explicit FakeKeyStore(vfdual::CngKeyMetadata metadata)
        : metadata_(std::move(metadata)), stats(std::make_shared<FakeKeyStats>()) {}

    [[nodiscard]] vfdual::CngKeyOpenResult open_or_create_p256_signing_key(
        const vfdual::CngKeyOpenRequest& request) override {
        ++open_calls;
        last_request = request;
        if (forced_error.has_error()) return {nullptr, forced_error};
        vfdual::HostIdentityError error;
        auto key = EphemeralBcryptSigningKey::create(
            metadata_, stats, error);
        if (key == nullptr) return {nullptr, std::move(error)};
        return {std::move(key), {}, report_created};
    }

    vfdual::CngKeyOpenRequest last_request{};
    std::size_t open_calls{};
    vfdual::HostIdentityError forced_error{};
    bool report_created{};
    std::shared_ptr<FakeKeyStats> stats;

private:
    vfdual::CngKeyMetadata metadata_;
};

vfdual::CngKeyMetadata development_metadata() {
    return {
        .provider_name =
            std::wstring(vfdual::kMicrosoftSoftwareKeyStorageProvider),
        .persistent_key_name =
            std::wstring(vfdual::kDevelopmentHostIdentityKeyName),
        .algorithm_name = L"ECDSA_P256",
        .algorithm_group_name = L"ECDSA",
        .key_length_bits = 256U,
        .key_usage = vfdual::kCngAllowSigningFlag,
        .export_policy = 0U,
        .implementation_type = vfdual::kCngImplementationSoftwareFlag,
        .key_type = 0U,
    };
}

vfdual::CngKeyMetadata formal_metadata() {
    return {
        .provider_name = std::wstring(vfdual::kMicrosoftPlatformCryptoProvider),
        .persistent_key_name = std::wstring(vfdual::kFormalHostIdentityKeyName),
        .algorithm_name = L"ECDSA_P256",
        .algorithm_group_name = L"ECDSA",
        .key_length_bits = 256U,
        .key_usage = vfdual::kCngAllowSigningFlag,
        .export_policy = 0U,
        .implementation_type = vfdual::kCngImplementationHardwareFlag,
        .key_type = vfdual::kCngMachineKeyFlag,
    };
}

template <std::size_t Size>
std::array<std::uint8_t, Size> filled(const std::uint8_t value) {
    std::array<std::uint8_t, Size> result{};
    result.fill(value);
    return result;
}

vfdual::HostIdentityChallenge valid_challenge() {
    return {
        .protocol_version = vfdual::kHostIdentityChallengeProtocolVersion,
        .challenge_type = vfdual::HostIdentityChallengeType::pairing,
        .host_id = "HOST-TEST-01",
        .server_nonce = filled<32U>(0x11U),
        .android_peer_ephemeral_public_key_sha256 = filled<32U>(0x22U),
        .android_peer_identity_public_key_sha256 = filled<32U>(0x33U),
        .session_id = filled<16U>(0x44U),
        .epoch = 7U,
    };
}

void test_development_identity_signs_and_mutations_fail() {
    FakeKeyStore adapter(development_metadata());
    const auto policy =
        vfdual::HostIdentityPolicy::development_named_software_provider(
            std::wstring(vfdual::kMicrosoftSoftwareKeyStorageProvider));
    vfdual::HostIdentityError error;
    auto identity =
        vfdual::HostCngDeviceIdentity::open_development_with_adapter(
        policy, adapter, error);
    CHECK(identity != nullptr);
    CHECK(!error.has_error());
    CHECK(adapter.stats->public_export_called);
    CHECK(identity->public_identity().untrusted_local_assurance_claim ==
        vfdual::HostIdentityAssurance::non_formal_development_software);
    CHECK(std::string(vfdual::host_identity_assurance_name(
        identity->public_identity().untrusted_local_assurance_claim)) ==
        "non_formal_development_software");
    CHECK(identity->public_identity().subject_public_key_info_der.size() == 91U);
    CHECK(identity->public_identity().public_key_sha256_hex.size() == 64U);

    const auto challenge = valid_challenge();
    const auto canonical = vfdual::build_host_identity_challenge(
        challenge,
        identity->public_identity().public_key_sha256,
        identity->public_identity().untrusted_local_assurance_claim);
    CHECK(canonical.succeeded());
    const auto signed_challenge = identity->sign_challenge(challenge);
    CHECK(signed_challenge.succeeded());
    CHECK(adapter.stats->sign_calls == 1U);
    CHECK(signed_challenge.signature->canonical_challenge == canonical.bytes);
    CHECK(signed_challenge.signature->signature_der.size() >= 8U);
    CHECK(signed_challenge.signature->signature_der.size() <= 72U);
    CHECK(signed_challenge.signature->signature_der[0] == 0x30U);
    CHECK(signed_challenge.signature->signature_der[1] ==
        signed_challenge.signature->signature_der.size() - 2U);
    CHECK(signed_challenge.signature->untrusted_local_assurance_claim ==
        vfdual::HostIdentityAssurance::non_formal_development_software);

    const auto verified = vfdual::verify_host_identity_proof_of_possession(
        identity->public_identity(), challenge, *signed_challenge.signature);
    CHECK(verified.completed());
    CHECK(verified.proof_of_possession_valid);

    auto nonce_mutation = challenge;
    nonce_mutation.server_nonce[0] ^= 0x01U;
    const auto nonce_verification = vfdual::verify_host_identity_proof_of_possession(
        identity->public_identity(), nonce_mutation,
        *signed_challenge.signature);
    CHECK(nonce_verification.completed());
    CHECK(!nonce_verification.proof_of_possession_valid);

    auto session_mutation = challenge;
    session_mutation.session_id[15] ^= 0x80U;
    const auto session_verification = vfdual::verify_host_identity_proof_of_possession(
        identity->public_identity(), session_mutation,
        *signed_challenge.signature);
    CHECK(session_verification.completed());
    CHECK(!session_verification.proof_of_possession_valid);

    auto type_mutation = challenge;
    type_mutation.challenge_type =
        vfdual::HostIdentityChallengeType::session_binding;
    const auto type_verification = vfdual::verify_host_identity_proof_of_possession(
        identity->public_identity(), type_mutation,
        *signed_challenge.signature);
    CHECK(type_verification.completed());
    CHECK(!type_verification.proof_of_possession_valid);

    auto relabeled_identity = identity->public_identity();
    auto relabeled_signature = *signed_challenge.signature;
    relabeled_identity.untrusted_local_assurance_claim =
        vfdual::HostIdentityAssurance::formal_platform_tpm;
    relabeled_signature.untrusted_local_assurance_claim =
        vfdual::HostIdentityAssurance::formal_platform_tpm;
    const auto relabeled = vfdual::verify_host_identity_proof_of_possession(
        relabeled_identity, challenge, relabeled_signature);
    CHECK(relabeled.completed());
    CHECK(!relabeled.proof_of_possession_valid);
}

void test_challenge_encoder_fails_closed() {
    const auto fingerprint = filled<32U>(0x55U);
    auto challenge = valid_challenge();
    const auto first =
        vfdual::build_host_identity_challenge(
            challenge,
            fingerprint,
            vfdual::HostIdentityAssurance::non_formal_development_software);
    const auto second =
        vfdual::build_host_identity_challenge(
            challenge,
            fingerprint,
            vfdual::HostIdentityAssurance::non_formal_development_software);
    CHECK(first.succeeded());
    CHECK(first.bytes == second.bytes);

    challenge.protocol_version += 1U;
    CHECK(!vfdual::build_host_identity_challenge(
        challenge, fingerprint,
        vfdual::HostIdentityAssurance::non_formal_development_software).succeeded());
    challenge = valid_challenge();
    challenge.epoch = 0U;
    CHECK(!vfdual::build_host_identity_challenge(
        challenge, fingerprint,
        vfdual::HostIdentityAssurance::non_formal_development_software).succeeded());
    challenge = valid_challenge();
    challenge.server_nonce.fill(0U);
    CHECK(!vfdual::build_host_identity_challenge(
        challenge, fingerprint,
        vfdual::HostIdentityAssurance::non_formal_development_software).succeeded());
    challenge = valid_challenge();
    challenge.host_id = "contains whitespace";
    CHECK(!vfdual::build_host_identity_challenge(
        challenge, fingerprint,
        vfdual::HostIdentityAssurance::non_formal_development_software).succeeded());
}

void test_formal_policy_rejects_software_fallback() {
    const auto policy = vfdual::HostIdentityPolicy::formal_platform_tpm();
    vfdual::HostIdentityError error;
    CHECK(!vfdual::validate_cng_key_metadata_for_policy(
        policy, development_metadata(), error));
    CHECK(error.code == vfdual::HostIdentityErrorCode::key_contract_rejected);

    FakeKeyStore adapter(formal_metadata());
    const auto identity =
        vfdual::HostCngDeviceIdentity::open_development_with_adapter(
            policy, adapter, error);
    CHECK(identity == nullptr);
    CHECK(error.code == vfdual::HostIdentityErrorCode::invalid_policy);
    CHECK(error.operation == "reject_formal_test_adapter");
    CHECK(adapter.open_calls == 0U);
    CHECK(!adapter.stats->public_export_called);
    CHECK(vfdual::kFormalHostIdentityKeyName.find(L"HOST-TEST-01") ==
        std::wstring::npos);
}

void test_private_export_contract_is_rejected() {
    auto metadata = formal_metadata();
    metadata.export_policy = 0x00000001U;
    vfdual::HostIdentityError error;
    CHECK(!vfdual::validate_cng_key_metadata_for_policy(
        vfdual::HostIdentityPolicy::formal_platform_tpm(), metadata, error));
    CHECK(error.code == vfdual::HostIdentityErrorCode::key_contract_rejected);
    CHECK(error.operation == "validate_private_export_policy");

    auto wrong_usage = formal_metadata();
    wrong_usage.key_usage = 0xffffffffU;
    CHECK(!vfdual::validate_cng_key_metadata_for_policy(
        vfdual::HostIdentityPolicy::formal_platform_tpm(),
        wrong_usage, error));
    CHECK(error.operation == "validate_signing_only_usage");
}

void test_formal_descriptor_requires_hardware() {
    vfdual::HostIdentityError error;
    CHECK(vfdual::validate_cng_key_metadata_for_policy(
        vfdual::HostIdentityPolicy::formal_platform_tpm(),
        formal_metadata(), error));

    auto no_hardware = formal_metadata();
    no_hardware.implementation_type = 0U;
    CHECK(!vfdual::validate_cng_key_metadata_for_policy(
        vfdual::HostIdentityPolicy::formal_platform_tpm(),
        no_hardware, error));
    CHECK(error.operation == "validate_formal_hardware_provider");
}

void test_native_status_is_preserved_without_sensitive_context() {
    FakeKeyStore adapter(development_metadata());
    adapter.forced_error = {
        .code = vfdual::HostIdentityErrorCode::key_open_or_create_failed,
        .native_domain =
            vfdual::HostIdentityNativeStatusDomain::ncrypt_security_status,
        .native_status = 0x80090016U,
        .operation = "open_or_create_persisted_key",
    };
    const auto policy =
        vfdual::HostIdentityPolicy::development_named_software_provider(
            std::wstring(vfdual::kMicrosoftSoftwareKeyStorageProvider));
    vfdual::HostIdentityError error;
    const auto identity =
        vfdual::HostCngDeviceIdentity::open_development_with_adapter(
            policy, adapter, error);
    CHECK(identity == nullptr);
    CHECK(error.native_status == 0x80090016U);
    const std::string diagnostic = vfdual::format_host_identity_error(error);
    CHECK(diagnostic.find("native_status=0x80090016") != std::string::npos);
    CHECK(diagnostic.find("VisionForge.HostIdentity") == std::string::npos);
    CHECK(diagnostic.find("HOST-TEST-01") == std::string::npos);
}

void test_cleanup_failure_does_not_replace_causal_failure() {
    const vfdual::HostIdentityError primary{
        .code = vfdual::HostIdentityErrorCode::key_finalize_failed,
        .native_domain =
            vfdual::HostIdentityNativeStatusDomain::ncrypt_security_status,
        .native_status = 0x80090010U,
        .operation = "finalize_persisted_key",
    };
    const vfdual::HostIdentityError cleanup{
        .code = vfdual::HostIdentityErrorCode::key_cleanup_failed,
        .native_domain =
            vfdual::HostIdentityNativeStatusDomain::ncrypt_security_status,
        .native_status = 0x80090016U,
        .operation = "delete_created_key_after_failure",
    };

    const vfdual::HostIdentityError combined =
        vfdual::preserve_host_identity_cleanup_failure(primary, cleanup);
    CHECK(combined.code ==
        vfdual::HostIdentityErrorCode::key_finalize_failed);
    CHECK(combined.native_status == 0x80090010U);
    CHECK(combined.operation == "finalize_persisted_key");
    CHECK(combined.cleanup_failure.has_value());
    CHECK(combined.cleanup_failure->code ==
        vfdual::HostIdentityErrorCode::key_cleanup_failed);
    CHECK(combined.cleanup_failure->native_status == 0x80090016U);
    CHECK(combined.cleanup_failure->operation ==
        "delete_created_key_after_failure");

    const std::string diagnostic =
        vfdual::format_host_identity_error(combined);
    CHECK(diagnostic.find("code=key_finalize_failed") !=
        std::string::npos);
    CHECK(diagnostic.find("native_status=0x80090010") !=
        std::string::npos);
    CHECK(diagnostic.find("cleanup_code=key_cleanup_failed") !=
        std::string::npos);
    CHECK(diagnostic.find("cleanup_native_status=0x80090016") !=
        std::string::npos);

    const vfdual::HostIdentityError primary_only =
        vfdual::preserve_host_identity_cleanup_failure(primary, {});
    CHECK(primary_only.code == primary.code);
    CHECK(!primary_only.cleanup_failure.has_value());
}

void test_new_invalid_key_is_discarded_but_existing_key_is_preserved() {
    auto invalid_metadata = development_metadata();
    invalid_metadata.key_usage = 0xffffffffU;
    const auto policy =
        vfdual::HostIdentityPolicy::development_named_software_provider(
            std::wstring(vfdual::kMicrosoftSoftwareKeyStorageProvider));

    FakeKeyStore newly_created(invalid_metadata);
    newly_created.report_created = true;
    vfdual::HostIdentityError error;
    auto identity =
        vfdual::HostCngDeviceIdentity::open_development_with_adapter(
            policy, newly_created, error);
    CHECK(identity == nullptr);
    CHECK(error.code ==
        vfdual::HostIdentityErrorCode::key_contract_rejected);
    CHECK(error.operation == "validate_signing_only_usage");
    CHECK(newly_created.stats->discard_calls == 1U);
    CHECK(!error.cleanup_failure.has_value());

    FakeKeyStore existing(invalid_metadata);
    identity = vfdual::HostCngDeviceIdentity::open_development_with_adapter(
        policy, existing, error);
    CHECK(identity == nullptr);
    CHECK(error.operation == "validate_signing_only_usage");
    CHECK(existing.stats->discard_calls == 0U);
}

void test_new_key_discard_failure_preserves_validation_root_cause() {
    auto invalid_metadata = development_metadata();
    invalid_metadata.export_policy = 0x00000001U;
    FakeKeyStore adapter(invalid_metadata);
    adapter.report_created = true;
    adapter.stats->discard_error = {
        .code = vfdual::HostIdentityErrorCode::key_cleanup_failed,
        .native_domain =
            vfdual::HostIdentityNativeStatusDomain::ncrypt_security_status,
        .native_status = 0x80090020U,
        .operation =
            "delete_new_persisted_key_after_failed_initialization",
    };
    const auto policy =
        vfdual::HostIdentityPolicy::development_named_software_provider(
            std::wstring(vfdual::kMicrosoftSoftwareKeyStorageProvider));

    vfdual::HostIdentityError error;
    const auto identity =
        vfdual::HostCngDeviceIdentity::open_development_with_adapter(
            policy, adapter, error);
    CHECK(identity == nullptr);
    CHECK(error.code ==
        vfdual::HostIdentityErrorCode::key_contract_rejected);
    CHECK(error.operation == "validate_private_export_policy");
    CHECK(adapter.stats->discard_calls == 1U);
    CHECK(error.cleanup_failure.has_value());
    CHECK(error.cleanup_failure->code ==
        vfdual::HostIdentityErrorCode::key_cleanup_failed);
    CHECK(error.cleanup_failure->native_status == 0x80090020U);
}

}  // namespace

int main() {
    test_development_identity_signs_and_mutations_fail();
    test_challenge_encoder_fails_closed();
    test_formal_policy_rejects_software_fallback();
    test_private_export_contract_is_rejected();
    test_formal_descriptor_requires_hardware();
    test_native_status_is_preserved_without_sensitive_context();
    test_cleanup_failure_does_not_replace_causal_failure();
    test_new_invalid_key_is_discarded_but_existing_key_is_preserved();
    test_new_key_discard_failure_preserves_validation_root_cause();
    std::cout << "VFDUAL_HOST_CNG_DEVICE_IDENTITY_OK\n";
    return EXIT_SUCCESS;
}
