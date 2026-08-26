#include "vfdual/host_pair_binding_store_v1.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace {

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "CHECK failed at line " << __LINE__ << '\n'; \
        return 1; \
    } \
} while (false)

vfdual::HostAuthenticatedControlPairBindingV1 binding() {
    return {
        .entitlement_id = std::string(32U, '1'),
        .pair_id = std::string(32U, '2'),
        .binding_id = std::string(32U, '3'),
        .binding_revision = 7U,
        .revocation_version = 9U,
        .generation_high_watermark = 0U,
        .host_identity_spki_sha256 = std::string(64U, 'a'),
        .android_identity_spki_sha256 =
            "3f6e6cc25161138d9067ffad9e9eaaf57bbb82fba3cf83c4ec37efa96cf318ba",
        .android_subject_public_key_info_der = {
            0x30U, 0x03U, 0x01U, 0x02U, 0x03U},
    };
}

bool same_pair(
    const vfdual::HostAuthenticatedControlPairBindingV1& left,
    const vfdual::HostAuthenticatedControlPairBindingV1& right) {
    return left.entitlement_id == right.entitlement_id &&
        left.pair_id == right.pair_id &&
        left.binding_id == right.binding_id &&
        left.binding_revision == right.binding_revision &&
        left.revocation_version == right.revocation_version &&
        left.host_identity_spki_sha256 == right.host_identity_spki_sha256 &&
        left.android_identity_spki_sha256 ==
            right.android_identity_spki_sha256 &&
        left.android_subject_public_key_info_der ==
            right.android_subject_public_key_info_der;
}

}  // namespace

int main() {
    const auto directory = std::filesystem::temp_directory_path() /
        (L"vfdual-pair-binding-store-test-" +
         std::to_wstring(GetCurrentProcessId()) + L"-" +
         std::to_wstring(GetTickCount64()));
    const auto state_file = directory / L"binding.state";
    std::error_code cleanup_error;
    std::filesystem::create_directories(directory);
    try {
        vfdual::HostPairBindingStoreV1 store(state_file);
        std::string error;
        CHECK(!store.load(error).has_value());
        CHECK(error.empty());

        const auto initial = binding();
        CHECK(store.commit_initial_binding(initial, error));
        CHECK(error.empty());
        auto loaded = store.load(error);
        CHECK(loaded.has_value());
        CHECK(error.empty());
        CHECK(same_pair(*loaded, initial));
        CHECK(loaded->generation_high_watermark == 0U);

        CHECK(store.commit_initial_binding(initial, error));
        auto other = initial;
        other.pair_id = std::string(32U, '4');
        CHECK(!store.commit_initial_binding(other, error));
        CHECK(!error.empty());

        auto mismatched_spki = initial;
        mismatched_spki.android_subject_public_key_info_der.back() ^= 1U;
        CHECK(!store.commit_initial_binding(mismatched_spki, error));
        CHECK(!error.empty());

        CHECK(store.commit_generation(initial, 4U, error));
        loaded = store.load(error);
        CHECK(loaded.has_value());
        CHECK(loaded->generation_high_watermark == 4U);
        CHECK(!store.commit_generation(initial, 4U, error));
        CHECK(!store.commit_generation(initial, 3U, error));
        CHECK(store.commit_generation(initial, 8U, error));
        loaded = store.load(error);
        CHECK(loaded.has_value());
        CHECK(loaded->generation_high_watermark == 8U);

        {
            std::ofstream corrupt(state_file, std::ios::binary | std::ios::trunc);
            corrupt << "not-a-binding\n";
        }
        CHECK(!store.load(error).has_value());
        CHECK(!error.empty());
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        std::filesystem::remove_all(directory, cleanup_error);
        return 1;
    }
    std::filesystem::remove_all(directory, cleanup_error);
    CHECK(!cleanup_error);
    std::cout << "VFDUAL_HOST_PAIR_BINDING_STORE_V1_OK\n";
    return 0;
}
