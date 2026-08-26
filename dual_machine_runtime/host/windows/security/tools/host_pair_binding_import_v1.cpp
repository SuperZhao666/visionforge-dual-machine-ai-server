#include "vfdual/host_device_identity_runtime.hpp"
#include "vfdual/host_pair_binding_store_v1.hpp"

#include <exception>
#include <filesystem>
#include <iostream>
#include <string>

namespace {

[[nodiscard]] int fail(const char* reason) {
    std::cerr << "VFDUAL_HOST_PAIR_BINDING_IMPORT_V1_FAILED reason="
              << reason << '\n';
    return 1;
}

}  // namespace

int wmain(const int argc, wchar_t* argv[]) {
    if (argc != 3 || argv[1] == nullptr || argv[2] == nullptr) {
        return fail("arguments");
    }
    try {
        const auto source_path =
            std::filesystem::absolute(argv[1]).lexically_normal();
        const auto destination_path =
            std::filesystem::absolute(argv[2]).lexically_normal();
        if (source_path == destination_path) {
            return fail("source_equals_destination");
        }

        vfdual::HostPairBindingStoreV1 source(source_path);
        std::string error;
        const auto binding = source.load(error);
        if (!binding.has_value() || !error.empty() ||
            binding->generation_high_watermark != 0U) {
            return fail("source_invalid");
        }

        vfdual::HostIdentityError identity_error;
        auto identity =
            vfdual::HostDeviceIdentityRuntime::open_for_current_build(
                identity_error);
        if (identity == nullptr || identity_error.has_error()) {
            return fail("host_identity_unavailable");
        }
        if (binding->host_identity_spki_sha256 !=
            identity->public_identity().public_key_sha256_hex) {
            return fail("host_identity_mismatch");
        }

        vfdual::HostPairBindingStoreV1 destination(destination_path);
        if (!destination.commit_initial_binding(*binding, error) ||
            !error.empty()) {
            return fail("destination_commit_rejected");
        }
        const auto committed = destination.load(error);
        if (!committed.has_value() || !error.empty() ||
            committed->entitlement_id != binding->entitlement_id ||
            committed->pair_id != binding->pair_id ||
            committed->binding_id != binding->binding_id ||
            committed->generation_high_watermark != 0U) {
            return fail("destination_verification_failed");
        }
        std::cout << "VFDUAL_HOST_PAIR_BINDING_IMPORT_V1_OK\n";
        return 0;
    } catch (const std::exception&) {
        return fail("exception");
    } catch (...) {
        return fail("unknown_exception");
    }
}
