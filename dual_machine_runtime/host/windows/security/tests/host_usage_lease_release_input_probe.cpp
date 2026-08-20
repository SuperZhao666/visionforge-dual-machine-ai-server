#include "vfdual/host_usage_lease_verifier_v1.hpp"

#include <cstdlib>
#include <iostream>

int main() {
    auto constructed =
        vfdual::HostUsageLeaseVerifierV1::create_from_build_pinned_keyring();
    if (!constructed.succeeded()) {
        std::cerr << "HOST_RELEASE_SECURITY_INPUTS_INVALID code="
                  << vfdual::host_usage_lease_verification_error_code_name_v1(
                         constructed.error.code)
                  << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "HOST_RELEASE_SECURITY_INPUTS_OK "
                 "HOST_AUTHORIZATION_GATE=required\n";
    return EXIT_SUCCESS;
}
