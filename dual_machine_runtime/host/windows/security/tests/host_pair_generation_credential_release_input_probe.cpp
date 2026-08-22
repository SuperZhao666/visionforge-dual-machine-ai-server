#include "vfdual/host_pair_generation_credential_verifier_v1.hpp"

#include <cstdlib>
#include <iostream>

int main() {
    auto constructed = vfdual::HostPairGenerationCredentialV1Verifier::
        create_from_build_pinned_keyring();
    if (!constructed.succeeded()) {
        std::cerr << "HOST_PAIR_CREDENTIAL_RELEASE_INPUTS_INVALID code="
                  << vfdual::
                         host_pair_generation_credential_error_code_name_v1(
                             constructed.error.code)
                  << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "HOST_PAIR_CREDENTIAL_RELEASE_INPUTS_OK "
                 "KEY_PURPOSES=disjoint\n";
    return EXIT_SUCCESS;
}
