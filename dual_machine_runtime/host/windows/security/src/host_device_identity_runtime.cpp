#include "vfdual/host_device_identity_runtime.hpp"

#include "vfdual/host_pair_generation_pop_signer_v1.hpp"
#include "vfdual/host_peer_handshake_transcript_signer_v1.hpp"
#include "vfdual/host_first_pairing_user_confirmation_signer_v1.hpp"
#include "vfdual/host_activation_confirmation_signer_v1.hpp"
#include "vfdual/host_usage_authorization_signer_v1.hpp"

#include <utility>

namespace vfdual {

HostDeviceIdentityRuntime::HostDeviceIdentityRuntime(
    std::unique_ptr<HostCngDeviceIdentity> identity)
    : identity_(std::move(identity)),
      handshake_signer_(
          std::make_unique<HostPeerHandshakeTranscriptSignerV1>(*identity_)),
      pair_pop_signer_(
          std::make_unique<HostPairGenerationPopSignerV1>(*identity_)),
      first_pairing_user_confirmation_signer_(
          std::make_unique<HostFirstPairingUserConfirmationSignerV1>(
              *identity_)),
      activation_confirmation_signer_(
          std::make_unique<HostActivationConfirmationSignerV1>(*identity_)),
      usage_authorization_signer_(
          std::make_unique<HostUsageAuthorizationSignerV1>(*identity_)) {}

HostDeviceIdentityRuntime::~HostDeviceIdentityRuntime() = default;

std::unique_ptr<HostDeviceIdentityRuntime>
HostDeviceIdentityRuntime::open_for_current_build(HostIdentityError& error) {
    error = {};
#if defined(VFDUAL_FORMAL_SECURE_DATA_PLANE_ONLY) && \
    VFDUAL_FORMAL_SECURE_DATA_PLANE_ONLY
    const HostIdentityPolicy policy =
        HostIdentityPolicy::formal_platform_tpm();
#else
    const HostIdentityPolicy policy =
        HostIdentityPolicy::development_named_software_provider(
            std::wstring(kMicrosoftSoftwareKeyStorageProvider));
#endif
    auto identity = HostCngDeviceIdentity::open_windows(policy, error);
    if (identity == nullptr) return nullptr;
    return std::unique_ptr<HostDeviceIdentityRuntime>(
        new HostDeviceIdentityRuntime(std::move(identity)));
}

const HostPublicIdentity&
HostDeviceIdentityRuntime::public_identity() const noexcept {
    return identity_->public_identity();
}

HostPeerHandshakeTranscriptSignerV1&
HostDeviceIdentityRuntime::peer_handshake_signer() noexcept {
    return *handshake_signer_;
}

HostPairGenerationPopSignerV1&
HostDeviceIdentityRuntime::pair_generation_pop_signer() noexcept {
    return *pair_pop_signer_;
}

HostFirstPairingUserConfirmationSignerV1&
HostDeviceIdentityRuntime::first_pairing_user_confirmation_signer() noexcept {
    return *first_pairing_user_confirmation_signer_;
}

HostActivationConfirmationSignerV1&
HostDeviceIdentityRuntime::activation_confirmation_signer() noexcept {
    return *activation_confirmation_signer_;
}

HostUsageAuthorizationSignerV1&
HostDeviceIdentityRuntime::usage_authorization_signer() noexcept {
    return *usage_authorization_signer_;
}

}  // namespace vfdual
