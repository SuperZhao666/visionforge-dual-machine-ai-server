#include "vfdual/host_device_identity_runtime.hpp"

#include "vfdual/host_peer_handshake_transcript_signer_v1.hpp"

#include <utility>

namespace vfdual {

HostDeviceIdentityRuntime::HostDeviceIdentityRuntime(
    std::unique_ptr<HostCngDeviceIdentity> identity)
    : identity_(std::move(identity)),
      handshake_signer_(
          std::make_unique<HostPeerHandshakeTranscriptSignerV1>(*identity_)) {}

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

}  // namespace vfdual
