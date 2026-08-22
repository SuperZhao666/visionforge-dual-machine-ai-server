#pragma once

#include "vfdual/host_cng_device_identity.h"

#include <memory>
#include <string_view>

namespace vfdual {

class HostAuthenticatedControlCoordinatorV1;
class HostPairGenerationPopSignerV1;
class HostPeerHandshakeTranscriptSignerV1;

inline constexpr std::wstring_view kHostDeviceIdentityProbeArgument{
    L"--host-device-identity-probe"};

/**
 * Production ownership boundary for the Host's long-term signing identity.
 *
 * The public identity is available for server-side pair registration.  The
 * restricted transcript signer is private and may be consumed only by the
 * authenticated control coordinator, so UI/runtime code cannot turn the
 * device key into an arbitrary signing oracle.
 */
class HostDeviceIdentityRuntime final {
public:
    ~HostDeviceIdentityRuntime();
    HostDeviceIdentityRuntime(const HostDeviceIdentityRuntime&) = delete;
    HostDeviceIdentityRuntime& operator=(
        const HostDeviceIdentityRuntime&) = delete;

    /**
     * Opens the policy selected by this build.  Formal builds accept only the
     * ACL-isolated Platform Crypto Provider machine key; non-formal builds use
     * the explicitly labelled current-user software provider key.
     */
    [[nodiscard]] static std::unique_ptr<HostDeviceIdentityRuntime>
    open_for_current_build(HostIdentityError& error);

    [[nodiscard]] const HostPublicIdentity& public_identity() const noexcept;

private:
    explicit HostDeviceIdentityRuntime(
        std::unique_ptr<HostCngDeviceIdentity> identity);

    [[nodiscard]] HostPeerHandshakeTranscriptSignerV1&
    peer_handshake_signer() noexcept;
    [[nodiscard]] HostPairGenerationPopSignerV1&
    pair_generation_pop_signer() noexcept;

    friend class HostAuthenticatedControlCoordinatorV1;

    std::unique_ptr<HostCngDeviceIdentity> identity_;
    std::unique_ptr<HostPeerHandshakeTranscriptSignerV1> handshake_signer_;
    std::unique_ptr<HostPairGenerationPopSignerV1> pair_pop_signer_;
};

}  // namespace vfdual
