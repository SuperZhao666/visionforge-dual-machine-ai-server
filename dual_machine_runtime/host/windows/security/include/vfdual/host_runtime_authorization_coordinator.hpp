#pragma once

#include "vfdual/authenticated_control_tcp_transport_v1.hpp"
#include "vfdual/host_authenticated_control_coordinator_v1.hpp"

#include <cstdint>
#include <atomic>
#include <memory>
#include <mutex>
#include <thread>

namespace vfdual {

class HostRuntimeService;
class HostDeviceIdentityRuntime;

/**
 * Security composition root between a confirmed VFB1 channel and the Host
 * runtime gate. A confirmed channel alone is retained but never opens the data
 * plane; raw lease verification and three-step commit are still mandatory.
 */
class HostRuntimeAuthorizationCoordinator final {
public:
    explicit HostRuntimeAuthorizationCoordinator(
        HostRuntimeService& runtime) noexcept;
    ~HostRuntimeAuthorizationCoordinator();
    HostRuntimeAuthorizationCoordinator(
        const HostRuntimeAuthorizationCoordinator&) = delete;
    HostRuntimeAuthorizationCoordinator& operator=(
        const HostRuntimeAuthorizationCoordinator&) = delete;

    [[nodiscard]] bool install_authenticated_channel(
        HostDeviceIdentityRuntime& identity_runtime,
        const HostAuthenticatedControlPairBindingV1& pair,
        std::uint64_t generation,
        std::unique_ptr<ConfirmedPeerHandshakeSessionV1> session,
        std::unique_ptr<AuthenticatedControlTcpConnectionV1> connection)
        noexcept;
    [[nodiscard]] bool has_authenticated_channel() const noexcept;
    void close() noexcept;

private:
    void run_authenticated_control() noexcept;

    HostRuntimeService& runtime_;
    HostDeviceIdentityRuntime* identity_runtime_{};
    HostAuthenticatedControlPairBindingV1 pair_;
    std::unique_ptr<ConfirmedPeerHandshakeSessionV1> session_;
    std::unique_ptr<AuthenticatedControlTcpConnectionV1> connection_;
    std::thread worker_;
    std::atomic_bool stopping_{};
    mutable std::mutex mutex_;
};

}  // namespace vfdual
