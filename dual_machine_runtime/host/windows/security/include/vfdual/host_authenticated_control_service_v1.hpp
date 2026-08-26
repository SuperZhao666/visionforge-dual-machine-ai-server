#pragma once

#include "vfdual/authenticated_control_tcp_transport_v1.hpp"
#include "vfdual/host_authenticated_control_coordinator_v1.hpp"
#include "vfdual/host_pair_binding_store_v1.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace vfdual {

/**
 * Production socket owner for successive exact VFB1 bound-pair handshakes.
 *
 * A successful candidate transfers its connection to the authorization
 * coordinator while this listener remains available for a later authenticated
 * reconnect.  Each successor must still consume a new server-authorized
 * generation for the same persisted pair.
 */
class HostAuthenticatedControlServiceV1 final {
public:
    using GenerationCommit = std::function<bool(
        const HostAuthenticatedControlPairBindingV1& binding,
        std::uint64_t generation)>;
    using SessionCommit = std::function<bool(
        const HostAuthenticatedControlPairBindingV1& binding,
        std::uint64_t generation,
        std::unique_ptr<ConfirmedPeerHandshakeSessionV1> session,
        std::unique_ptr<AuthenticatedControlTcpConnectionV1> connection)>;

    HostAuthenticatedControlServiceV1() = default;
    ~HostAuthenticatedControlServiceV1();
    HostAuthenticatedControlServiceV1(
        const HostAuthenticatedControlServiceV1&) = delete;
    HostAuthenticatedControlServiceV1& operator=(
        const HostAuthenticatedControlServiceV1&) = delete;

    [[nodiscard]] bool start(
        HostDeviceIdentityRuntime& identity_runtime,
        HostAuthenticatedControlPairBindingV1 pair_binding,
        std::string bind_ipv4,
        std::string host_runtime_version,
        GenerationCommit generation_commit,
        SessionCommit session_commit,
        std::string& error);
    void stop() noexcept;

    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] std::string last_error() const;

private:
    void run() noexcept;
    [[nodiscard]] bool process_candidate(
        std::unique_ptr<AuthenticatedControlTcpConnectionV1>& connection)
        noexcept;
    void set_error(std::string value) noexcept;

    mutable std::mutex state_mutex_;
    mutable std::mutex connection_mutex_;
    AuthenticatedControlTcpListenerV1 listener_;
    AuthenticatedControlTcpConnectionV1* active_connection_{};
    HostDeviceIdentityRuntime* identity_runtime_{};
    HostAuthenticatedControlPairBindingV1 pair_binding_;
    std::string host_runtime_version_;
    GenerationCommit generation_commit_;
    SessionCommit session_commit_;
    std::string last_error_;
    std::thread worker_;
    std::atomic_bool stopping_{};
    std::atomic_bool running_{};
};

}  // namespace vfdual
