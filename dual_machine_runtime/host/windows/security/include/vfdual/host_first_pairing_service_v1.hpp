#pragma once

#include "vfdual/authenticated_control_tcp_transport_v1.hpp"
#include "vfdual/host_first_pairing_coordinator_v1.hpp"

#include <atomic>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

namespace vfdual {

/**
 * Production socket owner for fresh pairing only.
 *
 * It listens on the dedicated first-pairing TCP port, commits the actual
 * authenticated-control route into VFP1, asks the local Host user to compare
 * the SAS, and carries only the typed activation records. A successful result
 * remains provisional; this service never opens or authorizes the data plane.
 */
class HostFirstPairingServiceV1 final {
public:
    using LocalConfirmation = std::function<bool(
        std::string_view decimal_sas,
        std::string_view android_ipv4)>;
    using PairBindingCommit = std::function<bool(
        const HostAuthenticatedControlPairBindingV1& binding)>;

    HostFirstPairingServiceV1() = default;
    ~HostFirstPairingServiceV1();
    HostFirstPairingServiceV1(const HostFirstPairingServiceV1&) = delete;
    HostFirstPairingServiceV1& operator=(
        const HostFirstPairingServiceV1&) = delete;

    [[nodiscard]] bool start(
        HostDeviceIdentityRuntime& identity_runtime,
        std::string bind_ipv4,
        std::string host_runtime_version,
        std::string host_client_version,
        LocalConfirmation local_confirmation,
        PairBindingCommit pair_binding_commit,
        std::string& error);
    void stop() noexcept;

    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] std::string last_error() const;
    [[nodiscard]] std::optional<HostAuthenticatedControlPairBindingV1>
    provisional_pair_binding() const;

private:
    void run() noexcept;
    [[nodiscard]] bool process_candidate(
        AuthenticatedControlTcpConnectionV1& connection) noexcept;
    void set_error(std::string value) noexcept;

    mutable std::mutex state_mutex_;
    mutable std::mutex connection_mutex_;
    AuthenticatedControlTcpListenerV1 listener_;
    AuthenticatedControlTcpConnectionV1* active_connection_{};
    HostDeviceIdentityRuntime* identity_runtime_{};
    std::string host_runtime_version_;
    std::string host_client_version_;
    LocalConfirmation local_confirmation_;
    PairBindingCommit pair_binding_commit_;
    std::string last_error_;
    std::optional<HostAuthenticatedControlPairBindingV1>
        provisional_pair_binding_;
    std::thread worker_;
    std::atomic_bool stopping_{};
    std::atomic_bool running_{};
};

}  // namespace vfdual
