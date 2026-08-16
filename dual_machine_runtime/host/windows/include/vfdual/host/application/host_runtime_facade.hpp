#pragma once

#include "vfdual/host/application/host_runtime_models.hpp"

#include <memory>
#include <optional>
#include <string>

namespace vfdual {
class IsolatedDhcpServer;
}

namespace vfdual::host::application {

/**
 * Application facade between the desktop UI and Windows infrastructure.
 *
 * <p>The header exposes only stable requests/read models. DXGI, CAT6 session,
 * socket, encoder and worker-thread types remain behind the private State.</p>
 */
class HostRuntimeFacade final {
public:
    explicit HostRuntimeFacade(vfdual::IsolatedDhcpServer* direct_link_owner = nullptr);
    ~HostRuntimeFacade();
    HostRuntimeFacade(const HostRuntimeFacade&) = delete;
    HostRuntimeFacade& operator=(const HostRuntimeFacade&) = delete;

    [[nodiscard]] bool start(const HostStartRequest& request, std::string& error);
    void request_stop() noexcept;
    void stop() noexcept;
    void restore_direct_link_on_clean_shutdown() noexcept;
    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] std::optional<HostRuntimeReadModel> snapshot() const;
    [[nodiscard]] std::string last_error() const;

private:
    struct State;
    std::unique_ptr<State> state_;
};

}  // namespace vfdual::host::application
