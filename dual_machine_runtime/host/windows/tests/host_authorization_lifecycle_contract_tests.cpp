#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#ifndef VFDUAL_SOURCE_DIR
#error "VFDUAL_SOURCE_DIR must point at the dual_machine_runtime source directory"
#endif

namespace {

void require(bool condition, const char* expression, int line) {
    if (condition) return;
    std::cerr << "CHECK failed: " << expression << " (line " << line << ")\n";
    std::exit(EXIT_FAILURE);
}

#define VFDUAL_TEST_REQUIRE(expression) \
    require(static_cast<bool>(expression), #expression, __LINE__)

std::string read_source(const char* relative_path) {
    const std::string path = std::string{VFDUAL_SOURCE_DIR} + "/" + relative_path;
    std::ifstream input{path, std::ios::binary};
    VFDUAL_TEST_REQUIRE(input.good());
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

std::string slice_between(
    const std::string& source, const std::string& begin, const std::string& end) {
    const std::size_t begin_index = source.find(begin);
    VFDUAL_TEST_REQUIRE(begin_index != std::string::npos);
    const std::size_t end_index = source.find(end, begin_index + begin.size());
    VFDUAL_TEST_REQUIRE(end_index != std::string::npos);
    return source.substr(begin_index, end_index - begin_index);
}

}  // namespace

int main() {
    const std::string runtime_source =
        read_source("host/windows/src/host_runtime_service.cpp");
    const std::string runtime_header =
        read_source("host/windows/include/vfdual/host_runtime_service.hpp");
    const std::string facade_header = read_source(
        "host/windows/include/vfdual/host/application/host_runtime_facade.hpp");
    const std::string facade_source =
        read_source("host/windows/src/host_runtime_facade.cpp");
    const std::string first_pairing_service = read_source(
        "host/windows/security/src/host_first_pairing_service_v1.cpp");
    const std::string authenticated_control_service = read_source(
        "host/windows/security/src/host_authenticated_control_service_v1.cpp");
    const std::string wired_link_contract =
        read_source("host/windows/include/vfdual/wired_link_contract.hpp");
    const std::string authorization_header =
        read_source("host/windows/include/vfdual/host_runtime_service.hpp");
    const std::string authorization_source =
        read_source("host/windows/src/host_runtime_authorization.cpp");
    const std::string authorization_coordinator = read_source(
        "host/windows/security/src/host_runtime_authorization_coordinator.cpp");
    const std::string cmake_source = read_source("CMakeLists.txt");

    // MSVC /showIncludes output can be localized.  If Ninja loses that
    // dependency stream, a header-only HostRuntimeService layout change can
    // otherwise leave host_runtime_facade.cpp built against the old size and
    // overlap HostRuntimeAuthorizationCoordinator at runtime.
    VFDUAL_TEST_REQUIRE(cmake_source.find(
                            "VFDUAL_HOST_RUNTIME_LAYOUT_HEADER") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find(
                            "host/windows/src/host_runtime_service.cpp") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find(
                            "host/windows/src/host_runtime_authorization.cpp") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find(
                            "host/windows/src/host_runtime_facade.cpp") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find("OBJECT_DEPENDS") !=
                         std::string::npos);

    // The first-pair/authenticated-control port split is a header-only
    // contract.  Chinese MSVC/Ninja builds must carry an explicit dependency
    // edge for both listener translation units so an incremental release can
    // never silently link two stale 5006 listeners.
    const std::string wired_link_dependencies = slice_between(
        cmake_source,
        "set(VFDUAL_WIRED_LINK_CONTRACT_HEADER",
        "add_library(vfdual_host_runtime_authorization_coordinator");
    VFDUAL_TEST_REQUIRE(wired_link_dependencies.find(
                            "host/windows/security/src/host_first_pairing_service_v1.cpp") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(wired_link_dependencies.find(
                            "host/windows/security/src/host_authenticated_control_service_v1.cpp") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(wired_link_dependencies.find(
                            "${VFDUAL_WIRED_LINK_CONTRACT_HEADER}") !=
                         std::string::npos);

    const std::string start = slice_between(
        runtime_source,
        "bool HostRuntimeService::start(const HostStreamSettings& settings, std::string& error)",
        "void HostRuntimeService::request_stop() noexcept");
    VFDUAL_TEST_REQUIRE(start.find("stop_runtime();") != std::string::npos);
    VFDUAL_TEST_REQUIRE(start.find("\n    stop();") == std::string::npos);
    VFDUAL_TEST_REQUIRE(start.find("authorization_gate_->stop()") ==
                         std::string::npos);

    const std::string publish_step = slice_between(
        runtime_source,
        "const bool step_succeeded = application.publish_next();",
        "const auto now = std::chrono::steady_clock::now();");
    VFDUAL_TEST_REQUIRE(publish_step.find(
                            "DesktopVideoStepStatus::data_plane_closed") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(publish_step.find(
                            "\"host_stream_authorization_closed\"") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(publish_step.find(
                            "recovery_suppressed=true data_plane_open=false") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(publish_step.find("break;") !=
                         std::string::npos);

    const std::string recovery_gate = slice_between(
        runtime_source,
        "while (!read_stop_requested(mutex_, stop_requested_)) {",
        "const bool committing_preferred_transport =");
    VFDUAL_TEST_REQUIRE(recovery_gate.find(
                            "authorization_gate_->permits_data_plane()") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(recovery_gate.find(
                            "\"host_stream_authorization_closed\"") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(recovery_gate.find(
                            "stage=recovery action=stop_stream") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(recovery_gate.find(
                            "recovery_suppressed=true data_plane_open=false") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(recovery_gate.find("break;") !=
                         std::string::npos);

    const std::string stop = slice_between(
        runtime_source,
        "void HostRuntimeService::stop() noexcept",
        "void HostRuntimeService::stop_runtime() noexcept");
    VFDUAL_TEST_REQUIRE(stop.find("authorization_gate_->stop()") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(stop.find("stop_runtime();") != std::string::npos);
    VFDUAL_TEST_REQUIRE(runtime_header.find("void stop_runtime() noexcept") !=
                         std::string::npos);

    VFDUAL_TEST_REQUIRE(facade_header.find(
                            "install_confirmed_peer_binding") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_header.find(
                            "submit_verified_usage_lease") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_header.find(
                            "authorization_read_model") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_header.find("std::string token") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_source.find(
                            "state_->runtime.install_confirmed_peer_binding") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_source.find(
                            "state_->runtime.submit_verified_usage_lease") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_source.find(
                            "state_->runtime.revoke_data_plane_authorization") !=
                         std::string::npos);

    // One authenticated peer connection may carry multiple independently
    // server-signed formal-use sessions.  A terminal old lease must not make
    // the next sequence-zero session look like a fork, while an active or
    // rollback-tainted gate remains fail-closed.
    VFDUAL_TEST_REQUIRE(authorization_header.find(
                            "reset_data_plane_authorization_for_new_session") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(authorization_source.find(
                            "authorization_gate_->reset()") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(authorization_coordinator.find(
                            "successor_session_genesis") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(authorization_coordinator.find(
                            "UsageLeaseGateState::expired") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(authorization_coordinator.find(
                            "UsageLeaseGateState::stopped") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(authorization_coordinator.find(
                            "monotonic_clock_rollback") !=
                         std::string::npos);

    // Closing an authenticated channel deliberately interrupts the worker's
    // blocking socket read.  That expected shutdown must not be emitted as a
    // red transport failure (for example WSAENOTSOCK/WSANOTINITIALISED).
    const std::string control_read_failure = slice_between(
        authorization_coordinator,
        "if (!incoming.succeeded()) {",
        "auto opened = opener.open(incoming.encoded_record);");
    const std::size_t stopping_guard = control_read_failure.find(
        "if (stopping_.load()) break;");
    const std::size_t failure_log = control_read_failure.find(
        "\"host_authenticated_control_worker_failed\"");
    VFDUAL_TEST_REQUIRE(stopping_guard != std::string::npos);
    VFDUAL_TEST_REQUIRE(failure_log != std::string::npos);
    VFDUAL_TEST_REQUIRE(stopping_guard < failure_log);

    const std::string authenticated_successor_install = slice_between(
        authorization_coordinator,
        "bool HostRuntimeAuthorizationCoordinator::install_authenticated_channel(",
        "bool HostRuntimeAuthorizationCoordinator::has_authenticated_channel()");
    const std::size_t successor_running_snapshot =
        authenticated_successor_install.find(
            "const bool preserve_operator_start_for_successor =");
    const std::size_t successor_fail_closed =
        authenticated_successor_install.find("close();");
    const std::size_t successor_intent_rearm =
        authenticated_successor_install.find(
            "runtime_.offer_pending_start_intent();");
    VFDUAL_TEST_REQUIRE(successor_running_snapshot != std::string::npos);
    VFDUAL_TEST_REQUIRE(successor_fail_closed != std::string::npos);
    VFDUAL_TEST_REQUIRE(successor_intent_rearm != std::string::npos);
    VFDUAL_TEST_REQUIRE(successor_running_snapshot < successor_fail_closed);
    VFDUAL_TEST_REQUIRE(successor_fail_closed < successor_intent_rearm);
    VFDUAL_TEST_REQUIRE(authenticated_successor_install.find(
                            "successor_authenticated=true") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(authenticated_successor_install.find(
                            "data_plane_open=false billing_started=false") !=
                         std::string::npos);

    // An Android process restart must fail closed, then preserve exactly the
    // already-running operator request for the authenticated successor.  The
    // reconnect path may only re-arm a one-shot start intent; it must not open
    // the data plane or do so during an intentional Host stop/replacement.
    const std::string channel_loss_recovery = slice_between(
        authorization_coordinator,
        "const bool preserve_operator_start =",
        "void HostRuntimeAuthorizationCoordinator::close() noexcept");
    VFDUAL_TEST_REQUIRE(channel_loss_recovery.find(
                            "!stopping_.load() && runtime_.is_running()") !=
                         std::string::npos);
    const std::size_t fail_closed_revoke = channel_loss_recovery.find(
        "runtime_.revoke_data_plane_authorization();");
    const std::size_t rearm_one_shot = channel_loss_recovery.find(
        "runtime_.offer_pending_start_intent();");
    VFDUAL_TEST_REQUIRE(fail_closed_revoke != std::string::npos);
    VFDUAL_TEST_REQUIRE(rearm_one_shot != std::string::npos);
    VFDUAL_TEST_REQUIRE(fail_closed_revoke < rearm_one_shot);
    VFDUAL_TEST_REQUIRE(channel_loss_recovery.find(
                            "if (preserve_operator_start)") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(channel_loss_recovery.find(
                            "data_plane_open=false billing_started=false") !=
                         std::string::npos);
    const std::string intentional_close = authorization_coordinator.substr(
        authorization_coordinator.find(
            "void HostRuntimeAuthorizationCoordinator::close() noexcept"));
    VFDUAL_TEST_REQUIRE(intentional_close.find(
                            "offer_pending_start_intent") ==
                         std::string::npos);

    const std::size_t reset_for_successor = authorization_coordinator.find(
        "runtime_.reset_data_plane_authorization_for_new_session()");
    const std::size_t install_successor = authorization_coordinator.find(
        "runtime_.install_confirmed_peer_binding(", reset_for_successor);
    VFDUAL_TEST_REQUIRE(reset_for_successor != std::string::npos);
    VFDUAL_TEST_REQUIRE(install_successor != std::string::npos);
    VFDUAL_TEST_REQUIRE(reset_for_successor < install_successor);

    const std::string facade_start = slice_between(
        facade_source,
        "bool HostRuntimeFacade::start(const HostStartRequest& request, std::string& error)",
        "void HostRuntimeFacade::request_stop() noexcept");
    const std::size_t first_pair_start =
        facade_start.find("state_->first_pairing.start(");
    const std::size_t protected_runtime_start =
        facade_start.find("state_->runtime.start(settings, error)");
    VFDUAL_TEST_REQUIRE(first_pair_start != std::string::npos);
    VFDUAL_TEST_REQUIRE(protected_runtime_start != std::string::npos);
    VFDUAL_TEST_REQUIRE(first_pair_start < protected_runtime_start);
    VFDUAL_TEST_REQUIRE(facade_start.find(
                            "if (!state_->first_pairing.is_running())") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_start.find(
                            "!persisted_pair.has_value()") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_source.find(
                            "commit_server_authorized_pair_and_listen") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_source.find(
                            "commit_server_authorized_rebinding(") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_source.find(
                            "start_authenticated_control(binding, true") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(first_pairing_service.find(
                            "if (completed || stopping_.load()) break;") ==
                         std::string::npos);
    // A successful bound handshake hands its socket to the authorization
    // coordinator.  The listener itself must stay alive so an Android process
    // restart or an APK overlay can authenticate a successor generation
    // without forcing the user to restart Host.
    const std::string authenticated_control_run = slice_between(
        authenticated_control_service,
        "void HostAuthenticatedControlServiceV1::run() noexcept",
        "bool HostAuthenticatedControlServiceV1::process_candidate(");
    VFDUAL_TEST_REQUIRE(authenticated_control_run.find(
                            "if (completed || stopping_.load()) break;") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(authenticated_control_run.find(
                            "if (stopping_.load()) break;") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(authenticated_control_run.find(
                            "(void)process_candidate(accepted.connection)") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(wired_link_contract.find(
                            "kWiredFirstPairingPort = 5006") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(wired_link_contract.find(
                            "kWiredAuthenticatedControlPort = 5008") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_start.find(
                            "state_->first_pairing.provisional_pair_binding()") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_start.find(
                            "if (persisted_pair.has_value() ||") !=
                         std::string::npos);
    const std::size_t wireless_discovery = facade_start.find(
        "vfdual::discover_wireless_lan_mobile_session(");
    VFDUAL_TEST_REQUIRE(wireless_discovery != std::string::npos);
    VFDUAL_TEST_REQUIRE(first_pair_start < wireless_discovery);
    VFDUAL_TEST_REQUIRE(wireless_discovery < protected_runtime_start);
    const std::size_t wireless_discovery_retries = facade_start.find(
        "state_->start_wireless_discovery_retries(error)");
    VFDUAL_TEST_REQUIRE(wireless_discovery_retries != std::string::npos);
    VFDUAL_TEST_REQUIRE(wireless_discovery < wireless_discovery_retries);
    VFDUAL_TEST_REQUIRE(wireless_discovery_retries < protected_runtime_start);
    VFDUAL_TEST_REQUIRE(facade_source.find(
                            "std::jthread wireless_discovery_retry_worker") !=
                         std::string::npos);
    const std::string wireless_retry_worker = slice_between(
        facade_source,
        "bool start_wireless_discovery_retries(std::string& error) noexcept",
        "void stop_wireless_discovery_retries() noexcept");
    VFDUAL_TEST_REQUIRE(wireless_retry_worker.find(
                            "while (!stop_token.stop_requested())") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(wireless_retry_worker.find(
                            "authorization.has_authenticated_channel()") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(wireless_retry_worker.find(
                            "discover_wireless_lan_mobile_session(") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(wireless_retry_worker.find(
                            "std::chrono::milliseconds{1'500}, stop_token") !=
                         std::string::npos);
    const std::string protected_runtime_failure = slice_between(
        facade_start,
        "if (!state_->runtime.start(settings, error))",
        "return true;");
    VFDUAL_TEST_REQUIRE(protected_runtime_failure.find(
                            "host_failure_is_authorization_pending(error)") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(protected_runtime_failure.find(
                            "if (!vfdual::host_failure_is_authorization_pending(error))") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(protected_runtime_failure.find(
                            "state_->stop_wireless_discovery_retries();") !=
                         std::string::npos);
    const std::string stop_security_services = slice_between(
        facade_source,
        "void stop_security_services() noexcept",
        "vfdual::HostRuntimeService runtime;");
    const std::size_t stop_discovery = stop_security_services.find(
        "stop_wireless_discovery_retries();");
    const std::size_t stop_first_pair = stop_security_services.find(
        "first_pairing.stop();");
    VFDUAL_TEST_REQUIRE(stop_discovery != std::string::npos);
    VFDUAL_TEST_REQUIRE(stop_first_pair != std::string::npos);
    VFDUAL_TEST_REQUIRE(stop_discovery < stop_first_pair);
    VFDUAL_TEST_REQUIRE(facade_start.find("\"0.0.0.0\"") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_start.find(
                            "state_->runtime.stop();") ==
                         std::string::npos);
    return EXIT_SUCCESS;
}
