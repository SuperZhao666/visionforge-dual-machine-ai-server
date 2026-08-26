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
    VFDUAL_TEST_REQUIRE(facade_start.find("\"0.0.0.0\"") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(facade_start.find(
                            "state_->runtime.stop();") ==
                         std::string::npos);
    return EXIT_SUCCESS;
}
