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

    const std::string start = slice_between(
        runtime_source,
        "bool HostRuntimeService::start(const HostStreamSettings& settings, std::string& error)",
        "void HostRuntimeService::request_stop() noexcept");
    VFDUAL_TEST_REQUIRE(start.find("stop_runtime();") != std::string::npos);
    VFDUAL_TEST_REQUIRE(start.find("\n    stop();") == std::string::npos);
    VFDUAL_TEST_REQUIRE(start.find("authorization_gate_->stop()") ==
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
    return EXIT_SUCCESS;
}
