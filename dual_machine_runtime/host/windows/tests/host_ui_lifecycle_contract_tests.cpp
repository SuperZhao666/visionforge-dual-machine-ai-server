#include <cstdlib>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#ifndef VFDUAL_SOURCE_DIR
#error "VFDUAL_SOURCE_DIR must point at the dual_machine_runtime source directory"
#endif

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::cerr << "CHECK failed: " << expression << " (" << file << ':' << line << ")\n";
    std::exit(EXIT_FAILURE);
}

#define VFDUAL_TEST_REQUIRE(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

    std::string read_source(const char* relative_path) {
    const std::string path = std::string{VFDUAL_SOURCE_DIR} + "/" + relative_path;
    std::ifstream input{path, std::ios::binary};
    VFDUAL_TEST_REQUIRE(input.good());
    std::ostringstream buffer;
    buffer << input.rdbuf();
    std::string text = buffer.str();
    for (std::size_t offset = text.find("\r\n");
         offset != std::string::npos;
         offset = text.find("\r\n", offset + 1U)) {
        text.replace(offset, 2U, "\n");
    }
    return text;
}

std::string slice_between(
    const std::string& source, const std::string& begin, const std::string& end) {
    const std::size_t begin_index = source.find(begin);
    VFDUAL_TEST_REQUIRE(begin_index != std::string::npos);
    const std::size_t end_index = source.find(end, begin_index + begin.size());
    VFDUAL_TEST_REQUIRE(end_index != std::string::npos);
    return source.substr(begin_index, end_index - begin_index);
}

bool ico_has_square_size(const std::string& icon, std::uint16_t expected_size) {
    if (icon.size() < 6U || static_cast<unsigned char>(icon[2]) != 1U ||
        static_cast<unsigned char>(icon[3]) != 0U) {
        return false;
    }
    const std::uint16_t count = static_cast<std::uint16_t>(
        static_cast<unsigned char>(icon[4]) |
        (static_cast<unsigned char>(icon[5]) << 8U));
    for (std::uint16_t index = 0; index < count; ++index) {
        const std::size_t offset = 6U + static_cast<std::size_t>(index) * 16U;
        if (offset + 16U > icon.size()) return false;
        const std::uint16_t width = static_cast<unsigned char>(icon[offset]) == 0U
            ? 256U : static_cast<unsigned char>(icon[offset]);
        const std::uint16_t height = static_cast<unsigned char>(icon[offset + 1U]) == 0U
            ? 256U : static_cast<unsigned char>(icon[offset + 1U]);
        if (width == expected_size && height == expected_size) return true;
    }
    return false;
}

}  // namespace

int main() {
    const std::string header =
        read_source("host/windows/include/vfdual/streamer_desktop_app.hpp");
    const std::string source =
        read_source("host/windows/src/streamer_desktop_app.cpp");
    const std::string cmake_source = read_source("CMakeLists.txt");
    const std::string host_build_script =
        read_source("host/windows/build_host_application.bat");
    const std::string host_release_verifier =
        read_source("host/windows/verify_host_release_artifact.ps1");
    const std::string release_version = read_source("release_version.txt");
    const std::string resource_source =
        read_source("host/windows/streamer_ui.rc");
    const std::string release_version_header_template =
        read_source("host/windows/include/vfdual/host_release_version.hpp.in");
    const std::string main_source =
        read_source("host/windows/src/streamer_desktop_main.cpp");
    const std::string runtime_source =
        read_source("host/windows/src/host_runtime_service.cpp");
    const std::string endpoint_discovery_source =
        read_source("host/windows/src/host_endpoint_discovery_facade.cpp");
    const std::string runtime_header =
        read_source("host/windows/include/vfdual/host_runtime_service.hpp");
    const std::string idle_ui_header =
        read_source("host/windows/include/vfdual/host_idle_ui_state.hpp");
    const std::string manifest_source =
        read_source("host/windows/VisionForgeHost.manifest");
    const std::string app_icon =
        read_source("host/windows/assets/ui/app.ico");

    for (const std::uint16_t size : {16U, 20U, 24U, 32U, 40U, 48U, 64U, 128U, 256U}) {
        VFDUAL_TEST_REQUIRE(ico_has_square_size(app_icon, size));
    }

    VFDUAL_TEST_REQUIRE(source.find(
                            "L\"VisionForgeStreamerDesktopWindow\"") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(main_source.find(
                            "L\"Global\\\\VisionForge.Host.MainInstance.v1\"") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find(
                            "add_executable(VisionForgeHost WIN32") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(release_version.find("1.0.8") == 0U);
    VFDUAL_TEST_REQUIRE(cmake_source.find("release_version.txt") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find(
                            "project(VisionForgeDualMachine VERSION") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find(
                            "configure_file(\n        host/windows/streamer_ui.rc") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find(
                            "configure_file(\n        host/windows/include/vfdual/host_release_version.hpp.in") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(release_version_header_template.find(
                            "L\"@VFDUAL_RELEASE_VERSION@\"") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("VF Host   v1.0.0") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("kHostReleaseVersion") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(resource_source.find(
                            "FILEVERSION @VFDUAL_VERSION_MAJOR@") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find(
                            "set_target_properties(VisionForgeHost PROPERTIES OUTPUT_NAME VFHost)") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find("$<$<CONFIG:Release>:/DYNAMICBASE>") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find("$<$<CONFIG:Release>:/HIGHENTROPYVA>") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find("$<$<CONFIG:Release>:/NXCOMPAT>") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find("$<$<CONFIG:Release>:/guard:cf>") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find("$<$<CONFIG:Release>:/CETCOMPAT>") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(host_build_script.find(
                            "--target VisionForgeHost --clean-first") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(host_build_script.find(
                            "verify_host_release_artifact.ps1") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(host_build_script.find(
                            "-DVFDUAL_ENABLE_PRIVATE_HOST_SYMBOLS=OFF") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(host_build_script.find(
                            "-PrivateSymbolsDirectory") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(host_release_verifier.find(
                            "Control Flow Guard instrumentation") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(host_release_verifier.find("CET compatibility") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(host_release_verifier.find(
                            "private_out_of_band") != std::string::npos);
    VFDUAL_TEST_REQUIRE(host_release_verifier.find(
                            "Get-AuthenticodeSignature") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(host_build_script.find(
                            "out\\VFHost.exe") != std::string::npos);
    VFDUAL_TEST_REQUIRE(host_build_script.find(
                            "BUILD_DIR%\\VFHost.exe") != std::string::npos);
    VFDUAL_TEST_REQUIRE(host_build_script.find(
                            "set \"VFDUAL_HOST_OUTPUT=%RUNTIME_ROOT%\\out\\VisionForgeHost.exe\"") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(host_build_script.find(
                            "copy /Y \"%BUILD_DIR%\\VisionForgeHost.exe\"") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(host_build_script.find(
                            "if exist \"%RUNTIME_ROOT%\\out\\VisionForgeHost.exe\" del /F /Q") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find(
                            "L\"VisionForge\" / L\"DualMachine\"") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(runtime_source.find(
                            "\"VisionForge\" / \"DualMachine\"") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(manifest_source.find(
                            "name=\"VisionForge.Host\"") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(manifest_source.find(
                            "version=\"@VFDUAL_WINDOWS_FILE_VERSION@\"") !=
                         std::string::npos);

    VFDUAL_TEST_REQUIRE(source.find("L\"VF Host\"") != std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("VF Mobile") != std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("VisionForge Host") == std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("VisionForge Mobile") == std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("VISIONFORGE  HOST") == std::string::npos);
    VFDUAL_TEST_REQUIRE(main_source.find("VisionForge Host") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(main_source.find("VF Host") != std::string::npos);
    VFDUAL_TEST_REQUIRE(idle_ui_header.find("VisionForge Mobile") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(idle_ui_header.find("VF Mobile") != std::string::npos);
    VFDUAL_TEST_REQUIRE(manifest_source.find(
                            "<description>VF CAT6 Host Streamer</description>") !=
                         std::string::npos);

    VFDUAL_TEST_REQUIRE(main_source.find(
                            "std::make_unique<vfdual::StreamerDesktopApp>()") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(header.find("void initialize_display_selection();") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(header.find("bool start_after_mobile_refresh_cancel_{};") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(header.find("enum class MobileRefreshState") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(header.find("std::atomic_bool mobile_refresh_finished_{true};") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("post_startup_completed_result(") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("post_mobile_refresh_completed_result(") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("host_gui_mobile_refresh_state_repaired") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("host_gui_startup_state_repaired") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("host_gui_acceptance_autostart_posted") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("host_gui_acceptance_autostart_received") !=
                         std::string::npos);

    VFDUAL_TEST_REQUIRE(header.find("pairing_wizard_step_") == std::string::npos);
    VFDUAL_TEST_REQUIRE(header.find("export_pairing_button_") == std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("export_pairing_package_to_clipboard") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("describe_pairing_export_recovery") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("WindowsPairingPackageExportError") ==
                         std::string::npos);

    // The capability switch is deliberately isolated in a one-line file so
    // development OFF and a future reviewed ON state share one fail-closed
    // loader contract instead of contradictory source checks.
    VFDUAL_TEST_REQUIRE(cmake_source.find(
                            "option(VFDUAL_FORMAL_SECURE_DATA_PLANE_ONLY") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find(
                            "formal_security_loader.cmake") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(cmake_source.find(
                            "formal_security_capability.cmake") ==
                         std::string::npos);
    const std::string formal_capability = read_source(
        "formal_security_capability.cmake");
    VFDUAL_TEST_REQUIRE(
        formal_capability ==
            "set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED OFF)\n" ||
        formal_capability ==
            "set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED ON)\n");
    const std::string formal_loader = read_source(
        "formal_security_loader.cmake");
    VFDUAL_TEST_REQUIRE(formal_loader.find(
                            "include(\"${CMAKE_CURRENT_LIST_DIR}/formal_security_capability.cmake\")") ==
                         0U);
    VFDUAL_TEST_REQUIRE(formal_loader.find(
                            "set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(formal_loader.find(
                            "if(NOT DEFINED VFDUAL_FORMAL_SECURITY_IMPLEMENTED OR") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(formal_loader.find(
                            "NOT \"${VFDUAL_FORMAL_SECURITY_IMPLEMENTED}\" MATCHES \"^(ON|OFF)$\")") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(formal_loader.find(
                            "message(FATAL_ERROR \"Formal security capability must be exactly ON or OFF\")") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(formal_loader.find(
                            "Formal secure data plane is not implemented") !=
                         std::string::npos);

    const std::string create_controls = slice_between(
        source, "void StreamerDesktopApp::create_controls(HWND window)",
        "void StreamerDesktopApp::initialize_display_selection()");
    VFDUAL_TEST_REQUIRE(create_controls.find("enumerate_host_display_outputs()") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(create_controls.find("设置与手机连接") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(create_controls.find("CAT6 有线优先") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(create_controls.find("无线局域网 UDP") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(create_controls.find("复制配对包") == std::string::npos);
    VFDUAL_TEST_REQUIRE(create_controls.find("pairing_wizard_step_") ==
                         std::string::npos);

    const std::string initialize_display_selection = slice_between(
        source, "void StreamerDesktopApp::initialize_display_selection()",
        "HWND StreamerDesktopApp::add_static");
    VFDUAL_TEST_REQUIRE(initialize_display_selection.find(
                            "display_outputs_ = enumerate_host_display_outputs();") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("host_gui_display_selection_initialized") !=
                         std::string::npos);

    const std::string failure_mapper = slice_between(
        source, "std::wstring friendly_host_failure(std::string_view error)",
        "bool set_window_text_if_changed(HWND control, std::wstring_view text)");
    const std::size_t wireless_discovery_index =
        failure_mapper.find("Automatic wireless-LAN UDP fallback was unavailable");
    const std::size_t mobile_ipv4_index =
        failure_mapper.find("Host DHCP received zero packets");
    const std::size_t heartbeat_index =
        failure_mapper.find("failure_stage=mobile_ready_timeout");
    const std::size_t firewall_index =
        failure_mapper.find("CAT6 firewall provisioning failed");
    const std::size_t wireless_firewall_index =
        failure_mapper.find("wireless_firewall_status=failed");
    const std::size_t legacy_firewall_conflict_index =
        failure_mapper.find("ambiguous_same_name_rule");
    const std::size_t h264_index = failure_mapper.find("H.264");
    VFDUAL_TEST_REQUIRE(wireless_discovery_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(mobile_ipv4_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(heartbeat_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(firewall_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(wireless_firewall_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(legacy_firewall_conflict_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(h264_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(legacy_firewall_conflict_index < wireless_discovery_index);
    VFDUAL_TEST_REQUIRE(wireless_firewall_index < wireless_discovery_index);
    VFDUAL_TEST_REQUIRE(firewall_index < wireless_discovery_index);
    VFDUAL_TEST_REQUIRE(wireless_discovery_index < mobile_ipv4_index);
    VFDUAL_TEST_REQUIRE(mobile_ipv4_index < heartbeat_index);
    VFDUAL_TEST_REQUIRE(failure_mapper.find("error.find(\"firewall\")") ==
                         std::string::npos);

    const std::string mobile_refresh_handler = slice_between(
        source, "case kMobileRefreshCompletedMessage:", "case kStartupCompletedMessage:");
    const std::size_t join_index =
        mobile_refresh_handler.find("safe_join_thread(mobile_refresh_thread_)");
    const std::size_t stale_branch_index =
        mobile_refresh_handler.find("if (!generation_matches)");
    VFDUAL_TEST_REQUIRE(join_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(stale_branch_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(join_index < stale_branch_index);
    VFDUAL_TEST_REQUIRE(mobile_refresh_handler.find(
                            "if (start_after_mobile_refresh_cancel_)") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(mobile_refresh_handler.find("start_streamer(window);") !=
                         std::string::npos);

    const std::string start_streamer = slice_between(
        source, "void StreamerDesktopApp::start_streamer(HWND window)",
        "void StreamerDesktopApp::stop_streamer()");
    VFDUAL_TEST_REQUIRE(start_streamer.find(
                            "reap_completed_mobile_refresh_thread(\"start_streamer_enter\")") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find(
                            "repair_stale_startup_state(\"start_streamer_enter\")") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find("mobile_refresh_stop_source_.request_stop();") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find(
                            "schedule_autostart_retry(window, acceptance_autostart_)") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find("cancel_mobile_refresh_probe();") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find("return;") <
                         start_streamer.find("const auto now"));
    VFDUAL_TEST_REQUIRE(start_streamer.find("try {") != std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find("catch (const std::exception& exception)") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find("catch (...)") != std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find("runtime_facade_.start(settings, error)") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find("post_startup_completed_result(") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find("host_gui_start_streamer_entered") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find("host_gui_start_streamer_skipped") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find("host_gui_start_streamer_selected") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find("host_gui_startup_thread_join_prepare") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(start_streamer.find("host_gui_startup_thread_created") !=
                         std::string::npos);

    const std::string refresh_mobile = slice_between(
        source, "void StreamerDesktopApp::refresh_mobile_device()",
        "void StreamerDesktopApp::cancel_mobile_refresh_probe() noexcept");
    VFDUAL_TEST_REQUIRE(refresh_mobile.find("try {") != std::string::npos);
    VFDUAL_TEST_REQUIRE(refresh_mobile.find("catch (const std::exception& exception)") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(refresh_mobile.find("catch (...)") != std::string::npos);
    VFDUAL_TEST_REQUIRE(refresh_mobile.find("post_mobile_refresh_completed_result(") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(refresh_mobile.find("discovery->discover(") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(endpoint_discovery_source.find(
                            "ensure_host_firewall_rules_automatically()") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(endpoint_discovery_source.find(
                            "measure_wireless_lan_mobile_session(") !=
                         std::string::npos);

    VFDUAL_TEST_REQUIRE(runtime_header.find(
                            "std::string transport{kCat6TransportName};") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("describe_link(metrics->transport)") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("std::wstring describe_link()") ==
                         std::string::npos);

    const std::string stop_streamer = slice_between(
        source, "void StreamerDesktopApp::stop_streamer()",
        "void StreamerDesktopApp::refresh_status()");
    VFDUAL_TEST_REQUIRE(stop_streamer.find("if (start_after_mobile_refresh_cancel_)") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(stop_streamer.find("start_after_mobile_refresh_cancel_ = false;") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("mobile_refresh_thread_.join()") ==
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(source.find("startup_thread_.join()") ==
                         std::string::npos);

    const std::string runtime_start = slice_between(
        runtime_source,
        "bool HostRuntimeService::start(const HostStreamSettings& settings, std::string& error)",
        "void HostRuntimeService::request_stop() noexcept");
    const std::size_t technical_teardown_index = runtime_start.find("stop_runtime();");
    const std::size_t worker_assignment_index = runtime_start.find("worker_ = std::thread");
    const std::size_t thread_create_failure_index =
        runtime_start.find("host_worker_thread_create_failed");
    VFDUAL_TEST_REQUIRE(technical_teardown_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(worker_assignment_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(thread_create_failure_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(technical_teardown_index < worker_assignment_index);
    VFDUAL_TEST_REQUIRE(worker_assignment_index < thread_create_failure_index);

    const std::string runtime_stop = slice_between(
        runtime_source,
        "void HostRuntimeService::stop() noexcept",
        "void HostRuntimeService::stop_runtime() noexcept");
    VFDUAL_TEST_REQUIRE(runtime_stop.find("stop_runtime();") != std::string::npos);
    VFDUAL_TEST_REQUIRE(runtime_stop.find("authorization_gate_->stop()") !=
                         std::string::npos);

    const std::string runtime_request_stop = slice_between(
        runtime_source,
        "void HostRuntimeService::request_stop() noexcept",
        "void HostRuntimeService::stop() noexcept");
    VFDUAL_TEST_REQUIRE(runtime_request_stop.find("stop_requested_ = true;") !=
                         std::string::npos);

    const std::string direct_link_restore = slice_between(
        runtime_source,
        "void HostRuntimeService::restore_direct_link_on_clean_shutdown() noexcept",
        "bool HostRuntimeService::is_running() const noexcept");
    VFDUAL_TEST_REQUIRE(direct_link_restore.find("\n    stop();") == std::string::npos);
    VFDUAL_TEST_REQUIRE(direct_link_restore.find("isolated_dhcp_server_->stop();") !=
                         std::string::npos);
    VFDUAL_TEST_REQUIRE(direct_link_restore.find(
                            "restore_host_direct_link_ipv4_automatically()") !=
                         std::string::npos);
    return EXIT_SUCCESS;
}
