#include "vfdual/host_cat6_bootstrap.hpp"

#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stop_token>
#include <string>
#include <thread>

#ifndef VFDUAL_SOURCE_DIR
#define VFDUAL_SOURCE_DIR "."
#endif

namespace {

std::atomic_bool measurement_started{};
std::atomic_bool oversized_slice{};
std::atomic_uint32_t maintenance_calls{};
std::atomic_uint32_t exhausted_deadline_measurements{};

std::optional<vfdual::Cat6SessionSnapshot> slow_empty_measurement(
    std::chrono::milliseconds timeout) {
    measurement_started.store(true);
    if (timeout > std::chrono::milliseconds(50)) oversized_slice.store(true);
    std::this_thread::sleep_for(timeout);
    return std::nullopt;
}

std::optional<vfdual::Cat6SessionSnapshot> deadline_exhaustion_measurement(
    std::chrono::milliseconds timeout) {
    if (timeout <= std::chrono::milliseconds::zero()) {
        ++exhausted_deadline_measurements;
    }
    return std::nullopt;
}

}  // namespace

int main() {
    static_assert(
        vfdual::kHostInitialCat6PeerEvidenceTimeout >
        std::chrono::milliseconds::zero());
    static_assert(
        vfdual::kHostInitialCat6PeerEvidenceTimeout < std::chrono::seconds(4));
    static_assert(vfdual::kHostCat6MobileReadyTimeout > std::chrono::seconds(32));
    static_assert(vfdual::isolated_dhcp_startup_wait_covers_interface_probe());

    vfdual::HostCat6BootstrapResult staged_failure{};
    staged_failure.direct_link.status = vfdual::HostDirectLinkStatus::already_ready;
    staged_failure.firewall.status = vfdual::HostFirewallStatus::ready;
    staged_failure.dhcp_start_attempted = true;
    staged_failure.dhcp_started = false;
    staged_failure.dhcp_native_error = 10048U;
    staged_failure.dhcp_detail = "isolated_dhcp_start_failed";
    if (vfdual::classify_host_cat6_bootstrap_failure(staged_failure) !=
            vfdual::HostCat6BootstrapFailureStage::dhcp ||
        std::string(vfdual::host_cat6_bootstrap_failure_stage_name(
            vfdual::HostCat6BootstrapFailureStage::dhcp)) != "dhcp") {
        std::cerr << "DHCP bootstrap failure was misclassified\n";
        return 1;
    }
    staged_failure.direct_link.status = vfdual::HostDirectLinkStatus::failed;
    if (vfdual::classify_host_cat6_bootstrap_failure(staged_failure) !=
        vfdual::HostCat6BootstrapFailureStage::direct_link) {
        std::cerr << "Direct-link failure precedence was lost\n";
        return 1;
    }
    staged_failure.direct_link.status = vfdual::HostDirectLinkStatus::already_ready;
    staged_failure.firewall.status = vfdual::HostFirewallStatus::failed;
    if (vfdual::classify_host_cat6_bootstrap_failure(staged_failure) !=
        vfdual::HostCat6BootstrapFailureStage::firewall) {
        std::cerr << "Firewall failure precedence was lost\n";
        return 1;
    }
    staged_failure.firewall.status = vfdual::HostFirewallStatus::ready;
    staged_failure.dhcp_start_attempted = false;
    staged_failure.dhcp_detail = "isolated_dhcp_owner_required";
    if (vfdual::classify_host_cat6_bootstrap_failure(staged_failure) !=
        vfdual::HostCat6BootstrapFailureStage::dhcp) {
        std::cerr << "Missing DHCP owner was misclassified\n";
        return 1;
    }
    staged_failure.dhcp_start_attempted = true;
    staged_failure.dhcp_detail = "isolated_dhcp_start_failed";
    staged_failure.dhcp_started = true;
    staged_failure.mobile_wait_attempted = true;
    if (vfdual::classify_host_cat6_bootstrap_failure(staged_failure) !=
        vfdual::HostCat6BootstrapFailureStage::mobile_ready_timeout) {
        std::cerr << "Mobile-ready timeout was misclassified\n";
        return 1;
    }
    staged_failure.dhcp_runtime_failed = true;
    staged_failure.dhcp_native_error = 10049U;
    staged_failure.dhcp_detail = "isolated_dhcp_reply_send_failed";
    if (vfdual::classify_host_cat6_bootstrap_failure(staged_failure) !=
        vfdual::HostCat6BootstrapFailureStage::dhcp) {
        std::cerr << "Runtime DHCP send failure was misclassified\n";
        return 1;
    }
    staged_failure.dhcp_runtime_failed = false;
    staged_failure.mobile = vfdual::Cat6SessionSnapshot{};
    if (vfdual::classify_host_cat6_bootstrap_failure(staged_failure) !=
        vfdual::HostCat6BootstrapFailureStage::none) {
        std::cerr << "Successful CAT6 bootstrap was misclassified\n";
        return 1;
    }

    std::stop_source stop_source;
    std::optional<vfdual::Cat6SessionSnapshot> result;
    std::thread waiter([&] {
        result = vfdual::wait_for_host_cat6_mobile(
            vfdual::kHostCat6MobileReadyTimeout,
            stop_source.get_token(), slow_empty_measurement, [] {
                ++maintenance_calls;
                return true;
            });
    });

    const auto measurement_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (!measurement_started.load() && std::chrono::steady_clock::now() < measurement_deadline) {
        std::this_thread::yield();
    }
    const auto cancel_started = std::chrono::steady_clock::now();
    stop_source.request_stop();
    waiter.join();
    const auto cancel_elapsed = std::chrono::steady_clock::now() - cancel_started;

    if (!measurement_started.load() || oversized_slice.load() ||
        maintenance_calls.load() == 0U || result.has_value() ||
        cancel_elapsed > std::chrono::milliseconds(500)) {
        std::cerr << "CAT6 bootstrap cancellation did not complete promptly\n";
        return 1;
    }

    exhausted_deadline_measurements.store(0U);
    std::stop_source deadline_stop_source;
    const auto exhausted = vfdual::wait_for_host_cat6_mobile(
        std::chrono::milliseconds{10}, deadline_stop_source.get_token(),
        deadline_exhaustion_measurement, [] {
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
            return true;
        });
    if (exhausted.has_value() || exhausted_deadline_measurements.load() != 0U) {
        std::cerr << "CAT6 wait called measurement after deadline exhaustion\n";
        return 1;
    }

    const std::string bootstrap_source_path =
        std::string(VFDUAL_SOURCE_DIR) +
        "/host/windows/src/host_cat6_bootstrap.cpp";
    std::ifstream bootstrap_source_file(bootstrap_source_path);
    const std::string bootstrap_source(
        (std::istreambuf_iterator<char>(bootstrap_source_file)),
        std::istreambuf_iterator<char>());
    if (bootstrap_source.empty() ||
        bootstrap_source.find("kDirectLinkStartupProbeTimeout") ==
            std::string::npos ||
        bootstrap_source.find("direct_link_detection_is_temporarily_pending") ==
            std::string::npos ||
        bootstrap_source.find("HostDirectLinkStatus::no_wired_adapter") ==
            std::string::npos ||
        bootstrap_source.find("not_operational") == std::string::npos ||
        bootstrap_source.find("oper=down") == std::string::npos ||
        bootstrap_source.find("dad=tentative") == std::string::npos ||
        bootstrap_source.find("direct_link_warmup_retry") ==
            std::string::npos ||
        bootstrap_source.find(
            "(std::min)(\n"
            "        std::chrono::duration_cast<std::chrono::milliseconds>(\n"
            "            kDirectLinkStartupProbeTimeout),\n"
            "        (std::max)(session_timeout") == std::string::npos) {
        std::cerr
            << "CAT6 direct-link startup warmup contract is missing in "
            << bootstrap_source_path << "\n";
        return 1;
    }

    const std::string runtime_source_path =
        std::string(VFDUAL_SOURCE_DIR) +
        "/host/windows/src/host_runtime_service.cpp";
    std::ifstream runtime_source_file(runtime_source_path);
    const std::string runtime_source(
        (std::istreambuf_iterator<char>(runtime_source_file)),
        std::istreambuf_iterator<char>());
    if (runtime_source.empty() ||
        runtime_source.find(
            "bootstrap_host_cat6_link(\n"
            "        kHostInitialCat6PeerEvidenceTimeout") ==
            std::string::npos ||
        runtime_source.find(
            "bootstrap_host_cat6_link(\n"
            "                    kHostCat6MobileReadyTimeout") ==
            std::string::npos ||
        runtime_source.find(
            "adapter_address_state_is_candidate_only=true") ==
            std::string::npos) {
        std::cerr
            << "Host startup must use a short peer-evidence budget while "
               "background CAT6 probes retain the long DHCP budget in "
            << runtime_source_path << "\n";
        return 1;
    }
    if (bootstrap_source.find("kWindowsAddressNotAvailable") ==
            std::string::npos ||
        bootstrap_source.find("kDhcpStartupAttemptsAfterAddressRepair") ==
            std::string::npos ||
        bootstrap_source.find("dhcp_address_repair_started") ==
            std::string::npos ||
        bootstrap_source.find("after_dhcp_address_repair_firewall") ==
            std::string::npos) {
        std::cerr
            << "CAT6 DHCP address-repair retry contract is missing in "
            << bootstrap_source_path << "\n";
        return 1;
    }
    if (bootstrap_source.find("prefer_persistent_address_backend") ==
            std::string::npos ||
        bootstrap_source.find("persistent netsh backend") ==
            std::string::npos ||
        bootstrap_source.find(
            "bootstrap_host_cat6_link_once(\n"
            "        session_timeout, isolated_dhcp_server, stop_token, true)") ==
            std::string::npos) {
        std::cerr
            << "CAT6 production bootstrap must start with the persistent "
               "address backend to avoid transient DHCP bind failures in "
            << bootstrap_source_path << "\n";
        return 1;
    }
    return 0;
}
