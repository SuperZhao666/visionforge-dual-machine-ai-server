#include "vfdual/host_cat6_bootstrap.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <thread>
#include <string>
#include <utility>

namespace vfdual {
namespace {

constexpr auto kDirectLinkStartupProbeTimeout = std::chrono::seconds{6};
constexpr auto kDirectLinkStartupProbeInterval = std::chrono::milliseconds{250};
constexpr auto kDirectLinkStartupProbeCancelSlice = std::chrono::milliseconds{50};
constexpr std::uint32_t kWindowsAddressNotAvailable = 10049U;
constexpr int kDhcpStartupAttemptsAfterAddressRepair = 2;

void stop_owned_dhcp(IsolatedDhcpServer* isolated_dhcp_server) noexcept {
    if (isolated_dhcp_server != nullptr && isolated_dhcp_server->running()) {
        isolated_dhcp_server->stop();
    }
}

std::string describe_dhcp_startup_state(
    const IsolatedDhcpServer* isolated_dhcp_server) {
    if (isolated_dhcp_server == nullptr) {
        return "dhcp_server=null";
    }
    const IsolatedDhcpMetrics metrics = isolated_dhcp_server->metrics();
    const auto stage =
        static_cast<IsolatedDhcpStartupStage>(metrics.startup_stage);
    return std::string{"startup_stage="} +
        isolated_dhcp_startup_stage_name(stage) +
        " startup_stage_code=" + std::to_string(metrics.startup_stage) +
        " interface_match_count=" +
        std::to_string(metrics.interface_match_count) +
        " interface_index=" + std::to_string(metrics.interface_index) +
        " last_error=" + std::to_string(
            isolated_dhcp_server->last_error());
}

void append_diagnostic(
    HostCat6BootstrapResult& result,
    std::string diagnostic) {
    result.diagnostics.push_back(std::move(diagnostic));
}

bool direct_link_detection_is_temporarily_pending(
    const HostDirectLinkProvisioningResult& result) noexcept {
    return result.status == HostDirectLinkStatus::no_wired_adapter &&
        result.detection_temporarily_pending;
}

bool wait_direct_link_startup_probe_slice(
    std::chrono::steady_clock::time_point deadline,
    std::stop_token stop_token) {
    while (!stop_token.stop_requested() &&
           std::chrono::steady_clock::now() < deadline) {
        const auto now = std::chrono::steady_clock::now();
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now);
        if (remaining <= std::chrono::milliseconds::zero()) break;
        std::this_thread::sleep_for(
            (std::min)(kDirectLinkStartupProbeCancelSlice, remaining));
    }
    return !stop_token.stop_requested();
}

HostDirectLinkProvisioningResult ensure_direct_link_after_startup_warmup(
    HostCat6BootstrapResult& result,
    std::chrono::milliseconds session_timeout,
    std::stop_token stop_token) {
    const auto probe_timeout = (std::min)(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            kDirectLinkStartupProbeTimeout),
        (std::max)(session_timeout, std::chrono::milliseconds::zero()));
    const auto deadline =
        std::chrono::steady_clock::now() + probe_timeout;
    std::uint32_t attempt = 0U;
    HostDirectLinkProvisioningResult direct_link{};
    do {
        ++attempt;
        direct_link = ensure_host_direct_link_ipv4_automatically();
        const bool temporarily_pending =
            direct_link_detection_is_temporarily_pending(direct_link);
        append_diagnostic(
            result,
            "stage=direct_link_probe attempt=" + std::to_string(attempt) +
                " probe_budget_ms=" + std::to_string(probe_timeout.count()) +
                " status=" +
                std::string(host_direct_link_status_name(direct_link.status)) +
                " temporarily_pending_direct_link=" +
                (temporarily_pending ? "true" : "false") +
                " detail={" + direct_link.detail + "}");
        if (!temporarily_pending || stop_token.stop_requested() ||
            std::chrono::steady_clock::now() >= deadline) {
            return direct_link;
        }
        append_diagnostic(
            result,
            "stage=direct_link_warmup_retry attempt=" +
                std::to_string(attempt) + " retry_delay_ms=" +
                std::to_string(kDirectLinkStartupProbeInterval.count()));
        const auto next_probe_at =
            (std::min)(deadline,
                       std::chrono::steady_clock::now() +
                           kDirectLinkStartupProbeInterval);
        if (!wait_direct_link_startup_probe_slice(next_probe_at, stop_token)) {
            return direct_link;
        }
    } while (true);
}

HostFirewallProvisioningResult ensure_firewall_automatically() {
    HostFirewallProvisioningResult result =
        ensure_host_firewall_rules();
    if (result.status != HostFirewallStatus::requires_elevation) return result;

    std::string worker_detail;
    if (!launch_host_firewall_provisioning_worker(worker_detail)) {
        result.status = HostFirewallStatus::failed;
        result.detail = "stage=firewall_elevated_worker " + worker_detail +
            " initial={" + result.detail + '}';
        return result;
    }
    result = ensure_host_firewall_rules();
    result.detail += " elevated_worker={" + worker_detail + '}';
    return result;
}

HostCat6BootstrapResult bootstrap_host_cat6_link_once(
    std::chrono::milliseconds session_timeout,
    IsolatedDhcpServer* isolated_dhcp_server,
    std::stop_token stop_token,
    bool prefer_persistent_address_backend) {
    set_host_direct_link_prefer_persistent_backend(
        prefer_persistent_address_backend);
    HostCat6BootstrapResult result{};
    append_diagnostic(
        result,
        std::string{"stage=begin preferred_address_backend="} +
            (prefer_persistent_address_backend ? "persistent_netsh" : "auto") +
            " ipv4_table={" + describe_host_ipv4_unicast_table() + "}");
    if (stop_token.stop_requested()) {
        stop_owned_dhcp(isolated_dhcp_server);
        append_diagnostic(result, "stage=cancelled_before_direct_link");
        return result;
    }
    result.direct_link =
        ensure_direct_link_after_startup_warmup(
            result, session_timeout, stop_token);
    append_diagnostic(
        result,
        std::string{"stage=after_direct_link status="} +
            host_direct_link_status_name(result.direct_link.status) +
            " detail={" + result.direct_link.detail + "} ipv4_table={" +
            describe_host_ipv4_unicast_table() + "}");
    if (!host_direct_link_is_ready(result.direct_link.status)) {
        stop_owned_dhcp(isolated_dhcp_server);
        return result;
    }
    if (stop_token.stop_requested()) {
        stop_owned_dhcp(isolated_dhcp_server);
        append_diagnostic(result, "stage=cancelled_before_firewall");
        return result;
    }
    result.firewall_attempted = true;
    result.firewall = ensure_firewall_automatically();
    append_diagnostic(
        result,
        std::string{"stage=after_firewall status="} +
            host_firewall_status_name(result.firewall.status) +
            " detail={" + result.firewall.detail + "}");
    if (!host_firewall_is_ready(result.firewall.status)) {
        stop_owned_dhcp(isolated_dhcp_server);
        const HostDirectLinkRestorationResult restoration =
            restore_host_direct_link_ipv4_automatically();
        result.firewall.detail +=
            " direct_link_rollback_status=" +
            std::string(host_direct_link_restore_status_name(restoration.status)) +
            " direct_link_rollback_detail=" + restoration.detail;
        append_diagnostic(
            result,
            std::string{"stage=firewall_rollback restore_status="} +
                host_direct_link_restore_status_name(restoration.status) +
                " detail={" + restoration.detail + "} ipv4_table={" +
                describe_host_ipv4_unicast_table() + "}");
        return result;
    }
    if (stop_token.stop_requested()) {
        stop_owned_dhcp(isolated_dhcp_server);
        append_diagnostic(result, "stage=cancelled_before_dhcp");
        return result;
    }
    if (isolated_dhcp_server == nullptr) {
        result.dhcp_detail = "isolated_dhcp_owner_required";
        append_diagnostic(result, "stage=dhcp_owner_missing");
        return result;
    }
    if (!isolated_dhcp_server->running()) {
        result.dhcp_start_attempted = true;
        for (int dhcp_attempt = 1;
             dhcp_attempt <= kDhcpStartupAttemptsAfterAddressRepair;
             ++dhcp_attempt) {
            append_diagnostic(
                result,
                "stage=before_dhcp_start attempt=" +
                    std::to_string(dhcp_attempt) + " " +
                    describe_dhcp_startup_state(isolated_dhcp_server) +
                    " ipv4_table={" + describe_host_ipv4_unicast_table() + "}");
            if (isolated_dhcp_server->start()) break;

            result.dhcp_native_error = isolated_dhcp_server->last_error();
            result.dhcp_detail = "isolated_dhcp_start_failed attempt=" +
                std::to_string(dhcp_attempt) + " " +
                describe_dhcp_startup_state(isolated_dhcp_server);
            append_diagnostic(
                result,
                "stage=dhcp_start_failed attempt=" +
                    std::to_string(dhcp_attempt) + " " + result.dhcp_detail +
                    " ipv4_table={" + describe_host_ipv4_unicast_table() +
                    "}");
            const bool address_repair_allowed =
                result.dhcp_native_error == kWindowsAddressNotAvailable &&
                dhcp_attempt < kDhcpStartupAttemptsAfterAddressRepair &&
                !stop_token.stop_requested();
            if (!address_repair_allowed) return result;

            append_diagnostic(
                result,
                "stage=dhcp_address_repair_started attempt=" +
                    std::to_string(dhcp_attempt + 1));
            result.direct_link =
                ensure_direct_link_after_startup_warmup(
                    result, session_timeout, stop_token);
            append_diagnostic(
                result,
                std::string{"stage=after_dhcp_address_repair status="} +
                    host_direct_link_status_name(result.direct_link.status) +
                    " detail={" + result.direct_link.detail +
                    "} ipv4_table={" + describe_host_ipv4_unicast_table() +
                    "}");
            if (!host_direct_link_is_ready(result.direct_link.status)) {
                return result;
            }
            result.firewall = ensure_firewall_automatically();
            append_diagnostic(
                result,
                std::string{"stage=after_dhcp_address_repair_firewall status="} +
                    host_firewall_status_name(result.firewall.status) +
                    " detail={" + result.firewall.detail + "}");
            if (!host_firewall_is_ready(result.firewall.status)) {
                return result;
            }
        }
    }
    result.dhcp_started = isolated_dhcp_server->running();
    result.dhcp_detail = result.dhcp_started ? "isolated_dhcp_running " :
        "isolated_dhcp_not_running_after_start ";
    result.dhcp_detail += describe_dhcp_startup_state(isolated_dhcp_server);
    append_diagnostic(result, "stage=after_dhcp_start " + result.dhcp_detail);
    result.mobile_wait_attempted = true;
    const auto watch_started_at = std::chrono::steady_clock::now();
    std::string last_subnet_state = describe_host_isolated_subnet_state();
    result.address_watch = "0ms:[" + last_subnet_state + ']';
    result.mobile = wait_for_host_cat6_mobile(
        session_timeout, stop_token, measure_cat6_mobile_session, [&] {
            // Watchdog: record every transition of the live 10.57.x address
            // set during the wait. This is the decisive evidence for whether
            // the isolated address is purged by the stack or rewritten by an
            // external machine-identity tool (its alias appears in the set).
            const std::string current_state = describe_host_isolated_subnet_state();
            if (current_state != last_subnet_state) {
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - watch_started_at).count();
                result.address_watch += " " + std::to_string(elapsed) +
                    "ms:[" + last_subnet_state + "]->[" + current_state + ']';
                append_diagnostic(
                    result,
                    "stage=address_watch_transition elapsed_ms=" +
                        std::to_string(elapsed) + " state={" +
                        current_state + "}");
                last_subnet_state = current_state;
            }
            HostFirewallProvisioningResult audit =
                ensure_firewall_automatically();
            const bool ready = host_firewall_is_ready(audit.status);
            result.firewall = std::move(audit);
            return ready;
        });
    if (!result.mobile.has_value()) {
        const IsolatedDhcpMetrics metrics = isolated_dhcp_server->metrics();
        append_diagnostic(
            result,
            "stage=mobile_wait_finished_without_session " +
                describe_dhcp_startup_state(isolated_dhcp_server) +
                " received_packets=" + std::to_string(metrics.received_packets) +
                " discovers=" + std::to_string(metrics.discovers) +
                " requests=" + std::to_string(metrics.requests) +
                " offers=" + std::to_string(metrics.offers) +
                " acknowledgements=" +
                std::to_string(metrics.acknowledgements) +
                " rejected_packets=" +
                std::to_string(metrics.rejected_packets) +
                " send_failures=" +
                std::to_string(metrics.send_failures) +
                " explicit_source_sends=" +
                std::to_string(metrics.explicit_source_sends));
        if (metrics.send_failures > 0U && metrics.explicit_source_sends == 0U) {
            result.dhcp_runtime_failed = true;
            result.dhcp_native_error = metrics.last_send_error;
            result.dhcp_detail =
                "isolated_dhcp_reply_send_failed send_failures=" +
                std::to_string(metrics.send_failures) +
                " last_send_error=" + std::to_string(metrics.last_send_error);
        }
    }
    return result;
}

}  // namespace

HostCat6BootstrapResult bootstrap_host_cat6_link(
    std::chrono::milliseconds session_timeout,
    IsolatedDhcpServer* isolated_dhcp_server,
    std::stop_token stop_token) {
    struct PreferenceReset final {
        ~PreferenceReset() {
            set_host_direct_link_prefer_persistent_backend(false);
        }
    } preference_reset;

    // E-system evidence showed repeated WSAEADDRNOTAVAIL (10049) when the
    // first CAT6 attempt used the transient IP Helper address backend.  The
    // DHCP server must bind 10.57.23.1 as a stable local address before any
    // mobile wait begins, so the production bootstrap now starts directly with
    // the persistent netsh backend and relies on the existing snapshot restore
    // path for clean rollback.
    return bootstrap_host_cat6_link_once(
        session_timeout, isolated_dhcp_server, stop_token, true);
}

}  // namespace vfdual
