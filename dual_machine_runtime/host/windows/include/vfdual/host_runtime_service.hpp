#pragma once

#include "vfdual/dxgi_desktop_capture.hpp"
#include "vfdual/host_data_plane_authorization_gate.hpp"
#include "vfdual/isolated_dhcp_server.hpp"
#include "vfdual/wired_link_contract.hpp"

#include <atomic>
#include <cstdint>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>

namespace vfdual {

class HostRuntimeAuthorizationCoordinator;

void log_host_runtime_event(std::string_view event, std::string_view detail = {});

struct HostStreamSettings {
    std::string local_host{kWiredHostIpv4};
    std::string phone_host;
    std::string transport{kCat6TransportName};
    std::uint32_t adapter_index{};
    std::uint32_t output_index{};
    std::uint32_t width{};
    std::uint32_t height{};
    DesktopCaptureRegion capture_region{};
    std::string display_id;
    std::int32_t display_left{};
    std::int32_t display_top{};
    std::int32_t display_right{};
    std::int32_t display_bottom{};
    std::int32_t roi_left{};
    std::int32_t roi_top{};
    std::int32_t roi_right{};
    std::int32_t roi_bottom{};
    std::uint32_t source_width{};
    std::uint32_t source_height{};
    std::string fallback_reason{"none"};
    /** Geometry-only selection reason; never contains a window title or process name. */
    std::string display_selection_reason{"system_primary"};
    /** Codec timing hint and idle-repeat rate; fresh frames remain uncapped. */
    std::uint32_t encoder_timing_fps{};
    /** Runtime circuit breaker for the same-adapter asynchronous shared-texture path. */
    bool skip_async_shared_encoder{};
    /** Runtime circuit breaker set after a real NVENC encode failure. */
    bool skip_nvenc_encoder{};
    /** Runtime circuit breaker set after a real hardware-MFT encode failure. */
    bool force_software_encoder{};
};

struct HostStreamMetrics {
    /**
     * Starts at one and increments after each successful in-process runtime
     * recovery. Frame/source identifiers and non-offset cumulative counters
     * are scoped to this epoch; published_frames and capture_timeouts remain
     * continuous for the whole user-started stream.
     */
    std::uint64_t stream_epoch{1U};
    std::uint64_t source_sequence{};
    std::uint64_t frame_id{};
    std::uint64_t capture_us{};
    std::uint64_t readback_wait_us{};
    std::uint64_t readback_copy_us{};
    std::uint64_t bridge_us{};
    std::uint64_t upload_us{};
    std::uint64_t encode_us{};
    std::uint64_t publish_us{};
    std::uint64_t capture_to_publish_us{};
    std::uint64_t access_unit_bytes{};
    std::uint32_t datagrams{};
    bool keyframe{};
    std::int32_t status{};
    std::int32_t bridge_mode{};
    std::int32_t native_status{};
    std::int32_t encoder_backend{};
    std::int32_t capture_vendor{};
    std::int32_t encoder_vendor{};
    bool encoder_same_adapter{};
    bool zero_copy{};
    bool asynchronous_pipeline{};
    bool async_shared_same_adapter{};
    std::uint32_t encoder_timing_fps{};
    std::int32_t nvenc_stage{};
    std::int32_t media_foundation_stage{};
    std::uint64_t published_frames{};
    std::uint64_t capture_timeouts{};
    std::uint64_t pointer_only_skips{};
    std::uint64_t outside_region_skips{};
    std::uint64_t staging_busy_drops{};
    bool mouse_button_publisher_running{};
    bool mouse_button_transport_ready{};
    bool mouse_button_authenticated_session_ready{};
    std::uint8_t physical_button_mask{};
    std::uint64_t mouse_button_packets_sent{};
    std::uint64_t mouse_button_send_failures{};
    std::uint32_t mouse_button_socket_error{};
    /**
     * DXGI output-duplication presents not individually observed between
     * acquired snapshots. This is not a count of ROI video frames dropped by
     * the Host pipeline.
     */
    std::uint64_t missed_present_frames{};
    std::uint64_t static_content_repeats{};
    bool repeated_content{};
    std::uint64_t hybrid_was_still_drawing{};
    std::uint64_t hybrid_mailbox_superseded{};
    std::uint64_t hybrid_mailbox_replaced{};
    std::uint64_t hybrid_ring_busy{};
    std::uint64_t hybrid_keyed_timeout{};
    std::uint64_t hybrid_completion_metrics_dropped{};
    std::uint64_t worker_frame_age_us{};
    std::uint64_t hybrid_latest_worker_frame_age_us{};
    std::uint64_t hybrid_maximum_worker_frame_age_us{};
    std::uint32_t recovery_count{};
    /** Runtime-selected output identity; never contains a window title. */
    std::string display_id;
    /** Enum-like selection reason suitable for diagnostics. */
    std::string display_selection_reason;
    /** Runtime-selected data path: cat6 or wireless_lan_udp. */
    std::string transport{kCat6TransportName};
    std::string mobile_ipv4;
    bool mobile_reachable{};
    std::uint32_t mobile_probe_failures{};
    std::uint64_t mobile_last_success_age_ms{};
    double packet_loss_ratio{1.0};
    double jitter_ms{};
    double rtt_ms{};
    double throughput_mbps{};
};

inline constexpr char kHostStartupCancelledError[] = "Host startup cancelled.";

/**
 * In-process runtime service used by the Windows GUI. It owns only the host
 * capture, adaptive H.264 encoding, UDP video and physical-button publishing.
 */
class HostRuntimeService final {
public:
    explicit HostRuntimeService(
        IsolatedDhcpServer* isolated_dhcp_server = nullptr,
        std::shared_ptr<HostDataPlaneAuthorizationGate> authorization_gate = {});
    ~HostRuntimeService();
    HostRuntimeService(const HostRuntimeService&) = delete;
    HostRuntimeService& operator=(const HostRuntimeService&) = delete;

    [[nodiscard]] bool start(const HostStreamSettings& settings, std::string& error);
    void request_stop() noexcept;
    void stop() noexcept;
    /** Restores only a VisionForge-owned CAT6 snapshot after the GUI has stopped DHCP. */
    void restore_direct_link_on_clean_shutdown() noexcept;
    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] std::optional<HostStreamMetrics> last_metrics() const;
    [[nodiscard]] std::string last_error() const;

    void revoke_data_plane_authorization() noexcept;
    [[nodiscard]] HostDataPlaneAuthorizationGate::Snapshot
        authorization_snapshot() noexcept;

private:
    // Only the security composition root may install a peer or a lease. The UI
    // facade cannot manufacture a "verified" aggregate and open this gate.
    friend class HostRuntimeAuthorizationCoordinator;
    [[nodiscard]] bool install_confirmed_peer_binding(UsageLeaseBinding binding);
    [[nodiscard]] UsageLeaseAdmission submit_verified_usage_lease(
        const VerifiedUsageLease& lease,
        std::uint64_t trusted_now_epoch);

    // Stops capture/encoder/transport workers without ending the current
    // authorized usage session. Public stop() remains the explicit business
    // action that terminates that session.
    void stop_runtime() noexcept;
    void run(HostStreamSettings settings, std::stop_token startup_stop_token);

    mutable std::mutex mutex_;
    std::condition_variable start_condition_;
    std::thread worker_;
    std::optional<HostStreamMetrics> last_metrics_;
    std::string last_error_;
    bool running_{};
    bool start_finished_{};
    bool stop_requested_{};
    std::stop_source startup_stop_source_;
    IsolatedDhcpServer* isolated_dhcp_server_{};
    std::shared_ptr<HostDataPlaneAuthorizationGate> authorization_gate_;
};

}  // namespace vfdual
