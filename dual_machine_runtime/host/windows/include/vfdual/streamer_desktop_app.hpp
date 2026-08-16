#pragma once

#include "vfdual/host/application/host_endpoint_discovery_facade.hpp"
#include "vfdual/host/application/host_runtime_facade.hpp"
#include "vfdual/isolated_dhcp_server.hpp"
#include "vfdual/host_display_catalog.hpp"
#include "vfdual/host_idle_ui_state.hpp"
#include "vfdual/host_ui_phase.hpp"
#include "vfdual/host_ui_telemetry.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <stop_token>
#include <thread>
#include <vector>

namespace vfdual {

/** Native Windows presentation layer for the independent streamer process. */
class StreamerDesktopApp final {
public:
    ~StreamerDesktopApp() noexcept;

    int run(HINSTANCE instance, bool acceptance_autostart = false);

private:
    enum class FontRole {
        small,
        caption,
        regular,
        section,
        title,
        hero,
        metric,
    };

    enum class SurfaceRole {
        window,
        panel,
        transparent,
        row,
        summary,
    };

    enum class TextRole {
        primary,
        muted,
        positive,
        capture,
        encode,
        publish,
        link,
    };

    enum class IconRole : std::size_t {
        app,
        display,
        encoder,
        phone,
        link,
        capture,
        video,
        send,
        network,
        pulse,
        router,
        play,
        settings,
        chevron,
        check,
        trash,
        lock,
        count,
    };

    enum class MobileRefreshState : std::uint8_t {
        idle = 0,
        running = 1,
    };

    struct MetricControls final {
        HWND current{};
        HWND p50{};
        HWND p95{};
    };

    struct ControlPlacement final {
        HWND handle{};
        RECT logical_bounds{};
        FontRole font_role{FontRole::regular};
        SurfaceRole surface_role{SurfaceRole::window};
        TextRole text_role{TextRole::primary};
    };

    static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM w_param, LPARAM l_param);
    LRESULT handle_message(HWND window, UINT message, WPARAM w_param, LPARAM l_param);
    void create_controls(HWND window);
    HWND add_static(HWND parent, const wchar_t* text, RECT logical_bounds, FontRole font_role,
                    SurfaceRole surface_role = SurfaceRole::window,
                    TextRole text_role = TextRole::primary,
                    DWORD static_style = SS_LEFT);
    HWND add_button(HWND parent, const wchar_t* text, int id, RECT logical_bounds);
    MetricControls add_metric_row(HWND window, int logical_y, const wchar_t* title,
                                  const wchar_t* detail, TextRole accent);
    void load_ui_icons();
    void release_ui_icons() noexcept;
    void layout_controls();
    void recreate_fonts(double scale);
    RECT transform_rect(RECT logical_bounds) const noexcept;
    void start_streamer(HWND window);
    void stop_streamer();
    void refresh_status();
    void set_status(const std::wstring& text);
    void set_ui_phase(HostUiPhase phase);
    void update_action_state(bool running, bool starting);
    void append_event(const std::wstring& event);
    void update_event_text();
    void open_diagnostics() const;
    void initialize_display_selection();
    void set_settings_panel_visible(bool visible);
    void refresh_display_selection();
    void refresh_mobile_device();
    bool reap_completed_mobile_refresh_thread(const char* context) noexcept;
    bool repair_stale_startup_state(const char* context) noexcept;
    bool mobile_refresh_running() const noexcept;
    void mark_mobile_refresh_idle() noexcept;
    void cancel_mobile_refresh_probe() noexcept;
    void apply_idle_ui_state(HostIdleEndpointState endpoint_state);
    void clear_runtime_metrics();
    void shutdown_background_runtime() noexcept;

    HWND window_{};
    HWND start_button_{};
    HWND stop_button_{};
    HWND settings_button_{};
    HWND diagnostics_button_{};
    HWND clear_events_button_{};
    HWND ready_state_text_{};
    HWND ready_detail_text_{};
    HWND mobile_state_text_{};
    HWND display_state_text_{};
    HWND encoder_state_text_{};
    HWND phone_state_text_{};
    HWND link_state_text_{};
    MetricControls capture_metric_{};
    MetricControls encode_metric_{};
    MetricControls publish_metric_{};
    MetricControls link_metric_{};
    HWND output_rate_value_{};
    HWND output_rate_p95_value_{};
    HWND bandwidth_text_{};
    HWND topology_host_state_text_{};
    HWND topology_link_state_text_{};
    HWND topology_mobile_state_text_{};
    HWND route_capture_latency_text_{};
    HWND route_network_latency_text_{};
    HWND events_title_text_{};
    HWND events_text_{};
    HWND status_text_{};
    HWND settings_title_text_{};
    HWND settings_description_text_{};
    HWND settings_contract_text_{};
    HWND refresh_displays_button_{};
    HWND refresh_mobile_button_{};
    HWND close_settings_button_{};
    HFONT small_font_{};
    HFONT regular_font_{};
    HFONT title_font_{};
    HFONT caption_font_{};
    HFONT section_font_{};
    HFONT hero_font_{};
    HFONT metric_font_{};
    HBRUSH background_brush_{};
    HBRUSH panel_background_brush_{};
    HBRUSH row_background_brush_{};
    HBRUSH summary_background_brush_{};
    std::array<HICON, static_cast<std::size_t>(IconRole::count)> icons_{};
    std::vector<ControlPlacement> control_placements_;
    std::vector<HWND> event_panel_controls_;
    std::vector<HWND> settings_panel_controls_;
    double layout_scale_{1.0};
    int layout_offset_x_{};
    int layout_offset_y_{};
    IsolatedDhcpServer isolated_dhcp_server_{};
    host::application::HostEndpointDiscoveryFacade endpoint_discovery_{&isolated_dhcp_server_};
    host::application::HostRuntimeFacade runtime_facade_{&isolated_dhcp_server_};
    HostUiTelemetry ui_telemetry_{};
    std::vector<HostDisplayOutput> display_outputs_;
    std::deque<std::wstring> recent_events_;
    std::thread startup_thread_;
    std::thread mobile_refresh_thread_;
    std::stop_source mobile_refresh_stop_source_;
    std::atomic_bool mobile_refresh_finished_{true};
    std::uint64_t startup_generation_{};
    std::uint64_t mobile_refresh_generation_{};
    std::uint64_t last_event_frame_{};
    std::uint32_t last_recovery_count_{};
    std::chrono::steady_clock::time_point retry_not_before_{};
    std::string last_mobile_ipv4_;
    std::string last_transport_;
    std::string last_runtime_display_id_;
    bool starting_{};
    bool was_running_{};
    bool mobile_reachable_{};
    bool acceptance_autostart_{};
    bool background_shutdown_done_{};
    HostUiPhase ui_phase_{HostUiPhase::idle};
    bool settings_panel_visible_{};
    MobileRefreshState mobile_refresh_state_{MobileRefreshState::idle};
    bool start_after_mobile_refresh_cancel_{};
};

}  // namespace vfdual
