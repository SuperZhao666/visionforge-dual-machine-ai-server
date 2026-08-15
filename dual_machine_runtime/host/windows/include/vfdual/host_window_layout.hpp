#pragma once

namespace vfdual {

inline constexpr int kHostLogicalClientWidth = 1240;
inline constexpr int kHostLogicalClientHeight = 860;
inline constexpr double kHostMinimumReadableScale = 0.72;
inline constexpr double kHostMaximumLayoutScale = 2.5;

struct HostLogicalRect final {
    int x{};
    int y{};
    int width{};
    int height{};
};

// Reference-derived geometry for the few dense regions where independent
// child controls and parent-drawn artwork must never overlap.
inline constexpr HostLogicalRect kHostHeaderStatusDot{564, 22, 10, 10};
inline constexpr HostLogicalRect kHostHeaderStatusText{580, 15, 300, 24};
inline constexpr HostLogicalRect kHostSummaryOutputLabel{738, 490, 120, 20};
inline constexpr HostLogicalRect kHostSummaryOutputValue{738, 510, 120, 24};
inline constexpr HostLogicalRect kHostSummaryProbeValue{870, 512, 120, 22};
inline constexpr HostLogicalRect kHostSummaryP95Label{1002, 490, 160, 20};
inline constexpr HostLogicalRect kHostSummaryP95Value{1002, 510, 160, 24};

struct HostClientSize final {
    int width{};
    int height{};
};

struct HostWindowLayout final {
    double scale{};
    int offset_x{};
    int offset_y{};
};

/** Minimum client area that preserves the normal 0.72 readable layout scale. */
HostClientSize host_minimum_readable_client_size() noexcept;

/**
 * Chooses a centered layout that always fits the realized client area.
 * WM_GETMINMAXINFO normally keeps this at or above the readable minimum; the
 * smaller-client path protects startup, snapping, and transient DPI changes.
 */
HostWindowLayout host_window_layout_for_client(int client_width, int client_height) noexcept;

/** Chooses an initial client size for the current DPI within the available area. */
HostClientSize host_initial_client_size(
    int maximum_client_width, int maximum_client_height, unsigned int dpi) noexcept;

}  // namespace vfdual
