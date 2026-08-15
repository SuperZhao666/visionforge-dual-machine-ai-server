#pragma once

#include "vfdual/model_contract.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace vfdual {

struct HostDisplayOutput {
    std::uint32_t adapter_index{};
    std::uint32_t output_index{};
    std::wstring device_name;
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t refresh_hz{};
    bool is_system_primary{};
    std::int32_t desktop_left{};
    std::int32_t desktop_top{};
    std::int32_t desktop_right{};
    std::int32_t desktop_bottom{};
};

struct HostDesktopRect {
    std::int32_t left{};
    std::int32_t top{};
    std::int32_t right{};
    std::int32_t bottom{};
};

struct HostDisplayWindowCandidate {
    HostDesktopRect window_rect{};
    HostDesktopRect client_rect{};
    std::uint32_t z_order{};
    bool has_client_rect{};
    bool is_visible{};
    bool is_minimized{};
    bool is_cloaked{};
    bool is_tool_window{};
    bool belongs_to_host_process{};
    bool belongs_to_shell_process{};
    bool is_borderless{};
};

enum class HostDisplaySelectionReason {
    external_window_fullscreen,
    external_window_borderless,
    system_primary,
    first_attached_output,
    no_attached_output,
};

struct HostDisplaySelectionScore {
    std::uint32_t candidate_z_order{};
    std::uint32_t output_coverage_per_mille{};
    std::uint32_t window_coverage_per_mille{};
    bool is_fullscreen{};
    bool is_borderless{};
};

struct HostDisplaySelection {
    const HostDisplayOutput* output{};
    HostDisplaySelectionReason reason{HostDisplaySelectionReason::no_attached_output};
    HostDisplaySelectionScore score{};
};

enum class HostCaptureFallbackReason {
    none,
    source_smaller_than_encoder,
    invalid_display_extent,
};

struct HostCaptureGeometry {
    HostDesktopRect display_rect{};
    HostDesktopRect roi_rect{};
    std::uint32_t source_width{};
    std::uint32_t source_height{};
    std::uint32_t local_roi_x{};
    std::uint32_t local_roi_y{};
    std::uint32_t local_roi_width{};
    std::uint32_t local_roi_height{};
    std::uint32_t encoder_width{};
    std::uint32_t encoder_height{};
    HostCaptureFallbackReason fallback_reason{HostCaptureFallbackReason::invalid_display_extent};
};

static_assert(
    kDefaultMobileModel.input.width == kDefaultMobileModel.input.height,
    "The centered host ROI requires a square model input.");
inline constexpr std::uint32_t kAiCaptureEdge = kDefaultMobileModel.input.width;

/** Enumerates the exact DXGI adapter/output pairs accepted by the capture core. */
[[nodiscard]] std::vector<HostDisplayOutput> enumerate_host_display_outputs();

/**
 * Enumerates visible external top-level windows without reading titles or
 * matching process names. Host-process, Windows-shell, minimized, cloaked and
 * tool windows remain represented as flags so the pure policy owns filtering.
 */
[[nodiscard]] std::vector<HostDisplayWindowCandidate> enumerate_host_display_window_candidates();

/**
 * Selects the output mostly covered by the topmost full-screen or large
 * borderless external window. The deterministic score is ordered by
 * full-screen class, Z order, output coverage, window coverage, borderless
 * style and stable output identity. It falls back explicitly to system primary.
 */
[[nodiscard]] HostDisplaySelection select_host_display_output(
    const std::vector<HostDisplayOutput>& outputs,
    const std::vector<HostDisplayWindowCandidate>& candidates) noexcept;

/** Returns the system primary display, falling back only when Windows has no primary match. */
[[nodiscard]] const HostDisplayOutput* select_preferred_display_output(
    const std::vector<HostDisplayOutput>& outputs) noexcept;

/** Retains a requested output when present, then falls back to the Windows primary display. */
[[nodiscard]] const HostDisplayOutput* select_matching_or_preferred_display_output(
    const std::vector<HostDisplayOutput>& outputs, std::string_view device_id) noexcept;

/** Computes the output-local crop and virtual-desktop coordinates for the AI ROI. */
[[nodiscard]] HostCaptureGeometry choose_centered_ai_capture_geometry(
    const HostDisplayOutput& output) noexcept;

[[nodiscard]] const char* host_capture_fallback_reason_name(
    HostCaptureFallbackReason reason) noexcept;

[[nodiscard]] const char* host_display_selection_reason_name(
    HostDisplaySelectionReason reason) noexcept;

}  // namespace vfdual
