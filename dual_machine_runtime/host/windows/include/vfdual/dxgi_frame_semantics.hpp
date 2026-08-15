#pragma once

#include <cstdint>
#include <span>

namespace vfdual {

struct DesktopChangeRect {
    std::int64_t left{};
    std::int64_t top{};
    std::int64_t right{};
    std::int64_t bottom{};
};

struct DesktopMoveChange {
    DesktopChangeRect source{};
    DesktopChangeRect destination{};
};

enum class DesktopMetadataState {
    unavailable,
    reliable,
};

enum class DesktopFrameSemantic {
    image_update,
    pointer_only,
    outside_region,
};

struct DesktopFrameSemanticInput {
    std::uint64_t last_present_qpc{};
    std::uint32_t accumulated_frames{};
    DesktopChangeRect capture_region{};
    DesktopMetadataState metadata_state{DesktopMetadataState::unavailable};
    std::span<const DesktopChangeRect> dirty_rects{};
    std::span<const DesktopMoveChange> move_rects{};
};

struct DesktopFrameSemanticDecision {
    DesktopFrameSemantic semantic{DesktopFrameSemantic::image_update};
    std::uint32_t missed_present_frames{};
};

[[nodiscard]] constexpr std::uint64_t static_frame_refresh_interval_us(
    std::uint32_t presentation_timing_fps) noexcept {
    if (presentation_timing_fps == 0U) return 0U;
    constexpr std::uint64_t microseconds_per_second = 1'000'000U;
    return (microseconds_per_second + presentation_timing_fps - 1U) /
        presentation_timing_fps;
}

[[nodiscard]] constexpr bool static_frame_refresh_due(
    std::uint64_t now_us, std::uint64_t last_submission_us,
    std::uint32_t presentation_timing_fps) noexcept {
    const std::uint64_t interval_us =
        static_frame_refresh_interval_us(presentation_timing_fps);
    return last_submission_us != 0U && interval_us != 0U &&
        now_us >= last_submission_us &&
        now_us - last_submission_us >= interval_us;
}

/**
 * A retained texture is semantically repeated only after that exact content
 * generation has been accepted by the outbound pipeline. If its first submit
 * was busy, the retry remains a real content update for the receiver.
 */
[[nodiscard]] constexpr bool retained_frame_repeats_submitted_content(
    bool retained_texture_reused, std::uint64_t content_sequence,
    std::uint64_t last_submitted_content_sequence) noexcept {
    return retained_texture_reused && content_sequence != 0U &&
        content_sequence == last_submitted_content_sequence;
}

/** A synthetic repeat cannot replace an unconsumed real observation. */
[[nodiscard]] constexpr bool repeated_frame_can_supersede_mailbox(
    bool pending_repeated_content, bool incoming_repeated_content) noexcept {
    return !incoming_repeated_content || pending_repeated_content;
}

/**
 * CPU-readback hybrid mode repeats the retained encoder texture on its worker.
 * Generating another repeat in the capture stage would consume a staging copy
 * and encoder slot without adding a new image. Synchronous and same-adapter
 * shared-texture paths still require capture-stage repeats.
 */
[[nodiscard]] constexpr bool capture_stage_owns_idle_repeat(
    bool hybrid_pipeline_active,
    bool async_shared_same_adapter) noexcept {
    return !hybrid_pipeline_active || async_shared_same_adapter;
}

/**
 * An explicitly requested recovery IDR is published as VFRG even when its
 * pixels came from the retained static texture. The Android resync gate admits
 * that current snapshot once. Later synthetic repeats keep the H.264 reference
 * chain alive but remain explicitly marked so Android excludes them from fresh
 * inference throughput and physical control. Physical trigger/output gates
 * remain independently required for real content updates.
 */
[[nodiscard]] constexpr bool wire_frame_repeats_content(
    bool captured_repeated_content, bool explicit_recovery_idr) noexcept {
    return captured_repeated_content && !explicit_recovery_idr;
}

/**
 * Bounds only the wait for an unchanged desktop. A real DXGI present returns
 * immediately, so this is not a producer FPS ceiling.
 */
[[nodiscard]] constexpr std::uint32_t static_frame_capture_wait_ms(
    std::uint64_t now_us, std::uint64_t last_submission_us,
    std::uint32_t presentation_timing_fps,
    std::uint32_t ordinary_timeout_ms) noexcept {
    const std::uint64_t interval_us =
        static_frame_refresh_interval_us(presentation_timing_fps);
    if (last_submission_us == 0U || interval_us == 0U ||
        now_us < last_submission_us) {
        return ordinary_timeout_ms;
    }
    const std::uint64_t elapsed_us = now_us - last_submission_us;
    if (elapsed_us >= interval_us) return 0U;
    const std::uint64_t remaining_us = interval_us - elapsed_us;
    const auto remaining_ms =
        static_cast<std::uint32_t>((remaining_us + 999U) / 1'000U);
    return remaining_ms < ordinary_timeout_ms
        ? remaining_ms
        : ordinary_timeout_ms;
}

[[nodiscard]] constexpr bool desktop_rects_intersect(
    const DesktopChangeRect& first, const DesktopChangeRect& second) noexcept {
    return first.left < second.right && first.right > second.left &&
           first.top < second.bottom && first.bottom > second.top;
}

[[nodiscard]] constexpr std::uint32_t missed_present_frame_count(
    std::uint64_t last_present_qpc, std::uint32_t accumulated_frames) noexcept {
    return last_present_qpc != 0 && accumulated_frames > 1 ? accumulated_frames - 1 : 0;
}

[[nodiscard]] inline DesktopFrameSemanticDecision decide_desktop_frame_semantic(
    const DesktopFrameSemanticInput& input) noexcept {
    DesktopFrameSemanticDecision decision{};
    if (input.last_present_qpc == 0) {
        decision.semantic = DesktopFrameSemantic::pointer_only;
        return decision;
    }

    decision.missed_present_frames =
        missed_present_frame_count(input.last_present_qpc, input.accumulated_frames);

    // Empty or unavailable metadata cannot prove that the capture region is unchanged.
    // Fail open so a real image update is never silently discarded.
    if (input.metadata_state != DesktopMetadataState::reliable ||
        (input.dirty_rects.empty() && input.move_rects.empty())) {
        return decision;
    }

    for (const DesktopChangeRect& dirty_rect : input.dirty_rects) {
        if (desktop_rects_intersect(dirty_rect, input.capture_region)) {
            return decision;
        }
    }
    for (const DesktopMoveChange& move : input.move_rects) {
        if (desktop_rects_intersect(move.source, input.capture_region) ||
            desktop_rects_intersect(move.destination, input.capture_region)) {
            return decision;
        }
    }

    decision.semantic = DesktopFrameSemantic::outside_region;
    return decision;
}

}  // namespace vfdual
