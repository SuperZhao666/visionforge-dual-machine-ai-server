#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>

namespace vfdual {

enum class HostRecoveryCause {
    none,
    cat6_link,
    video_pipeline,
    preferred_transport_upgrade,
};

enum class HostVideoFailureKind {
    none,
    bridge_failed,
    encode_failed,
};

enum class HostEncoderRuntimePath {
    other,
    nvenc_same_adapter_async_shared,
    nvenc_capture_device,
    nvenc_cross_adapter,
    windows_hardware,
};

enum class HostEncoderFailoverAction {
    none,
    skip_async_shared,
    skip_nvenc,
    force_software,
};

struct HostEncoderCircuitBreakers final {
    bool skip_async_shared{};
    bool skip_nvenc{};
    bool force_software{};
};

struct HostEncoderFailoverDecision final {
    HostEncoderFailoverAction action{HostEncoderFailoverAction::none};
    HostEncoderCircuitBreakers breakers{};
};

/**
 * Per-user-start encoder circuit breaker. It is deliberately not persisted:
 * a new Host process/run gets a fresh policy, while an in-process recovery
 * cannot select a cross-adapter NVENC path that already failed its bridge.
 */
class HostEncoderRecoveryPolicy final {
public:
    explicit constexpr HostEncoderRecoveryPolicy(
        HostEncoderCircuitBreakers initial = {}) noexcept
        : breakers_(initial) {}

    [[nodiscard]] constexpr HostEncoderFailoverDecision record_failure(
        HostRecoveryCause recovery_cause,
        HostVideoFailureKind failure,
        HostEncoderRuntimePath encoder_path) noexcept {
        HostEncoderFailoverAction action = HostEncoderFailoverAction::none;
        if (recovery_cause == HostRecoveryCause::video_pipeline &&
            failure == HostVideoFailureKind::bridge_failed &&
            encoder_path ==
                HostEncoderRuntimePath::nvenc_same_adapter_async_shared &&
            !breakers_.skip_async_shared) {
            breakers_.skip_async_shared = true;
            action = HostEncoderFailoverAction::skip_async_shared;
        } else if (recovery_cause == HostRecoveryCause::video_pipeline &&
            failure == HostVideoFailureKind::bridge_failed &&
            encoder_path == HostEncoderRuntimePath::nvenc_cross_adapter &&
            !breakers_.skip_nvenc) {
            breakers_.skip_nvenc = true;
            action = HostEncoderFailoverAction::skip_nvenc;
        } else if (recovery_cause == HostRecoveryCause::video_pipeline &&
                   failure == HostVideoFailureKind::encode_failed) {
            const bool nvenc_path =
                encoder_path ==
                    HostEncoderRuntimePath::nvenc_same_adapter_async_shared ||
                encoder_path == HostEncoderRuntimePath::nvenc_capture_device ||
                encoder_path == HostEncoderRuntimePath::nvenc_cross_adapter;
            if (nvenc_path && !breakers_.skip_nvenc) {
                breakers_.skip_nvenc = true;
                action = HostEncoderFailoverAction::skip_nvenc;
            } else if (encoder_path == HostEncoderRuntimePath::windows_hardware &&
                       !breakers_.force_software) {
                breakers_.force_software = true;
                action = HostEncoderFailoverAction::force_software;
            }
        }
        return HostEncoderFailoverDecision{action, breakers_};
    }

    [[nodiscard]] constexpr HostEncoderCircuitBreakers breakers() const noexcept {
        return breakers_;
    }

private:
    HostEncoderCircuitBreakers breakers_{};
};

/**
 * CAT6 hard-recovery state takes precedence over a simultaneous
 * capture/encoder failure. Soft heartbeat degradation is diagnostic only and
 * must never tear down an otherwise usable point-to-point link.
 */
[[nodiscard]] constexpr HostRecoveryCause choose_host_recovery_cause(
    bool cat6_recovery_required, bool video_step_succeeded) noexcept {
    if (cat6_recovery_required) return HostRecoveryCause::cat6_link;
    return video_step_succeeded
        ? HostRecoveryCause::none : HostRecoveryCause::video_pipeline;
}

[[nodiscard]] constexpr HostRecoveryCause choose_host_recovery_cause(
    bool preferred_transport_upgrade_ready,
    bool cat6_recovery_required,
    bool video_step_succeeded) noexcept {
    if (preferred_transport_upgrade_ready) {
        return HostRecoveryCause::preferred_transport_upgrade;
    }
    return choose_host_recovery_cause(
        cat6_recovery_required, video_step_succeeded);
}

[[nodiscard]] constexpr bool should_start_preferred_cat6_probe(
    bool active_transport_is_cat6,
    bool probe_in_flight,
    bool upgrade_ready,
    bool retry_due) noexcept {
    return !active_transport_is_cat6 && !probe_in_flight &&
        !upgrade_ready && retry_due;
}

[[nodiscard]] constexpr bool should_commit_preferred_cat6_upgrade(
    bool active_transport_is_cat6,
    bool cat6_session_ready) noexcept {
    return !active_transport_is_cat6 && cat6_session_ready;
}

enum class HostVideoForwardProgressFailure {
    none,
    publish_stalled,
    fresh_frame_stale,
};

struct HostVideoForwardProgressPolicyConfig final {
    std::chrono::microseconds maximum_publish_silence{
        std::chrono::milliseconds{1500}};
    std::chrono::microseconds maximum_fresh_frame_age{
        std::chrono::milliseconds{1500}};
};

struct HostVideoForwardProgressSample final {
    std::uint64_t monotonic_time_us{};
    std::uint64_t published_frames{};
    bool publication_expected{true};
    bool fresh_frame_published{};
    std::uint64_t capture_to_publish_us{};
};

struct HostVideoForwardProgressDecision final {
    HostVideoForwardProgressFailure failure{
        HostVideoForwardProgressFailure::none};
    std::uint64_t no_publish_progress_us{};
    std::uint64_t capture_to_publish_us{};

    [[nodiscard]] constexpr bool recovery_required() const noexcept {
        return failure != HostVideoForwardProgressFailure::none;
    }
};

/**
 * Detects a live video pipeline that still returns "healthy" statuses but no
 * longer advances UDP publication. Published synthetic repeats count as real
 * transport progress, while their intentionally old pixels never trip the
 * fresh-frame age guard. This policy observes the pipeline only; it neither
 * schedules frames nor limits their rate.
 */
class HostVideoForwardProgressPolicy final {
public:
    explicit HostVideoForwardProgressPolicy(
        HostVideoForwardProgressPolicyConfig config = {}) noexcept
        : config_(normalize(config)) {}

    [[nodiscard]] HostVideoForwardProgressDecision observe(
        const HostVideoForwardProgressSample& sample) noexcept {
        if (!sample.publication_expected) {
            initialized_ = true;
            last_progress_time_us_ = sample.monotonic_time_us;
            last_published_frames_ = sample.published_frames;
            return {};
        }
        if (!initialized_ || sample.monotonic_time_us < last_progress_time_us_ ||
            sample.published_frames < last_published_frames_) {
            initialized_ = true;
            last_progress_time_us_ = sample.monotonic_time_us;
            last_published_frames_ = sample.published_frames;
        } else if (sample.published_frames > last_published_frames_) {
            last_progress_time_us_ = sample.monotonic_time_us;
            last_published_frames_ = sample.published_frames;
        }

        const std::uint64_t no_publish_progress_us =
            sample.monotonic_time_us - last_progress_time_us_;
        if (sample.fresh_frame_published &&
            sample.capture_to_publish_us >=
                static_cast<std::uint64_t>(
                    config_.maximum_fresh_frame_age.count())) {
            return HostVideoForwardProgressDecision{
                HostVideoForwardProgressFailure::fresh_frame_stale,
                no_publish_progress_us,
                sample.capture_to_publish_us,
            };
        }
        if (no_publish_progress_us >=
            static_cast<std::uint64_t>(
                config_.maximum_publish_silence.count())) {
            return HostVideoForwardProgressDecision{
                HostVideoForwardProgressFailure::publish_stalled,
                no_publish_progress_us,
                sample.capture_to_publish_us,
            };
        }
        return HostVideoForwardProgressDecision{
            HostVideoForwardProgressFailure::none,
            no_publish_progress_us,
            sample.capture_to_publish_us,
        };
    }

    void reset() noexcept {
        initialized_ = false;
        last_progress_time_us_ = 0U;
        last_published_frames_ = 0U;
    }

private:
    [[nodiscard]] static HostVideoForwardProgressPolicyConfig normalize(
        HostVideoForwardProgressPolicyConfig config) noexcept {
        config.maximum_publish_silence = (std::max)(
            std::chrono::microseconds{1}, config.maximum_publish_silence);
        config.maximum_fresh_frame_age = (std::max)(
            std::chrono::microseconds{1}, config.maximum_fresh_frame_age);
        return config;
    }

    HostVideoForwardProgressPolicyConfig config_{};
    std::uint64_t last_progress_time_us_{};
    std::uint64_t last_published_frames_{};
    bool initialized_{};
};

/**
 * Recovery timing is deliberately independent from the capture frame rate.
 * A transient DXGI, encoder, display-hotplug or UDP failure must not turn into
 * a permanent process exit merely because several failures occur in a burst.
 */
struct HostRecoveryPolicyConfig final {
    std::uint32_t stable_frames_to_reset{300U};
    std::chrono::milliseconds initial_backoff{200};
    std::chrono::milliseconds maximum_backoff{5000};
};

struct HostRecoveryDecision final {
    std::uint32_t consecutive_failures{};
    std::uint64_t total_failures{};
    std::chrono::milliseconds retry_delay{};
    bool backoff_capped{};
};

class HostRecoveryPolicy final {
public:
    explicit HostRecoveryPolicy(HostRecoveryPolicyConfig config = {}) noexcept
        : config_(normalize(config)) {}

    [[nodiscard]] HostRecoveryDecision record_failure() noexcept {
        stable_published_frames_ = 0U;
        if (consecutive_failures_ != (std::numeric_limits<std::uint32_t>::max)()) {
            ++consecutive_failures_;
        }
        if (total_failures_ != (std::numeric_limits<std::uint64_t>::max)()) {
            ++total_failures_;
        }
        const auto delay = calculate_delay(consecutive_failures_);
        return HostRecoveryDecision{
            consecutive_failures_,
            total_failures_,
            delay,
            delay >= config_.maximum_backoff,
        };
    }

    /**
     * Returns true only when a prior failure streak has been cleared by a
     * sustained run of genuinely published frames.
     */
    [[nodiscard]] bool record_published_frame() noexcept {
        if (consecutive_failures_ == 0U) return false;
        if (stable_published_frames_ != (std::numeric_limits<std::uint32_t>::max)()) {
            ++stable_published_frames_;
        }
        if (stable_published_frames_ < config_.stable_frames_to_reset) return false;
        consecutive_failures_ = 0U;
        stable_published_frames_ = 0U;
        return true;
    }

    [[nodiscard]] std::uint32_t consecutive_failures() const noexcept {
        return consecutive_failures_;
    }

    [[nodiscard]] std::uint64_t total_failures() const noexcept {
        return total_failures_;
    }

    [[nodiscard]] std::uint32_t stable_published_frames() const noexcept {
        return stable_published_frames_;
    }

    [[nodiscard]] std::uint32_t stable_frames_to_reset() const noexcept {
        return config_.stable_frames_to_reset;
    }

private:
    static HostRecoveryPolicyConfig normalize(HostRecoveryPolicyConfig config) noexcept {
        config.stable_frames_to_reset = (std::max)(1U, config.stable_frames_to_reset);
        config.initial_backoff = (std::max)(std::chrono::milliseconds(1), config.initial_backoff);
        config.maximum_backoff = (std::max)(config.initial_backoff, config.maximum_backoff);
        return config;
    }

    [[nodiscard]] std::chrono::milliseconds calculate_delay(
        std::uint32_t consecutive_failures) const noexcept {
        auto delay = config_.initial_backoff;
        for (std::uint32_t failure = 1U;
             failure < consecutive_failures && delay < config_.maximum_backoff;
             ++failure) {
            const auto remaining = config_.maximum_backoff - delay;
            delay += (std::min)(delay, remaining);
        }
        return (std::min)(delay, config_.maximum_backoff);
    }

    HostRecoveryPolicyConfig config_;
    std::uint32_t consecutive_failures_{};
    std::uint64_t total_failures_{};
    std::uint32_t stable_published_frames_{};
};

}  // namespace vfdual
