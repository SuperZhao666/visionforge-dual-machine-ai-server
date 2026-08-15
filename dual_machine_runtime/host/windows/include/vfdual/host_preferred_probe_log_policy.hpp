#pragma once

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace vfdual {

inline constexpr auto kHostPreferredProbeLogHeartbeat =
    std::chrono::minutes{5};

struct HostPreferredProbeFailureState final {
    std::string failure_stage;
    std::string failure_status;
    std::string failure_reason;

    bool operator==(const HostPreferredProbeFailureState&) const = default;
};

/**
 * Keeps full preferred-link diagnostics useful without writing the same
 * multi-kilobyte adapter inventory after every five-second probe.
 */
class HostPreferredProbeLogPolicy final {
public:
    explicit HostPreferredProbeLogPolicy(
        std::chrono::milliseconds heartbeat =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                kHostPreferredProbeLogHeartbeat)) noexcept
        : heartbeat_((std::max)(std::chrono::milliseconds{1}, heartbeat)) {}

    [[nodiscard]] bool should_log_failure(
        HostPreferredProbeFailureState state,
        std::chrono::steady_clock::time_point now) {
        const bool state_changed = !last_failure_.has_value() ||
            *last_failure_ != state;
        const bool heartbeat_due = last_logged_at_.has_value() &&
            (now < *last_logged_at_ || now - *last_logged_at_ >= heartbeat_);
        if (!state_changed && !heartbeat_due) return false;

        last_failure_ = std::move(state);
        last_logged_at_ = now;
        return true;
    }

    void reset() noexcept {
        last_failure_.reset();
        last_logged_at_.reset();
    }

private:
    std::chrono::milliseconds heartbeat_;
    std::optional<HostPreferredProbeFailureState> last_failure_;
    std::optional<std::chrono::steady_clock::time_point> last_logged_at_;
};

/** Removes volatile adapter inventory while preserving the actionable reason. */
[[nodiscard]] inline std::string host_preferred_probe_root_reason(
    std::string_view detail) {
    constexpr std::string_view kInventoryMarker = " inventory_count=";
    const std::size_t inventory = detail.find(kInventoryMarker);
    return std::string{detail.substr(0, inventory)};
}

}  // namespace vfdual
