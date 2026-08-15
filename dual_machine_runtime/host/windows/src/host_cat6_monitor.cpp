#include "vfdual/host_cat6_monitor.hpp"

#include <chrono>
#include <limits>

namespace vfdual {

bool host_cat6_monitor_is_reachable(
    std::uint32_t consecutive_failures,
    std::chrono::milliseconds last_success_age) noexcept {
    return consecutive_failures < kHostCat6MonitorFailureThreshold &&
        last_success_age <= kHostCat6MonitorStaleAfter;
}

bool host_cat6_monitor_requires_recovery(
    std::uint32_t consecutive_failures,
    std::chrono::milliseconds last_success_age) noexcept {
    return consecutive_failures >= kHostCat6MonitorRecoveryFailureThreshold &&
        last_success_age > kHostCat6MonitorRecoveryAfter;
}

HostCat6Monitor::~HostCat6Monitor() { stop(); }

bool HostCat6Monitor::start(const Cat6SessionSnapshot& initial) noexcept {
    stop();
    {
        std::lock_guard lock(mutex_);
        latest_ = initial;
        last_success_at_ = std::chrono::steady_clock::now();
        consecutive_failures_ = 0U;
        monitor_faults_ = 0U;
    }
    stop_requested_ = false;
    try {
        worker_ = std::thread([this]() noexcept { run(); });
    } catch (...) {
        stop_requested_ = true;
        std::lock_guard lock(mutex_);
        monitor_faults_ = 1U;
        return false;
    }
    return true;
}

void HostCat6Monitor::stop() noexcept {
    stop_requested_ = true;
    try {
        if (worker_.joinable()) worker_.join();
    } catch (...) {
    }
}

HostCat6MonitorSnapshot HostCat6Monitor::snapshot() const {
    std::lock_guard lock(mutex_);
    HostCat6MonitorSnapshot value{};
    value.latest_session = latest_;
    value.consecutive_failures = consecutive_failures_;
    value.monitor_faults = monitor_faults_;
    const auto now = std::chrono::steady_clock::now();
    value.last_success_age_ms = latest_.has_value()
        ? static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
              now - last_success_at_).count())
        : std::numeric_limits<std::uint64_t>::max();
    value.reachable = latest_.has_value() && host_cat6_monitor_is_reachable(
        value.consecutive_failures,
        std::chrono::milliseconds{value.last_success_age_ms ==
                std::numeric_limits<std::uint64_t>::max()
            ? std::numeric_limits<std::int64_t>::max()
            : static_cast<std::int64_t>(value.last_success_age_ms)});
    value.recovery_required = !latest_.has_value() ||
        host_cat6_monitor_requires_recovery(
            value.consecutive_failures,
            std::chrono::milliseconds{value.last_success_age_ms ==
                    std::numeric_limits<std::uint64_t>::max()
                ? std::numeric_limits<std::int64_t>::max()
                : static_cast<std::int64_t>(value.last_success_age_ms)});
    return value;
}

void HostCat6Monitor::run() noexcept {
    constexpr auto kMeasurementWindow = std::chrono::milliseconds(1000);
    while (!stop_requested_) {
        try {
            std::optional<Cat6SessionSnapshot> endpoint;
            {
                std::lock_guard lock(mutex_);
                endpoint = latest_;
            }
            const auto measured = endpoint.has_value()
                ? measure_mobile_session(*endpoint, kMeasurementWindow)
                : std::nullopt;
            {
                std::lock_guard lock(mutex_);
                if (measured) {
                    latest_ = measured;
                    last_success_at_ = std::chrono::steady_clock::now();
                    consecutive_failures_ = 0U;
                } else if (consecutive_failures_ !=
                           std::numeric_limits<std::uint32_t>::max()) {
                    ++consecutive_failures_;
                }
            }
        } catch (...) {
            std::lock_guard lock(mutex_);
            if (monitor_faults_ != std::numeric_limits<std::uint64_t>::max()) {
                ++monitor_faults_;
            }
            if (consecutive_failures_ != std::numeric_limits<std::uint32_t>::max()) {
                ++consecutive_failures_;
            }
        }
        for (int interval = 0; interval < 10 && !stop_requested_; ++interval) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
}

}  // namespace vfdual
