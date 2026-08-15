#include "vfdual/host_cat6_bootstrap.hpp"

#include <algorithm>
#include <chrono>

namespace vfdual {

std::optional<Cat6SessionSnapshot> wait_for_host_cat6_mobile(
    std::chrono::milliseconds session_timeout,
    std::stop_token stop_token,
    HostCat6SessionMeasurer measure_session,
    HostCat6WaitMaintenance maintenance) {
    if (session_timeout <= std::chrono::milliseconds::zero() ||
        stop_token.stop_requested() || measure_session == nullptr) {
        return std::nullopt;
    }

    constexpr auto kCancellationSlice = std::chrono::milliseconds(50);
    constexpr auto kMaintenanceInterval = std::chrono::seconds(1);
    const auto deadline = std::chrono::steady_clock::now() + session_timeout;
    auto next_maintenance = std::chrono::steady_clock::now();
    while (!stop_token.stop_requested() && std::chrono::steady_clock::now() < deadline) {
        const auto now = std::chrono::steady_clock::now();
        if (maintenance && now >= next_maintenance) {
            if (!maintenance()) return std::nullopt;
            next_maintenance = now + kMaintenanceInterval;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining <= std::chrono::milliseconds::zero()) break;
        if (auto mobile = measure_session((std::min)(kCancellationSlice, remaining))) {
            return mobile;
        }
    }
    return std::nullopt;
}

}  // namespace vfdual
