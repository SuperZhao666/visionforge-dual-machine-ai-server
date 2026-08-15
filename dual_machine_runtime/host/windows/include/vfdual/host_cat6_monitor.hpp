#pragma once

#include "vfdual/host_cat6_session.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <thread>

namespace vfdual {

inline constexpr std::uint32_t kHostCat6MonitorFailureThreshold = 3U;
inline constexpr auto kHostCat6MonitorStaleAfter = std::chrono::seconds(4);
inline constexpr std::uint32_t kHostCat6MonitorRecoveryFailureThreshold = 5U;
inline constexpr auto kHostCat6MonitorRecoveryAfter = std::chrono::seconds(10);

struct HostCat6MonitorSnapshot final {
    std::optional<Cat6SessionSnapshot> latest_session;
    bool reachable{};
    bool recovery_required{};
    std::uint32_t consecutive_failures{};
    std::uint64_t last_success_age_ms{};
    std::uint64_t monitor_faults{};
};

[[nodiscard]] bool host_cat6_monitor_is_reachable(
    std::uint32_t consecutive_failures,
    std::chrono::milliseconds last_success_age) noexcept;

[[nodiscard]] bool host_cat6_monitor_requires_recovery(
    std::uint32_t consecutive_failures,
    std::chrono::milliseconds last_success_age) noexcept;

/** Refreshes the selected CAT6 or wireless-LAN session outside the video hot path. */
class HostCat6Monitor final {
public:
    HostCat6Monitor() = default;
    ~HostCat6Monitor();
    HostCat6Monitor(const HostCat6Monitor&) = delete;
    HostCat6Monitor& operator=(const HostCat6Monitor&) = delete;

    [[nodiscard]] bool start(const Cat6SessionSnapshot& initial) noexcept;
    void stop() noexcept;
    [[nodiscard]] HostCat6MonitorSnapshot snapshot() const;

private:
    void run() noexcept;

    mutable std::mutex mutex_;
    std::thread worker_;
    std::optional<Cat6SessionSnapshot> latest_;
    std::chrono::steady_clock::time_point last_success_at_{};
    std::uint32_t consecutive_failures_{};
    std::uint64_t monitor_faults_{};
    std::atomic_bool stop_requested_{false};
};

}  // namespace vfdual
