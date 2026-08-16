#pragma once

#include "vfdual/host_outbound_rate_tracker.hpp"
#include "vfdual/host/application/host_runtime_models.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>

namespace vfdual {

struct HostUiMetricTriple final {
    double current{};
    double p50{};
    double p95{};
};

struct HostUiTelemetrySnapshot final {
    std::optional<HostUiMetricTriple> capture_ms;
    std::optional<HostUiMetricTriple> encode_ms;
    std::optional<HostUiMetricTriple> publish_ms;
    std::optional<HostUiMetricTriple> total_ms;
    std::optional<HostUiMetricTriple> link_rtt_ms;
    std::optional<HostUiMetricTriple> output_fps;
};

/** Rolling presentation metrics derived only from completed host frames. */
class HostUiTelemetry final {
public:
    explicit HostUiTelemetry(std::size_t capacity = 180U);

    void reset() noexcept;
    [[nodiscard]] HostUiTelemetrySnapshot observe(const host::application::HostRuntimeReadModel& metrics,
                                                  std::uint64_t monotonic_ms);
    [[nodiscard]] HostUiTelemetrySnapshot snapshot() const;

private:
    void append(std::deque<double>& samples, double value);
    [[nodiscard]] static std::optional<HostUiMetricTriple> summarize(
        const std::deque<double>& samples);

    std::size_t capacity_;
    std::uint64_t last_published_frames_{};
    HostOutboundRateTracker outbound_rate_tracker_;
    std::deque<double> capture_ms_;
    std::deque<double> encode_ms_;
    std::deque<double> publish_ms_;
    std::deque<double> total_ms_;
    std::deque<double> link_rtt_ms_;
    std::deque<double> output_fps_;
};

}  // namespace vfdual
