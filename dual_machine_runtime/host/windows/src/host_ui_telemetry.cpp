#include "vfdual/host_ui_telemetry.hpp"

#include <algorithm>
#include <cmath>
#include <vector>

namespace vfdual {
namespace {

double percentile(const std::vector<double>& sorted, double probability) noexcept {
    const auto rank = static_cast<std::size_t>(
        std::ceil(probability * static_cast<double>(sorted.size())));
    return sorted[(std::max)(std::size_t{1U}, rank) - 1U];
}

}  // namespace

HostUiTelemetry::HostUiTelemetry(std::size_t capacity)
    : capacity_((std::max)(std::size_t{8U}, capacity)) {}

void HostUiTelemetry::reset() noexcept {
    last_published_frames_ = 0U;
    outbound_rate_tracker_.reset();
    capture_ms_.clear();
    encode_ms_.clear();
    publish_ms_.clear();
    total_ms_.clear();
    link_rtt_ms_.clear();
    output_fps_.clear();
}

HostUiTelemetrySnapshot HostUiTelemetry::observe(const host::application::HostRuntimeReadModel& metrics,
                                                 std::uint64_t monotonic_ms) {
    const auto observed_rate = outbound_rate_tracker_.observe(metrics.published_frames, monotonic_ms);
    if (observed_rate.has_value() && std::isfinite(*observed_rate)) {
        append(output_fps_, *observed_rate);
    }
    if (metrics.published_frames == 0U || metrics.published_frames == last_published_frames_) {
        return snapshot();
    }
    last_published_frames_ = metrics.published_frames;
    const auto microseconds_to_milliseconds = [](std::uint64_t value) {
        return static_cast<double>(value) / 1000.0;
    };
    append(capture_ms_, microseconds_to_milliseconds(metrics.capture_us));
    append(encode_ms_, microseconds_to_milliseconds(metrics.encode_us));
    append(publish_ms_, microseconds_to_milliseconds(metrics.publish_us));
    const std::uint64_t total_us = metrics.capture_to_publish_us != 0U
        ? metrics.capture_to_publish_us
        : metrics.capture_us + metrics.readback_wait_us + metrics.readback_copy_us +
            metrics.bridge_us + metrics.upload_us + metrics.encode_us + metrics.publish_us;
    append(total_ms_, microseconds_to_milliseconds(total_us));
    if (std::isfinite(metrics.rtt_ms) && metrics.rtt_ms >= 0.0) {
        append(link_rtt_ms_, metrics.rtt_ms);
    }
    return snapshot();
}

HostUiTelemetrySnapshot HostUiTelemetry::snapshot() const {
    return HostUiTelemetrySnapshot{summarize(capture_ms_), summarize(encode_ms_),
                                   summarize(publish_ms_), summarize(total_ms_),
                                   summarize(link_rtt_ms_), summarize(output_fps_)};
}

void HostUiTelemetry::append(std::deque<double>& samples, double value) {
    samples.push_back(value);
    while (samples.size() > capacity_) samples.pop_front();
}

std::optional<HostUiMetricTriple> HostUiTelemetry::summarize(
    const std::deque<double>& samples) {
    if (samples.empty()) return std::nullopt;
    std::vector<double> sorted(samples.begin(), samples.end());
    std::sort(sorted.begin(), sorted.end());
    return HostUiMetricTriple{samples.back(), percentile(sorted, 0.50),
                              percentile(sorted, 0.95)};
}

}  // namespace vfdual
