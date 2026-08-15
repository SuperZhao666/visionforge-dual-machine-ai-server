#pragma once

#include "vfdual/desktop_video_agent.hpp"

#include <fstream>
#include <cstddef>
#include <cstdint>
#include <string>

namespace vfdual {

/** Samples host timing records off the capture/encode hot path when configured. */
class StreamerMetricsCsv final {
public:
    [[nodiscard]] bool open(
        const std::string& path, std::uint32_t sample_interval_records = 1U);
    void append(const DesktopVideoStepMetrics& step);
    void close() noexcept;
    [[nodiscard]] std::int32_t last_error() const noexcept { return last_error_; }

private:
    [[nodiscard]] bool should_append(const DesktopVideoStepMetrics& step) noexcept;

    std::ofstream output_;
    std::size_t records_since_flush_{};
    std::uint64_t observed_records_{};
    std::uint32_t sample_interval_records_{1U};
    bool has_data_plane_state_{};
    bool data_plane_closed_{};
    std::int32_t last_error_{};
};

}  // namespace vfdual
