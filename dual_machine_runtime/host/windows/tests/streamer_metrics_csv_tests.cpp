#include "vfdual/streamer_metrics_csv.hpp"

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <string>

int main() {
    const std::filesystem::path path =
        std::filesystem::temp_directory_path() /
        "visionforge-host-metrics-v6-contract.csv";
    std::error_code error;
    std::filesystem::remove(path, error);

    vfdual::StreamerMetricsCsv csv;
    assert(csv.open(path.string(), 4U));
    vfdual::DesktopVideoStepMetrics metrics{};
    metrics.status = vfdual::DesktopVideoStepStatus::frame_queued;
    metrics.async_shared_same_adapter = true;
    metrics.hybrid_mailbox_replaced = 11U;
    metrics.hybrid_ring_busy = 12U;
    metrics.hybrid_keyed_timeout = 13U;
    metrics.worker_frame_age_us = 14U;
    metrics.hybrid_latest_worker_frame_age_us = 15U;
    metrics.hybrid_maximum_worker_frame_age_us = 16U;
    for (int index = 0; index < 10; ++index) csv.append(metrics);
    metrics.status = vfdual::DesktopVideoStepStatus::data_plane_closed;
    csv.append(metrics);
    csv.append(metrics);
    metrics.status = vfdual::DesktopVideoStepStatus::frame_published;
    csv.append(metrics);
    metrics.status = vfdual::DesktopVideoStepStatus::publish_failed;
    csv.append(metrics);
    metrics.status = vfdual::DesktopVideoStepStatus::frame_published;
    metrics.keyframe = true;
    csv.append(metrics);
    csv.close();

    std::ifstream input(path);
    std::string header;
    std::string row;
    assert(std::getline(input, header));
    std::size_t sampled_rows{};
    while (std::getline(input, row)) {
        assert(!row.empty());
        assert(std::count(header.begin(), header.end(), ',') ==
               std::count(row.begin(), row.end(), ','));
        ++sampled_rows;
    }
    // 15 observations become initial/periodic rows plus close/open transitions,
    // one failure and one keyframe. The unsampled hot-path rows never format.
    assert(sampled_rows == 8U);
    assert(header.find("async_shared_same_adapter") != std::string::npos);
    assert(header.find("hybrid_keyed_timeout") != std::string::npos);
    assert(header.find("worker_frame_age_us") != std::string::npos);

    input.close();
    std::filesystem::remove(path, error);
    return 0;
}
