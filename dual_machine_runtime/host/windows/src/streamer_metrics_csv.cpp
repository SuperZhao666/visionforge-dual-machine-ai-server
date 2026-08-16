#include "vfdual/streamer_metrics_csv.hpp"

#include <cerrno>
#include <algorithm>
#include <filesystem>

namespace vfdual {
namespace {
bool is_failure_status(DesktopVideoStepStatus status) noexcept {
    switch (status) {
        case DesktopVideoStepStatus::capture_access_lost:
        case DesktopVideoStepStatus::capture_device_removed:
        case DesktopVideoStepStatus::capture_failed:
        case DesktopVideoStepStatus::bridge_failed:
        case DesktopVideoStepStatus::encode_failed:
        case DesktopVideoStepStatus::publish_failed:
            return true;
        case DesktopVideoStepStatus::frame_published:
        case DesktopVideoStepStatus::data_plane_closed:
        case DesktopVideoStepStatus::capture_timeout:
        case DesktopVideoStepStatus::frame_queued:
        case DesktopVideoStepStatus::capture_pointer_only:
        case DesktopVideoStepStatus::capture_outside_region:
        case DesktopVideoStepStatus::staging_busy:
            return false;
    }
    return true;
}
}  // namespace

bool StreamerMetricsCsv::open(
    const std::string& path, std::uint32_t sample_interval_records) {
    close();
    last_error_ = 0;
    if (path.empty()) return true;
    std::error_code error;
    const bool needs_header = !std::filesystem::exists(path, error) ||
                              (!error && std::filesystem::file_size(path, error) == 0);
    output_.open(path, std::ios::out | std::ios::app);
    if (!output_) {
        last_error_ = errno != 0 ? errno : EIO;
        return false;
    }
    if (needs_header) {
        output_ << "source_sequence,frame_id,status,capture_present_us,capture_us,"
                   "readback_wait_us,readback_copy_us,bridge_us,upload_us,encode_us,"
                   "publish_us,capture_to_publish_us,accumulated_frames,"
                   "missed_present_frames,pointer_only_skips,outside_region_skips,"
                   "missed_present_frames_total,static_content_repeats,"
                   "repeated_content,hybrid_frames_submitted,"
                   "hybrid_staging_busy,hybrid_was_still_drawing,"
                   "hybrid_mailbox_superseded,hybrid_mailbox_replaced,"
                   "hybrid_ring_busy,hybrid_keyed_timeout,hybrid_published,"
                   "hybrid_completion_metrics_dropped,"
                   "worker_frame_age_us,hybrid_latest_worker_frame_age_us,"
                   "hybrid_maximum_worker_frame_age_us,"
                   "hybrid_staging_high_watermark,hybrid_mailbox_high_watermark,"
                   "hybrid_completion_high_watermark,bridge_mode,access_unit_bytes,"
                   "access_unit_prefix_be,first_annex_b_nal_type,annex_b_nal_type_mask,"
                   "datagrams,keyframe,native_status,encoder_backend,capture_vendor,"
                   "encoder_vendor,encoder_same_adapter,zero_copy,asynchronous_pipeline,"
                   "async_shared_same_adapter,"
                   "encoder_timing_fps,nvenc_stage,media_foundation_stage,publish_stage\n";
    }
    records_since_flush_ = 0;
    observed_records_ = 0;
    sample_interval_records_ = (std::max)(1U, sample_interval_records);
    has_data_plane_state_ = false;
    data_plane_closed_ = false;
    return true;
}

bool StreamerMetricsCsv::should_append(
    const DesktopVideoStepMetrics& step) noexcept {
    ++observed_records_;
    bool data_plane_transition{};
    if (step.status == DesktopVideoStepStatus::data_plane_closed) {
        data_plane_transition = !has_data_plane_state_ || !data_plane_closed_;
        has_data_plane_state_ = true;
        data_plane_closed_ = true;
    } else if (step.status == DesktopVideoStepStatus::frame_published) {
        data_plane_transition = has_data_plane_state_ && data_plane_closed_;
        has_data_plane_state_ = true;
        data_plane_closed_ = false;
    }
    return observed_records_ == 1U ||
        observed_records_ % sample_interval_records_ == 0U ||
        step.keyframe || data_plane_transition || is_failure_status(step.status);
}

void StreamerMetricsCsv::append(const DesktopVideoStepMetrics& step) {
    if (!output_ || !should_append(step)) return;
    output_ << step.source_sequence << ',' << step.frame_id << ','
            << static_cast<int>(step.status) << ',' << step.capture_present_us << ','
            << step.capture_us << ',' << step.readback_wait_us << ','
            << step.readback_copy_us << ',' << step.bridge_us << ',' << step.upload_us << ','
            << step.encode_us << ',' << step.publish_us << ','
            << step.capture_to_publish_us << ',' << step.accumulated_frames << ','
            << step.missed_present_frames << ',' << step.pointer_only_skips << ','
            << step.outside_region_skips << ',' << step.missed_present_frames_total << ','
            << step.static_content_repeats << ',' << step.repeated_content << ','
            << step.hybrid_frames_submitted << ',' << step.hybrid_staging_busy << ','
            << step.hybrid_was_still_drawing << ',' << step.hybrid_mailbox_superseded << ','
            << step.hybrid_mailbox_replaced << ',' << step.hybrid_ring_busy << ','
            << step.hybrid_keyed_timeout << ','
            << step.hybrid_published << ','
            << step.hybrid_completion_metrics_dropped << ','
            << step.worker_frame_age_us << ','
            << step.hybrid_latest_worker_frame_age_us << ','
            << step.hybrid_maximum_worker_frame_age_us << ','
            << step.hybrid_staging_high_watermark << ','
            << step.hybrid_mailbox_high_watermark << ','
            << step.hybrid_completion_high_watermark << ','
            << static_cast<int>(step.bridge_mode) << ',' << step.access_unit_bytes << ','
            << step.access_unit_prefix_be << ','
            << static_cast<unsigned>(step.first_annex_b_nal_type) << ','
            << step.annex_b_nal_type_mask << ',' << step.datagrams_sent << ','
            << step.keyframe << ','
            << step.native_status << ',' << static_cast<int>(step.encoder_backend) << ','
            << static_cast<int>(step.capture_vendor) << ','
            << static_cast<int>(step.encoder_vendor) << ','
            << step.encoder_same_adapter << ',' << step.zero_copy << ','
            << step.asynchronous_pipeline << ','
            << step.async_shared_same_adapter << ','
            << step.encoder_timing_fps << ','
            << static_cast<int>(step.nvenc_stage) << ','
            << static_cast<int>(step.media_foundation_stage) << ','
            << static_cast<int>(step.publish_stage) << '\n';
    ++records_since_flush_;
    // Keep the latest diagnostics durable at random-access boundaries while
    // avoiding a synchronous disk write on every capture attempt.
    if (step.keyframe || is_failure_status(step.status) ||
        step.status == DesktopVideoStepStatus::data_plane_closed ||
        records_since_flush_ >= 512U) {
        output_.flush();
        records_since_flush_ = 0;
    }
}

void StreamerMetricsCsv::close() noexcept {
    if (!output_.is_open()) return;
    output_.flush();
    output_.close();
    records_since_flush_ = 0;
    observed_records_ = 0;
    has_data_plane_state_ = false;
    data_plane_closed_ = false;
}
}  // namespace vfdual
