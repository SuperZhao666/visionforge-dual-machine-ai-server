#include "MobileControlCore.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using vfdual_android::AimSource;
using vfdual_android::ControlSuppressionReason;
using vfdual_android::MobileControlCore;
using vfdual_android::MobileControlOutput;
using vfdual_android::YoloDetection;

struct Options {
    std::filesystem::path trace_path;
    std::filesystem::path output_path;
    std::string model_profile{"default"};
    std::uint32_t maximum_frames{};
    std::uint32_t frames_per_second{10};
    std::uint64_t processing_age_us{};
    float gain{0.10F};
    float deadzone_pixels{2.0F};
    std::int32_t maximum_axis_delta{127};
    std::uint32_t switch_confirmation_ms{
        static_cast<std::uint32_t>(
            vfdual_android::MobileControlConfig{}
                .switch_confirmation_duration_us / 1'000U)};
    bool require_complete{};
};

struct TraceData {
    std::map<std::uint32_t, std::vector<YoloDetection>> frames;
    bool valid{};
};

struct AxisSummary {
    std::int32_t minimum{};
    std::int32_t maximum{};
    double signed_mean{};
    double absolute_mean{};
    std::int32_t absolute_p50{};
    std::int32_t absolute_p95{};
};

struct EvaluationCounters {
    std::uint32_t target_frames{};
    std::uint32_t head_frames{};
    std::uint32_t body_fallback_frames{};
    std::uint32_t no_target_frames{};
    std::uint32_t held_frames{};
    std::uint32_t lost_hold_frames{};
    std::uint32_t switch_pending_frames{};
    std::uint32_t switched_frames{};
    std::uint32_t zero_move_frames{};
    std::uint32_t nonzero_move_frames{};
    std::uint32_t saturated_frames{};
    std::uint32_t saturated_x_frames{};
    std::uint32_t saturated_y_frames{};
    std::uint32_t deadzone_frames{};
    std::uint32_t settle_guard_frames{};
    std::vector<std::int32_t> delta_x;
    std::vector<std::int32_t> delta_y;
};

[[nodiscard]] bool parse_unsigned(std::string_view value, std::uint32_t* destination) {
    const auto result = std::from_chars(value.data(), value.data() + value.size(), *destination);
    return result.ec == std::errc{} && result.ptr == value.data() + value.size();
}

[[nodiscard]] bool parse_unsigned64(std::string_view value, std::uint64_t* destination) {
    const auto result = std::from_chars(value.data(), value.data() + value.size(), *destination);
    return result.ec == std::errc{} && result.ptr == value.data() + value.size();
}

[[nodiscard]] bool parse_float(std::string_view value, float* destination) {
    try {
        const float parsed = std::stof(std::string(value));
        if (!std::isfinite(parsed)) return false;
        *destination = parsed;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

[[nodiscard]] bool parse_options(int argc, char** argv, Options* options) {
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--trace" && index + 1 < argc) options->trace_path = argv[++index];
        else if (argument == "--output" && index + 1 < argc) options->output_path = argv[++index];
        else if (argument == "--max-frames" && index + 1 < argc) {
            if (!parse_unsigned(argv[++index], &options->maximum_frames) || options->maximum_frames == 0U) return false;
        } else if (argument == "--fps" && index + 1 < argc) {
            if (!parse_unsigned(argv[++index], &options->frames_per_second) || options->frames_per_second == 0U ||
                options->frames_per_second > 1'000U) return false;
        } else if (argument == "--processing-age-us" && index + 1 < argc) {
            if (!parse_unsigned64(argv[++index], &options->processing_age_us)) return false;
        } else if (argument == "--gain" && index + 1 < argc) {
            if (!parse_float(argv[++index], &options->gain) || options->gain < 0.01F || options->gain > 2.0F) return false;
        } else if (argument == "--deadzone-pixels" && index + 1 < argc) {
            if (!parse_float(argv[++index], &options->deadzone_pixels) ||
                options->deadzone_pixels < 0.0F || options->deadzone_pixels > 64.0F) return false;
        } else if (argument == "--maximum-axis-delta" && index + 1 < argc) {
            std::uint32_t value{};
            if (!parse_unsigned(argv[++index], &value) || value == 0U || value > 127U) return false;
            options->maximum_axis_delta = static_cast<std::int32_t>(value);
        } else if (argument == "--switch-confirmation-ms" && index + 1 < argc) {
            if (!parse_unsigned(argv[++index], &options->switch_confirmation_ms)) return false;
        } else if (argument == "--model" && index + 1 < argc) {
            options->model_profile = argv[++index];
            if (options->model_profile != "default" &&
                options->model_profile != "overwatch2-head") return false;
        } else if (argument == "--require-complete") options->require_complete = true;
        else return false;
    }
    return !options->trace_path.empty();
}

void print_usage() {
    std::cerr << "usage: VisionForgeControlTraceEvaluate --trace qnn-detection-trace.csv "
                 "[--max-frames N] [--fps 10] [--processing-age-us N] "
                 "[--gain 0.10] [--deadzone-pixels 2.0] [--maximum-axis-delta 127] "
                 "[--switch-confirmation-ms 20] "
                 "[--model default|overwatch2-head] "
                 "[--output simulated-control.csv] [--require-complete]\n";
}

[[nodiscard]] std::vector<std::string> split_csv(std::string_view value) {
    std::vector<std::string> fields;
    std::size_t begin{};
    while (begin <= value.size()) {
        const std::size_t end = value.find(',', begin);
        fields.emplace_back(value.substr(begin, end == std::string_view::npos ? value.size() - begin : end - begin));
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    return fields;
}

[[nodiscard]] std::optional<YoloDetection> parse_detection(const std::vector<std::string>& fields) {
    if (fields.size() != 7U || fields[1] == "-1") return std::nullopt;
    try {
        const auto class_id = static_cast<std::uint32_t>(std::stoul(fields[1]));
        const float confidence = std::stof(fields[2]);
        const float x1 = std::stof(fields[3]);
        const float y1 = std::stof(fields[4]);
        const float x2 = std::stof(fields[5]);
        const float y2 = std::stof(fields[6]);
        const float values[]{confidence, x1, y1, x2, y2};
        if (!std::all_of(std::begin(values), std::end(values), [](float value) { return std::isfinite(value); })) {
            return std::nullopt;
        }
        return YoloDetection{x1, y1, x2, y2, confidence, class_id};
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

[[nodiscard]] TraceData read_trace(const std::filesystem::path& path) {
    std::ifstream input(path);
    TraceData trace;
    std::string row;
    if (!std::getline(input, row) || row != "frame_id,class_id,confidence,x1,y1,x2,y2") return trace;
    trace.valid = true;
    while (std::getline(input, row)) {
        const auto fields = split_csv(row);
        std::uint32_t frame_id{};
        if (fields.size() != 7U || !parse_unsigned(fields[0], &frame_id) || frame_id == 0U) {
            trace.valid = false;
            continue;
        }
        auto [iterator, inserted] = trace.frames.try_emplace(frame_id);
        (void)inserted;
        if (fields[1] == "-1") continue;
        if (const auto detection = parse_detection(fields)) iterator->second.push_back(*detection);
        else trace.valid = false;
    }
    return trace;
}

[[nodiscard]] std::string_view source_name(AimSource source) noexcept {
    switch (source) {
    case AimSource::head: return "head";
    case AimSource::body_fallback: return "body_fallback";
    case AimSource::geometric_head: return "geometric_head";
    case AimSource::selected_class: return "selected_class";
    default: return "none";
    }
}

[[nodiscard]] bool apply_model_profile(
    std::string_view profile, vfdual_android::MobileControlConfig* config) {
    if (profile == "default") return true;
    if (profile != "overwatch2-head") return false;

    const auto& model = vfdual::kOverwatch2Yolov5_416;
    const auto& target = model.aim_targets[1];
    config->body_class_id = target.body_class_id;
    config->head_class_id = target.head_class_id;
    config->selected_class_id = target.selected_class_id;
    config->selected_class_uses_head_box = target.uses_head_box;
    config->selected_class_uses_geometric_head =
        target.uses_geometric_head;
    config->head_body_pairing_enabled = target.uses_head_box;
    config->body_fallback_y_ratio = target.target_y_ratio;
    config->model_width = static_cast<float>(model.input.width);
    config->model_height = static_cast<float>(model.input.height);
    config->model_center_x = config->model_width * 0.5F;
    config->model_center_y = config->model_height * 0.5F;
    config->tracker.high_confidence_threshold =
        model.tracking_confidence.high_confidence_threshold;
    config->tracker.low_confidence_threshold =
        model.tracking_confidence.low_confidence_threshold;
    config->tracker.new_track_confidence_threshold =
        model.tracking_confidence.new_track_confidence_threshold;
    config->head_confidence_threshold = 0.0F;
    config->body_confidence_threshold = 0.0F;
    config->paired_body_min_confidence = 0.0F;
    config->head_only_min_confidence = 0.0F;
    config->body_fallback_min_confidence = 0.0F;
    config->head_only_max_center_distance_pixels = config->model_width;
    config->body_fallback_max_center_distance_pixels = config->model_width;
    config->reject_border_touching = false;
    config->body_min_width = 2.0F;
    config->body_min_height = 2.0F;
    config->body_max_width = config->model_width;
    config->body_max_height = config->model_height;
    config->body_min_aspect_ratio = 0.02F;
    config->body_max_aspect_ratio = 50.0F;
    vfdual_android::apply_mobile_model_control_tuning(model, *config);
    return true;
}

[[nodiscard]] std::string_view suppression_name(ControlSuppressionReason reason) noexcept {
    switch (reason) {
    case ControlSuppressionReason::invalid_time: return "invalid_time";
    case ControlSuppressionReason::stale_frame: return "stale_frame";
    case ControlSuppressionReason::non_monotonic_frame: return "non_monotonic_frame";
    case ControlSuppressionReason::no_valid_target: return "no_valid_target";
    case ControlSuppressionReason::lock_held: return "lock_held";
    case ControlSuppressionReason::switch_pending: return "switch_pending";
    case ControlSuppressionReason::deadzone: return "deadzone";
    case ControlSuppressionReason::settle_guard: return "settle_guard";
    default: return "none";
    }
}

[[nodiscard]] std::int32_t percentile(std::vector<std::int32_t> values, double fraction) {
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const auto index = static_cast<std::size_t>(std::ceil(fraction * static_cast<double>(values.size()))) - 1U;
    return values[std::min(index, values.size() - 1U)];
}

[[nodiscard]] AxisSummary summarize_axis(const std::vector<std::int32_t>& values) {
    AxisSummary summary;
    if (values.empty()) return summary;
    const auto [minimum, maximum] = std::minmax_element(values.begin(), values.end());
    summary.minimum = *minimum;
    summary.maximum = *maximum;
    const auto signed_sum = std::accumulate(values.begin(), values.end(), std::int64_t{});
    std::vector<std::int32_t> magnitudes;
    magnitudes.reserve(values.size());
    std::int64_t absolute_sum{};
    for (const auto value : values) {
        const auto magnitude = static_cast<std::int32_t>(std::abs(value));
        magnitudes.push_back(magnitude);
        absolute_sum += magnitude;
    }
    summary.signed_mean = static_cast<double>(signed_sum) / static_cast<double>(values.size());
    summary.absolute_mean = static_cast<double>(absolute_sum) / static_cast<double>(values.size());
    summary.absolute_p50 = percentile(magnitudes, 0.50);
    summary.absolute_p95 = percentile(magnitudes, 0.95);
    return summary;
}

void record_output(const MobileControlOutput& output, std::int32_t maximum_axis_delta,
                   EvaluationCounters* counters) {
    counters->delta_x.push_back(output.delta_x);
    counters->delta_y.push_back(output.delta_y);
    if (output.has_target) ++counters->target_frames;
    else ++counters->no_target_frames;
    if (output.source == AimSource::head) ++counters->head_frames;
    else if (output.source == AimSource::body_fallback) ++counters->body_fallback_frames;
    if (output.held) ++counters->held_frames;
    if (output.suppression_reason == ControlSuppressionReason::lock_held) ++counters->lost_hold_frames;
    if (output.suppression_reason == ControlSuppressionReason::switch_pending) ++counters->switch_pending_frames;
    if (output.suppression_reason == ControlSuppressionReason::deadzone) ++counters->deadzone_frames;
    if (output.suppression_reason == ControlSuppressionReason::settle_guard) ++counters->settle_guard_frames;
    if (output.switched) ++counters->switched_frames;
    if (output.has_move()) ++counters->nonzero_move_frames;
    else ++counters->zero_move_frames;
    const bool saturated_x = std::abs(output.delta_x) >= maximum_axis_delta;
    const bool saturated_y = std::abs(output.delta_y) >= maximum_axis_delta;
    if (saturated_x) ++counters->saturated_x_frames;
    if (saturated_y) ++counters->saturated_y_frames;
    if (saturated_x || saturated_y) ++counters->saturated_frames;
}

void write_output_row(std::ofstream* output, std::uint32_t frame_id, bool traced,
                      const MobileControlOutput& control) {
    if (!output->is_open()) return;
    *output << frame_id << ',' << static_cast<int>(traced) << ',' << static_cast<int>(control.has_target) << ','
            << static_cast<int>(control.held) << ',' << static_cast<int>(control.switched) << ','
            << source_name(control.source) << ',' << suppression_name(control.suppression_reason) << ','
            << control.target_x << ',' << control.target_y << ',' << control.delta_x << ',' << control.delta_y << ','
            << control.lock_id << ',' << control.track_id << '\n';
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    if (!parse_options(argc, argv, &options)) {
        print_usage();
        return 2;
    }
    const auto trace = read_trace(options.trace_path);
    if (!trace.valid || trace.frames.empty()) {
        std::cerr << "event=control_trace_evaluation_failed reason=trace_unreadable_or_invalid\n";
        return 3;
    }
    const std::uint32_t expected_frames = options.maximum_frames == 0U
        ? trace.frames.rbegin()->first : options.maximum_frames;
    const std::uint32_t traced_frames = static_cast<std::uint32_t>(std::count_if(
        trace.frames.begin(), trace.frames.end(), [expected_frames](const auto& value) {
            return value.first <= expected_frames;
        }));

    std::ofstream output;
    if (!options.output_path.empty()) {
        output.open(options.output_path);
        if (!output) {
            std::cerr << "event=control_trace_evaluation_failed reason=output_unwritable\n";
            return 4;
        }
        output << "frame_id,traced,has_target,held,switched,source,suppression,target_x,target_y,delta_x,delta_y,lock_id,track_id\n";
    }

    vfdual_android::MobileControlConfig control_config{};
    control_config.switch_confirmation_duration_us =
        static_cast<std::uint64_t>(options.switch_confirmation_ms) * 1'000ULL;
    if (!apply_model_profile(options.model_profile, &control_config)) {
        std::cerr << "event=control_trace_evaluation_failed reason=model_profile_invalid\n";
        return 7;
    }
    control_config.motion.response_gain = options.gain;
    control_config.motion.deadzone_pixels = options.deadzone_pixels;
    control_config.motion.maximum_axis_delta = options.maximum_axis_delta;
    control_config.motion.uncalibrated_maximum_axis_delta = std::min(
        control_config.motion.uncalibrated_maximum_axis_delta,
        options.maximum_axis_delta);
    control_config.motion.maximum_step_counts_per_tick = std::min(
        control_config.motion.maximum_step_counts_per_tick,
        static_cast<float>(options.maximum_axis_delta));
    control_config.motion.maximum_jerk_counts_per_tick2 = std::min(
        control_config.motion.maximum_jerk_counts_per_tick2,
        control_config.motion.maximum_step_counts_per_tick);
    control_config.motion.settle_maximum_axis_delta = std::min(
        control_config.motion.settle_maximum_axis_delta,
        options.maximum_axis_delta);
    MobileControlCore control_core;
    if (!control_core.configure(control_config)) {
        std::cerr << "event=control_trace_evaluation_failed reason=control_profile_invalid\n";
        return 6;
    }
    EvaluationCounters counters;
    const std::uint64_t interval_us = 1'000'000ULL / options.frames_per_second;
    constexpr std::uint64_t kTimelineOriginUs = 1'000'000ULL;
    for (std::uint32_t frame_id = 1; frame_id <= expected_frames; ++frame_id) {
        const auto iterator = trace.frames.find(frame_id);
        const bool traced = iterator != trace.frames.end();
        const std::span<const YoloDetection> detections = traced
            ? std::span<const YoloDetection>(iterator->second)
            : std::span<const YoloDetection>{};
        const std::uint64_t observed_at_us = kTimelineOriginUs + (frame_id - 1ULL) * interval_us;
        const auto control = control_core.process(
            detections, {frame_id, observed_at_us, observed_at_us + options.processing_age_us});
        record_output(control, options.maximum_axis_delta, &counters);
        write_output_row(&output, frame_id, traced, control);
    }

    const auto& control_metrics = control_core.metrics();
    const auto& tracker_metrics = control_core.tracker_metrics();
    const AxisSummary x = summarize_axis(counters.delta_x);
    const AxisSummary y = summarize_axis(counters.delta_y);
    const double coverage = static_cast<double>(traced_frames) / static_cast<double>(expected_frames);
    const double saturation_rate = static_cast<double>(counters.saturated_frames) /
        static_cast<double>(expected_frames);
    std::cout << std::fixed << std::setprecision(6)
              << "event=control_trace_evaluation_result"
              << " expected_frames=" << expected_frames
              << " traced_frames=" << traced_frames
              << " coverage=" << coverage
              << " model=" << options.model_profile
              << " fps=" << options.frames_per_second
              << " processing_age_us=" << options.processing_age_us
              << " gain=" << options.gain
              << " deadzone_pixels=" << options.deadzone_pixels
              << " maximum_axis_delta=" << options.maximum_axis_delta
              << " switch_confirmation_ms="
              << options.switch_confirmation_ms
              << " physical_output=disabled driver_calls=0"
              << " target_frames=" << counters.target_frames
              << " head_frames=" << counters.head_frames
              << " body_fallback_frames=" << counters.body_fallback_frames
              << " no_target_frames=" << counters.no_target_frames
              << " held_frames=" << counters.held_frames
              << " lost_hold_frames=" << counters.lost_hold_frames
              << " switch_pending_frames=" << counters.switch_pending_frames
              << " switched_frames=" << counters.switched_frames
              << " reacquisition_pending_frames="
              << control_metrics.reacquisition_pending_frames
              << " reacquisition_confirmations="
              << control_metrics.reacquisition_confirmations
              << " tracker_tracks_created=" << tracker_metrics.tracks_created
              << " tracker_tracks_expired=" << tracker_metrics.tracks_expired
              << " tracker_first_stage_matches=" << tracker_metrics.first_stage_matches
              << " tracker_second_stage_matches=" << tracker_metrics.second_stage_matches
              << " tracker_center_matches=" << tracker_metrics.center_distance_matches
              << " tracker_control_filter_blends="
              << tracker_metrics.control_filter_blends
              << " tracker_control_filter_bypasses="
              << tracker_metrics.control_filter_bypasses
              << " tracker_maximum_control_innovation_pixels="
              << tracker_metrics.maximum_control_innovation_pixels
              << " freshness_rejects=" << control_metrics.stale_frames
              << " non_monotonic_rejects=" << control_metrics.non_monotonic_frames
              << " invalid_time_rejects=" << control_metrics.invalid_time_frames
              << " zero_move_frames=" << counters.zero_move_frames
              << " nonzero_move_frames=" << counters.nonzero_move_frames
              << " saturated_frames=" << counters.saturated_frames
              << " saturated_x_frames=" << counters.saturated_x_frames
              << " saturated_y_frames=" << counters.saturated_y_frames
              << " saturation_rate=" << saturation_rate
              << " deadzone_frames=" << counters.deadzone_frames
              << " settle_guard_frames=" << counters.settle_guard_frames
              << " delta_x_min=" << x.minimum << " delta_x_max=" << x.maximum
              << " delta_x_mean=" << x.signed_mean << " delta_x_abs_mean=" << x.absolute_mean
              << " delta_x_abs_p50=" << x.absolute_p50 << " delta_x_abs_p95=" << x.absolute_p95
              << " delta_y_min=" << y.minimum << " delta_y_max=" << y.maximum
              << " delta_y_mean=" << y.signed_mean << " delta_y_abs_mean=" << y.absolute_mean
              << " delta_y_abs_p50=" << y.absolute_p50 << " delta_y_abs_p95=" << y.absolute_p95
              << '\n';
    if (options.require_complete && traced_frames != expected_frames) {
        std::cerr << "event=control_trace_evaluation_failed reason=incomplete_trace_coverage\n";
        return 5;
    }
    return 0;
}
