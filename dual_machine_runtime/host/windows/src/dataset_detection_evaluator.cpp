#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "vfdual/model_contract.hpp"

namespace {

constexpr float kDefaultModelInputSize =
    static_cast<float>(vfdual::kDefaultMobileModel.input.width);
constexpr float kMatchIouThreshold = 0.50F;

struct Box {
    float x1{};
    float y1{};
    float x2{};
    float y2{};
    std::uint32_t class_id{};
    float confidence{};
};

struct Options {
    std::filesystem::path labels_directory;
    std::filesystem::path trace_path;
    std::uint32_t maximum_frames{};
    float minimum_confidence{};
    float model_input_size{kDefaultModelInputSize};
    bool require_complete{};
};

struct Counters {
    std::uint32_t evaluated_frames{};
    std::uint32_t expected_frames{};
    std::uint32_t true_positive{};
    std::uint32_t false_positive{};
    std::uint32_t false_negative{};
    float matched_iou_sum{};
};

struct DetectionCandidate {
    std::uint32_t frame_id{};
    Box detection{};
};

[[nodiscard]] bool parse_unsigned(std::string_view value, std::uint32_t* destination) {
    const auto result = std::from_chars(value.data(), value.data() + value.size(), *destination);
    return result.ec == std::errc{} && result.ptr == value.data() + value.size();
}

[[nodiscard]] bool parse_confidence(std::string_view value, float* destination) {
    try {
        const float parsed = std::stof(std::string(value));
        if (!std::isfinite(parsed) || parsed < 0.0F || parsed > 1.0F) return false;
        *destination = parsed;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

[[nodiscard]] bool parse_model_input_size(std::string_view value, float* destination) {
    try {
        const float parsed = std::stof(std::string(value));
        if (!std::isfinite(parsed) || parsed < 32.0F || parsed > 4096.0F) return false;
        *destination = parsed;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

[[nodiscard]] bool parse_options(int argc, char** argv, Options* options) {
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--labels" && index + 1 < argc) options->labels_directory = argv[++index];
        else if (argument == "--trace" && index + 1 < argc) options->trace_path = argv[++index];
        else if (argument == "--max-frames" && index + 1 < argc) {
            if (!parse_unsigned(argv[++index], &options->maximum_frames) || options->maximum_frames == 0U) return false;
        } else if (argument == "--minimum-confidence" && index + 1 < argc) {
            if (!parse_confidence(argv[++index], &options->minimum_confidence)) return false;
        } else if (argument == "--model-input-size" && index + 1 < argc) {
            if (!parse_model_input_size(argv[++index], &options->model_input_size)) return false;
        } else if (argument == "--require-complete") options->require_complete = true;
        else return false;
    }
    return !options->labels_directory.empty() && !options->trace_path.empty();
}

void print_usage() {
    std::cerr << "usage: VisionForgeDatasetEvaluate --labels LABELS_DIR --trace qnn-detection-trace.csv "
                 "[--max-frames N] [--minimum-confidence 0.25] "
                 "[--model-input-size 416] [--require-complete]\n";
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

[[nodiscard]] std::optional<Box> parse_trace_box(const std::vector<std::string>& fields) {
    if (fields.size() != 7U || fields[1] == "-1") return std::nullopt;
    try {
        return Box{std::stof(fields[3]), std::stof(fields[4]), std::stof(fields[5]), std::stof(fields[6]),
                   static_cast<std::uint32_t>(std::stoul(fields[1])), std::stof(fields[2])};
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

[[nodiscard]] std::map<std::uint32_t, std::vector<Box>> read_trace(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::map<std::uint32_t, std::vector<Box>> trace;
    std::string row;
    if (!std::getline(input, row) || row != "frame_id,class_id,confidence,x1,y1,x2,y2") return trace;
    while (std::getline(input, row)) {
        const auto fields = split_csv(row);
        std::uint32_t frame_id{};
        if (fields.size() != 7U || !parse_unsigned(fields[0], &frame_id) || frame_id == 0U) continue;
        auto& detections = trace[frame_id];
        if (const auto box = parse_trace_box(fields)) detections.push_back(*box);
    }
    return trace;
}

[[nodiscard]] std::vector<Box> read_ground_truth(
    const std::filesystem::path& labels_directory, std::uint32_t frame_id,
    float model_input_size) {
    std::ifstream input(labels_directory / (std::to_string(frame_id) + ".txt"));
    std::vector<Box> boxes;
    std::uint32_t class_id{};
    float center_x{};
    float center_y{};
    float width{};
    float height{};
    while (input >> class_id >> center_x >> center_y >> width >> height) {
        boxes.push_back({(center_x - width * 0.5F) * model_input_size,
                         (center_y - height * 0.5F) * model_input_size,
                         (center_x + width * 0.5F) * model_input_size,
                         (center_y + height * 0.5F) * model_input_size,
                         class_id, 1.0F});
        std::string ignored;
        std::getline(input, ignored);
    }
    return boxes;
}

[[nodiscard]] float intersection_over_union(const Box& left, const Box& right) {
    const float x1 = std::max(left.x1, right.x1);
    const float y1 = std::max(left.y1, right.y1);
    const float x2 = std::min(left.x2, right.x2);
    const float y2 = std::min(left.y2, right.y2);
    const float intersection = std::max(0.0F, x2 - x1) * std::max(0.0F, y2 - y1);
    const float left_area = std::max(0.0F, left.x2 - left.x1) * std::max(0.0F, left.y2 - left.y1);
    const float right_area = std::max(0.0F, right.x2 - right.x1) * std::max(0.0F, right.y2 - right.y1);
    const float union_area = left_area + right_area - intersection;
    return union_area > 0.0F ? intersection / union_area : 0.0F;
}

void score_frame(std::vector<Box> detections, const std::vector<Box>& ground_truth, Counters* counters) {
    std::sort(detections.begin(), detections.end(), [](const Box& left, const Box& right) {
        return left.confidence > right.confidence;
    });
    std::vector<bool> matched(ground_truth.size());
    for (const auto& detection : detections) {
        float best_iou{};
        std::size_t best_index = ground_truth.size();
        for (std::size_t index{}; index < ground_truth.size(); ++index) {
            if (matched[index] || detection.class_id != ground_truth[index].class_id) continue;
            const float iou = intersection_over_union(detection, ground_truth[index]);
            if (iou > best_iou) {
                best_iou = iou;
                best_index = index;
            }
        }
        if (best_index != ground_truth.size() && best_iou >= kMatchIouThreshold) {
            matched[best_index] = true;
            ++counters->true_positive;
            counters->matched_iou_sum += best_iou;
        } else {
            ++counters->false_positive;
        }
    }
    for (const bool is_matched : matched) if (!is_matched) ++counters->false_negative;
}

[[nodiscard]] std::optional<float> calculate_class_zero_average_precision(
    const std::map<std::uint32_t, std::vector<Box>>& trace,
    const std::map<std::uint32_t, std::vector<Box>>& ground_truth_by_frame,
    float iou_threshold) {
    std::uint32_t ground_truth_count{};
    std::vector<DetectionCandidate> candidates;
    std::map<std::uint32_t, std::vector<bool>> matched_by_frame;
    for (const auto& [frame_id, ground_truth] : ground_truth_by_frame) {
        matched_by_frame.emplace(frame_id, std::vector<bool>(ground_truth.size()));
        ground_truth_count += static_cast<std::uint32_t>(std::count_if(ground_truth.begin(), ground_truth.end(),
            [](const Box& value) { return value.class_id == 0U; }));
        const auto trace_iterator = trace.find(frame_id);
        if (trace_iterator == trace.end()) continue;
        for (const auto& detection : trace_iterator->second) {
            if (detection.class_id == 0U) candidates.push_back({frame_id, detection});
        }
    }
    if (ground_truth_count == 0U) return std::nullopt;
    std::sort(candidates.begin(), candidates.end(), [](const DetectionCandidate& left, const DetectionCandidate& right) {
        return left.detection.confidence > right.detection.confidence;
    });
    std::vector<float> precision_points;
    std::vector<float> recall_points;
    precision_points.reserve(candidates.size());
    recall_points.reserve(candidates.size());
    std::uint32_t true_positive{};
    std::uint32_t false_positive{};
    for (const auto& candidate : candidates) {
        const auto& ground_truth = ground_truth_by_frame.at(candidate.frame_id);
        auto& matched = matched_by_frame.at(candidate.frame_id);
        float best_iou{};
        std::size_t best_index = ground_truth.size();
        for (std::size_t index{}; index < ground_truth.size(); ++index) {
            if (matched[index] || ground_truth[index].class_id != 0U) continue;
            const float iou = intersection_over_union(candidate.detection, ground_truth[index]);
            if (iou > best_iou) {
                best_iou = iou;
                best_index = index;
            }
        }
        if (best_index != ground_truth.size() && best_iou >= iou_threshold) {
            matched[best_index] = true;
            ++true_positive;
        } else {
            ++false_positive;
        }
        precision_points.push_back(static_cast<float>(true_positive) / static_cast<float>(true_positive + false_positive));
        recall_points.push_back(static_cast<float>(true_positive) / static_cast<float>(ground_truth_count));
    }
    float average_precision{};
    for (std::uint32_t index{}; index <= 100U; ++index) {
        const float recall_threshold = static_cast<float>(index) / 100.0F;
        float best_precision{};
        for (std::size_t point{}; point < recall_points.size(); ++point) {
            if (recall_points[point] >= recall_threshold) best_precision = std::max(best_precision, precision_points[point]);
        }
        average_precision += best_precision;
    }
    return average_precision / 101.0F;
}

[[nodiscard]] std::string format_optional_metric(std::optional<float> value) {
    if (!value.has_value()) return "--";
    std::ostringstream output;
    output.setf(std::ios::fixed);
    output.precision(4);
    output << *value;
    return output.str();
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    if (!parse_options(argc, argv, &options)) {
        print_usage();
        return 2;
    }
    auto trace = read_trace(options.trace_path);
    if (trace.empty()) {
        std::cerr << "event=dataset_evaluation_failed reason=trace_unreadable_or_invalid\n";
        return 3;
    }
    for (auto& [frame_id, detections] : trace) {
        detections.erase(std::remove_if(detections.begin(), detections.end(), [&options](const Box& detection) {
            return detection.confidence < options.minimum_confidence;
        }), detections.end());
    }
    const std::uint32_t expected_frames = options.maximum_frames == 0U
        ? trace.rbegin()->first : options.maximum_frames;
    Counters counters{};
    counters.expected_frames = expected_frames;
    std::map<std::uint32_t, std::vector<Box>> ground_truth_by_frame;
    for (const auto& [frame_id, detections] : trace) {
        if (frame_id > expected_frames) continue;
        const auto ground_truth = read_ground_truth(
            options.labels_directory, frame_id, options.model_input_size);
        score_frame(detections, ground_truth, &counters);
        ground_truth_by_frame.emplace(frame_id, ground_truth);
        ++counters.evaluated_frames;
    }
    const float precision_denominator = static_cast<float>(counters.true_positive + counters.false_positive);
    const float recall_denominator = static_cast<float>(counters.true_positive + counters.false_negative);
    const float precision = precision_denominator == 0.0F ? 0.0F : counters.true_positive / precision_denominator;
    const float recall = recall_denominator == 0.0F ? 0.0F : counters.true_positive / recall_denominator;
    const float f1 = precision + recall == 0.0F ? 0.0F : 2.0F * precision * recall / (precision + recall);
    const float mean_iou = counters.true_positive == 0U ? 0.0F : counters.matched_iou_sum / counters.true_positive;
    const auto ap50 = calculate_class_zero_average_precision(trace, ground_truth_by_frame, 0.50F);
    constexpr std::array<float, 10> kMapThresholds{0.50F, 0.55F, 0.60F, 0.65F, 0.70F,
                                                     0.75F, 0.80F, 0.85F, 0.90F, 0.95F};
    float map50_95_sum{};
    std::uint32_t map50_95_count{};
    for (const float threshold : kMapThresholds) {
        const auto average_precision = calculate_class_zero_average_precision(trace, ground_truth_by_frame, threshold);
        if (!average_precision.has_value()) continue;
        map50_95_sum += *average_precision;
        ++map50_95_count;
    }
    const std::optional<float> map50_95 = map50_95_count == 0U ? std::nullopt
        : std::optional<float>(map50_95_sum / static_cast<float>(map50_95_count));
    std::cout << "event=dataset_evaluation_result expected_frames=" << counters.expected_frames
              << " traced_frames=" << counters.evaluated_frames
              << " coverage=" << (counters.expected_frames == 0U ? 0.0F : static_cast<float>(counters.evaluated_frames) / counters.expected_frames)
              << " minimum_confidence=" << options.minimum_confidence
              << " model_input_size=" << options.model_input_size
              << " iou_threshold=" << kMatchIouThreshold
              << " tp=" << counters.true_positive << " fp=" << counters.false_positive << " fn=" << counters.false_negative
              << " precision=" << precision << " recall=" << recall << " f1=" << f1 << " matched_mean_iou=" << mean_iou
              << " ap50_class0=" << format_optional_metric(ap50)
              << " map50_95_class0=" << format_optional_metric(map50_95) << '\n';
    if (options.require_complete && counters.evaluated_frames != counters.expected_frames) {
        std::cerr << "event=dataset_evaluation_failed reason=incomplete_trace_coverage\n";
        return 4;
    }
    return 0;
}
