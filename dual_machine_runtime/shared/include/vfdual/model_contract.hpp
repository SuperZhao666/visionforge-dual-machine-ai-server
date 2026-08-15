#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace vfdual {

enum class GameModelId : std::uint8_t {
    valorant_yellow_416_v11s_no_flash,
    overwatch2_416_yolov5,
    delta_force_416_v8s,
    counter_strike_2_vombit_416_v8s,
};

inline constexpr std::uint32_t kNoModelClass = 0xffffffffU;

struct ModelInputDimensions {
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t channels{};
    std::uint32_t bytes_per_channel{};
};

struct SplitYoloOutputDimensions {
    std::uint32_t anchor_count{};
    std::uint32_t class_count{};
};

struct MobileTrackingConfidenceContract {
    float high_confidence_threshold{};
    float low_confidence_threshold{};
    float new_track_confidence_threshold{};
};

struct MobileAimTargetContract {
    std::string_view token{};
    std::uint32_t body_class_id{};
    std::uint32_t head_class_id{kNoModelClass};
    std::uint32_t selected_class_id{};
    bool uses_head_box{};
    bool uses_geometric_head{};
    float target_y_ratio{0.50F};
};

inline constexpr std::size_t kMaximumMobileAimTargets = 9U;

struct MobileModelContract {
    GameModelId id{};
    std::string_view token{};
    std::string_view qnn_library{};
    ModelInputDimensions input{};
    SplitYoloOutputDimensions output{};
    std::uint32_t body_class_id{};
    std::uint32_t head_class_id{};
    float default_confidence{};
    float nms_iou{};
    MobileTrackingConfidenceContract tracking_confidence{};
    std::array<std::string_view, 5> class_names{};
    std::array<MobileAimTargetContract, kMaximumMobileAimTargets> aim_targets{};
    std::size_t aim_target_count{};
};

inline constexpr MobileModelContract kValorantYellow416V11sNoFlash{
    .id = GameModelId::valorant_yellow_416_v11s_no_flash,
    .token = "valorant-yellow-416-v11s-no-flash",
    .qnn_library = "libvalorant_416_v11s_no_flash_w8a16.so",
    .input = {.width = 416U, .height = 416U, .channels = 3U, .bytes_per_channel = 2U},
    .output = {.anchor_count = 3549U, .class_count = 5U},
    .body_class_id = 0U,
    .head_class_id = 1U,
    .default_confidence = 0.27F,
    .nms_iou = 0.45F,
    .tracking_confidence = {
        .high_confidence_threshold = 0.50F,
        .low_confidence_threshold = 0.25F,
        .new_track_confidence_threshold = 0.50F,
    },
    .class_names = {"body", "head", "none", "utility", "flash"},
    .aim_targets = {{
        {.token = "body", .body_class_id = 0U, .head_class_id = 1U,
         .selected_class_id = 0U, .target_y_ratio = 0.50F},
        {.token = "head", .body_class_id = 0U, .head_class_id = 1U,
         .selected_class_id = 1U, .uses_head_box = true,
         .target_y_ratio = 0.50F},
    }},
    .aim_target_count = 2U,
};

inline constexpr MobileModelContract kOverwatch2Yolov5_416{
    .id = GameModelId::overwatch2_416_yolov5,
    .token = "overwatch2-416-yolov5",
    .qnn_library = "libow2_416_w8a16.so",
    .input = {.width = 416U, .height = 416U, .channels = 3U, .bytes_per_channel = 2U},
    .output = {.anchor_count = 3549U, .class_count = 2U},
    .body_class_id = 0U,
    .head_class_id = kNoModelClass,
    .default_confidence = 0.20F,
    .nms_iou = 0.45F,
    .tracking_confidence = {
        .high_confidence_threshold = 0.40F,
        .low_confidence_threshold = 0.20F,
        .new_track_confidence_threshold = 0.40F,
    },
    .class_names = {"enemy_body", "non_enemy_body", "", "", ""},
    .aim_targets = {{
        {.token = "body", .body_class_id = 0U,
         .head_class_id = kNoModelClass, .selected_class_id = 0U,
         .target_y_ratio = 0.50F},
        {.token = "head", .body_class_id = 0U,
         .head_class_id = kNoModelClass, .selected_class_id = 0U,
         .uses_geometric_head = true, .target_y_ratio = 0.18F},
    }},
    .aim_target_count = 2U,
};

inline constexpr MobileModelContract kDeltaForce416V8s{
    .id = GameModelId::delta_force_416_v8s,
    .token = "delta-force-416-v8s",
    .qnn_library = "libdelta_416_v8s_w8a16.so",
    .input = {.width = 416U, .height = 416U, .channels = 3U, .bytes_per_channel = 2U},
    .output = {.anchor_count = 3549U, .class_count = 5U},
    .body_class_id = 0U,
    .head_class_id = 1U,
    .default_confidence = 0.20F,
    .nms_iou = 0.70F,
    .tracking_confidence = {
        .high_confidence_threshold = 0.50F,
        .low_confidence_threshold = 0.25F,
        .new_track_confidence_threshold = 0.50F,
    },
    .class_names = {"body", "head", "teammate", "ai", "crosshair"},
    .aim_targets = {{
        {.token = "body", .body_class_id = 0U, .head_class_id = 1U,
         .selected_class_id = 0U, .target_y_ratio = 0.50F},
        {.token = "head", .body_class_id = 0U, .head_class_id = 1U,
         .selected_class_id = 1U, .uses_head_box = true,
         .target_y_ratio = 0.50F},
        {.token = "teammate", .body_class_id = 0U, .head_class_id = 1U,
         .selected_class_id = 2U, .target_y_ratio = 0.50F},
        {.token = "ai", .body_class_id = 0U, .head_class_id = 1U,
         .selected_class_id = 3U, .target_y_ratio = 0.50F},
        {.token = "crosshair", .body_class_id = 0U, .head_class_id = 1U,
         .selected_class_id = 4U, .target_y_ratio = 0.50F},
    }},
    .aim_target_count = 5U,
};

inline constexpr MobileModelContract kCounterStrike2Vombit416V8s{
    .id = GameModelId::counter_strike_2_vombit_416_v8s,
    .token = "counter-strike-2-vombit-416-v8s",
    .qnn_library = "libcs2_vombit_416_v8s_w8a16.so",
    .input = {.width = 416U, .height = 416U, .channels = 3U, .bytes_per_channel = 2U},
    .output = {.anchor_count = 3549U, .class_count = 4U},
    .body_class_id = 2U,
    .head_class_id = 3U,
    .default_confidence = 0.25F,
    .nms_iou = 0.45F,
    .tracking_confidence = {
        .high_confidence_threshold = 0.40F,
        .low_confidence_threshold = 0.20F,
        .new_track_confidence_threshold = 0.40F,
    },
    .class_names = {"ct_body", "ct_head", "t_body", "t_head", ""},
    .aim_targets = {{
        {.token = "ct_body", .body_class_id = 0U, .head_class_id = 1U,
         .selected_class_id = 0U, .target_y_ratio = 0.50F},
        {.token = "ct_head", .body_class_id = 0U, .head_class_id = 1U,
         .selected_class_id = 1U, .uses_head_box = true,
         .target_y_ratio = 0.50F},
        {.token = "t_body", .body_class_id = 2U, .head_class_id = 3U,
         .selected_class_id = 2U, .target_y_ratio = 0.50F},
        {.token = "t_head", .body_class_id = 2U, .head_class_id = 3U,
         .selected_class_id = 3U, .uses_head_box = true,
         .target_y_ratio = 0.50F},
    }},
    .aim_target_count = 4U,
};

[[nodiscard]] constexpr bool valid_tracking_confidence_contract(
    const MobileTrackingConfidenceContract& contract) noexcept {
    return contract.low_confidence_threshold >= 0.0F &&
           contract.low_confidence_threshold <= contract.high_confidence_threshold &&
           contract.high_confidence_threshold <= 1.0F &&
           contract.new_track_confidence_threshold >= contract.high_confidence_threshold &&
           contract.new_track_confidence_threshold <= 1.0F;
}

[[nodiscard]] constexpr bool valid_mobile_aim_target_contract(
    const MobileAimTargetContract& target,
    std::uint32_t class_count) noexcept {
    const bool class_ids_valid = !target.token.empty() &&
        target.body_class_id < class_count &&
        (target.head_class_id == kNoModelClass ||
         target.head_class_id < class_count) &&
        target.selected_class_id < class_count;
    const bool head_box_valid = !target.uses_head_box ||
        (target.head_class_id != kNoModelClass &&
         target.selected_class_id == target.head_class_id);
    const bool geometric_head_valid = !target.uses_geometric_head ||
        (!target.uses_head_box && target.head_class_id == kNoModelClass &&
         target.selected_class_id == target.body_class_id);
    return class_ids_valid && head_box_valid && geometric_head_valid &&
        target.target_y_ratio >= 0.0F && target.target_y_ratio <= 1.0F;
}

[[nodiscard]] constexpr bool valid_mobile_aim_targets(
    const MobileModelContract& model) noexcept {
    if (model.aim_target_count == 0U ||
        model.aim_target_count > model.aim_targets.size()) return false;
    for (std::size_t index = 0; index < model.aim_target_count; ++index) {
        if (!valid_mobile_aim_target_contract(
                model.aim_targets[index], model.output.class_count)) return false;
        for (std::size_t earlier = 0; earlier < index; ++earlier) {
            if (model.aim_targets[earlier].token ==
                model.aim_targets[index].token) return false;
        }
    }
    return true;
}

[[nodiscard]] constexpr bool matches_mobile_aim_target_contract(
    const MobileModelContract& model,
    std::uint32_t body_class_id,
    std::uint32_t head_class_id,
    std::uint32_t selected_class_id,
    bool uses_head_box,
    bool uses_geometric_head,
    float target_y_ratio) noexcept {
    for (std::size_t index = 0; index < model.aim_target_count; ++index) {
        const auto& target = model.aim_targets[index];
        const float ratio_delta = target.target_y_ratio > target_y_ratio
            ? target.target_y_ratio - target_y_ratio
            : target_y_ratio - target.target_y_ratio;
        if (target.body_class_id == body_class_id &&
            target.head_class_id == head_class_id &&
            target.selected_class_id == selected_class_id &&
            target.uses_head_box == uses_head_box &&
            target.uses_geometric_head == uses_geometric_head &&
            ratio_delta <= 0.0001F) return true;
    }
    return false;
}

static_assert(valid_tracking_confidence_contract(
    kValorantYellow416V11sNoFlash.tracking_confidence));
static_assert(valid_tracking_confidence_contract(
    kOverwatch2Yolov5_416.tracking_confidence));
static_assert(valid_tracking_confidence_contract(
    kDeltaForce416V8s.tracking_confidence));
static_assert(valid_tracking_confidence_contract(
    kCounterStrike2Vombit416V8s.tracking_confidence));
static_assert(valid_mobile_aim_targets(kValorantYellow416V11sNoFlash));
static_assert(valid_mobile_aim_targets(kOverwatch2Yolov5_416));
static_assert(valid_mobile_aim_targets(kDeltaForce416V8s));
static_assert(valid_mobile_aim_targets(kCounterStrike2Vombit416V8s));
static_assert(matches_mobile_aim_target_contract(
    kCounterStrike2Vombit416V8s, 0U, 1U, 1U, true, false, 0.50F));
static_assert(matches_mobile_aim_target_contract(
    kCounterStrike2Vombit416V8s, 2U, 3U, 3U, true, false, 0.50F));
static_assert(!matches_mobile_aim_target_contract(
    kCounterStrike2Vombit416V8s, 0U, 1U, 3U, true, false, 0.50F));

inline constexpr std::array<const MobileModelContract*, 4> kMobileModels{
    &kValorantYellow416V11sNoFlash,
    &kOverwatch2Yolov5_416,
    &kDeltaForce416V8s,
    &kCounterStrike2Vombit416V8s,
};

inline constexpr const MobileModelContract& kDefaultMobileModel =
    kValorantYellow416V11sNoFlash;

[[nodiscard]] constexpr const MobileModelContract* find_mobile_model(
    std::string_view token) noexcept {
    for (const MobileModelContract* model : kMobileModels) {
        if (model != nullptr && model->token == token) return model;
    }
    return nullptr;
}

[[nodiscard]] constexpr std::size_t model_input_bytes(
    const ModelInputDimensions& input) noexcept {
    return static_cast<std::size_t>(input.width) * input.height * input.channels *
           input.bytes_per_channel;
}

}  // namespace vfdual
