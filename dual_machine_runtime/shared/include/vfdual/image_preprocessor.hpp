#pragma once

#include "vfdual/model_contract.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace vfdual {

enum class YuvColorMatrix { bt601_limited, bt709_limited };

struct Yuv420ImageView {
    const std::uint8_t* y{};
    const std::uint8_t* u{};
    const std::uint8_t* v{};
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t y_row_stride{};
    std::uint32_t u_row_stride{};
    std::uint32_t v_row_stride{};
    std::uint32_t u_pixel_stride{1};
    std::uint32_t v_pixel_stride{1};
};

struct Yuv420PlaneView {
    const std::uint8_t* data{};
    std::size_t data_size{};
    std::uint32_t row_stride{};
    std::uint32_t pixel_stride{};
};

struct Yuv420CropRect {
    std::uint32_t left{};
    std::uint32_t top{};
    std::uint32_t right{};
    std::uint32_t bottom{};
};

/** Builds a cropped 4:2:0 view after proving every addressed plane byte is in bounds.
 * Odd crop coordinates are rejected because their chroma siting is ambiguous. */
[[nodiscard]] bool make_yuv420_image_view(
    const Yuv420PlaneView& y,
    const Yuv420PlaneView& u,
    const Yuv420PlaneView& v,
    std::uint32_t image_width,
    std::uint32_t image_height,
    const Yuv420CropRect& crop,
    Yuv420ImageView& output) noexcept;

struct LetterboxTransform {
    float scale{};
    float pad_x{};
    float pad_y{};
    std::uint32_t source_width{};
    std::uint32_t source_height{};
};

/** Converts decoded YUV420 to the selected W8A16 QNN model's RGB NHWC U16 contract.
 * The model scale is 1/65535, so each RGB byte is encoded exactly as byte*257. */
[[nodiscard]] bool preprocess_yuv420_to_model_rgb(
    const Yuv420ImageView& source,
    YuvColorMatrix matrix,
    const ModelInputDimensions& model_input,
    std::span<std::uint8_t> destination,
    LetterboxTransform& transform) noexcept;

/** Compatibility overload for the retired 320x320 runtime and its fixtures. */
[[nodiscard]] bool preprocess_yuv420_to_model_rgb(
    const Yuv420ImageView& source,
    YuvColorMatrix matrix,
    std::span<std::uint8_t> destination,
    LetterboxTransform& transform) noexcept;

}  // namespace vfdual
