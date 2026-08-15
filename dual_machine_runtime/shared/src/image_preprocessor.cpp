#include "vfdual/image_preprocessor.hpp"

#include <algorithm>
#include <array>
#include <cmath>

#if defined(__aarch64__) || defined(__ARM_NEON)
#include <arm_neon.h>
#endif

namespace vfdual {
namespace {
constexpr std::uint32_t kLegacyModelSide = 320;
constexpr std::uint32_t kAiTransportWidth = 640;
constexpr std::uint32_t kAiTransportHeight = 360;
constexpr std::int32_t kFixedPointShift = 12;
constexpr std::int32_t kFixedPointRound = 1 << (kFixedPointShift - 1);

struct YuvFixedPointCoefficients {
    std::int32_t red_v;
    std::int32_t green_u;
    std::int32_t green_v;
    std::int32_t blue_u;
};

constexpr YuvFixedPointCoefficients kBt601Fixed{6537, 1605, 3331, 8263};
constexpr YuvFixedPointCoefficients kBt709Fixed{7343, 873, 2183, 8652};

void put_u16_le(std::span<std::uint8_t> destination, std::size_t offset, std::uint8_t rgb) noexcept {
    const std::uint16_t value = static_cast<std::uint16_t>(rgb) * 257;
    destination[offset] = static_cast<std::uint8_t>(value & 0xff); destination[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}
[[nodiscard]] std::uint8_t clamp_byte(float value) noexcept { return static_cast<std::uint8_t>(std::clamp(std::lround(value), 0l, 255l)); }
[[nodiscard]] std::uint8_t clamp_fixed_byte(std::int32_t value) noexcept {
    if (value <= 0) return 0;
    constexpr std::int32_t kMaximumFixedByte = 255 << kFixedPointShift;
    if (value >= kMaximumFixedByte) return 255;
    return static_cast<std::uint8_t>((value + kFixedPointRound) >> kFixedPointShift);
}

inline void yuv_to_rgb_fixed(
    std::uint8_t y,
    std::uint8_t u,
    std::uint8_t v,
    const YuvFixedPointCoefficients& coefficients,
    std::uint8_t& red,
    std::uint8_t& green,
    std::uint8_t& blue) noexcept {
    // The floating point reference is BT.601/709 limited range.  A 12-bit
    // fixed-point representation is within one output level of that reference
    // while avoiding more than 300,000 floating-point conversions per frame.
    const std::int32_t luma = std::max(0, static_cast<std::int32_t>(y) - 16) * 4769;
    const std::int32_t chroma_u = static_cast<std::int32_t>(u) - 128;
    const std::int32_t chroma_v = static_cast<std::int32_t>(v) - 128;
    red = clamp_fixed_byte(luma + coefficients.red_v * chroma_v);
    green = clamp_fixed_byte(luma - coefficients.green_u * chroma_u - coefficients.green_v * chroma_v);
    blue = clamp_fixed_byte(luma + coefficients.blue_u * chroma_u);
}

inline void write_rgb_u16_bytes(
    std::uint8_t* destination,
    std::uint8_t red,
    std::uint8_t green,
    std::uint8_t blue) noexcept {
    // QNN consumes UINT16 with scale 1/65535. byte*257 has identical low and
    // high bytes, so write those bytes directly without a multiply or aliasing.
    destination[0] = red;
    destination[1] = red;
    destination[2] = green;
    destination[3] = green;
    destination[4] = blue;
    destination[5] = blue;
}
[[nodiscard]] const std::uint8_t* plane_at(const std::uint8_t* plane, std::uint32_t row_stride, std::uint32_t pixel_stride, std::uint32_t x, std::uint32_t y) noexcept {
    return plane + static_cast<std::size_t>(y) * row_stride + static_cast<std::size_t>(x) * pixel_stride;
}
[[nodiscard]] std::uint8_t sample_bilinear(const std::uint8_t* plane, std::uint32_t row_stride, std::uint32_t pixel_stride,
                                           std::uint32_t width, std::uint32_t height, float x, float y) noexcept {
    x = std::clamp(x, 0.0f, static_cast<float>(width - 1)); y = std::clamp(y, 0.0f, static_cast<float>(height - 1));
    const auto left = static_cast<std::uint32_t>(x); const auto top = static_cast<std::uint32_t>(y);
    const auto right = std::min(left + 1, width - 1); const auto bottom = std::min(top + 1, height - 1);
    const float horizontal = x - left; const float vertical = y - top;
    const float upper = *plane_at(plane, row_stride, pixel_stride, left, top) * (1.0f - horizontal) + *plane_at(plane, row_stride, pixel_stride, right, top) * horizontal;
    const float lower = *plane_at(plane, row_stride, pixel_stride, left, bottom) * (1.0f - horizontal) + *plane_at(plane, row_stride, pixel_stride, right, bottom) * horizontal;
    return clamp_byte(upper * (1.0f - vertical) + lower * vertical);
}
void yuv_to_rgb(std::uint8_t y, std::uint8_t u, std::uint8_t v, YuvColorMatrix matrix, std::uint8_t& red, std::uint8_t& green, std::uint8_t& blue) noexcept {
    const float luma = std::max(0, static_cast<int>(y) - 16) * 1.164383f;
    const float chroma_u = static_cast<int>(u) - 128.0f;
    const float chroma_v = static_cast<int>(v) - 128.0f;
    if (matrix == YuvColorMatrix::bt709_limited) {
        red = clamp_byte(luma + 1.792741f * chroma_v);
        green = clamp_byte(luma - 0.213249f * chroma_u - 0.532909f * chroma_v);
        blue = clamp_byte(luma + 2.112402f * chroma_u);
        return;
    }
    red = clamp_byte(luma + 1.596027f * chroma_v);
    green = clamp_byte(luma - 0.391762f * chroma_u - 0.812968f * chroma_v);
    blue = clamp_byte(luma + 2.017232f * chroma_u);
}

void preprocess_native_square_scalar(
    const Yuv420ImageView& source,
    YuvColorMatrix matrix,
    std::uint32_t model_side,
    std::span<std::uint8_t> destination) noexcept {
    const auto& coefficients = matrix == YuvColorMatrix::bt709_limited ? kBt709Fixed : kBt601Fixed;
    const std::uint32_t chroma_side = model_side / 2U;
    for (std::uint32_t output_y = 0; output_y < model_side; output_y += 2U) {
        const auto* y_row_0 = source.y + static_cast<std::size_t>(output_y) * source.y_row_stride;
        const auto* y_row_1 = source.y + static_cast<std::size_t>(output_y + 1U) * source.y_row_stride;
        const std::uint32_t chroma_y = output_y / 2U;
        const std::uint32_t bottom_chroma_y = std::min(chroma_y + 1U, chroma_side - 1U);
        auto* output_row_0 = destination.data() + static_cast<std::size_t>(output_y) * model_side * 6U;
        auto* output_row_1 = output_row_0 + static_cast<std::size_t>(model_side) * 6U;
        for (std::uint32_t output_x = 0; output_x < model_side; output_x += 2U) {
            const std::uint32_t chroma_x = output_x / 2U;
            const std::uint32_t right_chroma_x = std::min(chroma_x + 1U, chroma_side - 1U);
            const auto interpolate_chroma = [&](const std::uint8_t* plane, std::uint32_t row_stride,
                                                std::uint32_t pixel_stride) noexcept {
                const unsigned upper_left = *plane_at(plane, row_stride, pixel_stride, chroma_x, chroma_y);
                const unsigned upper_right = *plane_at(plane, row_stride, pixel_stride, right_chroma_x, chroma_y);
                const unsigned lower_left = *plane_at(plane, row_stride, pixel_stride, chroma_x, bottom_chroma_y);
                const unsigned lower_right = *plane_at(plane, row_stride, pixel_stride, right_chroma_x, bottom_chroma_y);
                return std::array<std::uint8_t, 4>{
                    static_cast<std::uint8_t>(upper_left),
                    static_cast<std::uint8_t>((upper_left + upper_right + 1U) / 2U),
                    static_cast<std::uint8_t>((upper_left + lower_left + 1U) / 2U),
                    static_cast<std::uint8_t>((upper_left + upper_right + lower_left + lower_right + 2U) / 4U)};
            };
            const auto u = interpolate_chroma(source.u, source.u_row_stride, source.u_pixel_stride);
            const auto v = interpolate_chroma(source.v, source.v_row_stride, source.v_pixel_stride);
            const std::array<std::uint8_t, 4> luma{
                y_row_0[output_x], y_row_0[output_x + 1U],
                y_row_1[output_x], y_row_1[output_x + 1U]};
            std::array<std::uint8_t*, 4> output{
                output_row_0 + static_cast<std::size_t>(output_x) * 6U,
                output_row_0 + static_cast<std::size_t>(output_x + 1U) * 6U,
                output_row_1 + static_cast<std::size_t>(output_x) * 6U,
                output_row_1 + static_cast<std::size_t>(output_x + 1U) * 6U};
            for (std::size_t pixel = 0; pixel < output.size(); ++pixel) {
                std::uint8_t red{}, green{}, blue{};
                yuv_to_rgb_fixed(luma[pixel], u[pixel], v[pixel], coefficients, red, green, blue);
                write_rgb_u16_bytes(output[pixel], red, green, blue);
            }
        }
    }
}

#if defined(__aarch64__) || defined(__ARM_NEON)
[[nodiscard]] inline uint8x8_t fixed_rgb_to_u8(
    int32x4_t low,
    int32x4_t high) noexcept {
    const int16x8_t rounded = vcombine_s16(
        vqmovn_s32(vrshrq_n_s32(low, kFixedPointShift)),
        vqmovn_s32(vrshrq_n_s32(high, kFixedPointShift)));
    return vqmovun_s16(rounded);
}

inline void convert_store_neon_8(
    const std::uint8_t* y_source,
    uint8x8_t u_values,
    uint8x8_t v_values,
    const YuvFixedPointCoefficients& coefficients,
    std::uint8_t* destination) noexcept {
    const uint16x8_t y_unsigned = vqsubq_u16(vmovl_u8(vld1_u8(y_source)), vdupq_n_u16(16U));
    const int16x8_t y_values = vreinterpretq_s16_u16(y_unsigned);
    const int16x8_t u_signed = vsubq_s16(
        vreinterpretq_s16_u16(vmovl_u8(u_values)), vdupq_n_s16(128));
    const int16x8_t v_signed = vsubq_s16(
        vreinterpretq_s16_u16(vmovl_u8(v_values)), vdupq_n_s16(128));

    int32x4_t luma_low = vmull_n_s16(vget_low_s16(y_values), 4769);
    int32x4_t luma_high = vmull_n_s16(vget_high_s16(y_values), 4769);
    int32x4_t red_low = vmlal_n_s16(luma_low, vget_low_s16(v_signed), coefficients.red_v);
    int32x4_t red_high = vmlal_n_s16(luma_high, vget_high_s16(v_signed), coefficients.red_v);
    int32x4_t green_low = vmlsl_n_s16(luma_low, vget_low_s16(u_signed), coefficients.green_u);
    green_low = vmlsl_n_s16(green_low, vget_low_s16(v_signed), coefficients.green_v);
    int32x4_t green_high = vmlsl_n_s16(luma_high, vget_high_s16(u_signed), coefficients.green_u);
    green_high = vmlsl_n_s16(green_high, vget_high_s16(v_signed), coefficients.green_v);
    int32x4_t blue_low = vmlal_n_s16(luma_low, vget_low_s16(u_signed), coefficients.blue_u);
    int32x4_t blue_high = vmlal_n_s16(luma_high, vget_high_s16(u_signed), coefficients.blue_u);

    const uint8x8_t red = fixed_rgb_to_u8(red_low, red_high);
    const uint8x8_t green = fixed_rgb_to_u8(green_low, green_high);
    const uint8x8_t blue = fixed_rgb_to_u8(blue_low, blue_high);
    uint16x8x3_t rgb_u16{};
    rgb_u16.val[0] = vmulq_n_u16(vmovl_u8(red), 257U);
    rgb_u16.val[1] = vmulq_n_u16(vmovl_u8(green), 257U);
    rgb_u16.val[2] = vmulq_n_u16(vmovl_u8(blue), 257U);
    vst3q_u16(reinterpret_cast<std::uint16_t*>(destination), rgb_u16);
}

[[nodiscard]] bool preprocess_native_square_neon(
    const Yuv420ImageView& source,
    YuvColorMatrix matrix,
    std::uint32_t model_side,
    std::span<std::uint8_t> destination) noexcept {
    // Qualcomm MediaCodec exposes the inference buffer as NV12 here. Keep a
    // portable scalar path for other flexible-YUV layouts.
    if (source.u_pixel_stride != 2U || source.v_pixel_stride != 2U ||
        source.v != source.u + 1U || source.u_row_stride != source.v_row_stride ||
        source.u_row_stride < model_side || (model_side % 16U) != 0U) {
        return false;
    }
    const auto& coefficients = matrix == YuvColorMatrix::bt709_limited ? kBt709Fixed : kBt601Fixed;
    const std::uint32_t chroma_side = model_side / 2U;
    for (std::uint32_t output_y = 0; output_y < model_side; output_y += 2U) {
        const auto* y_row_0 = source.y + static_cast<std::size_t>(output_y) * source.y_row_stride;
        const auto* y_row_1 = source.y + static_cast<std::size_t>(output_y + 1U) * source.y_row_stride;
        const std::uint32_t chroma_y = output_y / 2U;
        const std::uint32_t bottom_chroma_y = std::min(chroma_y + 1U, chroma_side - 1U);
        const auto* uv_top = source.u + static_cast<std::size_t>(chroma_y) * source.u_row_stride;
        const auto* uv_bottom = source.u + static_cast<std::size_t>(bottom_chroma_y) * source.u_row_stride;
        auto* output_row_0 = destination.data() + static_cast<std::size_t>(output_y) * model_side * 6U;
        auto* output_row_1 = output_row_0 + static_cast<std::size_t>(model_side) * 6U;
        for (std::uint32_t output_x = 0; output_x < model_side; output_x += 16U) {
            const std::uint32_t chroma_x = output_x / 2U;
            const auto top = vld2_u8(uv_top + static_cast<std::size_t>(chroma_x) * 2U);
            const auto bottom = vld2_u8(uv_bottom + static_cast<std::size_t>(chroma_x) * 2U);
            uint8x8_t top_u_next{};
            uint8x8_t top_v_next{};
            uint8x8_t bottom_u_next{};
            uint8x8_t bottom_v_next{};
            if (chroma_x + 8U < chroma_side) {
                const auto top_next = vld2_u8(uv_top + static_cast<std::size_t>(chroma_x + 1U) * 2U);
                const auto bottom_next = vld2_u8(uv_bottom + static_cast<std::size_t>(chroma_x + 1U) * 2U);
                top_u_next = top_next.val[0];
                top_v_next = top_next.val[1];
                bottom_u_next = bottom_next.val[0];
                bottom_v_next = bottom_next.val[1];
            } else {
                top_u_next = vext_u8(top.val[0], vdup_n_u8(vget_lane_u8(top.val[0], 7)), 1);
                top_v_next = vext_u8(top.val[1], vdup_n_u8(vget_lane_u8(top.val[1], 7)), 1);
                bottom_u_next = vext_u8(bottom.val[0], vdup_n_u8(vget_lane_u8(bottom.val[0], 7)), 1);
                bottom_v_next = vext_u8(bottom.val[1], vdup_n_u8(vget_lane_u8(bottom.val[1], 7)), 1);
            }

            const auto top_u_interleaved = vzip_u8(top.val[0], vrhadd_u8(top.val[0], top_u_next));
            const auto top_v_interleaved = vzip_u8(top.val[1], vrhadd_u8(top.val[1], top_v_next));
            const uint8x8_t vertical_u = vrhadd_u8(top.val[0], bottom.val[0]);
            const uint8x8_t vertical_v = vrhadd_u8(top.val[1], bottom.val[1]);
            const uint8x8_t center_u = vrhadd_u8(
                vrhadd_u8(top.val[0], top_u_next), vrhadd_u8(bottom.val[0], bottom_u_next));
            const uint8x8_t center_v = vrhadd_u8(
                vrhadd_u8(top.val[1], top_v_next), vrhadd_u8(bottom.val[1], bottom_v_next));
            const auto bottom_u_interleaved = vzip_u8(vertical_u, center_u);
            const auto bottom_v_interleaved = vzip_u8(vertical_v, center_v);
            const std::size_t y_offset = output_x;
            const std::size_t output_offset = static_cast<std::size_t>(output_x) * 6U;
            convert_store_neon_8(y_row_0 + y_offset, top_u_interleaved.val[0], top_v_interleaved.val[0],
                                 coefficients, output_row_0 + output_offset);
            convert_store_neon_8(y_row_0 + y_offset + 8U, top_u_interleaved.val[1], top_v_interleaved.val[1],
                                 coefficients, output_row_0 + output_offset + 48U);
            convert_store_neon_8(y_row_1 + y_offset, bottom_u_interleaved.val[0], bottom_v_interleaved.val[0],
                                 coefficients, output_row_1 + output_offset);
            convert_store_neon_8(y_row_1 + y_offset + 8U, bottom_u_interleaved.val[1], bottom_v_interleaved.val[1],
                                 coefficients, output_row_1 + output_offset + 48U);
        }
    }
    return true;
}
#endif

void preprocess_native_square(
    const Yuv420ImageView& source,
    YuvColorMatrix matrix,
    std::uint32_t model_side,
    std::span<std::uint8_t> destination) noexcept {
#if defined(__aarch64__) || defined(__ARM_NEON)
    if (preprocess_native_square_neon(source, matrix, model_side, destination)) return;
#endif
    preprocess_native_square_scalar(source, matrix, model_side, destination);
}

// The host's AI transport profile is 640x360 H.264.  Its 16:9 frame maps to
// 320x180 within the model's letterbox exactly at 2:1.  Retain the generic
// bilinear output mathematically, but replace repeated float coordinate work
// with the equivalent integer weights.  Any other source size uses the
// generic implementation below.
[[nodiscard]] std::uint8_t sample_half_scale_luma(
    const Yuv420ImageView& source, std::uint32_t output_x, std::uint32_t output_y) noexcept {
    const std::uint32_t source_x = output_x * 2U;
    const std::uint32_t source_y = output_y * 2U;
    const auto upper_left = *plane_at(source.y, source.y_row_stride, 1, source_x, source_y);
    const auto upper_right = *plane_at(source.y, source.y_row_stride, 1, source_x + 1U, source_y);
    const auto lower_left = *plane_at(source.y, source.y_row_stride, 1, source_x, source_y + 1U);
    const auto lower_right = *plane_at(source.y, source.y_row_stride, 1, source_x + 1U, source_y + 1U);
    return static_cast<std::uint8_t>((upper_left + upper_right + lower_left + lower_right + 2U) / 4U);
}

[[nodiscard]] std::uint8_t sample_quarter_chroma(
    const std::uint8_t* plane, std::uint32_t row_stride, std::uint32_t pixel_stride,
    std::uint32_t output_x, std::uint32_t output_y) noexcept {
    constexpr std::uint32_t kChromaWidth = kAiTransportWidth / 2U;
    constexpr std::uint32_t kChromaHeight = kAiTransportHeight / 2U;
    const auto upper_left = *plane_at(plane, row_stride, pixel_stride, output_x, output_y);
    const bool right_edge = output_x + 1U == kChromaWidth;
    const bool bottom_edge = output_y + 1U == kChromaHeight;
    if (right_edge && bottom_edge) return upper_left;
    if (right_edge) {
        const auto lower_left = *plane_at(plane, row_stride, pixel_stride, output_x, output_y + 1U);
        return static_cast<std::uint8_t>((3U * upper_left + lower_left + 2U) / 4U);
    }
    const auto upper_right = *plane_at(plane, row_stride, pixel_stride, output_x + 1U, output_y);
    if (bottom_edge) return static_cast<std::uint8_t>((3U * upper_left + upper_right + 2U) / 4U);
    const auto lower_left = *plane_at(plane, row_stride, pixel_stride, output_x, output_y + 1U);
    const auto lower_right = *plane_at(plane, row_stride, pixel_stride, output_x + 1U, output_y + 1U);
    return static_cast<std::uint8_t>((9U * upper_left + 3U * upper_right + 3U * lower_left + lower_right + 8U) / 16U);
}

void preprocess_ai_transport_640x360(
    const Yuv420ImageView& source, YuvColorMatrix matrix, std::span<std::uint8_t> destination) noexcept {
    // byte*257 for letterbox RGB value 114 is little-endian 0x72, 0x72.
    std::fill(destination.begin(), destination.end(), std::uint8_t{114});
    constexpr std::uint32_t kResizedHeight = kAiTransportHeight / 2U;
    constexpr std::uint32_t kPadY = (kLegacyModelSide - kResizedHeight) / 2U;
    for (std::uint32_t output_y = 0; output_y < kResizedHeight; ++output_y) {
        for (std::uint32_t output_x = 0; output_x < kLegacyModelSide; ++output_x) {
            const auto y = sample_half_scale_luma(source, output_x, output_y);
            const auto u = sample_quarter_chroma(source.u, source.u_row_stride, source.u_pixel_stride, output_x, output_y);
            const auto v = sample_quarter_chroma(source.v, source.v_row_stride, source.v_pixel_stride, output_x, output_y);
            std::uint8_t red{}, green{}, blue{};
            yuv_to_rgb(y, u, v, matrix, red, green, blue);
            const auto destination_offset = (static_cast<std::size_t>(kPadY + output_y) * kLegacyModelSide + output_x) * 6U;
            put_u16_le(destination, destination_offset, red);
            put_u16_le(destination, destination_offset + 2U, green);
            put_u16_le(destination, destination_offset + 4U, blue);
        }
    }
}
}  // namespace

bool make_yuv420_image_view(
    const Yuv420PlaneView& y,
    const Yuv420PlaneView& u,
    const Yuv420PlaneView& v,
    std::uint32_t image_width,
    std::uint32_t image_height,
    const Yuv420CropRect& crop,
    Yuv420ImageView& output) noexcept {
    output = {};
    if (image_width == 0U || image_height == 0U || y.data == nullptr || u.data == nullptr ||
        v.data == nullptr || y.pixel_stride != 1U || y.row_stride == 0U ||
        u.row_stride == 0U || v.row_stride == 0U || u.pixel_stride == 0U ||
        v.pixel_stride == 0U || crop.left >= crop.right || crop.top >= crop.bottom ||
        crop.right > image_width || crop.bottom > image_height ||
        ((crop.left | crop.top | crop.right | crop.bottom) & 1U) != 0U) {
        return false;
    }

    const auto plane_covers = [](const Yuv420PlaneView& plane, std::uint32_t last_x,
                                 std::uint32_t last_y) noexcept {
        const std::size_t row_offset = static_cast<std::size_t>(last_y) * plane.row_stride;
        const std::size_t column_offset = static_cast<std::size_t>(last_x) * plane.pixel_stride;
        return row_offset < plane.data_size && column_offset < plane.data_size - row_offset;
    };
    const std::uint32_t chroma_left = crop.left / 2U;
    const std::uint32_t chroma_top = crop.top / 2U;
    const std::uint32_t chroma_right = crop.right / 2U;
    const std::uint32_t chroma_bottom = crop.bottom / 2U;
    if (!plane_covers(y, crop.right - 1U, crop.bottom - 1U) ||
        !plane_covers(u, chroma_right - 1U, chroma_bottom - 1U) ||
        !plane_covers(v, chroma_right - 1U, chroma_bottom - 1U)) {
        return false;
    }

    output = {
        y.data + static_cast<std::size_t>(crop.top) * y.row_stride + crop.left,
        u.data + static_cast<std::size_t>(chroma_top) * u.row_stride +
            static_cast<std::size_t>(chroma_left) * u.pixel_stride,
        v.data + static_cast<std::size_t>(chroma_top) * v.row_stride +
            static_cast<std::size_t>(chroma_left) * v.pixel_stride,
        crop.right - crop.left,
        crop.bottom - crop.top,
        y.row_stride,
        u.row_stride,
        v.row_stride,
        u.pixel_stride,
        v.pixel_stride};
    return true;
}

bool preprocess_yuv420_to_model_rgb(
    const Yuv420ImageView& source,
    YuvColorMatrix matrix,
    const ModelInputDimensions& model_input,
    std::span<std::uint8_t> destination,
    LetterboxTransform& transform) noexcept {
    if (source.y == nullptr || source.u == nullptr || source.v == nullptr ||
        source.width == 0U || source.height == 0U || model_input.width == 0U ||
        model_input.height == 0U || model_input.channels != 3U ||
        model_input.bytes_per_channel != 2U ||
        destination.size() != model_input_bytes(model_input)) {
        return false;
    }
    const auto chroma_width = (source.width + 1U) / 2U;
    if (source.y_row_stride < source.width || source.u_pixel_stride == 0 || source.v_pixel_stride == 0 ||
        source.u_row_stride < (chroma_width - 1U) * source.u_pixel_stride + 1U ||
        source.v_row_stride < (chroma_width - 1U) * source.v_pixel_stride + 1U) return false;
    if (model_input.width == model_input.height && source.width == model_input.width &&
        source.height == model_input.height && (model_input.width % 2U) == 0U) {
        preprocess_native_square(source, matrix, model_input.width, destination);
        transform = LetterboxTransform{
            1.0f, 0.0f, 0.0f, model_input.width, model_input.height};
        return true;
    }
    if (model_input.width == kLegacyModelSide && model_input.height == kLegacyModelSide &&
        source.width == kAiTransportWidth && source.height == kAiTransportHeight) {
        preprocess_ai_transport_640x360(source, matrix, destination);
        transform = LetterboxTransform{0.5f, 0.0f, 70.0f, kAiTransportWidth, kAiTransportHeight};
        return true;
    }
    const float scale = std::min(
        static_cast<float>(model_input.width) / source.width,
        static_cast<float>(model_input.height) / source.height);
    const auto resized_width = static_cast<std::uint32_t>(std::lround(source.width * scale));
    const auto resized_height = static_cast<std::uint32_t>(std::lround(source.height * scale));
    const auto x0 = static_cast<std::uint32_t>(
        std::lround((model_input.width - resized_width) / 2.0f - 0.1f));
    const auto y0 = static_cast<std::uint32_t>(
        std::lround((model_input.height - resized_height) / 2.0f - 0.1f));
    for (std::size_t offset = 0; offset < destination.size(); offset += 2) put_u16_le(destination, offset, 114);
    for (std::uint32_t output_y = 0; output_y < resized_height; ++output_y) {
        for (std::uint32_t output_x = 0; output_x < resized_width; ++output_x) {
            const float source_x = (static_cast<float>(output_x) + 0.5f) * source.width / resized_width - 0.5f;
            const float source_y = (static_cast<float>(output_y) + 0.5f) * source.height / resized_height - 0.5f;
            const auto y = sample_bilinear(source.y, source.y_row_stride, 1, source.width, source.height, source_x, source_y);
            const auto chroma_height = (source.height + 1) / 2;
            const auto u = sample_bilinear(source.u, source.u_row_stride, source.u_pixel_stride, chroma_width, chroma_height, source_x / 2.0f, source_y / 2.0f);
            const auto v = sample_bilinear(source.v, source.v_row_stride, source.v_pixel_stride, chroma_width, chroma_height, source_x / 2.0f, source_y / 2.0f);
            std::uint8_t red{}, green{}, blue{}; yuv_to_rgb(y, u, v, matrix, red, green, blue);
            const auto destination_offset =
                (static_cast<std::size_t>(y0 + output_y) * model_input.width +
                 (x0 + output_x)) * 6U;
            put_u16_le(destination, destination_offset, red); put_u16_le(destination, destination_offset + 2, green); put_u16_le(destination, destination_offset + 4, blue);
        }
    }
    transform = LetterboxTransform{
        scale,
        (model_input.width - resized_width) / 2.0f,
        (model_input.height - resized_height) / 2.0f,
        source.width,
        source.height};
    return true;
}

bool preprocess_yuv420_to_model_rgb(
    const Yuv420ImageView& source,
    YuvColorMatrix matrix,
    std::span<std::uint8_t> destination,
    LetterboxTransform& transform) noexcept {
    constexpr ModelInputDimensions kLegacyInput{
        .width = kLegacyModelSide,
        .height = kLegacyModelSide,
        .channels = 3U,
        .bytes_per_channel = 2U};
    return preprocess_yuv420_to_model_rgb(
        source, matrix, kLegacyInput, destination, transform);
}
}  // namespace vfdual
