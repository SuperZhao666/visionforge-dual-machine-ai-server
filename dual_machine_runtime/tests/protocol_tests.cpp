#include "vfdual/access_unit_fragmenter.hpp"
#include "vfdual/access_unit_reassembler.hpp"
#include "vfdual/image_preprocessor.hpp"
#include "vfdual/h264_annex_b_access_units.hpp"
#include "vfdual/h264_access_unit.hpp"
#include "vfdual/mouse_button_protocol.hpp"
#include "vfdual/protocol.hpp"

#include <array>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <vector>

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
    std::exit(EXIT_FAILURE);
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

int main() {
    const vfdual::MouseButtonStatePacket button_source{0x12U, 0x1234abcdU, 9U};
    std::array<std::byte, vfdual::kMouseButtonPacketBytes> button_datagram{};
    CHECK(vfdual::encode_mouse_button_state_packet(
        button_source, button_datagram) == button_datagram.size());
    vfdual::MouseButtonStatePacket button_decoded{};
    CHECK(vfdual::decode_mouse_button_state_packet(
        button_datagram, button_decoded));
    CHECK(button_decoded.button_mask == button_source.button_mask);
    CHECK(button_decoded.session_id == button_source.session_id);
    CHECK(button_decoded.sequence == button_source.sequence);
    auto bad_button_datagram = button_datagram;
    bad_button_datagram[6] = std::byte{1U};
    CHECK(!vfdual::decode_mouse_button_state_packet(
        bad_button_datagram, button_decoded));
    CHECK(vfdual::encode_mouse_button_state_packet(
        {0x20U, 1U, 1U}, button_datagram) == 0U);
    CHECK(vfdual::encode_mouse_button_state_packet(
        {0x01U, 0U, 1U}, button_datagram) == 0U);

    const std::array<std::byte, 6> annex_b_idr{
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1},
        std::byte{0x65}, std::byte{0x80}};
    const std::array<std::byte, 6> annex_b_prediction{
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1},
        std::byte{0x41}, std::byte{0x80}};
    const std::array<std::byte, 6> avcc_idr{
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{2},
        std::byte{0x65}, std::byte{0x80}};
    CHECK(vfdual::h264_access_unit_contains_idr(annex_b_idr));
    CHECK(!vfdual::h264_access_unit_contains_idr(annex_b_prediction));
    CHECK(vfdual::h264_access_unit_contains_idr(avcc_idr));

    // Cross-language golden vector: Java and C++ must emit the exact same
    // 20-byte network-order header before any payload bytes.
    const vfdual::VideoFragment golden_source{
        {0x0102'0304'0506'0708ULL, 0x1122'3344U},
        false, 2U, 5U, {std::byte{'X'}}};
    const auto golden_packet = vfdual::encode_video_packet(golden_source);
    const std::array<std::byte, vfdual::kVideoPacketHeaderBytes> golden_header{
        std::byte{0x56}, std::byte{0x46}, std::byte{0x32}, std::byte{0x47},
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08},
        std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
        std::byte{0x00}, std::byte{0x02}, std::byte{0x00}, std::byte{0x05}};
    CHECK(golden_packet.size() == golden_header.size() + 1U);
    CHECK(std::equal(golden_header.begin(), golden_header.end(),
                     golden_packet.begin()));

    constexpr vfdual::VideoFrameIdentity identity{17U, 9U};
    const vfdual::VideoFragment source{
        identity, false, 1U, 2U,
        {std::byte{'B'}, std::byte{'C'}}};
    std::array<std::byte, vfdual::kMaxDatagramBytes> packet_storage{};
    const std::size_t packet_size = vfdual::encode_video_packet_into(
        source.identity, source.repeated_content, source.fragment_index,
        source.fragment_count, source.access_unit_part, packet_storage);
    CHECK(packet_size == vfdual::kVideoPacketHeaderBytes + 2U);
    const auto packet = vfdual::encode_video_packet(source);
    CHECK(std::equal(packet.begin(), packet.end(), packet_storage.begin()));
    CHECK(packet.size() == vfdual::kVideoPacketHeaderBytes + 2U);
    vfdual::VideoFragment decoded;
    CHECK(vfdual::decode_video_packet(packet, decoded));
    CHECK(decoded.identity == identity);
    CHECK(!decoded.repeated_content);
    CHECK(decoded.fragment_index == 1U && decoded.fragment_count == 2U);
    static_assert(vfdual::kMaxVideoFragmentsPerAccessUnit <
                  (std::numeric_limits<std::uint16_t>::max)());
    const auto excessive_fragment_count = static_cast<std::uint16_t>(
        vfdual::kMaxVideoFragmentsPerAccessUnit + 1U);
    const vfdual::VideoFragment excessive_fragment_count_source{
        {17U, 10U}, false, 0U, excessive_fragment_count,
        {std::byte{'X'}}};
    CHECK(vfdual::encode_video_packet(excessive_fragment_count_source).empty());
    auto corrupted = packet;
    corrupted[0] ^= std::byte{1};
    CHECK(!vfdual::decode_video_packet(corrupted, decoded));

    const vfdual::VideoFragment repeated_source{
        {17U, 10U}, true, 0U, 1U, {std::byte{'R'}}};
    const auto repeated_packet = vfdual::encode_video_packet(repeated_source);
    CHECK(repeated_packet[0] == std::byte{0x56});
    CHECK(repeated_packet[1] == std::byte{0x46});
    CHECK(repeated_packet[2] == std::byte{0x32});
    CHECK(repeated_packet[3] == std::byte{0x52});
    vfdual::VideoFragment repeated_decoded;
    CHECK(vfdual::decode_video_packet(repeated_packet, repeated_decoded));
    CHECK(repeated_decoded.repeated_content);
    CHECK(repeated_decoded.identity == repeated_source.identity);

    vfdual::AccessUnitReassembler reassembler;
    CHECK(reassembler.activate_epoch(17U));
    CHECK(!reassembler.push(decoded, 10U));
    const vfdual::VideoFragment first{
        identity, false, 0U, 2U, {std::byte{'A'}}};
    const auto complete = reassembler.push(first, 11U);
    CHECK(complete && complete->identity == identity &&
          complete->bytes.size() == 3U &&
          complete->bytes[0] == std::byte{'A'});
    CHECK(!reassembler.push(excessive_fragment_count_source, 12U));
    CHECK(reassembler.inflight_frame_count() == 0U);

    vfdual::AccessUnitReassembler ordered_reassembler;
    CHECK(ordered_reassembler.activate_epoch(21U));
    const vfdual::VideoFragment frame_20_first{
        {21U, 20U}, false, 0U, 2U, {std::byte{'A'}}};
    const vfdual::VideoFragment frame_21_complete{
        {21U, 21U}, false, 0U, 1U, {std::byte{'C'}}};
    const vfdual::VideoFragment frame_20_last{
        {21U, 20U}, false, 1U, 2U, {std::byte{'B'}}};
    CHECK(!ordered_reassembler.push(frame_20_first, 20U));
    CHECK(!ordered_reassembler.push(frame_21_complete, 21U));
    const auto ordered_20 = ordered_reassembler.push(frame_20_last, 22U);
    CHECK(ordered_20 && ordered_20->identity.frame_sequence == 20U);
    const auto ordered_21 = ordered_reassembler.pop_completed();
    CHECK(ordered_21 && ordered_21->identity.frame_sequence == 21U);
    CHECK(!ordered_reassembler.push(frame_20_first, 23U));
    CHECK(ordered_reassembler.inflight_frame_count() == 0U);

    // A candidate IDR may be admitted directly by the session preflight gate.
    // Seed its sequence so out-of-order prediction frames cannot overtake a
    // missing predecessor immediately after an epoch/decoder transition.
    vfdual::AccessUnitReassembler seeded_reassembler;
    CHECK(seeded_reassembler.activate_epoch(22U, 40U));
    const vfdual::VideoFragment frame_42_complete{
        {22U, 42U}, false, 0U, 1U, {std::byte{'C'}}};
    const vfdual::VideoFragment frame_41_complete{
        {22U, 41U}, false, 0U, 1U, {std::byte{'B'}}};
    CHECK(!seeded_reassembler.push(frame_42_complete, 24U));
    const auto seeded_41 = seeded_reassembler.push(frame_41_complete, 25U);
    CHECK(seeded_41 && seeded_41->identity.frame_sequence == 41U);
    const auto seeded_42 = seeded_reassembler.pop_completed();
    CHECK(seeded_42 && seeded_42->identity.frame_sequence == 42U);

    vfdual::AccessUnitReassembler conflict_reassembler;
    CHECK(conflict_reassembler.activate_epoch(30U));
    CHECK(!conflict_reassembler.push(
        {{30U, 1U}, false, 0U, 2U, {std::byte{'A'}}}, 1U));
    CHECK(!conflict_reassembler.push(
        {{30U, 1U}, false, 0U, 2U, {std::byte{'B'}}}, 2U));
    CHECK(conflict_reassembler.conflicting_duplicate_losses() == 1U);
    CHECK(conflict_reassembler.inflight_frame_count() == 0U);

    vfdual::AccessUnitReassembler bounded_reassembler(1U, 2U);
    CHECK(bounded_reassembler.activate_epoch(31U));
    CHECK(!bounded_reassembler.push(
        {{31U, 1U}, false, 0U, 2U, {std::byte{'A'}}}, 30U));
    CHECK(!bounded_reassembler.push(
        {{31U, 2U}, false, 0U, 2U, {std::byte{'B'}}}, 31U));
    CHECK(bounded_reassembler.incomplete_access_unit_losses() >= 1U);
    CHECK(bounded_reassembler.discard_expired(100U, 10U) <= 1U);

    vfdual::AccessUnitReassembler epoch_reassembler;
    CHECK(epoch_reassembler.activate_epoch(40U));
    CHECK(!epoch_reassembler.push(
        {{41U, 0U}, false, 0U, 1U, {std::byte{'X'}}}, 1U));
    CHECK(epoch_reassembler.foreign_or_retired_epoch_drops() == 1U);
    CHECK(epoch_reassembler.activate_epoch(41U));
    CHECK(epoch_reassembler.is_retired_epoch(40U));
    CHECK(!epoch_reassembler.push(
        {{40U, 1U}, false, 0U, 1U, {std::byte{'Y'}}}, 2U));
    CHECK(epoch_reassembler.foreign_or_retired_epoch_drops() == 2U);

    // Retirement must be permanent even after thousands of Host rotations.
    for (std::uint64_t value = 42U; value <= 4'096U; ++value) {
        CHECK(epoch_reassembler.activate_epoch(value));
    }
    CHECK(epoch_reassembler.retired_through() == 4'095U);
    CHECK(epoch_reassembler.is_retired_epoch(40U));
    CHECK(!epoch_reassembler.activate_epoch(40U));
    CHECK(!epoch_reassembler.push(
        {{40U, 2U}, false, 0U, 1U, {std::byte{'Z'}}}, 3U));

    // Exact byte-budget admission: one incomplete AU may consume the entire
    // budget, but a second byte must be rejected without overflow or leakage.
    vfdual::AccessUnitReassembler byte_bounded(
        4U, vfdual::kVideoPacketPayloadBytes);
    CHECK(byte_bounded.activate_epoch(50U));
    CHECK(!byte_bounded.push(
        {{50U, 1U}, false, 0U, 2U,
         std::vector<std::byte>(vfdual::kVideoPacketPayloadBytes,
                                std::byte{'A'})}, 1U));
    CHECK(byte_bounded.inflight_byte_count() ==
          vfdual::kVideoPacketPayloadBytes);
    CHECK(!byte_bounded.push(
        {{50U, 2U}, false, 0U, 2U, {std::byte{'C'}}}, 2U));
    CHECK(byte_bounded.inflight_byte_count() <=
          vfdual::kVideoPacketPayloadBytes);

    const std::array<std::byte, 5> access_unit{
        std::byte{'1'}, std::byte{'2'}, std::byte{'3'},
        std::byte{'4'}, std::byte{'5'}};
    const auto parts = vfdual::fragment_access_unit(
        {44U, 10U}, access_unit, false, 2U);
    CHECK(parts.size() == 3U && parts[2].fragment_index == 2U &&
          parts[2].access_unit_part.size() == 1U);
    const std::vector<std::byte> excessive_fragment_count_access_unit(
        (vfdual::kMaxVideoFragmentsPerAccessUnit + 1U) * 33U);
    CHECK(vfdual::fragment_access_unit(
        {44U, 11U}, excessive_fragment_count_access_unit, false, 33U).empty());
    const std::vector<std::byte> oversized_payload_access_unit(
        vfdual::kVideoPacketPayloadBytes + 1U);
    CHECK(vfdual::fragment_access_unit(
        {44U, 12U}, oversized_payload_access_unit, false,
        vfdual::kVideoPacketPayloadBytes + 1U).empty());

    // Slice headers below encode first_mb_in_slice as ue(0) and ue(1), so the
    // parser must preserve the first two slices in one access unit and split
    // the next picture at its first slice.
    const std::array<std::byte, 24> annex_b{
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}, std::byte{0x67}, std::byte{0x42},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}, std::byte{0x41}, std::byte{0x80},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}, std::byte{0x41}, std::byte{0x40},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}, std::byte{0x41}, std::byte{0x80}};
    const auto access_units = vfdual::split_h264_annex_b_access_units(annex_b);
    CHECK(access_units.size() == 2 && !access_units[0].empty() && !access_units[1].empty());

    const std::array<std::uint8_t, 4> y_plane{16, 16, 16, 16};
    const std::array<std::uint8_t, 1> chroma_plane{128};
    std::vector<std::uint8_t> model_input(320 * 320 * 3 * 2);
    vfdual::LetterboxTransform transform;
    const vfdual::Yuv420ImageView image{y_plane.data(), chroma_plane.data(), chroma_plane.data(), 2, 2, 2, 1, 1, 1, 1};
    CHECK(vfdual::preprocess_yuv420_to_model_rgb(image, vfdual::YuvColorMatrix::bt709_limited, model_input, transform));

    // The production 320x320 path consumes Qualcomm NV12-style interleaved
    // chroma and writes the W8A16 UINT16 NHWC contract without resize.
    std::vector<std::uint8_t> native_y(320U * 320U, 16U);
    std::vector<std::uint8_t> native_uv(320U * 160U, 128U);
    native_y[0] = 235U;
    const vfdual::Yuv420ImageView native_image{
        native_y.data(), native_uv.data(), native_uv.data() + 1U,
        320U, 320U, 320U, 320U, 320U, 2U, 2U};
    CHECK(vfdual::preprocess_yuv420_to_model_rgb(
        native_image, vfdual::YuvColorMatrix::bt709_limited, model_input, transform));
    CHECK(transform.scale == 1.0F && transform.pad_x == 0.0F && transform.pad_y == 0.0F);
    CHECK(model_input[0] == 255U && model_input[1] == 255U);
    CHECK(model_input[2] == 255U && model_input[3] == 255U);
    CHECK(model_input[4] == 255U && model_input[5] == 255U);
    CHECK(model_input[6] == 0U && model_input[7] == 0U);

    // The selected production profile consumes a native 416x416 frame. This
    // exercises the same no-resize path used by the phone after host capture.
    constexpr auto kProductionInput = vfdual::kDefaultMobileModel.input;
    std::vector<std::uint8_t> production_y(
        static_cast<std::size_t>(kProductionInput.width) * kProductionInput.height,
        16U);
    std::vector<std::uint8_t> production_uv(
        static_cast<std::size_t>(kProductionInput.width) *
            (kProductionInput.height / 2U),
        128U);
    production_y[0] = 235U;
    const vfdual::Yuv420ImageView production_image{
        production_y.data(), production_uv.data(), production_uv.data() + 1U,
        kProductionInput.width, kProductionInput.height,
        kProductionInput.width, kProductionInput.width, kProductionInput.width,
        2U, 2U};
    std::vector<std::uint8_t> production_model_input(
        vfdual::model_input_bytes(kProductionInput));
    CHECK(vfdual::preprocess_yuv420_to_model_rgb(
        production_image, vfdual::YuvColorMatrix::bt709_limited,
        kProductionInput, production_model_input, transform));
    CHECK(transform.scale == 1.0F && transform.pad_x == 0.0F &&
          transform.pad_y == 0.0F);
    CHECK(production_model_input[0] == 255U && production_model_input[1] == 255U);
    CHECK(production_model_input[6] == 0U && production_model_input[7] == 0U);
    CHECK(!vfdual::preprocess_yuv420_to_model_rgb(
        production_image, vfdual::YuvColorMatrix::bt709_limited,
        kProductionInput, model_input, transform));

    // YUV_420_888 may expose I420, NV12 or NV21. Plane metadata, not pointer
    // ordering assumptions, must make all three layouts produce identical RGB.
    constexpr std::uint32_t kLayoutStride = 324U;
    constexpr std::uint32_t kLayoutHeight = 320U;
    std::vector<std::uint8_t> padded_y(static_cast<std::size_t>(kLayoutStride) * kLayoutHeight, 82U);
    std::vector<std::uint8_t> i420_u(static_cast<std::size_t>(kLayoutStride / 2U) * (kLayoutHeight / 2U), 90U);
    std::vector<std::uint8_t> i420_v(static_cast<std::size_t>(kLayoutStride / 2U) * (kLayoutHeight / 2U), 240U);
    std::vector<std::uint8_t> nv12(static_cast<std::size_t>(kLayoutStride) * (kLayoutHeight / 2U));
    std::vector<std::uint8_t> nv21(nv12.size());
    for (std::size_t index = 0; index < nv12.size(); index += 2U) {
        nv12[index] = 90U; nv12[index + 1U] = 240U;
        nv21[index] = 240U; nv21[index + 1U] = 90U;
    }
    const vfdual::Yuv420CropRect full_crop{0U, 0U, 320U, 320U};
    vfdual::Yuv420ImageView i420_view;
    vfdual::Yuv420ImageView nv12_view;
    vfdual::Yuv420ImageView nv21_view;
    CHECK(vfdual::make_yuv420_image_view(
        {padded_y.data(), padded_y.size(), kLayoutStride, 1U},
        {i420_u.data(), i420_u.size(), kLayoutStride / 2U, 1U},
        {i420_v.data(), i420_v.size(), kLayoutStride / 2U, 1U},
        320U, 320U, full_crop, i420_view));
    CHECK(vfdual::make_yuv420_image_view(
        {padded_y.data(), padded_y.size(), kLayoutStride, 1U},
        {nv12.data(), nv12.size(), kLayoutStride, 2U},
        {nv12.data() + 1U, nv12.size() - 1U, kLayoutStride, 2U},
        320U, 320U, full_crop, nv12_view));
    CHECK(vfdual::make_yuv420_image_view(
        {padded_y.data(), padded_y.size(), kLayoutStride, 1U},
        {nv21.data() + 1U, nv21.size() - 1U, kLayoutStride, 2U},
        {nv21.data(), nv21.size(), kLayoutStride, 2U},
        320U, 320U, full_crop, nv21_view));
    std::vector<std::uint8_t> i420_rgb(model_input.size());
    std::vector<std::uint8_t> nv12_rgb(model_input.size());
    std::vector<std::uint8_t> nv21_rgb(model_input.size());
    CHECK(vfdual::preprocess_yuv420_to_model_rgb(i420_view, vfdual::YuvColorMatrix::bt709_limited, i420_rgb, transform));
    CHECK(vfdual::preprocess_yuv420_to_model_rgb(nv12_view, vfdual::YuvColorMatrix::bt709_limited, nv12_rgb, transform));
    CHECK(vfdual::preprocess_yuv420_to_model_rgb(nv21_view, vfdual::YuvColorMatrix::bt709_limited, nv21_rgb, transform));
    CHECK(i420_rgb == nv12_rgb && i420_rgb == nv21_rgb);

    // Matrix selection is observable for a saturated chroma sample.
    std::vector<std::uint8_t> bt601_rgb(model_input.size());
    CHECK(vfdual::preprocess_yuv420_to_model_rgb(i420_view, vfdual::YuvColorMatrix::bt601_limited, bt601_rgb, transform));
    CHECK(bt601_rgb != i420_rgb);

    // Exact-size semiplanar tails are valid; one-byte truncation and odd crop
    // coordinates are rejected before preprocessing can read out of bounds.
    vfdual::Yuv420ImageView rejected_view;
    CHECK(!vfdual::make_yuv420_image_view(
        {padded_y.data(), padded_y.size(), kLayoutStride, 1U},
        {native_uv.data(), native_uv.size(), 320U, 2U},
        {native_uv.data() + 1U, native_uv.size() - 2U, 320U, 2U},
        320U, 320U, full_crop, rejected_view));
    CHECK(!vfdual::make_yuv420_image_view(
        {padded_y.data(), padded_y.size(), kLayoutStride, 1U},
        {i420_u.data(), i420_u.size(), kLayoutStride / 2U, 1U},
        {i420_v.data(), i420_v.size(), kLayoutStride / 2U, 1U},
        320U, 320U, {1U, 0U, 319U, 320U}, rejected_view));

    // Desktop capture dimensions are independent of the fixed 320x320 QNN input.
    // A 16:9 decoded frame must be letterboxed, not treated as a 320x320 source.
    constexpr std::uint32_t kSourceWidth = 1920;
    constexpr std::uint32_t kSourceHeight = 1080;
    std::vector<std::uint8_t> widescreen_y(static_cast<std::size_t>(kSourceWidth) * kSourceHeight, 16);
    std::vector<std::uint8_t> widescreen_chroma(static_cast<std::size_t>(kSourceWidth / 2) * (kSourceHeight / 2), 128);
    const vfdual::Yuv420ImageView widescreen{widescreen_y.data(), widescreen_chroma.data(), widescreen_chroma.data(),
        kSourceWidth, kSourceHeight, kSourceWidth, kSourceWidth / 2, kSourceWidth / 2, 1, 1};
    CHECK(vfdual::preprocess_yuv420_to_model_rgb(widescreen, vfdual::YuvColorMatrix::bt709_limited, model_input, transform));
    CHECK(transform.source_width == kSourceWidth && transform.source_height == kSourceHeight);
    CHECK(transform.scale == 1.0F / 6.0F && transform.pad_x == 0.0F && transform.pad_y == 70.0F);

    // The 640x360 AI transport fast path must preserve the same letterbox
    // contract: black limited-range input remains black and the top border is
    // the RGB(114) model padding.
    constexpr std::uint32_t kTransportWidth = 640;
    constexpr std::uint32_t kTransportHeight = 360;
    std::vector<std::uint8_t> transport_y(static_cast<std::size_t>(kTransportWidth) * kTransportHeight, 16);
    std::vector<std::uint8_t> transport_chroma(static_cast<std::size_t>(kTransportWidth / 2) * (kTransportHeight / 2), 128);
    const vfdual::Yuv420ImageView transport{transport_y.data(), transport_chroma.data(), transport_chroma.data(),
        kTransportWidth, kTransportHeight, kTransportWidth, kTransportWidth / 2, kTransportWidth / 2, 1, 1};
    CHECK(vfdual::preprocess_yuv420_to_model_rgb(transport, vfdual::YuvColorMatrix::bt709_limited, model_input, transform));
    CHECK(transform.scale == 0.5F && transform.pad_x == 0.0F && transform.pad_y == 70.0F);
    CHECK(model_input[0] == 114 && model_input[1] == 114);
    const std::size_t center_offset = (static_cast<std::size_t>(160) * 320 + 160) * 6;
    CHECK(model_input[center_offset] == 0 && model_input[center_offset + 1] == 0);

    const vfdual::Yuv420ImageView invalid_stride{widescreen_y.data(), widescreen_chroma.data(), widescreen_chroma.data(),
        kSourceWidth, kSourceHeight, kSourceWidth - 1, kSourceWidth / 2, kSourceWidth / 2, 1, 1};
    CHECK(!vfdual::preprocess_yuv420_to_model_rgb(invalid_stride, vfdual::YuvColorMatrix::bt709_limited, model_input, transform));
    return 0;
}
