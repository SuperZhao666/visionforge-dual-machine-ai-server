#include "vfdual/media_foundation_h264_encoder.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <codecapi.h>
#include <d3d11.h>
#include <dxgi.h>
#include <mfapi.h>
#include <mferror.h>
#include <mfidl.h>
#include <mftransform.h>
#include <wmcodecdsp.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <utility>
#include <vector>

namespace vfdual {
namespace {

using Microsoft::WRL::ComPtr;
constexpr std::array<std::byte, 4> kAnnexBStartCode{
    std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}};
constexpr std::uint32_t kNvidiaVendorId = 0x10DE;
constexpr std::uint32_t kAmdVendorId = 0x1002;
constexpr std::uint32_t kIntelVendorId = 0x8086;
constexpr std::uint32_t kMicrosoftVendorId = 0x1414;
constexpr ULONGLONG kAsyncEventTimeoutMs = 250;

struct AdapterIdentity {
    LUID luid{};
    std::uint32_t vendor_id{};
};

struct TransformIdentity {
    std::string name;
    std::string clsid;
};

GraphicsAdapterVendor vendor_from_id(std::uint32_t vendor_id) noexcept {
    switch (vendor_id) {
        case kNvidiaVendorId: return GraphicsAdapterVendor::nvidia;
        case kAmdVendorId: return GraphicsAdapterVendor::amd;
        case kIntelVendorId: return GraphicsAdapterVendor::intel;
        case kMicrosoftVendorId: return GraphicsAdapterVendor::microsoft;
        default: return GraphicsAdapterVendor::unknown;
    }
}

HRESULT query_adapter_identity(ID3D11Device* device, AdapterIdentity& identity) noexcept {
    if (device == nullptr) return E_POINTER;
    ComPtr<IDXGIDevice> dxgi_device;
    ComPtr<IDXGIAdapter> adapter;
    DXGI_ADAPTER_DESC description{};
    HRESULT result = device->QueryInterface(IID_PPV_ARGS(&dxgi_device));
    if (SUCCEEDED(result)) result = dxgi_device->GetAdapter(&adapter);
    if (SUCCEEDED(result)) result = adapter->GetDesc(&description);
    if (SUCCEEDED(result)) {
        identity.luid = description.AdapterLuid;
        identity.vendor_id = description.VendorId;
    }
    return result;
}

std::string utf8_from_wide(const wchar_t* text, int length) {
    if (text == nullptr || length <= 0) return {};
    const int bytes = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, text, length, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return {};
    std::string converted(static_cast<std::size_t>(bytes), '\0');
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, text, length, converted.data(),
            bytes, nullptr, nullptr) != bytes) {
        return {};
    }
    return converted;
}

std::string guid_string(const GUID& value) {
    wchar_t text[39]{};
    const int length = StringFromGUID2(value, text, static_cast<int>(std::size(text)));
    return length > 1 ? utf8_from_wide(text, length - 1) : std::string{};
}

void query_transform_identity(
    IMFActivate* activation, TransformIdentity& identity) {
    if (activation == nullptr) return;
    wchar_t* friendly_name{};
    UINT32 friendly_name_length{};
    if (SUCCEEDED(activation->GetAllocatedString(
            MFT_FRIENDLY_NAME_Attribute, &friendly_name,
            &friendly_name_length))) {
        identity.name = utf8_from_wide(
            friendly_name, static_cast<int>(friendly_name_length));
    }
    CoTaskMemFree(friendly_name);
    GUID transform_clsid{};
    if (SUCCEEDED(activation->GetGUID(
            MFT_TRANSFORM_CLSID_Attribute, &transform_clsid))) {
        identity.clsid = guid_string(transform_clsid);
    }
    if (identity.name.empty()) {
        identity.name = identity.clsid.empty()
            ? "unidentified_hardware_h264_mft"
            : identity.clsid;
    }
}

void release_activations(IMFActivate** activations, UINT32 count) noexcept {
    for (UINT32 index = 0; index < count; ++index) {
        if (activations[index] != nullptr) activations[index]->Release();
    }
    CoTaskMemFree(activations);
}

HRESULT activate_adapter_h264_hardware_encoder(
    const AdapterIdentity& identity, ComPtr<IMFTransform>& transform,
    std::uint32_t& matching_transforms,
    TransformIdentity& transform_identity) noexcept {
    ComPtr<IMFAttributes> attributes;
    HRESULT result = MFCreateAttributes(&attributes, 1);
    if (SUCCEEDED(result)) {
        result = attributes->SetBlob(
            MFT_ENUM_ADAPTER_LUID, reinterpret_cast<const UINT8*>(&identity.luid), sizeof(identity.luid));
    }
    MFT_REGISTER_TYPE_INFO input{MFMediaType_Video, MFVideoFormat_NV12};
    MFT_REGISTER_TYPE_INFO output{MFMediaType_Video, MFVideoFormat_H264};
    IMFActivate** activations{};
    UINT32 count{};
    if (SUCCEEDED(result)) {
        result = MFTEnum2(
            MFT_CATEGORY_VIDEO_ENCODER,
            MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
            &input, &output, attributes.Get(), &activations, &count);
    }
    matching_transforms = count;
    if (SUCCEEDED(result) && count == 0) result = MF_E_TOPO_CODEC_NOT_FOUND;
    if (SUCCEEDED(result)) {
        query_transform_identity(activations[0], transform_identity);
        result = activations[0]->ActivateObject(IID_PPV_ARGS(&transform));
    }
    release_activations(activations, count);
    return result;
}

bool has_valid_config(const H264EncoderConfig& config) noexcept {
    return config.width >= 64 && config.height >= 64 &&
           config.width % 2U == 0 && config.height % 2U == 0 &&
           config.frames_per_second != 0 && config.keyframe_interval_frames != 0;
}

std::uint8_t clamp_byte(int value) noexcept {
    return static_cast<std::uint8_t>(std::clamp(value, 0, 255));
}

void bgra_to_nv12(const D3D11_MAPPED_SUBRESOURCE& mapped, const H264EncoderConfig& config,
                  std::vector<std::byte>& nv12) noexcept {
    const std::size_t luma_bytes = static_cast<std::size_t>(config.width) * config.height;
    auto* luma = reinterpret_cast<std::uint8_t*>(nv12.data());
    auto* chroma = luma + luma_bytes;
    for (std::uint32_t y = 0; y < config.height; ++y) {
        const auto* row = static_cast<const std::uint8_t*>(mapped.pData) +
                          static_cast<std::size_t>(y) * mapped.RowPitch;
        for (std::uint32_t x = 0; x < config.width; ++x) {
            const auto* pixel = row + static_cast<std::size_t>(x) * 4U;
            const int blue = pixel[0];
            const int green = pixel[1];
            const int red = pixel[2];
            luma[static_cast<std::size_t>(y) * config.width + x] =
                clamp_byte(((47 * red + 157 * green + 16 * blue + 128) >> 8) + 16);
        }
    }
    for (std::uint32_t y = 0; y < config.height; y += 2U) {
        const auto* first_row = static_cast<const std::uint8_t*>(mapped.pData) +
                                static_cast<std::size_t>(y) * mapped.RowPitch;
        const auto* second_row = static_cast<const std::uint8_t*>(mapped.pData) +
                                 static_cast<std::size_t>(y + 1U) * mapped.RowPitch;
        auto* output = chroma + static_cast<std::size_t>(y / 2U) * config.width;
        for (std::uint32_t x = 0; x < config.width; x += 2U) {
            int red{};
            int green{};
            int blue{};
            for (const auto* row : {first_row, second_row}) {
                for (std::uint32_t offset = 0; offset < 2U; ++offset) {
                    const auto* pixel = row + static_cast<std::size_t>(x + offset) * 4U;
                    blue += pixel[0];
                    green += pixel[1];
                    red += pixel[2];
                }
            }
            red /= 4;
            green /= 4;
            blue /= 4;
            output[x] = clamp_byte(((-26 * red - 87 * green + 112 * blue + 128) >> 8) + 128);
            output[x + 1U] = clamp_byte(((112 * red - 102 * green - 10 * blue + 128) >> 8) + 128);
        }
    }
}

bool starts_with_annex_b(std::span<const std::byte> data) noexcept {
    return data.size() >= 4U && data[0] == std::byte{0} && data[1] == std::byte{0} &&
           ((data[2] == std::byte{1}) || (data[2] == std::byte{0} && data[3] == std::byte{1}));
}

std::uint32_t read_be32(const std::byte* data) noexcept {
    return (std::to_integer<std::uint32_t>(data[0]) << 24U) |
           (std::to_integer<std::uint32_t>(data[1]) << 16U) |
           (std::to_integer<std::uint32_t>(data[2]) << 8U) |
           std::to_integer<std::uint32_t>(data[3]);
}

bool normalize_sample_to_annex_b(std::span<const std::byte> sample,
                                 std::vector<std::byte>& destination) {
    destination.clear();
    if (sample.empty()) return false;
    if (starts_with_annex_b(sample)) {
        destination.assign(sample.begin(), sample.end());
        return true;
    }
    std::size_t cursor{};
    while (cursor + 4U <= sample.size()) {
        const std::uint32_t size = read_be32(sample.data() + cursor);
        cursor += 4U;
        if (size == 0 || cursor + size > sample.size()) {
            destination.clear();
            return false;
        }
        destination.insert(destination.end(), kAnnexBStartCode.begin(), kAnnexBStartCode.end());
        destination.insert(destination.end(), sample.begin() + static_cast<std::ptrdiff_t>(cursor),
                           sample.begin() + static_cast<std::ptrdiff_t>(cursor + size));
        cursor += size;
    }
    return cursor == sample.size() && !destination.empty();
}

void append_avcc_parameter_sets(std::span<const std::byte> header,
                                std::vector<std::byte>& destination) {
    if (header.empty()) return;
    if (starts_with_annex_b(header)) {
        destination.insert(destination.end(), header.begin(), header.end());
        return;
    }
    if (header.size() < 7U || header[0] != std::byte{1}) return;
    std::size_t cursor = 5U;
    const std::uint8_t sequence_count = std::to_integer<std::uint8_t>(header[cursor++]) & 0x1fU;
    const auto append_sets = [&](std::uint8_t count, std::size_t& position) {
        for (std::uint8_t index = 0; index < count; ++index) {
            if (position + 2U > header.size()) return false;
            const std::size_t length =
                (std::to_integer<std::uint8_t>(header[position]) << 8U) |
                std::to_integer<std::uint8_t>(header[position + 1U]);
            position += 2U;
            if (length == 0 || position + length > header.size()) return false;
            destination.insert(destination.end(), kAnnexBStartCode.begin(), kAnnexBStartCode.end());
            destination.insert(destination.end(),
                               header.begin() + static_cast<std::ptrdiff_t>(position),
                               header.begin() + static_cast<std::ptrdiff_t>(position + length));
            position += length;
        }
        return true;
    };
    if (!append_sets(sequence_count, cursor) || cursor >= header.size()) return;
    const std::uint8_t picture_count = std::to_integer<std::uint8_t>(header[cursor++]);
    append_sets(picture_count, cursor);
}

bool contains_nal(std::span<const std::byte> access_unit, std::uint8_t expected) noexcept {
    for (std::size_t index = 0; index + 4U < access_unit.size(); ++index) {
        const bool short_start = access_unit[index] == std::byte{0} &&
            access_unit[index + 1U] == std::byte{0} && access_unit[index + 2U] == std::byte{1};
        const bool long_start = index + 5U < access_unit.size() && short_start == false &&
            access_unit[index] == std::byte{0} && access_unit[index + 1U] == std::byte{0} &&
            access_unit[index + 2U] == std::byte{0} && access_unit[index + 3U] == std::byte{1};
        if (!short_start && !long_start) continue;
        const std::size_t nal_index = index + (long_start ? 4U : 3U);
        if ((std::to_integer<std::uint8_t>(access_unit[nal_index]) & 0x1fU) == expected) return true;
    }
    return false;
}

HRESULT set_media_type_common(IMFMediaType* type, const GUID& subtype,
                              const H264EncoderConfig& config) noexcept {
    HRESULT result = type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    if (SUCCEEDED(result)) result = type->SetGUID(MF_MT_SUBTYPE, subtype);
    if (SUCCEEDED(result)) result = MFSetAttributeSize(type, MF_MT_FRAME_SIZE, config.width, config.height);
    if (SUCCEEDED(result)) result = MFSetAttributeRatio(type, MF_MT_FRAME_RATE, config.frames_per_second, 1);
    if (SUCCEEDED(result)) result = MFSetAttributeRatio(type, MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
    if (SUCCEEDED(result)) result = type->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    return result;
}

void set_bt709_limited_colorimetry(IMFMediaType* type) noexcept {
    // Desktop capture and the phone preprocessor share one explicit contract.
    // These attributes are advisory for older MFTs, so compatibility must not
    // depend on whether a particular Windows codec accepts every attribute.
    type->SetUINT32(MF_MT_VIDEO_PRIMARIES, MFVideoPrimaries_BT709);
    type->SetUINT32(MF_MT_TRANSFER_FUNCTION, MFVideoTransFunc_709);
    type->SetUINT32(MF_MT_YUV_MATRIX, MFVideoTransferMatrix_BT709);
    type->SetUINT32(MF_MT_VIDEO_NOMINAL_RANGE, MFNominalRange_16_235);
}

void try_set_codec_bool(ICodecAPI* codec, const GUID& key, bool enabled) noexcept {
    if (codec == nullptr) return;
    VARIANT value{};
    value.vt = VT_BOOL;
    value.boolVal = enabled ? VARIANT_TRUE : VARIANT_FALSE;
    codec->SetValue(&key, &value);
}

void try_set_codec_u32(ICodecAPI* codec, const GUID& key, std::uint32_t number) noexcept {
    if (codec == nullptr) return;
    VARIANT value{};
    value.vt = VT_UI4;
    value.ulVal = number;
    codec->SetValue(&key, &value);
}

}  // namespace

struct MediaFoundationH264Encoder::State final {
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<ID3D11Texture2D> staging;
    ComPtr<IMFTransform> transform;
    ComPtr<IMFMediaEventGenerator> event_generator;
    ComPtr<ICodecAPI> codec;
    H264EncoderConfig config{};
    MFT_OUTPUT_STREAM_INFO output_info{};
    std::vector<std::byte> nv12;
    std::vector<std::byte> sequence_header;
    std::vector<std::byte> access_unit;
    std::int32_t last_result{E_FAIL};
    std::uint64_t frame_index{};
    LONGLONG sample_duration{};
    GraphicsAdapterVendor adapter_vendor{GraphicsAdapterVendor::unknown};
    std::uint32_t adapter_vendor_id{};
    LUID adapter_luid{};
    std::uint32_t matching_hardware_transforms{};
    std::string transform_name;
    std::string transform_clsid;
    std::uint32_t pending_need_input{};
    std::uint32_t pending_have_output{};
    bool hardware{};
    bool asynchronous{};
    bool media_foundation_started{};
    bool com_owned{};

    HRESULT wait_for_async_event(MediaEventType expected) noexcept {
        auto& pending = expected == METransformNeedInput ? pending_need_input : pending_have_output;
        if (pending != 0) {
            --pending;
            return S_OK;
        }
        const ULONGLONG deadline = GetTickCount64() + kAsyncEventTimeoutMs;
        while (GetTickCount64() <= deadline) {
            ComPtr<IMFMediaEvent> event;
            HRESULT result = event_generator->GetEvent(MF_EVENT_FLAG_NO_WAIT, &event);
            if (result == MF_E_NO_EVENTS_AVAILABLE) {
                SwitchToThread();
                continue;
            }
            if (FAILED(result)) return result;
            MediaEventType type{MEUnknown};
            result = event->GetType(&type);
            if (FAILED(result)) return result;
            HRESULT event_status{};
            result = event->GetStatus(&event_status);
            if (FAILED(result)) return result;
            if (FAILED(event_status)) return event_status;
            if (type == METransformNeedInput) ++pending_need_input;
            if (type == METransformHaveOutput) ++pending_have_output;
            if (type == expected) {
                --pending;
                return S_OK;
            }
        }
        return HRESULT_FROM_WIN32(WAIT_TIMEOUT);
    }
};

MediaFoundationH264Encoder::MediaFoundationH264Encoder() noexcept
    : state_(std::make_unique<State>()) {}

MediaFoundationH264Encoder::~MediaFoundationH264Encoder() { reset(); }

GraphicsAdapterVendor graphics_adapter_vendor(ID3D11Device* device) noexcept {
    AdapterIdentity identity{};
    return SUCCEEDED(query_adapter_identity(device, identity))
        ? vendor_from_id(identity.vendor_id) : GraphicsAdapterVendor::unknown;
}

MediaFoundationHardwareProbeResult probe_media_foundation_h264_hardware(
    ID3D11Device* device) noexcept {
    MediaFoundationHardwareProbeResult probe{};
    AdapterIdentity identity{};
    HRESULT result = query_adapter_identity(device, identity);
    probe.adapter_vendor_id = identity.vendor_id;
    probe.adapter_vendor = vendor_from_id(identity.vendor_id);
    probe.adapter_luid_low = identity.luid.LowPart;
    probe.adapter_luid_high = identity.luid.HighPart;
    if (FAILED(result)) {
        probe.hresult = result;
        return probe;
    }
    const HRESULT com_result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool com_owned = SUCCEEDED(com_result);
    if (FAILED(com_result) && com_result != RPC_E_CHANGED_MODE) {
        probe.hresult = com_result;
        return probe;
    }
    result = MFStartup(MF_VERSION, MFSTARTUP_LITE);
    if (SUCCEEDED(result)) {
        ComPtr<IMFTransform> transform;
        TransformIdentity transform_identity;
        result = activate_adapter_h264_hardware_encoder(
            identity, transform, probe.matching_hardware_transforms,
            transform_identity);
        probe.activation_succeeded = SUCCEEDED(result) && transform != nullptr;
        probe.transform_name = std::move(transform_identity.name);
        probe.transform_clsid = std::move(transform_identity.clsid);
        transform.Reset();
        MFShutdown();
    }
    if (com_owned) CoUninitialize();
    probe.hresult = result;
    return probe;
}

bool MediaFoundationH264Encoder::initialize(
    ID3D11Device* device, const H264EncoderConfig& config,
    MediaFoundationEncoderMode mode) noexcept {
    reset();
    if (device == nullptr || !has_valid_config(config)) {
        state_->last_result = E_INVALIDARG;
        return false;
    }
    const HRESULT com_result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(com_result)) state_->com_owned = true;
    else if (com_result != RPC_E_CHANGED_MODE) {
        state_->last_result = com_result;
        return false;
    }
    HRESULT result = MFStartup(MF_VERSION, MFSTARTUP_LITE);
    if (FAILED(result)) {
        state_->last_result = result;
        reset();
        return false;
    }
    state_->media_foundation_started = true;
    AdapterIdentity identity{};
    if (mode == MediaFoundationEncoderMode::hardware) {
        result = query_adapter_identity(device, identity);
        if (SUCCEEDED(result)) {
            state_->adapter_vendor = vendor_from_id(identity.vendor_id);
            state_->adapter_vendor_id = identity.vendor_id;
            state_->adapter_luid = identity.luid;
            TransformIdentity transform_identity;
            result = activate_adapter_h264_hardware_encoder(
                identity, state_->transform,
                state_->matching_hardware_transforms,
                transform_identity);
            state_->transform_name = std::move(transform_identity.name);
            state_->transform_clsid = std::move(transform_identity.clsid);
            state_->hardware = SUCCEEDED(result);
        }
    } else {
        result = CoCreateInstance(CLSID_CMSH264EncoderMFT, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&state_->transform));
        state_->adapter_vendor = GraphicsAdapterVendor::microsoft;
        state_->adapter_vendor_id = kMicrosoftVendorId;
        state_->transform_name = "Microsoft H.264 Video Encoder MFT";
        state_->transform_clsid = guid_string(CLSID_CMSH264EncoderMFT);
    }
    if (FAILED(result)) {
        state_->last_result = result;
        reset();
        return false;
    }
    ComPtr<IMFAttributes> transform_attributes;
    if (state_->hardware && SUCCEEDED(state_->transform->GetAttributes(&transform_attributes))) {
        UINT32 asynchronous{};
        state_->asynchronous = SUCCEEDED(
            transform_attributes->GetUINT32(MF_TRANSFORM_ASYNC, &asynchronous)) && asynchronous != FALSE;
    }
    if (state_->hardware && !state_->asynchronous) {
        state_->last_result = MF_E_INVALIDREQUEST;
        reset();
        return false;
    }
    if (state_->asynchronous) {
        result = transform_attributes->SetUINT32(MF_TRANSFORM_ASYNC_UNLOCK, TRUE);
        if (SUCCEEDED(result)) result = state_->transform.As(&state_->event_generator);
        if (FAILED(result)) {
            state_->last_result = result;
            reset();
            return false;
        }
    }
    state_->transform.As(&state_->codec);
    // Encoder properties that change buffering and GOP structure must be set
    // before media-type negotiation; otherwise the Microsoft MFT can retain
    // its default reorder/look-ahead queue for the first sample.
    try_set_codec_bool(state_->codec.Get(), CODECAPI_AVLowLatencyMode, true);
    try_set_codec_u32(state_->codec.Get(), CODECAPI_AVEncMPVGOPSize,
                      config.keyframe_interval_frames);

    ComPtr<IMFMediaType> output_type;
    result = MFCreateMediaType(&output_type);
    if (SUCCEEDED(result)) result = set_media_type_common(output_type.Get(), MFVideoFormat_H264, config);
    if (SUCCEEDED(result)) set_bt709_limited_colorimetry(output_type.Get());
    if (SUCCEEDED(result)) result = output_type->SetUINT32(MF_MT_AVG_BITRATE, 20'000'000U);
    if (SUCCEEDED(result)) result = output_type->SetUINT32(MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Base);
    if (SUCCEEDED(result)) result = state_->transform->SetOutputType(0, output_type.Get(), 0);

    ComPtr<IMFMediaType> input_type;
    if (SUCCEEDED(result)) result = MFCreateMediaType(&input_type);
    if (SUCCEEDED(result)) result = set_media_type_common(input_type.Get(), MFVideoFormat_NV12, config);
    if (SUCCEEDED(result)) set_bt709_limited_colorimetry(input_type.Get());
    if (SUCCEEDED(result)) result = input_type->SetUINT32(MF_MT_DEFAULT_STRIDE, config.width);
    if (SUCCEEDED(result)) result = state_->transform->SetInputType(0, input_type.Get(), 0);
    if (FAILED(result)) {
        state_->last_result = result;
        reset();
        return false;
    }

    result = state_->transform->GetOutputStreamInfo(0, &state_->output_info);
    if (SUCCEEDED(result)) result = state_->transform->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
    if (SUCCEEDED(result)) result = state_->transform->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
    if (FAILED(result)) {
        state_->last_result = result;
        reset();
        return false;
    }

    ComPtr<IMFMediaType> active_output;
    if (SUCCEEDED(state_->transform->GetOutputCurrentType(0, &active_output))) {
        UINT32 header_size{};
        if (SUCCEEDED(active_output->GetBlobSize(MF_MT_MPEG_SEQUENCE_HEADER, &header_size)) &&
            header_size != 0) {
            state_->sequence_header.resize(header_size);
            UINT32 copied{};
            if (FAILED(active_output->GetBlob(MF_MT_MPEG_SEQUENCE_HEADER,
                                              reinterpret_cast<UINT8*>(state_->sequence_header.data()),
                                              header_size, &copied))) {
                state_->sequence_header.clear();
            } else {
                state_->sequence_header.resize(copied);
            }
        }
    }

    D3D11_TEXTURE2D_DESC staging{};
    staging.Width = config.width;
    staging.Height = config.height;
    staging.MipLevels = 1;
    staging.ArraySize = 1;
    staging.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    staging.SampleDesc.Count = 1;
    staging.Usage = D3D11_USAGE_STAGING;
    staging.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    result = device->CreateTexture2D(&staging, nullptr, &state_->staging);
    if (FAILED(result)) {
        state_->last_result = result;
        reset();
        return false;
    }
    state_->device = device;
    device->GetImmediateContext(&state_->context);
    if (!state_->context) {
        state_->last_result = E_NOINTERFACE;
        reset();
        return false;
    }
    state_->config = config;
    state_->sample_duration = 10'000'000LL / config.frames_per_second;
    state_->nv12.resize(static_cast<std::size_t>(config.width) * config.height * 3U / 2U);
    state_->last_result = S_OK;
    return true;
}

MediaFoundationEncodeResult MediaFoundationH264Encoder::encode(
    ID3D11Texture2D* texture, bool force_keyframe) noexcept {
    using Stage = MediaFoundationEncodeResult::Stage;
    if (!is_ready() || texture == nullptr) {
        state_->last_result = E_POINTER;
        return {false, false, state_->last_result, 0, Stage::validate_input};
    }
    D3D11_TEXTURE2D_DESC description{};
    texture->GetDesc(&description);
    if (description.Width != state_->config.width || description.Height != state_->config.height ||
        description.Format != DXGI_FORMAT_B8G8R8A8_UNORM) {
        state_->last_result = E_INVALIDARG;
        return {false, false, state_->last_result, 0, Stage::validate_input};
    }

    state_->context->CopyResource(state_->staging.Get(), texture);
    D3D11_MAPPED_SUBRESOURCE mapped{};
    HRESULT result = state_->context->Map(state_->staging.Get(), 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(result)) {
        state_->last_result = result;
        return {false, false, result, 0, Stage::texture_readback};
    }
    bgra_to_nv12(mapped, state_->config, state_->nv12);
    state_->context->Unmap(state_->staging.Get(), 0);

    if (force_keyframe) try_set_codec_bool(state_->codec.Get(), CODECAPI_AVEncVideoForceKeyFrame, true);
    ComPtr<IMFMediaBuffer> input_buffer;
    result = MFCreateMemoryBuffer(static_cast<DWORD>(state_->nv12.size()), &input_buffer);
    BYTE* input_bytes{};
    DWORD maximum{};
    if (SUCCEEDED(result)) result = input_buffer->Lock(&input_bytes, &maximum, nullptr);
    if (SUCCEEDED(result) && maximum >= state_->nv12.size()) {
        std::memcpy(input_bytes, state_->nv12.data(), state_->nv12.size());
        input_buffer->Unlock();
        result = input_buffer->SetCurrentLength(static_cast<DWORD>(state_->nv12.size()));
    } else if (SUCCEEDED(result)) {
        input_buffer->Unlock();
        result = E_OUTOFMEMORY;
    }
    ComPtr<IMFSample> input_sample;
    if (SUCCEEDED(result)) result = MFCreateSample(&input_sample);
    if (SUCCEEDED(result)) result = input_sample->AddBuffer(input_buffer.Get());
    if (SUCCEEDED(result)) result = input_sample->SetSampleTime(
        static_cast<LONGLONG>(state_->frame_index) * state_->sample_duration);
    if (SUCCEEDED(result)) result = input_sample->SetSampleDuration(state_->sample_duration);
    if (SUCCEEDED(result) && state_->asynchronous) {
        result = state_->wait_for_async_event(METransformNeedInput);
    }
    if (SUCCEEDED(result)) result = state_->transform->ProcessInput(0, input_sample.Get(), 0);
    if (FAILED(result)) {
        state_->last_result = result;
        return {false, false, result, 0, Stage::submit_input};
    }

    ComPtr<IMFSample> output_sample;
    const auto prepare_output_sample = [&]() noexcept {
        output_sample.Reset();
        if ((state_->output_info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) != 0) {
            return S_OK;
        }
        HRESULT prepare_result = MFCreateSample(&output_sample);
        ComPtr<IMFMediaBuffer> output_buffer;
        const DWORD output_size = std::max<DWORD>(state_->output_info.cbSize, 1U << 20U);
        if (SUCCEEDED(prepare_result)) prepare_result = MFCreateMemoryBuffer(output_size, &output_buffer);
        if (SUCCEEDED(prepare_result)) prepare_result = output_sample->AddBuffer(output_buffer.Get());
        return prepare_result;
    };
    result = prepare_output_sample();
    if (SUCCEEDED(result) && state_->asynchronous) {
        result = state_->wait_for_async_event(METransformHaveOutput);
    }
    MFT_OUTPUT_DATA_BUFFER output{};
    output.dwStreamID = 0;
    output.pSample = output_sample.Get();
    DWORD status{};
    if (SUCCEEDED(result)) result = state_->transform->ProcessOutput(0, 1, &output, &status);
    if (result == MF_E_TRANSFORM_STREAM_CHANGE) {
        if (output.pEvents != nullptr) {
            output.pEvents->Release();
            output.pEvents = nullptr;
        }
        ComPtr<IMFMediaType> changed_output_type;
        result = state_->transform->GetOutputAvailableType(0, 0, &changed_output_type);
        if (SUCCEEDED(result)) result = state_->transform->SetOutputType(0, changed_output_type.Get(), 0);
        if (SUCCEEDED(result)) result = state_->transform->GetOutputStreamInfo(0, &state_->output_info);
        if (SUCCEEDED(result)) result = prepare_output_sample();
        if (SUCCEEDED(result) && state_->asynchronous) {
            result = state_->wait_for_async_event(METransformHaveOutput);
        }
        output = {};
        output.dwStreamID = 0;
        output.pSample = output_sample.Get();
        status = 0;
        if (SUCCEEDED(result)) result = state_->transform->ProcessOutput(0, 1, &output, &status);
    }
    if (output.pEvents != nullptr) output.pEvents->Release();
    if (FAILED(result)) {
        state_->last_result = result;
        return {false, false, result, 0, Stage::receive_output};
    }
    if ((state_->output_info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) != 0) {
        output_sample.Attach(output.pSample);
    }
    if (!output_sample) {
        state_->last_result = E_UNEXPECTED;
        return {false, false, state_->last_result, 0, Stage::receive_output};
    }
    ComPtr<IMFMediaBuffer> contiguous;
    result = output_sample->ConvertToContiguousBuffer(&contiguous);
    BYTE* output_bytes{};
    DWORD output_length{};
    if (SUCCEEDED(result)) result = contiguous->Lock(&output_bytes, nullptr, &output_length);
    std::vector<std::byte> normalized;
    if (SUCCEEDED(result)) {
        const auto* first = reinterpret_cast<const std::byte*>(output_bytes);
        const bool normalized_ok = normalize_sample_to_annex_b(
            std::span<const std::byte>(first, output_length), normalized);
        contiguous->Unlock();
        if (!normalized_ok) result = MF_E_INVALIDMEDIATYPE;
    }
    if (FAILED(result)) {
        state_->last_result = result;
        return {false, false, result, 0, Stage::normalize_annex_b};
    }

    UINT32 clean_point{};
    const bool sample_keyframe = SUCCEEDED(output_sample->GetUINT32(MFSampleExtension_CleanPoint, &clean_point)) &&
                                 clean_point != 0;
    const bool keyframe = sample_keyframe || contains_nal(normalized, 5U);
    state_->access_unit.clear();
    if (keyframe) append_avcc_parameter_sets(state_->sequence_header, state_->access_unit);
    state_->access_unit.insert(state_->access_unit.end(), normalized.begin(), normalized.end());
    ++state_->frame_index;
    state_->last_result = S_OK;
    return {true, keyframe, S_OK, static_cast<std::uint32_t>(state_->access_unit.size()),
            Stage::complete};
}

void MediaFoundationH264Encoder::reset() noexcept {
    if (!state_) return;
    if (state_->transform) {
        state_->transform->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
        state_->transform->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
    }
    state_->codec.Reset();
    state_->event_generator.Reset();
    state_->transform.Reset();
    state_->staging.Reset();
    state_->context.Reset();
    state_->device.Reset();
    state_->nv12.clear();
    state_->sequence_header.clear();
    state_->access_unit.clear();
    state_->frame_index = 0;
    state_->adapter_vendor = GraphicsAdapterVendor::unknown;
    state_->adapter_vendor_id = 0;
    state_->adapter_luid = {};
    state_->matching_hardware_transforms = 0;
    state_->transform_name.clear();
    state_->transform_clsid.clear();
    state_->pending_need_input = 0;
    state_->pending_have_output = 0;
    state_->hardware = false;
    state_->asynchronous = false;
    if (state_->media_foundation_started) MFShutdown();
    state_->media_foundation_started = false;
    if (state_->com_owned) CoUninitialize();
    state_->com_owned = false;
}

bool MediaFoundationH264Encoder::is_ready() const noexcept {
    return state_ && state_->transform && state_->staging && state_->context &&
           (!state_->asynchronous || state_->event_generator);
}

bool MediaFoundationH264Encoder::is_hardware() const noexcept { return state_ && state_->hardware; }

GraphicsAdapterVendor MediaFoundationH264Encoder::adapter_vendor() const noexcept {
    return state_ ? state_->adapter_vendor : GraphicsAdapterVendor::unknown;
}

std::uint32_t MediaFoundationH264Encoder::adapter_vendor_id() const noexcept {
    return state_ ? state_->adapter_vendor_id : 0U;
}

std::uint32_t MediaFoundationH264Encoder::adapter_luid_low() const noexcept {
    return state_ ? state_->adapter_luid.LowPart : 0U;
}

std::int32_t MediaFoundationH264Encoder::adapter_luid_high() const noexcept {
    return state_ ? state_->adapter_luid.HighPart : 0;
}

std::uint32_t MediaFoundationH264Encoder::matching_hardware_transforms() const noexcept {
    return state_ ? state_->matching_hardware_transforms : 0U;
}

std::string_view MediaFoundationH264Encoder::transform_name() const noexcept {
    return state_ ? std::string_view{state_->transform_name} : std::string_view{};
}

std::string_view MediaFoundationH264Encoder::transform_clsid() const noexcept {
    return state_ ? std::string_view{state_->transform_clsid} : std::string_view{};
}

std::uint32_t MediaFoundationH264Encoder::effective_frames_per_second() const noexcept {
    return state_ ? state_->config.frames_per_second : 0U;
}

std::int32_t MediaFoundationH264Encoder::last_hresult() const noexcept {
    return state_->last_result;
}

std::span<const std::byte> MediaFoundationH264Encoder::access_unit() const noexcept {
    return state_->access_unit;
}

}  // namespace vfdual
