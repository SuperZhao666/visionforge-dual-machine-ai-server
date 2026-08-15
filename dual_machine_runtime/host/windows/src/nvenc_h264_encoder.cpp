#include "vfdual/nvenc_h264_encoder.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <d3d11.h>
#include <wrl/client.h>

#include "ffnvcodec/nvEncodeAPI.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <new>

namespace vfdual {
namespace {

constexpr std::size_t kEncoderBufferCount = 4;
// The same-adapter pipeline owns three shared slots and may present each one
// directly to NVENC. Keep every slot registered after its first use.
constexpr std::size_t kRegisteredTextureCount = 3;
using Microsoft::WRL::ComPtr;

struct NvencApi final {
    HMODULE library{};
    NV_ENCODE_API_FUNCTION_LIST functions{};
    ~NvencApi() { if (library != nullptr) FreeLibrary(library); }
};

bool load_api(NvencApi& api) noexcept {
    if (api.library != nullptr) {
        return api.functions.nvEncOpenEncodeSessionEx != nullptr;
    }
    api.library = LoadLibraryW(L"nvEncodeAPI64.dll");
    if (api.library == nullptr) return false;
    using CreateInstanceFn = NVENCSTATUS(NVENCAPI*)(NV_ENCODE_API_FUNCTION_LIST*);
    const auto create_instance = reinterpret_cast<CreateInstanceFn>(GetProcAddress(api.library, "NvEncodeAPICreateInstance"));
    if (create_instance == nullptr) {
        FreeLibrary(api.library);
        api.library = nullptr;
        return false;
    }
    api.functions = {};
    api.functions.version = NV_ENCODE_API_FUNCTION_LIST_VER;
    if (create_instance(&api.functions) == NV_ENC_SUCCESS) return true;
    api.functions = {};
    FreeLibrary(api.library);
    api.library = nullptr;
    return false;
}

bool has_valid_config(const H264EncoderConfig& config) noexcept {
    return config.width != 0 && config.height != 0 && config.frames_per_second != 0 &&
           config.keyframe_interval_frames != 0;
}

}  // namespace

struct NvencH264Encoder::State final {
    struct RegisteredTexture final {
        ComPtr<ID3D11Texture2D> texture;
        NV_ENC_REGISTERED_PTR input{};
    };

    NvencApi api;
    void* encoder{};
    std::array<RegisteredTexture, kRegisteredTextureCount> registered_textures{};
    std::array<NV_ENC_OUTPUT_PTR, kEncoderBufferCount> bitstream_buffers{};
    H264EncoderConfig config{};
    std::vector<std::byte> access_unit;
    std::int32_t last_status{NV_ENC_ERR_ENCODER_NOT_INITIALIZED};
    std::uint32_t frame_index{};
};

NvencH264Encoder::NvencH264Encoder() noexcept {
    try {
        state_ = std::make_unique<State>();
    } catch (...) {
        state_.reset();
    }
}
NvencH264Encoder::~NvencH264Encoder() { reset(); }

bool NvencH264Encoder::initialize(ID3D11Device* device, const H264EncoderConfig& config) noexcept {
    if (!state_) return false;
    reset();
    if (device == nullptr || !has_valid_config(config) || !load_api(state_->api)) {
        state_->last_status = NV_ENC_ERR_INVALID_PARAM;
        return false;
    }

    NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS session_parameters{NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_VER};
    session_parameters.device = device;
    session_parameters.deviceType = NV_ENC_DEVICE_TYPE_DIRECTX;
    session_parameters.apiVersion = NVENCAPI_VERSION;
    NVENCSTATUS status = state_->api.functions.nvEncOpenEncodeSessionEx(&session_parameters, &state_->encoder);
    if (status != NV_ENC_SUCCESS || state_->encoder == nullptr) {
        state_->last_status = status;
        return false;
    }

    NV_ENC_PRESET_CONFIG preset{NV_ENC_PRESET_CONFIG_VER};
    preset.presetCfg.version = NV_ENC_CONFIG_VER;
    status = state_->api.functions.nvEncGetEncodePresetConfigEx(
        state_->encoder, NV_ENC_CODEC_H264_GUID, NV_ENC_PRESET_P1_GUID,
        NV_ENC_TUNING_INFO_ULTRA_LOW_LATENCY, &preset);
    if (status != NV_ENC_SUCCESS) { state_->last_status = status; reset(); return false; }

    NV_ENC_CONFIG encoder_config = preset.presetCfg;
    encoder_config.version = NV_ENC_CONFIG_VER;
    encoder_config.profileGUID = NV_ENC_H264_PROFILE_BASELINE_GUID;
    encoder_config.gopLength = config.keyframe_interval_frames;
    encoder_config.frameIntervalP = 1;
    // UDP has no reliable session setup. Every IDR must be independently
    // decodable so a receiver that starts late or requests recovery receives
    // the H.264 SPS/PPS together with the next random-access frame.
    encoder_config.encodeCodecConfig.h264Config.repeatSPSPPS = 1;
    auto& vui = encoder_config.encodeCodecConfig.h264Config.h264VUIParameters;
    vui.videoSignalTypePresentFlag = 1;
    vui.videoFormat = NV_ENC_VUI_VIDEO_FORMAT_COMPONENT;
    vui.videoFullRangeFlag = 0;
    vui.colourDescriptionPresentFlag = 1;
    vui.colourPrimaries = NV_ENC_VUI_COLOR_PRIMARIES_BT709;
    vui.transferCharacteristics = NV_ENC_VUI_TRANSFER_CHARACTERISTIC_BT709;
    vui.colourMatrix = NV_ENC_VUI_MATRIX_COEFFS_BT709;
    // V17.9: transport is intentionally uncapped. Constant QP avoids a host
    // bitrate ceiling; the latest-frame receiver remains responsible for
    // overload handling on the phone side.
    encoder_config.rcParams.rateControlMode = NV_ENC_PARAMS_RC_CONSTQP;
    encoder_config.rcParams.constQP.qpIntra = 23;
    encoder_config.rcParams.constQP.qpInterP = 25;
    encoder_config.rcParams.constQP.qpInterB = 0;

    NV_ENC_INITIALIZE_PARAMS initialize_parameters{NV_ENC_INITIALIZE_PARAMS_VER};
    initialize_parameters.encodeGUID = NV_ENC_CODEC_H264_GUID;
    initialize_parameters.presetGUID = NV_ENC_PRESET_P1_GUID;
    initialize_parameters.encodeWidth = config.width;
    initialize_parameters.encodeHeight = config.height;
    initialize_parameters.darWidth = config.width;
    initialize_parameters.darHeight = config.height;
    initialize_parameters.frameRateNum = config.frames_per_second;
    initialize_parameters.frameRateDen = 1;
    initialize_parameters.enablePTD = 1;
    initialize_parameters.enableEncodeAsync = 0;
    initialize_parameters.tuningInfo = NV_ENC_TUNING_INFO_ULTRA_LOW_LATENCY;
    initialize_parameters.encodeConfig = &encoder_config;
    status = state_->api.functions.nvEncInitializeEncoder(state_->encoder, &initialize_parameters);
    if (status != NV_ENC_SUCCESS) { state_->last_status = status; reset(); return false; }

    for (auto& bitstream_buffer : state_->bitstream_buffers) {
        NV_ENC_CREATE_BITSTREAM_BUFFER bitstream_parameters{NV_ENC_CREATE_BITSTREAM_BUFFER_VER};
        status = state_->api.functions.nvEncCreateBitstreamBuffer(state_->encoder, &bitstream_parameters);
        if (status != NV_ENC_SUCCESS || bitstream_parameters.bitstreamBuffer == nullptr) {
            state_->last_status = status;
            reset();
            return false;
        }
        bitstream_buffer = bitstream_parameters.bitstreamBuffer;
    }
    state_->config = config;
    state_->last_status = NV_ENC_SUCCESS;
    return true;
}

NvencEncodeResult NvencH264Encoder::encode(ID3D11Texture2D* texture, bool force_keyframe) noexcept {
    if (!is_ready() || texture == nullptr) {
        return {false, false, NV_ENC_ERR_INVALID_PTR, 0,
                NvencEncodeResult::Stage::validate_input};
    }
    D3D11_TEXTURE2D_DESC texture_description{};
    texture->GetDesc(&texture_description);
    if (texture_description.Width != state_->config.width || texture_description.Height != state_->config.height ||
        texture_description.Format != DXGI_FORMAT_B8G8R8A8_UNORM) {
        state_->last_status = NV_ENC_ERR_INVALID_PARAM;
        return {false, false, state_->last_status, 0,
                NvencEncodeResult::Stage::validate_input};
    }
    const std::size_t buffer_index = state_->frame_index % state_->bitstream_buffers.size();
    State::RegisteredTexture* registered_texture = nullptr;
    State::RegisteredTexture* available_slot = nullptr;
    for (auto& cached_texture : state_->registered_textures) {
        if (cached_texture.texture.Get() == texture) {
            registered_texture = &cached_texture;
            break;
        }
        if (cached_texture.texture.Get() == nullptr && available_slot == nullptr) {
            available_slot = &cached_texture;
        }
    }
    if (registered_texture == nullptr) {
        if (available_slot == nullptr) {
            state_->last_status = NV_ENC_ERR_RESOURCE_REGISTER_FAILED;
            return {false, false, state_->last_status, 0,
                    NvencEncodeResult::Stage::register_resource};
        }
        NV_ENC_REGISTER_RESOURCE registration{NV_ENC_REGISTER_RESOURCE_VER};
        registration.resourceType = NV_ENC_INPUT_RESOURCE_TYPE_DIRECTX;
        registration.resourceToRegister = texture;
        registration.width = state_->config.width;
        registration.height = state_->config.height;
        registration.bufferFormat = NV_ENC_BUFFER_FORMAT_ARGB;
        registration.bufferUsage = NV_ENC_INPUT_IMAGE;
        const NVENCSTATUS registration_status =
            state_->api.functions.nvEncRegisterResource(state_->encoder, &registration);
        if (registration_status != NV_ENC_SUCCESS || registration.registeredResource == nullptr) {
            state_->last_status = registration_status == NV_ENC_SUCCESS
                ? NV_ENC_ERR_RESOURCE_REGISTER_FAILED
                : registration_status;
            return {false, false, state_->last_status, 0,
                    NvencEncodeResult::Stage::register_resource};
        }
        available_slot->texture = texture;
        available_slot->input = registration.registeredResource;
        registered_texture = available_slot;
    }

    NV_ENC_MAP_INPUT_RESOURCE mapped{NV_ENC_MAP_INPUT_RESOURCE_VER};
    mapped.registeredResource = registered_texture->input;
    NVENCSTATUS status = state_->api.functions.nvEncMapInputResource(state_->encoder, &mapped);
    if (status != NV_ENC_SUCCESS || mapped.mappedResource == nullptr) {
        state_->last_status = status;
        return {false, false, status, 0, NvencEncodeResult::Stage::map_resource};
    }

    const bool is_keyframe = force_keyframe || state_->frame_index == 0 ||
        state_->frame_index % state_->config.keyframe_interval_frames == 0;
    const NV_ENC_OUTPUT_PTR bitstream_buffer = state_->bitstream_buffers[buffer_index];
    NV_ENC_PIC_PARAMS picture{NV_ENC_PIC_PARAMS_VER};
    picture.inputBuffer = mapped.mappedResource;
    picture.bufferFmt = mapped.mappedBufferFmt;
    picture.inputWidth = state_->config.width;
    picture.inputHeight = state_->config.height;
    picture.outputBitstream = bitstream_buffer;
    picture.pictureStruct = NV_ENC_PIC_STRUCT_FRAME;
    picture.encodePicFlags = is_keyframe ? NV_ENC_PIC_FLAG_FORCEIDR : 0;
    status = state_->api.functions.nvEncEncodePicture(state_->encoder, &picture);
    if (status != NV_ENC_SUCCESS) {
        state_->api.functions.nvEncUnmapInputResource(state_->encoder, mapped.mappedResource);
        state_->last_status = status;
        return {false, false, status, 0, NvencEncodeResult::Stage::encode_picture};
    }

    NV_ENC_LOCK_BITSTREAM locked{NV_ENC_LOCK_BITSTREAM_VER};
    locked.outputBitstream = bitstream_buffer;
    status = state_->api.functions.nvEncLockBitstream(state_->encoder, &locked);
    if (status != NV_ENC_SUCCESS || locked.bitstreamBufferPtr == nullptr || locked.bitstreamSizeInBytes == 0) {
        state_->api.functions.nvEncUnmapInputResource(state_->encoder, mapped.mappedResource);
        state_->last_status = status;
        return {false, false, status, 0, NvencEncodeResult::Stage::lock_bitstream};
    }
    const auto* first = static_cast<const std::byte*>(locked.bitstreamBufferPtr);
    try {
        state_->access_unit.assign(first, first + locked.bitstreamSizeInBytes);
    } catch (const std::bad_alloc&) {
        state_->api.functions.nvEncUnlockBitstream(state_->encoder, bitstream_buffer);
        state_->api.functions.nvEncUnmapInputResource(state_->encoder, mapped.mappedResource);
        state_->last_status = NV_ENC_ERR_OUT_OF_MEMORY;
        return {false, false, state_->last_status, 0,
                NvencEncodeResult::Stage::copy_bitstream};
    } catch (...) {
        state_->api.functions.nvEncUnlockBitstream(state_->encoder, bitstream_buffer);
        state_->api.functions.nvEncUnmapInputResource(state_->encoder, mapped.mappedResource);
        state_->last_status = NV_ENC_ERR_GENERIC;
        return {false, false, state_->last_status, 0,
                NvencEncodeResult::Stage::copy_bitstream};
    }
    state_->api.functions.nvEncUnlockBitstream(state_->encoder, bitstream_buffer);
    state_->api.functions.nvEncUnmapInputResource(state_->encoder, mapped.mappedResource);
    ++state_->frame_index;
    state_->last_status = NV_ENC_SUCCESS;
    return {true, is_keyframe, NV_ENC_SUCCESS,
            static_cast<std::uint32_t>(state_->access_unit.size()),
            NvencEncodeResult::Stage::complete};
}

void NvencH264Encoder::reset() noexcept {
    if (!state_) return;
    if (state_->encoder != nullptr) {
        for (const auto& registered_texture : state_->registered_textures) {
            if (registered_texture.input != nullptr) {
                state_->api.functions.nvEncUnregisterResource(
                    state_->encoder, registered_texture.input);
            }
        }
    }
    if (state_->encoder != nullptr) {
        for (const NV_ENC_OUTPUT_PTR bitstream_buffer : state_->bitstream_buffers) {
            if (bitstream_buffer != nullptr) {
                state_->api.functions.nvEncDestroyBitstreamBuffer(state_->encoder, bitstream_buffer);
            }
        }
    }
    if (state_->encoder != nullptr) state_->api.functions.nvEncDestroyEncoder(state_->encoder);
    for (auto& registered_texture : state_->registered_textures) {
        registered_texture.input = nullptr;
        registered_texture.texture.Reset();
    }
    state_->bitstream_buffers.fill(nullptr);
    state_->encoder = nullptr;
    state_->access_unit.clear();
    state_->frame_index = 0;
}

bool NvencH264Encoder::is_ready() const noexcept {
    return state_ && state_->encoder != nullptr &&
           std::all_of(state_->bitstream_buffers.begin(), state_->bitstream_buffers.end(),
                       [](NV_ENC_OUTPUT_PTR buffer) { return buffer != nullptr; });
}
std::int32_t NvencH264Encoder::last_nvenc_status() const noexcept {
    return state_ ? state_->last_status : NV_ENC_ERR_OUT_OF_MEMORY;
}
std::span<const std::byte> NvencH264Encoder::access_unit() const noexcept {
    return state_ ? std::span<const std::byte>{state_->access_unit} : std::span<const std::byte>{};
}

}  // namespace vfdual
