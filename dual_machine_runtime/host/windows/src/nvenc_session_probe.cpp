#include "vfdual/nvenc_session_probe.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "ffnvcodec/nvEncodeAPI.h"

namespace vfdual {
namespace {
struct NvencApi final {
    HMODULE library{};
    NV_ENCODE_API_FUNCTION_LIST functions{};
    std::uint32_t runtime_api_version{};
    ~NvencApi() { if (library != nullptr) FreeLibrary(library); }
};

bool load_api(NvencApi& api) noexcept {
    api.library = LoadLibraryW(L"nvEncodeAPI64.dll");
    if (api.library == nullptr) return false;
    using GetMaxSupportedVersionFn = NVENCSTATUS(NVENCAPI*)(uint32_t*);
    using CreateInstanceFn = NVENCSTATUS(NVENCAPI*)(NV_ENCODE_API_FUNCTION_LIST*);
    const auto max_version = reinterpret_cast<GetMaxSupportedVersionFn>(GetProcAddress(api.library, "NvEncodeAPIGetMaxSupportedVersion"));
    const auto create_instance = reinterpret_cast<CreateInstanceFn>(GetProcAddress(api.library, "NvEncodeAPICreateInstance"));
    if (create_instance == nullptr) return false;
    api.runtime_api_version = NVENCAPI_VERSION;
    if (max_version != nullptr && max_version(&api.runtime_api_version) != NV_ENC_SUCCESS) api.runtime_api_version = NVENCAPI_VERSION;
    if (api.runtime_api_version < NVENCAPI_VERSION) return false;
    api.functions.version = NV_ENCODE_API_FUNCTION_LIST_VER;
    return create_instance(&api.functions) == NV_ENC_SUCCESS;
}

NVENCSTATUS open_session(const NvencApi& api, ID3D11Device* device, void** encoder) noexcept {
    NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS parameters{NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_VER};
    parameters.device = device;
    parameters.deviceType = NV_ENC_DEVICE_TYPE_DIRECTX;
    parameters.apiVersion = NVENCAPI_VERSION;
    return api.functions.nvEncOpenEncodeSessionEx(&parameters, encoder);
}
}  // namespace

NvencSessionProbeResult probe_nvenc_d3d11_session(ID3D11Device* device) noexcept {
    if (device == nullptr) return {false, false, NV_ENC_ERR_INVALID_PTR, 0};
    NvencApi api;
    if (!load_api(api)) return {false, false, NV_ENC_ERR_INVALID_VERSION, api.runtime_api_version};
    void* encoder = nullptr;
    const NVENCSTATUS status = open_session(api, device, &encoder);
    if (status == NV_ENC_SUCCESS && encoder != nullptr) api.functions.nvEncDestroyEncoder(encoder);
    return {true, status == NV_ENC_SUCCESS && encoder != nullptr, status, api.runtime_api_version};
}

NvencSessionProbeResult probe_nvenc_d3d11_texture_registration(ID3D11Device* device, ID3D11Texture2D* texture, std::uint32_t width, std::uint32_t height) noexcept {
    if (device == nullptr || texture == nullptr || width == 0 || height == 0) return {false, false, NV_ENC_ERR_INVALID_PTR, 0};
    NvencApi api;
    if (!load_api(api)) return {false, false, NV_ENC_ERR_INVALID_VERSION, api.runtime_api_version};
    void* encoder = nullptr;
    const NVENCSTATUS opened = open_session(api, device, &encoder);
    if (opened != NV_ENC_SUCCESS || encoder == nullptr) return {true, false, opened, api.runtime_api_version};
    NV_ENC_PRESET_CONFIG preset{NV_ENC_PRESET_CONFIG_VER};
    preset.presetCfg.version = NV_ENC_CONFIG_VER;
    const NVENCSTATUS preset_status = api.functions.nvEncGetEncodePresetConfigEx(
        encoder, NV_ENC_CODEC_H264_GUID, NV_ENC_PRESET_P1_GUID, NV_ENC_TUNING_INFO_ULTRA_LOW_LATENCY, &preset);
    if (preset_status != NV_ENC_SUCCESS) { api.functions.nvEncDestroyEncoder(encoder); return {true, false, preset_status, api.runtime_api_version}; }
    NV_ENC_CONFIG config = preset.presetCfg;
    config.version = NV_ENC_CONFIG_VER;
    config.profileGUID = NV_ENC_H264_PROFILE_BASELINE_GUID;
    config.gopLength = 60;
    config.frameIntervalP = 1;
    config.rcParams.rateControlMode = NV_ENC_PARAMS_RC_CBR;
    config.rcParams.averageBitRate = 8'000'000;
    config.rcParams.maxBitRate = 8'000'000;
    NV_ENC_INITIALIZE_PARAMS initialize{NV_ENC_INITIALIZE_PARAMS_VER};
    initialize.encodeGUID = NV_ENC_CODEC_H264_GUID;
    initialize.presetGUID = NV_ENC_PRESET_P1_GUID;
    initialize.encodeWidth = width;
    initialize.encodeHeight = height;
    initialize.darWidth = width;
    initialize.darHeight = height;
    initialize.frameRateNum = 60;
    initialize.frameRateDen = 1;
    initialize.enablePTD = 1;
    initialize.tuningInfo = NV_ENC_TUNING_INFO_ULTRA_LOW_LATENCY;
    initialize.encodeConfig = &config;
    const NVENCSTATUS initialized = api.functions.nvEncInitializeEncoder(encoder, &initialize);
    if (initialized != NV_ENC_SUCCESS) { api.functions.nvEncDestroyEncoder(encoder); return {true, false, initialized, api.runtime_api_version}; }
    NV_ENC_REGISTER_RESOURCE registration{NV_ENC_REGISTER_RESOURCE_VER};
    registration.resourceType = NV_ENC_INPUT_RESOURCE_TYPE_DIRECTX;
    registration.resourceToRegister = texture;
    registration.width = width;
    registration.height = height;
    registration.pitch = 0;  // Required by NVENC for DirectX resources.
    registration.bufferFormat = NV_ENC_BUFFER_FORMAT_ARGB;
    registration.bufferUsage = NV_ENC_INPUT_IMAGE;
    const NVENCSTATUS status = api.functions.nvEncRegisterResource(encoder, &registration);
    if (status != NV_ENC_SUCCESS || registration.registeredResource == nullptr) {
        api.functions.nvEncDestroyEncoder(encoder);
        return {true, false, status, api.runtime_api_version};
    }
    NV_ENC_MAP_INPUT_RESOURCE mapped{NV_ENC_MAP_INPUT_RESOURCE_VER};
    mapped.registeredResource = registration.registeredResource;
    const NVENCSTATUS mapped_status = api.functions.nvEncMapInputResource(encoder, &mapped);
    if (mapped_status != NV_ENC_SUCCESS) {
        api.functions.nvEncUnregisterResource(encoder, registration.registeredResource);
        api.functions.nvEncDestroyEncoder(encoder);
        return {true, false, mapped_status, api.runtime_api_version};
    }
    NV_ENC_CREATE_BITSTREAM_BUFFER bitstream{NV_ENC_CREATE_BITSTREAM_BUFFER_VER};
    const NVENCSTATUS bitstream_status = api.functions.nvEncCreateBitstreamBuffer(encoder, &bitstream);
    if (bitstream_status != NV_ENC_SUCCESS) {
        api.functions.nvEncUnmapInputResource(encoder, mapped.mappedResource);
        api.functions.nvEncUnregisterResource(encoder, registration.registeredResource);
        api.functions.nvEncDestroyEncoder(encoder);
        return {true, false, bitstream_status, api.runtime_api_version};
    }
    NV_ENC_PIC_PARAMS picture{NV_ENC_PIC_PARAMS_VER};
    picture.inputBuffer = mapped.mappedResource;
    picture.bufferFmt = NV_ENC_BUFFER_FORMAT_ARGB;
    picture.inputWidth = width;
    picture.inputHeight = height;
    picture.outputBitstream = bitstream.bitstreamBuffer;
    picture.pictureStruct = NV_ENC_PIC_STRUCT_FRAME;
    picture.encodePicFlags = NV_ENC_PIC_FLAG_FORCEIDR;
    const NVENCSTATUS encode_status = api.functions.nvEncEncodePicture(encoder, &picture);
    NV_ENC_LOCK_BITSTREAM locked{NV_ENC_LOCK_BITSTREAM_VER};
    locked.outputBitstream = bitstream.bitstreamBuffer;
    const NVENCSTATUS lock_status = encode_status == NV_ENC_SUCCESS ? api.functions.nvEncLockBitstream(encoder, &locked) : encode_status;
    const bool encoded = lock_status == NV_ENC_SUCCESS && locked.bitstreamBufferPtr != nullptr && locked.bitstreamSizeInBytes > 0;
    if (lock_status == NV_ENC_SUCCESS) api.functions.nvEncUnlockBitstream(encoder, bitstream.bitstreamBuffer);
    api.functions.nvEncDestroyBitstreamBuffer(encoder, bitstream.bitstreamBuffer);
    api.functions.nvEncUnmapInputResource(encoder, mapped.mappedResource);
    api.functions.nvEncUnregisterResource(encoder, registration.registeredResource);
    api.functions.nvEncDestroyEncoder(encoder);
    return {true, encoded, lock_status, api.runtime_api_version};
}
}  // namespace vfdual
