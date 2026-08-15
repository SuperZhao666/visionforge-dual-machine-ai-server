#include "vfdual/nvenc_session_probe.hpp"
#include "vfdual/nvenc_h264_encoder.hpp"

#include "ffnvcodec/nvEncodeAPI.h"

#include <d3d11.h>
#include <d3d11_1.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include <array>
#include <iostream>

int main() {
    using Microsoft::WRL::ComPtr;
    ComPtr<IDXGIFactory1> factory;
    if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&factory)))) return 1;
    ComPtr<IDXGIAdapter1> nvidia_adapter;
    for (UINT index = 0; ; ++index) {
        ComPtr<IDXGIAdapter1> candidate;
        if (factory->EnumAdapters1(index, &candidate) == DXGI_ERROR_NOT_FOUND) break;
        DXGI_ADAPTER_DESC1 description{};
        candidate->GetDesc1(&description);
        if (description.VendorId == 0x10DE) { nvidia_adapter = candidate; break; }
    }
    if (!nvidia_adapter) {
        std::cerr << "nvenc_session_probe_skipped reason=no_nvidia_adapter\n";
        return 77;
    }
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    D3D_FEATURE_LEVEL level{};
    const D3D_FEATURE_LEVEL levels[]{D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
    if (FAILED(D3D11CreateDevice(nvidia_adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT, levels, 2, D3D11_SDK_VERSION, &device, &level, &context))) return 1;
    const auto result = vfdual::probe_nvenc_d3d11_session(device.Get());
    D3D11_TEXTURE2D_DESC description{};
    description.Width = 320; description.Height = 320; description.MipLevels = 1; description.ArraySize = 1;
    description.Format = DXGI_FORMAT_B8G8R8A8_UNORM; description.SampleDesc.Count = 1;
    description.Usage = D3D11_USAGE_DEFAULT; description.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    std::array<ComPtr<ID3D11Texture2D>, 4> textures;
    for (auto& texture : textures) {
        if (FAILED(device->CreateTexture2D(&description, nullptr, &texture))) return 1;
    }
    const auto registration = vfdual::probe_nvenc_d3d11_texture_registration(
        device.Get(), textures.front().Get(), 320, 320);
    vfdual::NvencH264Encoder encoder;
    const vfdual::H264EncoderConfig config{
        .width = 320,
        .height = 320,
        .frames_per_second = 60,
        .keyframe_interval_frames = 60,
    };
    if (!encoder.initialize(device.Get(), config)) return 1;
    const auto first_frame = encoder.encode(textures[0].Get(), true);
    const auto second_frame = encoder.encode(textures[1].Get());
    const auto third_frame = encoder.encode(textures[2].Get());
    const auto capacity_result = encoder.encode(textures[3].Get());
    const auto cached_frame = encoder.encode(textures[0].Get());

    ComPtr<ID3D11Device> shared_worker_device;
    ComPtr<ID3D11DeviceContext> shared_worker_context;
    if (FAILED(D3D11CreateDevice(
            nvidia_adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT, levels, 2, D3D11_SDK_VERSION,
            &shared_worker_device, &level, &shared_worker_context))) {
        return 1;
    }
    D3D11_TEXTURE2D_DESC shared_description = description;
    shared_description.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE |
        D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;
    ComPtr<ID3D11Texture2D> source_shared_texture;
    if (FAILED(device->CreateTexture2D(
            &shared_description, nullptr, &source_shared_texture))) {
        return 1;
    }
    ComPtr<IDXGIKeyedMutex> source_keyed_mutex;
    ComPtr<IDXGIResource1> shared_resource;
    if (FAILED(source_shared_texture.As(&source_keyed_mutex)) ||
        FAILED(source_shared_texture.As(&shared_resource))) {
        return 1;
    }
    HANDLE shared_handle{};
    if (FAILED(shared_resource->CreateSharedHandle(
            nullptr,
            DXGI_SHARED_RESOURCE_READ | DXGI_SHARED_RESOURCE_WRITE,
            nullptr, &shared_handle))) {
        return 1;
    }
    ComPtr<ID3D11Device1> shared_worker_device1;
    ComPtr<ID3D11Texture2D> worker_shared_texture;
    ComPtr<IDXGIKeyedMutex> worker_keyed_mutex;
    const HRESULT open_status = shared_worker_device.As(&shared_worker_device1);
    const HRESULT open_texture_status = SUCCEEDED(open_status)
        ? shared_worker_device1->OpenSharedResource1(
              shared_handle, IID_PPV_ARGS(&worker_shared_texture))
        : open_status;
    const HRESULT worker_mutex_status = SUCCEEDED(open_texture_status)
        ? worker_shared_texture.As(&worker_keyed_mutex)
        : open_texture_status;
    CloseHandle(shared_handle);
    if (FAILED(open_status) || FAILED(open_texture_status) ||
        FAILED(worker_mutex_status)) {
        return 1;
    }
    if (source_keyed_mutex->AcquireSync(0U, 0U) != S_OK ||
        source_keyed_mutex->ReleaseSync(1U) != S_OK ||
        worker_keyed_mutex->AcquireSync(1U, 2'000U) != S_OK) {
        return 1;
    }
    vfdual::NvencH264Encoder shared_encoder;
    const bool shared_initialized =
        shared_encoder.initialize(shared_worker_device.Get(), config);
    const auto shared_frame = shared_initialized
        ? shared_encoder.encode(worker_shared_texture.Get(), true)
        : vfdual::NvencEncodeResult{};
    const HRESULT shared_release_status = worker_keyed_mutex->ReleaseSync(0U);
    std::cerr << "function_table=" << result.function_table_loaded << " session=" << result.session_opened << " status=" << result.nvenc_status
              << " registration=" << registration.session_opened << " registration_status=" << registration.nvenc_status
              << " persistent_first=" << first_frame.success << ':' << first_frame.bytes
              << " persistent_second=" << second_frame.success << ':' << second_frame.bytes
              << " persistent_third=" << third_frame.success << ':' << third_frame.bytes
              << " cache_capacity=" << capacity_result.success << ':' << capacity_result.nvenc_status
              << " cached_again=" << cached_frame.success << ':' << cached_frame.bytes
              << " shared_direct=" << shared_frame.success << ':' << shared_frame.bytes
              << " shared_release=0x" << std::hex << shared_release_status
              << " api=0x" << std::hex << result.runtime_api_version << '\n';
    return result.function_table_loaded && result.session_opened && registration.session_opened &&
                   first_frame.success && first_frame.keyframe &&
                   second_frame.success && !second_frame.keyframe &&
                   third_frame.success && !third_frame.keyframe &&
                   !capacity_result.success &&
                   capacity_result.nvenc_status == NV_ENC_ERR_RESOURCE_REGISTER_FAILED &&
                   capacity_result.stage == vfdual::NvencEncodeResult::Stage::register_resource &&
                   cached_frame.success && !cached_frame.keyframe &&
                   shared_initialized && shared_frame.success &&
                   shared_frame.keyframe && SUCCEEDED(shared_release_status)
               ? 0 : 1;
}
