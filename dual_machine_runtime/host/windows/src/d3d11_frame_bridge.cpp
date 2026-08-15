#include "vfdual/d3d11_frame_bridge.hpp"
#include "vfdual/frame_scaling_policy.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <d3d11.h>
#include <d3d11_1.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include <algorithm>
#include <cstring>
#include <vector>

namespace vfdual {
namespace {

using Microsoft::WRL::ComPtr;
constexpr UINT kNvidiaVendorId = 0x10DE;
constexpr DWORD kSharedMutexTimeoutMilliseconds = 50U;

bool device_uses_nvidia_adapter(ID3D11Device* device) noexcept {
    ComPtr<IDXGIDevice> dxgi_device;
    ComPtr<IDXGIAdapter> adapter;
    DXGI_ADAPTER_DESC description{};
    return SUCCEEDED(device->QueryInterface(IID_PPV_ARGS(&dxgi_device))) &&
           SUCCEEDED(dxgi_device->GetAdapter(&adapter)) &&
           SUCCEEDED(adapter->GetDesc(&description)) && description.VendorId == kNvidiaVendorId;
}

HRESULT create_nvidia_device(ComPtr<ID3D11Device>& device, ComPtr<ID3D11DeviceContext>& context) noexcept {
    ComPtr<IDXGIFactory1> factory;
    HRESULT result = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(result)) return result;
    for (UINT index = 0; ; ++index) {
        ComPtr<IDXGIAdapter1> adapter;
        result = factory->EnumAdapters1(index, &adapter);
        if (result == DXGI_ERROR_NOT_FOUND) return DXGI_ERROR_NOT_FOUND;
        if (FAILED(result)) return result;
        DXGI_ADAPTER_DESC1 description{};
        adapter->GetDesc1(&description);
        if (description.VendorId != kNvidiaVendorId) continue;
        constexpr D3D_FEATURE_LEVEL levels[]{D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
        D3D_FEATURE_LEVEL selected{};
        return D3D11CreateDevice(adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                                 levels, static_cast<UINT>(std::size(levels)), D3D11_SDK_VERSION,
                                 &device, &selected, &context);
    }
}

}  // namespace

struct D3D11FrameBridge::State final {
    ComPtr<ID3D11Device> source_device;
    ComPtr<ID3D11DeviceContext> source_context;
    ComPtr<ID3D11Device> encoder_device;
    ComPtr<ID3D11DeviceContext> encoder_context;
    ComPtr<ID3D11Texture2D> staging_texture;
    ComPtr<ID3D11Texture2D> encoder_texture;
    ComPtr<ID3D11Texture2D> shared_source_texture;
    ComPtr<ID3D11Texture2D> shared_encoder_texture;
    ComPtr<IDXGIKeyedMutex> shared_source_mutex;
    ComPtr<IDXGIKeyedMutex> shared_encoder_mutex;
    ComPtr<ID3D11Texture2D> gpu_scaled_texture;
    ComPtr<ID3D11Texture2D> gpu_scaled_staging_texture;
    ComPtr<ID3D11RenderTargetView> gpu_scaled_render_target;
    ComPtr<ID3D11VideoDevice> video_device;
    ComPtr<ID3D11VideoContext> video_context;
    ComPtr<ID3D11VideoProcessorEnumerator> video_enumerator;
    ComPtr<ID3D11VideoProcessor> video_processor;
    ComPtr<ID3D11VideoProcessorInputView> video_input_view;
    ComPtr<ID3D11VideoProcessorOutputView> video_output_view;
    ComPtr<ID3D11Texture2D> video_input_texture;
    std::vector<std::byte> upload_pixels;
    std::uint32_t target_width{};
    std::uint32_t target_height{};
    std::uint32_t presentation_timing_fps{};
    bool source_on_nvidia{};
    bool encoder_uses_source_device{};
    bool shared_bridge_probe_attempted{};
    bool shared_encoder_mutex_owned{};
    HANDLE shared_texture_handle{};
    FrameBridgeMode mode{FrameBridgeMode::cpu_staging_upload};
    std::int32_t last_hresult{E_FAIL};

    void reset_shared_bridge() noexcept {
        if (shared_encoder_mutex_owned && shared_encoder_mutex) {
            shared_encoder_mutex->ReleaseSync(0U);
        }
        shared_encoder_mutex_owned = false;
        shared_encoder_mutex.Reset();
        shared_source_mutex.Reset();
        shared_encoder_texture.Reset();
        shared_source_texture.Reset();
        if (shared_texture_handle != nullptr) {
            CloseHandle(shared_texture_handle);
            shared_texture_handle = nullptr;
        }
    }

    bool prepare_cross_adapter_shared_texture(
        const D3D11_TEXTURE2D_DESC& source) noexcept {
        if (shared_source_texture && shared_encoder_texture) return true;
        if (shared_bridge_probe_attempted || encoder_uses_source_device ||
            source.Width != target_width || source.Height != target_height) {
            return false;
        }
        shared_bridge_probe_attempted = true;

        ComPtr<ID3D11Device1> source_device1;
        ComPtr<ID3D11Device1> encoder_device1;
        HRESULT result = source_device.As(&source_device1);
        if (SUCCEEDED(result)) result = encoder_device.As(&encoder_device1);

        D3D11_TEXTURE2D_DESC shared_description = source;
        shared_description.Width = target_width;
        shared_description.Height = target_height;
        shared_description.Usage = D3D11_USAGE_DEFAULT;
        shared_description.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        shared_description.CPUAccessFlags = 0;
        shared_description.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE |
            D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;
        if (SUCCEEDED(result)) {
            result = source_device->CreateTexture2D(
                &shared_description, nullptr, &shared_source_texture);
        }

        ComPtr<IDXGIResource1> shared_resource;
        if (SUCCEEDED(result)) result = shared_source_texture.As(&shared_resource);
        if (SUCCEEDED(result)) {
            result = shared_resource->CreateSharedHandle(
                nullptr, DXGI_SHARED_RESOURCE_READ | DXGI_SHARED_RESOURCE_WRITE,
                nullptr, &shared_texture_handle);
        }
        if (SUCCEEDED(result)) {
            result = encoder_device1->OpenSharedResource1(
                shared_texture_handle, IID_PPV_ARGS(&shared_encoder_texture));
        }
        if (SUCCEEDED(result)) result = shared_source_texture.As(&shared_source_mutex);
        if (SUCCEEDED(result)) result = shared_encoder_texture.As(&shared_encoder_mutex);
        last_hresult = result;
        if (SUCCEEDED(result)) return true;
        reset_shared_bridge();
        return false;
    }

    BridgedFrame bridge_cross_adapter_shared_texture(
        ID3D11Texture2D* source_texture,
        const D3D11_TEXTURE2D_DESC& source) noexcept {
        if (!prepare_cross_adapter_shared_texture(source)) {
            return {nullptr, FrameBridgeMode::cpu_staging_upload, last_hresult};
        }
        if (shared_encoder_mutex_owned) {
            const HRESULT release_result = shared_encoder_mutex->ReleaseSync(0U);
            shared_encoder_mutex_owned = false;
            if (FAILED(release_result)) {
                last_hresult = release_result;
                reset_shared_bridge();
                return {nullptr, FrameBridgeMode::cpu_staging_upload, release_result};
            }
        }
        HRESULT result = shared_source_mutex->AcquireSync(
            0U, kSharedMutexTimeoutMilliseconds);
        if (result != S_OK) {
            last_hresult = result;
            reset_shared_bridge();
            return {nullptr, FrameBridgeMode::cpu_staging_upload, result};
        }
        source_context->CopyResource(shared_source_texture.Get(), source_texture);
        result = shared_source_mutex->ReleaseSync(1U);
        if (result == S_OK) {
            result = shared_encoder_mutex->AcquireSync(
                1U, kSharedMutexTimeoutMilliseconds);
        }
        if (result != S_OK) {
            last_hresult = result;
            reset_shared_bridge();
            return {nullptr, FrameBridgeMode::cpu_staging_upload, result};
        }
        shared_encoder_mutex_owned = true;
        mode = FrameBridgeMode::cross_adapter_shared_texture;
        last_hresult = S_OK;
        return {shared_encoder_texture.Get(), mode, S_OK};
    }

    void reset_gpu_scaler() noexcept {
        video_input_texture.Reset();
        video_input_view.Reset();
        video_output_view.Reset();
        video_processor.Reset();
        video_enumerator.Reset();
        video_context.Reset();
        video_device.Reset();
        gpu_scaled_render_target.Reset();
        gpu_scaled_staging_texture.Reset();
        gpu_scaled_texture.Reset();
    }

    bool prepare_gpu_scaler(ID3D11Texture2D* source_texture, const D3D11_TEXTURE2D_DESC& source) noexcept {
        if (gpu_scaled_texture && video_input_texture.Get() == source_texture) return true;
        reset_gpu_scaler();
        if (FAILED(source_device.As(&video_device)) || FAILED(source_context.As(&video_context))) return false;

        D3D11_TEXTURE2D_DESC scaled{};
        scaled.Width = target_width;
        scaled.Height = target_height;
        scaled.MipLevels = 1;
        scaled.ArraySize = 1;
        scaled.Format = source.Format;
        scaled.SampleDesc.Count = 1;
        scaled.Usage = D3D11_USAGE_DEFAULT;
        scaled.BindFlags = D3D11_BIND_RENDER_TARGET;
        if (FAILED(source_device->CreateTexture2D(&scaled, nullptr, &gpu_scaled_texture)) ||
            FAILED(source_device->CreateRenderTargetView(gpu_scaled_texture.Get(), nullptr, &gpu_scaled_render_target))) {
            reset_gpu_scaler();
            return false;
        }
        D3D11_TEXTURE2D_DESC encoder = scaled;
        encoder.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        if (FAILED(encoder_device->CreateTexture2D(&encoder, nullptr, &encoder_texture))) {
            reset_gpu_scaler();
            return false;
        }
        D3D11_TEXTURE2D_DESC staging = scaled;
        staging.Usage = D3D11_USAGE_STAGING;
        staging.BindFlags = 0;
        staging.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        if (FAILED(source_device->CreateTexture2D(&staging, nullptr, &gpu_scaled_staging_texture))) {
            reset_gpu_scaler();
            return false;
        }

        D3D11_VIDEO_PROCESSOR_CONTENT_DESC content{};
        content.InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
        content.InputFrameRate = {presentation_timing_fps, 1};
        content.InputWidth = source.Width;
        content.InputHeight = source.Height;
        content.OutputFrameRate = {presentation_timing_fps, 1};
        content.OutputWidth = target_width;
        content.OutputHeight = target_height;
        content.Usage = D3D11_VIDEO_USAGE_PLAYBACK_NORMAL;
        if (FAILED(video_device->CreateVideoProcessorEnumerator(&content, &video_enumerator)) ||
            FAILED(video_device->CreateVideoProcessor(video_enumerator.Get(), 0, &video_processor))) {
            reset_gpu_scaler();
            return false;
        }
        D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC output{};
        output.ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D;
        output.Texture2D.MipSlice = 0;
        if (FAILED(video_device->CreateVideoProcessorOutputView(gpu_scaled_texture.Get(), video_enumerator.Get(), &output,
                                                                  &video_output_view))) {
            reset_gpu_scaler();
            return false;
        }
        D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC input{};
        input.FourCC = 0;
        input.ViewDimension = D3D11_VPIV_DIMENSION_TEXTURE2D;
        input.Texture2D.MipSlice = 0;
        input.Texture2D.ArraySlice = 0;
        if (FAILED(video_device->CreateVideoProcessorInputView(source_texture, video_enumerator.Get(), &input,
                                                                 &video_input_view))) {
            reset_gpu_scaler();
            return false;
        }
        video_input_texture = source_texture;
        return true;
    }

    BridgedFrame bridge_gpu_scaled(ID3D11Texture2D* source_texture, const D3D11_TEXTURE2D_DESC& source) noexcept {
        if (!prepare_gpu_scaler(source_texture, source)) return {nullptr, FrameBridgeMode::cpu_staging_upload, E_FAIL};
        const float background[]{114.0F / 255.0F, 114.0F / 255.0F, 114.0F / 255.0F, 1.0F};
        source_context->ClearRenderTargetView(gpu_scaled_render_target.Get(), background);
        const FrameScaleExtent scaled_extent = fit_frame_extent(
            source.Width, source.Height, target_width, target_height);
        const auto scaled_width = static_cast<LONG>(scaled_extent.width);
        const auto scaled_height = static_cast<LONG>(scaled_extent.height);
        const RECT source_rect{0, 0, static_cast<LONG>(source.Width), static_cast<LONG>(source.Height)};
        const RECT destination_rect{static_cast<LONG>((target_width - scaled_width) / 2U),
                                    static_cast<LONG>((target_height - scaled_height) / 2U),
                                    static_cast<LONG>((target_width + scaled_width) / 2U),
                                    static_cast<LONG>((target_height + scaled_height) / 2U)};
        video_context->VideoProcessorSetStreamFrameFormat(video_processor.Get(), 0, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE);
        video_context->VideoProcessorSetStreamSourceRect(video_processor.Get(), 0, TRUE, &source_rect);
        video_context->VideoProcessorSetStreamDestRect(video_processor.Get(), 0, TRUE, &destination_rect);
        D3D11_VIDEO_PROCESSOR_STREAM stream{};
        stream.Enable = TRUE;
        stream.pInputSurface = video_input_view.Get();
        const HRESULT blit = video_context->VideoProcessorBlt(video_processor.Get(), video_output_view.Get(), 0, 1, &stream);
        if (FAILED(blit)) return {nullptr, FrameBridgeMode::gpu_scale_cpu_upload, blit};
        if (encoder_uses_source_device) {
            mode = FrameBridgeMode::gpu_scale_zero_copy;
            last_hresult = S_OK;
            return {gpu_scaled_texture.Get(), mode, S_OK};
        }
        source_context->CopyResource(gpu_scaled_staging_texture.Get(), gpu_scaled_texture.Get());
        D3D11_MAPPED_SUBRESOURCE mapped{};
        const HRESULT map_result = source_context->Map(gpu_scaled_staging_texture.Get(), 0, D3D11_MAP_READ, 0, &mapped);
        if (FAILED(map_result)) return {nullptr, FrameBridgeMode::gpu_scale_cpu_upload, map_result};
        const std::size_t row_bytes = static_cast<std::size_t>(target_width) * 4U;
        for (std::uint32_t row = 0; row < target_height; ++row) {
            const auto* source_row = static_cast<const std::byte*>(mapped.pData) +
                static_cast<std::size_t>(row) * mapped.RowPitch;
            std::memcpy(upload_pixels.data() + static_cast<std::size_t>(row) * row_bytes,
                        source_row, row_bytes);
        }
        source_context->Unmap(gpu_scaled_staging_texture.Get(), 0);
        encoder_context->UpdateSubresource(
            encoder_texture.Get(), 0, nullptr, upload_pixels.data(),
            static_cast<UINT>(row_bytes), 0);
        mode = FrameBridgeMode::gpu_scale_cpu_upload;
        last_hresult = S_OK;
        return {encoder_texture.Get(), FrameBridgeMode::gpu_scale_cpu_upload, S_OK};
    }
};

D3D11FrameBridge::D3D11FrameBridge() noexcept : state_(std::make_unique<State>()) {}
D3D11FrameBridge::~D3D11FrameBridge() = default;

bool D3D11FrameBridge::initialize(ID3D11Device* source_device, ID3D11DeviceContext* source_context,
                                  std::uint32_t target_width, std::uint32_t target_height,
                                  std::uint32_t presentation_timing_fps,
                                  FrameEncoderDevicePreference preference) noexcept {
    reset();
    if (source_device == nullptr || source_context == nullptr || target_width == 0 ||
        target_height == 0 || presentation_timing_fps == 0) {
        state_->last_hresult = E_INVALIDARG;
        return false;
    }
    state_->source_device = source_device;
    state_->source_context = source_context;
    state_->target_width = target_width;
    state_->target_height = target_height;
    state_->presentation_timing_fps = presentation_timing_fps;
    state_->upload_pixels.resize(static_cast<std::size_t>(target_width) * target_height * 4U);
    state_->source_on_nvidia = device_uses_nvidia_adapter(source_device);
    if (preference == FrameEncoderDevicePreference::capture_source || state_->source_on_nvidia) {
        state_->encoder_device = source_device;
        state_->encoder_context = source_context;
        state_->encoder_uses_source_device = true;
        state_->mode = FrameBridgeMode::zero_copy;
        state_->last_hresult = S_OK;
        return true;
    }
    const HRESULT result = create_nvidia_device(state_->encoder_device, state_->encoder_context);
    state_->last_hresult = result;
    return SUCCEEDED(result);
}

BridgedFrame D3D11FrameBridge::bridge(ID3D11Texture2D* source_texture) noexcept {
    if (source_texture == nullptr || !state_->encoder_device) return {nullptr, state_->mode, E_INVALIDARG};
    D3D11_TEXTURE2D_DESC source_description{};
    source_texture->GetDesc(&source_description);
    if (source_description.Format != DXGI_FORMAT_B8G8R8A8_UNORM) {
        state_->last_hresult = E_INVALIDARG;
        return {nullptr, state_->mode, E_INVALIDARG};
    }
    const bool can_use_zero_copy = state_->encoder_uses_source_device && source_description.Width == state_->target_width &&
                                   source_description.Height == state_->target_height;
    if (can_use_zero_copy) {
        state_->mode = FrameBridgeMode::zero_copy;
        state_->last_hresult = S_OK;
        return {source_texture, state_->mode, S_OK};
    }
    if (!state_->encoder_uses_source_device &&
        source_description.Width == state_->target_width &&
        source_description.Height == state_->target_height) {
        const BridgedFrame shared = state_->bridge_cross_adapter_shared_texture(
            source_texture, source_description);
        if (shared.texture != nullptr) return shared;
    }
    if (source_description.Width != state_->target_width || source_description.Height != state_->target_height) {
        const BridgedFrame gpu_scaled = state_->bridge_gpu_scaled(source_texture, source_description);
        if (gpu_scaled.texture != nullptr) return gpu_scaled;
    }
    state_->mode = FrameBridgeMode::cpu_staging_upload;
    if (state_->staging_texture) {
        D3D11_TEXTURE2D_DESC existing_description{};
        state_->staging_texture->GetDesc(&existing_description);
        if (existing_description.Width != source_description.Width || existing_description.Height != source_description.Height ||
            existing_description.Format != source_description.Format) {
            state_->encoder_texture.Reset();
            state_->staging_texture.Reset();
        }
    }
    if (!state_->staging_texture) {
        D3D11_TEXTURE2D_DESC staging_description = source_description;
        staging_description.Usage = D3D11_USAGE_STAGING;
        staging_description.BindFlags = 0;
        staging_description.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        staging_description.MiscFlags = 0;
        HRESULT result = state_->source_device->CreateTexture2D(&staging_description, nullptr, &state_->staging_texture);
        if (FAILED(result)) { state_->last_hresult = result; return {nullptr, state_->mode, result}; }

        D3D11_TEXTURE2D_DESC encoder_description = source_description;
        encoder_description.Width = state_->target_width;
        encoder_description.Height = state_->target_height;
        encoder_description.Usage = D3D11_USAGE_DEFAULT;
        encoder_description.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        encoder_description.CPUAccessFlags = 0;
        encoder_description.MiscFlags = 0;
        result = state_->encoder_device->CreateTexture2D(&encoder_description, nullptr, &state_->encoder_texture);
        if (FAILED(result)) { state_->last_hresult = result; return {nullptr, state_->mode, result}; }
    }
    state_->source_context->CopyResource(state_->staging_texture.Get(), source_texture);
    D3D11_MAPPED_SUBRESOURCE mapped{};
    const HRESULT map_result = state_->source_context->Map(state_->staging_texture.Get(), 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(map_result)) { state_->last_hresult = map_result; return {nullptr, state_->mode, map_result}; }
    const bool exact_size = source_description.Width == state_->target_width &&
        source_description.Height == state_->target_height;
    if (exact_size) {
        const std::size_t row_bytes = static_cast<std::size_t>(state_->target_width) * 4U;
        for (std::uint32_t row = 0; row < state_->target_height; ++row) {
            const auto* source_row = static_cast<const std::byte*>(mapped.pData) +
                static_cast<std::size_t>(row) * mapped.RowPitch;
            std::memcpy(state_->upload_pixels.data() + static_cast<std::size_t>(row) * row_bytes,
                        source_row, row_bytes);
        }
    } else {
        for (std::size_t pixel = 0; pixel < state_->upload_pixels.size(); pixel += 4U) {
            state_->upload_pixels[pixel] = std::byte{114};
            state_->upload_pixels[pixel + 1U] = std::byte{114};
            state_->upload_pixels[pixel + 2U] = std::byte{114};
            state_->upload_pixels[pixel + 3U] = std::byte{0xFF};
        }
        const FrameScaleExtent scaled_extent = fit_frame_extent(
            source_description.Width, source_description.Height,
            state_->target_width, state_->target_height);
        const std::uint32_t scaled_width = scaled_extent.width;
        const std::uint32_t scaled_height = scaled_extent.height;
        const std::uint32_t horizontal_padding = (state_->target_width - scaled_width) / 2U;
        const std::uint32_t vertical_padding = (state_->target_height - scaled_height) / 2U;
        for (std::uint32_t output_y = 0; output_y < scaled_height; ++output_y) {
            const auto source_y = (std::min)(
                source_description.Height - 1U,
                static_cast<std::uint32_t>(
                    static_cast<std::uint64_t>(output_y) *
                    source_description.Height / scaled_height));
            const auto* source_row = static_cast<const std::byte*>(mapped.pData) + static_cast<std::size_t>(source_y) * mapped.RowPitch;
            auto* output_row = state_->upload_pixels.data() + (static_cast<std::size_t>(output_y + vertical_padding) * state_->target_width + horizontal_padding) * 4U;
            for (std::uint32_t output_x = 0; output_x < scaled_width; ++output_x) {
                const auto source_x = (std::min)(
                    source_description.Width - 1U,
                    static_cast<std::uint32_t>(
                        static_cast<std::uint64_t>(output_x) *
                        source_description.Width / scaled_width));
                const auto* source_pixel = source_row + static_cast<std::size_t>(source_x) * 4U;
                std::copy_n(source_pixel, 4, output_row + static_cast<std::size_t>(output_x) * 4U);
            }
        }
    }
    state_->source_context->Unmap(state_->staging_texture.Get(), 0);
    state_->encoder_context->UpdateSubresource(
        state_->encoder_texture.Get(), 0, nullptr, state_->upload_pixels.data(),
        state_->target_width * 4U, 0);
    state_->last_hresult = S_OK;
    return {state_->encoder_texture.Get(), state_->mode, S_OK};
}

void D3D11FrameBridge::reset() noexcept {
    state_->reset_gpu_scaler();
    state_->reset_shared_bridge();
    state_->encoder_texture.Reset();
    state_->staging_texture.Reset();
    state_->encoder_context.Reset();
    state_->encoder_device.Reset();
    state_->source_context.Reset();
    state_->source_device.Reset();
    state_->mode = FrameBridgeMode::cpu_staging_upload;
    state_->upload_pixels.clear();
    state_->target_width = 0;
    state_->target_height = 0;
    state_->presentation_timing_fps = 0;
    state_->source_on_nvidia = false;
    state_->encoder_uses_source_device = false;
    state_->shared_bridge_probe_attempted = false;
}

ID3D11Device* D3D11FrameBridge::encoder_device() const noexcept { return state_->encoder_device.Get(); }
bool D3D11FrameBridge::uses_capture_device() const noexcept { return state_->encoder_uses_source_device; }
FrameBridgeMode D3D11FrameBridge::mode() const noexcept { return state_->mode; }
std::int32_t D3D11FrameBridge::last_hresult() const noexcept { return state_->last_hresult; }

}  // namespace vfdual
